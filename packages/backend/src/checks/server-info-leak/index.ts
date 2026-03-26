import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Detects server version disclosure through response headers.
 * Checks: Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version,
 * X-Generator, X-Runtime, X-Version.
 */

type HeaderPattern = {
  header: string;
  name: string;
  versionRegex?: RegExp; // if matched, version is exposed
};

const HEADERS_TO_CHECK: HeaderPattern[] = [
  { header: "server",              name: "Server",              versionRegex: /\d+[\d.]+/ },
  { header: "x-powered-by",       name: "X-Powered-By" },
  { header: "x-aspnet-version",   name: "X-AspNet-Version" },
  { header: "x-aspnetmvc-version",name: "X-AspNetMvc-Version" },
  { header: "x-generator",        name: "X-Generator" },
  { header: "x-runtime",          name: "X-Runtime" },
  { header: "x-version",          name: "X-Version" },
  { header: "x-drupal-cache",     name: "X-Drupal-Cache" },
  { header: "x-varnish",          name: "X-Varnish" },
  { header: "x-debug-token",      name: "X-Debug-Token" },
  { header: "x-debug-token-link", name: "X-Debug-Token-Link" },
];

function getHeader(resp: any, name: string): string | undefined {
  try {
    const vals = resp?.getHeader?.(name);
    return vals?.[0] ?? undefined;
  } catch {
    return undefined;
  }
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("check", (state, ctx) => {
    const resp = ctx.target.response;
    if (!resp) return done({ state });

    const findings: Finding[] = [];

    for (const hp of HEADERS_TO_CHECK) {
      const value = getHeader(resp, hp.header);
      if (!value) continue;

      const hasVersion = hp.versionRegex ? hp.versionRegex.test(value) : true;
      const severity = hp.header === "x-debug-token" || hp.header === "x-debug-token-link"
        ? Severity.MEDIUM
        : (hasVersion ? Severity.LOW : Severity.INFO);

      findings.push({
        name: `${hp.name} Header Information Leak`,
        description:
          `The response includes a \`${hp.name}\` header that discloses technology details.\n\n` +
          `**Value:** \`${value}\`\n\n` +
          `This information helps attackers fingerprint the server and find version-specific exploits. ` +
          `Consider removing or suppressing this header in production.`,
        severity,
        correlation: {
          requestID: ctx.target.request.getId(),
          locations: [],
        },
      });
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "server-info-leak",
      name: "Server Information Leakage",
      description:
        "Detects server version and technology disclosure through response headers " +
        "(Server, X-Powered-By, X-AspNet-Version, X-Debug-Token, etc.).",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.INFO],
      severities: [Severity.INFO, Severity.LOW, Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().build(),
    when: (t) => t.response !== undefined,
  };
});
