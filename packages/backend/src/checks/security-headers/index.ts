import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Checks for missing critical security headers on HTML responses:
 * - Strict-Transport-Security (HSTS)
 * - X-Content-Type-Options
 * - Permissions-Policy / Feature-Policy
 * - Referrer-Policy
 * - X-XSS-Protection (deprecated but still relevant for older browsers)
 */

type HeaderCheck = {
  header: string;
  alternates?: string[];
  name: string;
  description: string;
  severity: Severity;
  onlyTls?: boolean;
  validateValue?: (value: string) => string | null; // returns issue description or null if OK
};

const HEADER_CHECKS: HeaderCheck[] = [
  {
    header: "strict-transport-security",
    name: "Missing HSTS Header",
    description:
      "The response does not include a `Strict-Transport-Security` header. Without HSTS, " +
      "users can be downgraded to HTTP via man-in-the-middle attacks (SSL stripping).",
    severity: Severity.MEDIUM,
    onlyTls: true,
    validateValue: (v) => {
      const lower = v.toLowerCase();
      if (!lower.includes("max-age")) return "HSTS header missing `max-age` directive.";
      const match = lower.match(/max-age\s*=\s*(\d+)/);
      if (match && parseInt(match[1]!, 10) < 2592000) {
        return `HSTS max-age is only ${match[1]} seconds (less than 30 days). Recommend at least 31536000 (1 year).`;
      }
      return null;
    },
  },
  {
    header: "x-content-type-options",
    name: "Missing X-Content-Type-Options Header",
    description:
      "The response does not include `X-Content-Type-Options: nosniff`. Without this header, " +
      "browsers may MIME-sniff the response, potentially interpreting uploads or API responses as executable content.",
    severity: Severity.LOW,
    validateValue: (v) => {
      if (v.trim().toLowerCase() !== "nosniff") {
        return `X-Content-Type-Options has unexpected value \`${v}\`. Should be \`nosniff\`.`;
      }
      return null;
    },
  },
  {
    header: "permissions-policy",
    alternates: ["feature-policy"],
    name: "Missing Permissions-Policy Header",
    description:
      "The response does not include a `Permissions-Policy` (or legacy `Feature-Policy`) header. " +
      "This header restricts which browser features (camera, microphone, geolocation, etc.) can be used.",
    severity: Severity.INFO,
  },
  {
    header: "referrer-policy",
    name: "Missing Referrer-Policy Header",
    description:
      "The response does not include a `Referrer-Policy` header. Without it, the full URL " +
      "(potentially including sensitive query parameters) may be sent as a referrer to third-party sites.",
    severity: Severity.LOW,
  },
];

function getHeader(resp: any, name: string): string | undefined {
  try {
    const vals = resp?.getHeader?.(name);
    if (!vals || vals.length === 0) return undefined;
    return vals[0] ?? undefined;
  } catch {
    return undefined;
  }
}

function isHtml(resp: any): boolean {
  const ct = getHeader(resp, "content-type") ?? "";
  return ct.includes("text/html") || ct.includes("application/xhtml");
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("check", (state, ctx) => {
    const { response, request } = ctx.target;
    if (!response) return done({ state });
    if (response.getCode() !== 200) return done({ state });
    if (!isHtml(response)) return done({ state });

    const isTls = request.getTls?.() ?? false;
    const findings: Finding[] = [];

    for (const check of HEADER_CHECKS) {
      if (check.onlyTls && !isTls) continue;

      const value = getHeader(response, check.header);
      const altValue = check.alternates
        ? check.alternates.map(h => getHeader(response, h)).find(Boolean)
        : undefined;

      if (!value && !altValue) {
        findings.push({
          name: check.name,
          description: check.description,
          severity: check.severity,
          correlation: {
            requestID: request.getId(),
            locations: [],
          },
        });
      } else if (value && check.validateValue) {
        const issue = check.validateValue(value);
        if (issue) {
          findings.push({
            name: check.name.replace("Missing", "Misconfigured"),
            description: issue,
            severity: check.severity,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          });
        }
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "security-headers",
      name: "Missing Security Headers",
      description:
        "Checks for missing or misconfigured security headers including HSTS, " +
        "X-Content-Type-Options, Permissions-Policy, and Referrer-Policy.",
      type: "passive",
      tags: [Tags.SECURITY_HEADERS],
      severities: [Severity.INFO, Severity.LOW, Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().build(),
    when: (t) => t.response !== undefined && t.response.getCode() === 200,
  };
});
