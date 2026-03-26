import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Detects forms on HTTPS pages that submit to HTTP endpoints (mixed content).
 * This leaks form data (passwords, tokens) over unencrypted connections.
 */

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, ctx) => {
    const { request, response } = ctx.target;
    if (!response || response.getCode() !== 200) return done({ state });

    // Only check HTTPS pages
    if (!request.getTls?.()) return done({ state });

    const ct = (response.getHeader?.("content-type")?.[0] ?? "").toLowerCase();
    if (!ct.includes("text/html")) return done({ state });

    const body = response.getBody?.()?.toText?.() ?? "";
    if (!body) return done({ state });

    const findings: Finding[] = [];
    const formRegex = /<form\b([^>]*)>/gi;
    let m;
    while ((m = formRegex.exec(body)) !== null) {
      const attrs = m[1] ?? "";
      const actionMatch = attrs.match(/action\s*=\s*["']([^"']+)["']/i);
      if (!actionMatch) continue;
      const action = actionMatch[1]!;

      if (action.toLowerCase().startsWith("http://")) {
        findings.push({
          name: "Insecure Form Action (Mixed Content)",
          description:
            `A form on this HTTPS page submits to an HTTP endpoint: \`${action}\`\n\n` +
            `Form data (potentially including passwords, tokens, and personal information) ` +
            `will be transmitted in cleartext, vulnerable to interception.\n\n` +
            `**Recommendation:** Change the form action to use HTTPS.`,
          severity: Severity.MEDIUM,
          correlation: { requestID: request.getId(), locations: [] },
        });
        if (findings.length >= 3) break;
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "insecure-form-action",
      name: "Insecure Form Action (Mixed Content)",
      description: "Detects HTTPS pages containing forms that submit to HTTP endpoints, leaking form data in cleartext.",
      type: "passive",
      tags: [Tags.TLS, Tags.SENSITIVE_DATA],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined && t.request.getTls?.() === true,
  };
});
