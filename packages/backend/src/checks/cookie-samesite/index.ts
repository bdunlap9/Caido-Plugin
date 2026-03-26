import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { getSetCookieHeaders, keyStrategy } from "../../utils";

/**
 * Checks for cookies missing the SameSite attribute.
 * Without SameSite=Strict or SameSite=Lax, cookies are sent on cross-site
 * requests, enabling CSRF attacks.
 */

export default defineCheck<unknown>(({ step }) => {
  step("check", (state, ctx) => {
    const { response } = ctx.target;
    if (!response) return done({ state });

    const cookies = getSetCookieHeaders(response);
    if (cookies.length === 0) return done({ state });

    const findings: Finding[] = [];

    for (const cookie of cookies) {
      const raw = (cookie as any).raw ?? "";
      const lower = raw.toLowerCase();

      // Check if SameSite is present
      const hasSameSite = lower.includes("samesite");

      if (!hasSameSite) {
        findings.push({
          name: `Cookie '${cookie.key}' missing SameSite attribute`,
          description:
            `The cookie \`${cookie.key}\` is set without a SameSite attribute. ` +
            `Modern browsers default to \`Lax\`, but older browsers default to \`None\`, ` +
            `sending the cookie on all cross-site requests — enabling CSRF attacks.\n\n` +
            `**Recommendation:** Set \`SameSite=Strict\` or \`SameSite=Lax\` explicitly.`,
          severity: Severity.LOW,
          correlation: {
            requestID: ctx.target.request.getId(),
            locations: [],
          },
        });
      } else if (lower.includes("samesite=none")) {
        // SameSite=None requires Secure flag
        const hasSecure = lower.includes("secure");
        if (!hasSecure) {
          findings.push({
            name: `Cookie '${cookie.key}' has SameSite=None without Secure`,
            description:
              `The cookie \`${cookie.key}\` is set with \`SameSite=None\` but without the \`Secure\` flag. ` +
              `Browsers will reject this cookie. SameSite=None requires the Secure attribute.`,
            severity: Severity.MEDIUM,
            correlation: {
              requestID: ctx.target.request.getId(),
              locations: [],
            },
          });
        } else {
          findings.push({
            name: `Cookie '${cookie.key}' allows cross-site sending (SameSite=None)`,
            description:
              `The cookie \`${cookie.key}\` is set with \`SameSite=None\`, allowing it to be sent ` +
              `on all cross-site requests. Verify this is intentional (e.g., for SSO or embedded content).`,
            severity: Severity.INFO,
            correlation: {
              requestID: ctx.target.request.getId(),
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
      id: "cookie-samesite",
      name: "Cookie SameSite Attribute Check",
      description:
        "Checks for cookies missing the SameSite attribute or set to SameSite=None, " +
        "which can enable cross-site request forgery (CSRF) attacks.",
      type: "passive",
      tags: [Tags.COOKIES, Tags.CSRF, Tags.SECURITY_HEADERS],
      severities: [Severity.INFO, Severity.LOW, Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined,
  };
});
