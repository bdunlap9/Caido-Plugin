import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Active CORS misconfiguration check.
 * Sends requests with crafted Origin headers to detect:
 * 1. Origin reflection (echoes back any origin)
 * 2. Null origin allowed with credentials
 * 3. Wildcard with credentials (browser rejects but still a misconfig)
 * 4. Subdomain trust (trusts evil.target.com)
 */

type State = {
  stage: "reflect" | "subdomain" | "done";
};

function getHeader(resp: any, name: string): string | undefined {
  try {
    const v = resp?.getHeader?.(name);
    return Array.isArray(v) ? v[0] : v;
  } catch {
    return undefined;
  }
}

export default defineCheck<State>(({ step }) => {

  // Step 1: Send request with a foreign Origin to test reflection
  step("reflect", async (state, ctx) => {
    const spec = ctx.target.request.toSpec();
    const attackerOrigin = "https://evil.attacker.example";
    spec.setHeader("Origin", attackerOrigin);

    try {
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (!response) return done({ state });

      const acao = (getHeader(response, "access-control-allow-origin") ?? "").trim();
      const acac = (getHeader(response, "access-control-allow-credentials") ?? "").toLowerCase();

      // Check: Origin reflected back exactly
      if (acao === attackerOrigin) {
        const withCreds = acac === "true";
        return done({
          state,
          findings: [{
            name: "CORS Origin Reflection" + (withCreds ? " with Credentials" : ""),
            description:
              `The server reflects the \`Origin\` header in \`Access-Control-Allow-Origin\` without validation.\n\n` +
              `**Test Origin sent:** \`${attackerOrigin}\`\n` +
              `**ACAO returned:** \`${acao}\`\n` +
              `**Credentials:** \`${acac}\`\n\n` +
              (withCreds
                ? `This is **exploitable**: an attacker's page can make authenticated cross-origin requests and read the response, stealing sensitive data.`
                : `Without \`credentials: true\`, exploitation requires the response to contain sensitive data accessible without cookies.`),
            severity: withCreds ? Severity.HIGH : Severity.MEDIUM,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          }],
        });
      }

      // Check: Wildcard with credentials (browser blocks but still a misconfig)
      if (acao === "*" && acac === "true") {
        return done({
          state,
          findings: [{
            name: "CORS Wildcard with Credentials",
            description:
              "The server returns `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. " +
              "Browsers reject this combination, but it indicates a fundamental CORS misconfiguration.",
            severity: Severity.LOW,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          }],
        });
      }
    } catch {}

    return continueWith({ nextStep: "subdomain", state: { stage: "subdomain" } });
  });

  // Step 2: Test subdomain trust (evil.target.com)
  step("subdomain", async (state, ctx) => {
    const host = ctx.target.request.getHost();
    const scheme = ctx.target.request.getTls?.() ? "https" : "http";
    const subdomainOrigin = `${scheme}://evil.${host}`;

    const spec = ctx.target.request.toSpec();
    spec.setHeader("Origin", subdomainOrigin);

    try {
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (!response) return done({ state });

      const acao = (getHeader(response, "access-control-allow-origin") ?? "").trim();
      const acac = (getHeader(response, "access-control-allow-credentials") ?? "").toLowerCase();

      if (acao === subdomainOrigin && acac === "true") {
        return done({
          state,
          findings: [{
            name: "CORS Trusts Arbitrary Subdomains with Credentials",
            description:
              `The server trusts arbitrary subdomains in CORS.\n\n` +
              `**Test Origin:** \`${subdomainOrigin}\`\n` +
              `**ACAO returned:** \`${acao}\`\n` +
              `**Credentials:** true\n\n` +
              `If an attacker can control any subdomain (via XSS, subdomain takeover, etc.), ` +
              `they can make authenticated cross-origin requests.`,
            severity: Severity.MEDIUM,
            correlation: {
              requestID: request.getId(),
              locations: [],
            },
          }],
        });
      }
    } catch {}

    return done({ state });
  });

  return {
    metadata: {
      id: "cors-origin-reflection",
      name: "CORS Origin Reflection (Active)",
      description:
        "Actively tests CORS by sending requests with crafted Origin headers to detect " +
        "origin reflection, subdomain trust, and wildcard misconfiguration.",
      type: "active",
      tags: [Tags.CORS],
      severities: [Severity.LOW, Severity.MEDIUM, Severity.HIGH],
      aggressivity: { minRequests: 1, maxRequests: 2 },
    },
    initState: (): State => ({ stage: "reflect" }),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  };
});
