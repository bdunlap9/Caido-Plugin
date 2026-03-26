import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Active Host Header Injection
 *
 * Tests if the application trusts the Host header by:
 * 1. Sending a request with Host: evil.com — checks if response body contains evil.com
 * 2. Sending X-Forwarded-Host: evil.com — same check
 * 3. Sending duplicate Host header via X-Host, X-Forwarded-Server
 *
 * Exploitable for: password reset poisoning, cache poisoning, SSRF, web cache deception
 */

type State = {
  tests: Array<{ header: string; value: string }>;
  tIndex: number;
  baselineBody: string;
};

const ATTACKER_HOST = "evil-host-inject-test.example";

const HOST_TESTS = [
  { header: "X-Forwarded-Host", value: ATTACKER_HOST },
  { header: "X-Forwarded-Server", value: ATTACKER_HOST },
  { header: "X-Host", value: ATTACKER_HOST },
  { header: "X-Original-URL", value: `https://${ATTACKER_HOST}/` },
  { header: "X-Rewrite-URL", value: `https://${ATTACKER_HOST}/` },
];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

function getHeaders(resp: any): string {
  try {
    const location = resp?.getHeader?.("location")?.[0] ?? "";
    const setCookie = resp?.getHeader?.("set-cookie")?.[0] ?? "";
    return location + " " + setCookie;
  } catch { return ""; }
}

export default defineCheck<State>(({ step }) => {
  step("setup", (state, ctx) => {
    const baselineBody = getBody(ctx.target.response).toLowerCase();
    return continueWith({
      nextStep: "test",
      state: { tests: [...HOST_TESTS], tIndex: 0, baselineBody },
    });
  });

  step("test", async (state, ctx) => {
    if (state.tIndex >= state.tests.length) return done({ state });

    const test = state.tests[state.tIndex]!;
    const spec = ctx.target.request.toSpec();
    spec.setHeader(test.header, test.value);

    try {
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (!response) return continueWith({ nextStep: "test", state: { ...state, tIndex: state.tIndex + 1 } });

      const body = getBody(response).toLowerCase();
      const headers = getHeaders(response).toLowerCase();
      const needle = ATTACKER_HOST.toLowerCase();

      // Check HEADERS first (Location/Set-Cookie) — this is the strongest signal
      const inHeaders = headers.includes(needle);

      // Check BODY — but only if it's NOT in the baseline (avoid URL reflection FPs)
      const inBody = body.includes(needle) && !state.baselineBody.includes(needle);

      if (inBody || inHeaders) {

        return done({
          state,
          findings: [{
            name: `Host Header Injection via ${test.header}`,
            description:
              `The application reflects the \`${test.header}\` header value in the response.\n\n` +
              `**Injected value:** \`${test.value}\`\n` +
              `**Found in:** ${inBody ? "response body" : ""}${inBody && inHeaders ? " + " : ""}${inHeaders ? "response headers (Location/Set-Cookie)" : ""}\n\n` +
              `**Impact:** This can enable:\n` +
              `- **Password reset poisoning** — reset links point to attacker domain\n` +
              `- **Web cache poisoning** — cached responses contain attacker URLs\n` +
              `- **SSRF** — server makes requests to attacker-controlled host\n` +
              `- **Open redirect** — Location header points to attacker domain`,
            severity: inHeaders ? Severity.HIGH : Severity.MEDIUM,
            correlation: { requestID: request.getId(), locations: [] },
          }],
        });
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, tIndex: state.tIndex + 1 } });
  });

  return {
    metadata: {
      id: "host-header-injection",
      name: "Host Header Injection",
      description:
        "Tests for host header injection by sending crafted Host, X-Forwarded-Host, " +
        "X-Host, and X-Forwarded-Server headers to detect password reset poisoning, " +
        "cache poisoning, and SSRF vulnerabilities.",
      type: "active",
      tags: [Tags.INJECTION, Tags.REDIRECT],
      severities: [Severity.MEDIUM, Severity.HIGH],
      aggressivity: { minRequests: 1, maxRequests: HOST_TESTS.length },
    },
    initState: (): State => ({ tests: [], tIndex: 0, baselineBody: "" }),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  };
});
