import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import {
  createRequestWithParameter,
  extractParameters,
  hasParameters,
  type Parameter,
} from "../../utils";
import { keyStrategy } from "../../utils/key";

/**
 * Active CRLF Injection / HTTP Response Splitting
 *
 * Injects CRLF sequences (\r\n) into parameters and checks if a custom header
 * appears in the response. If so, the attacker can inject arbitrary HTTP headers,
 * enabling XSS via injected Content-Type, session fixation via injected Set-Cookie, etc.
 */

type State = {
  params: Parameter[];
  pIndex: number;
  payIndex: number;
};

const INJECTED_HEADER = "X-CRLF-Test";
const INJECTED_VALUE = "crlf-injected";

const PAYLOADS = [
  `\r\n${INJECTED_HEADER}: ${INJECTED_VALUE}`,
  `%0d%0a${INJECTED_HEADER}:%20${INJECTED_VALUE}`,
  `%0D%0A${INJECTED_HEADER}:%20${INJECTED_VALUE}`,
  `%E5%98%8A%E5%98%8D${INJECTED_HEADER}:%20${INJECTED_VALUE}`,  // UTF-8 encoded CRLF
  `\n${INJECTED_HEADER}: ${INJECTED_VALUE}`,
  `%0a${INJECTED_HEADER}:%20${INJECTED_VALUE}`,
];

function getHeader(resp: any, name: string): string | undefined {
  try {
    const v = resp?.getHeader?.(name);
    return Array.isArray(v) ? v[0] : v;
  } catch { return undefined; }
}

export default defineCheck<State>(({ step }) => {
  step("collect", (state, ctx) => {
    const params = extractParameters(ctx);
    if (params.length === 0) return done({ state });
    return continueWith({ nextStep: "test", state: { params, pIndex: 0, payIndex: 0 } });
  });

  step("test", async (state, ctx) => {
    if (state.pIndex >= state.params.length) return done({ state });
    const param = state.params[state.pIndex]!;

    if (state.payIndex >= PAYLOADS.length) {
      return continueWith({
        nextStep: "test",
        state: { ...state, pIndex: state.pIndex + 1, payIndex: 0 },
      });
    }

    const payload = PAYLOADS[state.payIndex]!;
    const testValue = String(param.value ?? "") + payload;

    try {
      const spec = createRequestWithParameter(ctx, param, testValue);
      const { request, response } = await ctx.sdk.requests.send(spec);

      if (response) {
        // Check if our injected header appears in the response
        const injected = getHeader(response, INJECTED_HEADER);
        if (injected && injected.includes(INJECTED_VALUE)) {
          return done({
            state,
            findings: [{
              name: `CRLF Injection in '${param.name}'`,
              description:
                `Parameter \`${param.name}\` (${param.source}) is vulnerable to CRLF injection.\n\n` +
                `A \\r\\n sequence injected into the parameter caused a custom header to appear in the response.\n\n` +
                `**Payload:** \`${payload.replace(/\r/g, "\\r").replace(/\n/g, "\\n")}\`\n` +
                `**Injected header:** \`${INJECTED_HEADER}: ${INJECTED_VALUE}\`\n\n` +
                `**Impact:**\n` +
                `- **HTTP Response Splitting** — inject arbitrary response headers\n` +
                `- **XSS** — inject \`Content-Type: text/html\` + body\n` +
                `- **Session fixation** — inject \`Set-Cookie\` header\n` +
                `- **Cache poisoning** — poison shared cache with injected content`,
              severity: Severity.HIGH,
              correlation: { requestID: request.getId(), locations: [] },
            }],
          });
        }

        // Also check if CRLF appears in Location header (redirect-based injection)
        const location = getHeader(response, "location") ?? "";
        if (location.includes(INJECTED_VALUE)) {
          return done({
            state,
            findings: [{
              name: `CRLF Injection in redirect via '${param.name}'`,
              description:
                `Parameter \`${param.name}\` allows CRLF injection into the Location redirect header.\n\n` +
                `**Payload:** \`${payload.replace(/\r/g, "\\r").replace(/\n/g, "\\n")}\``,
              severity: Severity.HIGH,
              correlation: { requestID: request.getId(), locations: [] },
            }],
          });
        }
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, payIndex: state.payIndex + 1 } });
  });

  return {
    metadata: {
      id: "crlf-injection",
      name: "CRLF Injection / HTTP Response Splitting",
      description:
        "Tests for CRLF injection by injecting \\r\\n sequences into parameters and checking " +
        "if custom headers appear in the response. Covers raw CRLF, URL-encoded, and UTF-8 encoded variants.",
      type: "active",
      tags: [Tags.INJECTION],
      severities: [Severity.HIGH],
      aggressivity: { minRequests: 1, maxRequests: "Infinity" },
    },
    initState: (): State => ({ params: [], pIndex: 0, payIndex: 0 }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build(),
    when: (t) => hasParameters(t),
  };
});
