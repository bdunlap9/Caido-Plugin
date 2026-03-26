import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { extractParameters, hasParameters, type Parameter } from "../../utils";
import { keyStrategy } from "../../utils/key";

/**
 * HTTP Parameter Pollution (HPP)
 *
 * Sends requests with duplicate parameters to detect server-side handling differences.
 * Different servers handle duplicates differently:
 * - PHP: uses last value
 * - ASP.NET: concatenates with comma
 * - JSP/Tomcat: uses first value
 * - Python/Flask: uses first value
 *
 * If the response changes when a parameter is duplicated with a different value,
 * it indicates HPP potential — attackers can bypass WAFs or alter business logic.
 */

type State = {
  params: Parameter[];
  pIndex: number;
  baselineBody: string;
};

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

export default defineCheck<State>(({ step }) => {
  step("collect", (state, ctx) => {
    const params = extractParameters(ctx).filter(p => p.source === "query");
    if (params.length === 0) return done({ state });

    const baselineBody = getBody(ctx.target.response);
    return continueWith({
      nextStep: "test",
      state: { params, pIndex: 0, baselineBody },
    });
  });

  step("test", async (state, ctx) => {
    if (state.pIndex >= state.params.length) return done({ state });
    const param = state.params[state.pIndex]!;

    // Build URL with duplicated parameter: original + HPP value
    const origQuery = ctx.target.request.getQuery() ?? "";
    const hppValue = "hpp_test_" + Math.random().toString(36).slice(2, 8);
    const newQuery = origQuery + `&${encodeURIComponent(param.name)}=${hppValue}`;

    try {
      const spec = ctx.target.request.toSpec();
      spec.setQuery(newQuery);
      const { request, response } = await ctx.sdk.requests.send(spec);

      if (response) {
        const body = getBody(response);

        // Check if the HPP test value appears in the response (server used our duplicate)
        if (body.includes(hppValue)) {
          // Filter URL reflection: strip URLs/query strings that contain the test value
          // (servers commonly echo full URLs in canonical, alternate, breadcrumb links)
          const cleaned = body
            .replace(/(?:href|src|action|value|content)\s*=\s*["'][^"']*hpp_test_[^"']*["']/gi, "")
            .replace(/https?:\/\/[^\s"'<>]*hpp_test_[^\s"'<>]*/gi, "")
            .replace(/\?[^\s"'<>]*hpp_test_[^\s"'<>]*/gi, "");

          if (cleaned.includes(hppValue)) {
            return continueWith({
              nextStep: "test",
              state: { ...state, pIndex: state.pIndex + 1 },
              findings: [{
                name: `HTTP Parameter Pollution in '${param.name}'`,
                description:
                  `Parameter \`${param.name}\` is susceptible to HTTP Parameter Pollution.\n\n` +
                  `When duplicated with a second value (\`${hppValue}\`), the server used or reflected ` +
                  `the injected value outside of URL context.\n\n` +
                  `**Original value:** \`${param.value}\`\n` +
                  `**Injected duplicate:** \`${hppValue}\`\n\n` +
                  `**Impact:** HPP can bypass WAF rules, alter application logic, override security ` +
                  `parameters (e.g., price, role), and facilitate injection attacks.`,
                severity: Severity.MEDIUM,
                correlation: { requestID: request.getId(), locations: [] },
              }],
            });
          }
        }
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, pIndex: state.pIndex + 1 } });
  });

  return {
    metadata: {
      id: "http-param-pollution",
      name: "HTTP Parameter Pollution",
      description:
        "Tests for HTTP Parameter Pollution by sending duplicate query parameters and checking " +
        "if the server processes the injected value, which can bypass WAFs and alter logic.",
      type: "active",
      tags: [Tags.INJECTION, Tags.INPUT_VALIDATION],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 1, maxRequests: "Infinity" },
    },
    initState: (): State => ({ params: [], pIndex: 0, baselineBody: "" }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build(),
    when: (t) => hasParameters(t),
  };
});
