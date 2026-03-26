import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Actively tests for dangerous HTTP methods:
 * - TRACE: Can be used for Cross-Site Tracing (XST) to steal cookies
 * - PUT: May allow file upload / overwrite
 * - DELETE: May allow file deletion
 *
 * Sends an OPTIONS request first, then verifies with actual method requests.
 */

type State = {
  methodsToTest: string[];
  mIndex: number;
};

const DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE"];

export default defineCheck<State>(({ step }) => {

  step("options", async (state, ctx) => {
    // First send OPTIONS to see what's advertised
    const spec = ctx.target.request.toSpec();
    spec.setMethod("OPTIONS");
    spec.setBody(undefined as any);

    try {
      const { response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const allow = (response.getHeader?.("allow")?.[0] ?? "").toUpperCase();
        const accessAllow = (response.getHeader?.("access-control-allow-methods")?.[0] ?? "").toUpperCase();
        const combined = allow + " " + accessAllow;

        // Filter to only test methods that appear advertised (or test all if no Allow header)
        const methodsToTest = combined.trim()
          ? DANGEROUS_METHODS.filter(m => combined.includes(m))
          : DANGEROUS_METHODS;

        if (methodsToTest.length === 0) return done({ state });

        return continueWith({
          nextStep: "testMethod",
          state: { methodsToTest, mIndex: 0 },
        });
      }
    } catch {}

    // If OPTIONS fails, test all methods
    return continueWith({
      nextStep: "testMethod",
      state: { methodsToTest: [...DANGEROUS_METHODS], mIndex: 0 },
    });
  });

  step("testMethod", async (state, ctx) => {
    if (state.mIndex >= state.methodsToTest.length) return done({ state });

    const method = state.methodsToTest[state.mIndex]!;
    const spec = ctx.target.request.toSpec();
    spec.setMethod(method);

    // For TRACE, don't send a body
    if (method === "TRACE") {
      spec.setBody(undefined as any);
    }

    try {
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const code = response.getCode();

        // TRACE: Check if the server echoes back the request
        if (method === "TRACE" && code === 200) {
          const body = response.getBody?.()?.toText?.() ?? "";
          const ct = (response.getHeader?.("content-type")?.[0] ?? "").toLowerCase();
          if (ct.includes("message/http") || body.includes("TRACE /")) {
            return continueWith({
              nextStep: "testMethod",
              state: { ...state, mIndex: state.mIndex + 1 },
              findings: [{
                name: "TRACE Method Enabled (Cross-Site Tracing)",
                description:
                  "The server responds to `TRACE` requests by echoing back the request, " +
                  "including headers like `Cookie` and `Authorization`. This enables **Cross-Site " +
                  "Tracing (XST)** attacks that can steal credentials even when `HttpOnly` cookies are set.\n\n" +
                  "**Recommendation:** Disable the TRACE method on the web server.",
                severity: Severity.MEDIUM,
                correlation: {
                  requestID: request.getId(),
                  locations: [],
                },
              }],
            });
          }
        }

        // PUT/DELETE: Check if the server accepts these methods (2xx response)
        if ((method === "PUT" || method === "DELETE") && code >= 200 && code < 300) {
          return continueWith({
            nextStep: "testMethod",
            state: { ...state, mIndex: state.mIndex + 1 },
            findings: [{
              name: `${method} Method Enabled`,
              description:
                `The server accepts \`${method}\` requests and returned a ${code} status. ` +
                `This method can be dangerous if not properly authenticated, potentially allowing ` +
                `${method === "PUT" ? "file upload or overwrite" : "resource deletion"}.\n\n` +
                `**Recommendation:** Disable ${method} if not needed, or ensure proper authentication/authorization.`,
              severity: Severity.LOW,
              correlation: {
                requestID: request.getId(),
                locations: [],
              },
            }],
          });
        }
      }
    } catch {}

    return continueWith({
      nextStep: "testMethod",
      state: { ...state, mIndex: state.mIndex + 1 },
    });
  });

  return {
    metadata: {
      id: "insecure-methods",
      name: "Insecure HTTP Methods",
      description:
        "Tests for dangerous HTTP methods (TRACE, PUT, DELETE) that may enable " +
        "Cross-Site Tracing, file upload, or resource deletion.",
      type: "active",
      tags: [Tags.SECURITY_HEADERS, Tags.INFO],
      severities: [Severity.LOW, Severity.MEDIUM],
      aggressivity: { minRequests: 1, maxRequests: 4 },
    },
    initState: (): State => ({ methodsToTest: [], mIndex: 0 }),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
  };
});
