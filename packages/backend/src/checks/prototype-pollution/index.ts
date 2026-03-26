import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { extractParameters, type Parameter } from "../../utils";
import { keyStrategy } from "../../utils/key";

/**
 * v2: Fixed Prototype Pollution
 * - Uses UNIQUE canary value that can't appear in normal responses
 * - Baseline comparison: only flags if canary appears in payload response but not baseline
 * - Confirmation via behavioral change: polluted property alters server behavior (status code, content)
 * - Tests both query string and JSON body vectors
 * - Detects __proto__, constructor.prototype, and Object.assign deep merge
 */

type State = {
  params: Parameter[];
  payIndex: number;
  stage: "query" | "json";
  baselineBody: string;
  baselineCode: number;
};

const CANARY = "pp_canary_" + "x7k9m2";

type PPPayload = {
  queryAppend?: string;
  jsonBody?: string;
  description: string;
};

const QUERY_PAYLOADS: PPPayload[] = [
  { queryAppend: `&__proto__[ppCanary]=${CANARY}`, description: "__proto__ bracket notation" },
  { queryAppend: `&__proto__.ppCanary=${CANARY}`, description: "__proto__ dot notation" },
  { queryAppend: `&constructor[prototype][ppCanary]=${CANARY}`, description: "constructor.prototype bracket" },
  { queryAppend: `&__proto__%5BppCanary%5D=${CANARY}`, description: "__proto__ URL-encoded brackets" },
  // Status-change payloads: if these work, server behavior changes
  { queryAppend: `&__proto__[status]=510`, description: "__proto__ status code pollution" },
  { queryAppend: `&__proto__[statusCode]=510`, description: "__proto__ statusCode pollution" },
];

const JSON_PAYLOADS: PPPayload[] = [
  { jsonBody: `{"__proto__":{"ppCanary":"${CANARY}"}}`, description: "__proto__ in JSON body" },
  { jsonBody: `{"constructor":{"prototype":{"ppCanary":"${CANARY}"}}}`, description: "constructor.prototype in JSON" },
  // Nested merge
  { jsonBody: `{"a":{"__proto__":{"ppCanary":"${CANARY}"}}}`, description: "Nested __proto__ in JSON" },
];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

export default defineCheck<State>(({ step }) => {
  step("collect", (state, ctx) => {
    const params = extractParameters(ctx);
    const baselineBody = getBody(ctx.target.response);
    const baselineCode = ctx.target.response?.getCode?.() ?? 200;
    return continueWith({
      nextStep: "testQuery",
      state: { params, payIndex: 0, stage: "query" as const, baselineBody, baselineCode },
    });
  });

  step("testQuery", async (state, ctx) => {
    if (state.payIndex >= QUERY_PAYLOADS.length) {
      return continueWith({ nextStep: "testJson", state: { ...state, payIndex: 0, stage: "json" as const } });
    }

    const pp = QUERY_PAYLOADS[state.payIndex]!;
    const origQuery = ctx.target.request.getQuery() ?? "";

    try {
      const spec = ctx.target.request.toSpec();
      spec.setQuery(origQuery + pp.queryAppend!);
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const body = getBody(response);
        const code = response.getCode?.() ?? 200;

        // Detection 1: canary value appears in response but not baseline
        if (body.includes(CANARY) && !state.baselineBody.includes(CANARY)) {
          // CRITICAL: Filter out URL reflection. Servers commonly echo the full URL
          // (including our __proto__[ppCanary]=canary query param) in <link>, <a href>,
          // <input value>, canonical tags, etc. This is NOT prototype pollution.
          // Real pollution: canary appears as a standalone value NOT inside a URL context.
          const bodyWithoutUrlReflection = body
            // Remove any attribute value containing both __proto__ and the canary
            .replace(/(?:href|src|action|value|content|data-\w+)\s*=\s*["'][^"']*__proto__[^"']*["']/gi, "")
            // Remove any URL-like string containing the canary
            .replace(/https?:\/\/[^\s"'<>]*pp_canary[^\s"'<>]*/gi, "")
            // Remove query strings containing the canary
            .replace(/\?[^\s"'<>]*pp_canary[^\s"'<>]*/gi, "");

          if (bodyWithoutUrlReflection.includes(CANARY)) {
            return done({ state, findings: [{
              name: "Server-Side Prototype Pollution (Query)",
              description:
                `Prototype pollution detected via query string.\n\n` +
                `**Method:** ${pp.description}\n` +
                `**Canary:** \`${CANARY}\` found in response body outside URL context (absent in baseline)\n\n` +
                `**Impact:** RCE via polluted properties (child_process, VM), privilege escalation, DoS.`,
              severity: Severity.HIGH,
              correlation: { requestID: request.getId(), locations: [] },
            }] });
          }
        }

        // Detection 2: status code changed (status/statusCode pollution)
        if (pp.description.includes("status") && code === 510 && state.baselineCode !== 510) {
          return done({ state, findings: [{
            name: "Server-Side Prototype Pollution (Status Code Change)",
            description:
              `Prototype pollution confirmed: polluting \`__proto__.status\` changed the HTTP status code from ${state.baselineCode} to 510.\n\n` +
              `**Method:** ${pp.description}\n\n` +
              `**Impact:** Confirmed prototype pollution — attacker-controlled properties propagate server-wide.`,
            severity: Severity.CRITICAL,
            correlation: { requestID: request.getId(), locations: [] },
          }] });
        }
      }
    } catch {}

    return continueWith({ nextStep: "testQuery", state: { ...state, payIndex: state.payIndex + 1 } });
  });

  step("testJson", async (state, ctx) => {
    const method = ctx.target.request.getMethod().toUpperCase();
    if (method === "GET" || state.payIndex >= JSON_PAYLOADS.length) return done({ state });

    const jp = JSON_PAYLOADS[state.payIndex]!;

    try {
      const spec = ctx.target.request.toSpec();
      spec.setHeader("Content-Type", "application/json");
      spec.setBody(jp.jsonBody!);
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const body = getBody(response);
        if (body.includes(CANARY) && !state.baselineBody.includes(CANARY)) {
          // Filter URL reflection same as query test
          const cleaned = body
            .replace(/(?:href|src|action|value|content)\s*=\s*["'][^"']*pp_canary[^"']*["']/gi, "")
            .replace(/https?:\/\/[^\s"'<>]*pp_canary[^\s"'<>]*/gi, "");

          if (cleaned.includes(CANARY)) {
            return done({ state, findings: [{
              name: "Server-Side Prototype Pollution (JSON Body)",
              description:
                `Prototype pollution via JSON body merge/deep-copy.\n\n` +
                `**Method:** ${jp.description}\n` +
                `**Canary:** \`${CANARY}\` found in response outside URL context\n\n` +
                `Common in Node.js apps using \`lodash.merge\`, \`jQuery.extend\`, \`Object.assign\` with deep copy.`,
              severity: Severity.HIGH,
              correlation: { requestID: request.getId(), locations: [] },
            }] });
          }
        }
      }
    } catch {}

    return continueWith({ nextStep: "testJson", state: { ...state, payIndex: state.payIndex + 1 } });
  });

  return {
    metadata: {
      id: "prototype-pollution",
      name: "Server-Side Prototype Pollution",
      description: "Tests __proto__ and constructor.prototype injection via query strings and JSON bodies. Uses unique canary values and status code change detection for confirmation.",
      type: "active",
      tags: [Tags.INJECTION, Tags.RCE],
      severities: [Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 1, maxRequests: QUERY_PAYLOADS.length + JSON_PAYLOADS.length },
    },
    initState: (): State => ({ params: [], payIndex: 0, stage: "query" as const, baselineBody: "", baselineCode: 200 }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().build(),
  };
});
