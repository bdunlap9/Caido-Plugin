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
 * v2: Fixed NoSQL Injection
 * - Sends baseline request FIRST to get clean response length
 * - Confirmation: if operator payload changes response, sends INVERSE operator to confirm
 * - Covers MongoDB + CouchDB
 * - $where time-based: measures response time instead of body pattern
 */

type State = {
  params: Parameter[];
  pIndex: number;
  payIndex: number;
  baselineLen: number;
  baselineBody: string;
  baselineTime: number;
};

const NOSQL_ERROR_SIGS = [
  /MongoError/i, /MongoServerError/i, /mongoose.*Error/i,
  /BSON/i, /BSONTypeError/i, /CastError/i,
  /unknown.*operator/i, /BadValue/i,
  /\$[a-z]+.*not.*valid/i, /not a valid.*ObjectId/i,
  /failed to parse/i, /Cannot use.*operator/i,
  // CouchDB
  /invalid_key|no_db_file|bad_request.*selector/i,
];

type Payload = {
  value: string;
  description: string;
  detection: "error" | "length" | "time";
};

const PAYLOADS: Payload[] = [
  // Error-triggering
  { value: '{"$invalid":1}', description: "Invalid operator (error)", detection: "error" },
  { value: "';return true;var a='", description: "JS injection breakout (error)", detection: "error" },

  // Operator injection (length-based — need baseline comparison)
  { value: '{"$gt":""}', description: "MongoDB $gt always-true", detection: "length" },
  { value: '{"$ne":"__nosql_impossible_value__"}', description: "MongoDB $ne bypass", detection: "length" },
  { value: '{"$regex":".*"}', description: "MongoDB $regex wildcard", detection: "length" },

  // Bracket notation (query string)
  { value: "[$gt]=", description: "$gt bracket notation", detection: "length" },
  { value: "[$ne]=__nosql_impossible_value__", description: "$ne bracket notation", detection: "length" },

  // $where time-based (5 second sleep)
  { value: '{"$where":"sleep(5000)||true"}', description: "MongoDB $where sleep (time)", detection: "time" },

  // CouchDB
  { value: '{"$gt":null}', description: "CouchDB selector $gt:null", detection: "length" },
];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

export default defineCheck<State>(({ step }) => {
  step("collect", (state, ctx) => {
    const params = extractParameters(ctx);
    if (params.length === 0) return done({ state });
    const baseBody = getBody(ctx.target.response);
    const baseTime = ctx.target.response?.getRoundtripTime?.() ?? 0;
    return continueWith({
      nextStep: "test",
      state: { params, pIndex: 0, payIndex: 0, baselineLen: baseBody.length, baselineBody: baseBody.slice(0, 500), baselineTime: baseTime },
    });
  });

  step("test", async (state, ctx) => {
    if (state.pIndex >= state.params.length) return done({ state });
    const param = state.params[state.pIndex]!;
    if (state.payIndex >= PAYLOADS.length) {
      return continueWith({ nextStep: "test", state: { ...state, pIndex: state.pIndex + 1, payIndex: 0 } });
    }

    const payload = PAYLOADS[state.payIndex]!;
    const testValue = payload.value.startsWith("{") || payload.value.startsWith("[")
      ? payload.value
      : param.value + payload.value;

    try {
      const spec = createRequestWithParameter(ctx, param, testValue);
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (!response) return continueWith({ nextStep: "test", state: { ...state, payIndex: state.payIndex + 1 } });

      const body = getBody(response);
      const time = response.getRoundtripTime?.() ?? 0;

      // ── Error-based detection ──
      if (payload.detection === "error") {
        const hit = NOSQL_ERROR_SIGS.find(r => r.test(body));
        // Verify error wasn't in baseline
        if (hit && !hit.test(state.baselineBody)) {
          return done({ state, findings: [{
            name: `NoSQL Injection (Error) in '${param.name}'`,
            description:
              `Parameter \`${param.name}\` (${param.source}) triggered a NoSQL error.\n\n` +
              `**Payload:** \`${testValue}\`\n**Error:** matched \`${hit.source}\``,
            severity: Severity.HIGH,
            correlation: { requestID: request.getId(), locations: [] },
          }] });
        }
      }

      // ── Length-based detection with confirmation ──
      if (payload.detection === "length") {
        const lenDiff = Math.abs(body.length - state.baselineLen);
        const threshold = Math.max(state.baselineLen * 0.3, 50);
        if (lenDiff > threshold && body.length > state.baselineLen) {
          // Confirmation: send a definitely-false condition
          const falseValue = '{"$gt":"__nosql_impossible_match_12345__"}';
          const confirmSpec = createRequestWithParameter(ctx, param, falseValue);
          try {
            const { response: confirmResp } = await ctx.sdk.requests.send(confirmSpec);
            const confirmBody = getBody(confirmResp);
            const confirmLen = confirmBody.length;
            // If false-condition response is small like baseline, but true-condition was big → confirmed
            if (Math.abs(confirmLen - state.baselineLen) < threshold) {
              return done({ state, findings: [{
                name: `NoSQL Injection (Operator) in '${param.name}'`,
                description:
                  `Parameter \`${param.name}\` (${param.source}) is vulnerable to NoSQL operator injection.\n\n` +
                  `**Payload:** \`${testValue}\`\n**Method:** ${payload.description}\n` +
                  `**Baseline:** ${state.baselineLen} bytes → **Payload:** ${body.length} bytes → **Confirm (false):** ${confirmLen} bytes\n\n` +
                  `The always-true condition returned more data while the always-false returned baseline-sized data, confirming injection.`,
                severity: Severity.CRITICAL,
                correlation: { requestID: request.getId(), locations: [] },
              }] });
            }
          } catch {}
        }
      }

      // ── Time-based detection ──
      if (payload.detection === "time") {
        const delta = time - state.baselineTime;
        if (delta > 4000) {
          // Confirm with second request
          try {
            const { response: confirmResp } = await ctx.sdk.requests.send(spec);
            const confirmTime = confirmResp?.getRoundtripTime?.() ?? 0;
            if (confirmTime - state.baselineTime > 4000) {
              return done({ state, findings: [{
                name: `NoSQL Injection ($where Time-Based) in '${param.name}'`,
                description:
                  `Parameter \`${param.name}\` triggered a ${delta}ms delay via MongoDB \`$where\` sleep.\n\n` +
                  `**Payload:** \`${testValue}\`\n**Baseline:** ${state.baselineTime}ms, **Payload:** ${time}ms, **Confirm:** ${confirmTime}ms`,
                severity: Severity.CRITICAL,
                correlation: { requestID: request.getId(), locations: [] },
              }] });
            }
          } catch {}
        }
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, payIndex: state.payIndex + 1 } });
  });

  return {
    metadata: {
      id: "nosql-injection",
      name: "NoSQL Injection (MongoDB/CouchDB)",
      description: "Detects NoSQL injection via error signatures, length-differential with confirmation, and $where time-based sleep. Covers MongoDB and CouchDB.",
      type: "active",
      tags: [Tags.INJECTION, Tags.INPUT_VALIDATION],
      severities: [Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 1, maxRequests: "Infinity" },
    },
    initState: (): State => ({ params: [], pIndex: 0, payIndex: 0, baselineLen: 0, baselineBody: "", baselineTime: 0 }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build(),
    when: (t) => hasParameters(t),
  };
});
