import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Passive File Path Disclosure
 *
 * Detects server filesystem paths leaked in response bodies.
 * These paths reveal the server's OS, installation directory, username,
 * and application structure — aiding targeted attacks.
 */

const PATH_PATTERNS = [
  // Unix/Linux absolute paths with common web roots
  { pattern: /\/(?:var|srv|opt|home|usr|etc|tmp)\/\w[\w./-]{5,80}/g, name: "Unix path", os: "Linux/Unix" },
  { pattern: /\/(?:www|htdocs|html|public_html|webapp|app|sites)\/\w[\w./-]{3,80}/g, name: "Web root path", os: "Linux/Unix" },

  // Windows absolute paths
  { pattern: /[A-Z]:\\(?:Users|Windows|inetpub|Program Files|xampp|wamp|www)\\[\w\\.-]{5,80}/gi, name: "Windows path", os: "Windows" },
  { pattern: /[A-Z]:\\(?:temp|tmp|logs?)\\[\w\\.-]{3,60}/gi, name: "Windows temp path", os: "Windows" },

  // PHP-specific paths in error messages
  { pattern: /in\s+(\/[\w./-]+\.php)\s+on\s+line\s+\d+/gi, name: "PHP error path", os: "Linux" },
  { pattern: /in\s+([A-Z]:\\[\w\\.-]+\.php)\s+on\s+line\s+\d+/gi, name: "PHP error path", os: "Windows" },

  // Python traceback paths
  { pattern: /File\s+"(\/[\w./-]+\.py)",\s+line\s+\d+/g, name: "Python traceback path", os: "Linux" },

  // Java stack trace paths
  { pattern: /at\s+[\w.]+\(([\w]+\.java:\d+)\)/g, name: "Java source reference", os: "any" },

  // .NET paths
  { pattern: /in\s+([A-Z]:\\[\w\\.-]+\.cs):line\s+\d+/gi, name: ".NET source path", os: "Windows" },
  { pattern: /Source File:\s*([\w\\/.:-]+)/gi, name: "ASP.NET source", os: "any" },
];

const TEXT_HINTS = ["text/html", "application/json", "text/plain", "text/xml", "application/xml"];

function isScannable(resp: any): boolean {
  const cts = resp?.getHeader?.("content-type") ?? [];
  return (cts as string[]).some((v: string) => {
    const lower = String(v).toLowerCase();
    // Skip JS/CSS — paths in code files are expected, not disclosure
    if (lower.includes("javascript") || lower.includes("css") || lower.includes("wasm")) return false;
    return TEXT_HINTS.some(h => lower.includes(h));
  });
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, ctx) => {
    const resp = ctx.target.response;
    if (!resp) return done({ state });
    if (!isScannable(resp)) return done({ state });

    // Skip code file extensions
    const path = (ctx.target.request.getPath?.() ?? "").toLowerCase();
    if (/\.(js|mjs|cjs|jsx|ts|tsx|css|scss|map|svg|woff|ttf|png|jpg|gif)(\?|$)/.test(path)) {
      return done({ state });
    }

    const body = resp.getBody?.()?.toText?.() ?? "";
    if (!body || body.length < 20) return done({ state });

    // Only scan first 256KB
    const scanBody = body.slice(0, 256 * 1024);

    const findings: Finding[] = [];
    const seenPaths = new Set<string>();

    for (const pp of PATH_PATTERNS) {
      pp.pattern.lastIndex = 0;
      let m;
      while ((m = pp.pattern.exec(scanBody)) !== null) {
        const path = m[1] ?? m[0];
        const normalized = path.replace(/\\/g, "/").toLowerCase();

        // Skip very short or common false positives
        if (normalized.length < 8) continue;
        if (normalized === "/var/log" || normalized === "/tmp/") continue;
        if (seenPaths.has(normalized)) continue;
        seenPaths.add(normalized);

        if (seenPaths.size <= 5) {
          findings.push({
            name: `${pp.name} Disclosed`,
            description:
              `A server filesystem path was found in the response.\n\n` +
              `**Path:** \`${path}\`\n` +
              `**Type:** ${pp.name} (${pp.os})\n\n` +
              `Disclosed paths reveal the server's OS, directory structure, and username, ` +
              `aiding targeted path traversal, privilege escalation, and social engineering attacks.`,
            severity: Severity.LOW,
            correlation: { requestID: ctx.target.request.getId(), locations: [] },
          });
        }
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "file-path-disclosure",
      name: "File Path Disclosure",
      description:
        "Detects server filesystem paths leaked in response bodies, including Unix/Windows " +
        "paths, web roots, PHP/Python/Java error paths, and .NET source references.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.FILE_DISCLOSURE],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined,
  };
});
