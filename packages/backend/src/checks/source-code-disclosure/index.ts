import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * v2: Fixed Source Code Disclosure — eliminates false positives
 *
 * ONLY scans responses where server code is UNEXPECTED:
 *   ✅ text/html, application/json, text/plain, text/xml
 *   ❌ application/javascript, text/css (code is expected there)
 *   ❌ .js, .mjs, .css, .map files (code is expected there)
 *
 * All patterns require very specific multi-signal context, not just keywords.
 */

type SourcePattern = {
  pattern: RegExp;
  language: string;
  severity: Severity;
  /** Extra validation: must also pass this test on the match to confirm */
  validate?: (match: string, fullBody: string) => boolean;
};

const SOURCE_PATTERNS: SourcePattern[] = [
  // ── PHP (very reliable — <?php is almost never in non-PHP responses) ──
  { pattern: /<\?php\s/i, language: "PHP (<?php tag)", severity: Severity.HIGH },
  { pattern: /\$_(?:GET|POST|REQUEST|SESSION|COOKIE|SERVER)\s*\[/g, language: "PHP superglobal", severity: Severity.HIGH },
  {
    pattern: /(?:include|require)(?:_once)?\s*\(\s*["'](?:\/|\.\.\/|[a-z])/g,
    language: "PHP include/require with path",
    severity: Severity.HIGH,
    // Must have a file extension to be a real include
    validate: (m) => /\.(php|inc|tpl|class)['"]/.test(m) || /\//.test(m),
  },
  { pattern: /mysql_(?:connect|query|fetch_array|real_escape_string)\s*\(/g, language: "PHP legacy mysql_ function", severity: Severity.HIGH },

  // ── ASP.NET (very reliable — these directives never appear in normal HTML) ──
  { pattern: /<%@\s*Page\s+Language\s*=/i, language: "ASP.NET Page directive", severity: Severity.HIGH },
  { pattern: /<script[^>]+runat\s*=\s*["']server["']/i, language: "ASP.NET server-side script", severity: Severity.HIGH },

  // ── JSP (require Language attribute to avoid FPs from template engines) ──
  {
    pattern: /<%@\s*page\s+(?:language|contentType|import)\s*=/i,
    language: "JSP page directive",
    severity: Severity.HIGH,
  },

  // ── Python/Django/Flask (require import + from for specificity) ──
  {
    pattern: /^from\s+(?:django|flask|fastapi|tornado|pyramid)\.\w+\s+import\s+\w+/im,
    language: "Python web framework import",
    severity: Severity.HIGH,
  },
  {
    pattern: /(?:SECRET_KEY|DATABASES)\s*=\s*[{'"]/i,
    language: "Django/Flask settings",
    severity: Severity.CRITICAL,
    // Must also have another Django signal
    validate: (_m, body) => /django|INSTALLED_APPS|MIDDLEWARE|ALLOWED_HOSTS/i.test(body),
  },

  // ── Ruby/Rails (require inheritance syntax for specificity) ──
  {
    pattern: /class\s+\w+Controller\s*<\s*ApplicationController/i,
    language: "Rails controller class",
    severity: Severity.HIGH,
  },

  // ── Node.js env secrets (only when NOT in a JS response) ──
  {
    pattern: /process\.env\.(?:SECRET_KEY|DB_PASSWORD|API_SECRET|JWT_SECRET|PRIVATE_KEY)\b/g,
    language: "Node.js process.env secret",
    severity: Severity.CRITICAL,
  },

  // ── Raw SQL (very strict: must look like actual executable SQL, not just keywords) ──
  {
    pattern: /(?:SELECT\s+[\w.*,\s]+\s+FROM\s+\w+\s+WHERE|INSERT\s+INTO\s+\w+\s*\(|UPDATE\s+\w+\s+SET\s+\w+\s*=|DELETE\s+FROM\s+\w+\s+WHERE)/i,
    language: "Raw SQL query",
    severity: Severity.MEDIUM,
    // Must NOT be inside a JS string assignment (which would be expected client-side SQL like IndexedDB)
    validate: (m, body) => {
      // If the SQL appears inside a quoted string in JS, it's probably intentional client-side
      const idx = body.indexOf(m);
      if (idx > 0) {
        const before = body.slice(Math.max(0, idx - 50), idx);
        // Skip if preceded by a JS string assignment
        if (/[=:]\s*['"`]$/.test(before)) return false;
        // Skip if preceded by a SQL comment marker (documentation)
        if (/--\s*$/.test(before)) return false;
      }
      return true;
    },
  },

  // ── Connection strings (very specific format) ──
  {
    pattern: /(?:Server|Data Source)\s*=\s*[\w.\\]+;\s*(?:Database|Initial Catalog)\s*=\s*\w+;\s*(?:User Id|Uid)\s*=\s*\w+;\s*(?:Password|Pwd)\s*=/i,
    language: "Database connection string",
    severity: Severity.CRITICAL,
  },
];

/** Content types where code IS expected — skip these entirely */
function isCodeContentType(resp: any): boolean {
  const cts = resp?.getHeader?.("content-type") ?? [];
  return (cts as string[]).some((v: string) => {
    const lower = String(v).toLowerCase();
    return lower.includes("javascript") ||
           lower.includes("ecmascript") ||
           lower.includes("text/css") ||
           lower.includes("wasm") ||
           lower.includes("typescript");
  });
}

/** Content types where code is UNEXPECTED — scan these */
function isScannable(resp: any): boolean {
  const cts = resp?.getHeader?.("content-type") ?? [];
  return (cts as string[]).some((v: string) => {
    const lower = String(v).toLowerCase();
    return lower.includes("text/html") ||
           lower.includes("application/json") ||
           lower.includes("text/plain") ||
           lower.includes("text/xml") ||
           lower.includes("application/xml") ||
           lower.includes("application/xhtml");
  });
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, ctx) => {
    const resp = ctx.target.response;
    if (!resp) return done({ state });

    // CRITICAL: Skip JS/CSS responses — code there is normal, not disclosure
    if (isCodeContentType(resp)) return done({ state });

    // Only scan content types where server code would be unexpected
    if (!isScannable(resp)) return done({ state });

    // Skip paths that are obviously code files
    const path = (ctx.target.request.getPath?.() ?? "").toLowerCase();
    if (/\.(js|mjs|cjs|jsx|ts|tsx|css|scss|less|map|woff|ttf|svg|png|jpg)(\?|$)/.test(path)) {
      return done({ state });
    }

    const body = resp.getBody?.()?.toText?.() ?? "";
    if (!body || body.length < 30) return done({ state });

    const scanBody = body.slice(0, 256 * 1024);
    const findings: Finding[] = [];
    const seenLanguages = new Set<string>();

    for (const sp of SOURCE_PATTERNS) {
      if (seenLanguages.has(sp.language)) continue;

      sp.pattern.lastIndex = 0;
      const match = sp.pattern.exec(scanBody);
      if (match) {
        // Run optional validation
        if (sp.validate && !sp.validate(match[0], scanBody)) continue;

        seenLanguages.add(sp.language);
        const snippet = match[0].slice(0, 80);
        findings.push({
          name: `Source Code Disclosure: ${sp.language}`,
          description:
            `Server-side code (${sp.language}) detected in a response that should not contain code.\n\n` +
            `**Content-Type:** \`${(resp.getHeader?.("content-type")?.[0] ?? "unknown")}\`\n` +
            `**Match:** \`${snippet}${match[0].length > 80 ? "..." : ""}\`\n\n` +
            `Exposed source code reveals application logic, credentials, and internal paths.`,
          severity: sp.severity,
          correlation: { requestID: ctx.target.request.getId(), locations: [] },
        });
        if (findings.length >= 3) break;
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "source-code-disclosure",
      name: "Source Code Disclosure",
      description:
        "Detects leaked server-side source code in HTML/JSON/text responses. " +
        "Skips JS/CSS responses where code is expected. Covers PHP, ASP.NET, JSP, " +
        "Python/Django, Ruby/Rails, Node.js env secrets, raw SQL, and connection strings.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.FILE_DISCLOSURE],
      severities: [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined,
  };
});
