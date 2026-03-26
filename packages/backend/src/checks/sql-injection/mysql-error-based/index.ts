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
 * Multi-Database Error-Based SQL Injection
 *
 * Improvements over original:
 * 1. Detects MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and generic ODBC errors
 * 2. Baseline comparison: checks if error exists in the ORIGINAL response first
 * 3. Focused payload set: 12 payloads instead of 27 overlapping ones
 * 4. Encoding variations for WAF bypass
 * 5. Reports which database engine was detected
 * 6. Uses MEDIUM severity for weak signals, CRITICAL for confirmed errors
 */

type State = {
  params: Parameter[];
  pIndex: number;
  payIndex: number;
  baselineErrors: string[];  // errors already present in original response
};

const SAFE_MAX_BODY = 256 * 1024;
const TEXT_HINTS = ["text/", "json", "xml", "javascript", "x-www-form"];

// ═══════════════════════════════════════════════════════════════════════════════
// Error Signatures — organized by database engine
// ═══════════════════════════════════════════════════════════════════════════════

type ErrorSignature = {
  pattern: string;  // lowercase substring to search for
  db: string;       // database engine name
  confidence: "high" | "medium";
};

const ERROR_SIGNATURES: ErrorSignature[] = [
  // ── MySQL / MariaDB ──
  { pattern: "you have an error in your sql syntax", db: "MySQL", confidence: "high" },
  { pattern: "mysql server version for the right syntax", db: "MySQL", confidence: "high" },
  { pattern: "mariadb server version for the right syntax", db: "MariaDB", confidence: "high" },
  { pattern: "warning: mysql_", db: "MySQL", confidence: "high" },
  { pattern: "warning: mysqli_", db: "MySQL", confidence: "high" },
  { pattern: "mysqlclient.", db: "MySQL", confidence: "medium" },
  { pattern: "com.mysql.jdbc", db: "MySQL", confidence: "high" },
  { pattern: "unknown column", db: "MySQL", confidence: "medium" },
  { pattern: "mysql_fetch_", db: "MySQL", confidence: "high" },
  { pattern: "mysql_num_rows", db: "MySQL", confidence: "high" },
  { pattern: "not a valid mysql result", db: "MySQL", confidence: "high" },
  { pattern: "truncated incorrect", db: "MySQL", confidence: "medium" },

  // ── PostgreSQL ──
  { pattern: "pg_query():", db: "PostgreSQL", confidence: "high" },
  { pattern: "pg_exec():", db: "PostgreSQL", confidence: "high" },
  { pattern: "pgsql error:", db: "PostgreSQL", confidence: "high" },
  { pattern: 'error:  unterminated quoted string at or near "', db: "PostgreSQL", confidence: "high" },
  { pattern: "syntax error at or near", db: "PostgreSQL", confidence: "high" },
  { pattern: "invalid input syntax for type", db: "PostgreSQL", confidence: "high" },
  { pattern: "org.postgresql.util.psqlexception", db: "PostgreSQL", confidence: "high" },
  { pattern: "error:  column", db: "PostgreSQL", confidence: "medium" },
  { pattern: "pgexecutor.execute", db: "PostgreSQL", confidence: "high" },
  { pattern: "psycopg2.errors", db: "PostgreSQL", confidence: "high" },

  // ── Microsoft SQL Server ──
  { pattern: "unclosed quotation mark after the character string", db: "MSSQL", confidence: "high" },
  { pattern: "incorrect syntax near", db: "MSSQL", confidence: "high" },
  { pattern: "microsoft ole db provider for sql server", db: "MSSQL", confidence: "high" },
  { pattern: "microsoft sql native client error", db: "MSSQL", confidence: "high" },
  { pattern: "[sql server]", db: "MSSQL", confidence: "high" },
  { pattern: "mssql_query()", db: "MSSQL", confidence: "high" },
  { pattern: "sqlsrv_query()", db: "MSSQL", confidence: "high" },
  { pattern: "system.data.sqlclient.sqlerror", db: "MSSQL", confidence: "high" },
  { pattern: "conversion failed when converting", db: "MSSQL", confidence: "medium" },
  { pattern: "operand type clash:", db: "MSSQL", confidence: "medium" },

  // ── Oracle ──
  { pattern: "ora-00933:", db: "Oracle", confidence: "high" },
  { pattern: "ora-06512:", db: "Oracle", confidence: "high" },
  { pattern: "ora-00936:", db: "Oracle", confidence: "high" },
  { pattern: "ora-00907:", db: "Oracle", confidence: "high" },
  { pattern: "ora-01756:", db: "Oracle", confidence: "high" },
  { pattern: "oracle error", db: "Oracle", confidence: "medium" },
  { pattern: "oracle.jdbc", db: "Oracle", confidence: "high" },
  { pattern: "quoted string not properly terminated", db: "Oracle", confidence: "high" },

  // ── SQLite ──
  { pattern: "sqlite3.operationalerror:", db: "SQLite", confidence: "high" },
  { pattern: "sqlite_error", db: "SQLite", confidence: "high" },
  { pattern: "near \"\": syntax error", db: "SQLite", confidence: "high" },
  { pattern: "unrecognized token:", db: "SQLite", confidence: "high" },
  { pattern: "sqlite.exception", db: "SQLite", confidence: "high" },
  { pattern: "system.data.sqlite.sqliteexception", db: "SQLite", confidence: "high" },

  // ── Generic ODBC / JDBC / PDO ──
  { pattern: "[odbc sql server driver]", db: "ODBC/MSSQL", confidence: "high" },
  { pattern: "sqlstate[42000]", db: "Generic SQL", confidence: "high" },
  { pattern: "sqlstate[hy000]", db: "Generic SQL", confidence: "high" },
  { pattern: "sqlstate[42s22]", db: "Generic SQL", confidence: "high" },
  { pattern: "sqlexception", db: "Generic SQL", confidence: "medium" },
  { pattern: "pdo::query", db: "PDO/PHP", confidence: "high" },
  { pattern: "pdoexception", db: "PDO/PHP", confidence: "high" },
  { pattern: "operand should contain", db: "Generic SQL", confidence: "medium" },
  { pattern: "near '", db: "Generic SQL", confidence: "medium" },
];

// ═══════════════════════════════════════════════════════════════════════════════
// Payloads — focused set covering string/numeric/comment contexts
// ═══════════════════════════════════════════════════════════════════════════════

const PAYLOADS = [
  // ── String context terminators ──
  "'",                       // Single quote (most common)
  '"',                       // Double quote
  "\\",                      // Backslash (escape char)

  // ── Clause terminators ──
  "')--",                    // Close paren + single quote + comment
  "'--",                     // Single quote + comment
  "';--",                    // Semicolon + comment

  // ── Type confusion (forces error on strongly-typed DBs) ──
  "' AND '1'='",             // Unclosed AND
  "1 OR 1=1",               // Numeric context tautology (may change results)
  "' UNION SELECT NULL--",  // UNION with NULL (column-count mismatch reveals error)

  // ── Encoded variations for WAF bypass ──
  "%27",                     // URL-encoded single quote
  "%22",                     // URL-encoded double quote
  "%27%20OR%20%271%27=%271", // Encoded ' OR '1'='1
];

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

function isTextual(ct: string[] | undefined): boolean {
  if (!ct || !ct.length) return true;
  return ct.some(h => TEXT_HINTS.some(t => String(h).toLowerCase().includes(t)));
}

function getBodyLower(resp: any): string | null {
  try {
    const b = resp?.getBody?.();
    if (!b) return null;
    const size = b.getSize?.();
    if (typeof size === "number" && size > SAFE_MAX_BODY * 4) return null;
    const text = b.toText?.();
    if (typeof text !== "string" || !text.length) return null;
    return text.slice(0, SAFE_MAX_BODY).toLowerCase();
  } catch {
    return null;
  }
}

function findErrors(body: string): ErrorSignature[] {
  const hits: ErrorSignature[] = [];
  for (const sig of ERROR_SIGNATURES) {
    if (body.includes(sig.pattern)) {
      hits.push(sig);
    }
  }
  return hits;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Check Definition
// ═══════════════════════════════════════════════════════════════════════════════

export default defineCheck<State>(({ step }) => {

  // ── Step 1: Collect params + baseline errors ─────────────────────────────
  step("collect", (state, ctx) => {
    const params = extractParameters(ctx);
    if (params.length === 0) return done({ state });

    // Check what errors already exist in the original response
    const origBody = getBodyLower(ctx.target.response);
    const baselineErrors = origBody
      ? findErrors(origBody).map(e => e.pattern)
      : [];

    return continueWith({
      nextStep: "test",
      state: { params, pIndex: 0, payIndex: 0, baselineErrors },
    });
  });

  // ── Step 2: Test payloads ────────────────────────────────────────────────
  step("test", async (state, ctx) => {
    if (state.pIndex >= state.params.length) return done({ state });

    const param = state.params[state.pIndex]!;

    if (state.payIndex >= PAYLOADS.length) {
      // Move to next parameter
      return continueWith({
        nextStep: "test",
        state: { ...state, pIndex: state.pIndex + 1, payIndex: 0 },
      });
    }

    const payload = PAYLOADS[state.payIndex]!;
    const testValue = String(param.value ?? "") + payload;

    try {
      const spec = createRequestWithParameter(ctx, param, testValue);
      const { request, response } = await ctx.sdk.requests.send(spec);

      if (response) {
        const cts = response.getHeader?.("Content-Type") ?? [];
        if (isTextual(cts)) {
          const bodyL = getBodyLower(response);
          if (bodyL) {
            const hits = findErrors(bodyL);

            // Filter out errors that were already in the baseline response
            const newHits = hits.filter(h => !state.baselineErrors.includes(h.pattern));

            if (newHits.length > 0) {
              const best = newHits.find(h => h.confidence === "high") ?? newHits[0]!;
              const severity = best.confidence === "high" ? Severity.CRITICAL : Severity.HIGH;
              const allDbs = [...new Set(newHits.map(h => h.db))].join(", ");

              return done({
                findings: [{
                  name: `SQL Injection (${best.db}) in '${param.name}'`,
                  severity,
                  description:
                    `Parameter \`${param.name}\` (${param.source}) triggered a database error when mutated.\n\n` +
                    `**Database detected:** ${allDbs}\n` +
                    `**Confidence:** ${best.confidence}\n\n` +
                    `**Payload:**\n\`\`\`\n${testValue}\n\`\`\`\n\n` +
                    `**Error signature:**\n\`\`\`\n${best.pattern}\n\`\`\`\n\n` +
                    (newHits.length > 1
                      ? `**Additional signatures found:** ${newHits.slice(1).map(h => `\`${h.pattern}\``).join(", ")}\n`
                      : ""),
                  correlation: { requestID: request?.getId?.() ?? "", locations: [] },
                }],
                state,
              });
            }
          }
        }
      }
    } catch {
      // Network/timeout error — skip
    }

    return continueWith({
      nextStep: "test",
      state: { ...state, payIndex: state.payIndex + 1 },
    });
  });

  return {
    metadata: {
      id: "mysql-error-based-sqli",
      name: "Error-Based SQL Injection (Multi-DB)",
      description:
        "Detects SQL injection by triggering database error messages. Covers MySQL, MariaDB, " +
        "PostgreSQL, MSSQL, Oracle, SQLite, and generic ODBC/PDO errors. Compares against " +
        "baseline response to eliminate false positives from existing error pages.",
      type: "active",
      tags: [Tags.SQLI, Tags.INJECTION],
      severities: [Severity.HIGH, Severity.CRITICAL],
      aggressivity: {
        minRequests: 1,
        maxRequests: PAYLOADS.length,
      },
    },
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().withQueryKeys().build(),
    initState: (): State => ({ params: [], pIndex: 0, payIndex: 0, baselineErrors: [] }),
    when: (t) => hasParameters(t),
  };
});
