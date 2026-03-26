import { continueWith, defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * GraphQL Introspection v3 — Ultimate Detection
 *
 * Probe methods (tried in order per path):
 *   1. POST application/json (standard)
 *   2. POST mini query (bypasses query complexity limits)
 *   3. GET ?query= (no body, proper headers)
 *   4. POST application/graphql (raw query body, no JSON wrapper)
 *   5. POST with operationName (required by some servers)
 *   6. POST with newline-obfuscated query (WAF bypass)
 *
 * Schema analysis:
 *   - Sensitive types (User, Admin, Auth, Token, Payment, Secret, etc.)
 *   - Partial match: UserType, AdminPayload, CreateUserInput, etc.
 *   - Dangerous mutations (createUser, deleteAdmin, resetPassword, transferFunds, etc.)
 *   - Enum values (ORDER_STATUS, USER_ROLE, PERMISSION — reveals business logic)
 *   - Deprecated fields (reveal API evolution, old attack vectors still active)
 *   - Input types with password/secret/token fields
 *   - Subscription count (real-time data exposure)
 *
 * Also detects:
 *   - Debug tool pages (probes /graphiql, /playground, /altair, /voyager, /explorer)
 *   - Field suggestion disclosure ("Did you mean X?")
 *   - x-apollo-tracing header (performance data leak)
 */

type State = {
  stage: "passive" | "probe" | "tools";
  probeIndex: number;
  gqlPath: string;
};

const GQL_PATHS = [
  "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
  "/gql", "/v1/graphql", "/v2/graphql", "/v3/graphql",
  "/query", "/api/query", "/graphql/v1", "/graphql/v2",
  "/graphql/console", "/api", "/api/v1", "/api/v2",
  "/graphql/schema", "/data", "/api/data",
];

const TOOL_PATHS = [
  "/graphiql", "/playground", "/altair", "/voyager",
  "/graphql/playground", "/graphql/graphiql", "/graphql/explorer",
  "/api/graphiql", "/api/playground",
];

const FULL_INTROSPECTION_QUERY = `query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind description fields(includeDeprecated:true){name description args{name description type{...TypeRef}defaultValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{name description type{...TypeRef}defaultValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}directives{name description locations args{name description type{...TypeRef}defaultValue}}}}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}`;

const MINI_INTROSPECTION_QUERY = `{__schema{queryType{name}mutationType{name}subscriptionType{name}types{name kind fields{name type{name kind ofType{name}}args{name type{name}}}inputFields{name type{name}}enumValues{name}}}}`;

// WAF bypass: add newlines and tabs inside the query
const WAF_BYPASS_QUERY = `{\n\t__schema\n\t{\n\t\tqueryType{name}\n\t\tmutationType{name}\n\t\ttypes{\n\t\t\tname\n\t\t\tkind\n\t\t\tfields{name type{name}}\n\t\t}\n\t}\n}`;

const SENSITIVE_WORDS = [
  "user", "admin", "account", "profile", "customer", "member", "staff", "employee",
  "auth", "login", "session", "token", "jwt", "oauth", "credential", "permission",
  "payment", "billing", "invoice", "transaction", "order", "subscription", "card", "charge",
  "secret", "config", "setting", "role", "policy", "apikey", "accesskey", "key",
  "password", "otp", "mfa", "twofactor", "2fa", "reset",
  "internal", "debug", "management", "system", "private", "hidden",
  "upload", "file", "media", "document", "attachment",
  "bank", "wallet", "balance", "transfer", "payout", "refund",
];

const DANGEROUS_MUTATION_WORDS = [
  "create", "add", "register", "signup", "invite",
  "delete", "remove", "destroy", "purge", "drop",
  "update", "set", "change", "modify", "patch",
  "reset", "forgot", "recover",
  "grant", "assign", "elevate", "promote", "escalate",
  "exec", "execute", "run", "eval", "invoke", "deploy", "migrate", "seed", "import",
  "disable", "enable", "toggle", "activate", "deactivate",
  "generate", "issue", "revoke", "rotate",
  "transfer", "withdraw", "refund", "charge", "payout", "send",
  "approve", "reject", "verify", "confirm",
];

function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}

function isSensitiveName(name: string): boolean {
  const lower = name.toLowerCase();
  return SENSITIVE_WORDS.some(w => lower.includes(w));
}

function isDangerousMutation(name: string): boolean {
  const lower = name.toLowerCase();
  return DANGEROUS_MUTATION_WORDS.some(w => lower.startsWith(w));
}

interface SchemaAnalysis {
  typeCount: number;
  queryCount: number;
  mutationCount: number;
  subscriptionCount: number;
  sensitiveTypes: string[];
  dangerousMutations: string[];
  allMutations: string[];
  allQueries: string[];
  hasSubscriptions: boolean;
  sensitiveEnums: Array<{ name: string; values: string[] }>;
  deprecatedFields: Array<{ type: string; field: string; reason: string }>;
  sensitiveInputFields: Array<{ type: string; field: string }>;
  customScalarCount: number;
}

function analyzeSchema(body: string): SchemaAnalysis {
  const r: SchemaAnalysis = {
    typeCount: 0, queryCount: 0, mutationCount: 0, subscriptionCount: 0,
    sensitiveTypes: [], dangerousMutations: [], allMutations: [], allQueries: [],
    hasSubscriptions: false, sensitiveEnums: [], deprecatedFields: [],
    sensitiveInputFields: [], customScalarCount: 0,
  };

  try {
    const data = JSON.parse(body);
    const schema = data?.data?.__schema;
    if (!schema) return r;

    const types: any[] = schema.types ?? [];
    r.typeCount = types.length;

    for (const t of types) {
      if (!t?.name || t.name.startsWith("__")) continue;

      // Sensitive type detection (partial match)
      if (isSensitiveName(t.name)) r.sensitiveTypes.push(t.name);

      // Custom scalars
      if (t.kind === "SCALAR" && !["String", "Int", "Float", "Boolean", "ID"].includes(t.name)) {
        r.customScalarCount++;
      }

      // Enum values (business logic disclosure)
      if (t.kind === "ENUM" && t.enumValues?.length > 0) {
        const vals = t.enumValues.map((e: any) => e.name);
        if (isSensitiveName(t.name) || vals.some((v: string) => /admin|superuser|root|owner|manager|banned|suspended/i.test(v))) {
          r.sensitiveEnums.push({ name: t.name, values: vals.slice(0, 20) });
        }
      }

      // Input types with sensitive fields
      if (t.kind === "INPUT_OBJECT" && t.inputFields) {
        for (const f of t.inputFields) {
          if (/password|secret|token|apikey|credit.?card|ssn|cvv/i.test(f.name)) {
            r.sensitiveInputFields.push({ type: t.name, field: f.name });
          }
        }
      }

      // Deprecated fields
      if (t.fields) {
        for (const f of t.fields) {
          if (f.isDeprecated) {
            r.deprecatedFields.push({ type: t.name, field: f.name, reason: f.deprecationReason || "no reason" });
          }
        }
      }
    }

    // Queries
    const qName = schema.queryType?.name ?? "Query";
    const qType = types.find((t: any) => t.name === qName);
    if (qType?.fields) {
      r.queryCount = qType.fields.length;
      r.allQueries = qType.fields.map((f: any) => f.name).slice(0, 50);
    }

    // Mutations
    const mName = schema.mutationType?.name;
    if (mName) {
      const mType = types.find((t: any) => t.name === mName);
      if (mType?.fields) {
        r.mutationCount = mType.fields.length;
        r.allMutations = mType.fields.map((f: any) => f.name).slice(0, 50);
        r.dangerousMutations = r.allMutations.filter(isDangerousMutation);
      }
    }

    // Subscriptions
    const sName = schema.subscriptionType?.name;
    if (sName) {
      r.hasSubscriptions = true;
      const sType = types.find((t: any) => t.name === sName);
      r.subscriptionCount = sType?.fields?.length ?? 0;
    }
  } catch {}

  return r;
}

type ProbeResult = { request: any; response: any } | null;

async function tryIntrospection(ctx: any, path: string): Promise<{ result: ProbeResult; body: string; code: number; method: string }> {
  const attempts: Array<{ label: string; fn: () => Promise<ProbeResult> }> = [
    // 1. Standard POST JSON
    { label: "POST JSON", fn: () => {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("POST"); spec.setPath(path); spec.setQuery("");
      spec.setHeader("Content-Type", "application/json"); spec.setHeader("Accept", "application/json");
      spec.setBody(JSON.stringify({ query: FULL_INTROSPECTION_QUERY }));
      return ctx.sdk.requests.send(spec);
    }},
    // 2. Mini query (bypass complexity)
    { label: "POST mini", fn: () => {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("POST"); spec.setPath(path); spec.setQuery("");
      spec.setHeader("Content-Type", "application/json"); spec.setHeader("Accept", "application/json");
      spec.setBody(JSON.stringify({ query: MINI_INTROSPECTION_QUERY }));
      return ctx.sdk.requests.send(spec);
    }},
    // 3. GET ?query= (proper — no body, no content-type)
    { label: "GET", fn: () => {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("GET"); spec.setPath(path);
      spec.setQuery(`query=${encodeURIComponent(MINI_INTROSPECTION_QUERY)}`);
      spec.removeHeader("Content-Type"); spec.setHeader("Accept", "application/json");
      return ctx.sdk.requests.send(spec);
    }},
    // 4. POST application/graphql (raw body, no JSON wrapper)
    { label: "POST raw", fn: () => {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("POST"); spec.setPath(path); spec.setQuery("");
      spec.setHeader("Content-Type", "application/graphql"); spec.setHeader("Accept", "application/json");
      spec.setBody(MINI_INTROSPECTION_QUERY);
      return ctx.sdk.requests.send(spec);
    }},
    // 5. POST with operationName
    { label: "POST+opName", fn: () => {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("POST"); spec.setPath(path); spec.setQuery("");
      spec.setHeader("Content-Type", "application/json"); spec.setHeader("Accept", "application/json");
      spec.setBody(JSON.stringify({ operationName: "IntrospectionQuery", query: FULL_INTROSPECTION_QUERY }));
      return ctx.sdk.requests.send(spec);
    }},
    // 6. WAF bypass: newlines/tabs in query
    { label: "POST WAF-bypass", fn: () => {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("POST"); spec.setPath(path); spec.setQuery("");
      spec.setHeader("Content-Type", "application/json"); spec.setHeader("Accept", "application/json");
      spec.setBody(JSON.stringify({ query: WAF_BYPASS_QUERY }));
      return ctx.sdk.requests.send(spec);
    }},
  ];

  for (const attempt of attempts) {
    try {
      const result = await attempt.fn();
      const body = getBody(result?.response);
      const code = result?.response?.getCode?.() ?? 0;
      if (code === 200 && body.includes("__schema") && body.includes("queryType")) {
        return { result, body, code, method: attempt.label };
      }
    } catch {}
  }

  return { result: null, body: "", code: 0, method: "" };
}

export default defineCheck<State>(({ step }) => {
  // ── PASSIVE: check existing response ──
  step("passive", (state, ctx) => {
    const resp = ctx.target.response;
    const body = getBody(resp);
    const findings: Finding[] = [];

    // Introspection in current response
    if (body.includes("__schema") && body.includes("queryType")) {
      const analysis = analyzeSchema(body);
      if (analysis.typeCount > 0) {
        findings.push(...buildFindings(ctx, "current response", analysis, "", undefined));
      }
    }

    // x-apollo-tracing header (performance data leak)
    try {
      const tracing = resp?.getHeader?.("x-apollo-tracing")?.[0] ?? resp?.getHeader?.("apollo-tracing")?.[0];
      if (tracing) {
        findings.push({
          name: "Apollo Tracing Header Exposed",
          description:
            `The response includes an \`x-apollo-tracing\` header, exposing resolver performance data.\n\n` +
            `This reveals internal resolver names, execution times, and query plan details.\n\n` +
            `**Recommendation:** Set \`tracing: false\` in Apollo Server config for production.`,
          severity: Severity.LOW,
          correlation: { requestID: ctx.target.request.getId(), locations: [] },
        });
      }
    } catch {}

    // Debug tools in HTML
    const debugTools: string[] = [];
    if (/graphiql/i.test(body) && (body.includes("react") || body.includes("fetcher"))) debugTools.push("GraphiQL");
    if (/graphql.?playground/i.test(body) && body.includes("endpoint")) debugTools.push("Playground");
    if (/altair/i.test(body) && /graphql/i.test(body)) debugTools.push("Altair");
    if (/voyager/i.test(body) && /graphql/i.test(body)) debugTools.push("Voyager");
    if (/graphql.?explorer/i.test(body)) debugTools.push("Explorer");
    if (debugTools.length > 0) {
      findings.push({
        name: "GraphQL Debug Tool Exposed",
        description:
          `Interactive GraphQL tools detected: ${debugTools.map(t => `**${t}**`).join(", ")}.\n\n` +
          `These allow full schema exploration, query building, and often bypass authentication.\n\n` +
          `**Recommendation:** Remove from production.`,
        severity: Severity.MEDIUM,
        correlation: { requestID: ctx.target.request.getId(), locations: [] },
      });
    }

    // Field suggestion disclosure
    const suggestions = [...body.matchAll(/Did you mean\s+["'](\w+)["']/gi)].map(m => m[1]).filter(Boolean);
    if (suggestions.length > 0) {
      findings.push({
        name: "GraphQL Field Suggestion Disclosure",
        description:
          `Error messages reveal valid field names: ${[...new Set(suggestions)].map(s => `\`${s}\``).join(", ")}.\n\n` +
          `Attackers can enumerate the schema without introspection.`,
        severity: Severity.LOW,
        correlation: { requestID: ctx.target.request.getId(), locations: [] },
      });
    }

    return continueWith({
      nextStep: "probe",
      state: { ...state, stage: "probe" as const, probeIndex: 0, gqlPath: "" },
      ...(findings.length > 0 ? { findings } : {}),
    });
  });

  // ── ACTIVE: probe GraphQL paths ──
  step("probe", async (state, ctx) => {
    if (state.probeIndex >= GQL_PATHS.length) {
      return continueWith({ nextStep: "tools", state: { ...state, stage: "tools" as const, probeIndex: 0 } });
    }

    const path = GQL_PATHS[state.probeIndex]!;
    const { result, body, method } = await tryIntrospection(ctx, path);

    if (result && body.includes("__schema")) {
      const analysis = analyzeSchema(body);
      const findings = buildFindings(ctx, path, analysis, method, result.request);

      // After finding introspection, skip remaining paths and go to tools
      return continueWith({
        nextStep: "tools",
        state: { ...state, stage: "tools" as const, gqlPath: path, probeIndex: 0 },
        findings,
      });
    }

    // Check if endpoint exists (introspection disabled)
    if (result?.response) {
      const respBody = getBody(result.response);
      const code = result.response.getCode?.() ?? 0;
      const isGql = respBody.includes('"errors"') || respBody.includes("Must provide query") ||
                    respBody.includes("Syntax Error") || (code === 400 && respBody.includes("graphql"));

      if (isGql) {
        // Confirm with __typename
        try {
          const spec = ctx.target.request.toSpec();
          spec.setMethod("POST"); spec.setPath(path); spec.setQuery("");
          spec.setHeader("Content-Type", "application/json"); spec.setHeader("Accept", "application/json");
          spec.setBody(JSON.stringify({ query: "{__typename}" }));
          const confirmResult = await ctx.sdk.requests.send(spec);
          const confirmBody = getBody(confirmResult?.response);
          if (confirmResult?.response?.getCode?.() === 200 && confirmBody.includes("__typename")) {
            return continueWith({
              nextStep: "probe",
              state: { ...state, probeIndex: state.probeIndex + 1, gqlPath: path },
              findings: [{
                name: `GraphQL Endpoint at ${path} (introspection disabled)`,
                description:
                  `Confirmed GraphQL endpoint at \`${path}\`. Introspection is disabled but the endpoint ` +
                  `responds to queries.\n\nThe schema can still be enumerated via field suggestion brute-forcing and error analysis.`,
                severity: Severity.INFO,
                correlation: { requestID: confirmResult.request.getId(), locations: [] },
              }],
            });
          }
        } catch {}
      }
    }

    return continueWith({ nextStep: "probe", state: { ...state, probeIndex: state.probeIndex + 1 } });
  });

  // ── Probe for debug tool pages ──
  step("tools", async (state, ctx) => {
    if (state.probeIndex >= TOOL_PATHS.length) return done({ state });

    const path = TOOL_PATHS[state.probeIndex]!;
    try {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("GET"); spec.setPath(path); spec.setQuery("");
      spec.removeHeader("Content-Type"); spec.setHeader("Accept", "text/html");
      const { request, response } = await ctx.sdk.requests.send(spec);
      const code = response?.getCode?.() ?? 0;
      const body = getBody(response);
      if (code === 200 && body.length > 500 && /graphiql|playground|altair|voyager|explorer/i.test(body) && body.includes("<html")) {
        return continueWith({
          nextStep: "tools",
          state: { ...state, probeIndex: state.probeIndex + 1 },
          findings: [{
            name: `GraphQL Tool Page at ${path}`,
            description:
              `An interactive GraphQL tool page was found at \`${path}\`.\n\n` +
              `This provides a full IDE for building and executing queries, exploring the schema, ` +
              `and often bypasses authentication entirely.\n\n` +
              `**Recommendation:** Remove or restrict access to debug tools in production.`,
            severity: Severity.MEDIUM,
            correlation: { requestID: request.getId(), locations: [] },
          }],
        });
      }
    } catch {}

    return continueWith({ nextStep: "tools", state: { ...state, probeIndex: state.probeIndex + 1 } });
  });

  return {
    metadata: {
      id: "graphql-introspection",
      name: "GraphQL Introspection & Schema Analysis",
      description:
        "Probes 19 GraphQL paths with 6 methods (POST JSON, mini query, GET, raw body, operationName, WAF bypass). " +
        "Analyzes schemas for sensitive types, dangerous mutations, business-logic enums, deprecated fields, " +
        "password input fields, and custom scalars. Probes 9 debug tool paths. Detects Apollo tracing headers.",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.ATTACK_SURFACE],
      severities: [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: GQL_PATHS.length * 6 + TOOL_PATHS.length },
    },
    initState: (): State => ({ stage: "passive" as const, probeIndex: 0, gqlPath: "" }),
    dedupeKey: keyStrategy().withHost().withPort().build(),
  };
});

function buildFindings(ctx: any, path: string, a: SchemaAnalysis, method: string, request?: any): Finding[] {
  const findings: Finding[] = [];
  const reqId = request?.getId?.() ?? ctx.target.request.getId();

  // Main finding
  const desc = [
    `Full schema introspection succeeded at \`${path}\`${method ? ` via **${method}**` : ""}.`,
    "",
    "**Schema overview:**",
    `- Types: **${a.typeCount}** (${a.customScalarCount} custom scalars)`,
    `- Queries: **${a.queryCount}**`,
    `- Mutations: **${a.mutationCount}**`,
    a.hasSubscriptions ? `- Subscriptions: **${a.subscriptionCount}** (real-time data exposure)` : null,
  ].filter(Boolean);

  if (a.sensitiveTypes.length > 0) {
    desc.push("", `**Sensitive types:** ${a.sensitiveTypes.slice(0, 20).map(t => `\`${t}\``).join(", ")}`);
  }
  if (a.allQueries.length > 0) {
    desc.push("", `**Queries:** ${a.allQueries.slice(0, 20).map(q => `\`${q}\``).join(", ")}${a.allQueries.length > 20 ? ` (+${a.allQueries.length - 20})` : ""}`);
  }
  if (a.allMutations.length > 0) {
    desc.push("", `**Mutations:** ${a.allMutations.slice(0, 20).map(m => `\`${m}\``).join(", ")}${a.allMutations.length > 20 ? ` (+${a.allMutations.length - 20})` : ""}`);
  }
  if (a.sensitiveEnums.length > 0) {
    desc.push("", "**Business-logic enums:**");
    for (const e of a.sensitiveEnums.slice(0, 5)) {
      desc.push(`- \`${e.name}\`: ${e.values.slice(0, 10).map(v => `\`${v}\``).join(", ")}`);
    }
  }
  if (a.sensitiveInputFields.length > 0) {
    desc.push("", `**Input types with sensitive fields:** ${a.sensitiveInputFields.slice(0, 10).map(f => `\`${f.type}.${f.field}\``).join(", ")}`);
  }
  if (a.deprecatedFields.length > 0) {
    desc.push("", `**Deprecated fields (${a.deprecatedFields.length}):** ${a.deprecatedFields.slice(0, 5).map(f => `\`${f.type}.${f.field}\``).join(", ")} — may expose old attack vectors`);
  }

  desc.push("", "**Recommendation:** Disable introspection in production (`introspection: false`).");

  findings.push({
    name: `GraphQL Full Introspection at ${path}`,
    description: desc.join("\n"),
    severity: a.sensitiveTypes.length > 3 || a.sensitiveInputFields.length > 0 ? Severity.HIGH : Severity.MEDIUM,
    correlation: { requestID: reqId, locations: [] },
  });

  // Separate finding for dangerous mutations
  if (a.dangerousMutations.length > 0) {
    findings.push({
      name: "GraphQL Dangerous Mutations Exposed",
      description:
        `Potentially dangerous mutations discovered:\n\n` +
        a.dangerousMutations.slice(0, 20).map(m => `- \`${m}\``).join("\n") + "\n\n" +
        `These may enable privilege escalation, account takeover, data destruction, or financial fraud.\n\n` +
        `**Recommendation:** Enforce authorization on every mutation. Rate-limit sensitive operations.`,
      severity: Severity.HIGH,
      correlation: { requestID: reqId, locations: [] },
    });
  }

  return findings;
}
