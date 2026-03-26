import { continueWith, defineCheck, done, ScanAggressivity, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Active check for exposed API documentation endpoints.
 * Swagger/OpenAPI, GraphQL, and other API docs often leak all endpoints,
 * parameters, and sometimes authentication details.
 */

type Probe = { path: string; pattern: RegExp; name: string; severity: Severity };

const PROBES_CORE: Probe[] = [
  { path: "/swagger.json", pattern: /"swagger"\s*:\s*"2|"openapi"/i, name: "Swagger JSON", severity: Severity.MEDIUM },
  { path: "/swagger/v1/swagger.json", pattern: /"swagger"|"openapi"/i, name: "Swagger JSON (v1)", severity: Severity.MEDIUM },
  { path: "/api-docs", pattern: /"swagger"|"openapi"|"paths"/i, name: "API Docs", severity: Severity.MEDIUM },
  { path: "/v1/api-docs", pattern: /"swagger"|"openapi"/i, name: "API Docs v1", severity: Severity.MEDIUM },
  { path: "/v2/api-docs", pattern: /"swagger"|"openapi"/i, name: "API Docs v2", severity: Severity.MEDIUM },
  { path: "/openapi.json", pattern: /"openapi"/i, name: "OpenAPI JSON", severity: Severity.MEDIUM },
  { path: "/openapi.yaml", pattern: /openapi:|swagger:/i, name: "OpenAPI YAML", severity: Severity.MEDIUM },
  { path: "/swagger-ui.html", pattern: /swagger-ui|Swagger UI/i, name: "Swagger UI", severity: Severity.LOW },
  { path: "/swagger-ui/", pattern: /swagger-ui|Swagger UI/i, name: "Swagger UI", severity: Severity.LOW },
  { path: "/graphql", pattern: /"data"|__schema|__typename/i, name: "GraphQL Endpoint", severity: Severity.MEDIUM },
];

const PROBES_AGGRESSIVE: Probe[] = [
  { path: "/api/swagger.json", pattern: /"swagger"|"openapi"/i, name: "API Swagger", severity: Severity.MEDIUM },
  { path: "/docs", pattern: /swagger|openapi|redoc|API/i, name: "Docs page", severity: Severity.LOW },
  { path: "/redoc", pattern: /ReDoc|openapi/i, name: "ReDoc", severity: Severity.LOW },
  { path: "/graphiql", pattern: /GraphiQL|graphql/i, name: "GraphiQL IDE", severity: Severity.MEDIUM },
  { path: "/altair", pattern: /Altair|graphql/i, name: "Altair GraphQL", severity: Severity.MEDIUM },
  { path: "/.well-known/openapi", pattern: /"openapi"|"paths"/i, name: "Well-Known OpenAPI", severity: Severity.MEDIUM },
  { path: "/api/v1/openapi.json", pattern: /"openapi"/i, name: "API v1 OpenAPI", severity: Severity.MEDIUM },
];

type State = { probes: Probe[]; pIndex: number };

export default defineCheck<State>(({ step }) => {
  step("setup", (state, ctx) => {
    const probes = ctx.config.aggressivity === ScanAggressivity.HIGH
      ? [...PROBES_CORE, ...PROBES_AGGRESSIVE]
      : PROBES_CORE;
    return continueWith({ nextStep: "test", state: { probes, pIndex: 0 } });
  });

  step("test", async (state, ctx) => {
    if (state.pIndex >= state.probes.length) return done({ state });
    const probe = state.probes[state.pIndex]!;

    try {
      const spec = ctx.target.request.toSpec();
      spec.setMethod("GET");
      spec.setPath(probe.path);
      spec.setQuery("");

      const { request, response } = await ctx.sdk.requests.send(spec);
      if (response && response.getCode() === 200) {
        const body = response.getBody?.()?.toText?.() ?? "";
        const ct = (response.getHeader?.("content-type")?.[0] ?? "").toLowerCase();

        // Skip HTML error pages
        if (ct.includes("text/html") && !probe.pattern.test(body)) {
          // likely custom 404
        } else if (probe.pattern.test(body)) {
          return continueWith({
            nextStep: "test",
            state: { ...state, pIndex: state.pIndex + 1 },
            findings: [{
              name: `Exposed ${probe.name} at ${probe.path}`,
              description:
                `API documentation is publicly accessible at \`${probe.path}\`.\n\n` +
                `Exposed API docs reveal all endpoints, parameters, request/response schemas, ` +
                `and sometimes authentication mechanisms. This information significantly aids ` +
                `attackers in discovering and exploiting vulnerabilities.\n\n` +
                `**Recommendation:** Restrict access to API documentation in production.`,
              severity: probe.severity,
              correlation: { requestID: request.getId(), locations: [] },
            }],
          });
        }
      }
    } catch {}

    return continueWith({ nextStep: "test", state: { ...state, pIndex: state.pIndex + 1 } });
  });

  return {
    metadata: {
      id: "open-api-exposure",
      name: "Exposed API Documentation",
      description:
        "Probes for publicly accessible Swagger/OpenAPI docs, GraphQL endpoints, " +
        "and API documentation that reveals internal endpoint structure.",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.ATTACK_SURFACE],
      severities: [Severity.LOW, Severity.MEDIUM],
      aggressivity: { minRequests: 3, maxRequests: PROBES_CORE.length + PROBES_AGGRESSIVE.length },
    },
    initState: (): State => ({ probes: [], pIndex: 0 }),
    dedupeKey: keyStrategy().withHost().withPort().build(),
  };
});
