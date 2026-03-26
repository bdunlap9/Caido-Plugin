import { defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

function h(resp: any, name: string): string | undefined {
  try {
    const v = resp?.getHeader?.(name);
    if (!v) return undefined;
    const arr = Array.isArray(v) ? v : [v];
    return arr.find(Boolean);
  } catch {
    return undefined;
  }
}

const TEXT_HTML = /text\/html|application\/xhtml\+xml/i;

function bodyText(resp: any): string {
  try {
    const b = resp?.getBody?.();
    return b?.toText?.() ?? "";
  } catch {
    return "";
  }
}

function isCloudflareChallenge(resp: any): boolean {
  const status = resp?.getCode?.() ?? 0;
  const server = (h(resp, "server") || "").toLowerCase();
  const cfMitigated = (h(resp, "cf-mitigated") || "").toLowerCase().includes("challenge");
  const setCookie = (h(resp, "set-cookie") || "").toLowerCase();
  const contentType = h(resp, "content-type") || "";
  const htmlish = TEXT_HTML.test(contentType);

  const body = htmlish ? bodyText(resp) : "";
  const looksChallenge =
    /Just a moment\.\.\./i.test(body) ||
    /__cf_chl_|\/cdn-cgi\/challenge-platform\//i.test(body);

  return (
    server.includes("cloudflare") &&
    (status >= 400 || cfMitigated || setCookie.includes("__cf_bm") || looksChallenge)
  );
}

function isHtmlChallenge(resp: any): boolean {
  const ct = h(resp, "content-type") || "";
  if (!TEXT_HTML.test(ct)) return false;
  const b = bodyText(resp);
  return /Just a moment\.\.\./i.test(b) || /challenge/i.test(b);
}

export default defineCheck<unknown>(({ step }) => {
  step("checkCors", (_state, context) => {
    const resp = context.target.response;
    if (!resp) {
      return done({ state: {} });
    }

    try {
      if (isCloudflareChallenge(resp) || isHtmlChallenge(resp)) {
        return done({ state: {} });
      }

      const status = resp.getCode?.() ?? 0;
      if (!(status > 0 && status < 400)) return done({ state: {} });

      const acao = (h(resp, "access-control-allow-origin") || "").trim();
      const acac = (h(resp, "access-control-allow-credentials") || "").toLowerCase();
      const ct = h(resp, "content-type") || "";

      const findings = [];

      // Check 1: Null origin with credentials
      if (acao === "null" && acac === "true") {
        findings.push({
          name: "CORS Null Origin Allowed with Credentials",
          description:
            "The response sets **Access-Control-Allow-Origin: null** and **Access-Control-Allow-Credentials: true**. " +
            "This is exploitable via sandboxed iframes, file:// URLs, and data: URLs." +
            `\n\n**Content-Type:** ${ct}`,
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }

      // Check 2: Wildcard with credentials (browser rejects but still a misconfig)
      if (acao === "*" && acac === "true") {
        findings.push({
          name: "CORS Wildcard with Credentials",
          description:
            "The response sets **Access-Control-Allow-Origin: \\*** and **Access-Control-Allow-Credentials: true**. " +
            "Browsers reject this combination, but it indicates a fundamental CORS misconfiguration.",
          severity: Severity.LOW,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }

      // Check 3: Wildcard ACAO on sensitive endpoints (check if response has auth-related headers)
      if (acao === "*") {
        const hasAuthHeaders = !!(h(resp, "set-cookie") || h(resp, "www-authenticate") || h(resp, "authorization"));
        if (hasAuthHeaders) {
          findings.push({
            name: "CORS Wildcard on Authenticated Endpoint",
            description:
              "The response sets **Access-Control-Allow-Origin: \\*** on an endpoint that also sets authentication-related headers. " +
              "While `*` prevents credentialed requests, this endpoint may leak sensitive data in non-credentialed responses.",
            severity: Severity.INFO,
            correlation: {
              requestID: context.target.request.getId(),
              locations: [],
            },
          });
        }
      }

      // Check 4: ACAO reflects the request Origin header (passive detection)
      const reqOrigin = context.target.request.getHeader?.("Origin")?.[0];
      if (reqOrigin && acao === reqOrigin && acac === "true" && acao !== "null") {
        findings.push({
          name: "CORS Origin Reflected with Credentials",
          description:
            `The response mirrors the request's \`Origin: ${reqOrigin}\` in ACAO with credentials enabled. ` +
            "This may indicate the server reflects any origin without validation. " +
            "Confirm with the active CORS Origin Reflection check.",
          severity: Severity.MEDIUM,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }

      if (findings.length === 0) return done({ state: {} });

      return done({ state: {}, findings });
    } catch {
      return done({ state: {} });
    }
  });

  return {
    metadata: {
      id: "cors-misconfig",
      name: "CORS Misconfiguration (Passive)",
      description:
        "Detects CORS misconfigurations including null origin with credentials, wildcard with credentials, wildcard on authenticated endpoints, and origin reflection.",
      type: "passive",
      tags: [Tags.CORS],
      severities: [Severity.LOW, Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
