import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Cacheable Authenticated Response Detection
 *
 * Detects responses that:
 * 1. Are associated with authentication (contain Set-Cookie with session tokens,
 *    or the request had Authorization/Cookie headers)
 * 2. Do NOT have proper Cache-Control headers (no-store, no-cache, private)
 *
 * Without proper cache headers, proxies and CDNs may cache authenticated
 * responses, serving one user's data to another.
 */

function getHeader(obj: any, name: string): string | undefined {
  try {
    const v = obj?.getHeader?.(name);
    return Array.isArray(v) ? v[0] : v;
  } catch {
    return undefined;
  }
}

function isAuthenticated(request: any, response: any): boolean {
  // Check if request carries auth
  const hasAuth = !!getHeader(request, "authorization");
  const hasCookie = !!getHeader(request, "cookie");

  // Check if response sets a session cookie
  const setCookie = (getHeader(response, "set-cookie") ?? "").toLowerCase();
  const setsSession = /session|sid|token|auth|jwt|access/i.test(setCookie);

  return hasAuth || (hasCookie && setsSession) || setsSession;
}

function hasCacheProtection(response: any): boolean {
  const cacheControl = (getHeader(response, "cache-control") ?? "").toLowerCase();
  const pragma = (getHeader(response, "pragma") ?? "").toLowerCase();

  // Must have at least one of these
  const hasNoStore = cacheControl.includes("no-store");
  const hasNoCache = cacheControl.includes("no-cache");
  const hasPrivate = cacheControl.includes("private");
  const hasMustRevalidate = cacheControl.includes("must-revalidate");
  const hasPragmaNoCache = pragma.includes("no-cache");

  return hasNoStore || hasPrivate || (hasNoCache && hasMustRevalidate) || hasPragmaNoCache;
}

function isHtml(response: any): boolean {
  const ct = (getHeader(response, "content-type") ?? "").toLowerCase();
  return ct.includes("text/html") || ct.includes("application/json") || ct.includes("application/xml");
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("check", (state, ctx) => {
    const { request, response } = ctx.target;
    if (!response) return done({ state });

    // Only check successful responses with content
    const code = response.getCode();
    if (code < 200 || code >= 300) return done({ state });
    if (!isHtml(response)) return done({ state });

    // Check if this is an authenticated context
    if (!isAuthenticated(request, response)) return done({ state });

    // Check if cache protection is in place
    if (hasCacheProtection(response)) return done({ state });

    const cacheControl = getHeader(response, "cache-control") ?? "(not set)";
    const findings: Finding[] = [{
      name: "Cacheable Authenticated Response",
      description:
        `An authenticated response lacks proper cache protection headers.\n\n` +
        `**Current Cache-Control:** \`${cacheControl}\`\n\n` +
        `Without \`Cache-Control: no-store\` or \`Cache-Control: private\`, intermediate ` +
        `proxies, CDNs, and browser caches may store this response. This can lead to:\n` +
        `- **Cache poisoning**: One user's data served to another\n` +
        `- **Data leakage**: Sensitive data persisted in shared caches\n` +
        `- **Session fixation**: Cached Set-Cookie headers replayed\n\n` +
        `**Recommendation:** Add \`Cache-Control: no-store, no-cache, must-revalidate, private\``,
      severity: Severity.LOW,
      correlation: {
        requestID: request.getId(),
        locations: [],
      },
    }];

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "cacheable-auth",
      name: "Cacheable Authenticated Response",
      description:
        "Detects authenticated responses missing Cache-Control protection (no-store, private). " +
        "Cached authenticated responses can leak sensitive data through shared proxies and CDNs.",
      type: "passive",
      tags: [Tags.SECURITY_HEADERS, Tags.SENSITIVE_DATA],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined,
  };
});
