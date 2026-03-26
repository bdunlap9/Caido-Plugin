import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Passive CSRF Token Detection
 *
 * Scans HTML responses for <form> elements that:
 * 1. Use POST method (GET forms are generally safe from CSRF)
 * 2. Do NOT contain a hidden input with a name matching common anti-CSRF patterns
 * 3. Do NOT have an action pointing to a third-party domain
 *
 * Common CSRF token field names: csrf, _token, __RequestVerificationToken,
 * authenticity_token, csrfmiddlewaretoken, _csrf, nonce, antiforgery, etc.
 */

const CSRF_TOKEN_NAMES = [
  "csrf", "csrf_token", "csrftoken", "_csrf", "__csrf",
  "csrfmiddlewaretoken",       // Django
  "_token",                    // Laravel
  "authenticity_token",        // Rails
  "__requestverificationtoken", // ASP.NET
  "antiforgery",               // ASP.NET
  "xsrf", "xsrf_token", "_xsrf",
  "nonce", "state",            // OAuth
  "token", "form_token",
  "verify", "verification",
];

const CSRF_HEADER_NAMES = [
  "x-csrf-token", "x-xsrf-token", "x-request-token",
];

function isHtml(resp: any): boolean {
  const ct = (resp?.getHeader?.("content-type")?.[0] ?? "").toLowerCase();
  return ct.includes("text/html") || ct.includes("application/xhtml");
}

type ParsedForm = {
  action: string;
  method: string;
  hasToken: boolean;
  index: number;
};

function extractForms(html: string, host: string): ParsedForm[] {
  const forms: ParsedForm[] = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;

  let match;
  while ((match = formRegex.exec(html)) !== null) {
    const attrs = (match[1] || "").toLowerCase();
    const body = (match[2] || "").toLowerCase();

    // Extract method (default GET)
    const methodMatch = attrs.match(/method\s*=\s*["']?(\w+)/);
    const method = (methodMatch ? methodMatch[1]! : "get").toUpperCase();

    // Only care about POST/PUT/PATCH/DELETE forms
    if (method === "GET") continue;

    // Extract action
    const actionMatch = attrs.match(/action\s*=\s*["']([^"']*)/);
    const action = actionMatch ? actionMatch[1]! : "";

    // Skip forms pointing to third-party domains
    if (action && /^https?:\/\//i.test(action)) {
      try {
        const actionHost = new URL(action).hostname;
        if (actionHost !== host && !actionHost.endsWith("." + host)) continue;
      } catch {}
    }

    // Check for CSRF token in hidden inputs
    const inputRegex = /<input\b[^>]*>/gi;
    let hasToken = false;
    let inputMatch;
    while ((inputMatch = inputRegex.exec(body)) !== null) {
      const input = inputMatch[0].toLowerCase();
      const nameMatch = input.match(/name\s*=\s*["']([^"']*)/);
      if (!nameMatch) continue;
      const name = nameMatch[1]!.toLowerCase();

      if (CSRF_TOKEN_NAMES.some(t => name.includes(t))) {
        hasToken = true;
        break;
      }
    }

    // Also check for CSRF meta tags in the page (common in SPA frameworks)
    if (!hasToken) {
      for (const headerName of CSRF_HEADER_NAMES) {
        if (html.toLowerCase().includes(`name="${headerName}"`) ||
            html.toLowerCase().includes(`name='${headerName}'`)) {
          hasToken = true;
          break;
        }
      }
    }

    // Check for JavaScript-based CSRF (common in React/Vue/Angular)
    if (!hasToken) {
      const jsPatterns = [
        /csrf[_-]?token/i,
        /x-csrf/i,
        /x-xsrf/i,
        /__requestverificationtoken/i,
      ];
      // If the page has JS that references CSRF tokens, it may be adding them dynamically
      if (jsPatterns.some(p => p.test(html))) {
        hasToken = true;
      }
    }

    forms.push({
      action: action || "(same page)",
      method,
      hasToken,
      index: forms.length,
    });
  }

  return forms;
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, ctx) => {
    const resp = ctx.target.response;
    if (!resp) return done({ state });
    if (resp.getCode() !== 200) return done({ state });
    if (!isHtml(resp)) return done({ state });

    const body = resp.getBody?.()?.toText?.() ?? "";
    if (!body || body.length < 50) return done({ state });

    const host = ctx.target.request.getHost();
    const forms = extractForms(body, host);
    const vulnerable = forms.filter(f => !f.hasToken);

    if (vulnerable.length === 0) return done({ state });

    const findings: Finding[] = vulnerable.map(f => ({
      name: `Form Missing CSRF Token (${f.method} ${f.action})`,
      description:
        `A \`${f.method}\` form with action \`${f.action}\` does not appear to contain ` +
        `an anti-CSRF token. Without CSRF protection, an attacker can trick authenticated ` +
        `users into submitting this form from a malicious page.\n\n` +
        `**Note:** This is a heuristic check. If the application uses a custom token field ` +
        `name or adds tokens via JavaScript at submission time, this may be a false positive.`,
      severity: Severity.MEDIUM,
      correlation: {
        requestID: ctx.target.request.getId(),
        locations: [],
      },
    }));

    // Cap at 3 findings per page to avoid noise
    return done({ state, findings: findings.slice(0, 3) });
  });

  return {
    metadata: {
      id: "csrf-token-missing",
      name: "Missing CSRF Token",
      description:
        "Detects HTML forms using POST/PUT/PATCH/DELETE that do not contain anti-CSRF " +
        "token fields. Checks for common token names (csrf_token, _token, authenticity_token, etc.) " +
        "and meta tags. Accounts for JavaScript-based CSRF handling in SPA frameworks.",
      type: "passive",
      tags: [Tags.CSRF, Tags.FORM_HIJACKING],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined && t.response.getCode() === 200,
  };
});
