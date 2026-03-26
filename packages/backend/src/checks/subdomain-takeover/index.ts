import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Passive Subdomain Takeover Indicator Detection
 *
 * Detects response patterns that indicate a subdomain points to an unclaimed
 * cloud service (S3, Heroku, GitHub Pages, Azure, Shopify, etc.).
 * These are strong indicators that the subdomain can be taken over by an attacker.
 */

type TakeoverSignature = {
  service: string;
  patterns: RegExp[];
  severity: Severity;
};

const SIGNATURES: TakeoverSignature[] = [
  // AWS S3
  { service: "Amazon S3", patterns: [/NoSuchBucket/, /The specified bucket does not exist/i], severity: Severity.HIGH },
  // GitHub Pages
  { service: "GitHub Pages", patterns: [/There isn't a GitHub Pages site here/i, /For root URLs.*you must provide an index\.html/i], severity: Severity.MEDIUM },
  // Heroku
  { service: "Heroku", patterns: [/no-such-app\.herokuapp\.com/, /No such app/i, /herokucdn\.com\/error-pages/i], severity: Severity.HIGH },
  // Shopify
  { service: "Shopify", patterns: [/Sorry, this shop is currently unavailable/i, /only-resolve-dns/i], severity: Severity.MEDIUM },
  // Tumblr
  { service: "Tumblr", patterns: [/Whatever you were looking for doesn't currently exist at this address/i, /There's nothing here/i], severity: Severity.MEDIUM },
  // WordPress.com
  { service: "WordPress.com", patterns: [/Do you want to register/i], severity: Severity.LOW },
  // Azure
  { service: "Azure", patterns: [/404 Web Site not found/i, /The resource you are looking for has been removed/i], severity: Severity.HIGH },
  // Fastly
  { service: "Fastly", patterns: [/Fastly error: unknown domain/i], severity: Severity.HIGH },
  // Pantheon
  { service: "Pantheon", patterns: [/The gods are wise/i, /404 error unknown site/i], severity: Severity.MEDIUM },
  // Fly.io
  { service: "Fly.io", patterns: [/fly\.io.*404/i], severity: Severity.MEDIUM },
  // Netlify
  { service: "Netlify", patterns: [/Not Found - Request ID:/i], severity: Severity.MEDIUM },
  // Surge.sh
  { service: "Surge.sh", patterns: [/project not found/i], severity: Severity.MEDIUM },
  // Cargo Collective
  { service: "Cargo Collective", patterns: [/If you're moving your domain away from Cargo/i], severity: Severity.LOW },
  // Unbounce
  { service: "Unbounce", patterns: [/The requested URL was not found on this server.*unbounce/i], severity: Severity.MEDIUM },
  // Zendesk
  { service: "Zendesk", patterns: [/Help Center Closed/i, /this help center no longer exists/i], severity: Severity.MEDIUM },
  // Bitbucket
  { service: "Bitbucket", patterns: [/Repository not found/i], severity: Severity.MEDIUM },
  // Ghost
  { service: "Ghost", patterns: [/The thing you were looking for is no longer here/i], severity: Severity.LOW },
  // Tilda
  { service: "Tilda", patterns: [/Domain has been assigned/i, /Please renew your subscription/i], severity: Severity.LOW },
];

function isTextual(resp: any): boolean {
  const cts = resp?.getHeader?.("content-type") ?? [];
  return (cts as string[]).some((v: string) => ["text/", "json", "xml"].some(h => String(v).toLowerCase().includes(h)));
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, ctx) => {
    const resp = ctx.target.response;
    if (!resp) return done({ state });

    const code = resp.getCode?.() ?? 0;
    // Most takeover indicators appear on 404, 403, or error pages
    if (code < 400 && code !== 0) return done({ state });
    if (!isTextual(resp)) return done({ state });

    const body = resp.getBody?.()?.toText?.() ?? "";
    if (!body || body.length < 10) return done({ state });

    const findings: Finding[] = [];

    for (const sig of SIGNATURES) {
      for (const pattern of sig.patterns) {
        if (pattern.test(body)) {
          findings.push({
            name: `Subdomain Takeover Indicator: ${sig.service}`,
            description:
              `The response matches a known ${sig.service} "unclaimed" page pattern.\n\n` +
              `**Host:** \`${ctx.target.request.getHost()}\`\n` +
              `**Status:** ${code}\n` +
              `**Pattern:** \`${pattern.source}\`\n\n` +
              `This strongly indicates the subdomain's DNS points to an unclaimed ${sig.service} resource. ` +
              `An attacker can claim this resource and serve arbitrary content on your subdomain, ` +
              `enabling phishing, cookie theft (if parent domain cookies are scoped), and SEO poisoning.`,
            severity: sig.severity,
            correlation: { requestID: ctx.target.request.getId(), locations: [] },
          });
          break; // One finding per service is enough
        }
      }
      if (findings.length >= 3) break;
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "subdomain-takeover",
      name: "Subdomain Takeover Indicator",
      description: "Detects response patterns indicating a subdomain points to an unclaimed cloud service (S3, Heroku, GitHub Pages, Azure, Shopify, etc.).",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.ATTACK_SURFACE],
      severities: [Severity.LOW, Severity.MEDIUM, Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().build(),
    when: (t) => t.response !== undefined && (t.response.getCode() >= 400 || t.response.getCode() === 0),
  };
});
