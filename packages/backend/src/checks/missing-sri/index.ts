import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Passive Subresource Integrity Check
 *
 * Scans HTML responses for <script> and <link rel="stylesheet"> tags that load
 * external resources (CDNs, third-party domains) without integrity= attributes.
 * Without SRI, a compromised CDN can serve malicious code to all users.
 */

function isHtml(resp: any): boolean {
  const ct = (resp?.getHeader?.("content-type")?.[0] ?? "").toLowerCase();
  return ct.includes("text/html") || ct.includes("application/xhtml");
}

function isExternal(src: string, pageHost: string): boolean {
  try {
    if (src.startsWith("//") || src.startsWith("http://") || src.startsWith("https://")) {
      const url = new URL(src, "https://placeholder.example");
      return url.hostname !== pageHost && !url.hostname.endsWith("." + pageHost);
    }
  } catch {}
  return false;
}

type ExternalResource = { tag: string; src: string; hasIntegrity: boolean };

function findExternalResources(html: string, host: string): ExternalResource[] {
  const resources: ExternalResource[] = [];

  // External <script src="...">
  const scriptRegex = /<script\b([^>]*)>/gi;
  let m;
  while ((m = scriptRegex.exec(html)) !== null) {
    const attrs = m[1] ?? "";
    const srcMatch = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
    if (!srcMatch) continue;
    const src = srcMatch[1]!;
    if (!isExternal(src, host)) continue;
    const hasIntegrity = /\bintegrity\s*=\s*["']/i.test(attrs);
    resources.push({ tag: "script", src, hasIntegrity });
  }

  // External <link rel="stylesheet" href="...">
  const linkRegex = /<link\b([^>]*)>/gi;
  while ((m = linkRegex.exec(html)) !== null) {
    const attrs = m[1] ?? "";
    if (!/rel\s*=\s*["']stylesheet["']/i.test(attrs)) continue;
    const hrefMatch = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i);
    if (!hrefMatch) continue;
    const src = hrefMatch[1]!;
    if (!isExternal(src, host)) continue;
    const hasIntegrity = /\bintegrity\s*=\s*["']/i.test(attrs);
    resources.push({ tag: "link[stylesheet]", src, hasIntegrity });
  }

  return resources;
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, ctx) => {
    const resp = ctx.target.response;
    if (!resp || resp.getCode() !== 200 || !isHtml(resp)) return done({ state });

    const body = resp.getBody?.()?.toText?.() ?? "";
    if (!body) return done({ state });

    const host = ctx.target.request.getHost();
    const resources = findExternalResources(body, host);
    const missing = resources.filter(r => !r.hasIntegrity);

    if (missing.length === 0) return done({ state });

    const list = missing.slice(0, 8).map(r => `- \`<${r.tag}>\` → \`${r.src}\``).join("\n");

    const findings: Finding[] = [{
      name: `External Resources Without Subresource Integrity (${missing.length})`,
      description:
        `${missing.length} external script(s)/stylesheet(s) are loaded without \`integrity\` attributes.\n\n` +
        `**Resources missing SRI:**\n${list}\n\n` +
        `Without SRI, if the CDN or third-party host is compromised, attackers can serve ` +
        `malicious JavaScript/CSS to all users of this page.\n\n` +
        `**Recommendation:** Add \`integrity="sha384-..."  crossorigin="anonymous"\` to all external resources.`,
      severity: Severity.MEDIUM,
      correlation: { requestID: ctx.target.request.getId(), locations: [] },
    }];

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "missing-sri",
      name: "Missing Subresource Integrity",
      description:
        "Detects external scripts and stylesheets loaded without SRI integrity attributes, " +
        "which enables supply-chain attacks via compromised CDNs.",
      type: "passive",
      tags: [Tags.SUPPLY_CHAIN, Tags.XSS],
      severities: [Severity.MEDIUM],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined && t.response.getCode() === 200,
  };
});
