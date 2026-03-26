/**
 * HyperCrawler v3.0 — Bulletproof scanner integration for all 56 checks.
 *
 * v3 fixes over v2:
 *  1.  History seeding pulls ALL methods + ALL status codes (not just GET 200)
 *  2.  History seeding preserves original method, body, and content-type
 *  3.  JSON body support: detects JSON endpoints and submits JSON POST/PUT
 *  4.  JSON response link extraction: parses _links, href, url, next fields
 *  5.  Smart form defaults per input type (email, number, url, tel, date, etc.)
 *  6.  Scan config uses ACTIVE settings with user-chosen aggressivity
 *  7.  Cookie forwarding from Caido browser session
 *  8.  Error page seeding: 403/500 responses seeded for passive disclosure checks
 *  9.  robots.txt/sitemap uses same scheme as seed (not hardcoded HTTPS)
 * 10.  Redirect responses tracked with their query parameters
 * 11.  Dual Accept headers: sends both HTML and JSON variants for content-negotiating APIs
 * 12.  Deduplication includes query parameter KEYS (not just URL string)
 */

import { RequestSpec } from "caido:utils";
import type { BackendSDK } from "../types";
import { startActiveScan } from "./scanner/execution";
import { ConfigStore } from "../stores/config";

// ═══════════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════════

type CrawlJob = {
  url: string;
  depth: number;
  from?: string;
  method?: string;
  body?: string;
  contentType?: string;
  accept?: string;       // Accept header override
  cookies?: string;      // Cookie header to forward
};

type DiscoveredEndpoint = {
  url: string;
  method: string;
  params: string[];
  source: "link" | "form" | "redirect" | "js" | "robots" | "sitemap" | "json-api" | "history";
  requestId?: string;
};

type CrawlerConfig = {
  concurrency: number;
  delayMs: number;
  maxDepth: number;
  maxRequests: number;
  sameHostOnly: boolean;
  includeRegex?: string;
  excludeRegex?: string;
  userAgent: string;
  // Scanner integration
  autoScan: boolean;
  scanBatchSize: number;
  scanBatchDelayMs: number;
  scanAggressivity: string;  // "low" | "medium" | "high"
  // Discovery
  parseRobotsTxt: boolean;
  parseSitemapXml: boolean;
  extractJsUrls: boolean;
  extractJsonUrls: boolean;
  submitForms: boolean;
  followRedirects: boolean;
  forwardCookies: boolean;
  seedErrorPages: boolean;
};

export type CrawlerStatus = {
  running: boolean;
  queued: number;
  inFlight: number;
  visited: number;
  discovered: number;
  sent: number;
  ok200: number;
  redirects: number;
  errors: number;
  forms: number;
  params: number;
  endpoints: number;
  scansLaunched: number;
  requestIdsCollected: number;
  since: number;
  last: string | null;
  seedHost: string | null;
  seedScheme: string;
  config: CrawlerConfig;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Defaults
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_CONFIG: CrawlerConfig = {
  concurrency: 10,
  delayMs: 50,
  maxDepth: 5,
  maxRequests: 10000,
  sameHostOnly: true,
  includeRegex: undefined,
  excludeRegex: undefined,
  userAgent: "HyperCrawler/3.0 (Weeke-Scanner)",
  autoScan: true,
  scanBatchSize: 15,
  scanBatchDelayMs: 2000,
  scanAggressivity: "medium",
  parseRobotsTxt: true,
  parseSitemapXml: true,
  extractJsUrls: true,
  extractJsonUrls: true,
  submitForms: true,
  followRedirects: true,
  forwardCookies: true,
  seedErrorPages: true,
};

// ═══════════════════════════════════════════════════════════════════════════════
// Static extension deny list
// ═══════════════════════════════════════════════════════════════════════════════

const STATIC_EXTENSIONS = new Set([
  ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
  ".css", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
  ".mp4", ".mp3", ".avi", ".mov", ".mkv", ".webm", ".ogg", ".flac",
  ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".tar",
  ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".swf", ".exe", ".dmg", ".iso", ".apk",
]);

// ═══════════════════════════════════════════════════════════════════════════════
// Singleton state
// ═══════════════════════════════════════════════════════════════════════════════

let RUNNING = false;
let STOP_REQUESTED = false;
let config: CrawlerConfig = { ...DEFAULT_CONFIG };
let seedHost: string | null = null;
let seedScheme = "https";
let sessionCookies = "";  // Cookies captured from browser session

const visited = new Set<string>();
const queue: CrawlJob[] = [];
const discoveredEndpoints: DiscoveredEndpoint[] = [];
const collectedRequestIds: Set<string> = new Set();
let scanBatchBuffer: string[] = [];
let scanBatchTimer: ReturnType<typeof setTimeout> | null = null;

const stats = {
  queued: 0, inFlight: 0, visited: 0, discovered: 0, sent: 0,
  ok200: 0, redirects: 0, errors: 0, forms: 0, params: 0,
  endpoints: 0, scansLaunched: 0, requestIdsCollected: 0,
  since: 0, last: null as string | null,
};

// ═══════════════════════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════════════════════

function log(sdk: BackendSDK, ...args: any[]) {
  try { sdk.console.log("[Crawler]", ...args); } catch {}
}
function warn(sdk: BackendSDK, ...args: any[]) {
  try { sdk.console.log("[Crawler][WARN]", ...args); } catch {}
}
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function normUrl(u: string, base?: string): string | null {
  try {
    const url = base ? new URL(u, base) : new URL(u);
    url.hash = "";
    return url.toString();
  } catch { return null; }
}

function hostMatches(url: string): boolean {
  if (!config.sameHostOnly || !seedHost) return true;
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    const seed = seedHost.toLowerCase();
    // Exact match
    if (hostname === seed) return true;
    // www variant: www.site.com ↔ site.com
    const stripWww = (h: string) => h.startsWith("www.") ? h.slice(4) : h;
    if (stripWww(hostname) === stripWww(seed)) return true;
    return false;
  } catch { return false; }
}

function shouldFollowPath(pathname: string): boolean {
  const lower = (pathname || "").toLowerCase();
  const lastSegment = lower.split("/").pop() || "";
  const ext = lastSegment.includes(".") ? "." + lastSegment.split(".").pop()! : "";
  if (STATIC_EXTENSIONS.has(ext)) return false;
  if (config.includeRegex) {
    try { if (!new RegExp(config.includeRegex, "i").test(lower)) return false; } catch {}
  }
  if (config.excludeRegex) {
    try { if (new RegExp(config.excludeRegex, "i").test(lower)) return false; } catch {}
  }
  return true;
}

function getVisitKey(job: CrawlJob): string {
  // Dedupe by method + URL (including query) + body hash
  const method = (job.method || "GET").toUpperCase();
  // Normalize query param keys for dedup (order-independent)
  let normalizedUrl = job.url;
  try {
    const u = new URL(job.url);
    const keys = [...new URLSearchParams(u.search).keys()].sort();
    u.search = keys.length ? "?" + keys.join("&") : "";
    normalizedUrl = u.toString();
  } catch {}
  const key = `${method}|${normalizedUrl}`;
  if (job.body) return key + "|" + simpleHash(job.body);
  return key;
}

function simpleHash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  return h.toString(36);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Content type helpers
// ═══════════════════════════════════════════════════════════════════════════════

function isHtml(headers: string[] | undefined): boolean {
  return (headers ?? []).some(v => /text\/html|application\/xhtml/i.test(String(v)));
}
function isJson(headers: string[] | undefined): boolean {
  return (headers ?? []).some(v => /application\/json|\+json/i.test(String(v)));
}
function isJs(headers: string[] | undefined): boolean {
  return (headers ?? []).some(v => /javascript|ecmascript/i.test(String(v)));
}
function isXml(headers: string[] | undefined): boolean {
  return (headers ?? []).some(v => /text\/xml|application\/xml/i.test(String(v)));
}
function getBody(resp: any): string {
  try { return resp?.getBody?.()?.toText?.() ?? ""; } catch { return ""; }
}
function getCts(resp: any): string[] {
  try {
    const v = resp?.getHeader?.("Content-Type") ?? [];
    return Array.isArray(v) ? v : [String(v)];
  } catch { return []; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Link extraction — HTML
// ═══════════════════════════════════════════════════════════════════════════════

function extractAllLinks(html: string, baseUrl: string): string[] {
  const out = new Set<string>();

  // href: a, link, area, base
  for (const m of html.matchAll(/<(?:a|link|area|base)\b[^>]*?\bhref\s*=\s*["']([^"'#]+?)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // src: img, script, iframe, embed, video, audio, source, object, input, track
  for (const m of html.matchAll(/<(?:img|script|iframe|embed|video|audio|source|object|input|track)\b[^>]*?\bsrc\s*=\s*["']([^"'#]+?)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // form action
  for (const m of html.matchAll(/<form\b[^>]*?\baction\s*=\s*["']([^"'#]+?)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // formaction
  for (const m of html.matchAll(/\bformaction\s*=\s*["']([^"'#]+?)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // data-href, data-src, data-url, data-link, data-action
  for (const m of html.matchAll(/\bdata-(?:href|src|url|link|action)\s*=\s*["']([^"'#]+?)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // meta refresh
  for (const m of html.matchAll(/<meta\b[^>]*?http-equiv\s*=\s*["']refresh["'][^>]*?content\s*=\s*["'][^"']*?url\s*=\s*([^"'\s;]+)/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // srcset
  for (const m of html.matchAll(/\bsrcset\s*=\s*["']([^"']+?)["']/gi)) {
    for (const entry of m[1]!.split(",")) {
      const src = entry.trim().split(/\s+/)[0];
      if (src) { const u = normUrl(src, baseUrl); if (u) out.add(u); }
    }
  }
  // object data
  for (const m of html.matchAll(/<object\b[^>]*?\bdata\s*=\s*["']([^"'#]+?)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }

  return [...out];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Link extraction — JSON responses (NEW in v3)
// ═══════════════════════════════════════════════════════════════════════════════

function extractJsonUrls(jsonStr: string, baseUrl: string): string[] {
  const out = new Set<string>();
  // Match URL-like values in JSON: "href": "/path", "url": "https://...", "_links"
  const urlValueRegex = /["'](?:href|url|uri|link|next|prev|self|first|last|source|target|redirect|callback|return_url|continue|goto)["']\s*:\s*["'](\/[^"'\s]+|https?:\/\/[^"'\s]+)["']/gi;
  for (const m of jsonStr.matchAll(urlValueRegex)) {
    const u = normUrl(m[1]!, baseUrl);
    if (u) out.add(u);
  }
  // Also match bare path strings that look like API endpoints
  const apiPathRegex = /["'](\/api\/[^"'\s]{2,}|\/v[0-9]+\/[^"'\s]{2,})["']/gi;
  for (const m of jsonStr.matchAll(apiPathRegex)) {
    const u = normUrl(m[1]!, baseUrl);
    if (u) out.add(u);
  }
  return [...out];
}

// ═══════════════════════════════════════════════════════════════════════════════
// Form extraction with smart defaults
// ═══════════════════════════════════════════════════════════════════════════════

type ParsedForm = {
  action: string;
  method: string;
  enctype: string;
  inputs: Array<{ name: string; value: string; type: string }>;
};

/** Smart default values based on input type — prevents server-side validation rejections */
function smartDefault(name: string, type: string): string {
  const lower = name.toLowerCase();
  switch (type) {
    case "email": return "test@example.com";
    case "number": return "1";
    case "tel": return "5551234567";
    case "url": return "https://example.com";
    case "date": return "2024-01-15";
    case "datetime-local": return "2024-01-15T12:00";
    case "time": return "12:00";
    case "color": return "#000000";
    case "range": return "50";
    case "month": return "2024-01";
    case "week": return "2024-W03";
    default: break;
  }
  // Name-based heuristics
  if (lower.includes("email")) return "test@example.com";
  if (lower.includes("phone") || lower.includes("tel") || lower.includes("mobile")) return "5551234567";
  if (lower.includes("url") || lower.includes("website") || lower.includes("link")) return "https://example.com";
  if (lower.includes("zip") || lower.includes("postal")) return "12345";
  if (lower.includes("age") || lower.includes("quantity") || lower.includes("amount") || lower.includes("count")) return "1";
  if (lower.includes("date") || lower.includes("birthday") || lower.includes("dob")) return "2024-01-15";
  if (lower.includes("year")) return "2024";
  if (lower.includes("name")) return "test";
  if (lower.includes("pass")) return "Test1234!";
  if (lower.includes("search") || lower.includes("query") || lower.includes("q") || lower === "s") return "test";
  if (lower.includes("page") || lower.includes("id") || lower.includes("num")) return "1";
  return "test";
}

function extractForms(html: string, baseUrl: string): ParsedForm[] {
  const forms: ParsedForm[] = [];
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;

  for (const fm of html.matchAll(formRegex)) {
    const attrs = fm[1] || "";
    const body = fm[2] || "";

    const actionMatch = attrs.match(/\baction\s*=\s*["']([^"']*)["']/i);
    const rawAction = actionMatch ? actionMatch[1]! : "";
    const action = normUrl(rawAction || baseUrl, baseUrl) || baseUrl;

    const methodMatch = attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i);
    const method = (methodMatch ? methodMatch[1]! : "GET").toUpperCase();

    const enctypeMatch = attrs.match(/\benctype\s*=\s*["']([^"']*)["']/i);
    const enctype = enctypeMatch ? enctypeMatch[1]!.toLowerCase() : "application/x-www-form-urlencoded";

    const inputs: ParsedForm["inputs"] = [];
    const inputRegex = /<(?:input|select|textarea)\b([^>]*?)(?:\/>|>)/gi;
    for (const im of body.matchAll(inputRegex)) {
      const iattrs = im[1] || "";
      const nameMatch = iattrs.match(/\bname\s*=\s*["']([^"']*)["']/i);
      if (!nameMatch) continue;
      const name = nameMatch[1]!;
      const valueMatch = iattrs.match(/\bvalue\s*=\s*["']([^"']*)["']/i);
      const typeMatch = iattrs.match(/\btype\s*=\s*["']([^"']*)["']/i);
      const type = typeMatch ? typeMatch[1]!.toLowerCase() : "text";
      if (["submit", "button", "image", "reset", "file"].includes(type)) continue;
      const value = valueMatch ? valueMatch[1]! : "";
      inputs.push({ name, value: value || smartDefault(name, type), type });
    }

    forms.push({ action, method, enctype, inputs });
  }

  return forms;
}

// ═══════════════════════════════════════════════════════════════════════════════
// JavaScript URL extraction
// ═══════════════════════════════════════════════════════════════════════════════

function extractJsUrls(code: string, baseUrl: string): string[] {
  const out = new Set<string>();
  // String literal paths/URLs
  for (const m of code.matchAll(/["'`]((?:\/[a-zA-Z0-9_.\-/]+(?:\?[^"'`\s]*)?)|(?:https?:\/\/[^"'`\s]+))["'`]/g)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // fetch/axios/XMLHttpRequest
  for (const m of code.matchAll(/(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*["'`]([^"'`]+)["'`]/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  // window.location
  for (const m of code.matchAll(/(?:window\.)?location(?:\.href)?\s*=\s*["'`]([^"'`]+)["'`]/gi)) {
    const u = normUrl(m[1]!, baseUrl); if (u) out.add(u);
  }
  return [...out];
}

function extractInlineScriptUrls(html: string, baseUrl: string): string[] {
  const out = new Set<string>();
  for (const m of html.matchAll(/<script\b[^>]*?>([\s\S]*?)<\/script>/gi)) {
    if ((m[1] || "").trim().length > 5) {
      for (const u of extractJsUrls(m[1]!, baseUrl)) out.add(u);
    }
  }
  return [...out];
}

// ─── SPA Framework Route Extraction ──────────────────────────────────────────

function extractSpaRoutes(html: string, baseUrl: string, depth: number) {
  // Angular: [routerLink]="'/path'", ng-href="/path"
  for (const m of html.matchAll(/(?:\[routerLink\]\s*=\s*["']|ng-href\s*=\s*["'])([^"']+)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl);
    if (u && depth + 1 <= config.maxDepth) enqueue({ url: u, depth: depth + 1, from: baseUrl });
  }
  // React: to="/path" (from react-router Link)
  for (const m of html.matchAll(/\bto\s*=\s*["'](\/[^"']+)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl);
    if (u && depth + 1 <= config.maxDepth) enqueue({ url: u, depth: depth + 1, from: baseUrl });
  }
  // Vue: :to="'/path'" or :href="'/path'"
  for (const m of html.matchAll(/:(?:to|href)\s*=\s*["'](?:'|")?(\/[^"']+?)(?:'|")?["']/gi)) {
    const u = normUrl(m[1]!, baseUrl);
    if (u && depth + 1 <= config.maxDepth) enqueue({ url: u, depth: depth + 1, from: baseUrl });
  }
  // data-route, data-page-url
  for (const m of html.matchAll(/\bdata-(?:route|page-url|path|endpoint)\s*=\s*["'](\/[^"']+)["']/gi)) {
    const u = normUrl(m[1]!, baseUrl);
    if (u && depth + 1 <= config.maxDepth) enqueue({ url: u, depth: depth + 1, from: baseUrl });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// robots.txt + sitemap.xml
// ═══════════════════════════════════════════════════════════════════════════════

function parseRobotsTxt(text: string, origin: string): string[] {
  const urls: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    const match = trimmed.match(/^(?:Dis)?Allow:\s*(.+)/i);
    if (match) {
      const path = match[1]!.trim().split(/\s/)[0]!;
      if (path && path !== "/" && path !== "*") {
        const clean = path.replace(/\*/g, "").replace(/\$$/, "");
        if (clean.length > 1) { const u = normUrl(clean, origin); if (u) urls.push(u); }
      }
    }
    const sm = trimmed.match(/^Sitemap:\s*(.+)/i);
    if (sm) { const u = normUrl(sm[1]!.trim(), origin); if (u) urls.push(u); }
  }
  return urls;
}

function parseSitemapXml(xml: string, origin: string): string[] {
  const urls: string[] = [];
  for (const m of xml.matchAll(/<loc>\s*(.*?)\s*<\/loc>/gi)) {
    const u = normUrl(m[1]!, origin); if (u) urls.push(u);
  }
  return urls;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Enqueue + endpoint tracking
// ═══════════════════════════════════════════════════════════════════════════════

function enqueue(job: CrawlJob): boolean {
  const key = getVisitKey(job);
  if (visited.has(key)) return false;
  try {
    const u = new URL(job.url);
    if (!shouldFollowPath(u.pathname)) return false;
    if (!hostMatches(job.url)) return false;
  } catch { return false; }
  // Forward session cookies if configured
  if (config.forwardCookies && sessionCookies && !job.cookies) {
    job.cookies = sessionCookies;
  }
  queue.push(job);
  stats.discovered++;
  return true;
}

function addEndpoint(ep: DiscoveredEndpoint) {
  discoveredEndpoints.push(ep);
  stats.endpoints = discoveredEndpoints.length;
  stats.params += ep.params.length;
}

function trackUrlParams(url: string, method: string, source: DiscoveredEndpoint["source"]) {
  try {
    const u = new URL(url);
    const params = [...new URLSearchParams(u.search).keys()];
    if (params.length > 0) {
      addEndpoint({ url, method, params, source });
    }
  } catch {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Scanner auto-feed (v3: uses active config + user aggressivity)
// ═══════════════════════════════════════════════════════════════════════════════

function feedToScanner(sdk: BackendSDK, requestId: string) {
  if (!config.autoScan) return;
  if (collectedRequestIds.has(requestId)) return;
  collectedRequestIds.add(requestId);
  stats.requestIdsCollected = collectedRequestIds.size;
  scanBatchBuffer.push(requestId);

  if (scanBatchBuffer.length >= config.scanBatchSize) {
    flushScanBatch(sdk);
  } else if (!scanBatchTimer) {
    scanBatchTimer = setTimeout(() => flushScanBatch(sdk), config.scanBatchDelayMs);
  }
}

function flushScanBatch(sdk: BackendSDK) {
  if (scanBatchTimer) { clearTimeout(scanBatchTimer); scanBatchTimer = null; }
  if (scanBatchBuffer.length === 0) return;

  const batch = [...scanBatchBuffer];
  scanBatchBuffer = [];

  const configStore = ConfigStore.get();
  const userConfig = configStore.getUserConfig();

  // v3: Use active scan config with user-chosen aggressivity
  const aggressivity = config.scanAggressivity || userConfig.passive.aggressivity || "medium";
  const scanConfig = {
    aggressivity: aggressivity as any,
    inScopeOnly: false,
    concurrentChecks: aggressivity === "high" ? 4 : (aggressivity === "medium" ? 3 : 2),
    concurrentTargets: aggressivity === "high" ? 3 : 2,
    concurrentRequests: aggressivity === "high" ? 8 : 5,
    requestsDelayMs: aggressivity === "high" ? 20 : 50,
    scanTimeout: 15 * 60,
    checkTimeout: 3 * 60,
    severities: ["info", "low", "medium", "high", "critical"] as any[],
  };

  try {
    const result = startActiveScan(sdk, {
      requestIDs: batch,
      scanConfig,
      title: `Crawl Scan [${aggressivity}] (${batch.length} targets)`,
    });
    if (result.kind === "Success") {
      stats.scansLaunched++;
      log(sdk, `Auto-scan launched: ${batch.length} targets, aggressivity=${aggressivity}, session=${result.value.id}`);
      try { sdk.api.send("crawler:scan-launched" as any, result.value.id, batch.length); } catch {}
    } else {
      warn(sdk, "Auto-scan failed:", result.kind === "Error" ? result.error : "unknown");
    }
  } catch (e: any) {
    warn(sdk, "Auto-scan exception:", e?.message || e);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Core crawl logic
// ═══════════════════════════════════════════════════════════════════════════════

async function crawlOne(sdk: BackendSDK, job: CrawlJob, _workerId: number) {
  // CRITICAL: inFlight is incremented by the scheduler BEFORE calling this.
  // We MUST decrement it on ALL code paths including early returns.
  try {
    if (STOP_REQUESTED || !RUNNING) return;

    const vkey = getVisitKey(job);
    if (visited.has(vkey)) return;
    visited.add(vkey);
    stats.visited = visited.size;
    stats.last = job.url;

    if (!hostMatches(job.url)) return;

    // Build request spec
    const method = (job.method || "GET").toUpperCase();
    let spec: InstanceType<typeof RequestSpec>;
    try {
      spec = new RequestSpec(job.url);
    } catch (e: any) {
      warn(sdk, "Invalid URL, skipping:", job.url, e?.message);
      return;
    }

  // NOTE: We do NOT use sdk.requests.inScope() here because when no scope
  // is configured in Caido, inScope() returns false for everything, which
  // would kill the entire crawl. The crawler has its own host filtering
  // via hostMatches() + includeRegex/excludeRegex above.

  try {
    if (method !== "GET") spec.setMethod(method);
    spec.setHeader("User-Agent", config.userAgent);
    spec.setHeader("Accept", job.accept || "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7");

    // Forward cookies from browser session
    if (job.cookies) {
      spec.setHeader("Cookie", job.cookies);
    }

    if (job.body && job.contentType) {
      spec.setHeader("Content-Type", job.contentType);
      spec.setBody(job.body);
    }
  } catch {}

  // NOTE: stats.inFlight is already incremented by the scheduler before calling this

  try {
    if (config.delayMs > 0) await sleep(config.delayMs);

    // Capture cookies from response Set-Cookie headers for session continuity
    const captureCookies = (resp: any) => {
      try {
        const setCookies = resp?.getHeader?.("Set-Cookie") ?? resp?.getHeader?.("set-cookie") ?? [];
        const arr = Array.isArray(setCookies) ? setCookies : [setCookies];
        for (const sc of arr) {
          const cookiePart = String(sc).split(";")[0];
          if (cookiePart && cookiePart.includes("=")) {
            const name = cookiePart.split("=")[0]!.trim();
            // Update session cookies with new values
            if (sessionCookies.includes(name + "=")) {
              sessionCookies = sessionCookies.replace(new RegExp(name + "=[^;]*"), cookiePart);
            } else {
              sessionCookies = sessionCookies ? sessionCookies + "; " + cookiePart : cookiePart;
            }
          }
        }
      } catch {}
    };

    // Set Referer header for better crawl authenticity
    if (job.from) {
      try { spec.setHeader("Referer", job.from); } catch {}
    }

    const result = await sdk.requests.send(spec);
    stats.sent++;

    const response = result?.response;
    const request = result?.request;
    const code = response?.getCode?.() ?? 0;

    // Capture Set-Cookie headers for session continuity
    if (config.forwardCookies && response) {
      captureCookies(response);
    }

    // Feed EVERY response to scanner (passive checks need error pages too)
    const requestId = request?.getId?.() || (result as any)?.id;
    if (requestId) {
      feedToScanner(sdk, String(requestId));
    }

    try { sdk.api.send("crawler:progress" as any, getStatus()); } catch {}

    // ── Handle redirects ──────────────────────────────────────────────────
    if (config.followRedirects && [301, 302, 307, 308].includes(code)) {
      stats.redirects++;
      const locHeaders = response?.getHeader?.("Location") ?? response?.getHeader?.("location") ?? [];
      const location = Array.isArray(locHeaders) ? locHeaders[0] : locHeaders;
      if (location) {
        const redirectUrl = normUrl(String(location), job.url);
        if (redirectUrl && job.depth + 1 <= config.maxDepth) {
          enqueue({ url: redirectUrl, depth: job.depth + 1, from: job.url });
          addEndpoint({ url: redirectUrl, method: "GET", params: [], source: "redirect" });
          trackUrlParams(redirectUrl, "GET", "redirect");
        }
      }
    }

    // ── Process response body ─────────────────────────────────────────────
    const cts = getCts(response);
    const body = getBody(response);

    if (code >= 200 && code < 400 || (config.seedErrorPages && code >= 400)) {
      if (code === 200) stats.ok200++;

      // ── HTML responses ──
      if (isHtml(cts) && body) {
        const links = extractAllLinks(body, job.url);
        for (const link of links) {
          if (job.depth + 1 <= config.maxDepth) {
            if (enqueue({ url: link, depth: job.depth + 1, from: job.url })) {
              trackUrlParams(link, "GET", "link");
            }
          }
        }

        // ── Extract URLs from HTML comments (hidden endpoints, debug URLs) ──
        const commentRegex = /<!--([\s\S]*?)-->/g;
        let cm;
        while ((cm = commentRegex.exec(body)) !== null) {
          const comment = cm[1] || "";
          // Find URLs/paths inside comments
          const commentUrls = comment.match(/(?:href|src|action|url)\s*=\s*["']([^"']+)["']|(?:https?:\/\/[^\s"'<>]+)|(?:\/[a-zA-Z0-9_.\-/]+\.(?:php|html|asp|jsp|json|xml|do|action)(?:\?[^\s"'<>]*)?)/gi);
          if (commentUrls) {
            for (const cu of commentUrls) {
              const cleaned = cu.replace(/^(?:href|src|action|url)\s*=\s*["']/i, "").replace(/["']$/, "");
              const u = normUrl(cleaned, job.url);
              if (u && hostMatches(u) && job.depth + 1 <= config.maxDepth) {
                enqueue({ url: u, depth: job.depth + 1, from: job.url });
              }
            }
          }
        }

        // Forms
        const forms = extractForms(body, job.url);
        stats.forms += forms.length;
        for (const form of forms) {
          const paramNames = form.inputs.map(i => i.name);
          addEndpoint({ url: form.action, method: form.method, params: paramNames, source: "form" });

          if (config.submitForms && job.depth + 1 <= config.maxDepth) {
            if (form.method === "GET") {
              try {
                const u = new URL(form.action);
                for (const input of form.inputs) u.searchParams.set(input.name, input.value);
                enqueue({ url: u.toString(), depth: job.depth + 1, from: job.url });
              } catch {}
            } else if (form.enctype === "application/json" || form.enctype.includes("json")) {
              // JSON form submission (v3 new)
              const jsonBody: Record<string, string> = {};
              for (const input of form.inputs) jsonBody[input.name] = input.value;
              enqueue({
                url: form.action, depth: job.depth + 1, from: job.url,
                method: form.method, body: JSON.stringify(jsonBody),
                contentType: "application/json",
              });
            } else {
              // URL-encoded POST
              const bodyParams = new URLSearchParams();
              for (const input of form.inputs) bodyParams.set(input.name, input.value);
              enqueue({
                url: form.action, depth: job.depth + 1, from: job.url,
                method: form.method, body: bodyParams.toString(),
                contentType: "application/x-www-form-urlencoded",
              });
            }

            // v3: Also submit as JSON if the form was url-encoded (catch JSON APIs)
            if (form.method === "POST" && !form.enctype.includes("json") && form.inputs.length > 0) {
              const jsonBody: Record<string, string> = {};
              for (const input of form.inputs) jsonBody[input.name] = input.value;
              enqueue({
                url: form.action, depth: job.depth + 1, from: job.url,
                method: "POST", body: JSON.stringify(jsonBody),
                contentType: "application/json",
                accept: "application/json",
              });
            }
          }
        }

        // Inline JS URLs
        if (config.extractJsUrls) {
          for (const u of extractInlineScriptUrls(body, job.url)) {
            if (job.depth + 1 <= config.maxDepth) enqueue({ url: u, depth: job.depth + 1, from: job.url });
          }
        }

        // ── SPA framework route extraction (Angular, React, Vue) ──
        extractSpaRoutes(body, job.url, job.depth);

        // ── XML form detection (for XXE check) ──
        for (const form of forms) {
          if (form.enctype.includes("xml") || form.enctype.includes("soap")) {
            // Submit as XML so XXE check can analyze
            const xmlBody = `<?xml version="1.0"?><root>${form.inputs.map(i => `<${i.name}>${i.value}</${i.name}>`).join("")}</root>`;
            enqueue({
              url: form.action, depth: job.depth + 1, from: job.url,
              method: form.method || "POST", body: xmlBody,
              contentType: "application/xml",
            });
          }
        }

        // ── Detect GraphQL endpoints referenced in HTML/JS ──
        const gqlMatches = body.match(/["'`](\/(?:api\/)?graphql[^"'`\s]*)["'`]/gi);
        if (gqlMatches) {
          for (const m of gqlMatches) {
            const path = m.slice(1, -1);
            const gqlUrl = normUrl(path, job.url);
            if (gqlUrl && hostMatches(gqlUrl)) {
              enqueue({
                url: gqlUrl, depth: job.depth + 1, from: job.url,
                method: "POST", body: GRAPHQL_INTROSPECTION,
                contentType: "application/json", accept: "application/json",
              });
            }
          }
        }
      }

      // ── JSON responses (v3 new) ──
      if (config.extractJsonUrls && isJson(cts) && body) {
        const jsonUrls = extractJsonUrls(body, job.url);
        for (const u of jsonUrls) {
          if (job.depth + 1 <= config.maxDepth) {
            if (enqueue({ url: u, depth: job.depth + 1, from: job.url })) {
              trackUrlParams(u, "GET", "json-api");
            }
          }
        }
      }

      // ── JS files ──
      if (config.extractJsUrls && isJs(cts) && body) {
        for (const u of extractJsUrls(body, job.url)) {
          if (job.depth + 1 <= config.maxDepth) enqueue({ url: u, depth: job.depth + 1, from: job.url });
        }
      }

      // ── XML/Sitemap ──
      if (isXml(cts) && body) {
        if (config.parseSitemapXml) {
          for (const u of parseSitemapXml(body, job.url)) {
            enqueue({ url: u, depth: 1, from: job.url });
          }
        }
        // v4: Track XML endpoints for XXE check — re-submit as XML if it was originally non-XML
        if (method === "POST" || method === "PUT") {
          addEndpoint({ url: job.url, method, params: [], source: "link" as any });
        }
      }

      // ── v4: If endpoint returns JSON, also probe with XML Content-Type for XXE ──
      if (isJson(cts) && (method === "POST" || method === "PUT") && job.contentType?.includes("json") && body) {
        // The endpoint accepts JSON — also try XML to see if it accepts that too
        try {
          const xmlProbe = `<?xml version="1.0"?><root><test>1</test></root>`;
          enqueue({
            url: job.url, depth: job.depth, from: job.url,
            method, body: xmlProbe,
            contentType: "application/xml",
          });
        } catch {}
      }

      // ── v4: If a POST returned HTML with a form, re-probe the action with PUT/PATCH ──
      if (method === "POST" && isHtml(cts) && body.includes("<form")) {
        enqueue({ url: job.url, depth: job.depth, from: job.url, method: "PUT", body: job.body, contentType: job.contentType });
      }
    }
  } catch (e: any) {
    stats.errors++;
    warn(sdk, "crawl error", job.url, e?.message ?? e);
  }
  // The outer try/finally handles inFlight decrement
  } finally {
    stats.inFlight--;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Scheduler
// ═══════════════════════════════════════════════════════════════════════════════

async function scheduler(sdk: BackendSDK) {
  const conc = Math.max(1, config.concurrency);
  let idx = 0;
  let consecutive429 = 0;

  while (!STOP_REQUESTED && RUNNING && (queue.length > 0 || stats.inFlight > 0) && stats.visited < config.maxRequests) {
    while (!STOP_REQUESTED && RUNNING && stats.inFlight < conc && queue.length > 0) {
      const job = queue.shift()!;
      // CRITICAL FIX: increment inFlight BEFORE launching async crawlOne
      // Otherwise the scheduler sees inFlight=0 and exits before crawlOne starts
      stats.inFlight++;
      crawlOne(sdk, job, idx++).catch((e: any) => {
        stats.errors++;
        warn(sdk, "crawlOne uncaught:", e?.message ?? e);
      });
    }
    stats.queued = queue.length;

    // Adaptive delay: slow down if getting rate-limited
    const delay = consecutive429 > 3 ? Math.min(config.delayMs * 5, 2000) : 10;
    await sleep(delay);

    // Emit progress periodically
    if (idx % 10 === 0) {
      try { sdk.api.send("crawler:progress" as any, getStatus()); } catch {}
    }
  }

  // Wait for remaining in-flight requests to complete
  let waitCount = 0;
  while (stats.inFlight > 0 && waitCount < 300) {
    await sleep(100);
    waitCount++;
  }

  flushScanBatch(sdk);
  RUNNING = false;
  log(sdk, `Crawl finished. Visited=${stats.visited}, Endpoints=${stats.endpoints}, Scans=${stats.scansLaunched}`);
  try { sdk.api.send("crawler:finished" as any, getStatus()); } catch {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// robots.txt + sitemap discovery (v3: uses seed scheme, not hardcoded HTTPS)
// ═══════════════════════════════════════════════════════════════════════════════

async function discoverRobotsAndSitemap(sdk: BackendSDK, origin: string) {
  if (config.parseRobotsTxt) {
    try {
      const robotsUrl = normUrl("/robots.txt", origin);
      if (robotsUrl) {
        const spec = new RequestSpec(robotsUrl);
        spec.setHeader("User-Agent", config.userAgent);
        if (sessionCookies) spec.setHeader("Cookie", sessionCookies);
        const result = await sdk.requests.send(spec);
        const reqId = result?.request?.getId?.();
        if (reqId) feedToScanner(sdk, String(reqId));

        if ((result?.response?.getCode?.() ?? 0) === 200) {
          const body = getBody(result.response);
          const urls = parseRobotsTxt(body, origin);
          log(sdk, `robots.txt: found ${urls.length} paths`);
          for (const u of urls) {
            if (u.toLowerCase().includes("sitemap")) {
              enqueue({ url: u, depth: 0, from: robotsUrl });
            } else {
              enqueue({ url: u, depth: 1, from: robotsUrl });
              addEndpoint({ url: u, method: "GET", params: [], source: "robots" });
            }
          }
        }
      }
    } catch (e: any) { warn(sdk, "robots.txt failed:", e?.message); }
  }

  if (config.parseSitemapXml) {
    try {
      const sitemapUrl = normUrl("/sitemap.xml", origin);
      if (sitemapUrl) {
        const spec = new RequestSpec(sitemapUrl);
        spec.setHeader("User-Agent", config.userAgent);
        if (sessionCookies) spec.setHeader("Cookie", sessionCookies);
        const result = await sdk.requests.send(spec);
        const reqId = result?.request?.getId?.();
        if (reqId) feedToScanner(sdk, String(reqId));

        if ((result?.response?.getCode?.() ?? 0) === 200) {
          const body = getBody(result.response);
          const urls = parseSitemapXml(body, origin);
          log(sdk, `sitemap.xml: found ${urls.length} URLs`);
          for (const u of urls) {
            enqueue({ url: u, depth: 0, from: sitemapUrl });
            addEndpoint({ url: u, method: "GET", params: [], source: "sitemap" });
          }
        }
      }
    } catch (e: any) { warn(sdk, "sitemap.xml failed:", e?.message); }
  }

  // ═══ GraphQL endpoint discovery ═══════════════════════════════════════════
  try { await discoverGraphQL(sdk, origin); } catch (e: any) { warn(sdk, "GraphQL discovery error:", e?.message); }

  // ═══ Common API path probing ══════════════════════════════════════════════
  try { await discoverApiPaths(sdk, origin); } catch (e: any) { warn(sdk, "API discovery error:", e?.message); }

  // ═══ WSDL/SOAP discovery (for XXE check) ═════════════════════════════════
  try { await discoverSoapWsdl(sdk, origin); } catch (e: any) { warn(sdk, "SOAP/WSDL discovery error:", e?.message); }
}

// ─── GraphQL Discovery ───────────────────────────────────────────────────────

const GRAPHQL_PATHS = [
  "/graphql", "/graphql/", "/graphql/v1", "/graphql/v2",
  "/api/graphql", "/api/graphql/", "/gql", "/query",
  "/v1/graphql", "/v2/graphql",
];

const GRAPHQL_INTROSPECTION = JSON.stringify({
  query: "{ __schema { types { name } } }",
});

async function discoverGraphQL(sdk: BackendSDK, origin: string) {
  let found = false;
  for (const path of GRAPHQL_PATHS) {
    if (found) break;
    try {
      const url = normUrl(path, origin);
      if (!url) continue;

      // Test with POST introspection query
      const spec = new RequestSpec(url);
      spec.setMethod("POST");
      spec.setHeader("Content-Type", "application/json");
      spec.setHeader("Accept", "application/json");
      spec.setHeader("User-Agent", config.userAgent);
      if (sessionCookies) spec.setHeader("Cookie", sessionCookies);
      spec.setBody(GRAPHQL_INTROSPECTION);

      const result = await sdk.requests.send(spec);
      const reqId = result?.request?.getId?.();
      if (reqId) feedToScanner(sdk, String(reqId));

      const code = result?.response?.getCode?.() ?? 0;
      const body = getBody(result.response);

      if (code === 200 && (body.includes("__schema") || body.includes("__type") || body.includes('"data"'))) {
        found = true;
        log(sdk, `GraphQL endpoint found: ${path}`);
        addEndpoint({ url, method: "POST", params: ["query"], source: "link" as any });

        // Also enqueue GET variant for GraphQL GET support
        const getUrl = normUrl(`${path}?query={__typename}`, origin);
        if (getUrl) {
          enqueue({ url: getUrl, depth: 1, from: url });
          addEndpoint({ url: getUrl, method: "GET", params: ["query"], source: "link" as any });
        }

        // Send a full introspection query so scanner checks can analyze the response
        const fullIntrospection = JSON.stringify({
          query: `{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name } } } } } } }`,
        });
        const fullSpec = new RequestSpec(url);
        fullSpec.setMethod("POST");
        fullSpec.setHeader("Content-Type", "application/json");
        fullSpec.setHeader("Accept", "application/json");
        fullSpec.setHeader("User-Agent", config.userAgent);
        if (sessionCookies) fullSpec.setHeader("Cookie", sessionCookies);
        fullSpec.setBody(fullIntrospection);

        try {
          const fullResult = await sdk.requests.send(fullSpec);
          const fullReqId = fullResult?.request?.getId?.();
          if (fullReqId) feedToScanner(sdk, String(fullReqId));
        } catch {}
      } else if (code === 200 || code === 400 || code === 405) {
        // Even errors from GraphQL endpoints are interesting for the scanner
        if (body.includes("graphql") || body.includes("query") || body.includes("Must provide query")) {
          found = true;
          log(sdk, `GraphQL endpoint found (error response): ${path}`);
          if (reqId) feedToScanner(sdk, String(reqId));
          addEndpoint({ url, method: "POST", params: ["query"], source: "link" as any });
        }
      }
    } catch {}
  }
}

// ─── Common API Path Discovery ───────────────────────────────────────────────

const API_PATHS = [
  "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
  "/rest", "/rest/", "/v1", "/v2",
  "/api/health", "/api/status", "/health", "/status", "/ping",
  "/.well-known/openid-configuration",
  "/.well-known/jwks.json",
];

async function discoverApiPaths(sdk: BackendSDK, origin: string) {
  let discovered = 0;
  for (const path of API_PATHS) {
    if (discovered >= 5) break; // Cap discovery to avoid noise
    try {
      const url = normUrl(path, origin);
      if (!url) continue;

      const spec = new RequestSpec(url);
      spec.setHeader("Accept", "application/json, text/html;q=0.9");
      spec.setHeader("User-Agent", config.userAgent);
      if (sessionCookies) spec.setHeader("Cookie", sessionCookies);

      const result = await sdk.requests.send(spec);
      const reqId = result?.request?.getId?.();
      const code = result?.response?.getCode?.() ?? 0;
      const body = getBody(result.response);
      const cts = getCts(result.response);

      if (code === 200 && body.length > 2) {
        if (reqId) feedToScanner(sdk, String(reqId));

        // Extract URLs from JSON API responses
        if (isJson(cts)) {
          const urls = extractJsonUrls(body, origin);
          for (const u of urls) {
            enqueue({ url: u, depth: 1, from: url });
            trackUrlParams(u, "GET", "json-api");
          }
          discovered++;
        }

        enqueue({ url, depth: 1, from: origin });
        addEndpoint({ url, method: "GET", params: [], source: "link" as any });
      }
    } catch {}
  }
  if (discovered > 0) log(sdk, `API discovery: found ${discovered} API paths`);
}

// ─── WSDL / SOAP Discovery (for XXE check) ──────────────────────────────────

const SOAP_PATHS = [
  "/ws", "/wsdl", "/service", "/services",
  "/soap", "/Service.asmx", "/Service.svc",
  "/?wsdl", "/?WSDL",
];

async function discoverSoapWsdl(sdk: BackendSDK, origin: string) {
  let found = 0;
  for (const path of SOAP_PATHS) {
    if (found >= 2) break;
    try {
      const url = normUrl(path, origin);
      if (!url) continue;

      const spec = new RequestSpec(url);
      spec.setHeader("Accept", "text/xml, application/xml, */*");
      spec.setHeader("User-Agent", config.userAgent);
      if (sessionCookies) spec.setHeader("Cookie", sessionCookies);

      const result = await sdk.requests.send(spec);
      const reqId = result?.request?.getId?.();
      const code = result?.response?.getCode?.() ?? 0;
      const body = getBody(result.response);
      const cts = getCts(result.response);

      if (code === 200 && (isXml(cts) || body.includes("<wsdl:") || body.includes("<definitions") || body.includes("schemas.xmlsoap.org"))) {
        if (reqId) feedToScanner(sdk, String(reqId));
        addEndpoint({ url, method: "POST", params: [], source: "link" as any });

        // Also try a SOAP POST so XXE check sees it as a POST/XML endpoint
        const soapBody = `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><test/></soap:Body></soap:Envelope>`;
        enqueue({
          url, depth: 1, from: origin,
          method: "POST", body: soapBody,
          contentType: "text/xml",
        });

        found++;
        log(sdk, `SOAP/WSDL endpoint found: ${path}`);
      }
    } catch {}
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// History seeding (v3: ALL methods, ALL status codes, preserves method/body)
// ═══════════════════════════════════════════════════════════════════════════════

async function seedFromHistory(sdk: BackendSDK, limit = 1000): Promise<CrawlJob[]> {
  const seeds: CrawlJob[] = [];
  const seenUrls = new Set<string>();

  try {
    if (!sdk?.requests?.query) return seeds;

    // v3: Query ALL responses, not just 200
    for (const filter of ["resp.code.gte:200", "resp.code.gte:400"]) {
      let cursor: any = null;
      while (seeds.length < limit) {
        let q = sdk.requests.query()
          .filter(filter)
          .descending("req", "created_at")
          .first(250);
        if (cursor) q = q.after(cursor);
        const res = await q.execute();
        for (const it of (res?.items || [])) {
          const req = it.request;
          const scheme = req.getTls?.() ? "https" : "http";
          const host = req.getHost?.() || "";
          const port = req.getPort?.();
          const path = req.getPath?.() || "/";
          const query = req.getQuery?.() || "";
          const method = req.getMethod?.() || "GET";
          const portSuffix = port && port !== 80 && port !== 443 ? `:${port}` : "";
          const qs = query ? `?${query}` : "";
          const url = normUrl(`${scheme}://${host}${portSuffix}${path}${qs}`);
          if (!url || seenUrls.has(url + method)) continue;

          // SCOPE CHECK: If seedHost is set, only include matching hosts
          if (seedHost) {
            const stripWww = (h: string) => h.startsWith("www.") ? h.slice(4) : h;
            if (stripWww(host.toLowerCase()) !== stripWww(seedHost.toLowerCase())) continue;
          }

          seenUrls.add(url + method);

          const job: CrawlJob = { url, depth: 0, method };

          // v3: Preserve body for POST/PUT endpoints
          if (method !== "GET" && method !== "HEAD") {
            try {
              const bodyRaw = req.getBody?.();
              if (bodyRaw) {
                job.body = bodyRaw.toText?.() ?? undefined;
                const ct = req.getHeader?.("Content-Type")?.[0];
                if (ct) job.contentType = ct;
              }
            } catch {}
          }

          // v3: Capture cookies from history for session forwarding
          if (!sessionCookies) {
            try {
              const cookie = req.getHeader?.("Cookie")?.[0];
              if (cookie && cookie.length > 5) sessionCookies = cookie;
            } catch {}
          }

          seeds.push(job);
          if (seeds.length >= limit) break;
        }
        if (res?.pageInfo?.hasNextPage) cursor = res.pageInfo.endCursor; else break;
      }
    }
  } catch (e: any) {
    warn(sdk, "seedFromHistory failed:", e?.message);
  }
  return seeds;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════════

function resetState() {
  visited.clear(); queue.length = 0;
  discoveredEndpoints.length = 0;
  collectedRequestIds.clear();
  scanBatchBuffer = [];
  if (scanBatchTimer) { clearTimeout(scanBatchTimer); scanBatchTimer = null; }
  seedHost = null; seedScheme = "https"; sessionCookies = "";
  Object.assign(stats, {
    queued: 0, inFlight: 0, visited: 0, discovered: 0, sent: 0,
    ok200: 0, redirects: 0, errors: 0, forms: 0, params: 0,
    endpoints: 0, scansLaunched: 0, requestIdsCollected: 0,
    since: Date.now(), last: null,
  });
}

function getStatus(): CrawlerStatus {
  return { running: RUNNING, seedHost, seedScheme, config: { ...config }, ...stats, queued: queue.length };
}

function getEndpoints(): DiscoveredEndpoint[] {
  return [...discoveredEndpoints];
}

export async function crawlerStart(sdk: BackendSDK, opts: Partial<CrawlerConfig> & { seeds?: string[] } = {}) {
  if (RUNNING) return { status: getStatus(), message: "Already running" };

  config = { ...DEFAULT_CONFIG, ...(opts || {}) };
  resetState();
  RUNNING = true;
  STOP_REQUESTED = false;

  // Determine seeds
  let seedJobs: CrawlJob[];
  const rawSeeds = Array.isArray(opts?.seeds) ? opts.seeds : [];

  if (rawSeeds.length > 0) {
    // Set seedHost FIRST from raw seeds so history filtering + hostMatches work
    for (const s of rawSeeds) {
      try {
        const abs = s.includes("://") ? s : `https://${s.replace(/^\/*/, "")}`;
        const u = new URL(abs);
        if (!seedHost) {
          seedHost = u.hostname;
          seedScheme = u.protocol.replace(":", "");
        }
      } catch {}
    }
    seedJobs = rawSeeds.map(s => {
      const abs = s.includes("://") ? s : `https://${s.replace(/^\/*/, "")}`;
      return { url: normUrl(abs)!, depth: 0 };
    }).filter(j => j.url);
  } else {
    // No explicit seeds — seedHost is null, seedFromHistory pulls everything
    // We'll set seedHost from the first history result after seeding
    seedJobs = await seedFromHistory(sdk, 1000);
  }

  // Determine seed host and scheme
  for (const job of seedJobs) {
    if (job.url) {
      if (!seedHost) {
        try {
          const u = new URL(job.url);
          seedHost = u.hostname;
          seedScheme = u.protocol.replace(":", "");
        } catch {}
      }
      enqueue(job);
    }
  }

  if (!seedHost && queue.length > 0) {
    try {
      const u = new URL(queue[0]!.url);
      seedHost = u.hostname;
      seedScheme = u.protocol.replace(":", "");
    } catch {}
  }

  log(sdk, `Starting crawl: seeds=${queue.length}, host=${seedHost}, scheme=${seedScheme}, cookies=${sessionCookies ? "yes" : "no"}`);

  // Discover robots.txt, sitemap.xml, GraphQL, API paths, SOAP/WSDL
  // CRITICAL: wrapped in try/catch so scheduler ALWAYS starts even if discovery fails
  if (seedHost) {
    try {
      await discoverRobotsAndSitemap(sdk, `${seedScheme}://${seedHost}`);
    } catch (e: any) {
      warn(sdk, "Discovery phase error (non-fatal):", e?.message ?? e);
    }
  }

  try { sdk.api.send("crawler:started" as any, getStatus()); } catch {}
  scheduler(sdk).catch((e: any) => warn(sdk, "Scheduler error:", e?.message));

  return { status: getStatus() };
}

export function crawlerStop(sdk: BackendSDK) {
  STOP_REQUESTED = true; RUNNING = false;
  flushScanBatch(sdk);
  log(sdk, "Crawl stop requested");
  try { sdk.api.send("crawler:finished" as any, getStatus()); } catch {}
  return { status: getStatus() };
}

export function crawlerConfigure(_sdk: BackendSDK, opts: Partial<CrawlerConfig> = {}) {
  config = { ...config, ...opts };
  return { status: getStatus() };
}

export function crawlerGetStatus(_sdk: BackendSDK) {
  return { status: getStatus() };
}

export function crawlerGetEndpoints(_sdk: BackendSDK) {
  return { endpoints: getEndpoints() };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Passive intercept hook
// ═══════════════════════════════════════════════════════════════════════════════

export function crawlerOnIntercept(sdk: BackendSDK, request: any) {
  if (!RUNNING) return;
  try {
    const scheme = request.getTls?.() ? "https" : "http";
    const host = request.getHost?.() || "";
    const port = request.getPort?.();
    const path = request.getPath?.() || "/";
    const query = request.getQuery?.() || "";
    const method = request.getMethod?.() || "GET";
    const portSuffix = port && port !== 80 && port !== 443 ? `:${port}` : "";
    const qs = query ? `?${query}` : "";
    const url = normUrl(`${scheme}://${host}${portSuffix}${path}${qs}`);
    if (url) {
      const job: CrawlJob = { url, depth: 0, method };
      // Capture cookies from live browsing
      if (config.forwardCookies && !sessionCookies) {
        try {
          const cookie = request.getHeader?.("Cookie")?.[0];
          if (cookie && cookie.length > 5) sessionCookies = cookie;
        } catch {}
      }
      enqueue(job);
    }
  } catch {}
}
