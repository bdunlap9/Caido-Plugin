// Very small “textual” gate so we don’t parse images, fonts, etc.
export function isTextualContentType(cts: string[] | undefined): boolean {
  if (!cts || cts.length === 0) return false;
  const L = cts.map(String).map(s => s.toLowerCase());
  return L.some(v =>
    v.includes("text/") ||
    v.includes("json") ||
    v.includes("xml") ||
    v.includes("javascript") ||
    v.includes("x-www-form-urlencoded")
  );
}

/**
 * Strip non-visible / noisy HTML parts so minified JS/CSS don’t cause false matches.
 * This is intentionally light-weight (regex-based) for speed.
 */
export function stripNoisyHtml(input: string): string {
  if (!input) return "";
  let s = input;
  // Remove comments
  s = s.replace(/<!--([\s\S]*?)-->/g, "");
  // Remove <script>...</script> and <style>...</style>
  s = s.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, "");
  s = s.replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, "");
  // Collapse tags to spaces so text around attributes becomes contiguous
  s = s.replace(/<\/?[^>]+>/g, " ");
  return s;
}

/**
 * Extract emails with confidence scoring and aggressive de-duplication.
 * - RFC 5322 is huge; we use a practical subset and then post-filter.
 * - We also mark "high" confidence when preceded by "mailto:" or when surrounded by human text.
 */
export function extractLikelyEmails(input: string): Array<{ value: string; confidence: "high" | "medium" }> {
  const text = input || "";
  const out = new Map<string, "high" | "medium">();

  // Practical email pattern: local@domain.tld
  // local: 1-64 allowed chars; domain: at least one dot; tld: letters 2-24
  const re = /\b(?:mailto:)?([A-Z0-9._%+-]{1,64})@([A-Z0-9.-]+\.[A-Z]{2,24})\b/gi;

  // Reserved / non-routable / test domains we don't want to flag
  const reserved = new Set([
    "example.com","example.net","example.org","invalid","localhost","local","localdomain",
    "test","test.local","home","lan","internal"
  ]);

  // Simple TLD sanity (letters only, length 2-24)
  const tldOK = (d: string) => {
    const m = d.toLowerCase().match(/\.([a-z]{2,24})$/);
    return !!m;
  };

  // Obvious throwaways and bot senders
  const isThrowawayLocal = (l: string) => /^(no[-_. ]?reply|do[-_. ]?not[-_. ]?reply|noreply\d*)$/i.test(l);

  // Some false positives come from things like "something@2x.png" in asset names.
  const looksLikeAsset = (d: string) => /\.(png|jpe?g|gif|svg|webp|css|js|map|ico|mp4|mp3|woff2?|ttf|otf)$/i.test(d);

  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    const full = m[0];
    const local = m[1] ?? "";
    const domainFull = m[2] ?? "";
    if (!local || !domainFull) continue;
    const domain = domainFull.toLowerCase();

    // Confidence booster if the match had "mailto:" prefix
    const hadMailto = /^mailto:/i.test(full);

    // Domain sanity
    if (!domain.includes(".")) continue;
    if (!tldOK(domain)) continue;
    if (reserved.has(domain) || reserved.has(domain.split(".").slice(-2).join("."))) continue;
    if (domain.endsWith(".local") || domain.endsWith(".internal")) continue;
    if (looksLikeAsset(domain)) continue; // things like "img@2x.png" slip through otherwise

    // Local-part sanity
    if (!/[a-z]/i.test(local)) continue; // must have at least one letter (avoid pure numbers/hashes)
    if (isThrowawayLocal(local)) continue;
    if (/\.\.|^\.|\.$|^-|-$/.test(local)) continue; // consecutive dots or starting/ending dot/hyphen

    // Extra false positive reducer: ensure surrounding characters look like human text, not code junk
    const start = Math.max(0, m.index - 20);
    const end = Math.min(text.length, m.index + full.length + 20);
    const around = text.slice(start, end);
    const looksLikeCodeNoise = /[#{};=:)(\[\])"']/.test(around) && !/\b(mail|contact|support|help|@)\b/i.test(around);
    const confidence: "high" | "medium" = hadMailto || !looksLikeCodeNoise ? "high" : "medium";

    const value = `${local}@${domain}`;
    const prev = out.get(value);
    if (!prev || prev === "medium") out.set(value, confidence); // keep higher confidence
  }

  return [...out.entries()].map(([value, confidence]) => ({ value, confidence }));
}
