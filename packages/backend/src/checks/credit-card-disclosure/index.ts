import { defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import { isTextualContentType } from "../../utils/emails";

// ---- helpers --------------------------------------------------------------

// Exclude decimals & ensure clean digit boundaries around the whole candidate.
// Accepts 13–19 digits with optional single separators (space or dash).
const CC_CANDIDATE = /(?<![\d.])(?:\d[ -]?){13,19}(?![\d.])/g;

// Known BIN/IIN patterns and lengths to reduce Luhn-only FPs.
type Brand = {
  name: string;
  lengths: number[];
  prefixes: RegExp[];
};

const BRANDS: Brand[] = [
  { name: "Visa",        lengths: [13,16,19], prefixes: [/^4/] },
  { name: "Mastercard",  lengths: [16],       prefixes: [/^5[1-5]/, /^22[2-9]/, /^2[3-7]\d/] },
  { name: "American Express", lengths: [15],  prefixes: [/^34/, /^37/] },
  { name: "Discover",    lengths: [16,19],    prefixes: [/^6011/, /^65/, /^64[4-9]/, /^622(12[6-9]|1[3-9]\d|[2-8]\d{2}|9([01]\d|2[0-5]))/] },
  { name: "JCB",         lengths: [16,19],    prefixes: [/^35(2[89]|[3-8]\d)/] },
  { name: "Diners Club", lengths: [14,16],    prefixes: [/^3(0[0-5]|[68])/] },
  { name: "Maestro",     lengths: [12,13,14,15,16,17,18,19], prefixes: [/^(50|5[6-9]|6[0-9])/] },
];

export function luhnOk(digits: string): boolean {
  let sum = 0, dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (dbl) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

function matchBrand(digits: string): string | null {
  for (const b of BRANDS) {
    if (!b.lengths.includes(digits.length)) continue;
    if (b.prefixes.some((re) => re.test(digits))) return b.name;
  }
  return null;
}

function maskPan(d: string): string {
  const first6 = d.slice(0, 6);
  const last4 = d.slice(-4);
  const mid = Math.max(0, d.length - 10);
  return `${first6}${"*".repeat(mid)}${last4}`;
}

function nearestKey(body: string, startIndex: number): string | null {
  const windowStart = Math.max(0, startIndex - 160);
  const slice = body.slice(windowStart, startIndex);
  const m =
    slice.match(/"([A-Za-z0-9_.\-\/]+)"\s*:\s*$/) ||
    slice.match(/([A-Za-z0-9_.\-\/]+)\s*=\s*$/);
  return m ? m[1]!.toLowerCase() : null;
}

const NOISY_KEYS = [
  "score", "scores", "ranking", "rank", "index", "indices", "id", "ids",
  "guid", "uuid", "token", "nonce", "order", "qty", "quantity", "price",
  "amount", "offset", "timestamp", "time", "ts", "version", "model",
  "tracking", "predictor", "feature", "upc", "ean", "sku", "zipcode", "postal",
  "phone", "msisdn", "member_price", "item_id", "parent_item_id",
];

function isLikelyTelemetryKey(k: string | null): boolean {
  if (!k) return false;
  return NOISY_KEYS.some((w) => k.includes(w));
}

function* findRealPans(body: string): Generator<{ pan: string; brand: string; index: number }> {
  const seen = new Set<string>();
  for (const m of body.matchAll(CC_CANDIDATE)) {
    const raw = m[0];
    const index = m.index ?? 0;
    const digits = raw.replace(/[^\d]/g, "");

    if (digits.length < 13 || digits.length > 19) continue;
    if (seen.has(digits)) continue;
    seen.add(digits);

    const prev = body[index - 1] || "";
    const next = body[index + raw.length] || "";
    if (prev.toLowerCase() === "e" || next.toLowerCase() === "e") continue;

    if (isLikelyTelemetryKey(nearestKey(body, index))) continue;

    if (!luhnOk(digits)) continue;
    const brand = matchBrand(digits);
    if (!brand) continue;

    yield { pan: digits, brand, index };
  }
}

// ---- check ----------------------------------------------------------------

export default defineCheck<unknown>(({ step }) => {
  step("scan", (_state, ctx) => {
    const response = ctx.target.response;
    if (!response) return done({ state: {} });

    const cts = response.getHeader?.("content-type") ?? [];
    if (!isTextualContentType(cts)) return done({ state: {} });

    const body = response.getBody?.()?.toText?.() ?? "";
    if (!body || body.length === 0) return done({ state: {} });

    const results = Array.from(findRealPans(body)).slice(0, 12);
    if (results.length === 0) return done({ state: {} });

    const items = results.map(({ pan, brand }) => `- ${maskPan(pan)} (${brand})`).join("\n");
    const snippetPreview = (() => {
      const first = results[0];
      if (!first) return "";
      const span = 160;
      const start = Math.max(0, first.index - Math.floor(span / 2));
      return body.slice(start, start + span);
    })();

    return done({
      state: {},
      findings: [
        {
          name: "Credit Card Number Disclosed",
          description:
            "One or more Primary Account Numbers (PANs) appear in the response body. " +
            "Heuristics include Luhn validity, plausible IIN/brand, and context checks to reduce false positives.\n\n" +
            "**Discovered (masked):**\n" + items + "\n\n" +
            "**Response evidence (snippet):**\n```\n" + snippetPreview + "\n```",
          severity: Severity.MEDIUM,
          correlation: {
            requestID: ctx.target.request.getId(),
            locations: [],
          },
        },
      ],
    });
  });

  return {
    metadata: {
      id: "credit-card-disclosure",
      name: "Credit Card Number Disclosed",
      description: "Detects possible credit card numbers (PANs) in responses using Luhn + IIN and context gating.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.PII],
      severities: [Severity.LOW, Severity.MEDIUM, Severity.HIGH],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().build(),
    when: (target) => target.response !== undefined,
  };
});
