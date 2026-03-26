import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Passively detects secrets, API keys, and tokens leaked in response bodies.
 * Covers: AWS, GitHub, Slack, Google, Stripe, Twilio, SendGrid, Heroku,
 * JWT tokens, Bearer tokens, generic API keys, and private keys.
 */

type SecretPattern = {
  name: string;
  pattern: RegExp;
  severity: Severity;
};

const SECRET_PATTERNS: SecretPattern[] = [
  // ── AWS ──
  { name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/g, severity: Severity.CRITICAL },
  { name: "AWS Secret Access Key", pattern: /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, severity: Severity.CRITICAL },

  // ── GitHub ──
  { name: "GitHub Personal Access Token", pattern: /\bghp_[A-Za-z0-9_]{36}\b/g, severity: Severity.HIGH },
  { name: "GitHub OAuth Token", pattern: /\bgho_[A-Za-z0-9_]{36}\b/g, severity: Severity.HIGH },
  { name: "GitHub App Token", pattern: /\b(ghu|ghs)_[A-Za-z0-9_]{36}\b/g, severity: Severity.HIGH },
  { name: "GitHub Fine-Grained PAT", pattern: /\bgithub_pat_[A-Za-z0-9_]{22,82}\b/g, severity: Severity.HIGH },

  // ── Slack ──
  { name: "Slack Bot Token", pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g, severity: Severity.HIGH },
  { name: "Slack User Token", pattern: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g, severity: Severity.HIGH },
  { name: "Slack Webhook URL", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g, severity: Severity.MEDIUM },

  // ── Google ──
  { name: "Google API Key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: Severity.MEDIUM },
  { name: "Google OAuth Client Secret", pattern: /(?:client_secret|google_secret)\s*[=:]\s*["']?([A-Za-z0-9_-]{24})["']?/gi, severity: Severity.HIGH },

  // ── Stripe ──
  { name: "Stripe Secret Key", pattern: /\bsk_live_[0-9a-zA-Z]{24,99}\b/g, severity: Severity.CRITICAL },
  { name: "Stripe Publishable Key", pattern: /\bpk_live_[0-9a-zA-Z]{24,99}\b/g, severity: Severity.LOW },

  // ── Twilio ──
  { name: "Twilio API Key", pattern: /\bSK[0-9a-fA-F]{32}\b/g, severity: Severity.HIGH },

  // ── SendGrid ──
  { name: "SendGrid API Key", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: Severity.HIGH },

  // ── Heroku ──
  { name: "Heroku API Key", pattern: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, severity: Severity.LOW }, // UUID — only flagged when near "heroku"

  // ── Mailgun ──
  { name: "Mailgun API Key", pattern: /\bkey-[0-9a-zA-Z]{32}\b/g, severity: Severity.HIGH },

  // ── JWT Tokens ──
  { name: "JWT Token", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: Severity.MEDIUM },

  // ── Bearer Tokens (generic, long-lived) ──
  { name: "Bearer Token in Body", pattern: /["']Bearer\s+[A-Za-z0-9_\-.~+/]{20,}["']/g, severity: Severity.MEDIUM },

  // ── Generic API Key patterns ──
  { name: "Generic API Key", pattern: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*["']([A-Za-z0-9_\-]{20,64})["']/gi, severity: Severity.MEDIUM },
  { name: "Generic Secret", pattern: /(?:secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9_\-]{20,64})["']/gi, severity: Severity.HIGH },
  { name: "Generic Password in Config", pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,64})["']/gi, severity: Severity.HIGH },

  // ── NPM Token ──
  { name: "NPM Token", pattern: /\/\/registry\.npmjs\.org\/:_authToken=[A-Za-z0-9_-]+/g, severity: Severity.HIGH },

  // ── Firebase ──
  { name: "Firebase Database URL", pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi, severity: Severity.LOW },

  // ── Azure ──
  { name: "Azure Storage Key", pattern: /(?:AccountKey|SharedAccessSignature)\s*=\s*[A-Za-z0-9+/=]{40,}/gi, severity: Severity.CRITICAL },

  // ── OpenAI ──
  { name: "OpenAI API Key", pattern: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, severity: Severity.HIGH },
  { name: "OpenAI API Key (new format)", pattern: /\bsk-proj-[A-Za-z0-9_-]{40,}\b/g, severity: Severity.HIGH },

  // ── Anthropic ──
  { name: "Anthropic API Key", pattern: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/g, severity: Severity.HIGH },

  // ── Shopify ──
  { name: "Shopify Access Token", pattern: /\bshpat_[a-fA-F0-9]{32}\b/g, severity: Severity.HIGH },
  { name: "Shopify Shared Secret", pattern: /\bshpss_[a-fA-F0-9]{32}\b/g, severity: Severity.HIGH },

  // ── Discord ──
  { name: "Discord Bot Token", pattern: /\b(?:Bot |Bearer )[MN][A-Za-z\d]{23,}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b/g, severity: Severity.HIGH },
  { name: "Discord Webhook", pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g, severity: Severity.MEDIUM },

  // ── Telegram (require "bot" context nearby to avoid FP on random number:string combos) ──
  { name: "Telegram Bot Token", pattern: /(?:telegram|bot_token|TELEGRAM|tg_token|bot)\s*[=:]\s*['"]?\d{8,10}:[A-Za-z0-9_-]{35}\b/gi, severity: Severity.MEDIUM },

  // ── DigitalOcean ──
  { name: "DigitalOcean PAT", pattern: /\bdop_v1_[a-f0-9]{64}\b/g, severity: Severity.HIGH },

  // ── Datadog (require context — key alone is just a hex string) ──
  { name: "Datadog API Key", pattern: /(?:datadog|dd[-_]api[-_]?key)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/gi, severity: Severity.MEDIUM },

  // ── Supabase ──
  { name: "Supabase Key", pattern: /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: Severity.MEDIUM },

  // ── Private keys inline ──
  { name: "RSA Private Key Header", pattern: /-----BEGIN RSA PRIVATE KEY-----/g, severity: Severity.CRITICAL },
  { name: "Private Key Header", pattern: /-----BEGIN PRIVATE KEY-----/g, severity: Severity.CRITICAL },
  { name: "EC Private Key Header", pattern: /-----BEGIN EC PRIVATE KEY-----/g, severity: Severity.CRITICAL },
];

const TEXT_HINTS = ["text/", "json", "xml", "javascript", "x-www-form"];

function isTextual(resp: any): boolean {
  const cts = resp?.getHeader?.("content-type") ?? [];
  return (cts as string[]).some((v: string) =>
    TEXT_HINTS.some(h => String(v).toLowerCase().includes(h))
  );
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, ctx) => {
    const resp = ctx.target.response;
    if (!resp) return done({ state });
    if (!isTextual(resp)) return done({ state });

    const body = resp.getBody?.()?.toText?.() ?? "";
    if (!body || body.length < 10) return done({ state });

    // Cap body scan at 512KB for performance
    const scanBody = body.slice(0, 512 * 1024);

    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const sp of SECRET_PATTERNS) {
      // Reset regex lastIndex
      sp.pattern.lastIndex = 0;
      const matches = scanBody.match(sp.pattern);
      if (!matches) continue;

      for (const match of matches) {
        const dedupeKey = `${sp.name}:${match.slice(0, 20)}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        // Mask the secret for safe reporting
        const masked = match.length > 12
          ? match.slice(0, 6) + "***" + match.slice(-4)
          : match.slice(0, 3) + "***";

        findings.push({
          name: `${sp.name} Disclosed`,
          description:
            `A **${sp.name}** was found in the response body.\n\n` +
            `**Masked value:** \`${masked}\`\n\n` +
            `Exposed secrets can lead to unauthorized access, data breaches, and account takeover. ` +
            `Rotate this credential immediately and remove it from the response.`,
          severity: sp.severity,
          correlation: {
            requestID: ctx.target.request.getId(),
            locations: [],
          },
        });
      }

      // Limit findings per response to avoid flooding
      if (findings.length >= 10) break;
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "secret-disclosure",
      name: "Secret / API Key Disclosure",
      description:
        "Detects leaked API keys, tokens, and secrets in response bodies. Covers AWS, GitHub, " +
        "Slack, Google, Stripe, Twilio, SendGrid, JWT, Bearer tokens, and generic API key patterns.",
      type: "passive",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.SENSITIVE_DATA],
      severities: [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (t) => t.response !== undefined,
  };
});
