import { defineCheck, done, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";
import {
  isTextualContentType,
  stripNoisyHtml,
  extractLikelyEmails,
} from "../../utils/emails";

type State = Record<string, never>;

export default defineCheck<State>(({ step }) => {
  step("scan", (_state, ctx) => {
    const resp = ctx.target.response;
    if (!resp) return done({ state: {} as State });

    const cts = resp.getHeader?.("content-type") ?? [];
    if (!isTextualContentType(cts)) return done({ state: {} as State });

    const body = resp.getBody?.()?.toText?.() ?? "";
    if (!body) return done({ state: {} as State });

    // Remove noisy parts and extract
    const visible = stripNoisyHtml(body);
    const emails = extractLikelyEmails(visible)
      .filter(e => e.confidence === "high");

    if (emails.length === 0) return done({ state: {} as State });

    const snippet = visible.slice(0, 500);
    const list = emails.map(e => `- \`${e.value}\``).join("\n");

    return done({
      state: {} as State,
      findings: [
        {
          name: "Email address disclosure",
          description:
            `One or more email addresses were found in the response body.\n\n` +
            `**Addresses (de-duplicated):**\n${list}\n\n` +
            `**Content-Type:** ${cts.join(", ")}\n` +
            `**Snippet:**\n\`\`\`\n${snippet}\n\`\`\`\n`,
          severity: Severity.LOW,
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
      id: "email-disclosure",
      name: "Email address disclosure (low-noise)",
      description:
        "Detects likely email addresses in textual responses with aggressive false-positive reduction and de-duplication.",
      type: "passive",
      tags: [Tags.INFO, Tags.PII],
      severities: [Severity.LOW],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    dedupeKey: keyStrategy().withMethod().withHost().withPort().withPath().build(),
    initState: () => ({} as State),
    when: (target) => target.response !== undefined,
  };
});
