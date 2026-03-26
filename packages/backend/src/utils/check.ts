import {
  type CheckMetadata,
  defineCheck,
  done,
  type Finding,
  type RuntimeContext,
} from "engine";

import { extractBodyMatches } from "./body";
import { keyStrategy } from "./key";

/** Content types where regex disclosure scanning is NOT appropriate */
function isCodeAsset(context: RuntimeContext): boolean {
  // Check content type
  try {
    const ct = (context.target.response?.getHeader?.("content-type")?.[0] ?? "").toLowerCase();
    if (ct.includes("javascript") || ct.includes("css") || ct.includes("image/") ||
        ct.includes("font") || ct.includes("wasm") || ct.includes("octet-stream")) {
      return true;
    }
  } catch {}
  // Check file extension
  const path = (context.target.request.getPath?.() ?? "").toLowerCase();
  if (/\.(js|mjs|cjs|jsx|ts|tsx|css|scss|map|svg|woff|woff2|ttf|eot|png|jpg|gif|ico|webp)(\?|$)/.test(path)) {
    return true;
  }
  return false;
}

export const defineResponseRegexCheck = (options: {
  patterns: RegExp[];
  toFindings: (matches: string[], runtimeContext: RuntimeContext) => Finding[];
  metadata: CheckMetadata;
}) => {
  return defineCheck(({ step }) => {
    step("scanResponse", (state, context) => {
      const response = context.target.response;
      if (response === undefined || response.getCode() !== 200) {
        return done({ state });
      }

      // Skip JS/CSS/image/font responses — code/assets are NOT disclosure
      if (isCodeAsset(context)) {
        return done({ state });
      }

      const matches = extractBodyMatches(response, options.patterns);
      if (matches.length > 0) {
        return done({
          findings: options.toFindings(matches, context),
          state,
        });
      }

      return done({ state });
    });

    return {
      metadata: options.metadata,
      initState: () => ({}),
      dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
      when: (context) =>
        context.response !== undefined && context.response.getCode() === 200,
    };
  });
};
