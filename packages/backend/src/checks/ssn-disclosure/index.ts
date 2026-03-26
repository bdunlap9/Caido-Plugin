import { Severity } from "engine";

import { Tags } from "../../types";
import { defineResponseRegexCheck } from "../../utils/check";

// Social Security Number regex patterns
// IMPORTANT: SSN patterns are inherently FP-prone. Real SSNs:
// - Area (first 3): 001-899 but NOT 000, 666
// - Group (middle 2): 01-99 but NOT 00
// - Serial (last 4): 0001-9999 but NOT 0000
// We require 2+ matches or a context keyword to flag.
const SSN_PATTERNS = [
  // Standard SSN format: XXX-XX-XXXX (with valid area numbers)
  /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  // SSN with spaces: XXX XX XXXX
  /\b(?!000|666|9\d\d)\d{3}\s(?!00)\d{2}\s(?!0000)\d{4}\b/g,
  // SSN with dots: XXX.XX.XXXX
  /\b(?!000|666|9\d\d)\d{3}\.(?!00)\d{2}\.(?!0000)\d{4}\b/g,
];

export default defineResponseRegexCheck({
  patterns: SSN_PATTERNS,
  toFindings: (matches, context) => {
    // Require at least 2 distinct SSN-like matches OR a context keyword
    // to avoid flagging random number patterns like phone numbers
    const unique = [...new Set(matches)];
    const body = context.target.response?.getBody?.()?.toText?.() ?? "";
    const hasContext = /ssn|social.security|tax.id|taxpayer|tin\b|identity.number/i.test(body);

    if (unique.length < 2 && !hasContext) return [];

    return [{
      name: "Social Security Number Disclosed",
      description:
        `Potential Social Security Numbers detected in the response.\n\n` +
        `**Matches:** ${unique.slice(0, 5).map(s => `\`${s}\``).join(", ")}\n\n` +
        `SSN disclosure enables identity theft and financial fraud.`,
      severity: Severity.HIGH,
      correlation: {
        requestID: context.target.request.getId(),
        locations: [],
      },
    }];
  },
  metadata: {
    id: "ssn-disclosure",
    name: "Social Security Number Disclosed",
    description:
      "Detects Social Security Numbers in HTTP responses that could lead to identity theft",
    type: "passive",
    tags: [Tags.INFORMATION_DISCLOSURE, Tags.SENSITIVE_DATA],
    severities: [Severity.HIGH],
    aggressivity: {
      minRequests: 0,
      maxRequests: 0,
    },
  },
});
