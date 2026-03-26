import { defineCheck, done, type Finding, Severity } from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Passive DOM XSS Sink Detection
 *
 * Scans response bodies for dangerous JavaScript patterns where user-controllable
 * sources (location.hash, document.URL, document.referrer, window.name, etc.)
 * flow into dangerous sinks (innerHTML, document.write, eval, etc.).
 *
 * This is a passive check — it only inspects existing responses, sending zero requests.
 */

type SinkPattern = {
  pattern: RegExp;
  sink: string;
  severity: Severity;
  description: string;
};

// ── Dangerous sinks fed by user-controllable sources ─────────────────────────

const DOM_SOURCES = [
  "location\\.hash",
  "location\\.search",
  "location\\.href",
  "location\\.pathname",
  "document\\.URL",
  "document\\.documentURI",
  "document\\.referrer",
  "document\\.baseURI",
  "window\\.name",
  "document\\.cookie",
  "window\\.location",
  "location\\.toString\\(\\)",
  // Common patterns for extracting params
  "URLSearchParams",
  "getParameter",
  "\\$_GET",
  "\\$_REQUEST",
];

const SOURCE_GROUP = `(?:${DOM_SOURCES.join("|")})`;

const SINK_PATTERNS: SinkPattern[] = [
  // Direct HTML injection sinks
  {
    pattern: new RegExp(`\\.innerHTML\\s*=\\s*[^;]*${SOURCE_GROUP}`, "i"),
    sink: "innerHTML",
    severity: Severity.HIGH,
    description: "User-controlled data assigned to `innerHTML`. Attacker can inject arbitrary HTML/JS.",
  },
  {
    pattern: new RegExp(`\\.outerHTML\\s*=\\s*[^;]*${SOURCE_GROUP}`, "i"),
    sink: "outerHTML",
    severity: Severity.HIGH,
    description: "User-controlled data assigned to `outerHTML`. Attacker can replace element content.",
  },
  {
    pattern: new RegExp(`document\\.write\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "document.write",
    severity: Severity.HIGH,
    description: "User-controlled data passed to `document.write()`. Classic DOM XSS vector.",
  },
  {
    pattern: new RegExp(`document\\.writeln\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "document.writeln",
    severity: Severity.HIGH,
    description: "User-controlled data passed to `document.writeln()`.",
  },

  // Code execution sinks
  {
    pattern: new RegExp(`eval\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "eval()",
    severity: Severity.CRITICAL,
    description: "User-controlled data passed to `eval()`. Direct code execution.",
  },
  {
    pattern: new RegExp(`setTimeout\\s*\\([^,]*${SOURCE_GROUP}`, "i"),
    sink: "setTimeout",
    severity: Severity.HIGH,
    description: "User-controlled data as first argument to `setTimeout()` (string overload executes as JS).",
  },
  {
    pattern: new RegExp(`setInterval\\s*\\([^,]*${SOURCE_GROUP}`, "i"),
    sink: "setInterval",
    severity: Severity.HIGH,
    description: "User-controlled data as first argument to `setInterval()` (string overload executes as JS).",
  },
  {
    pattern: new RegExp(`Function\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "new Function()",
    severity: Severity.CRITICAL,
    description: "User-controlled data passed to `Function()` constructor. Direct code execution.",
  },

  // jQuery sinks
  {
    pattern: new RegExp(`\\$\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "jQuery $()",
    severity: Severity.HIGH,
    description: "User-controlled data passed to jQuery `$()`. If input starts with `<`, jQuery creates DOM elements.",
  },
  {
    pattern: new RegExp(`\\.html\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "jQuery .html()",
    severity: Severity.HIGH,
    description: "User-controlled data passed to jQuery `.html()` (equivalent to innerHTML).",
  },
  {
    pattern: new RegExp(`\\.append\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "jQuery .append()",
    severity: Severity.MEDIUM,
    description: "User-controlled data passed to jQuery `.append()`. Can inject HTML.",
  },
  {
    pattern: new RegExp(`\\.prepend\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "jQuery .prepend()",
    severity: Severity.MEDIUM,
    description: "User-controlled data passed to jQuery `.prepend()`. Can inject HTML.",
  },

  // URL-based sinks
  {
    pattern: new RegExp(`\\.src\\s*=\\s*[^;]*${SOURCE_GROUP}`, "i"),
    sink: ".src assignment",
    severity: Severity.MEDIUM,
    description: "User-controlled data assigned to element `.src`. Can load attacker-controlled resources.",
  },
  {
    pattern: new RegExp(`\\.href\\s*=\\s*[^;]*${SOURCE_GROUP}`, "i"),
    sink: ".href assignment",
    severity: Severity.MEDIUM,
    description: "User-controlled data assigned to `.href`. Can redirect to attacker page or `javascript:` URI.",
  },
  {
    pattern: new RegExp(`\\.action\\s*=\\s*[^;]*${SOURCE_GROUP}`, "i"),
    sink: ".action assignment",
    severity: Severity.MEDIUM,
    description: "User-controlled data assigned to form `.action`. Can redirect form submissions.",
  },

  // Dangerous insertAdjacent* methods
  {
    pattern: new RegExp(`insertAdjacentHTML\\s*\\([^)]*${SOURCE_GROUP}`, "i"),
    sink: "insertAdjacentHTML",
    severity: Severity.HIGH,
    description: "User-controlled data passed to `insertAdjacentHTML()`. Injects raw HTML like innerHTML.",
  },

  // Standalone dangerous patterns (no source needed — the sink itself is suspicious)
  {
    pattern: /document\.write\s*\(\s*(?:unescape|decodeURIComponent)\s*\(/i,
    sink: "document.write(decode...())",
    severity: Severity.MEDIUM,
    description: "document.write with decode function — common DOM XSS pattern in tracking scripts.",
  },
];

const HTML_CT = ["text/html", "application/xhtml"];

function isHtml(resp: any): boolean {
  const cts = resp?.getHeader?.("Content-Type") ?? [];
  return (cts as string[]).some((v: string) =>
    HTML_CT.some(h => String(v).toLowerCase().includes(h))
  );
}

export default defineCheck<Record<never, never>>(({ step }) => {
  step("scan", (state, context) => {
    const { response } = context.target;
    if (!response) return done({ state });
    if (response.getCode() !== 200) return done({ state });
    if (!isHtml(response)) return done({ state });

    const body = response.getBody()?.toText();
    if (!body || body.length < 50) return done({ state });

    // Only scan <script> blocks for efficiency
    const scriptBlocks: string[] = [];
    const scriptRegex = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
    let match;
    while ((match = scriptRegex.exec(body)) !== null) {
      if (match[1] && match[1].trim().length > 10) {
        scriptBlocks.push(match[1]);
      }
    }

    if (scriptBlocks.length === 0) return done({ state });
    const jsContent = scriptBlocks.join("\n");

    const findings: Finding[] = [];
    const seenSinks = new Set<string>();

    for (const sp of SINK_PATTERNS) {
      if (seenSinks.has(sp.sink)) continue;
      if (sp.pattern.test(jsContent)) {
        seenSinks.add(sp.sink);
        findings.push({
          name: `DOM XSS Sink: ${sp.sink}`,
          description:
            `A potentially dangerous DOM XSS pattern was detected in a JavaScript block.\n\n` +
            `**Sink:** \`${sp.sink}\`\n` +
            `**Risk:** ${sp.description}\n\n` +
            `This is a **passive detection** — manual verification is recommended to confirm ` +
            `that a user-controllable source actually reaches this sink.`,
          severity: sp.severity,
          correlation: {
            requestID: context.target.request.getId(),
            locations: [],
          },
        });
      }
    }

    return done({ state, findings });
  });

  return {
    metadata: {
      id: "dom-xss-sinks",
      name: "DOM XSS Sink Detection",
      description:
        "Passively detects dangerous JavaScript patterns where user-controllable sources " +
        "(location.hash, document.URL, etc.) flow into DOM XSS sinks (innerHTML, eval, " +
        "document.write, jQuery, etc.).",
      type: "passive",
      tags: [Tags.XSS, Tags.INJECTION, Tags.INPUT_VALIDATION],
      severities: [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 0, maxRequests: 0 },
    },
    initState: () => ({}),
    dedupeKey: keyStrategy().withHost().withPort().withPath().build(),
    when: (target) => {
      return target.response !== undefined && target.response.getCode() === 200;
    },
  };
});
