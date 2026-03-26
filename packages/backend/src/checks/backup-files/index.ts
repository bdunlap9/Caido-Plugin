import {
  continueWith,
  defineCheck,
  done,
  ScanAggressivity,
  Severity,
} from "engine";
import { Tags } from "../../types";
import { keyStrategy } from "../../utils/key";

/**
 * Active Backup & Sensitive File Discovery
 *
 * Probes for common backup, editor, and config file patterns:
 * - Backup extensions: .bak, .old, .orig, .save, .copy, ~, .swp
 * - Config files: web.config, wp-config.php, config.php, .htaccess, .htpasswd
 * - Version control: .svn/entries, .hg/requires
 * - Package files: composer.json, package.json (with versions = info leak)
 * - Debug files: debug.log, error.log, .DS_Store, Thumbs.db
 */

type FileProbe = {
  path: string;
  pattern?: RegExp;        // Response must match this to confirm
  antiPattern?: RegExp;    // Response must NOT match this (avoids custom 404 pages)
  severity: Severity;
  name: string;
};

const PROBES_CORE: FileProbe[] = [
  // ── Version control ──
  { path: "/.svn/entries", pattern: /^\d+/m, name: "SVN Entries", severity: Severity.HIGH },
  { path: "/.hg/requires", pattern: /revlogv\d|store|dotencode/i, name: "Mercurial Requires", severity: Severity.HIGH },

  // ── Server config ──
  { path: "/.htaccess", pattern: /RewriteRule|RewriteCond|Deny from|Allow from|AuthType/i, name: ".htaccess", severity: Severity.MEDIUM },
  { path: "/.htpasswd", pattern: /^[a-zA-Z0-9_-]+:\$|^[a-zA-Z0-9_-]+:\{/m, name: ".htpasswd", severity: Severity.CRITICAL },
  { path: "/web.config", pattern: /<configuration|<system\.web/i, name: "web.config", severity: Severity.HIGH },
  { path: "/crossdomain.xml", pattern: /<cross-domain-policy|allow-access-from/i, name: "crossdomain.xml", severity: Severity.LOW },

  // ── Application config ──
  { path: "/wp-config.php.bak", pattern: /DB_PASSWORD|DB_NAME|AUTH_KEY/i, name: "WordPress Config Backup", severity: Severity.CRITICAL },
  { path: "/config.php.bak", pattern: /password|database|secret/i, name: "Config Backup", severity: Severity.HIGH },
  { path: "/configuration.php.bak", pattern: /password|\$db/i, name: "Joomla Config Backup", severity: Severity.HIGH },
  { path: "/config/database.yml", pattern: /adapter:|password:|database:/i, name: "Rails DB Config", severity: Severity.HIGH },

  // ── Debug/log files ──
  { path: "/debug.log", pattern: /\[\d{4}-\d{2}-\d{2}|PHP |Error|Warning|Exception/i, name: "Debug Log", severity: Severity.MEDIUM },
  { path: "/error.log", pattern: /\[\d{4}-\d{2}-\d{2}|error|warning|fatal/i, name: "Error Log", severity: Severity.MEDIUM },
  { path: "/access.log", pattern: /\d+\.\d+\.\d+\.\d+.*"GET|"POST/i, name: "Access Log", severity: Severity.MEDIUM },

  // ── DS_Store / metadata ──
  { path: "/.DS_Store", pattern: /Bud1|DSDB/i, name: ".DS_Store", severity: Severity.LOW },

  // ── Package files (version info leak) ──
  { path: "/composer.json", pattern: /"require"|"name".*".*\/.*"/i, name: "composer.json", severity: Severity.LOW },
  { path: "/package.json", pattern: /"dependencies"|"name"/i, name: "package.json", severity: Severity.LOW },
];

const PROBES_AGGRESSIVE: FileProbe[] = [
  // ── Backup extensions of current path ──
  // These are dynamically generated in the step from the target's path
  { path: "/server-status", pattern: /Apache Server Status|Total Accesses/i, name: "Apache Server Status", severity: Severity.MEDIUM },
  { path: "/server-info", pattern: /Apache Server Information|Module Name/i, name: "Apache Server Info", severity: Severity.MEDIUM },
  { path: "/elmah.axd", pattern: /Error log|ELMAH/i, name: "ELMAH Error Log", severity: Severity.HIGH },
  { path: "/trace.axd", pattern: /Application Trace|Request Details/i, name: "ASP.NET Trace", severity: Severity.HIGH },
  { path: "/_profiler", pattern: /Symfony Profiler|profiler/i, name: "Symfony Profiler", severity: Severity.HIGH },
  { path: "/actuator", pattern: /"_links"|"self"|"health"/i, name: "Spring Actuator", severity: Severity.HIGH },
  { path: "/actuator/env", pattern: /"propertySources"|"activeProfiles"/i, name: "Spring Actuator Env", severity: Severity.CRITICAL },
];

function getProbes(aggressivity: ScanAggressivity): FileProbe[] {
  switch (aggressivity) {
    case ScanAggressivity.LOW: return PROBES_CORE.slice(0, 6);
    case ScanAggressivity.MEDIUM: return PROBES_CORE;
    case ScanAggressivity.HIGH: return [...PROBES_CORE, ...PROBES_AGGRESSIVE];
    default: return PROBES_CORE.slice(0, 6);
  }
}

type State = {
  probes: FileProbe[];
  pIndex: number;
  backupExts: string[];
  bIndex: number;
};

const BACKUP_EXTS = [".bak", ".old", ".orig", ".save", ".copy", "~", ".swp", ".tmp"];

export default defineCheck<State>(({ step }) => {

  step("setup", (state, ctx) => {
    const probes = getProbes(ctx.config.aggressivity);

    // Generate backup-extension probes for the current path
    const origPath = ctx.target.request.getPath();
    const backupExts = origPath && origPath !== "/" && /\.\w+$/.test(origPath)
      ? BACKUP_EXTS : [];

    return continueWith({
      nextStep: "testProbe",
      state: { probes, pIndex: 0, backupExts, bIndex: 0 },
    });
  });

  step("testProbe", async (state, ctx) => {
    // First test static probes, then backup extensions
    if (state.pIndex < state.probes.length) {
      const probe = state.probes[state.pIndex]!;

      try {
        const spec = ctx.target.request.toSpec();
        spec.setMethod("GET");
        spec.setPath(probe.path);
        spec.setQuery("");

        const { request, response } = await ctx.sdk.requests.send(spec);

        if (response && response.getCode() === 200) {
          const body = response.getBody?.()?.toText?.() ?? "";
          const ct = (response.getHeader?.("content-type")?.[0] ?? "").toLowerCase();

          // Skip HTML error pages
          if (ct.includes("text/html") && (body.includes("404") || body.includes("not found"))) {
            // Likely a custom 404 page
          } else if (!probe.pattern || probe.pattern.test(body)) {
            if (!probe.antiPattern || !probe.antiPattern.test(body)) {
              return continueWith({
                nextStep: "testProbe",
                state: { ...state, pIndex: state.pIndex + 1 },
                findings: [{
                  name: `Sensitive File Found: ${probe.name}`,
                  description:
                    `The file \`${probe.path}\` is publicly accessible and matched expected content patterns.\n\n` +
                    `This file may contain sensitive configuration data, credentials, or internal server information.`,
                  severity: probe.severity,
                  correlation: { requestID: request.getId(), locations: [] },
                }],
              });
            }
          }
        }
      } catch {}

      return continueWith({
        nextStep: "testProbe",
        state: { ...state, pIndex: state.pIndex + 1 },
      });
    }

    // Then test backup extensions of current path
    if (state.bIndex < state.backupExts.length) {
      const ext = state.backupExts[state.bIndex]!;
      const origPath = ctx.target.request.getPath();
      const backupPath = origPath + ext;

      try {
        const spec = ctx.target.request.toSpec();
        spec.setMethod("GET");
        spec.setPath(backupPath);
        spec.setQuery("");

        const { request, response } = await ctx.sdk.requests.send(spec);

        if (response && response.getCode() === 200) {
          const body = response.getBody?.()?.toText?.() ?? "";
          const ct = (response.getHeader?.("content-type")?.[0] ?? "").toLowerCase();

          // Verify it's not a custom 404 and has real content
          if (body.length > 10 && !ct.includes("text/html")) {
            return continueWith({
              nextStep: "testProbe",
              state: { ...state, bIndex: state.bIndex + 1 },
              findings: [{
                name: `Backup File Found: ${backupPath}`,
                description:
                  `A backup copy of \`${origPath}\` was found at \`${backupPath}\`.\n\n` +
                  `Backup files may contain source code, credentials, or configuration that ` +
                  `the web server does not process (serving raw content instead).`,
                severity: Severity.HIGH,
                correlation: { requestID: request.getId(), locations: [] },
              }],
            });
          }
        }
      } catch {}

      return continueWith({
        nextStep: "testProbe",
        state: { ...state, bIndex: state.bIndex + 1 },
      });
    }

    return done({ state });
  });

  return {
    metadata: {
      id: "backup-files",
      name: "Backup & Sensitive File Discovery",
      description:
        "Probes for common backup files (.bak, .old, ~, .swp), server config files " +
        "(.htaccess, web.config, .htpasswd), version control artifacts (.svn, .hg), " +
        "debug endpoints (server-status, actuator), and log files.",
      type: "active",
      tags: [Tags.INFORMATION_DISCLOSURE, Tags.FILE_DISCLOSURE],
      severities: [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
      aggressivity: { minRequests: 3, maxRequests: 30 },
    },
    initState: (): State => ({ probes: [], pIndex: 0, backupExts: [], bIndex: 0 }),
    dedupeKey: keyStrategy().withHost().withPort().withBasePath().build(),
  };
});
