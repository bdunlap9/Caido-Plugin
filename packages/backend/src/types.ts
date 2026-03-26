import type { SDK } from "caido:plugin";

// BackendEvents: events sent from backend to frontend
export type BackendEvents = {
  "passive:queue-new": (taskID: string, requestID: string) => void;
  "passive:queue-started": (taskID: string) => void;
  "passive:queue-finished": (taskID: string) => void;
  "active:session-updated": (sessionID: string) => void;
  "session:created": (...args: any[]) => void;
  "session:updated": (...args: any[]) => void;
  "session:progress": (...args: any[]) => void;
  // Crawler events
  "crawler:started": (...args: any[]) => void;
  "crawler:progress": (...args: any[]) => void;
  "crawler:finished": (...args: any[]) => void;
  "crawler:scan-launched": (sessionId: string, targetCount: number) => void;
};

// BackendSDK: the SDK type used throughout the backend.
// We use `any` for the API generic to avoid circular imports with index.ts.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type BackendSDK = SDK<any, BackendEvents>;

export enum Tags {
  // General
  XSS = "xss",
  CORS = "cors",
  SENSITIVE = "sensitive",
  INFO = "info",
  DISCLOSURE = "disclosure",

  // Clickjacking / framing
  CLICKJACKING = "clickjacking",
  X_FRAME_OPTIONS = "x-frame-options",
  UI_REDRESSING = "ui-redressing",
  FRAME_ANCESTORS = "frame-ancestors",

  // Security headers
  SECURITY_HEADERS = "security-headers",

  // CSP
  CSP = "csp",
  SCRIPT_SRC = "script-src",
  STYLE_SRC = "style-src",
  FORM_ACTION = "form-action",
  REPORT_ONLY = "report-only",
  ENFORCEMENT = "enforcement",
  SUPPLY_CHAIN = "supply-chain",
  ATTACK_SURFACE = "attack-surface",

  // Injection
  INJECTION = "injection",
  CSS_INJECTION = "css-injection",
  COMMAND_EXECUTION = "command-execution",
  SQLI = "sqli",
  SSTI = "ssti",
  RCE = "rce",
  TEMPLATE = "template",
  INPUT_VALIDATION = "input-validation",

  // Information disclosure
  INFORMATION_DISCLOSURE = "information-disclosure",
  SENSITIVE_DATA = "sensitive-data",
  PII = "pii",
  ERROR_HANDLING = "error-handling",
  DEBUG = "debug",
  FILE_DISCLOSURE = "file-disclosure",

  // Cookies
  COOKIES = "cookies",
  HTTPONLY = "httponly",
  SECURE = "secure",
  TLS = "tls",

  // Redirect
  REDIRECT = "redirect",
  OPEN_REDIRECT = "open-redirect",

  // Crypto
  HASH = "hash",
  PASSWORD = "password",
  CRYPTOGRAPHY = "cryptography",

  // Forms / CSRF
  FORM_HIJACKING = "form-hijacking",
  CSRF = "csrf",

  // Path traversal
  PATH_TRAVERSAL = "path-traversal",

  // Syntax / validation
  SYNTAX = "syntax",
  VALIDATION = "validation",

  // Access control
  BROKEN_ACCESS_CONTROL = "broken-access-control",
  BYPASS = "bypass",
}
