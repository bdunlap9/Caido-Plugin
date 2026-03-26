import antiClickjackingScan from "./anti-clickjacking";
import applicationErrorsScan from "./application-errors";
import backupFilesScan from "./backup-files";
import bigRedirectsScan from "./big-redirects";
import cacheableAuthScan from "./cacheable-auth";
import commandInjectionScan from "./command-injection";
import cookieHttpOnlyScan from "./cookie-httponly";
import cookieSameSiteScan from "./cookie-samesite";
import cookieSecureScan from "./cookie-secure";
import corsMisconfigScan from "./cors-misconfig";
import corsOriginReflectionScan from "./cors-origin-reflection";
import creditCardDisclosureScan from "./credit-card-disclosure";
import crlfInjectionScan from "./crlf-injection";
import csrfTokenMissingScan from "./csrf-token-missing";
import cspAllowlistedScriptsScan from "./csp-allowlisted-scripts";
import cspClickjackingScan from "./csp-clickjacking";
import cspFormHijackingScan from "./csp-form-hijacking";
import cspMalformedSyntaxScan from "./csp-malformed-syntax";
import cspNotEnforcedScan from "./csp-not-enforced";
import cspUntrustedScriptScan from "./csp-untrusted-script";
import cspUntrustedStyleScan from "./csp-untrusted-style";
import dbConnectionDisclosureScan from "./db-connection-disclosure";
import debugErrorsScan from "./debug-errors";
import directoryListingScan from "./directory-listing";
import domXssSinksScan from "./dom-xss";
import emailDisclosureScan from "./email-disclosure";
import exposedEnvScan from "./exposed-env";
import filePathDisclosureScan from "./file-path-disclosure";
import forbiddenBypassScan from "./forbidden-bypass";
import gitConfigScan from "./git-config";
import graphqlInjectionScan from "./graphql-injection";
import graphqlIntrospectionScan from "./graphql-introspection";
import hashDisclosureScan from "./hash-disclosure";
import hostHeaderInjectionScan from "./host-header-injection";
import httpParamPollutionScan from "./http-param-pollution";
import insecureFormActionScan from "./insecure-form-action";
import insecureMethodsScan from "./insecure-methods";
import jsonHtmlResponseScan from "./json-html-response";
import jwtWeaknessScan from "./jwt-weakness";
import logInjectionScan from "./log-injection";
import missingContentTypeScan from "./missing-content-type";
import missingSriScan from "./missing-sri";
import nosqlInjectionScan from "./nosql-injection";
import openApiExposureScan from "./open-api-exposure";
import openRedirectScan from "./open-redirect";
import pathTraversalScan from "./path-traversal";
import phpinfoScan from "./phpinfo";
import privateIpDisclosureScan from "./private-ip-disclosure";
import privateKeyDisclosureScan from "./private-key-disclosure";
import prototypePollutionScan from "./prototype-pollution";
import { basicReflectedXSSScan } from "./reflected-xss";
import robotsTxtScan from "./robots-txt";
import secretDisclosureScan from "./secret-disclosure";
import securityHeadersScan from "./security-headers";
import serverInfoLeakScan from "./server-info-leak";
import sourceCodeDisclosureScan from "./source-code-disclosure";
import { mysqlErrorBased, mysqlTimeBased } from "./sql-injection";
import sqlStatementInParams from "./sql-statement-in-params";
import ssrfDetectionScan from "./ssrf-detection";
import ssnDisclosureScan from "./ssn-disclosure";
import sstiScan from "./ssti";
import subdomainTakeoverScan from "./subdomain-takeover";
import suspectTransformScan from "./suspect-transform";
import xxeInjectionScan from "./xxe-injection";

export type CheckID = (typeof Checks)[keyof typeof Checks];
export const Checks = {
  ANTI_CLICKJACKING: "anti-clickjacking",
  APPLICATION_ERRORS: "application-errors",
  BACKUP_FILES: "backup-files",
  BIG_REDIRECTS: "big-redirects",
  CACHEABLE_AUTH: "cacheable-auth",
  COMMAND_INJECTION: "command-injection",
  COOKIE_HTTPONLY: "cookie-httponly",
  COOKIE_SAMESITE: "cookie-samesite",
  COOKIE_SECURE: "cookie-secure",
  CORS_MISCONFIG: "cors-misconfig",
  CORS_ORIGIN_REFLECTION: "cors-origin-reflection",
  CREDIT_CARD_DISCLOSURE: "credit-card-disclosure",
  CRLF_INJECTION: "crlf-injection",
  CSRF_TOKEN_MISSING: "csrf-token-missing",
  CSP_ALLOWLISTED_SCRIPTS: "csp-allowlisted-scripts",
  CSP_CLICKJACKING: "csp-clickjacking",
  CSP_FORM_HIJACKING: "csp-form-hijacking",
  CSP_MALFORMED_SYNTAX: "csp-malformed-syntax",
  CSP_NOT_ENFORCED: "csp-not-enforced",
  CSP_UNTRUSTED_SCRIPT: "csp-untrusted-script",
  CSP_UNTRUSTED_STYLE: "csp-untrusted-style",
  DB_CONNECTION_DISCLOSURE: "db-connection-disclosure",
  DEBUG_ERRORS: "debug-errors",
  DIRECTORY_LISTING: "directory-listing",
  DOM_XSS_SINKS: "dom-xss-sinks",
  EMAIL_DISCLOSURE: "email-disclosure",
  EXPOSED_ENV: "exposed-env",
  FILE_PATH_DISCLOSURE: "file-path-disclosure",
  FORBIDDEN_BYPASS: "forbidden-bypass",
  GIT_CONFIG: "git-config",
  GRAPHQL_INJECTION: "graphql-injection",
  GRAPHQL_INTROSPECTION: "graphql-introspection",
  HASH_DISCLOSURE: "hash-disclosure",
  HOST_HEADER_INJECTION: "host-header-injection",
  HTTP_PARAM_POLLUTION: "http-param-pollution",
  INSECURE_FORM_ACTION: "insecure-form-action",
  INSECURE_METHODS: "insecure-methods",
  JSON_HTML_RESPONSE: "json-html-response",
  JWT_WEAKNESS: "jwt-weakness",
  LOG_INJECTION: "log-injection",
  MISSING_CONTENT_TYPE: "missing-content-type",
  MISSING_SRI: "missing-sri",
  NOSQL_INJECTION: "nosql-injection",
  OPEN_API_EXPOSURE: "open-api-exposure",
  OPEN_REDIRECT: "open-redirect",
  PATH_TRAVERSAL: "path-traversal",
  PHPINFO: "phpinfo",
  PRIVATE_IP_DISCLOSURE: "private-ip-disclosure",
  PRIVATE_KEY_DISCLOSURE: "private-key-disclosure",
  PROTOTYPE_POLLUTION: "prototype-pollution",
  BASIC_REFLECTED_XSS: "basic-reflected-xss",
  ROBOTS_TXT: "robots-txt",
  SECRET_DISCLOSURE: "secret-disclosure",
  SECURITY_HEADERS: "security-headers",
  SERVER_INFO_LEAK: "server-info-leak",
  SOURCE_CODE_DISCLOSURE: "source-code-disclosure",
  MYSQL_ERROR_BASED_SQLI: "mysql-error-based-sqli",
  MYSQL_TIME_BASED_SQLI: "mysql-time-based-sqli",
  SSRF_DETECTION: "ssrf-detection",
  SSTI: "ssti",
  SQL_STATEMENT_IN_PARAMS: "sql-statement-in-params",
  SSN_DISCLOSURE: "ssn-disclosure",
  SUBDOMAIN_TAKEOVER: "subdomain-takeover",
  SUSPECT_TRANSFORM: "suspect-transform",
  XXE_INJECTION: "xxe-injection",
} as const;

export const checks = [
  // ── Passive: Security Headers & Config ──
  antiClickjackingScan,
  securityHeadersScan,
  missingContentTypeScan,
  serverInfoLeakScan,
  cacheableAuthScan,

  // ── Passive: Cookie Security ──
  cookieHttpOnlyScan,
  cookieSecureScan,
  cookieSameSiteScan,

  // ── Passive: CORS ──
  corsMisconfigScan,

  // ── Passive: CSP ──
  cspAllowlistedScriptsScan,
  cspClickjackingScan,
  cspFormHijackingScan,
  cspMalformedSyntaxScan,
  cspNotEnforcedScan,
  cspUntrustedScriptScan,
  cspUntrustedStyleScan,

  // ── Passive: Information Disclosure ──
  applicationErrorsScan,
  debugErrorsScan,
  creditCardDisclosureScan,
  dbConnectionDisclosureScan,
  emailDisclosureScan,
  filePathDisclosureScan,
  forbiddenBypassScan,
  hashDisclosureScan,
  privateIpDisclosureScan,
  privateKeyDisclosureScan,
  secretDisclosureScan,
  sourceCodeDisclosureScan,
  ssnDisclosureScan,
  sqlStatementInParams,
  bigRedirectsScan,
  jsonHtmlResponseScan,
  jwtWeaknessScan,
  subdomainTakeoverScan,

  // ── Passive: XSS, CSRF, Mixed Content, SRI ──
  domXssSinksScan,
  csrfTokenMissingScan,
  missingSriScan,
  insecureFormActionScan,

  // ── Active: Injection ──
  basicReflectedXSSScan,
  mysqlErrorBased,
  mysqlTimeBased,
  nosqlInjectionScan,
  commandInjectionScan,
  crlfInjectionScan,
  sstiScan,
  pathTraversalScan,
  suspectTransformScan,
  prototypePollutionScan,
  httpParamPollutionScan,
  hostHeaderInjectionScan,
  logInjectionScan,
  xxeInjectionScan,
  ssrfDetectionScan,

  // ── Active: GraphQL ──
  graphqlIntrospectionScan,
  graphqlInjectionScan,

  // ── Active: CORS ──
  corsOriginReflectionScan,

  // ── Active: Config / Discovery ──
  exposedEnvScan,
  gitConfigScan,
  directoryListingScan,
  phpinfoScan,
  robotsTxtScan,
  openRedirectScan,
  insecureMethodsScan,
  backupFilesScan,
  openApiExposureScan,
] as const;
