export function isLikelyCloudflareChallenge(response: any): boolean {
  const status = response?.getStatus?.() ?? 0;
  const server = (getHeader(response, "server") || "").toLowerCase();
  const cfMitigated = (getHeader(response, "cf-mitigated") || "").toLowerCase().includes("challenge");
  const setCookie = (getHeader(response, "set-cookie") || "").toLowerCase();
  const contentType = getHeader(response, "content-type") || "";

  const htmlish = /text\/html|application\/xhtml\+xml/i.test(contentType);
  const body = htmlish ? (response?.getBody?.()?.toText?.() ?? "") : "";

  const looksChallenge =
    /Just a moment\.\.\./i.test(body) ||
    /__cf_chl_|\/cdn-cgi\/challenge-platform\//i.test(body);

  return (
    server.includes("cloudflare") &&
    (status >= 400 || cfMitigated || setCookie.includes("__cf_bm") || looksChallenge)
  );
}

export function getHeader(resp: any, name: string): string | undefined {
  try {
    const v = resp?.getHeader?.(name);
    if (!v) return undefined;
    return Array.isArray(v) ? v[0] : v;
  } catch {
    return undefined;
  }
}
