export function isTextualContentType(headers: any): boolean {
  try {
    const vals = headers?.getHeader?.("Content-Type") ?? [];
    const arr = Array.isArray(vals) ? vals : [vals];
    const ct = arr.map((x: any) => String(x || "").toLowerCase()).join(", ");
    return /(text\/|json|xml|javascript|x-www-form-urlencoded)/i.test(ct);
  } catch {
    return false;
  }
}

const EMAIL_RE = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24})(?![A-Za-z0-9._%+-])/g;

const BORING_LOCAL_PARTS = new Set([
  "noreply","no-reply","donotreply","do-not-reply","support","info","help",
  "service","orders","customerservice","admin","webmaster","example","root"
]);

export function extractLikelyEmails(text: string): string[] {
  const hits = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = EMAIL_RE.exec(text)) !== null) {
    const local = (m[1] ?? "").toLowerCase();
    const domain = (m[2] ?? "").toLowerCase();

    // filters
    if (!local || !domain) continue;
    if (BORING_LOCAL_PARTS.has(local)) continue;
    if (/^example\.com$/.test(domain)) continue;
    if (/localhost|\.local$|\.invalid$/.test(domain)) continue;
    if (/^[0-9._-]+$/.test(local)) continue; // purely numeric-ish
    if (/^.*@.*\(at\).*$/.test(m[0])) continue;

    hits.add(`${local}@${domain}`);
  }
  return Array.from(hits);
}
