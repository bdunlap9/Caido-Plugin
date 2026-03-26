import * as Checks from "./checks";

function serializeCheckMeta(ch: any) {
  try {
    const meta = ch?.metadata ?? {};
    return {
      id: String(meta.id || ""),
      name: String(meta.name || ""),
      description: String(meta.description || ""),
      tags: Array.isArray(meta.tags) ? meta.tags : [],
      severities: Array.isArray(meta.severities) ? meta.severities : [],
      type: meta.type || "passive",
      aggressivity: meta.aggressivity || { minRequests: 0, maxRequests: 0 },
    };
  } catch {
    return null;
  }
}

export function listChecksSafe() {
  try {
    const all = Object.values(Checks).filter(Boolean);
    const metas = all.map(serializeCheckMeta).filter(Boolean);
    return metas;
  } catch {
    return [];
  }
}
