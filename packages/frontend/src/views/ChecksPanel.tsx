import React, { useEffect, useState, useCallback } from "react";

type Meta = {
  id: string;
  name: string;
  description?: string;
  tags?: string[];
  severities?: string[];
  type?: string;
};

async function fetchWithTimeout(input: RequestInfo, init: RequestInit & { timeout?: number } = {}) {
  const { timeout = 8000, ...rest } = init;
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(input, { ...rest, signal: ctrl.signal });
    return res;
  } finally {
    clearTimeout(id);
  }
}

export default function ChecksPanel() {
  const [state, setState] = useState<{loading: boolean; err?: string; data: Meta[]}>({ loading: true, data: [] });

  const load = useCallback(async () => {
    try {
      setState({ loading: true, data: [] });
      const health = await fetchWithTimeout("/__scanner/health", { timeout: 4000 });
      if (!health.ok) throw new Error(`health ${health.status}`);
      const r = await fetchWithTimeout("/__scanner/checks", { timeout: 8000 });
      if (!r.ok) throw new Error(`checks ${r.status}`);
      const json = await r.json();
      setState({ loading: false, data: Array.isArray(json) ? json : [] });
    } catch (e:any) {
      setState({ loading: false, err: e?.message || "Failed to load checks", data: [] });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (state.loading) return <div style={{padding: 16}}>Loading…</div>;
  if (state.err) return (
    <div style={{padding:16}}>
      <div style={{color:"#e66", marginBottom:8}}>Couldn’t load checks: {state.err}</div>
      <button onClick={load}>Retry</button>
    </div>
  );

  if (!state.data.length) return <div style={{padding:16}}>No checks found.</div>;

  return (
    <div style={{padding:16, display:"grid", gap:12}}>
      {state.data.map(m => (
        <div key={m.id} style={{border:"1px solid #333", borderRadius:8, padding:12}}>
          <div style={{fontWeight:600}}>{m.name}</div>
          {m.description && <div style={{opacity:.8, marginTop:4}}>{m.description}</div>}
          <div style={{marginTop:6, fontSize:12, opacity:.8}}>
            <b>Type:</b> {m.type || "passive"} &nbsp; • &nbsp;
            <b>Severities:</b> {(m.severities||[]).join(", ") || "—"} &nbsp; • &nbsp;
            <b>Tags:</b> {(m.tags||[]).join(", ") || "—"}
          </div>
        </div>
      ))}
    </div>
  );
}
