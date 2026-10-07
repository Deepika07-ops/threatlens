import { useState } from "react";

const API = "http://127.0.0.1:8000";

export default function DataCollection({ onChanged }) {
  const [file, setFile] = useState(null);
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  const call = async (path, body) => {
    const r = await fetch(`${API}${path}`, { method: "POST", body });
    if (!r.ok) throw new Error(r.status + " " + (await r.text()));
    return r.json();
  };

  const run = async (fn) => {
    setBusy(true); setMsg("");
    try {
      setMsg(await fn());
      onChanged?.(); window.dispatchEvent(new Event("threatlens:changed"));
    } catch (e) {
      setMsg("Failed: " + String(e.message || e));
    } finally {
      setBusy(false);
    }
  };

  const upload = () =>
    run(async () => {
      const fd = new FormData();
      fd.append("file", file);
      const ing = await call("/ingest", fd);
      await call("/score");
      return "Ingested and scored. " + JSON.stringify(ing);
    });

  const sample = () =>
    run(async () => {
      const ing = await call("/ingest/sample");
      await call("/score");
      return "Sample feed ingested and scored. " + JSON.stringify(ing);
    });

  const btn = (c) => ({
    background: c, color: "#04120d", border: "none", borderRadius: 8,
    padding: "8px 18px", fontWeight: 700, cursor: "pointer", marginRight: 10,
  });

  return (
    <div style={{ color: "#cbd5e1" }}>
      <p style={{ fontSize: 13, color: "#64748b", marginTop: 0 }}>
        Upload a CSV threat feed (type, value, source, first_seen, count, malware_family).
        Duplicates are merged and every indicator is scored automatically.
      </p>
      <input type="file" accept=".csv"
        onChange={(e) => setFile(e.target.files[0] ?? null)} />
      <div style={{ marginTop: 12 }}>
        <button style={btn("#10b981")} disabled={!file || busy} onClick={upload}>
          {busy ? "Working..." : "Upload and score"}
        </button>
        <button style={btn("#38bdf8")} disabled={busy} onClick={sample}>
          Load sample feed
        </button>
      </div>
      {msg && <p style={{ marginTop: 12, fontSize: 13, color: "#94a3b8", wordBreak: "break-all" }}>{msg}</p>}
    </div>
  );
}

