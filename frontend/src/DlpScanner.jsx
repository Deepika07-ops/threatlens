import { useState } from "react";

const API = "http://127.0.0.1:8000";
const SAMPLE =
  "Customer card 4111 1111 1111 1111, email ravi@example.com, " +
  "config key AKIAIOSFODNN7EXAMPLE";

export default function DlpScanner() {
  const [text, setText] = useState(SAMPLE);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const scan = async () => {
    setBusy(true); setError(""); setResult(null);
    try {
      const r = await fetch(`${API}/dlp/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!r.ok) throw new Error(r.status + " " + (await r.text()));
      setResult(await r.json());
    } catch (e) {
      setError(String(e.message || e));
    } finally {
      setBusy(false);
    }
  };

  const findings = result
    ? Array.isArray(result) ? result
      : result.findings ?? result.matches ?? result.results ?? []
    : [];
  const kind = (f) => f.type ?? f.kind ?? f.label ?? f.pattern ?? "finding";
  const masked = (f) => f.masked ?? f.masked_value ?? f.value ?? "";

  return (
    <div style={{ color: "#cbd5e1" }}>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={5}
        style={{ width: "100%", boxSizing: "border-box", background: "#0b1220",
                 color: "#e2e8f0", border: "1px solid #1e293b", borderRadius: 10,
                 padding: 12, fontFamily: "Consolas, monospace", fontSize: 13 }}
      />
      <button onClick={scan} disabled={busy}
        style={{ marginTop: 10, background: "#10b981", color: "#04120d", border: "none",
                 borderRadius: 8, padding: "8px 18px", fontWeight: 700, cursor: "pointer" }}>
        {busy ? "Scanning..." : "Scan for sensitive data"}
      </button>

      {error && <p style={{ color: "#f43f5e" }}>Scan failed: {error}</p>}

      {result && (
        <div style={{ marginTop: 14 }}>
          <p style={{ color: findings.length ? "#f59e0b" : "#10b981", fontWeight: 600 }}>
            {findings.length
              ? `${findings.length} sensitive item(s) found`
              : "No sensitive data found"}
          </p>
          {findings.map((f, idx) => (
            <div key={idx} style={{ display: "flex", gap: 12, padding: "6px 0",
                                    borderTop: "1px solid #1e293b", fontSize: 13 }}>
              <span style={{ background: "#3b1d28", color: "#f43f5e", borderRadius: 6,
                             padding: "2px 8px", fontSize: 12, fontWeight: 700 }}>
                {String(kind(f)).toUpperCase()}
              </span>
              <code>{masked(f)}</code>
            </div>
          ))}
          <details style={{ marginTop: 10 }}>
            <summary style={{ cursor: "pointer", color: "#64748b" }}>Raw response</summary>
            <pre style={{ fontSize: 12, overflowX: "auto" }}>{JSON.stringify(result, null, 2)}</pre>
          </details>
        </div>
      )}
    </div>
  );
}
