import { useState } from "react";

const API = "http://127.0.0.1:8000";

export default function ReportsPanel() {
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState("");

  const download = async (path, filename, label) => {
    setBusy(label); setMsg("");
    try {
      const r = await fetch(`${API}${path}`);
      if (!r.ok) throw new Error(r.status + " " + (await r.text()));
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setMsg(`${filename} downloaded (${Math.round(blob.size / 1024)} KB)`);
    } catch (e) {
      setMsg("Failed: " + String(e.message || e));
    } finally {
      setBusy("");
    }
  };

  const card = {
    flex: 1, background: "#0b1220", border: "1px solid #1e293b",
    borderRadius: 12, padding: 16, color: "#cbd5e1",
  };
  const btn = (c) => ({
    marginTop: 10, background: c, color: "#04120d", border: "none",
    borderRadius: 8, padding: "8px 18px", fontWeight: 700, cursor: "pointer",
  });

  return (
    <div>
      <div style={{ display: "flex", gap: 16 }}>
        <div style={card}>
          <strong>Threat Intelligence Report</strong>
          <p style={{ fontSize: 13, color: "#64748b" }}>
            Executive summary, top 10 threats, analyst decisions and recommendations.
          </p>
          <button style={btn("#10b981")} disabled={!!busy}
            onClick={() => download("/report", "ThreatLens_Report.pdf", "pdf")}>
            {busy === "pdf" ? "Generating..." : "Generate PDF"}
          </button>
        </div>

        <div style={card}>
          <strong>STIX 2.1 Export</strong>
          <p style={{ fontSize: 13, color: "#64748b" }}>
            Approved indicators as a STIX bundle with a TLP:AMBER marking, ready to share.
          </p>
          <button style={btn("#a855f7")} disabled={!!busy}
            onClick={() => download("/export/stix", "threatlens_stix.json", "stix")}>
            {busy === "stix" ? "Exporting..." : "Export STIX"}
          </button>
        </div>
      </div>
      {msg && <p style={{ marginTop: 12, fontSize: 13, color: "#94a3b8" }}>{msg}</p>}
    </div>
  );
}
