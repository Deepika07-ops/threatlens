import { useEffect, useState } from "react";

const API = "http://127.0.0.1:8000";
const sevColor = { High: "#f43f5e", Medium: "#f59e0b", Low: "#10b981" };
const statusColor = {
  Pending: "#f59e0b", Approved: "#10b981",
  Rejected: "#f43f5e", Escalated: "#a855f7",
};
const btn = (c) => ({
  background: "transparent", color: c, border: `1px solid ${c}`,
  borderRadius: 8, padding: "6px 12px", cursor: "pointer", marginRight: 8,
});

export default function ThreatTable({ onChanged }) {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);

  const load = async () => {
    const r = await fetch(`${API}/indicators`);
    const d = await r.json();
    const list = Array.isArray(d) ? d : d.items ?? d.indicators ?? [];
    setRows(list);
    setSelected((s) => (s ? list.find((x) => x.id === s.id) ?? null : null));
  };
  useEffect(() => {
    load();
    const h = () => load();
    window.addEventListener("threatlens:changed", h);
    return () => window.removeEventListener("threatlens:changed", h);
  }, []);

  const review = async (id, status) => {
    const r = await fetch(`${API}/indicators/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, note: `Marked ${status} from dashboard` }),
    });
    if (!r.ok) { alert("Update failed: " + r.status + " " + (await r.text())); return; }
    await load();
    onChanged?.();
  };

  const th = { padding: "8px 10px", fontSize: 12, color: "#64748b", textAlign: "left" };
  const td = { padding: "8px 10px", fontSize: 13 };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
      <div style={{ maxHeight: 420, overflowY: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", color: "#cbd5e1" }}>
          <thead>
            <tr><th style={th}>TYPE</th><th style={th}>INDICATOR</th><th style={th}>SCORE</th><th style={th}>SEVERITY</th><th style={th}>STATUS</th></tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.id} onClick={() => setSelected(i)}
                  style={{ cursor: "pointer", borderTop: "1px solid #1e293b",
                           background: selected?.id === i.id ? "#0f1b2d" : "transparent" }}>
                <td style={td}>{i.type}</td>
                <td style={td}>{i.value}</td>
                <td style={td}>{i.score}</td>
                <td style={{ ...td, color: sevColor[i.severity], fontWeight: 600 }}>{i.severity}</td>
                <td style={{ ...td, color: statusColor[i.status] }}>{i.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <aside style={{ background: "#0b1220", padding: 16, borderRadius: 12, color: "#cbd5e1" }}>
        {!selected ? <p>Click an indicator to see why it got its score.</p> : (
          <>
            <h3 style={{ marginTop: 0 }}>Why this score?</h3>
            <p style={{ wordBreak: "break-all", fontSize: 13 }}>{selected.value}</p>
            <p style={{ fontSize: 12, color: "#64748b" }}>
              {selected.source} · {selected.malware_family} · first seen {selected.first_seen}
            </p>
            {(selected.breakdown ?? []).map((b) => (
              <div key={b.factor} style={{ display: "flex", justifyContent: "space-between", fontSize: 13, padding: "3px 0" }}>
                <span>{b.factor.replaceAll("_", " ")} <span style={{ color: "#64748b" }}>({b.value} × {b.weight})</span></span>
                <strong>+{Number(b.points).toFixed(1)}</strong>
              </div>
            ))}
            <p style={{ borderTop: "1px solid #1e293b", paddingTop: 8 }}>
              <strong>Total: {selected.score}</strong>
            </p>
            <p>{(selected.tags ?? []).map((t) => (
              <span key={t} style={{ background: "#1e293b", borderRadius: 6, padding: "2px 8px", marginRight: 6, fontSize: 12 }}>
                {t.toUpperCase()}
              </span>
            ))}</p>
            <button style={btn("#10b981")} onClick={() => review(selected.id, "Approved")}>Approve</button>
            <button style={btn("#f43f5e")} onClick={() => review(selected.id, "Rejected")}>Reject</button>
            <button style={btn("#a855f7")} onClick={() => review(selected.id, "Escalated")}>Escalate</button>
          </>
        )}
      </aside>
    </div>
  );
}

