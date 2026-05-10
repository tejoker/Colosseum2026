"use client";

import React, { useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

type DemoResult = Record<string, unknown> & {
  receipt_verification?: Record<string, unknown>;
};

const scenarioLabels: Record<string, string> = {
  valid_leash_passes: "Valid leash",
  missing_signature_fails: "Missing signature",
  bad_signature_fails: "Bad signature",
  tampered_amount_fails: "Tampered amount",
  wrong_merchant_fails: "Wrong merchant",
  nonce_replay_fails: "Nonce replay",
  ajwt_replay_fails: "A-JWT replay",
  revoked_agent_fails: "Revoked agent",
  out_of_ring_agent_fails: "Out of ring",
};

export default function LeashDemoPage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [error, setError] = useState("");

  const scenarios = useMemo(() => Object.keys(scenarioLabels), []);

  async function runDemo() {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const response = await fetch(`${API}/dev/leash/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setError(typeof data === "string" ? data : JSON.stringify(data));
      } else {
        setResult(data as DemoResult);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <main style={styles.wrap}>
      <section style={styles.header}>
        <div>
          <div style={styles.eyebrow}>Development</div>
          <h1 style={styles.title}>Cryptographic Action Leash</h1>
        </div>
        <button onClick={runDemo} disabled={loading} style={styles.button}>
          {loading ? "Running" : "Run"}
        </button>
      </section>

      {error && <div style={styles.error}>{error}</div>}

      <section style={styles.grid}>
        {scenarios.map((key) => {
          const value = result?.[key];
          const pass = value === true;
          return (
            <div key={key} style={{ ...styles.row, borderColor: pass ? "#16a34a" : "#334155" }}>
              <span style={styles.label}>{scenarioLabels[key]}</span>
              <span style={{ ...styles.badge, background: pass ? "#dcfce7" : "#fee2e2", color: pass ? "#166534" : "#991b1b" }}>
                {result ? (pass ? "pass" : "fail") : "idle"}
              </span>
            </div>
          );
        })}
      </section>

      {result?.receipt_verification && (
        <section style={styles.receipt}>
          <div style={styles.receiptTitle}>Receipt Verification</div>
          <pre style={styles.pre}>{JSON.stringify(result.receipt_verification, null, 2)}</pre>
        </section>
      )}
    </main>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrap: {
    minHeight: "100vh",
    background: "#f8fafc",
    color: "#0f172a",
    fontFamily: "system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
    padding: "32px",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 16,
    maxWidth: 980,
    margin: "0 auto 20px",
  },
  eyebrow: {
    fontSize: 12,
    fontWeight: 700,
    color: "#475569",
    textTransform: "uppercase",
  },
  title: {
    fontSize: 28,
    lineHeight: 1.2,
    margin: "4px 0 0",
  },
  button: {
    minWidth: 96,
    height: 40,
    border: "1px solid #0f172a",
    background: "#0f172a",
    color: "#fff",
    borderRadius: 6,
    fontWeight: 700,
    cursor: "pointer",
  },
  error: {
    maxWidth: 980,
    margin: "0 auto 20px",
    border: "1px solid #fecaca",
    background: "#fef2f2",
    color: "#991b1b",
    borderRadius: 6,
    padding: 12,
    fontFamily: "monospace",
    fontSize: 13,
  },
  grid: {
    maxWidth: 980,
    margin: "0 auto",
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
    gap: 10,
  },
  row: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: 12,
    background: "#fff",
    border: "1px solid #e2e8f0",
    borderRadius: 6,
    padding: "12px 14px",
  },
  label: {
    fontSize: 14,
    fontWeight: 650,
  },
  badge: {
    minWidth: 48,
    textAlign: "center",
    borderRadius: 999,
    padding: "3px 8px",
    fontSize: 12,
    fontWeight: 800,
    textTransform: "uppercase",
  },
  receipt: {
    maxWidth: 980,
    margin: "18px auto 0",
    background: "#fff",
    border: "1px solid #e2e8f0",
    borderRadius: 6,
    padding: 16,
  },
  receiptTitle: {
    fontSize: 14,
    fontWeight: 800,
    marginBottom: 10,
  },
  pre: {
    margin: 0,
    background: "#0f172a",
    color: "#e2e8f0",
    borderRadius: 6,
    padding: 12,
    overflowX: "auto",
    fontSize: 12,
  },
};
