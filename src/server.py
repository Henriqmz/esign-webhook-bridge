from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .processor import WebhookProcessor, compute_signature, verify_signature

STUDIO_HTML = """<!doctype html>
<html lang="pt-BR" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>eSign Webhook Bridge — HMAC-SHA256 &amp; Idempotency Console</title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet" />
  <style>
    :root, [data-theme="dark"] {
      --bg: #050a0f; --surface: #0b1219; --surface-2: #111b24; --surface-hover: #172430;
      --text: #f0f7fc; --muted: #9ab3c8; --accent: #d4f1ff; --accent-ink: #050a0f;
      --accent-soft: rgba(212, 241, 255, 0.11); --accent-border: rgba(212, 241, 255, 0.34);
      --border: rgba(212, 241, 255, 0.14);
      --ok-bg: rgba(52, 211, 153, 0.15); --ok-text: #6ee7b7;
      --warn-bg: rgba(251, 191, 36, 0.15); --warn-text: #fcd34d;
      --err-bg: rgba(248, 113, 113, 0.15); --err-text: #fca5a5;
    }
    [data-theme="light"] {
      --bg: #f0f7fc; --surface: #ffffff; --surface-2: #e3eef6; --surface-hover: #d5e5f1;
      --text: #050a0f; --muted: #395064; --accent: #050a0f; --accent-ink: #f0f7fc;
      --accent-soft: rgba(5, 10, 15, 0.08); --accent-border: rgba(5, 10, 15, 0.3);
      --border: rgba(5, 10, 15, 0.14);
      --ok-bg: #ecfdf5; --ok-text: #047857;
      --warn-bg: #fffbeb; --warn-text: #b45309;
      --err-bg: #fef2f2; --err-text: #b91c1c;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "Plus Jakarta Sans", system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
    .shell-header {
      padding: 18px max(24px, calc((100% - 1180px) / 2)); border-bottom: 1px solid var(--border);
      background: var(--surface); display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 1rem;
    }
    .brand { display: flex; align-items: center; gap: 0.85rem; }
    .logo { width: 38px; height: 38px; border-radius: 10px; background: var(--accent); color: var(--accent-ink); display: grid; place-items: center; font-weight: 900; font-size: 0.84rem; }
    .brand-title { font-weight: 800; font-size: 1.08rem; }
    .brand-sub { font-size: 0.78rem; color: var(--muted); }
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 0.4rem;
      padding: 0.54rem 0.96rem; border-radius: 9px; border: 1px solid var(--border);
      background: var(--surface-2); color: var(--text); font: inherit; font-size: 0.82rem; font-weight: 700; cursor: pointer;
    }
    .btn:hover { background: var(--surface-hover); border-color: var(--accent-border); }
    .btn-primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
    .shell-body { width: min(1180px, calc(100% - 48px)); margin: 0 auto; padding: 26px 0 44px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 0.9rem; margin-bottom: 22px; }
    .kpi { background: var(--surface-2); border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 12px; padding: 0.95rem 1.1rem; }
    .kpi-label { font-size: 0.72rem; color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; }
    .kpi-val { font-size: 1.65rem; font-weight: 800; color: var(--accent); margin-top: 0.2rem; }
    .grid { display: grid; grid-template-columns: 0.95fr 1.25fr; gap: 20px; align-items: start; }
    .card { background: var(--surface-2); border: 1px solid var(--border); border-radius: 14px; padding: 1.25rem; }
    .card h2 { margin: 0 0 0.35rem; font-size: 1.04rem; }
    .sub { margin: 0 0 1rem; font-size: 0.82rem; color: var(--muted); }
    .input, select { width: 100%; padding: 0.58rem 0.8rem; border-radius: 9px; border: 1px solid var(--border); background: var(--bg); color: var(--text); font: inherit; font-size: 0.85rem; margin-bottom: 0.75rem; }
    label { display: block; font-size: 0.78rem; font-weight: 600; color: var(--muted); margin-bottom: 0.25rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
    th, td { text-align: left; padding: 0.72rem 0.55rem; border-bottom: 1px solid var(--border); }
    th { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
    .mono { font-family: "JetBrains Mono", monospace; font-size: 0.75rem; color: var(--muted); }
    .badge { display: inline-block; font-family: "JetBrains Mono", monospace; font-size: 0.69rem; font-weight: 700; padding: 0.2rem 0.55rem; border-radius: 999px; }
    .b-ok { background: var(--ok-bg); color: var(--ok-text); }
    .b-warn { background: var(--warn-bg); color: var(--warn-text); }
    .b-err { background: var(--err-bg); color: var(--err-text); }
    @media (max-width: 920px) { .kpi-grid { grid-template-columns: repeat(2, 1fr); } .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <header class="shell-header">
    <div class="brand">
      <span class="logo">HMAC</span>
      <div>
        <div class="brand-title">eSign Webhook-to-CRM Bridge</div>
        <div class="brand-sub">Validação Criptográfica HMAC-SHA256 (Constant-Time) · Idempotência por Evento</div>
      </div>
    </div>
    <button id="themeToggle" type="button" class="btn" style="border-radius:999px">
      <span id="themeIcon">☀</span> <span id="themeLabel">Modo Claro</span>
    </button>
  </header>

  <main class="shell-body">
    <section class="kpi-grid">
      <div class="kpi"><div class="kpi-label">Negócios Atualizados</div><div class="kpi-val" id="kUpdated">--</div></div>
      <div class="kpi"><div class="kpi-label">Duplicatas Ignoradas</div><div class="kpi-val" id="kDup">--</div></div>
      <div class="kpi"><div class="kpi-label">Ataques/HMAC Inválidos</div><div class="kpi-val" id="kSpoof">--</div></div>
      <div class="kpi"><div class="kpi-label">Eventos Auditados</div><div class="kpi-val" id="kTotal">--</div></div>
    </section>

    <div class="grid">
      <section class="card">
        <h2>Disparador de Webhooks (Teste Criptográfico)</h2>
        <p class="sub">Dispare chamadas reais para <code>POST /webhooks/esign</code> testando assinatura válida, spoofing (401) ou reentrega duplicada.</p>
        <label>Event ID</label>
        <input id="fEventId" class="input" value="evt-2026-904" />
        <label>Tipo do Evento</label>
        <select id="fType">
          <option value="doc_signed">doc_signed → CONTRACT_SIGNED</option>
          <option value="doc_refused">doc_refused → CONTRACT_REFUSED</option>
          <option value="doc_expired">doc_expired → FOLLOWUP_EXPIRED</option>
        </select>
        <label>ID do Negócio no CRM</label>
        <input id="fDeal" class="input" value="DEAL-8840" />
        <label>Signatário</label>
        <input id="fSigner" class="input" value="Marina Alves (Acme Cloud)" />
        <div style="display:grid;gap:0.5rem;margin-top:0.35rem">
          <button type="button" class="btn btn-primary" onclick="sendSim('valid')">✓ Enviar com HMAC-SHA256 Válido</button>
          <button type="button" class="btn" onclick="sendSim('tampered')">✕ Testar Assinatura Inválida (Spoofing 401)</button>
          <button type="button" class="btn" onclick="sendSim('replay')">↻ Reenviar Mesmo Event ID (Idempotência)</button>
        </div>
      </section>

      <section class="card">
        <h2>Trilha de Auditoria HTTP &amp; CRM</h2>
        <p class="sub">Histórico em tempo real de verificações <code>hmac.compare_digest</code> e transições de etapa no funil.</p>
        <div style="overflow-x:auto">
          <table>
            <thead><tr><th>Horário / Event ID</th><th>HTTP / Verificação</th><th>Negócio CRM</th><th>Nova Etapa</th></tr></thead>
            <tbody id="auditBody"></tbody>
          </table>
        </div>
      </section>
    </div>
  </main>

  <script>
    const root = document.documentElement;
    function applyTheme(t) {
      root.setAttribute("data-theme", t);
      localStorage.setItem("hmac-theme", t);
      document.getElementById("themeIcon").textContent = t === "light" ? "☾" : "☀";
      document.getElementById("themeLabel").textContent = t === "light" ? "Modo Escuro" : "Modo Claro";
    }
    applyTheme(localStorage.getItem("hmac-theme") || "dark");
    document.getElementById("themeToggle").addEventListener("click", () => {
      applyTheme(root.getAttribute("data-theme") === "dark" ? "light" : "dark");
    });

    async function loadState() {
      const s = await (await fetch("/api/state")).json();
      document.getElementById("kUpdated").textContent = s.counts.updated;
      document.getElementById("kDup").textContent = s.counts.duplicate;
      document.getElementById("kSpoof").textContent = s.counts.rejected;
      document.getElementById("kTotal").textContent = s.logs.length;

      const tbody = document.getElementById("auditBody");
      tbody.innerHTML = "";
      s.logs.forEach(item => {
        const cls = item.http === 200 ? (item.result === "updated" ? "b-ok" : "b-warn") : "b-err";
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${item.event_id}</strong><br/><span class="mono">${item.ts}</span></td>
          <td><span class="badge ${cls}">HTTP ${item.http} · ${item.result}</span><br/><span class="mono">${item.sig_preview}</span></td>
          <td class="mono">${item.deal_id}</td>
          <td><strong>${item.stage || "—"}</strong></td>
        `;
        tbody.appendChild(tr);
      });
    }

    window.sendSim = async (mode) => {
      if (mode === "valid") {
        document.getElementById("fEventId").value = `evt-2026-${Math.floor(100 + Math.random() * 899)}`;
      }
      const body = {
        mode,
        event_id: document.getElementById("fEventId").value,
        event_type: document.getElementById("fType").value,
        external_deal_id: document.getElementById("fDeal").value,
        signer_name: document.getElementById("fSigner").value,
      };
      await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      loadState();
    };

    loadState();
  </script>
</body>
</html>
"""


def make_handler(secret: str, processor: WebhookProcessor, audit_logs: list[dict[str, Any]] | None = None):
    logs = audit_logs if audit_logs is not None else []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            pass

        def _respond(self, code: int, body: dict) -> None:
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path == "/api/state":
                counts = {
                    "updated": sum(1 for x in logs if x["result"] == "updated"),
                    "duplicate": sum(1 for x in logs if x["result"] == "duplicate_ignored"),
                    "rejected": sum(1 for x in logs if x["http"] == 401),
                }
                self._respond(200, {"counts": counts, "logs": list(reversed(logs[-20:]))})
                return
            html_bytes = STUDIO_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)

        def do_POST(self) -> None:
            if self.path == "/api/simulate":
                length = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(length).decode("utf-8"))
                mode = req.pop("mode", "valid")
                raw_payload = json.dumps(req, ensure_ascii=False).encode("utf-8")
                sig = (
                    "sha256=0000deadbeef0000invalid"
                    if mode == "tampered"
                    else f"sha256={compute_signature(secret, raw_payload)}"
                )
                now_str = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                if not verify_signature(secret, raw_payload, sig):
                    logs.append(
                        {
                            "ts": now_str,
                            "event_id": req.get("event_id", "-"),
                            "deal_id": req.get("external_deal_id", "-"),
                            "http": 401,
                            "result": "invalid_signature",
                            "stage": "",
                            "sig_preview": sig[:24] + "...",
                        }
                    )
                    self._respond(200, {"simulated": "rejected"})
                    return
                outcome = processor.handle_event(req)
                logs.append(
                    {
                        "ts": now_str,
                        "event_id": req.get("event_id", "-"),
                        "deal_id": outcome.deal_id or "-",
                        "http": 200,
                        "result": outcome.status,
                        "stage": outcome.new_stage or "",
                        "sig_preview": sig[:24] + "...",
                    }
                )
                self._respond(200, {"simulated": outcome.status})
                return

            if self.path != "/webhooks/esign":
                self._respond(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            sig = self.headers.get("X-Webhook-Signature", "")
            now_str = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            if not verify_signature(secret, raw_body, sig):
                logs.append(
                    {
                        "ts": now_str,
                        "event_id": "external",
                        "deal_id": "-",
                        "http": 401,
                        "result": "invalid_signature",
                        "stage": "",
                        "sig_preview": (sig or "none")[:24],
                    }
                )
                self._respond(401, {"error": "invalid_signature"})
                return
            try:
                payload = json.loads(raw_body.decode("utf-8"))
                outcome = processor.handle_event(payload)
            except (json.JSONDecodeError, ValueError) as exc:
                self._respond(400, {"error": str(exc)})
                return
            logs.append(
                {
                    "ts": now_str,
                    "event_id": str(payload.get("event_id", "")),
                    "deal_id": outcome.deal_id or "-",
                    "http": 200,
                    "result": outcome.status,
                    "stage": outcome.new_stage or "",
                    "sig_preview": sig[:24] + "...",
                }
            )
            self._respond(
                200,
                {"status": outcome.status, "deal_id": outcome.deal_id, "new_stage": outcome.new_stage},
            )

    return Handler


def seed_demo_events(secret: str, processor: WebhookProcessor, logs: list[dict[str, Any]]) -> None:
    samples = [
        ({"event_id": "evt-2026-101", "event_type": "doc_signed", "external_deal_id": "DEAL-5012", "signer_name": "Marina Alves"}, True),
        ({"event_id": "evt-2026-101", "event_type": "doc_signed", "external_deal_id": "DEAL-5012", "signer_name": "Marina Alves"}, True),
        ({"event_id": "evt-spoof-99", "event_type": "doc_signed", "external_deal_id": "DEAL-9999", "signer_name": "Attacker"}, False),
        ({"event_id": "evt-2026-102", "event_type": "doc_refused", "external_deal_id": "DEAL-5048", "signer_name": "Carlos Mendes"}, True),
    ]
    for p, valid in samples:
        raw = json.dumps(p).encode("utf-8")
        sig = f"sha256={compute_signature(secret, raw)}" if valid else "sha256=bad000signature"
        if not valid:
            logs.append({"ts": "14:20:11 UTC", "event_id": p["event_id"], "deal_id": p["external_deal_id"], "http": 401, "result": "invalid_signature", "stage": "", "sig_preview": sig[:24]})
        else:
            out = processor.handle_event(p)
            logs.append({"ts": "14:22:05 UTC", "event_id": p["event_id"], "deal_id": out.deal_id, "http": 200, "result": out.status, "stage": out.new_stage or "", "sig_preview": sig[:24] + "..."})


def main() -> None:
    parser = argparse.ArgumentParser(description="eSign Webhook-to-CRM Bridge")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8095")))
    args = parser.parse_args()

    host = os.getenv("HOST", "127.0.0.1")
    secret = os.getenv("WEBHOOK_SECRET", "demo-secret")
    proc = WebhookProcessor()
    logs: list[dict[str, Any]] = []
    seed_demo_events(secret, proc, logs)
    server = HTTPServer((host, args.port), make_handler(secret, proc, logs))
    print(f"eSign Webhook Bridge Studio em http://{host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
