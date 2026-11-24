from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

from .processor import WebhookProcessor, verify_signature


def make_handler(secret: str, processor: WebhookProcessor):
    class Handler(BaseHTTPRequestHandler):
        def _respond(self, code: int, body: dict) -> None:
            raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:
            if self.path != "/webhooks/esign":
                self._respond(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            sig = self.headers.get("X-Webhook-Signature", "")
            if not verify_signature(secret, raw_body, sig):
                self._respond(401, {"error": "invalid_signature"})
                return
            try:
                payload = json.loads(raw_body.decode("utf-8"))
                outcome = processor.handle_event(payload)
            except (json.JSONDecodeError, ValueError) as exc:
                self._respond(400, {"error": str(exc)})
                return
            self._respond(
                200,
                {"status": outcome.status, "deal_id": outcome.deal_id, "new_stage": outcome.new_stage},
            )

    return Handler


def main() -> None:
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8095"))
    secret = os.getenv("WEBHOOK_SECRET", "demo-secret")
    server = HTTPServer((host, port), make_handler(secret, WebhookProcessor()))
    print(f"eSign Webhook Bridge ouvindo em http://{host}:{port}/webhooks/esign")
    server.serve_forever()


if __name__ == "__main__":
    main()
