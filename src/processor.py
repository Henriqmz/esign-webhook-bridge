from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

EVENT_STAGE_MAP = {
    "doc_signed": "CONTRACT_SIGNED",
    "doc_refused": "CONTRACT_REFUSED",
    "doc_expired": "FOLLOWUP_EXPIRED",
}


def compute_signature(secret: str, raw_body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, raw_body: bytes, received_sig: str) -> bool:
    expected = compute_signature(secret, raw_body)
    cleaned = (received_sig or "").strip().removeprefix("sha256=")
    return hmac.compare_digest(expected, cleaned)


@dataclass
class WebhookOutcome:
    status: str
    deal_id: str | None = None
    new_stage: str | None = None


class WebhookProcessor:
    """Processes verified eSign events idempotently and updates CRM deal stages."""

    def __init__(self) -> None:
        self.processed_events: set[str] = set()
        self.crm_updates: list[dict[str, Any]] = []

    def handle_event(self, payload: dict[str, Any]) -> WebhookOutcome:
        event_id = str(payload.get("event_id", "")).strip()
        event_type = str(payload.get("event_type", "")).strip().lower()
        deal_id = str(payload.get("external_deal_id", "")).strip()

        if not event_id or not deal_id:
            raise ValueError("Payload inválido: 'event_id' e 'external_deal_id' são obrigatórios.")
        if event_id in self.processed_events:
            return WebhookOutcome(status="duplicate_ignored", deal_id=deal_id)

        target_stage = EVENT_STAGE_MAP.get(event_type)
        if not target_stage:
            return WebhookOutcome(status="event_ignored", deal_id=deal_id)

        self.processed_events.add(event_id)
        self.crm_updates.append(
            {
                "event_id": event_id,
                "deal_id": deal_id,
                "stage": target_stage,
                "signer": payload.get("signer_name", ""),
            }
        )
        return WebhookOutcome(status="updated", deal_id=deal_id, new_stage=target_stage)
