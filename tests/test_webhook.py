import json

from src.processor import WebhookProcessor, compute_signature, verify_signature


def test_hmac_signature_verification():
    body = json.dumps({"event_id": "ev-1", "event_type": "doc_signed", "external_deal_id": "D-42"}).encode("utf-8")
    sig = compute_signature("top-secret", body)
    assert verify_signature("top-secret", body, f"sha256={sig}") is True
    assert verify_signature("top-secret", body, "sha256=deadbeef") is False


def test_webhook_processor_idempotency_and_stage_mapping():
    proc = WebhookProcessor()
    payload = {
        "event_id": "ev-100",
        "event_type": "doc_signed",
        "external_deal_id": "DEAL-500",
        "signer_name": "Marina Alves",
    }
    first = proc.handle_event(payload)
    assert first.status == "updated"
    assert first.new_stage == "CONTRACT_SIGNED"

    dup = proc.handle_event(payload)
    assert dup.status == "duplicate_ignored"
    assert len(proc.crm_updates) == 1
