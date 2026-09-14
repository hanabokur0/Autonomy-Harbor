from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from .models import ActionReceipt, ActionRequest, CapabilityRegistry, GateDecision

RECEIPT_VERSION = "0.1"


def _canonical_json(data: Mapping[str, Any]) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def create_receipt(
    *,
    request: ActionRequest,
    decision: GateDecision,
    registry: CapabilityRegistry,
    outcome: str,
    result: Mapping[str, Any],
    previous_receipt_hash: str | None = None,
    created_at: str | None = None,
) -> ActionReceipt:
    created_at = created_at or datetime.now(timezone.utc).isoformat()
    body = {
        "receipt_version": RECEIPT_VERSION,
        "request_id": request.request_id,
        "capability": request.capability,
        "action": request.action,
        "resource": request.resource,
        "gate": decision.verdict,
        "gate_reason": decision.reason,
        "matched_grant_ids": list(decision.matched_grant_ids),
        "outcome": outcome,
        "result": dict(result),
        "registry_id": registry.registry_id,
        "registry_version": registry.version,
        "created_at": created_at,
        "previous_receipt_hash": previous_receipt_hash,
    }
    receipt_hash = hashlib.sha256(_canonical_json(body)).hexdigest()
    body["matched_grant_ids"] = tuple(body["matched_grant_ids"])
    return ActionReceipt(
        **body,
        receipt_hash=receipt_hash,
    )
