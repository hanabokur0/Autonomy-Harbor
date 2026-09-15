from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

from .appliance import (
    ActionRequest,
    ExecutionPermitLedger,
    UnixJsonClient,
    action_request_dict,
    action_request_from_dict,
    final_receipt_from_appliance,
    gate_decision_dict,
    gate_decision_from_dict,
    issue_execution_permit,
    load_signer,
    registry_from_dict,
    serve_unix_json,
    sign_execution_result,
    trust_store_from_list,
    verify_and_consume_execution_permit,
)
from .adapters import build_adapter_registry
from .gate import CapabilityGate
from .models import GateDecision
from .receipt import create_receipt
from .review_broker import request_digest
from .verifiable import (
    SignedEnvelope,
    SignedReviewAuthorizer,
    ReplayLedger,
    issue_signed_review_lease,
)


def load_profile(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _service(profile: Mapping[str, Any], role: str) -> dict[str, Any]:
    services = profile.get("services", {})
    if role not in services:
        raise KeyError(f"service_role_not_configured:{role}")
    return dict(services[role])


def _load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def planner_handler(_: Mapping[str, Any]):
    def handle(message: dict[str, Any]) -> dict[str, Any]:
        if message.get("op") == "health":
            return {"role": "planner", "status": "ok", "private_key_loaded": False}
        if message.get("op") != "propose":
            raise ValueError("planner_op_not_supported")
        intent = dict(message.get("intent", {}))
        request = ActionRequest(
            request_id=str(intent["request_id"]),
            capability=str(intent["capability"]),
            action=str(intent["action"]),
            resource=str(intent["resource"]),
            payload=dict(intent.get("payload", {})),
            actor=str(intent.get("actor", "planner-agent")),
        )
        return {"role": "planner", "request": action_request_dict(request)}
    return handle


def review_signer_handler(profile: Mapping[str, Any], config: Mapping[str, Any]):
    signer = load_signer(config["private_key"], subject=str(config["subject"]))

    def handle(message: dict[str, Any]) -> dict[str, Any]:
        if message.get("op") == "health":
            return {"role": "review_signer", "status": "ok", "key_id": signer.key_id}
        if message.get("op") != "approve_review":
            raise ValueError("review_signer_op_not_supported")
        approval = dict(message.get("approval", {}))
        if approval.get("approved") is not True or not str(approval.get("approved_by", "")).strip():
            raise PermissionError("explicit_human_approval_required")
        request = action_request_from_dict(message["request"])
        base = gate_decision_from_dict(message["base_decision"])
        envelope = issue_signed_review_lease(
            request=request,
            base_decision=base,
            signer=signer,
            ttl_seconds=int(message.get("ttl_seconds", 300)),
            lease_id=message.get("lease_id"),
            now=datetime.now(timezone.utc),
        )
        return {"role": "review_signer", "signed_review_lease": envelope.as_dict()}
    return handle


def gate_handler(profile: Mapping[str, Any], config: Mapping[str, Any]):
    registry = registry_from_dict(_load_json(config["registry"]))
    trust = trust_store_from_list(_load_json(config["trust_store"]))
    signer = load_signer(config["private_key"], subject=str(config["subject"]))
    review_ledger = ReplayLedger(config["review_replay_db"])
    authorizer = SignedReviewAuthorizer(trust_store=trust, replay_ledger=review_ledger)
    gate = CapabilityGate()

    def handle(message: dict[str, Any]) -> dict[str, Any]:
        if message.get("op") == "health":
            return {
                "role": "gate", "status": "ok", "key_id": signer.key_id,
                "registry_id": registry.registry_id, "registry_version": registry.version,
            }
        if message.get("op") != "authorize":
            raise ValueError("gate_op_not_supported")
        request = action_request_from_dict(message["request"])
        base = gate.evaluate(request, registry)
        decision = base
        signed_lease_raw = message.get("signed_review_lease")
        if base.verdict == "REVIEW" and signed_lease_raw is not None:
            authorization = authorizer.redeem(
                envelope=SignedEnvelope.from_dict(signed_lease_raw),
                request=request,
                base_decision=base,
                now=datetime.now(timezone.utc),
            )
            if authorization.authorized:
                decision = GateDecision(
                    verdict="ALLOW",
                    reason="signed_human_review_lease_redeemed",
                    matched_grant_ids=(*base.matched_grant_ids, f"signed-review-lease:{authorization.lease_id}"),
                )
            else:
                decision = GateDecision(
                    verdict="REVIEW",
                    reason=f"signed_review_lease_rejected:{authorization.reason}",
                    matched_grant_ids=base.matched_grant_ids,
                )
        response: dict[str, Any] = {
            "role": "gate",
            "base_decision": gate_decision_dict(base),
            "decision": gate_decision_dict(decision),
        }
        if decision.verdict == "ALLOW":
            permit = issue_execution_permit(
                request=request,
                decision=decision,
                registry=registry,
                signer=signer,
                ttl_seconds=int(config.get("permit_ttl_seconds", 30)),
                now=datetime.now(timezone.utc),
            )
            response["execution_permit"] = permit.as_dict()
        return response
    return handle


def executor_handler(profile: Mapping[str, Any], config: Mapping[str, Any]):
    trust = trust_store_from_list(_load_json(config["trust_store"]))
    signer = load_signer(config["private_key"], subject=str(config["subject"]))
    ledger = ExecutionPermitLedger(config["permit_replay_db"])
    executor = build_adapter_registry(sandbox_root=Path(config["sandbox_root"]), config=config)

    def handle(message: dict[str, Any]) -> dict[str, Any]:
        if message.get("op") == "health":
            return {"role": "executor", "status": "ok", "key_id": signer.key_id, "adapters": executor.manifest()}
        if message.get("op") != "execute":
            raise ValueError("executor_op_not_supported")
        if "execution_permit" not in message:
            raise PermissionError("signed_execution_permit_required")
        request = action_request_from_dict(message["request"])
        permit = SignedEnvelope.from_dict(message["execution_permit"])
        authorization = verify_and_consume_execution_permit(
            envelope=permit,
            request=request,
            trust_store=trust,
            ledger=ledger,
            now=datetime.now(timezone.utc),
        )
        if not authorization.authorized:
            return {"role": "executor", "executed": False, "reason": authorization.reason}
        try:
            dispatch = executor.execute(request)
            result = dispatch.as_dict()
            outcome = "SUCCEEDED"
        except Exception as exc:
            result = {"error": type(exc).__name__, "reason": str(exc)}
            outcome = "FAILED"
        signed_result = sign_execution_result(
            request=request,
            permit=permit,
            outcome=outcome,
            result=result,
            signer=signer,
            now=datetime.now(timezone.utc),
        )
        return {
            "role": "executor",
            "executed": True,
            "outcome": outcome,
            "signed_execution_result": signed_result.as_dict(),
        }
    return handle


def verifier_handler(profile: Mapping[str, Any], config: Mapping[str, Any]):
    trust = trust_store_from_list(_load_json(config["trust_store"]))
    signer = load_signer(config["private_key"], subject=str(config["subject"]))
    chain_state_path = Path(config["chain_state"])
    chain_state_path.parent.mkdir(parents=True, exist_ok=True)

    def load_chain() -> tuple[str | None, str | None]:
        if not chain_state_path.exists():
            return None, None
        value = _load_json(chain_state_path)
        return value.get("previous_receipt_hash"), value.get("previous_envelope_hash")

    def save_chain(receipt_hash: str, envelope_hash: str) -> None:
        chain_state_path.write_text(json.dumps({
            "previous_receipt_hash": receipt_hash,
            "previous_envelope_hash": envelope_hash,
        }, indent=2), encoding="utf-8")

    def handle(message: dict[str, Any]) -> dict[str, Any]:
        if message.get("op") == "health":
            return {"role": "verifier", "status": "ok", "key_id": signer.key_id}
        if message.get("op") != "finalize":
            raise ValueError("verifier_op_not_supported")
        request = action_request_from_dict(message["request"])
        permit = SignedEnvelope.from_dict(message["execution_permit"])
        result = SignedEnvelope.from_dict(message["signed_execution_result"])
        previous_receipt_hash, previous_envelope_hash = load_chain()
        receipt, signed = final_receipt_from_appliance(
            request=request,
            permit=permit,
            execution_result=result,
            trust_store=trust,
            signer=signer,
            previous_receipt_hash=previous_receipt_hash,
            previous_envelope_hash=previous_envelope_hash,
            now=datetime.now(timezone.utc),
        )
        save_chain(receipt.receipt_hash, signed.envelope_hash)
        return {
            "role": "verifier",
            "verified": True,
            "receipt": {
                "receipt_version": receipt.receipt_version,
                "request_id": receipt.request_id,
                "capability": receipt.capability,
                "action": receipt.action,
                "resource": receipt.resource,
                "gate": receipt.gate,
                "gate_reason": receipt.gate_reason,
                "matched_grant_ids": list(receipt.matched_grant_ids),
                "outcome": receipt.outcome,
                "result": dict(receipt.result),
                "registry_id": receipt.registry_id,
                "registry_version": receipt.registry_version,
                "created_at": receipt.created_at,
                "previous_receipt_hash": receipt.previous_receipt_hash,
                "receipt_hash": receipt.receipt_hash,
            },
            "signed_receipt": signed.as_dict(),
        }
    return handle


def run_service(*, role: str, profile_path: str | Path) -> None:
    profile = load_profile(profile_path)
    config = _service(profile, role)
    if role == "planner":
        handler = planner_handler(profile)
    elif role == "review_signer":
        handler = review_signer_handler(profile, config)
    elif role == "gate":
        handler = gate_handler(profile, config)
    elif role == "executor":
        handler = executor_handler(profile, config)
    elif role == "verifier":
        handler = verifier_handler(profile, config)
    else:
        raise ValueError(f"unknown_appliance_role:{role}")
    serve_unix_json(config["socket"], handler)
