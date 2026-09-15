from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path
import socket
import sqlite3
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .executor import SandboxedExecutor
from .gate import CapabilityGate
from .models import ActionRequest, CapabilityGrant, CapabilityRegistry, GateDecision
from .receipt import create_receipt
from .review_broker import request_digest
from .verifiable import (
    Ed25519Signer,
    SignedEnvelope,
    SignedReviewAuthorizer,
    TrustStore,
    TrustedSigner,
    ReplayLedger,
    issue_signed_review_lease,
    sign_action_receipt,
    sign_payload,
    verify_envelope,
)

APPLIANCE_VERSION = "0.9"


def _now(now: datetime | None = None) -> datetime:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now_must_be_timezone_aware")
    return current.astimezone(timezone.utc)


def action_request_dict(request: ActionRequest) -> dict[str, Any]:
    return {
        "request_id": request.request_id,
        "capability": request.capability,
        "action": request.action,
        "resource": request.resource,
        "payload": dict(request.payload),
        "actor": request.actor,
    }


def action_request_from_dict(value: Mapping[str, Any]) -> ActionRequest:
    return ActionRequest(
        request_id=str(value["request_id"]),
        capability=str(value["capability"]),
        action=str(value["action"]),
        resource=str(value["resource"]),
        payload=dict(value.get("payload", {})),
        actor=str(value.get("actor", "agent")),
    )


def gate_decision_dict(decision: GateDecision) -> dict[str, Any]:
    return {
        "verdict": decision.verdict,
        "reason": decision.reason,
        "matched_grant_ids": list(decision.matched_grant_ids),
    }


def gate_decision_from_dict(value: Mapping[str, Any]) -> GateDecision:
    return GateDecision(
        verdict=str(value["verdict"]),
        reason=str(value["reason"]),
        matched_grant_ids=tuple(str(x) for x in value.get("matched_grant_ids", [])),
    )


def registry_dict(registry: CapabilityRegistry) -> dict[str, Any]:
    return {
        "registry_id": registry.registry_id,
        "version": registry.version,
        "grants": [
            {
                "grant_id": grant.grant_id,
                "capability": grant.capability,
                "effect": grant.effect,
                "actions": list(grant.actions),
                "resources": list(grant.resources),
                "issued_by": grant.issued_by,
                "note": grant.note,
            }
            for grant in registry.grants
        ],
    }


def registry_from_dict(value: Mapping[str, Any]) -> CapabilityRegistry:
    return CapabilityRegistry(
        registry_id=str(value["registry_id"]),
        version=str(value["version"]),
        grants=tuple(
            CapabilityGrant(
                grant_id=str(item["grant_id"]),
                capability=str(item["capability"]),
                effect=str(item["effect"]),
                actions=tuple(str(x) for x in item["actions"]),
                resources=tuple(str(x) for x in item["resources"]),
                issued_by=str(item.get("issued_by", "human")),
                note=str(item.get("note", "")),
            )
            for item in value.get("grants", [])
        ),
    )


def execution_permit_payload(
    *,
    permit_id: str,
    request: ActionRequest,
    decision: GateDecision,
    registry: CapabilityRegistry,
    issued_at: str,
    expires_at: str,
) -> dict[str, Any]:
    if decision.verdict != "ALLOW":
        raise ValueError("execution_permit_requires_allow")
    return {
        "permit_version": APPLIANCE_VERSION,
        "permit_id": permit_id,
        "request_digest": request_digest(request),
        "request_id": request.request_id,
        "capability": request.capability,
        "action": request.action,
        "resource": request.resource,
        "actor": request.actor,
        "gate_verdict": decision.verdict,
        "gate_reason": decision.reason,
        "matched_grant_ids": list(decision.matched_grant_ids),
        "registry_id": registry.registry_id,
        "registry_version": registry.version,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "max_uses": 1,
        "authority_effect": "EXECUTION_ONCE",
    }


def issue_execution_permit(
    *,
    request: ActionRequest,
    decision: GateDecision,
    registry: CapabilityRegistry,
    signer: Ed25519Signer,
    ttl_seconds: int = 30,
    permit_id: str | None = None,
    now: datetime | None = None,
) -> SignedEnvelope:
    if ttl_seconds < 1 or ttl_seconds > 300:
        raise ValueError("permit_ttl_must_be_between_1_and_300")
    current = _now(now)
    payload = execution_permit_payload(
        permit_id=permit_id or f"permit-{request.request_id}-{int(current.timestamp())}",
        request=request,
        decision=decision,
        registry=registry,
        issued_at=current.isoformat(),
        expires_at=(current + timedelta(seconds=ttl_seconds)).isoformat(),
    )
    return sign_payload(
        payload_type="execution_permit",
        payload=payload,
        signer=signer,
        signed_at=current.isoformat(),
    )


class ExecutionPermitLedger:
    """Persistent replay protection for Gate-issued one-shot permits."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS execution_permit_use (
                permit_id TEXT PRIMARY KEY,
                envelope_hash TEXT NOT NULL UNIQUE,
                consumed_at TEXT NOT NULL
            )
            """
        )

    def consume(self, *, permit_id: str, envelope_hash: str, consumed_at: str) -> bool:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                "INSERT INTO execution_permit_use(permit_id, envelope_hash, consumed_at) VALUES (?, ?, ?)",
                (permit_id, envelope_hash, consumed_at),
            )
            self._connection.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            self._connection.execute("ROLLBACK")
            return False
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._connection.close()


@dataclass(frozen=True, slots=True)
class PermitAuthorization:
    authorized: bool
    reason: str
    permit_id: str | None = None
    gate_decision: GateDecision | None = None
    registry_id: str | None = None
    registry_version: str | None = None


def verify_and_consume_execution_permit(
    *,
    envelope: SignedEnvelope,
    request: ActionRequest,
    trust_store: TrustStore,
    ledger: ExecutionPermitLedger,
    now: datetime | None = None,
) -> PermitAuthorization:
    current = _now(now)
    verified = verify_envelope(
        envelope,
        trust_store,
        required_role="execution_permit_issuer",
        expected_payload_type="execution_permit",
    )
    if not verified.ok:
        return PermitAuthorization(False, f"permit_{verified.reason}")
    payload = dict(envelope.payload)
    required = {
        "permit_version", "permit_id", "request_digest", "request_id", "capability", "action",
        "resource", "actor", "gate_verdict", "gate_reason", "matched_grant_ids", "registry_id",
        "registry_version", "issued_at", "expires_at", "max_uses", "authority_effect",
    }
    if set(payload) != required:
        return PermitAuthorization(False, "permit_payload_fields_mismatch")
    if payload["permit_version"] != APPLIANCE_VERSION:
        return PermitAuthorization(False, "permit_version_mismatch")
    if payload["authority_effect"] != "EXECUTION_ONCE" or payload["max_uses"] != 1:
        return PermitAuthorization(False, "permit_authority_invalid")
    if payload["gate_verdict"] != "ALLOW":
        return PermitAuthorization(False, "permit_gate_not_allow")
    issued = datetime.fromisoformat(str(payload["issued_at"]).replace("Z", "+00:00"))
    expires = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
    if issued.tzinfo is None or expires.tzinfo is None:
        return PermitAuthorization(False, "permit_timestamp_invalid")
    if current < issued.astimezone(timezone.utc):
        return PermitAuthorization(False, "permit_not_yet_valid", str(payload["permit_id"]))
    if current >= expires.astimezone(timezone.utc):
        return PermitAuthorization(False, "permit_expired", str(payload["permit_id"]))
    if request_digest(request) != payload["request_digest"]:
        return PermitAuthorization(False, "permit_request_digest_mismatch", str(payload["permit_id"]))
    for field in ("request_id", "capability", "action", "resource", "actor"):
        if str(payload[field]) != str(getattr(request, field)):
            return PermitAuthorization(False, f"permit_{field}_mismatch", str(payload["permit_id"]))
    consumed = ledger.consume(
        permit_id=str(payload["permit_id"]),
        envelope_hash=envelope.envelope_hash,
        consumed_at=current.isoformat(),
    )
    if not consumed:
        return PermitAuthorization(False, "permit_already_used", str(payload["permit_id"]))
    decision = GateDecision(
        verdict="ALLOW",
        reason=str(payload["gate_reason"]),
        matched_grant_ids=tuple(str(x) for x in payload["matched_grant_ids"]),
    )
    return PermitAuthorization(
        True,
        "execution_permit_redeemed",
        str(payload["permit_id"]),
        decision,
        str(payload["registry_id"]),
        str(payload["registry_version"]),
    )


def sign_execution_result(
    *,
    request: ActionRequest,
    permit: SignedEnvelope,
    outcome: str,
    result: Mapping[str, Any],
    signer: Ed25519Signer,
    now: datetime | None = None,
) -> SignedEnvelope:
    current = _now(now)
    payload = {
        "result_version": APPLIANCE_VERSION,
        "result_id": f"result-{request.request_id}-{int(current.timestamp() * 1_000_000)}",
        "permit_id": str(permit.payload["permit_id"]),
        "permit_hash": permit.envelope_hash,
        "request_digest": request_digest(request),
        "request_id": request.request_id,
        "capability": request.capability,
        "action": request.action,
        "resource": request.resource,
        "outcome": outcome,
        "result": dict(result),
        "executed_at": current.isoformat(),
        "authority_effect": "EVIDENCE_ONLY",
    }
    return sign_payload(
        payload_type="execution_result",
        payload=payload,
        signer=signer,
        signed_at=current.isoformat(),
    )


def verify_execution_result(
    *,
    envelope: SignedEnvelope,
    permit: SignedEnvelope,
    request: ActionRequest,
    trust_store: TrustStore,
) -> tuple[bool, str]:
    verified = verify_envelope(
        envelope,
        trust_store,
        required_role="executor_result_signer",
        expected_payload_type="execution_result",
    )
    if not verified.ok:
        return False, f"execution_result_{verified.reason}"
    payload = dict(envelope.payload)
    if payload.get("authority_effect") != "EVIDENCE_ONLY":
        return False, "execution_result_authority_invalid"
    if payload.get("permit_hash") != permit.envelope_hash:
        return False, "execution_result_permit_hash_mismatch"
    if payload.get("permit_id") != permit.payload.get("permit_id"):
        return False, "execution_result_permit_id_mismatch"
    if payload.get("request_digest") != request_digest(request):
        return False, "execution_result_request_digest_mismatch"
    for field in ("request_id", "capability", "action", "resource"):
        if str(payload.get(field)) != str(getattr(request, field)):
            return False, f"execution_result_{field}_mismatch"
    if payload.get("outcome") not in {"SUCCEEDED", "FAILED"}:
        return False, "execution_result_outcome_invalid"
    return True, "verified"


def final_receipt_from_appliance(
    *,
    request: ActionRequest,
    permit: SignedEnvelope,
    execution_result: SignedEnvelope,
    trust_store: TrustStore,
    signer: Ed25519Signer,
    previous_receipt_hash: str | None = None,
    previous_envelope_hash: str | None = None,
    now: datetime | None = None,
) -> tuple[Any, SignedEnvelope]:
    permit_check = verify_envelope(
        permit,
        trust_store,
        required_role="execution_permit_issuer",
        expected_payload_type="execution_permit",
    )
    if not permit_check.ok:
        raise ValueError(f"invalid_execution_permit:{permit_check.reason}")
    result_ok, result_reason = verify_execution_result(
        envelope=execution_result,
        permit=permit,
        request=request,
        trust_store=trust_store,
    )
    if not result_ok:
        raise ValueError(result_reason)
    pp = dict(permit.payload)
    decision = GateDecision(
        verdict="ALLOW",
        reason=str(pp["gate_reason"]),
        matched_grant_ids=tuple(str(x) for x in pp["matched_grant_ids"]),
    )
    registry = CapabilityRegistry(
        registry_id=str(pp["registry_id"]),
        version=str(pp["registry_version"]),
        grants=(),
    )
    rp = dict(execution_result.payload)
    current = _now(now)
    receipt = create_receipt(
        request=request,
        decision=decision,
        registry=registry,
        outcome=str(rp["outcome"]),
        result=dict(rp["result"]),
        previous_receipt_hash=previous_receipt_hash,
        created_at=current.isoformat(),
    )
    signed = sign_action_receipt(
        receipt,
        signer,
        signed_at=current.isoformat(),
        previous_envelope_hash=previous_envelope_hash,
    )
    return receipt, signed


def _write_private_key(path: Path) -> Ed25519Signer:
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(raw).decode("ascii"), encoding="utf-8")
    os.chmod(path, 0o600)
    return Ed25519Signer.from_private_bytes(subject=path.stem, private_key=raw)


def load_signer(path: str | Path, *, subject: str) -> Ed25519Signer:
    raw = base64.b64decode(Path(path).read_text(encoding="utf-8").strip())
    return Ed25519Signer.from_private_bytes(subject=subject, private_key=raw)


def save_signer(path: str | Path, *, subject: str) -> Ed25519Signer:
    path = Path(path)
    private = Ed25519PrivateKey.generate()
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.b64encode(raw).decode("ascii"), encoding="utf-8")
    os.chmod(path, 0o600)
    return Ed25519Signer.from_private_bytes(subject=subject, private_key=raw)


def trusted_signer_dict(record: TrustedSigner) -> dict[str, Any]:
    return {
        "key_id": record.key_id,
        "subject": record.subject,
        "public_key_b64": record.public_key_b64,
        "roles": list(record.roles),
        "status": record.status,
    }


def trust_store_from_list(values: list[Mapping[str, Any]]) -> TrustStore:
    return TrustStore(
        TrustedSigner(
            key_id=str(v["key_id"]),
            subject=str(v["subject"]),
            public_key_b64=str(v["public_key_b64"]),
            roles=tuple(str(x) for x in v["roles"]),
            status=str(v.get("status", "ACTIVE")),
        )
        for v in values
    )


class UnixJsonClient:
    def __init__(self, socket_path: str | Path, timeout: float = 5.0) -> None:
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def call(self, message: Mapping[str, Any]) -> dict[str, Any]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            sock.sendall(json.dumps(dict(message), ensure_ascii=False).encode("utf-8") + b"\n")
            chunks = bytearray()
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.extend(data)
                if b"\n" in data:
                    break
        if not chunks:
            raise RuntimeError("empty_service_response")
        return json.loads(bytes(chunks).split(b"\n", 1)[0].decode("utf-8"))


def serve_unix_json(
    socket_path: str | Path,
    handler: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    socket_mode: int = 0o660,
) -> None:
    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        os.chmod(path, socket_mode)
        server.listen(16)
        while True:
            conn, _ = server.accept()
            with conn:
                try:
                    buffer = bytearray()
                    while True:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buffer.extend(chunk)
                        if b"\n" in chunk:
                            break
                    request = json.loads(bytes(buffer).split(b"\n", 1)[0].decode("utf-8"))
                    if request.get("op") == "shutdown":
                        response = {"ok": True, "service_pid": os.getpid(), "stopping": True}
                        conn.sendall(json.dumps(response).encode("utf-8") + b"\n")
                        return
                    response = handler(request)
                    response.setdefault("ok", True)
                    response.setdefault("service_pid", os.getpid())
                except Exception as exc:
                    response = {
                        "ok": False,
                        "service_pid": os.getpid(),
                        "error": type(exc).__name__,
                        "reason": str(exc),
                    }
                conn.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def initialize_appliance(root: str | Path) -> Path:
    """Create a local reference appliance with process-specific keys and state paths.

    This is a developer/reference initializer, not production KMS provisioning.
    """
    root = Path(root).resolve()
    run_dir = root / "run"
    config_dir = root / "config"
    state_dir = root / "state"
    secret_dir = root / "secrets"
    sandbox_dir = root / "sandbox"
    for path in (run_dir, config_dir, state_dir, secret_dir, sandbox_dir):
        path.mkdir(parents=True, exist_ok=True)
    os.chmod(secret_dir, 0o700)

    review_signer = save_signer(secret_dir / "review_signer.key", subject="human-review-broker")
    gate_signer = save_signer(secret_dir / "gate_permit_signer.key", subject="runtime-gate")
    executor_signer = save_signer(secret_dir / "executor_result_signer.key", subject="runtime-executor")
    verifier_signer = save_signer(secret_dir / "verifier_receipt_signer.key", subject="runtime-verifier")

    registry = CapabilityRegistry(
        registry_id="personal-agent-appliance",
        version="0.9-reference",
        grants=(
            CapabilityGrant(
                grant_id="sandbox-read-auto",
                capability="filesystem.read",
                effect="ALLOW",
                actions=("read_text",),
                resources=("approved/*",),
                issued_by="human:appliance-init",
            ),
            CapabilityGrant(
                grant_id="sandbox-write-review",
                capability="filesystem.write",
                effect="REVIEW",
                actions=("write_text",),
                resources=("approved/*",),
                issued_by="human:appliance-init",
            ),
            CapabilityGrant(
                grant_id="control-plane-deny",
                capability="runtime.*",
                effect="DENY",
                actions=("*",),
                resources=("*",),
                issued_by="human:appliance-init",
            ),
        ),
    )
    registry_path = config_dir / "capability_registry.json"
    registry_path.write_text(json.dumps(registry_dict(registry), ensure_ascii=False, indent=2), encoding="utf-8")

    gate_trust = [trusted_signer_dict(review_signer.trusted_record("review_issuer"))]
    executor_trust = [trusted_signer_dict(gate_signer.trusted_record("execution_permit_issuer"))]
    verifier_trust = [
        trusted_signer_dict(gate_signer.trusted_record("execution_permit_issuer")),
        trusted_signer_dict(executor_signer.trusted_record("executor_result_signer")),
    ]
    public_trust = [
        trusted_signer_dict(review_signer.trusted_record("review_issuer")),
        trusted_signer_dict(gate_signer.trusted_record("execution_permit_issuer")),
        trusted_signer_dict(executor_signer.trusted_record("executor_result_signer")),
        trusted_signer_dict(verifier_signer.trusted_record("runtime_receipt_signer")),
    ]
    for name, content in (
        ("gate_trust.json", gate_trust),
        ("executor_trust.json", executor_trust),
        ("verifier_trust.json", verifier_trust),
        ("public_trust.json", public_trust),
    ):
        (config_dir / name).write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")

    profile = {
        "appliance_version": APPLIANCE_VERSION,
        "profile_id": "local-reference-appliance",
        "transport": "unix-domain-socket",
        "authority_model": {
            "planner_may_sign": False,
            "review_signer_may_execute": False,
            "gate_may_execute": False,
            "executor_may_change_registry": False,
            "verifier_may_execute": False,
            "execution_requires_gate_permit": True,
        },
        "services": {
            "planner": {
                "socket": str(run_dir / "planner.sock"),
                "state_dir": str(state_dir / "planner"),
                "private_keys": [],
            },
            "review_signer": {
                "socket": str(run_dir / "review_signer.sock"),
                "state_dir": str(state_dir / "review_signer"),
                "private_key": str(secret_dir / "review_signer.key"),
                "subject": "human-review-broker",
                "roles": ["review_issuer"],
            },
            "gate": {
                "socket": str(run_dir / "gate.sock"),
                "state_dir": str(state_dir / "gate"),
                "registry": str(registry_path),
                "trust_store": str(config_dir / "gate_trust.json"),
                "private_key": str(secret_dir / "gate_permit_signer.key"),
                "subject": "runtime-gate",
                "roles": ["execution_permit_issuer"],
                "review_replay_db": str(state_dir / "gate" / "review_replay.sqlite3"),
                "permit_ttl_seconds": 30,
            },
            "executor": {
                "socket": str(run_dir / "executor.sock"),
                "state_dir": str(state_dir / "executor"),
                "trust_store": str(config_dir / "executor_trust.json"),
                "private_key": str(secret_dir / "executor_result_signer.key"),
                "subject": "runtime-executor",
                "roles": ["executor_result_signer"],
                "permit_replay_db": str(state_dir / "executor" / "permit_replay.sqlite3"),
                "sandbox_root": str(sandbox_dir),
                "adapters": [],
            },
            "verifier": {
                "socket": str(run_dir / "verifier.sock"),
                "state_dir": str(state_dir / "verifier"),
                "trust_store": str(config_dir / "verifier_trust.json"),
                "private_key": str(secret_dir / "verifier_receipt_signer.key"),
                "subject": "runtime-verifier",
                "roles": ["runtime_receipt_signer"],
                "chain_state": str(state_dir / "verifier" / "receipt_chain.json"),
            },
        },
        "public_trust_store": str(config_dir / "public_trust.json"),
    }
    for service in profile["services"].values():
        Path(service["state_dir"]).mkdir(parents=True, exist_ok=True)
    profile_path = config_dir / "appliance_profile.json"
    profile_path.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")
    return profile_path
