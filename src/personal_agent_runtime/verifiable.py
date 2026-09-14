from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import binascii
import hashlib
import json
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import ActionReceipt, ActionRequest, CapabilityRegistry, GateDecision
from .review_broker import ReviewAuthorization, ReviewLease, request_digest

ENVELOPE_VERSION = "0.7"
SIGNATURE_ALGORITHM = "Ed25519"


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _plain(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp_must_be_timezone_aware")
    return dt.astimezone(timezone.utc)


def _now_iso(now: datetime | None = None) -> str:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now_must_be_timezone_aware")
    return current.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class TrustedSigner:
    key_id: str
    subject: str
    public_key_b64: str
    roles: tuple[str, ...]
    status: str = "ACTIVE"

    def __post_init__(self) -> None:
        if not self.key_id.strip() or not self.subject.strip():
            raise ValueError("trusted_signer_identity_is_required")
        if self.status not in {"ACTIVE", "REVOKED"}:
            raise ValueError("invalid_signer_status")
        try:
            raw = _b64d(self.public_key_b64)
        except Exception as exc:
            raise ValueError("invalid_public_key_encoding") from exc
        if len(raw) != 32:
            raise ValueError("ed25519_public_key_must_be_32_bytes")
        expected_key_id = f"ed25519-{hashlib.sha256(raw).hexdigest()[:24]}"
        if self.key_id != expected_key_id:
            raise ValueError("key_id_does_not_match_public_key")
        object.__setattr__(self, "roles", tuple(sorted(set(self.roles))))


class TrustStore:
    """Immutable-by-interface public trust roots used by verification only."""

    def __init__(self, signers: Iterable[TrustedSigner]) -> None:
        items = tuple(signers)
        by_id: dict[str, TrustedSigner] = {}
        for signer in items:
            if signer.key_id in by_id:
                raise ValueError("duplicate_trusted_signer_key_id")
            by_id[signer.key_id] = signer
        self._signers = MappingProxyType(by_id)

    def get(self, key_id: str) -> TrustedSigner | None:
        return self._signers.get(key_id)

    @property
    def signers(self) -> tuple[TrustedSigner, ...]:
        return tuple(self._signers.values())


class Ed25519Signer:
    """Reference signer. Production deployments should use KMS/HSM-backed keys."""

    def __init__(self, *, subject: str, private_key: Ed25519PrivateKey) -> None:
        if not subject.strip():
            raise ValueError("signer_subject_is_required")
        self.subject = subject
        self._private_key = private_key
        raw_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._public_key_raw = raw_public
        self.key_id = f"ed25519-{hashlib.sha256(raw_public).hexdigest()[:24]}"

    @classmethod
    def generate(cls, *, subject: str) -> "Ed25519Signer":
        return cls(subject=subject, private_key=Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, *, subject: str, private_key: bytes) -> "Ed25519Signer":
        return cls(subject=subject, private_key=Ed25519PrivateKey.from_private_bytes(private_key))

    @property
    def public_key_b64(self) -> str:
        return _b64e(self._public_key_raw)

    def trusted_record(self, *roles: str) -> TrustedSigner:
        return TrustedSigner(
            key_id=self.key_id,
            subject=self.subject,
            public_key_b64=self.public_key_b64,
            roles=tuple(roles),
        )

    def sign(self, data: bytes) -> str:
        return _b64e(self._private_key.sign(data))


@dataclass(frozen=True, slots=True)
class SignedEnvelope:
    envelope_version: str
    payload_type: str
    payload: Mapping[str, Any]
    payload_hash: str
    signer_id: str
    key_id: str
    signature_algorithm: str
    signed_at: str
    signature: str
    previous_envelope_hash: str | None
    envelope_hash: str

    def __post_init__(self) -> None:
        if self.envelope_version != ENVELOPE_VERSION:
            raise ValueError("unsupported_envelope_version")
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("unsupported_signature_algorithm")
        if len(self.payload_hash) != 64 or len(self.envelope_hash) != 64:
            raise ValueError("envelope_hashes_must_be_sha256")
        _parse_time(self.signed_at)
        object.__setattr__(self, "payload", MappingProxyType(_plain(self.payload)))

    def signature_view(self) -> dict[str, Any]:
        return {
            "envelope_version": self.envelope_version,
            "payload_type": self.payload_type,
            "payload": _plain(self.payload),
            "payload_hash": self.payload_hash,
            "signer_id": self.signer_id,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm,
            "signed_at": self.signed_at,
            "previous_envelope_hash": self.previous_envelope_hash,
        }

    def hash_view(self) -> dict[str, Any]:
        return {**self.signature_view(), "signature": self.signature}

    def as_dict(self) -> dict[str, Any]:
        return {**self.hash_view(), "envelope_hash": self.envelope_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedEnvelope":
        return cls(
            envelope_version=str(value["envelope_version"]),
            payload_type=str(value["payload_type"]),
            payload=dict(value["payload"]),
            payload_hash=str(value["payload_hash"]),
            signer_id=str(value["signer_id"]),
            key_id=str(value["key_id"]),
            signature_algorithm=str(value["signature_algorithm"]),
            signed_at=str(value["signed_at"]),
            signature=str(value["signature"]),
            previous_envelope_hash=(
                None if value.get("previous_envelope_hash") is None else str(value["previous_envelope_hash"])
            ),
            envelope_hash=str(value["envelope_hash"]),
        )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    payload_hash_ok: bool
    envelope_hash_ok: bool
    signer_trusted: bool
    signer_active: bool
    signer_subject_ok: bool
    role_ok: bool
    signature_ok: bool
    reason: str


def sign_payload(
    *,
    payload_type: str,
    payload: Mapping[str, Any],
    signer: Ed25519Signer,
    signed_at: str | None = None,
    previous_envelope_hash: str | None = None,
) -> SignedEnvelope:
    if not payload_type.strip():
        raise ValueError("payload_type_is_required")
    signed_at = signed_at or _now_iso()
    plain_payload = _plain(payload)
    payload_hash = sha256_hex(plain_payload)
    signature_view = {
        "envelope_version": ENVELOPE_VERSION,
        "payload_type": payload_type,
        "payload": plain_payload,
        "payload_hash": payload_hash,
        "signer_id": signer.subject,
        "key_id": signer.key_id,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signed_at": signed_at,
        "previous_envelope_hash": previous_envelope_hash,
    }
    signature = signer.sign(canonical_bytes(signature_view))
    envelope_hash = sha256_hex({**signature_view, "signature": signature})
    return SignedEnvelope(
        **signature_view,
        signature=signature,
        envelope_hash=envelope_hash,
    )


def verify_envelope(
    envelope: SignedEnvelope,
    trust_store: TrustStore,
    *,
    required_role: str | None = None,
    expected_payload_type: str | None = None,
) -> VerificationResult:
    payload_hash_ok = envelope.payload_hash == sha256_hex(envelope.payload)
    envelope_hash_ok = envelope.envelope_hash == sha256_hex(envelope.hash_view())
    trusted = trust_store.get(envelope.key_id)
    signer_trusted = trusted is not None
    signer_active = bool(trusted and trusted.status == "ACTIVE")
    signer_subject_ok = bool(trusted and trusted.subject == envelope.signer_id)
    role_ok = bool(trusted and (required_role is None or required_role in trusted.roles))
    type_ok = expected_payload_type is None or envelope.payload_type == expected_payload_type
    signature_ok = False
    if trusted is not None:
        try:
            public_key = Ed25519PublicKey.from_public_bytes(_b64d(trusted.public_key_b64))
            public_key.verify(_b64d(envelope.signature), canonical_bytes(envelope.signature_view()))
            signature_ok = True
        except (InvalidSignature, ValueError, TypeError, binascii.Error):
            signature_ok = False

    checks = {
        "payload_hash_mismatch": payload_hash_ok,
        "envelope_hash_mismatch": envelope_hash_ok,
        "untrusted_signer": signer_trusted,
        "signer_revoked": signer_active,
        "signer_subject_mismatch": signer_subject_ok,
        "role_not_allowed": role_ok,
        "payload_type_mismatch": type_ok,
        "signature_invalid": signature_ok,
    }
    reason = "verified"
    for failure, passed in checks.items():
        if not passed:
            reason = failure
            break
    ok = all(checks.values())
    return VerificationResult(
        ok=ok,
        payload_hash_ok=payload_hash_ok,
        envelope_hash_ok=envelope_hash_ok,
        signer_trusted=signer_trusted,
        signer_active=signer_active,
        signer_subject_ok=signer_subject_ok,
        role_ok=role_ok,
        signature_ok=signature_ok,
        reason=reason,
    )


def review_lease_payload(lease: ReviewLease) -> dict[str, Any]:
    return {
        "lease_id": lease.lease_id,
        "request_digest": lease.request_digest,
        "capability": lease.capability,
        "action": lease.action,
        "resource": lease.resource,
        "review_grant_ids": list(lease.review_grant_ids),
        "issued_by": lease.issued_by,
        "issued_at": lease.issued_at,
        "expires_at": lease.expires_at,
        "max_uses": lease.max_uses,
        "issuer_type": lease.issuer_type,
        "authority_effect": "ONE_SHOT_REVIEW_ONLY",
    }


def review_lease_from_payload(payload: Mapping[str, Any]) -> ReviewLease:
    expected_fields = {
        "lease_id", "request_digest", "capability", "action", "resource",
        "review_grant_ids", "issued_by", "issued_at", "expires_at",
        "max_uses", "issuer_type", "authority_effect",
    }
    if set(payload) != expected_fields:
        raise ValueError("review_lease_payload_fields_mismatch")
    if payload.get("authority_effect") != "ONE_SHOT_REVIEW_ONLY":
        raise ValueError("invalid_review_lease_authority_effect")
    return ReviewLease(
        lease_id=str(payload["lease_id"]),
        request_digest=str(payload["request_digest"]),
        capability=str(payload["capability"]),
        action=str(payload["action"]),
        resource=str(payload["resource"]),
        review_grant_ids=tuple(str(v) for v in payload["review_grant_ids"]),
        issued_by=str(payload["issued_by"]),
        issued_at=str(payload["issued_at"]),
        expires_at=str(payload["expires_at"]),
        max_uses=int(payload["max_uses"]),
        issuer_type=str(payload["issuer_type"]),
    )


def issue_signed_review_lease(
    *,
    request: ActionRequest,
    base_decision: GateDecision,
    signer: Ed25519Signer,
    ttl_seconds: int = 300,
    lease_id: str | None = None,
    now: datetime | None = None,
    previous_envelope_hash: str | None = None,
) -> SignedEnvelope:
    if base_decision.verdict != "REVIEW":
        raise ValueError("signed_lease_can_only_be_issued_for_review")
    if ttl_seconds < 1 or ttl_seconds > 3600:
        raise ValueError("ttl_seconds_must_be_between_1_and_3600")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now_must_be_timezone_aware")
    current = current.astimezone(timezone.utc)
    lease = ReviewLease(
        lease_id=lease_id or f"signed-lease-{request.request_id}-{int(current.timestamp())}",
        request_digest=request_digest(request),
        capability=request.capability,
        action=request.action,
        resource=request.resource,
        review_grant_ids=tuple(base_decision.matched_grant_ids),
        issued_by=signer.subject,
        issued_at=current.isoformat(),
        expires_at=(current + timedelta(seconds=ttl_seconds)).isoformat(),
    )
    return sign_payload(
        payload_type="review_lease",
        payload=review_lease_payload(lease),
        signer=signer,
        signed_at=current.isoformat(),
        previous_envelope_hash=previous_envelope_hash,
    )


def capability_registry_payload(registry: CapabilityRegistry) -> dict[str, Any]:
    grants = []
    for grant in sorted(registry.grants, key=lambda item: item.grant_id):
        grants.append({
            "grant_id": grant.grant_id,
            "capability": grant.capability,
            "effect": grant.effect,
            "actions": list(grant.actions),
            "resources": list(grant.resources),
            "issued_by": grant.issued_by,
            "note": grant.note,
        })
    return {
        "registry_id": registry.registry_id,
        "version": registry.version,
        "grants": grants,
        "authority_effect": "ATTESTS_EXACT_REGISTRY_SNAPSHOT",
    }


def attest_capability_registry(
    registry: CapabilityRegistry,
    signer: Ed25519Signer,
    *,
    signed_at: str | None = None,
    previous_envelope_hash: str | None = None,
) -> SignedEnvelope:
    return sign_payload(
        payload_type="capability_registry",
        payload=capability_registry_payload(registry),
        signer=signer,
        signed_at=signed_at,
        previous_envelope_hash=previous_envelope_hash,
    )


def verify_capability_registry_attestation(
    registry: CapabilityRegistry,
    envelope: SignedEnvelope,
    trust_store: TrustStore,
) -> VerificationResult:
    verified = verify_envelope(
        envelope,
        trust_store,
        required_role="capability_authority",
        expected_payload_type="capability_registry",
    )
    if not verified.ok:
        return verified
    if _plain(envelope.payload) != capability_registry_payload(registry):
        return VerificationResult(
            ok=False,
            payload_hash_ok=verified.payload_hash_ok,
            envelope_hash_ok=verified.envelope_hash_ok,
            signer_trusted=verified.signer_trusted,
            signer_active=verified.signer_active,
            signer_subject_ok=verified.signer_subject_ok,
            role_ok=verified.role_ok,
            signature_ok=verified.signature_ok,
            reason="registry_snapshot_mismatch",
        )
    return verified


def action_receipt_payload(receipt: ActionReceipt) -> dict[str, Any]:
    return {
        "receipt_version": receipt.receipt_version,
        "request_id": receipt.request_id,
        "capability": receipt.capability,
        "action": receipt.action,
        "resource": receipt.resource,
        "gate": receipt.gate,
        "gate_reason": receipt.gate_reason,
        "matched_grant_ids": list(receipt.matched_grant_ids),
        "outcome": receipt.outcome,
        "result": _plain(receipt.result),
        "registry_id": receipt.registry_id,
        "registry_version": receipt.registry_version,
        "created_at": receipt.created_at,
        "previous_receipt_hash": receipt.previous_receipt_hash,
        "receipt_hash": receipt.receipt_hash,
    }


def sign_action_receipt(
    receipt: ActionReceipt,
    signer: Ed25519Signer,
    *,
    signed_at: str | None = None,
    previous_envelope_hash: str | None = None,
) -> SignedEnvelope:
    return sign_payload(
        payload_type="action_receipt",
        payload=action_receipt_payload(receipt),
        signer=signer,
        signed_at=signed_at,
        previous_envelope_hash=previous_envelope_hash,
    )


@dataclass(frozen=True, slots=True)
class EnvelopeChainResult:
    ok: bool
    verified_count: int
    failed_index: int | None
    reason: str


def verify_envelope_chain(
    envelopes: Iterable[SignedEnvelope],
    trust_store: TrustStore,
    *,
    required_role: str | None = None,
    expected_payload_type: str | None = None,
    expected_previous_hash: str | None = None,
) -> EnvelopeChainResult:
    previous = expected_previous_hash
    count = 0
    for index, envelope in enumerate(envelopes):
        verified = verify_envelope(
            envelope,
            trust_store,
            required_role=required_role,
            expected_payload_type=expected_payload_type,
        )
        if not verified.ok:
            return EnvelopeChainResult(False, count, index, verified.reason)
        if envelope.previous_envelope_hash != previous:
            return EnvelopeChainResult(False, count, index, "previous_envelope_hash_mismatch")
        previous = envelope.envelope_hash
        count += 1
    return EnvelopeChainResult(True, count, None, "verified")


class ReplayLedger:
    """SQLite-backed one-shot ledger. UNIQUE lease_id survives runtime restarts."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS review_lease_use (
                lease_id TEXT PRIMARY KEY,
                envelope_hash TEXT NOT NULL UNIQUE,
                consumed_at TEXT NOT NULL
            )
            """
        )

    def consume(self, *, lease_id: str, envelope_hash: str, consumed_at: str) -> bool:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                "INSERT INTO review_lease_use(lease_id, envelope_hash, consumed_at) VALUES (?, ?, ?)",
                (lease_id, envelope_hash, consumed_at),
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


class SignedReviewAuthorizer:
    """Runtime-side verifier for review leases issued by a separate trusted process."""

    def __init__(self, *, trust_store: TrustStore, replay_ledger: ReplayLedger | None = None) -> None:
        self._trust_store = trust_store
        self._ledger = replay_ledger or ReplayLedger()

    def redeem(
        self,
        *,
        envelope: SignedEnvelope,
        request: ActionRequest,
        base_decision: GateDecision,
        now: datetime | None = None,
    ) -> ReviewAuthorization:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("now_must_be_timezone_aware")
        current = current.astimezone(timezone.utc)

        if base_decision.verdict != "REVIEW":
            return ReviewAuthorization(False, "base_gate_is_not_review")

        verification = verify_envelope(
            envelope,
            self._trust_store,
            required_role="review_issuer",
            expected_payload_type="review_lease",
        )
        if not verification.ok:
            return ReviewAuthorization(False, f"signed_lease_{verification.reason}")

        try:
            lease = review_lease_from_payload(envelope.payload)
        except (KeyError, TypeError, ValueError) as exc:
            return ReviewAuthorization(False, f"signed_lease_payload_invalid:{type(exc).__name__}")

        if lease.issued_by != envelope.signer_id:
            return ReviewAuthorization(False, "signed_lease_issuer_mismatch", lease.lease_id)
        if current < _parse_time(lease.issued_at):
            return ReviewAuthorization(False, "lease_not_yet_valid", lease.lease_id)
        if current >= _parse_time(lease.expires_at):
            return ReviewAuthorization(False, "lease_expired", lease.lease_id)
        if request_digest(request) != lease.request_digest:
            return ReviewAuthorization(False, "request_digest_mismatch", lease.lease_id)
        if (
            request.capability != lease.capability
            or request.action != lease.action
            or request.resource != lease.resource
        ):
            return ReviewAuthorization(False, "lease_scope_mismatch", lease.lease_id)
        if tuple(base_decision.matched_grant_ids) != tuple(lease.review_grant_ids):
            return ReviewAuthorization(False, "review_policy_changed", lease.lease_id)

        # Consume before execution. SQLite uniqueness preserves one-shot semantics across restarts.
        consumed = self._ledger.consume(
            lease_id=lease.lease_id,
            envelope_hash=envelope.envelope_hash,
            consumed_at=current.isoformat(),
        )
        if not consumed:
            return ReviewAuthorization(False, "lease_already_used", lease.lease_id)
        return ReviewAuthorization(True, "signed_human_review_lease_redeemed", lease.lease_id)
