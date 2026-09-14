from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from threading import Lock
from typing import Iterable

from .models import ActionRequest, GateDecision


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


def request_digest(request: ActionRequest) -> str:
    payload = {
        "request_id": request.request_id,
        "capability": request.capability,
        "action": request.action,
        "resource": request.resource,
        "payload": dict(request.payload),
        "actor": request.actor,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ReviewLease:
    lease_id: str
    request_digest: str
    capability: str
    action: str
    resource: str
    review_grant_ids: tuple[str, ...]
    issued_by: str
    issued_at: str
    expires_at: str
    max_uses: int = 1
    issuer_type: str = "HUMAN"

    def __post_init__(self) -> None:
        if not self.lease_id.strip():
            raise ValueError("lease_id_is_required")
        if self.issuer_type != "HUMAN":
            raise ValueError("review_lease_must_be_human_issued")
        if not self.issued_by.strip():
            raise ValueError("issued_by_is_required")
        if self.max_uses != 1:
            raise ValueError("v0_6_review_leases_are_one_shot")
        if len(self.request_digest) != 64:
            raise ValueError("request_digest_must_be_sha256")
        issued = _parse_time(self.issued_at)
        expires = _parse_time(self.expires_at)
        if expires <= issued:
            raise ValueError("expires_at_must_be_after_issued_at")
        object.__setattr__(self, "review_grant_ids", tuple(self.review_grant_ids))


@dataclass(frozen=True, slots=True)
class ReviewAuthorization:
    authorized: bool
    reason: str
    lease_id: str | None = None


@dataclass(frozen=True, slots=True)
class ReviewEventReceipt:
    event_version: str
    event: str
    lease_id: str
    request_id: str | None
    request_digest: str
    reason: str
    actor: str
    created_at: str
    previous_event_hash: str | None
    event_hash: str

    def as_dict(self) -> dict[str, object]:
        return {
            "event_version": self.event_version,
            "event": self.event,
            "lease_id": self.lease_id,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "reason": self.reason,
            "actor": self.actor,
            "created_at": self.created_at,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
        }


class ReviewBroker:
    """Trusted review control-plane reference.

    The planner/agent must not receive a reference to lease issuance or cancellation APIs.
    v0.6 trusts the broker boundary; cryptographic issuer proof is deferred to v0.7.
    """

    def __init__(self, leases: Iterable[ReviewLease] = ()) -> None:
        self._leases: dict[str, ReviewLease] = {}
        self._uses: dict[str, int] = {}
        self._cancelled: dict[str, str] = {}
        self._events: list[ReviewEventReceipt] = []
        self._lock = Lock()
        for lease in leases:
            self.register(lease)

    @property
    def events(self) -> tuple[ReviewEventReceipt, ...]:
        return tuple(self._events)

    def register(self, lease: ReviewLease) -> None:
        with self._lock:
            if lease.lease_id in self._leases:
                raise ValueError("duplicate_lease_id")
            self._leases[lease.lease_id] = lease
            self._uses[lease.lease_id] = 0
            self._append_event(
                event="ISSUED",
                lease=lease,
                request_id=None,
                reason="human_review_lease_registered",
                actor=lease.issued_by,
                created_at=lease.issued_at,
            )

    def issue_for_review(
        self,
        *,
        request: ActionRequest,
        base_decision: GateDecision,
        issued_by: str,
        ttl_seconds: int = 300,
        lease_id: str | None = None,
        now: datetime | None = None,
    ) -> ReviewLease:
        if base_decision.verdict != "REVIEW":
            raise ValueError("lease_can_only_be_issued_for_review")
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ValueError("ttl_seconds_must_be_between_1_and_3600")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("now_must_be_timezone_aware")
        current = current.astimezone(timezone.utc)
        lease = ReviewLease(
            lease_id=lease_id or f"lease-{request.request_id}-{int(current.timestamp())}",
            request_digest=request_digest(request),
            capability=request.capability,
            action=request.action,
            resource=request.resource,
            review_grant_ids=tuple(base_decision.matched_grant_ids),
            issued_by=issued_by,
            issued_at=current.isoformat(),
            expires_at=(current + timedelta(seconds=ttl_seconds)).isoformat(),
        )
        self.register(lease)
        return lease

    def cancel(
        self,
        lease_id: str,
        *,
        cancelled_by: str,
        reason: str = "human_cancelled",
        now: datetime | None = None,
    ) -> ReviewEventReceipt:
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise KeyError("lease_not_found")
            if lease_id in self._cancelled:
                raise ValueError("lease_already_cancelled")
            self._cancelled[lease_id] = reason
            return self._append_event(
                event="CANCELLED",
                lease=lease,
                request_id=None,
                reason=reason,
                actor=cancelled_by,
                created_at=_now_iso(now),
            )

    def redeem(
        self,
        *,
        lease_id: str,
        request: ActionRequest,
        base_decision: GateDecision,
        now: datetime | None = None,
    ) -> ReviewAuthorization:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ValueError("now_must_be_timezone_aware")
        current = current.astimezone(timezone.utc)

        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                return ReviewAuthorization(False, "lease_not_found", lease_id)
            if base_decision.verdict != "REVIEW":
                return self._reject(lease, request, "base_gate_is_not_review", current)
            if lease_id in self._cancelled:
                return self._reject(lease, request, "lease_cancelled", current)
            if self._uses.get(lease_id, 0) >= lease.max_uses:
                return self._reject(lease, request, "lease_already_used", current)
            if current < _parse_time(lease.issued_at):
                return self._reject(lease, request, "lease_not_yet_valid", current)
            if current >= _parse_time(lease.expires_at):
                return self._reject(lease, request, "lease_expired", current)
            if request_digest(request) != lease.request_digest:
                return self._reject(lease, request, "request_digest_mismatch", current)
            if request.capability != lease.capability or request.action != lease.action or request.resource != lease.resource:
                return self._reject(lease, request, "lease_scope_mismatch", current)
            if tuple(base_decision.matched_grant_ids) != tuple(lease.review_grant_ids):
                return self._reject(lease, request, "review_policy_changed", current)

            # Consume before execution. Executor failure must not make the lease reusable.
            self._uses[lease_id] = self._uses.get(lease_id, 0) + 1
            self._append_event(
                event="REDEEMED",
                lease=lease,
                request_id=request.request_id,
                reason="one_shot_review_lease_redeemed",
                actor=lease.issued_by,
                created_at=current.isoformat(),
            )
            return ReviewAuthorization(True, "human_review_lease_redeemed", lease_id)

    def _reject(
        self,
        lease: ReviewLease,
        request: ActionRequest,
        reason: str,
        current: datetime,
    ) -> ReviewAuthorization:
        self._append_event(
            event="REJECTED",
            lease=lease,
            request_id=request.request_id,
            reason=reason,
            actor=request.actor,
            created_at=current.isoformat(),
        )
        return ReviewAuthorization(False, reason, lease.lease_id)

    def _append_event(
        self,
        *,
        event: str,
        lease: ReviewLease,
        request_id: str | None,
        reason: str,
        actor: str,
        created_at: str,
    ) -> ReviewEventReceipt:
        previous_hash = self._events[-1].event_hash if self._events else None
        body = {
            "event_version": "0.6",
            "event": event,
            "lease_id": lease.lease_id,
            "request_id": request_id,
            "request_digest": lease.request_digest,
            "reason": reason,
            "actor": actor,
            "created_at": created_at,
            "previous_event_hash": previous_hash,
        }
        event_hash = sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        receipt = ReviewEventReceipt(**body, event_hash=event_hash)
        self._events.append(receipt)
        return receipt
