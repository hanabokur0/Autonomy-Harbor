from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol

from .executor import SandboxedExecutor
from .gate import CapabilityGate
from .models import ActionReceipt, ActionRequest, CapabilityRegistry, GateDecision
from .receipt import create_receipt
from .review_broker import ReviewBroker
from .verifiable import (
    Ed25519Signer,
    SignedEnvelope,
    SignedReviewAuthorizer,
    TrustStore,
    sign_action_receipt,
    verify_capability_registry_attestation,
)


class ActionExecutor(Protocol):
    def execute(self, request: ActionRequest): ...


class PersonalAgentRuntime:
    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        sandbox_root: Path,
        previous_receipt_hash: str | None = None,
        review_broker: ReviewBroker | None = None,
        signed_review_authorizer: SignedReviewAuthorizer | None = None,
        executor: ActionExecutor | None = None,
        trust_store: TrustStore | None = None,
        registry_attestation: SignedEnvelope | None = None,
        require_signed_registry: bool = False,
        receipt_signer: Ed25519Signer | None = None,
        previous_signed_receipt_hash: str | None = None,
    ) -> None:
        self._registry = registry
        self._gate = CapabilityGate()
        self._executor = executor or SandboxedExecutor(sandbox_root)
        self._review_broker = review_broker
        self._signed_review_authorizer = signed_review_authorizer
        self._previous_receipt_hash = previous_receipt_hash
        self._receipt_signer = receipt_signer
        self._previous_signed_receipt_hash = previous_signed_receipt_hash

        if require_signed_registry:
            if trust_store is None or registry_attestation is None:
                raise ValueError("signed_registry_attestation_required")
            result = verify_capability_registry_attestation(registry, registry_attestation, trust_store)
            if not result.ok:
                raise ValueError(f"invalid_registry_attestation:{result.reason}")
        elif registry_attestation is not None:
            if trust_store is None:
                raise ValueError("trust_store_required_for_registry_attestation")
            result = verify_capability_registry_attestation(registry, registry_attestation, trust_store)
            if not result.ok:
                raise ValueError(f"invalid_registry_attestation:{result.reason}")

    @property
    def registry(self) -> CapabilityRegistry:
        return self._registry

    def run(
        self,
        request: ActionRequest,
        *,
        review_lease_id: str | None = None,
        signed_review_lease: SignedEnvelope | None = None,
        now: datetime | None = None,
    ) -> ActionReceipt:
        if review_lease_id is not None and signed_review_lease is not None:
            raise ValueError("choose_legacy_or_signed_review_lease_not_both")

        base_decision = self._gate.evaluate(request, self._registry)
        decision = base_decision

        if base_decision.verdict == "REVIEW" and signed_review_lease is not None:
            if self._signed_review_authorizer is None:
                decision = GateDecision(
                    verdict="REVIEW",
                    reason="signed_review_authorizer_unavailable",
                    matched_grant_ids=base_decision.matched_grant_ids,
                )
            else:
                authorization = self._signed_review_authorizer.redeem(
                    envelope=signed_review_lease,
                    request=request,
                    base_decision=base_decision,
                    now=now,
                )
                if authorization.authorized:
                    decision = GateDecision(
                        verdict="ALLOW",
                        reason="signed_human_review_lease_redeemed",
                        matched_grant_ids=(
                            *base_decision.matched_grant_ids,
                            f"signed-review-lease:{authorization.lease_id}",
                        ),
                    )
                else:
                    decision = GateDecision(
                        verdict="REVIEW",
                        reason=f"signed_review_lease_rejected:{authorization.reason}",
                        matched_grant_ids=base_decision.matched_grant_ids,
                    )

        elif base_decision.verdict == "REVIEW" and review_lease_id is not None:
            if self._review_broker is None:
                decision = GateDecision(
                    verdict="REVIEW",
                    reason="review_broker_unavailable",
                    matched_grant_ids=base_decision.matched_grant_ids,
                )
            else:
                authorization = self._review_broker.redeem(
                    lease_id=review_lease_id,
                    request=request,
                    base_decision=base_decision,
                    now=now,
                )
                if authorization.authorized:
                    decision = GateDecision(
                        verdict="ALLOW",
                        reason="human_review_lease_redeemed",
                        matched_grant_ids=(
                            *base_decision.matched_grant_ids,
                            f"review-lease:{authorization.lease_id}",
                        ),
                    )
                else:
                    decision = GateDecision(
                        verdict="REVIEW",
                        reason=f"review_lease_rejected:{authorization.reason}",
                        matched_grant_ids=base_decision.matched_grant_ids,
                    )

        if decision.verdict != "ALLOW":
            receipt = create_receipt(
                request=request,
                decision=decision,
                registry=self._registry,
                outcome="NOT_EXECUTED",
                result={},
                previous_receipt_hash=self._previous_receipt_hash,
            )
            self._previous_receipt_hash = receipt.receipt_hash
            return receipt

        try:
            result = self._executor.execute(request)
            outcome = "SUCCEEDED"
        except Exception as exc:  # receipt must survive executor failure
            result = {"error": type(exc).__name__, "reason": str(exc)}
            outcome = "FAILED"

        receipt = create_receipt(
            request=request,
            decision=decision,
            registry=self._registry,
            outcome=outcome,
            result=result,
            previous_receipt_hash=self._previous_receipt_hash,
        )
        self._previous_receipt_hash = receipt.receipt_hash
        return receipt

    def run_signed(
        self,
        request: ActionRequest,
        *,
        review_lease_id: str | None = None,
        signed_review_lease: SignedEnvelope | None = None,
        now: datetime | None = None,
    ) -> tuple[ActionReceipt, SignedEnvelope]:
        if self._receipt_signer is None:
            raise ValueError("receipt_signer_not_configured")
        receipt = self.run(
            request,
            review_lease_id=review_lease_id,
            signed_review_lease=signed_review_lease,
            now=now,
        )
        signed_at = None
        if now is not None:
            if now.tzinfo is None:
                raise ValueError("now_must_be_timezone_aware")
            signed_at = now.isoformat()
        envelope = sign_action_receipt(
            receipt,
            self._receipt_signer,
            signed_at=signed_at,
            previous_envelope_hash=self._previous_signed_receipt_hash,
        )
        self._previous_signed_receipt_hash = envelope.envelope_hash
        return receipt, envelope
