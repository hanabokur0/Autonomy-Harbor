from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .models import CapabilityGrant, CapabilityRegistry
from .verifiable import (
    Ed25519Signer,
    SignedEnvelope,
    TrustStore,
    sha256_hex,
    sign_payload,
    verify_envelope,
)

VALID_PRSP_STATUSES = frozenset({"PASS", "REVIEW", "HOLD", "REJECT", "SKIP"})
PROMOTION_ORDER = {"PASS": 0, "REVIEW": 1, "HOLD": 2, "REJECT": 3}


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _grant_view(grant: CapabilityGrant) -> dict[str, Any]:
    return {
        "grant_id": grant.grant_id,
        "capability": grant.capability,
        "effect": grant.effect,
        "actions": list(grant.actions),
        "resources": list(grant.resources),
        "issued_by": grant.issued_by,
        "note": grant.note,
    }


def registry_digest(registry: CapabilityRegistry) -> str:
    return sha256_hex({
        "registry_id": registry.registry_id,
        "version": registry.version,
        "grants": [_grant_view(g) for g in sorted(registry.grants, key=lambda g: g.grant_id)],
    })


@dataclass(frozen=True, slots=True)
class CapabilityDelta:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]
    digest: str

    @property
    def has_authority_change(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    @property
    def has_possible_authority_expansion(self) -> bool:
        # Conservative by design: any addition or mutation needs promotion evidence.
        return bool(self.added or self.changed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": list(self.changed),
            "digest": self.digest,
            "has_authority_change": self.has_authority_change,
            "has_possible_authority_expansion": self.has_possible_authority_expansion,
        }


def diff_registries(baseline: CapabilityRegistry, proposed: CapabilityRegistry) -> CapabilityDelta:
    old = {g.grant_id: _grant_view(g) for g in baseline.grants}
    new = {g.grant_id: _grant_view(g) for g in proposed.grants}
    added = tuple(sorted(set(new) - set(old)))
    removed = tuple(sorted(set(old) - set(new)))
    changed = tuple(sorted(k for k in set(old) & set(new) if old[k] != new[k]))
    digest = sha256_hex({
        "baseline": registry_digest(baseline),
        "proposed": registry_digest(proposed),
        "added": list(added),
        "removed": list(removed),
        "changed": list(changed),
    })
    return CapabilityDelta(added=added, removed=removed, changed=changed, digest=digest)


@dataclass(frozen=True, slots=True)
class PromotionRequest:
    promotion_id: str
    app_id: str
    baseline_registry_digest: str
    proposed_registry_digest: str
    capability_delta: CapabilityDelta
    required_domains: tuple[str, ...]
    requested_by: str
    target_stage: str = "production-candidate"

    def __post_init__(self) -> None:
        if not self.promotion_id.strip():
            raise ValueError("promotion_id_is_required")
        if not self.app_id.strip():
            raise ValueError("app_id_is_required")
        if not self.required_domains:
            raise ValueError("required_domains_must_not_be_empty")
        object.__setattr__(self, "required_domains", tuple(sorted(set(self.required_domains))))

    @property
    def request_digest(self) -> str:
        return sha256_hex(self.as_dict(include_digest=False))

    def as_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        value = {
            "promotion_id": self.promotion_id,
            "app_id": self.app_id,
            "baseline_registry_digest": self.baseline_registry_digest,
            "proposed_registry_digest": self.proposed_registry_digest,
            "capability_delta": self.capability_delta.as_dict(),
            "required_domains": list(self.required_domains),
            "requested_by": self.requested_by,
            "target_stage": self.target_stage,
            "authority_effect": "NONE",
        }
        if include_digest:
            value["request_digest"] = sha256_hex(value)
        return value


def build_promotion_request(
    *,
    promotion_id: str,
    baseline: CapabilityRegistry,
    proposed: CapabilityRegistry,
    requested_by: str,
    app_id: str = "personal-agent-runtime",
    required_domains: Iterable[str] = ("authorization", "failure", "observability", "security"),
    target_stage: str = "production-candidate",
) -> PromotionRequest:
    return PromotionRequest(
        promotion_id=promotion_id,
        app_id=app_id,
        baseline_registry_digest=registry_digest(baseline),
        proposed_registry_digest=registry_digest(proposed),
        capability_delta=diff_registries(baseline, proposed),
        required_domains=tuple(required_domains),
        requested_by=requested_by,
        target_stage=target_stage,
    )


@dataclass(frozen=True, slots=True)
class PRSPScenarioResult:
    scenario_id: str
    domain: str
    status: str
    reason: str = ""
    severity: str = "unknown"
    evidence_required: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        status = self.status.upper()
        if status not in VALID_PRSP_STATUSES:
            raise ValueError(f"invalid_prsp_status:{self.status}")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "evidence_required", tuple(self.evidence_required))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PRSPScenarioResult":
        return cls(
            scenario_id=str(value["scenario_id"]),
            domain=str(value["domain"]),
            status=str(value["status"]),
            reason=str(value.get("reason", "")),
            severity=str(value.get("severity", "unknown")),
            evidence_required=tuple(str(v) for v in value.get("evidence_required", ())),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "domain": self.domain,
            "status": self.status,
            "reason": self.reason,
            "severity": self.severity,
            "evidence_required": list(self.evidence_required),
        }


@dataclass(frozen=True, slots=True)
class PRSPSimulationReceipt:
    receipt_version: str
    run_id: str
    app_id: str
    overall_gate: str
    results: tuple[PRSPScenarioResult, ...]
    generated_at: str = ""
    app_stage: str = "unknown"
    summary: Mapping[str, int] = MappingProxyType({})

    def __post_init__(self) -> None:
        gate = self.overall_gate.upper()
        if gate not in {"PASS", "REVIEW", "HOLD", "REJECT"}:
            raise ValueError("invalid_prsp_overall_gate")
        object.__setattr__(self, "overall_gate", gate)
        object.__setattr__(self, "results", tuple(self.results))
        object.__setattr__(self, "summary", MappingProxyType(dict(self.summary)))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PRSPSimulationReceipt":
        return cls(
            receipt_version=str(value["receipt_version"]),
            run_id=str(value["run_id"]),
            generated_at=str(value.get("generated_at", "")),
            app_id=str(value["app_id"]),
            app_stage=str(value.get("app_stage", "unknown")),
            overall_gate=str(value["overall_gate"]),
            summary={str(k): int(v) for k, v in dict(value.get("summary", {})).items()},
            results=tuple(PRSPScenarioResult.from_dict(v) for v in value["results"]),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "run_id": self.run_id,
            "generated_at": self.generated_at,
            "app_id": self.app_id,
            "app_stage": self.app_stage,
            "overall_gate": self.overall_gate,
            "summary": dict(self.summary),
            "results": [result.as_dict() for result in self.results],
        }


def recompute_prsp_gate(results: Iterable[PRSPScenarioResult]) -> str:
    active = tuple(r for r in results if r.status != "SKIP")
    if not active:
        return "HOLD"
    if any(r.status == "REJECT" for r in active):
        return "REJECT"
    if any(r.status == "HOLD" for r in active):
        return "HOLD"
    if any(r.status == "REVIEW" for r in active):
        return "REVIEW"
    return "PASS"


def prsp_promotion_evidence_payload(
    request: PromotionRequest,
    receipt: PRSPSimulationReceipt,
) -> dict[str, Any]:
    return {
        "promotion_request_digest": request.request_digest,
        "promotion_id": request.promotion_id,
        "app_id": request.app_id,
        "prsp_receipt": receipt.as_dict(),
        "authority_effect": "EVIDENCE_ONLY",
    }


def sign_prsp_promotion_evidence(
    *,
    request: PromotionRequest,
    receipt: PRSPSimulationReceipt,
    signer: Ed25519Signer,
    signed_at: str | None = None,
    previous_envelope_hash: str | None = None,
) -> SignedEnvelope:
    return sign_payload(
        payload_type="prsp_promotion_evidence",
        payload=prsp_promotion_evidence_payload(request, receipt),
        signer=signer,
        signed_at=signed_at,
        previous_envelope_hash=previous_envelope_hash,
    )


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    verdict: str
    reason: str
    promotion_id: str
    prsp_run_id: str | None
    missing_domains: tuple[str, ...] = ()
    observed_gate: str | None = None
    authority_effect: str = "NONE"

    @property
    def eligible(self) -> bool:
        return self.verdict == "PASS"

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "promotion_id": self.promotion_id,
            "prsp_run_id": self.prsp_run_id,
            "missing_domains": list(self.missing_domains),
            "observed_gate": self.observed_gate,
            "eligible": self.eligible,
            "authority_effect": self.authority_effect,
        }


class PRSPPromotionGate:
    """Fail-closed promotion gate. It never mutates a Capability Registry."""

    def __init__(
        self,
        *,
        trust_store: TrustStore,
        required_signer_role: str = "promotion_evidence_issuer",
    ) -> None:
        self._trust_store = trust_store
        self._required_signer_role = required_signer_role

    def evaluate(
        self,
        *,
        request: PromotionRequest,
        signed_evidence: SignedEnvelope,
    ) -> PromotionDecision:
        verification = verify_envelope(
            signed_evidence,
            self._trust_store,
            required_role=self._required_signer_role,
            expected_payload_type="prsp_promotion_evidence",
        )
        if not verification.ok:
            return PromotionDecision(
                verdict="REJECT",
                reason=f"invalid_signed_promotion_evidence:{verification.reason}",
                promotion_id=request.promotion_id,
                prsp_run_id=None,
            )

        payload = dict(signed_evidence.payload)
        if payload.get("authority_effect") != "EVIDENCE_ONLY":
            return PromotionDecision(
                verdict="REJECT",
                reason="promotion_evidence_attempted_authority_effect",
                promotion_id=request.promotion_id,
                prsp_run_id=None,
            )
        if payload.get("promotion_request_digest") != request.request_digest:
            return PromotionDecision(
                verdict="REJECT",
                reason="promotion_request_digest_mismatch",
                promotion_id=request.promotion_id,
                prsp_run_id=None,
            )
        if payload.get("promotion_id") != request.promotion_id:
            return PromotionDecision(
                verdict="REJECT",
                reason="promotion_id_mismatch",
                promotion_id=request.promotion_id,
                prsp_run_id=None,
            )
        if payload.get("app_id") != request.app_id:
            return PromotionDecision(
                verdict="REJECT",
                reason="promotion_app_id_mismatch",
                promotion_id=request.promotion_id,
                prsp_run_id=None,
            )

        try:
            receipt = PRSPSimulationReceipt.from_dict(payload["prsp_receipt"])
        except (KeyError, TypeError, ValueError) as exc:
            return PromotionDecision(
                verdict="REJECT",
                reason=f"invalid_prsp_receipt:{type(exc).__name__}",
                promotion_id=request.promotion_id,
                prsp_run_id=None,
            )

        if receipt.app_id != request.app_id:
            return PromotionDecision(
                verdict="REJECT",
                reason="prsp_receipt_app_id_mismatch",
                promotion_id=request.promotion_id,
                prsp_run_id=receipt.run_id,
            )

        computed = recompute_prsp_gate(receipt.results)
        if computed != receipt.overall_gate:
            return PromotionDecision(
                verdict="REJECT",
                reason=f"prsp_gate_inconsistent:declared={receipt.overall_gate}:computed={computed}",
                promotion_id=request.promotion_id,
                prsp_run_id=receipt.run_id,
                observed_gate=computed,
            )

        covered = {r.domain for r in receipt.results if r.status != "SKIP"}
        missing = tuple(sorted(set(request.required_domains) - covered))
        if missing:
            return PromotionDecision(
                verdict="HOLD",
                reason="required_prsp_domains_missing",
                promotion_id=request.promotion_id,
                prsp_run_id=receipt.run_id,
                missing_domains=missing,
                observed_gate=computed,
            )

        if computed != "PASS":
            return PromotionDecision(
                verdict=computed,
                reason=f"prsp_overall_gate_{computed.lower()}",
                promotion_id=request.promotion_id,
                prsp_run_id=receipt.run_id,
                observed_gate=computed,
            )

        return PromotionDecision(
            verdict="PASS",
            reason="promotion_evidence_satisfies_prsp_gate",
            promotion_id=request.promotion_id,
            prsp_run_id=receipt.run_id,
            observed_gate=computed,
        )
