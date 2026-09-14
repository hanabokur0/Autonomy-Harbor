from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from .gate import CapabilityGate
from .models import ActionRequest, CapabilityGrant, CapabilityRegistry
from .repo_maintainer import RepoMaintainer, load_repo_snapshot
from .promotion import (
    PRSPPromotionGate,
    PRSPScenarioResult,
    PRSPSimulationReceipt,
    build_promotion_request,
    sign_prsp_promotion_evidence,
)
from .review_broker import ReviewBroker
from .appliance import initialize_appliance
from .appliance_demo import run_appliance_demo
from .appliance_services import run_service
from .runtime import PersonalAgentRuntime
from .verifiable import (
    Ed25519Signer,
    SignedReviewAuthorizer,
    TrustStore,
    attest_capability_registry,
    issue_signed_review_lease,
    verify_capability_registry_attestation,
    verify_envelope,
    verify_envelope_chain,
)


def _demo() -> int:
    registry = CapabilityRegistry(
        registry_id="demo",
        version="1",
        grants=(
            CapabilityGrant(
                grant_id="echo-allow",
                capability="tool.echo",
                effect="ALLOW",
                actions=("echo",),
                resources=("console",),
            ),
        ),
    )
    runtime = PersonalAgentRuntime(registry=registry, sandbox_root=Path(".par-sandbox"))
    receipt = runtime.run(
        ActionRequest(
            request_id="demo-001",
            capability="tool.echo",
            action="echo",
            resource="console",
            payload={"text": "Personal Agent Runtime is alive."},
        )
    )
    print(json.dumps(_receipt_dict(receipt), ensure_ascii=False, indent=2))
    return 0


def _maintain(snapshot: Path, limit: int) -> int:
    snapshot_id, observations = load_repo_snapshot(snapshot)
    receipt = RepoMaintainer().build_receipt(observations, snapshot_id=snapshot_id, limit=limit)
    print(json.dumps(receipt.as_dict(), ensure_ascii=False, indent=2))
    return 0


def _review_demo() -> int:
    registry = CapabilityRegistry(
        registry_id="review-demo",
        version="0.6",
        grants=(
            CapabilityGrant(
                grant_id="review-write",
                capability="filesystem.write",
                effect="REVIEW",
                actions=("write_text",),
                resources=("approved/*.txt",),
            ),
        ),
    )
    request = ActionRequest(
        request_id="review-demo-001",
        capability="filesystem.write",
        action="write_text",
        resource="approved/note.txt",
        payload={"text": "one-shot human approved write"},
        actor="demo-agent",
    )
    broker = ReviewBroker()
    gate = CapabilityGate()
    base = gate.evaluate(request, registry)
    now = datetime.now(timezone.utc)
    lease = broker.issue_for_review(
        request=request,
        base_decision=base,
        issued_by="human:cli-demo",
        ttl_seconds=300,
        lease_id="review-demo-lease",
        now=now,
    )
    runtime = PersonalAgentRuntime(
        registry=registry,
        sandbox_root=Path(".par-sandbox"),
        review_broker=broker,
    )
    approved = runtime.run(request, review_lease_id=lease.lease_id, now=now)
    replay = runtime.run(request, review_lease_id=lease.lease_id, now=now)
    print(json.dumps({
        "lease": {
            "lease_id": lease.lease_id,
            "request_digest": lease.request_digest,
            "expires_at": lease.expires_at,
            "max_uses": lease.max_uses,
        },
        "approved_attempt": _receipt_dict(approved),
        "replay_attempt": _receipt_dict(replay),
        "review_events": [event.as_dict() for event in broker.events],
    }, ensure_ascii=False, indent=2))
    return 0



def _signed_review_demo() -> int:
    review_signer = Ed25519Signer.generate(subject="human:cli-demo")
    capability_signer = Ed25519Signer.generate(subject="control-plane:cli-demo")
    receipt_signer = Ed25519Signer.generate(subject="runtime:cli-demo")
    trust = TrustStore((
        review_signer.trusted_record("review_issuer"),
        capability_signer.trusted_record("capability_authority"),
        receipt_signer.trusted_record("runtime_receipt_signer"),
    ))
    registry = CapabilityRegistry(
        registry_id="signed-review-demo",
        version="0.7",
        grants=(
            CapabilityGrant(
                grant_id="review-write",
                capability="filesystem.write",
                effect="REVIEW",
                actions=("write_text",),
                resources=("signed-approved/*.txt",),
            ),
        ),
    )
    request = ActionRequest(
        request_id="signed-review-demo-001",
        capability="filesystem.write",
        action="write_text",
        resource="signed-approved/note.txt",
        payload={"text": "cryptographically scoped one-shot approval"},
        actor="demo-agent",
    )
    gate = CapabilityGate()
    base = gate.evaluate(request, registry)
    now = datetime.now(timezone.utc)
    registry_attestation = attest_capability_registry(
        registry, capability_signer, signed_at=now.isoformat()
    )
    signed_lease = issue_signed_review_lease(
        request=request,
        base_decision=base,
        signer=review_signer,
        lease_id="signed-review-demo-lease",
        ttl_seconds=300,
        now=now,
    )
    runtime = PersonalAgentRuntime(
        registry=registry,
        sandbox_root=Path(".par-sandbox"),
        signed_review_authorizer=SignedReviewAuthorizer(trust_store=trust),
        trust_store=trust,
        registry_attestation=registry_attestation,
        require_signed_registry=True,
        receipt_signer=receipt_signer,
    )
    approved_receipt, approved_envelope = runtime.run_signed(
        request, signed_review_lease=signed_lease, now=now
    )
    replay_receipt, replay_envelope = runtime.run_signed(
        request, signed_review_lease=signed_lease, now=now
    )
    attestation_check = verify_capability_registry_attestation(registry, registry_attestation, trust)
    lease_check = verify_envelope(
        signed_lease, trust, required_role="review_issuer", expected_payload_type="review_lease"
    )
    chain_check = verify_envelope_chain(
        (approved_envelope, replay_envelope),
        trust,
        required_role="runtime_receipt_signer",
        expected_payload_type="action_receipt",
    )
    print(json.dumps({
        "registry_attestation_verified": attestation_check.ok,
        "signed_review_lease_verified": lease_check.ok,
        "approved_attempt": _receipt_dict(approved_receipt),
        "approved_signed_receipt": approved_envelope.as_dict(),
        "replay_attempt": _receipt_dict(replay_receipt),
        "replay_signed_receipt": replay_envelope.as_dict(),
        "signed_receipt_chain": {
            "ok": chain_check.ok,
            "verified_count": chain_check.verified_count,
            "reason": chain_check.reason,
        },
        "trust_store": [
            {
                "key_id": signer.key_id,
                "subject": signer.subject,
                "roles": list(signer.roles),
                "status": signer.status,
            }
            for signer in trust.signers
        ],
    }, ensure_ascii=False, indent=2))
    return 0


def _promotion_demo() -> int:
    evidence_signer = Ed25519Signer.generate(subject="prsp:cli-demo")
    trust = TrustStore((evidence_signer.trusted_record("promotion_evidence_issuer"),))
    baseline = CapabilityRegistry(
        registry_id="promotion-demo",
        version="0.7",
        grants=(
            CapabilityGrant(
                grant_id="github-read",
                capability="github.repo.read",
                effect="ALLOW",
                actions=("read",),
                resources=("hanabokur0/*",),
            ),
        ),
    )
    proposed = CapabilityRegistry(
        registry_id="promotion-demo",
        version="0.8-candidate",
        grants=(
            *baseline.grants,
            CapabilityGrant(
                grant_id="github-issue-review",
                capability="github.issue.create",
                effect="REVIEW",
                actions=("create_issue",),
                resources=("hanabokur0/*",),
            ),
        ),
    )
    request = build_promotion_request(
        promotion_id="promotion-demo-001",
        baseline=baseline,
        proposed=proposed,
        requested_by="maintainer-agent",
    )
    pass_results = tuple(
        PRSPScenarioResult(
            scenario_id=f"DEMO-{i:03d}",
            domain=domain,
            status="PASS",
            reason="Reference evidence declared and checked for demo.",
        )
        for i, domain in enumerate(request.required_domains, start=1)
    )
    pass_receipt = PRSPSimulationReceipt(
        receipt_version="0.1",
        run_id="sim-promotion-demo-pass",
        app_id=request.app_id,
        app_stage="poc",
        overall_gate="PASS",
        results=pass_results,
    )
    signed_pass = sign_prsp_promotion_evidence(
        request=request,
        receipt=pass_receipt,
        signer=evidence_signer,
        signed_at=datetime.now(timezone.utc).isoformat(),
    )
    gate = PRSPPromotionGate(trust_store=trust)
    passed = gate.evaluate(request=request, signed_evidence=signed_pass)

    hold_receipt = PRSPSimulationReceipt(
        receipt_version="0.1",
        run_id="sim-promotion-demo-hold",
        app_id=request.app_id,
        app_stage="poc",
        overall_gate="HOLD",
        results=(
            PRSPScenarioResult(
                scenario_id="AUTHZ-DEMO", domain="authorization", status="HOLD",
                reason="Scope rollback evidence missing."
            ),
            *tuple(r for r in pass_results if r.domain != "authorization"),
        ),
    )
    signed_hold = sign_prsp_promotion_evidence(
        request=request,
        receipt=hold_receipt,
        signer=evidence_signer,
        signed_at=datetime.now(timezone.utc).isoformat(),
    )
    held = gate.evaluate(request=request, signed_evidence=signed_hold)
    print(json.dumps({
        "promotion_request": request.as_dict(),
        "pass_case": passed.as_dict(),
        "hold_case": held.as_dict(),
        "important": "PASS is promotion eligibility only; the proposed registry is not activated or signed by this gate.",
    }, ensure_ascii=False, indent=2))
    return 0



def _appliance_init(root: Path) -> int:
    profile = initialize_appliance(root)
    print(json.dumps({"appliance_version": "0.9", "profile": str(profile)}, ensure_ascii=False, indent=2))
    return 0


def _appliance_demo(root: Path) -> int:
    result = run_appliance_demo(root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _appliance_service(role: str, profile: Path) -> int:
    run_service(role=role, profile_path=profile)
    return 0

def _receipt_dict(receipt) -> dict:
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
        "result": dict(receipt.result),
        "registry_id": receipt.registry_id,
        "registry_version": receipt.registry_version,
        "created_at": receipt.created_at,
        "previous_receipt_hash": receipt.previous_receipt_hash,
        "receipt_hash": receipt.receipt_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="par-runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo")
    sub.add_parser("review-demo")
    sub.add_parser("signed-review-demo")
    sub.add_parser("promotion-demo")
    appliance_init = sub.add_parser("appliance-init")
    appliance_init.add_argument("root", type=Path)
    appliance_demo = sub.add_parser("appliance-demo")
    appliance_demo.add_argument("root", type=Path, nargs="?", default=Path(".par-appliance"))
    appliance_service = sub.add_parser("appliance-service")
    appliance_service.add_argument("--role", required=True, choices=("planner", "review_signer", "gate", "executor", "verifier"))
    appliance_service.add_argument("--profile", required=True, type=Path)
    maintain = sub.add_parser("maintain")
    maintain.add_argument("snapshot", type=Path)
    maintain.add_argument("--limit", type=int, default=3)

    args = parser.parse_args()
    if args.command == "demo":
        return _demo()
    if args.command == "review-demo":
        return _review_demo()
    if args.command == "signed-review-demo":
        return _signed_review_demo()
    if args.command == "promotion-demo":
        return _promotion_demo()
    if args.command == "appliance-init":
        return _appliance_init(args.root)
    if args.command == "appliance-demo":
        return _appliance_demo(args.root)
    if args.command == "appliance-service":
        return _appliance_service(args.role, args.profile)
    if args.command == "maintain":
        return _maintain(args.snapshot, args.limit)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
