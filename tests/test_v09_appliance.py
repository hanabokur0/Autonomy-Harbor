from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

import pytest

from personal_agent_runtime.appliance import (
    ExecutionPermitLedger,
    action_request_dict,
    initialize_appliance,
    issue_execution_permit,
    sign_execution_result,
    trust_store_from_list,
    verify_and_consume_execution_permit,
    verify_execution_result,
)
from personal_agent_runtime.appliance_demo import run_appliance_demo
from personal_agent_runtime.models import ActionRequest, CapabilityGrant, CapabilityRegistry, GateDecision
from personal_agent_runtime.verifiable import Ed25519Signer, SignedEnvelope


def _request() -> ActionRequest:
    return ActionRequest(
        request_id="v09-001",
        capability="filesystem.write",
        action="write_text",
        resource="approved/test.txt",
        payload={"text": "hello"},
        actor="planner",
    )


def _registry() -> CapabilityRegistry:
    return CapabilityRegistry(
        registry_id="v09-test",
        version="0.9",
        grants=(
            CapabilityGrant(
                grant_id="write",
                capability="filesystem.write",
                effect="ALLOW",
                actions=("write_text",),
                resources=("approved/*",),
            ),
        ),
    )


def test_appliance_profile_separates_keys_and_planner_has_none(tmp_path: Path):
    profile_path = initialize_appliance(tmp_path / "appliance")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    services = profile["services"]
    assert profile["appliance_version"] == "0.9"
    assert services["planner"]["private_keys"] == []
    private_keys = {
        services[role]["private_key"]
        for role in ("review_signer", "gate", "executor", "verifier")
    }
    assert len(private_keys) == 4
    for key in private_keys:
        mode = os.stat(key).st_mode & 0o777
        assert mode == 0o600
    assert services["review_signer"]["private_key"] not in json.dumps(services["executor"])
    assert services["gate"]["private_key"] not in json.dumps(services["review_signer"])


def test_execution_permit_requires_allow():
    signer = Ed25519Signer.generate(subject="gate")
    with pytest.raises(ValueError, match="execution_permit_requires_allow"):
        issue_execution_permit(
            request=_request(),
            decision=GateDecision("REVIEW", "human_review_required", ("review",)),
            registry=_registry(),
            signer=signer,
        )


def test_execution_permit_is_request_bound_and_one_shot_across_restart(tmp_path: Path):
    gate_signer = Ed25519Signer.generate(subject="gate")
    trust = trust_store_from_list([{
        "key_id": gate_signer.key_id,
        "subject": gate_signer.subject,
        "public_key_b64": gate_signer.public_key_b64,
        "roles": ["execution_permit_issuer"],
        "status": "ACTIVE",
    }])
    request = _request()
    now = datetime.now(timezone.utc)
    permit = issue_execution_permit(
        request=request,
        decision=GateDecision("ALLOW", "explicit_capability_grant", ("write",)),
        registry=_registry(),
        signer=gate_signer,
        now=now,
        permit_id="permit-persistent",
    )
    db = tmp_path / "permit.sqlite3"
    ledger = ExecutionPermitLedger(db)
    first = verify_and_consume_execution_permit(
        envelope=permit, request=request, trust_store=trust, ledger=ledger, now=now
    )
    ledger.close()
    assert first.authorized is True

    ledger2 = ExecutionPermitLedger(db)
    replay = verify_and_consume_execution_permit(
        envelope=permit, request=request, trust_store=trust, ledger=ledger2, now=now
    )
    ledger2.close()
    assert replay.authorized is False
    assert replay.reason == "permit_already_used"

    modified = ActionRequest(**{**action_request_dict(request), "payload": {"text": "changed"}})
    ledger3 = ExecutionPermitLedger(tmp_path / "fresh.sqlite3")
    mismatch = verify_and_consume_execution_permit(
        envelope=permit, request=modified, trust_store=trust, ledger=ledger3, now=now
    )
    ledger3.close()
    assert mismatch.authorized is False
    assert mismatch.reason == "permit_request_digest_mismatch"


def test_execution_result_is_bound_to_permit_and_request(tmp_path: Path):
    gate = Ed25519Signer.generate(subject="gate")
    executor = Ed25519Signer.generate(subject="executor")
    trust = trust_store_from_list([
        {"key_id": gate.key_id, "subject": gate.subject, "public_key_b64": gate.public_key_b64,
         "roles": ["execution_permit_issuer"], "status": "ACTIVE"},
        {"key_id": executor.key_id, "subject": executor.subject, "public_key_b64": executor.public_key_b64,
         "roles": ["executor_result_signer"], "status": "ACTIVE"},
    ])
    request = _request()
    permit = issue_execution_permit(
        request=request,
        decision=GateDecision("ALLOW", "ok", ("write",)),
        registry=_registry(), signer=gate,
    )
    result = sign_execution_result(
        request=request, permit=permit, outcome="SUCCEEDED", result={"bytes_written": 5}, signer=executor
    )
    ok, reason = verify_execution_result(envelope=result, permit=permit, request=request, trust_store=trust)
    assert (ok, reason) == (True, "verified")

    tampered = result.as_dict()
    tampered["payload"]["result"] = {"bytes_written": 999}
    bad = SignedEnvelope.from_dict(tampered)
    ok, reason = verify_execution_result(envelope=bad, permit=permit, request=request, trust_store=trust)
    assert ok is False
    assert reason.startswith("execution_result_")


def test_expired_execution_permit_is_rejected(tmp_path: Path):
    signer = Ed25519Signer.generate(subject="gate")
    trust = trust_store_from_list([{
        "key_id": signer.key_id, "subject": signer.subject, "public_key_b64": signer.public_key_b64,
        "roles": ["execution_permit_issuer"], "status": "ACTIVE",
    }])
    now = datetime.now(timezone.utc)
    permit = issue_execution_permit(
        request=_request(),
        decision=GateDecision("ALLOW", "ok", ("write",)),
        registry=_registry(), signer=signer, ttl_seconds=1, now=now,
    )
    ledger = ExecutionPermitLedger(tmp_path / "expire.sqlite3")
    checked = verify_and_consume_execution_permit(
        envelope=permit, request=_request(), trust_store=trust, ledger=ledger,
        now=now + timedelta(seconds=2),
    )
    ledger.close()
    assert checked.authorized is False
    assert checked.reason == "permit_expired"


def test_appliance_demo_uses_distinct_processes_and_enforces_boundaries(tmp_path: Path):
    result = run_appliance_demo(tmp_path / "demo")
    assert result["process_isolation_confirmed"] is True
    assert len(set(result["service_pids"].values())) == 5
    assert result["first_gate"]["verdict"] == "REVIEW"
    assert result["second_gate"]["verdict"] == "ALLOW"
    assert result["raw_executor_call"]["ok"] is False
    assert result["raw_executor_call"]["reason"] == "signed_execution_permit_required"
    assert result["execution"]["executed"] is True
    assert result["execution"]["outcome"] == "SUCCEEDED"
    assert result["permit_replay"]["executed"] is False
    assert result["permit_replay"]["reason"] == "permit_already_used"
    assert result["verification"]["verified"] is True
    assert Path(result["written_file"]).read_text(encoding="utf-8").startswith("Personal Agent Runtime v0.9")

def test_v09_schemas_and_manifest_invariants_exist():
    root = Path(__file__).resolve().parents[1]
    for name in ("appliance_profile.schema.json", "execution_permit.schema.json", "execution_result.schema.json"):
        value = json.loads((root / "schemas" / name).read_text(encoding="utf-8"))
        assert value["type"] == "object"
    manifest = (root / "component_manifest.yaml").read_text(encoding="utf-8")
    assert 'manifest_version: "0.9"' in manifest
    assert "id: appliance-profile" in manifest
    assert "planner_has_no_private_signing_key" in manifest
    assert "executor_requires_signed_gate_permit" in manifest
    assert "permit_replay_survives_executor_restart" in manifest
