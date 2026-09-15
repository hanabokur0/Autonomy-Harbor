from __future__ import annotations

import json
from pathlib import Path

from personal_agent_runtime.mcp_server import FinalizedReceiptLog, HarborMCPBridge


class FakeClient:
    def __init__(self, socket_path: str, script: dict[str, list[dict]]) -> None:
        self.socket_path = socket_path
        self.script = script
        self.calls: list[dict] = []

    def call(self, message: dict) -> dict:
        self.calls.append(message)
        queue = self.script[self.socket_path]
        if not queue:
            raise AssertionError(f"unexpected call:{self.socket_path}:{message}")
        return queue.pop(0)


def _fixture(tmp_path: Path):
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps({
        "registry_id": "test",
        "version": "1",
        "grants": [
            {
                "grant_id": "read",
                "capability": "filesystem.read",
                "effect": "ALLOW",
                "actions": ["read_text"],
                "resources": ["approved/*"],
                "issued_by": "human",
                "note": "",
            },
            {
                "grant_id": "write",
                "capability": "filesystem.write",
                "effect": "REVIEW",
                "actions": ["write_text"],
                "resources": ["approved/*"],
                "issued_by": "human",
                "note": "",
            },
        ],
    }), encoding="utf-8")
    profile = {
        "services": {
            "planner": {"socket": "planner.sock"},
            "gate": {"socket": "gate.sock", "registry": str(registry_path)},
            "executor": {"socket": "executor.sock"},
            "verifier": {"socket": "verifier.sock"},
            "review_signer": {"socket": "review.sock", "private_key": "SHOULD_NOT_BE_USED"},
        }
    }
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return profile_path


def test_mcp_actor_is_operator_controlled_and_allow_uses_full_harbor_path(tmp_path: Path):
    profile_path = _fixture(tmp_path)
    request = {
        "request_id": "r1",
        "capability": "filesystem.read",
        "action": "read_text",
        "resource": "approved/a.txt",
        "payload": {},
        "actor": "mcp:claude",
    }
    receipt = {
        "request_id": "r1",
        "outcome": "SUCCEEDED",
        "result": {"adapter_id": "sandbox", "output": {"text": "ok"}},
        "receipt_hash": "a" * 64,
    }
    script = {
        "planner.sock": [{"request": request}],
        "gate.sock": [{
            "base_decision": {"verdict": "ALLOW", "reason": "explicit", "matched_grant_ids": ["read"]},
            "decision": {"verdict": "ALLOW", "reason": "explicit", "matched_grant_ids": ["read"]},
            "execution_permit": {"payload_type": "execution_permit"},
        }],
        "executor.sock": [{"executed": True, "outcome": "SUCCEEDED", "signed_execution_result": {"payload_type": "execution_result"}}],
        "verifier.sock": [{"verified": True, "receipt": receipt, "signed_receipt": {"payload_type": "action_receipt"}}],
    }
    clients = {}
    def factory(socket_path: str):
        client = FakeClient(socket_path, script)
        clients[socket_path] = client
        return client

    log = FinalizedReceiptLog(tmp_path / "receipts.jsonl")
    bridge = HarborMCPBridge(profile_path=profile_path, actor="mcp:claude", receipt_log=log, client_factory=factory)
    result = bridge.submit_action_request(
        request_id="r1", capability="filesystem.read", action="read_text", resource="approved/a.txt"
    )
    assert result["status"] == "VERIFIED"
    planner_intent = clients["planner.sock"].calls[0]["intent"]
    assert planner_intent["actor"] == "mcp:claude"
    assert result["receipt"]["receipt_hash"] == "a" * 64
    assert log.find("r1")["outcome"] == "SUCCEEDED"


def test_review_stops_before_executor_without_signed_human_lease(tmp_path: Path):
    profile_path = _fixture(tmp_path)
    request = {
        "request_id": "r2", "capability": "filesystem.write", "action": "write_text",
        "resource": "approved/a.txt", "payload": {"text": "x"}, "actor": "mcp-agent",
    }
    script = {
        "planner.sock": [{"request": request}],
        "gate.sock": [{
            "base_decision": {"verdict": "REVIEW", "reason": "human_review_required", "matched_grant_ids": ["write"]},
            "decision": {"verdict": "REVIEW", "reason": "human_review_required", "matched_grant_ids": ["write"]},
        }],
        "executor.sock": [],
        "verifier.sock": [],
    }
    made = []
    def factory(socket_path: str):
        made.append(socket_path)
        return FakeClient(socket_path, script)

    bridge = HarborMCPBridge(profile_path=profile_path, client_factory=factory)
    result = bridge.submit_action_request(
        request_id="r2", capability="filesystem.write", action="write_text",
        resource="approved/a.txt", payload={"text": "x"}
    )
    assert result["status"] == "NOT_EXECUTED"
    assert result["gate"]["verdict"] == "REVIEW"
    assert "executor.sock" not in made
    assert "review.sock" not in made


def test_signed_review_lease_is_forwarded_to_gate_but_not_issued_by_mcp(tmp_path: Path):
    profile_path = _fixture(tmp_path)
    request = {
        "request_id": "r3", "capability": "filesystem.write", "action": "write_text",
        "resource": "approved/a.txt", "payload": {"text": "x"}, "actor": "mcp-agent",
    }
    lease = {"payload_type": "review_lease", "signature": "external-human-signature"}
    script = {
        "planner.sock": [{"request": request}],
        "gate.sock": [{
            "base_decision": {"verdict": "REVIEW", "reason": "human_review_required", "matched_grant_ids": ["write"]},
            "decision": {"verdict": "REVIEW", "reason": "signed_review_lease_rejected:test", "matched_grant_ids": ["write"]},
        }],
        "executor.sock": [],
        "verifier.sock": [],
    }
    clients = {}
    def factory(socket_path: str):
        client = FakeClient(socket_path, script)
        clients[socket_path] = client
        return client

    bridge = HarborMCPBridge(profile_path=profile_path, client_factory=factory)
    bridge.submit_action_request(
        request_id="r3", capability="filesystem.write", action="write_text",
        resource="approved/a.txt", payload={"text": "x"}, signed_review_lease=lease,
    )
    assert clients["gate.sock"].calls[0]["signed_review_lease"] == lease
    assert "review.sock" not in clients


def test_check_capability_is_local_dry_run(tmp_path: Path):
    profile_path = _fixture(tmp_path)
    calls = []
    def factory(socket_path: str):
        calls.append(socket_path)
        raise AssertionError("dry run must not connect to appliance services")

    bridge = HarborMCPBridge(profile_path=profile_path, client_factory=factory)
    decision = bridge.check_capability("filesystem.read", "read_text", "approved/a.txt")
    assert decision["verdict"] == "ALLOW"
    assert calls == []
