from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from personal_agent_runtime import (
    ActionRequest,
    CapabilityGrant,
    CapabilityRegistry,
    PersonalAgentRuntime,
)


class RuntimeTests(unittest.TestCase):
    def make_runtime(self, *grants: CapabilityGrant):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        registry = CapabilityRegistry(
            registry_id="test",
            version="1",
            grants=tuple(grants),
        )
        return PersonalAgentRuntime(
            registry=registry,
            sandbox_root=Path(temp.name),
        )

    def test_default_deny(self):
        runtime = self.make_runtime()
        receipt = runtime.run(ActionRequest(
            request_id="1",
            capability="tool.echo",
            action="echo",
            resource="console",
            payload={"text": "no"},
        ))
        self.assertEqual("DENY", receipt.gate)
        self.assertEqual("NOT_EXECUTED", receipt.outcome)

    def test_allow_executes(self):
        runtime = self.make_runtime(CapabilityGrant(
            grant_id="allow-echo",
            capability="tool.echo",
            effect="ALLOW",
            actions=("echo",),
            resources=("console",),
        ))
        receipt = runtime.run(ActionRequest(
            request_id="2",
            capability="tool.echo",
            action="echo",
            resource="console",
            payload={"text": "yes"},
        ))
        self.assertEqual("ALLOW", receipt.gate)
        self.assertEqual("SUCCEEDED", receipt.outcome)
        self.assertEqual("yes", receipt.result["text"])

    def test_review_never_executes(self):
        runtime = self.make_runtime(CapabilityGrant(
            grant_id="review-write",
            capability="filesystem.write",
            effect="REVIEW",
            actions=("write_text",),
            resources=("*.txt",),
        ))
        receipt = runtime.run(ActionRequest(
            request_id="3",
            capability="filesystem.write",
            action="write_text",
            resource="note.txt",
            payload={"text": "blocked until approval"},
        ))
        self.assertEqual("REVIEW", receipt.gate)
        self.assertEqual("NOT_EXECUTED", receipt.outcome)

    def test_deny_overrides_allow(self):
        runtime = self.make_runtime(
            CapabilityGrant(
                grant_id="allow-read",
                capability="filesystem.read",
                effect="ALLOW",
                actions=("read_text",),
                resources=("*",),
            ),
            CapabilityGrant(
                grant_id="deny-secret",
                capability="filesystem.read",
                effect="DENY",
                actions=("read_text",),
                resources=("secret/*",),
            ),
        )
        receipt = runtime.run(ActionRequest(
            request_id="4",
            capability="filesystem.read",
            action="read_text",
            resource="secret/token.txt",
        ))
        self.assertEqual("DENY", receipt.gate)
        self.assertEqual("explicit_deny_precedence", receipt.gate_reason)

    def test_protected_control_plane_is_hard_denied(self):
        runtime = self.make_runtime(CapabilityGrant(
            grant_id="malicious-grant",
            capability="runtime.permission.*",
            effect="ALLOW",
            actions=("*",),
            resources=("*",),
            issued_by="agent",
        ))
        receipt = runtime.run(ActionRequest(
            request_id="5",
            capability="runtime.permission.grant",
            action="grant",
            resource="self",
        ))
        self.assertEqual("DENY", receipt.gate)
        self.assertEqual(
            "control_plane_capability_is_not_agent_addressable",
            receipt.gate_reason,
        )

    def test_action_mismatch_denied(self):
        runtime = self.make_runtime(CapabilityGrant(
            grant_id="echo-only",
            capability="tool.echo",
            effect="ALLOW",
            actions=("echo",),
            resources=("*",),
        ))
        receipt = runtime.run(ActionRequest(
            request_id="6",
            capability="tool.echo",
            action="write_text",
            resource="x.txt",
            payload={"text": "should not write"},
        ))
        self.assertEqual("DENY", receipt.gate)

    def test_sandbox_escape_fails_even_when_capability_allowed(self):
        runtime = self.make_runtime(CapabilityGrant(
            grant_id="write-sandbox",
            capability="filesystem.write",
            effect="ALLOW",
            actions=("write_text",),
            resources=("*",),
        ))
        receipt = runtime.run(ActionRequest(
            request_id="7",
            capability="filesystem.write",
            action="write_text",
            resource="../escape.txt",
            payload={"text": "no"},
        ))
        self.assertEqual("ALLOW", receipt.gate)
        self.assertEqual("FAILED", receipt.outcome)
        self.assertIn("sandbox_escape_denied", receipt.result["reason"])

    def test_receipts_are_hash_chained(self):
        runtime = self.make_runtime(CapabilityGrant(
            grant_id="echo",
            capability="tool.echo",
            effect="ALLOW",
            actions=("echo",),
            resources=("console",),
        ))
        first = runtime.run(ActionRequest(
            request_id="8a",
            capability="tool.echo",
            action="echo",
            resource="console",
        ))
        second = runtime.run(ActionRequest(
            request_id="8b",
            capability="tool.echo",
            action="echo",
            resource="console",
        ))
        self.assertEqual(first.receipt_hash, second.previous_receipt_hash)
        self.assertEqual(64, len(first.receipt_hash))


if __name__ == "__main__":
    unittest.main()
