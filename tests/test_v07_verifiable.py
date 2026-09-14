from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from personal_agent_runtime import (
    ActionRequest,
    CapabilityGate,
    CapabilityGrant,
    CapabilityRegistry,
    Ed25519Signer,
    PersonalAgentRuntime,
    ReplayLedger,
    SignedEnvelope,
    SignedReviewAuthorizer,
    TrustStore,
    attest_capability_registry,
    issue_signed_review_lease,
    sign_payload,
    verify_capability_registry_attestation,
    verify_envelope,
    verify_envelope_chain,
)

ROOT = Path(__file__).resolve().parents[1]


class RecordingExecutor:
    def __init__(self, fail: bool = False):
        self.calls: list[ActionRequest] = []
        self.fail = fail

    def execute(self, request: ActionRequest):
        self.calls.append(request)
        if self.fail:
            raise RuntimeError("simulated_failure")
        return {"ok": True, "request_id": request.request_id}


def review_registry(version: str = "0.7") -> CapabilityRegistry:
    return CapabilityRegistry(
        "v07-review",
        version,
        (
            CapabilityGrant(
                grant_id="github-issue-create-review",
                capability="github.issue.create",
                effect="REVIEW",
                actions=("create_issue",),
                resources=("hanabokur0/*",),
            ),
        ),
    )


def request(body: str = "body") -> ActionRequest:
    return ActionRequest(
        request_id="maint-v07-001",
        capability="github.issue.create",
        action="create_issue",
        resource="hanabokur0/LoPAS-CHD-Protocol",
        payload={"title": "maintain", "body": body},
        actor="repo-maintainer-agent",
    )


class V07VerifiableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 9, 15, 1, 0, tzinfo=timezone.utc)
        self.review_signer = Ed25519Signer.generate(subject="human:kuroko")
        self.capability_signer = Ed25519Signer.generate(subject="control-plane:owner")
        self.receipt_signer = Ed25519Signer.generate(subject="runtime:local-device")
        self.trust = TrustStore((
            self.review_signer.trusted_record("review_issuer"),
            self.capability_signer.trusted_record("capability_authority"),
            self.receipt_signer.trusted_record("runtime_receipt_signer"),
        ))
        self.registry = review_registry()
        self.gate = CapabilityGate()

    def signed_lease(self, req: ActionRequest | None = None, ttl: int = 300):
        req = req or request()
        base = self.gate.evaluate(req, self.registry)
        return issue_signed_review_lease(
            request=req,
            base_decision=base,
            signer=self.review_signer,
            ttl_seconds=ttl,
            lease_id="signed-lease-001",
            now=self.now,
        )

    def test_signed_envelope_verifies(self):
        env = sign_payload(
            payload_type="test",
            payload={"value": 1},
            signer=self.review_signer,
            signed_at=self.now.isoformat(),
        )
        result = verify_envelope(env, self.trust, required_role="review_issuer", expected_payload_type="test")
        self.assertTrue(result.ok)
        self.assertEqual("verified", result.reason)

    def test_payload_tamper_is_detected(self):
        env = sign_payload(
            payload_type="test",
            payload={"value": 1},
            signer=self.review_signer,
            signed_at=self.now.isoformat(),
        )
        data = env.as_dict()
        data["payload"]["value"] = 2
        tampered = SignedEnvelope.from_dict(data)
        result = verify_envelope(tampered, self.trust, required_role="review_issuer")
        self.assertFalse(result.ok)
        self.assertEqual("payload_hash_mismatch", result.reason)

    def test_untrusted_signer_is_rejected(self):
        stranger = Ed25519Signer.generate(subject="human:stranger")
        env = sign_payload(
            payload_type="test",
            payload={"value": 1},
            signer=stranger,
            signed_at=self.now.isoformat(),
        )
        result = verify_envelope(env, self.trust)
        self.assertFalse(result.ok)
        self.assertEqual("untrusted_signer", result.reason)

    def test_wrong_signer_role_is_rejected(self):
        env = sign_payload(
            payload_type="review_lease",
            payload={"fake": True},
            signer=self.receipt_signer,
            signed_at=self.now.isoformat(),
        )
        result = verify_envelope(env, self.trust, required_role="review_issuer")
        self.assertFalse(result.ok)
        self.assertEqual("role_not_allowed", result.reason)

    def test_signed_review_executes_without_review_broker(self):
        req = request()
        lease = self.signed_lease(req)
        executor = RecordingExecutor()
        authorizer = SignedReviewAuthorizer(trust_store=self.trust)
        runtime = PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=authorizer,
            executor=executor,
        )
        receipt = runtime.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=1))
        self.assertEqual("ALLOW", receipt.gate)
        self.assertEqual("signed_human_review_lease_redeemed", receipt.gate_reason)
        self.assertEqual("SUCCEEDED", receipt.outcome)
        self.assertEqual(1, len(executor.calls))

    def test_signed_review_replay_is_rejected(self):
        req = request()
        lease = self.signed_lease(req)
        executor = RecordingExecutor()
        authorizer = SignedReviewAuthorizer(trust_store=self.trust)
        runtime = PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=authorizer,
            executor=executor,
        )
        first = runtime.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=1))
        second = runtime.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=2))
        self.assertEqual("SUCCEEDED", first.outcome)
        self.assertEqual("REVIEW", second.gate)
        self.assertIn("lease_already_used", second.gate_reason)
        self.assertEqual(1, len(executor.calls))

    def test_replay_ledger_survives_authorizer_restart(self):
        db_path = Path(self.temp.name) / "replay.sqlite3"
        req = request()
        lease = self.signed_lease(req)
        executor = RecordingExecutor()

        ledger1 = ReplayLedger(db_path)
        authorizer1 = SignedReviewAuthorizer(trust_store=self.trust, replay_ledger=ledger1)
        runtime1 = PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=authorizer1,
            executor=executor,
        )
        first = runtime1.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=1))
        ledger1.close()

        ledger2 = ReplayLedger(db_path)
        self.addCleanup(ledger2.close)
        authorizer2 = SignedReviewAuthorizer(trust_store=self.trust, replay_ledger=ledger2)
        runtime2 = PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=authorizer2,
            executor=executor,
        )
        second = runtime2.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=2))
        self.assertEqual("SUCCEEDED", first.outcome)
        self.assertEqual("REVIEW", second.gate)
        self.assertIn("lease_already_used", second.gate_reason)
        self.assertEqual(1, len(executor.calls))

    def test_signed_lease_binds_exact_request(self):
        approved = request("approved")
        changed = request("changed")
        lease = self.signed_lease(approved)
        runtime = PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=SignedReviewAuthorizer(trust_store=self.trust),
            executor=RecordingExecutor(),
        )
        receipt = runtime.run(changed, signed_review_lease=lease, now=self.now + timedelta(seconds=1))
        self.assertEqual("REVIEW", receipt.gate)
        self.assertIn("request_digest_mismatch", receipt.gate_reason)

    def test_expired_signed_lease_is_rejected(self):
        req = request()
        lease = self.signed_lease(req, ttl=5)
        runtime = PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=SignedReviewAuthorizer(trust_store=self.trust),
            executor=RecordingExecutor(),
        )
        receipt = runtime.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=5))
        self.assertEqual("REVIEW", receipt.gate)
        self.assertIn("lease_expired", receipt.gate_reason)

    def test_signed_lease_cannot_override_deny(self):
        req = request()
        review_base = self.gate.evaluate(req, self.registry)
        lease = issue_signed_review_lease(
            request=req,
            base_decision=review_base,
            signer=self.review_signer,
            lease_id="deny-attempt",
            now=self.now,
        )
        deny_registry = CapabilityRegistry(
            "deny-registry",
            "0.7",
            (
                *self.registry.grants,
                CapabilityGrant(
                    grant_id="deny-specific",
                    capability="github.issue.create",
                    effect="DENY",
                    actions=("create_issue",),
                    resources=("hanabokur0/LoPAS-CHD-Protocol",),
                ),
            ),
        )
        executor = RecordingExecutor()
        runtime = PersonalAgentRuntime(
            registry=deny_registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=SignedReviewAuthorizer(trust_store=self.trust),
            executor=executor,
        )
        receipt = runtime.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=1))
        self.assertEqual("DENY", receipt.gate)
        self.assertEqual("NOT_EXECUTED", receipt.outcome)
        self.assertEqual([], executor.calls)

    def test_registry_attestation_verifies_exact_snapshot(self):
        attestation = attest_capability_registry(
            self.registry,
            self.capability_signer,
            signed_at=self.now.isoformat(),
        )
        result = verify_capability_registry_attestation(self.registry, attestation, self.trust)
        self.assertTrue(result.ok)

        changed = review_registry(version="0.7.1")
        mismatch = verify_capability_registry_attestation(changed, attestation, self.trust)
        self.assertFalse(mismatch.ok)
        self.assertEqual("registry_snapshot_mismatch", mismatch.reason)

    def test_runtime_can_require_signed_registry(self):
        attestation = attest_capability_registry(
            self.registry,
            self.capability_signer,
            signed_at=self.now.isoformat(),
        )
        PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            trust_store=self.trust,
            registry_attestation=attestation,
            require_signed_registry=True,
        )
        with self.assertRaises(ValueError):
            PersonalAgentRuntime(
                registry=self.registry,
                sandbox_root=Path(self.temp.name),
                trust_store=self.trust,
                require_signed_registry=True,
            )

    def test_runtime_signed_receipts_verify_and_chain(self):
        allow_registry = CapabilityRegistry(
            "allow-registry",
            "0.7",
            (
                CapabilityGrant(
                    grant_id="echo",
                    capability="tool.echo",
                    effect="ALLOW",
                    actions=("echo",),
                    resources=("console",),
                ),
            ),
        )
        runtime = PersonalAgentRuntime(
            registry=allow_registry,
            sandbox_root=Path(self.temp.name),
            executor=RecordingExecutor(),
            receipt_signer=self.receipt_signer,
        )
        req1 = ActionRequest("r1", "tool.echo", "echo", "console", {"text": "1"})
        req2 = ActionRequest("r2", "tool.echo", "echo", "console", {"text": "2"})
        _, env1 = runtime.run_signed(req1, now=self.now)
        _, env2 = runtime.run_signed(req2, now=self.now + timedelta(seconds=1))
        v1 = verify_envelope(env1, self.trust, required_role="runtime_receipt_signer", expected_payload_type="action_receipt")
        v2 = verify_envelope(env2, self.trust, required_role="runtime_receipt_signer", expected_payload_type="action_receipt")
        self.assertTrue(v1.ok)
        self.assertTrue(v2.ok)
        self.assertEqual(env1.envelope_hash, env2.previous_envelope_hash)

    def test_executor_failure_still_consumes_signed_lease(self):
        req = request()
        lease = self.signed_lease(req)
        executor = RecordingExecutor(fail=True)
        runtime = PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            signed_review_authorizer=SignedReviewAuthorizer(trust_store=self.trust),
            executor=executor,
        )
        first = runtime.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=1))
        second = runtime.run(req, signed_review_lease=lease, now=self.now + timedelta(seconds=2))
        self.assertEqual("FAILED", first.outcome)
        self.assertEqual("REVIEW", second.gate)
        self.assertIn("lease_already_used", second.gate_reason)
        self.assertEqual(1, len(executor.calls))


    def test_signed_receipt_chain_can_be_independently_verified(self):
        env1 = sign_payload(
            payload_type="action_receipt",
            payload={"receipt": 1},
            signer=self.receipt_signer,
            signed_at=self.now.isoformat(),
        )
        env2 = sign_payload(
            payload_type="action_receipt",
            payload={"receipt": 2},
            signer=self.receipt_signer,
            signed_at=(self.now + timedelta(seconds=1)).isoformat(),
            previous_envelope_hash=env1.envelope_hash,
        )
        result = verify_envelope_chain(
            (env1, env2),
            self.trust,
            required_role="runtime_receipt_signer",
            expected_payload_type="action_receipt",
        )
        self.assertTrue(result.ok)
        self.assertEqual(2, result.verified_count)

    def test_chain_break_is_detected(self):
        env1 = sign_payload(
            payload_type="action_receipt",
            payload={"receipt": 1},
            signer=self.receipt_signer,
            signed_at=self.now.isoformat(),
        )
        env2 = sign_payload(
            payload_type="action_receipt",
            payload={"receipt": 2},
            signer=self.receipt_signer,
            signed_at=(self.now + timedelta(seconds=1)).isoformat(),
            previous_envelope_hash=None,
        )
        result = verify_envelope_chain(
            (env1, env2),
            self.trust,
            required_role="runtime_receipt_signer",
            expected_payload_type="action_receipt",
        )
        self.assertFalse(result.ok)
        self.assertEqual("previous_envelope_hash_mismatch", result.reason)

    def test_v07_schemas_are_valid_json(self):
        for name in ("signed_envelope.schema.json", "trusted_signer.schema.json"):
            data = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertIn("properties", data)

    def test_manifest_declares_signed_trust_boundary(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn('manifest_version: "0.9"', text)
        self.assertIn("trusted_signer_keys", text)
        self.assertIn("signed_review_lease_cannot_override_deny", text)
        self.assertIn("runtime_does_not_need_review_issuer_private_key", text)


if __name__ == "__main__":
    unittest.main()
