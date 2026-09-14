from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from personal_agent_runtime import (
    ActionRequest,
    CapabilityGrant,
    CapabilityRegistry,
    PersonalAgentRuntime,
    ReviewBroker,
)
from personal_agent_runtime.gate import CapabilityGate

ROOT = Path(__file__).resolve().parents[1]


class RecordingExecutor:
    def __init__(self, fail: bool = False):
        self.calls: list[ActionRequest] = []
        self.fail = fail

    def execute(self, request: ActionRequest):
        self.calls.append(request)
        if self.fail:
            raise RuntimeError("simulated_executor_failure")
        return {"recorded": True, "request_id": request.request_id}


def review_grant() -> CapabilityGrant:
    return CapabilityGrant(
        grant_id="github-issue-create-review",
        capability="github.issue.create",
        effect="REVIEW",
        actions=("create_issue",),
        resources=("hanabokur0/*",),
    )


def make_request(*, body: str = "body") -> ActionRequest:
    return ActionRequest(
        request_id="maint-001",
        capability="github.issue.create",
        action="create_issue",
        resource="hanabokur0/LoPAS-CHD-Protocol",
        payload={"title": "test", "body": body},
        actor="repo-maintainer-agent",
    )


class ReviewBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = CapabilityRegistry("review-test", "0.6", (review_grant(),))
        self.gate = CapabilityGate()
        self.now = datetime(2026, 9, 15, 0, 0, tzinfo=timezone.utc)

    def runtime(self, broker: ReviewBroker, executor: RecordingExecutor):
        return PersonalAgentRuntime(
            registry=self.registry,
            sandbox_root=Path(self.temp.name),
            review_broker=broker,
            executor=executor,
        )

    def issue(self, broker: ReviewBroker, request: ActionRequest, ttl: int = 300):
        base = self.gate.evaluate(request, self.registry)
        return broker.issue_for_review(
            request=request,
            base_decision=base,
            issued_by="human:test",
            ttl_seconds=ttl,
            lease_id="lease-001",
            now=self.now,
        )

    def test_review_without_lease_still_does_not_execute(self):
        broker = ReviewBroker()
        executor = RecordingExecutor()
        receipt = self.runtime(broker, executor).run(make_request(), now=self.now)
        self.assertEqual("REVIEW", receipt.gate)
        self.assertEqual("NOT_EXECUTED", receipt.outcome)
        self.assertEqual([], executor.calls)

    def test_exact_human_lease_executes_once(self):
        broker = ReviewBroker()
        executor = RecordingExecutor()
        request = make_request()
        lease = self.issue(broker, request)
        receipt = self.runtime(broker, executor).run(
            request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=1)
        )
        self.assertEqual("ALLOW", receipt.gate)
        self.assertEqual("human_review_lease_redeemed", receipt.gate_reason)
        self.assertEqual("SUCCEEDED", receipt.outcome)
        self.assertEqual(1, len(executor.calls))
        self.assertIn("review-lease:lease-001", receipt.matched_grant_ids)

    def test_replay_is_rejected(self):
        broker = ReviewBroker()
        executor = RecordingExecutor()
        request = make_request()
        lease = self.issue(broker, request)
        runtime = self.runtime(broker, executor)
        first = runtime.run(request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=1))
        second = runtime.run(request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=2))
        self.assertEqual("SUCCEEDED", first.outcome)
        self.assertEqual("REVIEW", second.gate)
        self.assertEqual("NOT_EXECUTED", second.outcome)
        self.assertIn("lease_already_used", second.gate_reason)
        self.assertEqual(1, len(executor.calls))

    def test_payload_change_breaks_digest_binding(self):
        broker = ReviewBroker()
        executor = RecordingExecutor()
        original = make_request(body="approved body")
        lease = self.issue(broker, original)
        changed = make_request(body="changed after approval")
        receipt = self.runtime(broker, executor).run(
            changed, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=1)
        )
        self.assertEqual("REVIEW", receipt.gate)
        self.assertIn("request_digest_mismatch", receipt.gate_reason)
        self.assertEqual([], executor.calls)

    def test_expired_lease_is_rejected(self):
        broker = ReviewBroker()
        executor = RecordingExecutor()
        request = make_request()
        lease = self.issue(broker, request, ttl=5)
        receipt = self.runtime(broker, executor).run(
            request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=5)
        )
        self.assertEqual("REVIEW", receipt.gate)
        self.assertIn("lease_expired", receipt.gate_reason)

    def test_cancelled_lease_is_rejected(self):
        broker = ReviewBroker()
        executor = RecordingExecutor()
        request = make_request()
        lease = self.issue(broker, request)
        broker.cancel(lease.lease_id, cancelled_by="human:test", now=self.now + timedelta(seconds=1))
        receipt = self.runtime(broker, executor).run(
            request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=2)
        )
        self.assertEqual("REVIEW", receipt.gate)
        self.assertIn("lease_cancelled", receipt.gate_reason)

    def test_executor_failure_still_consumes_lease(self):
        broker = ReviewBroker()
        executor = RecordingExecutor(fail=True)
        request = make_request()
        lease = self.issue(broker, request)
        runtime = self.runtime(broker, executor)
        first = runtime.run(request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=1))
        second = runtime.run(request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=2))
        self.assertEqual("FAILED", first.outcome)
        self.assertEqual("REVIEW", second.gate)
        self.assertIn("lease_already_used", second.gate_reason)
        self.assertEqual(1, len(executor.calls))

    def test_deny_cannot_be_turned_into_lease(self):
        deny_registry = CapabilityRegistry(
            "deny-test",
            "0.6",
            (
                review_grant(),
                CapabilityGrant(
                    grant_id="deny-specific",
                    capability="github.issue.create",
                    effect="DENY",
                    actions=("create_issue",),
                    resources=("hanabokur0/LoPAS-CHD-Protocol",),
                ),
            ),
        )
        request = make_request()
        base = self.gate.evaluate(request, deny_registry)
        self.assertEqual("DENY", base.verdict)
        with self.assertRaises(ValueError):
            ReviewBroker().issue_for_review(
                request=request,
                base_decision=base,
                issued_by="human:test",
                now=self.now,
            )

    def test_review_events_are_hash_chained(self):
        broker = ReviewBroker()
        request = make_request()
        lease = self.issue(broker, request)
        executor = RecordingExecutor()
        self.runtime(broker, executor).run(
            request, review_lease_id=lease.lease_id, now=self.now + timedelta(seconds=1)
        )
        self.assertEqual("ISSUED", broker.events[0].event)
        self.assertEqual("REDEEMED", broker.events[1].event)
        self.assertEqual(broker.events[0].event_hash, broker.events[1].previous_event_hash)
        self.assertEqual(64, len(broker.events[1].event_hash))

    def test_v06_schemas_are_valid_json(self):
        for name in ("review_lease.schema.json", "review_event_receipt.schema.json"):
            data = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertIn("properties", data)

    def test_manifest_declares_broker_as_control_plane(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn('manifest_version: "0.9"', text)
        block = text.split("- id: review-broker", 1)[1].split("- id: personal-agent-runtime", 1)[0]
        self.assertIn("runtime_position: trusted_control_plane", block)
        self.assertIn("lease_cannot_override_deny", block)
        self.assertIn("lease_is_one_shot", block)


if __name__ == "__main__":
    unittest.main()
