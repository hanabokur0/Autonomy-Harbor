from pathlib import Path
import json
import unittest

from personal_agent_runtime import (
    CapabilityGrant,
    CapabilityRegistry,
    Ed25519Signer,
    PRSPPromotionGate,
    PRSPScenarioResult,
    PRSPSimulationReceipt,
    TrustStore,
    build_promotion_request,
    diff_registries,
    recompute_prsp_gate,
    sign_prsp_promotion_evidence,
)

ROOT = Path(__file__).resolve().parents[1]


def baseline_registry() -> CapabilityRegistry:
    return CapabilityRegistry(
        "par",
        "0.7",
        (
            CapabilityGrant(
                "read",
                "github.repo.read",
                "ALLOW",
                ("read",),
                ("hanabokur0/*",),
            ),
        ),
    )


def proposed_registry() -> CapabilityRegistry:
    base = baseline_registry()
    return CapabilityRegistry(
        "par",
        "0.8-candidate",
        (
            *base.grants,
            CapabilityGrant(
                "issue-review",
                "github.issue.create",
                "REVIEW",
                ("create_issue",),
                ("hanabokur0/*",),
            ),
        ),
    )


def pass_receipt(app_id: str = "personal-agent-runtime") -> PRSPSimulationReceipt:
    results = tuple(
        PRSPScenarioResult(f"X-{i}", domain, "PASS", "checked")
        for i, domain in enumerate(("authorization", "failure", "observability", "security"), 1)
    )
    return PRSPSimulationReceipt(
        "0.1",
        "sim-pass",
        app_id,
        "PASS",
        results,
        app_stage="poc",
    )


class V08PromotionGateTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519Signer.generate(subject="prsp:test")
        self.trust = TrustStore((self.signer.trusted_record("promotion_evidence_issuer"),))
        self.request = build_promotion_request(
            promotion_id="prom-001",
            baseline=baseline_registry(),
            proposed=proposed_registry(),
            requested_by="maintainer-agent",
        )
        self.gate = PRSPPromotionGate(trust_store=self.trust)

    def signed(self, receipt=None, request=None):
        return sign_prsp_promotion_evidence(
            request=request or self.request,
            receipt=receipt or pass_receipt(),
            signer=self.signer,
            signed_at="2026-09-15T00:00:00+00:00",
        )

    def test_registry_diff_detects_added_grant(self):
        delta = diff_registries(baseline_registry(), proposed_registry())
        self.assertEqual(("issue-review",), delta.added)
        self.assertTrue(delta.has_possible_authority_expansion)
        self.assertEqual(64, len(delta.digest))

    def test_pass_receipt_allows_promotion_eligibility_only(self):
        decision = self.gate.evaluate(request=self.request, signed_evidence=self.signed())
        self.assertEqual("PASS", decision.verdict)
        self.assertTrue(decision.eligible)
        self.assertEqual("NONE", decision.authority_effect)

    def test_hold_propagates(self):
        results = list(pass_receipt().results)
        results[0] = PRSPScenarioResult("AUTHZ-HOLD", "authorization", "HOLD", "rollback missing")
        receipt = PRSPSimulationReceipt("0.1", "sim-hold", self.request.app_id, "HOLD", tuple(results))
        decision = self.gate.evaluate(request=self.request, signed_evidence=self.signed(receipt))
        self.assertEqual("HOLD", decision.verdict)
        self.assertFalse(decision.eligible)

    def test_review_propagates(self):
        results = list(pass_receipt().results)
        results[0] = PRSPScenarioResult("AUTHZ-REVIEW", "authorization", "REVIEW", "specialist review")
        receipt = PRSPSimulationReceipt("0.1", "sim-review", self.request.app_id, "REVIEW", tuple(results))
        decision = self.gate.evaluate(request=self.request, signed_evidence=self.signed(receipt))
        self.assertEqual("REVIEW", decision.verdict)

    def test_reject_propagates(self):
        results = list(pass_receipt().results)
        results[0] = PRSPScenarioResult("AUTHZ-REJECT", "authorization", "REJECT", "known failure")
        receipt = PRSPSimulationReceipt("0.1", "sim-reject", self.request.app_id, "REJECT", tuple(results))
        decision = self.gate.evaluate(request=self.request, signed_evidence=self.signed(receipt))
        self.assertEqual("REJECT", decision.verdict)

    def test_missing_required_domain_holds(self):
        receipt = PRSPSimulationReceipt(
            "0.1", "sim-missing", self.request.app_id, "PASS",
            tuple(r for r in pass_receipt().results if r.domain != "security"),
        )
        decision = self.gate.evaluate(request=self.request, signed_evidence=self.signed(receipt))
        self.assertEqual("HOLD", decision.verdict)
        self.assertEqual(("security",), decision.missing_domains)

    def test_all_skip_is_hold(self):
        receipt = PRSPSimulationReceipt(
            "0.1", "sim-skip", self.request.app_id, "HOLD",
            (PRSPScenarioResult("SKIP-1", "authorization", "SKIP"),),
        )
        self.assertEqual("HOLD", recompute_prsp_gate(receipt.results))

    def test_declared_pass_with_hold_result_is_rejected_as_inconsistent(self):
        results = list(pass_receipt().results)
        results[0] = PRSPScenarioResult("AUTHZ-HOLD", "authorization", "HOLD")
        receipt = PRSPSimulationReceipt("0.1", "sim-bad", self.request.app_id, "PASS", tuple(results))
        decision = self.gate.evaluate(request=self.request, signed_evidence=self.signed(receipt))
        self.assertEqual("REJECT", decision.verdict)
        self.assertIn("prsp_gate_inconsistent", decision.reason)

    def test_evidence_for_other_promotion_request_cannot_be_replayed(self):
        other = build_promotion_request(
            promotion_id="prom-002",
            baseline=baseline_registry(),
            proposed=CapabilityRegistry(
                "par", "0.8-other",
                (*baseline_registry().grants, CapabilityGrant("other", "filesystem.write", "REVIEW", ("write_text",), ("workspace/*",))),
            ),
            requested_by="maintainer-agent",
        )
        evidence = self.signed(request=other)
        decision = self.gate.evaluate(request=self.request, signed_evidence=evidence)
        self.assertEqual("REJECT", decision.verdict)
        self.assertEqual("promotion_request_digest_mismatch", decision.reason)

    def test_wrong_signer_role_is_rejected(self):
        signer = Ed25519Signer.generate(subject="not-prsp")
        trust = TrustStore((signer.trusted_record("runtime_receipt_signer"),))
        evidence = sign_prsp_promotion_evidence(
            request=self.request, receipt=pass_receipt(), signer=signer,
            signed_at="2026-09-15T00:00:00+00:00",
        )
        decision = PRSPPromotionGate(trust_store=trust).evaluate(request=self.request, signed_evidence=evidence)
        self.assertEqual("REJECT", decision.verdict)
        self.assertIn("role_not_allowed", decision.reason)

    def test_wrong_app_id_is_rejected(self):
        receipt = pass_receipt(app_id="some-other-app")
        evidence = self.signed(receipt)
        decision = self.gate.evaluate(request=self.request, signed_evidence=evidence)
        self.assertEqual("REJECT", decision.verdict)
        self.assertEqual("prsp_receipt_app_id_mismatch", decision.reason)

    def test_promotion_gate_does_not_mutate_registry(self):
        baseline = baseline_registry()
        before = tuple(baseline.grants)
        decision = self.gate.evaluate(request=self.request, signed_evidence=self.signed())
        self.assertEqual("PASS", decision.verdict)
        self.assertEqual(before, baseline.grants)
        self.assertEqual(1, len(baseline.grants))

    def test_v08_schemas_are_authority_neutral(self):
        for name in ("promotion_request.schema.json", "promotion_decision.schema.json"):
            data = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual("NONE", data["properties"]["authority_effect"]["const"])

    def test_manifest_declares_prsp_promotion_invariants(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn('manifest_version: "0.9"', text)
        block = text.split("- id: prsp", 1)[1]
        self.assertIn("prsp_pass_is_not_a_capability_grant", block)
        self.assertIn("promotion_gate_never_mutates_capability_registry", block)
        self.assertIn("promotion_evidence_signer_is_separate_from_capability_authority", block)


if __name__ == "__main__":
    unittest.main()
