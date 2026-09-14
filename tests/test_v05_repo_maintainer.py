from pathlib import Path
import json
import unittest

from personal_agent_runtime import (
    ActionRequest,
    CapabilityGrant,
    CapabilityRegistry,
    PersonalAgentRuntime,
    RepoMaintainer,
    load_repo_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]


def load_registry() -> CapabilityRegistry:
    data = json.loads((ROOT / "examples" / "repo_maintainer_capabilities.json").read_text(encoding="utf-8"))
    return CapabilityRegistry(
        registry_id=data["registry_id"],
        version=data["version"],
        grants=tuple(
            CapabilityGrant(
                grant_id=g["grant_id"],
                capability=g["capability"],
                effect=g["effect"],
                actions=tuple(g["actions"]),
                resources=tuple(g["resources"]),
            )
            for g in data["grants"]
        ),
    )


class V05RepoMaintainerTests(unittest.TestCase):
    def test_bootstrap_snapshot_contains_35_repositories(self):
        snapshot_id, observations = load_repo_snapshot(ROOT / "examples" / "repo_snapshot_35.json")
        self.assertEqual(snapshot_id, "hanabokur0-2026-09-14-bootstrap")
        self.assertEqual(len(observations), 35)

    def test_bootstrap_top_three_are_core_spec_gaps(self):
        snapshot_id, observations = load_repo_snapshot(ROOT / "examples" / "repo_snapshot_35.json")
        receipt = RepoMaintainer().build_receipt(observations, snapshot_id=snapshot_id, limit=3)
        names = [item.full_name for item in receipt.selected]
        self.assertEqual(
            names,
            [
                "hanabokur0/LoPAS-CHD-Protocol",
                "hanabokur0/LoPAS-DRM",
                "hanabokur0/LoPAS-LCA",
            ],
        )
        self.assertTrue(all(item.route == "REVIEW" for item in receipt.selected))

    def test_same_snapshot_is_deterministic(self):
        snapshot_id, observations = load_repo_snapshot(ROOT / "examples" / "repo_snapshot_35.json")
        maintainer = RepoMaintainer()
        a = maintainer.build_receipt(observations, snapshot_id=snapshot_id, limit=3)
        b = maintainer.build_receipt(observations, snapshot_id=snapshot_id, limit=3)
        self.assertEqual(a.input_digest, b.input_digest)
        self.assertEqual(a.receipt_hash, b.receipt_hash)
        self.assertEqual(a.selected, b.selected)

    def test_issue_proposal_routes_to_review_and_does_not_execute(self):
        snapshot_id, observations = load_repo_snapshot(ROOT / "examples" / "repo_snapshot_35.json")
        candidate = RepoMaintainer().select(observations, limit=1)[0]
        runtime = PersonalAgentRuntime(
            registry=load_registry(),
            sandbox_root=ROOT / ".par-sandbox" / "v05-review",
        )
        receipt = runtime.run(candidate.to_action_request(request_id="maint-001"))
        self.assertEqual(receipt.gate, "REVIEW")
        self.assertEqual(receipt.outcome, "NOT_EXECUTED")

    def test_merge_is_explicitly_denied(self):
        runtime = PersonalAgentRuntime(
            registry=load_registry(),
            sandbox_root=ROOT / ".par-sandbox" / "v05-deny",
        )
        receipt = runtime.run(
            ActionRequest(
                request_id="merge-001",
                capability="github.merge",
                action="merge_pull_request",
                resource="hanabokur0/lopas-protocol-foundry",
            )
        )
        self.assertEqual(receipt.gate, "DENY")
        self.assertEqual(receipt.outcome, "NOT_EXECUTED")

    def test_v05_schemas_are_valid_json(self):
        for name in ("repo_snapshot.schema.json", "maintenance_receipt.schema.json"):
            data = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertIn("properties", data)

    def test_manifest_declares_repo_maintainer_without_authority(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn('manifest_version: "0.9"', text)
        block = text.split("- id: repo-maintainer-agent", 1)[1].split("- id: personal-agent-runtime", 1)[0]
        self.assertIn("may_mutate_authority: false", block)
        self.assertIn("github_issue_create_defaults_to_review", block)
        self.assertIn("github_merge_and_repo_delete_default_to_deny", block)


if __name__ == "__main__":
    unittest.main()
