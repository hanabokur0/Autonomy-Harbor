from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]


class V04ContractTests(unittest.TestCase):
    def test_drm_and_lca_are_declared(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("id: lopas-drm", text)
        self.assertIn("id: lopas-lca", text)
        self.assertIn('manifest_version: "0.9"', text)

    def test_dda_name_collision_is_explicitly_resolved(self):
        arch = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        manifest = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("DDM — Decision Dependency Mapper", arch)
        self.assertIn("Deliberative Decision Architecture", arch)
        self.assertIn('upstream_dda: "Decision Dependency Architecture"', manifest)
        self.assertIn('canonical_name: "Deliberative Decision Architecture"', manifest)

    def test_drm_cannot_grant_authority(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        block = text.split("- id: lopas-drm", 1)[1].split("- id: lopas-dda", 1)[0]
        self.assertIn("may_mutate_authority: false", block)
        self.assertIn("human_app_tag_is_not_runtime_authorization", block)

    def test_lca_cannot_grant_authority(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        block = text.split("- id: lopas-lca", 1)[1].split("- id: protocol-memory", 1)[0]
        self.assertIn("may_mutate_authority: false", block)
        self.assertIn("validated_learning_never_creates_authority", block)

    def test_v04_integration_docs_exist(self):
        self.assertTrue((ROOT / "integrations" / "drm" / "README.md").exists())
        self.assertTrue((ROOT / "integrations" / "lca" / "README.md").exists())

    def test_v04_schemas_are_valid_json_and_authority_neutral(self):
        for name in (
            "decision_contract.schema.json",
            "learning_claim.schema.json",
            "learning_validation.schema.json",
        ):
            data = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(data["properties"]["authority_effect"]["const"], "NONE")

    def test_learning_validation_routes_are_bounded(self):
        data = json.loads((ROOT / "schemas" / "learning_validation.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(
            set(data["properties"]["verdict"]["enum"]),
            {"VALIDATED", "UNRESOLVED", "REJECTED"},
        )
        self.assertNotIn("ALLOW", data["properties"]["verdict"]["enum"])


if __name__ == "__main__":
    unittest.main()
