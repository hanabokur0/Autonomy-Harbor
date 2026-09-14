from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ArchitectureManifestTests(unittest.TestCase):
    def test_required_architecture_files_exist(self):
        self.assertTrue((ROOT / "ARCHITECTURE.md").exists())
        self.assertTrue((ROOT / "component_manifest.yaml").exists())

    def test_manifest_keeps_authority_out_of_learning_components(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("forbidden_learning_targets:", text)
        self.assertIn("capability_grants", text)
        self.assertIn("credential_scope", text)
        self.assertIn("deny_rules", text)

    def test_new_cognitive_components_are_declared(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        for component in (
            "lopas-mccp",
            "lopas-lptm-minimal",
            "lopas-dda",
            "lopas-chd-protocol",
            "protocol-foundry",
            "information-compost",
            "protocol-memory",
            "prsp",
        ):
            self.assertIn(f"id: {component}", text)

    def test_chd_is_cognitive_monitor_not_authority(self):
        text = (ROOT / "component_manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("id: lopas-chd-protocol", text)
        self.assertIn("layer: cognitive_hazard_monitor", text)
        self.assertIn("may_mutate_authority: false", text)
        self.assertIn("chd_safe_does_not_imply_gate_allow", text)

    def test_chd_contract_files_exist(self):
        self.assertTrue((ROOT / "integrations" / "chd" / "README.md").exists())
        self.assertTrue((ROOT / "schemas" / "cognitive_hazard_signal.schema.json").exists())

    def test_architecture_has_pre_and_post_chd(self):
        text = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        self.assertIn("Pre-CHD", text)
        self.assertIn("Post-CHD", text)
        self.assertIn("CHD: SAFE", text)
        self.assertIn("Capability Gate: DENY", text)


if __name__ == "__main__":
    unittest.main()
