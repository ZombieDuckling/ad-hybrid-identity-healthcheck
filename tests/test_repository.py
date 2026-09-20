import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

FORBIDDEN_TEXT = [
    "revo" + "lutionary",
    "cutting" + "-edge",
    "sea" + "mless",
    "AI" + "-powered",
    "game" + "-changer",
]

SECRET_PATTERNS = [
    re.compile(r"gho_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
]


class RepositoryValidationTests(unittest.TestCase):
    def test_sample_json_loads(self):
        identity = json.loads((ROOT / "data/sample-identity-snapshot.json").read_text())
        connector = json.loads((ROOT / "data/sample-connector-snapshot.json").read_text())
        self.assertGreaterEqual(len(identity["users"]), 4)
        self.assertGreaterEqual(len(identity["devices"]), 1)
        self.assertIn("sync", connector)
        self.assertIn("federation", connector)

    def test_sample_contains_expected_lab_findings(self):
        identity = json.loads((ROOT / "data/sample-identity-snapshot.json").read_text())
        connector = json.loads((ROOT / "data/sample-connector-snapshot.json").read_text())

        upns = [user["user_principal_name"] for user in identity["users"]]
        duplicates = {upn for upn in upns if upns.count(upn) > 1}
        self.assertIn("duplicate.user@example.test", duplicates)

        missing_immutable = [
            user for user in identity["users"]
            if user["source"] == "on_prem_ad" and user["enabled"] and not user.get("immutable_id")
        ]
        self.assertEqual(["sam.operator@example.test"], [user["user_principal_name"] for user in missing_immutable])

        self.assertFalse(connector["sync"]["password_hash_sync_enabled"])
        active_agents = [agent for agent in connector["pta_agents"] if agent["status"] == "active"]
        self.assertEqual(1, len(active_agents))

    def test_required_files_exist(self):
        required = [
            "README.md",
            "LICENSE",
            "scripts/Invoke-HybridIdentityHealthCheck.ps1",
            "docs/finding-classification.md",
            "docs/report-template.md",
            ".github/workflows/ci.yml",
        ]
        for relative in required:
            self.assertTrue((ROOT / relative).exists(), relative)

    def test_no_obvious_secrets_or_banned_copy(self):
        checked_suffixes = {".md", ".ps1", ".json", ".yml", ".py"}
        for path in ROOT.rglob("*"):
            if not path.is_file() or path.suffix not in checked_suffixes:
                continue
            text = path.read_text(errors="ignore")
            self.assertNotIn("\u2014", text, f"em dash found in {path}")
            for phrase in FORBIDDEN_TEXT:
                self.assertNotIn(phrase.lower(), text.lower(), f"{phrase} found in {path}")
            for pattern in SECRET_PATTERNS:
                self.assertIsNone(pattern.search(text), f"possible secret found in {path}")

    def test_powershell_script_is_read_only(self):
        script = (ROOT / "scripts/Invoke-HybridIdentityHealthCheck.ps1").read_text()
        forbidden_verbs = [
            "Set-Mg",
            "New-Mg",
            "Remove-Mg",
            "Update-Mg",
            "Set-AD",
            "New-AD",
            "Remove-AD",
            "Disable-AD",
        ]
        for verb in forbidden_verbs:
            self.assertNotIn(verb, script)
        self.assertIn("ConvertFrom-Json", script)
        self.assertIn("Set-Content", script)


if __name__ == "__main__":
    unittest.main()
