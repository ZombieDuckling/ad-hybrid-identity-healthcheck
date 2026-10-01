import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ReportGeneratorTests(unittest.TestCase):
    def test_generator_writes_structured_report_to_requested_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.md"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/generate_sample_report.py"),
                    "--users",
                    str(ROOT / "data/synthetic-directory-export.csv"),
                    "--sync-errors",
                    str(ROOT / "data/synthetic-sync-errors.json"),
                    "--rules",
                    str(ROOT / "policies/healthcheck-rules.json"),
                    "--output",
                    str(output),
                ],
                check=True,
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

            self.assertIn("Wrote", result.stdout)
            report = output.read_text(encoding="utf-8")

        self.assertIn("# AD Hybrid Identity Healthcheck Report", report)
        self.assertIn("Data classification: synthetic sample data", report)
        self.assertIn("Findings: 7", report)
        self.assertIn("Users reviewed: 6", report)
        self.assertIn("Sync errors reviewed: 2", report)
        for rule_id in [
            "ID-PRIV-MFA",
            "ID-PRIV-PASSWORD-AGE",
            "ID-STALE-ACTIVE",
            "ID-SYNC-ERROR",
        ]:
            self.assertIn(rule_id, report)

    def test_checked_in_sample_report_stays_in_sync(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.md"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/generate_sample_report.py"),
                    "--users",
                    str(ROOT / "data/synthetic-directory-export.csv"),
                    "--sync-errors",
                    str(ROOT / "data/synthetic-sync-errors.json"),
                    "--rules",
                    str(ROOT / "policies/healthcheck-rules.json"),
                    "--output",
                    str(output),
                ],
                check=True,
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

            generated_report = output.read_text(encoding="utf-8")

        checked_in_report = (
            ROOT / "sample-output/ad-hybrid-healthcheck-report.md"
        ).read_text(encoding="utf-8")
        self.assertEqual(checked_in_report, generated_report)


if __name__ == "__main__":
    unittest.main()
