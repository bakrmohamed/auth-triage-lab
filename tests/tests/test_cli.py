import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ROW = '{"timestamp":"2026-01-01T00:00:00Z","source_ip":"192.0.2.1","user":"demo","outcome":"failure"}\n'


def run(*args, text=""):
    return subprocess.run([sys.executable, "-m", "authtriage", *args], input=text,
                          text=True, capture_output=True, cwd=ROOT)


class CliTests(unittest.TestCase):
    def test_stdin(self):
        result = run("-", text=ROW)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["summary"]["valid_events"], 1)

    def test_strict_still_emits_report(self):
        result = run("-", "--strict", text=ROW + 'bad\n')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["summary"]["invalid_records"], 1)

    def test_permissive_reports_invalid(self):
        result = run("-", text='bad\n')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["summary"]["invalid_records"], 1)

    def test_output_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "report.md"
            result = run("-", "--format", "markdown", "--output", str(output), text=ROW)
            self.assertEqual(result.returncode, 0)
            original = output.read_text()
            self.assertIn("# Authentication triage report", original)
            result = run("-", "--output", str(output), text=ROW)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(output.read_text(), original)

    def test_input_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "events.jsonl"
            source.write_text(ROW)
            result = run(str(source), "--output", str(source))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(source.read_text(), ROW)

    def test_bad_config_and_missing_file(self):
        self.assertEqual(run("-", "--window-seconds", "0").returncode, 2)
        self.assertEqual(run("/nonexistent-authtriage-file").returncode, 2)

    def test_committed_example_reports_are_reproducible(self):
        generated = run("examples/auth-events.jsonl", "--strict")
        self.assertEqual(generated.returncode, 0)
        expected = (ROOT / "examples/report.json").read_text()
        self.assertEqual(generated.stdout, expected)
        report = json.loads(generated.stdout)
        self.assertEqual(report["summary"]["valid_events"], 14)
        self.assertEqual(report["summary"]["findings"], 3)
        generated_md = run("examples/auth-events.jsonl", "--format", "markdown")
        self.assertEqual(generated_md.stdout, (ROOT / "examples/report.md").read_text())

    def test_malformed_fixture(self):
        result = run("examples/malformed.jsonl", "--strict")
        self.assertEqual(result.returncode, 2)
        summary = json.loads(result.stdout)["summary"]
        self.assertEqual((summary["valid_events"], summary["invalid_records"]), (1, 3))

    def test_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "events.jsonl"
            source.write_bytes(b'\xff')
            result = run(str(source))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
