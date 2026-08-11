import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from rat_detector_core.cli import main


LOW_RISK = {
    "chain": "bsc",
    "token_address": "0x1111111111111111111111111111111111111111",
    "creator_address": "0x2222222222222222222222222222222222222222",
    "delivery_id": "bsc:synthetic:cli",
    "creator_nonce": 42,
    "creator_age_seconds": 7_776_000,
    "creator_deploys_24h": 1,
    "creator_token_share_pct": 2,
    "has_social": True,
    "bytecode_family_matches": False,
    "funder_kind": "eoa",
    "control_evidence": "none",
    "dependencies": {
        "creator_profile": "complete",
        "holdings": "complete",
        "provenance": "complete",
    },
}


class CliTests(unittest.TestCase):
    def test_analyze_emits_machine_readable_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.json"
            path.write_text(json.dumps(LOW_RISK), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main(["analyze", str(path)])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["conclusion"], "no_matching_patterns")
        self.assertEqual(payload["schema_version"], "1.0")

    def test_invalid_json_returns_validation_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text("{", encoding="utf-8")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                exit_code = main(["analyze", str(path)])

        self.assertEqual(exit_code, 2)
        self.assertIn("invalid JSON", errors.getvalue())

    def test_non_standard_nan_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nan.json"
            payload = json.dumps(LOW_RISK).replace(
                '"creator_token_share_pct": 2',
                '"creator_token_share_pct": NaN',
            )
            path.write_text(payload, encoding="utf-8")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                exit_code = main(["analyze", str(path)])

        self.assertEqual(exit_code, 2)
        self.assertIn("non-standard JSON constant", errors.getvalue())

    def test_fingerprint_command_is_offline(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["fingerprint", "0x63a9059cbb"])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["selectors"], ["a9059cbb"])
        self.assertEqual(len(payload["fingerprint"]), 64)


if __name__ == "__main__":
    unittest.main()
