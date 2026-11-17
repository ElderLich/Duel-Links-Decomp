"""Publication must not promote arbitrary receipts or malformed public claims."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import export_progress as exporter


ROOT = Path(__file__).resolve().parents[1]


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = exporter.read(ROOT / "site/progress.json")

    def test_duplicate_range_cannot_inflate_progress(self):
        data = copy.deepcopy(self.snapshot)
        data["units"].append(copy.deepcopy(data["units"][0]))
        data["summary"]["verified_functions"] += 1
        data["summary"]["matched_body_bytes"] += data["units"][0]["body_bytes"]
        with self.assertRaisesRegex(ValueError, "Duplicate/overlapping"):
            exporter.validate(data)

    def test_private_bytes_cannot_enter_public_ledger(self):
        data = copy.deepcopy(self.snapshot)
        data["units"][0]["hex"] = "private-byte-dump"
        with self.assertRaisesRegex(ValueError, "Unexpected unit fields"):
            exporter.validate(data)

    def test_engine_denominator_cannot_be_invented(self):
        data = copy.deepcopy(self.snapshot)
        data["summary"]["completion_percent"] = 100
        with self.assertRaisesRegex(ValueError, "denominator"):
            exporter.validate(data)

    def test_loose_matched_receipt_does_not_bypass_failed_integration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/targets.json").write_bytes((ROOT / "config/targets.json").read_bytes())
            (root / "Results").mkdir()
            (root / "Results/forged.json").write_text(json.dumps({"status": "matched", "functions": [{"name": "Invented"}]}))
            with patch.object(exporter.integrate, "current_local_receipts", side_effect=ValueError("Latest local integration did not pass")):
                with self.assertRaisesRegex(ValueError, "did not pass"):
                    exporter.export(root, "https://github.com/ElderLich/Duel-Links-Decomp")

    def test_research_counts_cannot_be_modified_independently(self):
        data = copy.deepcopy(self.snapshot)
        data["references"]["host_bindings"] = 999999
        canonical = {"references": self.snapshot["references"], "negative_control": {"status": self.snapshot["summary"]["negative_control"]}}
        original_digest, original_read = exporter.digest, exporter.read
        def digest(path):
            return data["units"][0]["gate_sha256"] if path.name == "build_and_match.py" else original_digest(path)
        def read(path):
            return canonical if path.name == "research.json" else original_read(path)
        with patch.object(exporter, "validate_research", return_value=canonical), patch.object(exporter, "digest", side_effect=digest), patch.object(exporter, "read", side_effect=read):
            # Source/hash binding is covered separately; this isolates research claims.
            with self.assertRaisesRegex(ValueError, "Published research/control"):
                exporter.validate_checkout(data, ROOT)


if __name__ == "__main__":
    unittest.main()
