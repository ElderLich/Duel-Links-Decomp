"""Dashboard derives every counter from accepted scope; no native inputs in CI."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dashboard_under_test", ROOT / "Tools/export_dashboard.py")
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)
spec = importlib.util.spec_from_file_location("integration_fixtures", ROOT / "Tools/Matching/test_integrate.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = fixtures.Fixture(self.root)
        self.snapshot = self.fixture.run()

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_counts_unknown_attribution_and_single_day_not_fake_history(self):
        data = dashboard.build_dashboard(self.root, self.snapshot)
        self.assertEqual(1, data["scope"]["integrated_units"])
        self.assertEqual(6, data["scope"]["integrated_body_bytes"])
        self.assertEqual(0, data["scope"]["pending_units"])
        self.assertIsNone(data["scope"]["engine_completion_percent"])
        self.assertFalse(data["scope"]["inventory_complete"])
        self.assertEqual([{"id": "unknown", "label": "Unknown / unrecorded", "units": 1, "body_bytes": 6}], data["models"])
        self.assertEqual(data["models"], data["contributors"])
        self.assertEqual(1, len(data["daily_trend"]))
        self.assertEqual(1, len(data["milestones"]))
        self.assertEqual("consistency-only-no-native-binaries", data["integration"]["ci_verification"])
        self.assertFalse({"tokens", "cost", "visitors"} & set(data))

    def test_tampered_totals_attribution_or_trends_fail(self):
        data = dashboard.build_dashboard(self.root, self.snapshot)
        for mutate in (lambda d: d["scope"].update(integrated_units=100), lambda d: d["models"][0].update(label="Invented model"),
                       lambda d: d["daily_trend"].append(dict(d["daily_trend"][0])), lambda d: d.update(visitors=1000)):
            changed = copy.deepcopy(data)
            mutate(changed)
            with self.assertRaises(ValueError):
                dashboard.validate_dashboard(self.root, changed)

    def test_regression_does_not_overwrite_dashboard(self):
        original = dashboard.export(self.root)
        saved = (self.root / "site/dashboard.json").read_bytes()
        self.fixture.fail = True
        for _ in range(2):
            with self.assertRaises(ValueError):
                self.fixture.run()
            with self.assertRaises(ValueError):
                dashboard.export(self.root)
            self.assertEqual(saved, (self.root / "site/dashboard.json").read_bytes())
        # Public consistency remains explicitly weaker than local native state.
        self.assertEqual(original, dashboard.validate_dashboard(self.root, original))

    def test_source_change_invalidates_public_dashboard(self):
        data = dashboard.build_dashboard(self.root, self.snapshot)
        (self.root / "Source/pilot.cpp").write_text("changed")
        with self.assertRaises(ValueError):
            dashboard.validate_dashboard(self.root, data)


if __name__ == "__main__":
    unittest.main()
