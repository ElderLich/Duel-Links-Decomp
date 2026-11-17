#!/usr/bin/env python3
"""Export truthful enrolled-scope statistics from the fresh full-integration ledger."""
from __future__ import annotations

import argparse
from collections import defaultdict
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dashboard_integration", ROOT / "Tools/Matching/integrate.py")
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)

PROJECT = {"name": "Duel Links Native Decompilation", "repo_url": "https://github.com/ElderLich/Duel-Links-Decomp", "branch": "main"}
LABELS = {"steam-current": ("Steam / current", "steam"), "steam-previous": ("Steam / previous", "steam"),
          "cn-arm64-10.10.1032": ("CN / 10.10.1032", "cn")}


def attribution(units, field):
    groups = {}
    for unit in units:
        label = unit[field]
        key = "unknown" if label is None else integration.digest(label.encode())[:16]
        group = groups.setdefault(key, {"id": key, "label": "Unknown / unrecorded" if label is None else label,
                                        "units": 0, "body_bytes": 0})
        group["units"] += 1
        group["body_bytes"] += unit["body_bytes"]
    return [groups[key] for key in sorted(groups)]


def build_dashboard(root, snapshot):
    integration.validate_snapshot(root, snapshot)
    enrolled = integration.load_scope(root)
    units = [{"id": u["id"], "name": u["name"], "target": u["target"], "source": u["source"],
              "original_rva": u["original_rva"], "body_bytes": u["body_bytes"], "status": "integrated",
              "first_accepted_date": u["first_recorded_date"], "contributor": u["contributor"], "model": u["model"]}
             for u in snapshot["units"]]
    total_bytes = sum(u["body_bytes"] for u in units)
    targets = []
    for name, target in sorted(integration.read(root / "config/targets.json")["targets"].items()):
        own = [u for u in units if u["target"] == name]
        scoped = [u for u in enrolled["units"] if u["target"] == name]
        label, platform = LABELS.get(name, (name, target["architecture"]))
        targets.append({"id": name, "label": label, "platform": platform, "sha256": target["sha256"],
                        "enrolled_units": len(scoped), "enrolled_body_bytes": sum(u["body_bytes"] for u in scoped),
                        "integrated_units": len(own), "integrated_body_bytes": sum(u["body_bytes"] for u in own),
                        "pending_units": len(scoped) - len(own), "pending_body_bytes": sum(u["body_bytes"] for u in scoped) - sum(u["body_bytes"] for u in own)})
    days = defaultdict(lambda: [0, 0])
    for unit in units:
        days[unit["first_accepted_date"]][0] += 1
        days[unit["first_accepted_date"]][1] += unit["body_bytes"]
    daily = []
    count = size = 0
    for day, (added_count, added_bytes) in sorted(days.items()):
        count += added_count
        size += added_bytes
        daily.append({"date": day, "accepted_units": added_count, "accepted_body_bytes": added_bytes,
                      "cumulative_units": count, "cumulative_body_bytes": size})
    return {"schema_version": 1, "project": PROJECT,
            "integration": {"id": snapshot["id"], "completed_at": snapshot["completed_at"], "status": "passed",
                            "verification": snapshot["verification"], "ci_verification": "consistency-only-no-native-binaries",
                            "snapshot_sha256": integration.digest(integration.canonical(snapshot))},
            "scope": {"inventory_complete": False, "enrolled_units": len(enrolled["units"]),
                      "enrolled_body_bytes": sum(u["body_bytes"] for u in enrolled["units"]),
                      "integrated_units": len(units), "integrated_body_bytes": total_bytes,
                      "pending_units": len(enrolled["units"]) - len(units),
                      "pending_body_bytes": sum(u["body_bytes"] for u in enrolled["units"]) - total_bytes,
                      "engine_total_units": None, "engine_total_body_bytes": None, "engine_completion_percent": None},
            "targets": targets, "units": units, "daily_trend": daily,
            "size_map": [{key: u[key] for key in ("id", "name", "target", "source", "body_bytes", "status")} for u in units],
            "contributors": attribution(units, "contributor"), "models": attribution(units, "model"),
            "milestones": [{"id": "full-enrolled-integration", "date": snapshot["completed_at"].split("T")[0],
                            "label": "All enrolled units rebuilt and matched", "units": len(units), "body_bytes": total_bytes}],
            "limitations": ["Full enrolled-scope success is not whole-engine completion; the native inventory denominator is unknown.",
                            "CI validates committed source, recipe, toolchain pins and ledger consistency. It cannot independently match private native binaries.",
                            "First recorded dates retain their evidence basis: the initial pilot uses its historical publication day; later units use a fresh verified local enrollment timestamp. Rebuilds do not add progress again.",
                            "Contributor and model attribution are unknown where no historical evidence was recorded. Token, cost and visitor data are not collected."]}


def validate_dashboard(root, data):
    expected = build_dashboard(root, integration.read(root / "config/integration.json"))
    if data != expected:
        raise integration.IntegrationError("Dashboard differs from its validated integration ledger")
    return data


def export(root=ROOT):
    snapshot = integration.read(root / "config/integration.json")
    integration.validate_local_state(root, snapshot)
    data = build_dashboard(root, snapshot)
    integration.write(root / "site/dashboard.json", data)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Validate committed consistency without private native inputs")
    args = parser.parse_args(argv)
    if args.check:
        validate_dashboard(ROOT, integration.read(ROOT / "site/dashboard.json"))
        print("Dashboard consistent; native matching was NOT independently rerun in this check.")
    else:
        data = export()
        print(f"Dashboard exported from full integration: {data['scope']['integrated_units']} units, {data['scope']['integrated_body_bytes']} bytes.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"Dashboard export failed: {error}", file=sys.stderr)
        raise SystemExit(2)
