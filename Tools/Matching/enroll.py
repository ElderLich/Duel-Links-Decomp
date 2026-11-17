#!/usr/bin/env python3
"""Compile a reviewed recipe and record its first verified local enrollment.

This prepares scope; it does not publish acceptance. Full integration must still
rebuild every enrolled unit before any dashboard can count the new functions.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from pathlib import Path
import sys

import integrate as integration


def enroll(root, recipe_relative, template_relative, source):
    root = root.resolve()
    scope_path = root / "config/scope.json"
    prior = scope_path.read_bytes()
    scope = integration.load_scope(root)
    if scope_path.read_bytes() != prior:
        raise integration.IntegrationError("Enrolled scope changed while preparing the candidate")
    recipe_path = integration.relative_file(root, recipe_relative)
    template_path = integration.relative_file(root, template_relative)
    recipe_pin = integration.file_identity(root, recipe_relative)
    template_pin = integration.file_identity(root, template_relative)
    recipe, template = integration.read(recipe_path), integration.read(template_path)
    if integration.recipe_shape(recipe) != integration.recipe_shape(template):
        raise integration.IntegrationError("Local recipe differs from its reviewed public template")
    source = integration.source_name(root, source)
    if source not in recipe["inputs"]:
        raise integration.IntegrationError("Primary source is absent from recipe inputs")
    target = recipe["target"]
    targets = integration.read(root / "config/targets.json")["targets"]
    bindings = {key: integration.file_identity(root, value) for key, value in integration.BINDINGS.items()}
    report = integration.load_gate(root).run_recipe(recipe_path, targets)
    if report.get("status") != "matched":
        integration.write(root / "Results/Enrollment/last-failure.json", report)
        raise integration.IntegrationError("Candidate recipe did not match; scope unchanged")
    # The timestamp is captured after the compiler result, not taken from an input
    # file's mutable mtime or a presumed public release date.
    recorded_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # The date and membership are part of the hash commitment, alongside the
    # compiler receipt. An unhashed sidecar could otherwise rewrite the date.
    envelope = {"schema_version": 1, "recorded_at": recorded_at,
                "unit_ids": [target + ":" + item["name"] for item in report["functions"]],
                "matching_receipt": report}
    raw = integration.canonical(envelope) + b"\n"
    receipt_hash = integration.digest(raw)
    units = []
    for item in report["functions"]:
        original = item["original"]
        units.append({"id": target + ":" + item["name"], "name": item["name"], "target": target,
                      "original_rva": original["rva"].lower(), "body_bytes": original["size"],
                      "body_sha256": original["sha256"], "boundary": original["boundary"],
                      "source": source, "recipe": recipe_relative, "recipe_template": template_relative,
                      "first_recorded_date": recorded_at.split("T")[0], "date_basis": "verified-local-enrollment-date",
                      "acceptance_evidence": {"receipt_sha256": receipt_hash, "recorded_at": recorded_at},
                      "contributor": None, "model": None})
    current_ids = {u["id"] for u in scope["units"]}
    if any(u["id"] in current_ids for u in units):
        raise integration.IntegrationError("Recipe contains an already enrolled unit; use full integration to rebuild it")
    updated = copy.deepcopy(scope)
    updated["units"].extend(units)
    integration.check_ranges(updated["units"])
    integration.verify_receipt(root, report, recipe_path, recipe, units, bindings, targets)
    if integration.file_identity(root, recipe_relative) != recipe_pin or integration.file_identity(root, template_relative) != template_pin:
        raise integration.IntegrationError("Candidate recipe or public template changed during compilation")
    for key, relative in integration.BINDINGS.items():
        if integration.file_identity(root, relative) != bindings[key]:
            raise integration.IntegrationError(f"Enrollment input changed during compilation: {key}")
    integration.load_scope(root, updated)
    for previous in integration.prior_snapshots(root):
        integration.prevent_regression(updated, previous)
    path = root / "Results/Enrollment" / (receipt_hash + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    # Do not replace concurrent user edits, including changes made during the
    # compilation. Validate first, then commit one atomic scope replacement.
    if scope_path.read_bytes() != prior:
        raise integration.IntegrationError("Enrolled scope changed during compilation; candidate was not enrolled")
    integration.write(scope_path, updated)
    return units


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recipe", help="Repository-relative local recipe")
    parser.add_argument("--template", required=True, help="Reviewed public recipe")
    parser.add_argument("--source", required=True, help="Primary readable source")
    args = parser.parse_args()
    units = enroll(integration.ROOT, args.recipe, args.template, args.source)
    print(f"Recorded {len(units)} freshly verified candidates. Run full integration before publishing progress.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print(f"Enrollment failed: {error}", file=sys.stderr)
        raise SystemExit(2)
