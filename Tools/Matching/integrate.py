#!/usr/bin/env python3
"""Freshly rebuild the entire enrolled scope; publish only an all-passing ledger.

Public validation is consistency checking, not an independent native match.
Full compiler receipts and the latest-attempt state remain private in Results.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
SHA = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_:.+-]{1,160}\Z")
BINDINGS = {"scope": "config/scope.json", "targets": "config/targets.json",
            "matcher": "Tools/Matching/build_and_match.py", "integrator": "Tools/Matching/integrate.py",
            "enroller": "Tools/Matching/enroll.py",
            "exporter": "Tools/export_dashboard.py", "progress_exporter": "Tools/export_progress.py",
            "research": "config/research.json"}
UNIT_FIELDS = {"id", "name", "target", "original_rva", "body_bytes", "body_sha256", "boundary", "source", "recipe",
               "recipe_template", "first_recorded_date", "date_basis", "acceptance_evidence", "contributor", "model"}
PUBLIC_UNIT_FIELDS = (UNIT_FIELDS - {"recipe", "recipe_template"}) | {"status", "target_sha256", "recipe_id", "inputs", "recipe_binding",
                     "tools", "toolchain_files", "dependency_manifest_sha256", "receipt_sha256"}


class IntegrationError(ValueError):
    pass


def canonical(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise IntegrationError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=pairs)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(path)


def checked_hash(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise IntegrationError("Expected a SHA256 digest")
    return value


def positive(value):
    if type(value) is not int or value <= 0:
        raise IntegrationError("Expected a positive integer")
    return value


def relative_file(root, value):
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./ -]+", value)
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or PurePosixPath(value).is_absolute()):
        raise IntegrationError("Expected a repository-relative path")
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()):
        raise IntegrationError("Repository path escapes the checkout")
    return path


def file_identity(root, value):
    data = relative_file(root, value).read_bytes()
    return {"path": value, "sha256": digest(data), "bytes": len(data)}


def source_name(root, raw):
    path = Path(raw)
    value = path.resolve().relative_to(root.resolve()).as_posix() if path.is_absolute() else raw
    relative_file(root, value)
    if PurePosixPath(value).parts[0] not in {"Source", "include"} or PurePosixPath(value).suffix not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
        raise IntegrationError("Input is not a public source/header")
    return value


def recipe_shape(recipe):
    """Machine-local executable paths are the sole permitted template difference."""
    result = json.loads(json.dumps(recipe))
    result["tools"] = {name: {"sha256": checked_hash(tool["sha256"])} for name, tool in sorted(recipe["tools"].items())}
    result["toolchainFiles"] = [{"name": str(item["path"]).replace("\\", "/").rsplit("/", 1)[-1],
                                 "sha256": checked_hash(item["sha256"])} for item in recipe.get("toolchainFiles", [])]
    return result


def check_ranges(units):
    ends = {}
    for unit in sorted(units, key=lambda u: (u["target"], int(u["original_rva"], 16))):
        start = int(unit["original_rva"], 16)
        if start < ends.get(unit["target"], 0):
            raise IntegrationError("Enrolled units overlap or double-count one target range")
        ends[unit["target"]] = start + unit["body_bytes"]


def load_scope(root, scope=None):
    scope = read(root / "config/scope.json") if scope is None else scope
    if set(scope) != {"schema_version", "name", "inventory_complete", "engine_total_units", "engine_total_body_bytes", "units"}:
        raise IntegrationError("Unexpected enrolled-scope fields")
    if (scope["schema_version"] != 1 or scope["inventory_complete"] is not False
            or scope["engine_total_units"] is not None or scope["engine_total_body_bytes"] is not None):
        raise IntegrationError("Whole-engine inventory is not established")
    if not isinstance(scope["name"], str) or not scope["units"]:
        raise IntegrationError("The accepted enrolled scope must not be empty")
    targets = read(root / "config/targets.json")["targets"]
    seen = set()
    for unit in scope["units"]:
        if set(unit) != UNIT_FIELDS or unit["id"] in seen or not IDENTIFIER.fullmatch(unit["id"]):
            raise IntegrationError("Invalid or duplicate enrolled unit")
        seen.add(unit["id"])
        if unit["target"] not in targets or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", unit["name"]):
            raise IntegrationError("Unknown target or invalid function name")
        if not re.fullmatch(r"0x[0-9a-f]+", unit["original_rva"]) or unit["boundary"] != "leaf-return-u32":
            raise IntegrationError("Only the reviewed strict leaf boundary is enrolled")
        positive(unit["body_bytes"]); checked_hash(unit["body_sha256"])
        if source_name(root, unit["source"]) != unit["source"]:
            raise IntegrationError("Invalid enrolled source")
        for key in ("recipe", "recipe_template"):
            relative_file(root, unit[key])
            if not unit[key].startswith("config/recipes/") or not unit[key].endswith(".json"):
                raise IntegrationError("Recipe must live under config/recipes")
        if unit["recipe_template"].endswith(".local.json"):
            raise IntegrationError("Public recipe template cannot be machine-local")
        first_day = date.fromisoformat(unit["first_recorded_date"])
        evidence = unit["acceptance_evidence"]
        if unit["date_basis"] == "published-progress-snapshot-date":
            if set(evidence) != {"receipt_sha256", "publication_snapshot_sha256"}:
                raise IntegrationError("Historical publication needs its frozen evidence basis")
            for value in evidence.values():
                checked_hash(value)
        elif unit["date_basis"] == "verified-local-enrollment-date":
            if set(evidence) != {"receipt_sha256", "recorded_at"}:
                raise IntegrationError("New enrollment needs its verified receipt and UTC time")
            checked_hash(evidence["receipt_sha256"])
            stamp = evidence["recorded_at"]
            if not isinstance(stamp, str) or not stamp.endswith("Z"):
                raise IntegrationError("Enrollment time must be explicit UTC")
            recorded = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if recorded.date() != first_day or recorded > datetime.now(timezone.utc):
                raise IntegrationError("Enrollment date differs from its recorded UTC time")
        else:
            raise IntegrationError("First recorded day needs its frozen evidence basis")
        for key in ("contributor", "model"):
            if unit[key] is not None and (not isinstance(unit[key], str) or not re.fullmatch(r"[A-Za-z0-9_. +@-]{1,100}", unit[key])):
                raise IntegrationError("Invalid recorded attribution")
    check_ranges(scope["units"])
    return scope


def prevent_regression(scope, previous):
    """Once accepted, an identity/range/date cannot disappear or be shortened."""
    if not previous:
        return
    current = {unit["id"]: unit for unit in scope["units"]}
    immutable = {"id", "target", "name", "original_rva", "body_bytes", "body_sha256", "boundary",
                 "first_recorded_date", "date_basis", "acceptance_evidence", "contributor", "model"}
    for old in previous["units"]:
        if old["id"] not in current:
            raise IntegrationError("An accepted unit disappeared from the enrolled scope")
        if any(old[key] != current[old["id"]][key] for key in immutable):
            raise IntegrationError("An accepted unit changed identity, shrank, or rewrote its acceptance history")


def committed_snapshots(root):
    """Check available acceptance history; Git failures must not erase the baseline.

    Public CI checks HEAD and its fetched parent. This detects an ordinary commit
    dropping acceptance, but cannot authenticate deliberately rewritten history.
    """
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=10)

    repository = git("rev-parse", "--is-inside-work-tree")
    if repository.returncode:
        if "not a git repository" in repository.stderr.lower():
            return  # Standalone fixture/exported checkout, explicitly no history.
        raise IntegrationError("Cannot inspect committed acceptance: " + repository.stderr.strip())
    for ref in ("HEAD", "HEAD^"):
        resolved = git("rev-parse", "--verify", "--quiet", ref)
        if resolved.returncode == 1:
            continue  # Unborn or genuinely unavailable parent, including bootstrap.
        if resolved.returncode:
            raise IntegrationError("Cannot resolve acceptance baseline: " + resolved.stderr.strip())
        listed = git("ls-tree", ref, "--", "config/integration.json")
        if listed.returncode:
            raise IntegrationError("Cannot inspect acceptance tree: " + listed.stderr.strip())
        if not listed.stdout.strip():
            continue  # Initial commit predates the integration ledger.
        result = git("show", f"{ref}:config/integration.json")
        if result.returncode:
            raise IntegrationError("Cannot read committed acceptance: " + result.stderr.strip())
        yield json.loads(result.stdout)


def prior_snapshots(root):
    path = root / "config/integration.json"
    if path.is_file():
        yield read(path)
    yield from committed_snapshots(root)


def load_gate(root):
    spec = importlib.util.spec_from_file_location("enrolled_matching_gate", root / BINDINGS["matcher"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_snapshot(root, data):
    """Public checkout consistency only; never claim that CI reran native matching."""
    expected = {"schema_version", "id", "status", "completed_at", "verification", "bindings", "units", "previous_integration_sha256", "payload_sha256"}
    if set(data) != expected or data["schema_version"] != 1 or data["status"] != "passed":
        raise IntegrationError("A successful integration snapshot is required")
    if not re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{32}", data["id"]):
        raise IntegrationError("Invalid integration ID")
    if not isinstance(data["completed_at"], str) or not data["completed_at"].endswith("Z"):
        raise IntegrationError("Integration time must be explicit UTC")
    completed = datetime.fromisoformat(data["completed_at"].replace("Z", "+00:00"))
    if data["verification"] != "local-native-full-enrolled-scope":
        raise IntegrationError("Unexpected integration verification claim")
    if data["payload_sha256"] != digest(canonical({k: v for k, v in data.items() if k != "payload_sha256"})):
        raise IntegrationError("Integration payload digest mismatch")
    if data["previous_integration_sha256"] is not None:
        checked_hash(data["previous_integration_sha256"])
    if set(data["bindings"]) != set(BINDINGS):
        raise IntegrationError("Integration bindings are incomplete")
    for key, value in BINDINGS.items():
        if data["bindings"][key] != file_identity(root, value):
            raise IntegrationError(f"Stale integration binding: {key}")
    scope = load_scope(root)
    for previous in committed_snapshots(root):
        prevent_regression(scope, previous)
    units = {u["id"]: u for u in scope["units"]}
    if len(data["units"]) != len(units) or {u["id"] for u in data["units"]} != set(units):
        raise IntegrationError("Integration does not cover every enrolled unit")
    targets = read(root / "config/targets.json")["targets"]
    for unit in data["units"]:
        enrolled = units[unit["id"]]
        if set(unit) != PUBLIC_UNIT_FIELDS or unit["status"] != "integrated":
            raise IntegrationError("Unexpected integrated-unit fields")
        for key in UNIT_FIELDS - {"recipe", "recipe_template"}:
            if unit[key] != enrolled[key]:
                raise IntegrationError("Integrated unit differs from enrolled acceptance")
        if date.fromisoformat(unit["first_recorded_date"]) > completed.date():
            raise IntegrationError("Acceptance date is after integration")
        if (unit["date_basis"] == "verified-local-enrollment-date"
                and datetime.fromisoformat(unit["acceptance_evidence"]["recorded_at"].replace("Z", "+00:00")) > completed):
            raise IntegrationError("Enrollment timestamp is after integration completion")
        if unit["target_sha256"] != targets[unit["target"]]["sha256"]:
            raise IntegrationError("Integrated target identity differs")
        if unit["recipe_id"] != digest(enrolled["recipe"].encode()):
            raise IntegrationError("Recipe identifier differs")
        for key in ("receipt_sha256", "dependency_manifest_sha256"):
            checked_hash(unit[key])
        template = read(relative_file(root, enrolled["recipe_template"]))
        specifications = [f for f in template["functions"] if f["name"] == unit["name"]]
        if len(specifications) != 1 or template["target"] != unit["target"]:
            raise IntegrationError("Public recipe does not identify the enrolled function")
        original_spec = specifications[0]["original"]
        if (original_spec.get("boundary") != unit["boundary"] or original_spec.get("size") != unit["body_bytes"]
                or ("rva" in original_spec and int(original_spec["rva"], 0) != int(unit["original_rva"], 16))):
            raise IntegrationError("Public recipe range differs from enrolled acceptance")
        binding = unit["recipe_binding"]
        if set(binding) != {"template", "shape_sha256", "local_sha256"} or binding["template"] != file_identity(root, enrolled["recipe_template"]):
            raise IntegrationError("Recipe template changed")
        if binding["shape_sha256"] != digest(canonical(recipe_shape(template))):
            raise IntegrationError("Recipe shape differs from its public template")
        checked_hash(binding["local_sha256"])
        expected_inputs = [file_identity(root, source_name(root, name)) for name in template["inputs"]]
        if unit["inputs"] != expected_inputs or unit["source"] not in [x["path"] for x in expected_inputs]:
            raise IntegrationError("Source/dependency input changed")
        tools = [{"name": name, "sha256": value["sha256"]} for name, value in sorted(template["tools"].items())]
        components = recipe_shape(template)["toolchainFiles"]
        for values, expected_values in ((unit["tools"], tools), (unit["toolchain_files"], components)):
            if [{k: v for k, v in item.items() if k != "bytes"} for item in values] != expected_values:
                raise IntegrationError("Compiler dependency pins differ from the template")
            for item in values:
                if set(item) != {"name", "sha256", "bytes"}:
                    raise IntegrationError("Private/unexpected compiler identity fields")
                positive(item["bytes"]); checked_hash(item["sha256"])
    check_ranges(data["units"])
    return data


def verify_receipt(root, report, recipe_path, recipe, enrolled, bindings, targets):
    if report.get("status") != "matched" or report.get("acceptancePolicy") != "leaf-return-u32-v2":
        raise IntegrationError("Fresh strict matching failed or used an obsolete acceptance policy")
    if (report.get("buildProfile") != "msvc-x64-closed-v1" or report.get("declaredInputsClosed") is not True
            or not isinstance(report.get("dependencies"), list) or not report["dependencies"]):
        raise IntegrationError("Closed compiler dependency evidence is required")
    if report.get("matchingGate", {}).get("sha256") != bindings["matcher"]["sha256"]:
        raise IntegrationError("Receipt used a stale matcher")
    if report.get("recipe", {}).get("sha256") != digest(recipe_path.read_bytes()) or Path(report["recipe"]["path"]).resolve() != recipe_path.resolve():
        raise IntegrationError("Receipt is not bound to the freshly run recipe")
    target = targets[recipe["target"]]
    if report.get("targetName") != recipe["target"] or any(report["target"][key] != target[key] for key in ("sha256", "bytes")):
        raise IntegrationError("Receipt target mismatch")
    inputs = [file_identity(root, source_name(root, name)) for name in recipe["inputs"]]
    actual = [{"path": source_name(root, item["path"]), "sha256": item["sha256"], "bytes": item["bytes"]} for item in report["inputs"]]
    if actual != inputs:
        raise IntegrationError("Receipt source/dependency identities differ")
    source_policy = report.get("sourcePolicy", {})
    if (source_policy.get("policy") != "readable-cpp-heuristic-v1" or source_policy.get("status") != "passed"
            or source_policy.get("inputCount") != len(inputs)):
        raise IntegrationError("Readable source policy evidence is missing")
    declared = {item["path"] for item in inputs}
    sources = {name for name in declared if PurePosixPath(name).suffix in {".c", ".cc", ".cpp", ".cxx"}}
    compiled, observed = [], set()
    for dependency in report["dependencies"]:
        source = source_name(root, dependency["source"])
        seen = {source_name(root, name) for name in dependency["observedInputs"]}
        if dependency.get("version") != "1.2" or source not in sources or source not in seen:
            raise IntegrationError("Invalid compiler-produced source dependency record")
        record = dependency["record"]
        raw = Path(record["path"]).read_bytes()
        if digest(raw) != record["sha256"] or len(raw) != record["bytes"]:
            raise IntegrationError("Compiler dependency record changed")
        compiled.append(source)
        observed.update(seen)
    if set(compiled) != sources or len(compiled) != len(sources) or observed != declared:
        raise IntegrationError("Compiler-observed inputs do not close the declared source/header set")
    tool_policy = report.get("toolDependencies", {})
    if (tool_policy.get("policy") != "msvc-static-delay-and-known-backends-v1"
            or tool_policy.get("localFileCount") != len(report["tools"]) + len(report.get("toolchainFiles", []))):
        raise IntegrationError("Compiler tool dependency closure is missing")
    if not report.get("compilerObjects"):
        raise IntegrationError("Compiler-produced object evidence is required")
    for item in report["compilerObjects"]:
        raw = Path(item["path"]).read_bytes()
        if digest(raw) != item["sha256"] or len(raw) != item["bytes"]:
            raise IntegrationError("Compiler-produced object changed")
    functions = {item["name"]: item for item in report["functions"]}
    if len(functions) != len(report["functions"]) or set(functions) != {u["name"] for u in enrolled}:
        raise IntegrationError("Fresh recipe omitted or duplicated an enrolled function")
    for unit in enrolled:
        item = functions[unit["name"]]
        original, rebuilt = item["original"], item["rebuilt"]
        if (item["status"] != "matched" or item.get("firstDifferentByte") is not None
                or original["rva"].lower() != unit["original_rva"] or original["size"] != unit["body_bytes"]
                or original["sha256"] != unit["body_sha256"] or original["boundary"] != unit["boundary"]
                or original.get("entryAnchor") not in {"pe-export", "pe-unwind", "elf-function-symbol"}
                or rebuilt.get("entryAnchor") not in {"pe-export", "pe-unwind", "elf-function-symbol"}
                or original["size"] != rebuilt["size"] or original["sha256"] != rebuilt["sha256"]
                or digest(bytes.fromhex(original["hex"])) != original["sha256"] or original["hex"] != rebuilt["hex"]):
            raise IntegrationError("Fresh native result changed, shrank or failed its accepted body")
    return inputs


def run_integration(root=ROOT, targets_override=None):
    root = root.resolve()
    attempt = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex
    state_path = root / "Results/Integration/state.json"
    write(state_path, {"id": attempt, "status": "running"})
    try:
        scope = load_scope(root)
        previous = list(prior_snapshots(root))
        for old in previous:
            prevent_regression(scope, old)
        targets = read(root / "config/targets.json")["targets"]
        if targets_override:
            overrides = read(targets_override)["targets"]
            if ({name: {k: v for k, v in value.items() if k != "path"} for name, value in overrides.items()}
                    != {name: {k: v for k, v in value.items() if k != "path"} for name, value in targets.items()}):
                raise IntegrationError("--targets may relocate inputs but cannot change pinned identities")
            targets = overrides
        bindings = {key: file_identity(root, value) for key, value in BINDINGS.items()}
        verify_new_enrollments(root, scope, previous, bindings, targets)
        gate = load_gate(root)
        grouped = {}
        for unit in scope["units"]:
            grouped.setdefault(unit["recipe"], []).append(unit)
        directory = root / "Results/Integration" / attempt
        directory.mkdir(parents=True, exist_ok=False)
        public_units = []
        failures = []
        for relative, enrolled in sorted(grouped.items()):
            recipe_path = relative_file(root, relative)
            recipe = read(recipe_path)
            templates = {u["recipe_template"] for u in enrolled}
            if len(templates) != 1:
                raise IntegrationError("One local recipe has conflicting public templates")
            template_path = next(iter(templates))
            template = read(relative_file(root, template_path))
            if recipe_shape(recipe) != recipe_shape(template):
                raise IntegrationError("Local recipe differs from public template beyond machine paths")
            if recipe["target"] != enrolled[0]["target"] or any(u["target"] != recipe["target"] for u in enrolled):
                raise IntegrationError("Recipe target differs from enrolled units")
            if len(recipe["functions"]) != len(enrolled) or {f["name"] for f in recipe["functions"]} != {u["name"] for u in enrolled}:
                raise IntegrationError("Every recipe function must be explicitly enrolled")
            recipe_id = digest(relative.encode())
            receipt_path = directory / (recipe_id + ".json")
            try:
                report = gate.run_recipe(recipe_path, targets)  # Always compiles afresh; no receipt reuse.
                write(receipt_path, report)
                inputs = verify_receipt(root, report, recipe_path, recipe, enrolled, bindings, targets)
            except Exception as error:
                failures.append({"recipe_id": recipe_id, "error": str(error)})
                if not receipt_path.is_file():
                    write(receipt_path, {"status": "failed", "error": str(error)})
                continue
            for unit in enrolled:
                public_units.append({**{k: v for k, v in unit.items() if k not in {"recipe", "recipe_template"}},
                    "status": "integrated", "target_sha256": targets[unit["target"]]["sha256"], "recipe_id": recipe_id,
                    "inputs": inputs, "recipe_binding": {"template": file_identity(root, template_path),
                    "shape_sha256": digest(canonical(recipe_shape(recipe))), "local_sha256": digest(recipe_path.read_bytes())},
                    "tools": [{"name": name, "sha256": item["sha256"], "bytes": item["bytes"]} for name, item in sorted(report["tools"].items())],
                    "toolchain_files": [{"name": str(item["path"]).replace("\\", "/").rsplit("/", 1)[-1],
                                         "sha256": item["sha256"], "bytes": item["bytes"]} for item in report.get("toolchainFiles", [])],
                    "dependency_manifest_sha256": digest(canonical(report["dependencies"])), "receipt_sha256": digest(receipt_path.read_bytes())})
        if failures:
            write(directory / "failures.json", failures)
            raise IntegrationError(f"Full enrolled integration failed for {len(failures)} recipe(s); no success ledger published")
        data = {"schema_version": 1, "id": attempt, "status": "passed", "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "verification": "local-native-full-enrolled-scope", "bindings": bindings,
                "units": sorted(public_units, key=lambda u: u["id"]),
                "previous_integration_sha256": digest(canonical(previous[0])) if previous else None}
        data["payload_sha256"] = digest(canonical(data))
        validate_snapshot(root, data)  # Rechecks every source/producer after the last build.
        write(root / "config/integration.json", data)
        write(state_path, {"id": attempt, "status": "passed", "snapshot_sha256": digest(canonical(data))})
        return data
    except Exception as error:
        write(state_path, {"id": attempt, "status": "failed", "error": str(error)})
        raise


def verify_new_enrollments(root, scope, previous, bindings, targets):
    """New acceptance dates come from a fresh local enrollment, never a guessed publication.

    Later rebuilds keep that first record unchanged. As elsewhere, this is local
    maintainer evidence, not an authenticated external clock or signed attestation.
    """
    accepted = {unit["id"] for snapshot in previous for unit in snapshot["units"]}
    fresh = [unit for unit in scope["units"] if unit["id"] not in accepted]
    grouped = {}
    for unit in fresh:
        if unit["date_basis"] != "verified-local-enrollment-date":
            if accepted:
                raise IntegrationError("New units require a verified local enrollment, not a historical publication date")
            # Initial historical migration only; later additions use fresh evidence.
            continue
        grouped.setdefault(unit["acceptance_evidence"]["receipt_sha256"], []).append(unit)
    for receipt_hash, enrolled in grouped.items():
        path = root / "Results/Enrollment" / (receipt_hash + ".json")
        if digest(path.read_bytes()) != receipt_hash:
            raise IntegrationError("First enrollment receipt changed")
        record = read(path)
        if (set(record) != {"schema_version", "recorded_at", "unit_ids", "matching_receipt"}
                or record["schema_version"] != 1
                or sorted(record["unit_ids"]) != sorted(u["id"] for u in enrolled)
                or any(record["recorded_at"] != u["acceptance_evidence"]["recorded_at"] for u in enrolled)):
            raise IntegrationError("First enrollment record differs from the declared acceptance")
        recipes = {u["recipe"] for u in enrolled}
        if len(recipes) != 1:
            raise IntegrationError("First enrollment receipt spans different recipes")
        recipe_path = relative_file(root, next(iter(recipes)))
        verify_receipt(root, record["matching_receipt"], recipe_path, read(recipe_path), enrolled, bindings, targets)


def current_local_receipts(root=ROOT):
    """Return (Path, full receipt) pairs from the latest successful full integration only."""
    root = root.resolve()
    data = validate_snapshot(root, read(root / "config/integration.json"))
    state = read(root / "Results/Integration/state.json")
    if state != {"id": data["id"], "status": "passed", "snapshot_sha256": digest(canonical(data))}:
        raise IntegrationError("Latest local integration did not pass; historical success cannot be published")
    reports = {}
    scope = {u["id"]: u for u in load_scope(root)["units"]}
    targets = read(root / "config/targets.json")["targets"]
    for unit in data["units"]:
        path = root / "Results/Integration" / data["id"] / (unit["recipe_id"] + ".json")
        if digest(path.read_bytes()) != unit["receipt_sha256"]:
            raise IntegrationError("Private integration receipt changed")
        report = read(path)
        target_data = Path(report["target"]["path"]).read_bytes()
        if digest(target_data) != report["target"]["sha256"] or len(target_data) != report["target"]["bytes"]:
            raise IntegrationError("Native target changed since integration")
        enrolled = [scope[u["id"]] for u in data["units"] if u["recipe_id"] == unit["recipe_id"]]
        recipe_path = relative_file(root, scope[unit["id"]]["recipe"])
        recipe = read(recipe_path)
        verify_receipt(root, report, recipe_path, recipe, enrolled, data["bindings"], targets)
        if digest(canonical(report["dependencies"])) != unit["dependency_manifest_sha256"]:
            raise IntegrationError("Compiler dependency manifest changed")
        for item in list(report["tools"].values()) + report.get("toolchainFiles", []):
            raw = Path(item["path"]).read_bytes()
            if digest(raw) != item["sha256"] or len(raw) != item["bytes"]:
                raise IntegrationError("Compiler dependency changed since integration")
        reports[path] = report
    return sorted(reports.items(), key=lambda item: str(item[0]))


def validate_local_state(root, data):
    if read(root / "config/integration.json") != data:
        raise IntegrationError("Requested snapshot is not the current local integration")
    current_local_receipts(root)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Public checkout consistency only; does not rerun native matching")
    parser.add_argument("--targets", type=Path, help="Private target path overrides with identical pins")
    args = parser.parse_args(argv)
    if args.check:
        validate_snapshot(ROOT, read(ROOT / "config/integration.json"))
        print("Integration snapshot consistent; native binaries/compiler were NOT independently verified.")
    else:
        result = run_integration(ROOT, args.targets)
        print(f"Full enrolled integration passed: {len(result['units'])} units, {sum(u['body_bytes'] for u in result['units'])} bytes.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"Integration failed: {error}", file=sys.stderr)
        raise SystemExit(2)
