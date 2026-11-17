"""Export an allowlisted public progress snapshot; never publish raw match receipts."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from Matching import integrate

SHA = re.compile(r"[0-9a-f]{64}\Z")
SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
RVA = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")
REPO = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
LABELS = {
    "steam-current": ("Steam / current", "steam", "MSVC 14.44 bootstrap; original compiler flags unresolved."),
    "steam-previous": ("Steam / previous", "steam", "Historical target. Addresses and matches are version-specific."),
    "cn-arm64-10.10.1032": ("CN / 10.10.1032", "cn", "Android ARM64. Exact compiler and link recipe unresolved."),
}
BOUNDARIES = {"leaf-return-u32"}


def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_path(raw):
    value = str(raw).replace("\\", "/")
    if "/Decomp/" in value:
        value = value.rsplit("/Decomp/", 1)[1]
    parts = PurePosixPath(value).parts
    if (not parts or parts[0] not in {"Source", "include"}
            or any(p in {"", ".", ".."} for p in value.split("/"))
            or not re.fullmatch(r"[A-Za-z0-9_./ -]+", value)
            or PurePosixPath(value).suffix not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}):
        raise ValueError("Source path is not a public repository source/header path")
    return value


def checked_hash(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise ValueError("Expected SHA256")
    return value


def integer(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Expected nonnegative integer")
    return value


def optional_json(path):
    return read(path) if path.is_file() else None


def references(root, targets):
    cn = root / "Evidence/CN_10.10.1032"
    bridge = optional_json(cn / "BuildAndBindingsSummary.json")
    contracts = optional_json(cn / "SharedExportContracts.json")
    rea = optional_json(root.parent / "Audit/CN_Steam_REA_Evidence.json")
    result = dict(host_bindings=None, verified_export_contracts=None, shared_exports=None,
                  active_wasm_imports=None, newly_recovered_card_references=None,
                  bridge_receipt_sha256=None, contracts_receipt_sha256=None,
                  card_reference_receipt_sha256=None)
    cn_hash = targets.get("cn-arm64-10.10.1032", {}).get("sha256")
    steam_hash = targets.get("steam-current", {}).get("sha256")
    if bridge and bridge.get("nativeSha256") == cn_hash:
        result.update(host_bindings=integer(bridge["bindings"]),
                      active_wasm_imports=integer(bridge["activeWasmImports"]),
                      bridge_receipt_sha256=digest(cn / "BuildAndBindingsSummary.json"))
    if contracts and contracts.get("cnSha256") == cn_hash and contracts.get("steamSha256") == steam_hash:
        result.update(verified_export_contracts=len(contracts["contracts"]),
                      contracts_receipt_sha256=digest(cn / "SharedExportContracts.json"))
    if rea:
        exports = {}
        for record in rea.get("records", []):
            data = record.get("normalized_result") or {}
            identity = data.get("artifact", {}).get("sha256")
            if (record.get("operation") == "inspect_native_exports" and identity in {cn_hash, steam_hash}
                    and data.get("coverage", {}).get("status") == "complete" and not data.get("issues")):
                exports[identity] = {e["name"] for e in data.get("exports", []) if e.get("name")}
        if cn_hash in exports and steam_hash in exports:
            result["shared_exports"] = len(exports[cn_hash] & exports[steam_hash])
    card_receipts = sorted((root / "Evidence/CardResearch").glob("*/ReviewedMultiSelectorReferences.json"))
    if card_receipts:
        path = card_receipts[-1]
        data = read(path)
        if data.get("binary_sha256") == steam_hash:
            missing = data.get("absent_from_pre_adapter_cards_csv", {})
            ids = {integer(v) for values in missing.values() for v in values}
            result.update(newly_recovered_card_references=len(ids), card_reference_receipt_sha256=digest(path))
    return result


def validate_references(refs):
    counts = {"host_bindings", "verified_export_contracts", "shared_exports", "active_wasm_imports", "newly_recovered_card_references"}
    hashes = {"bridge_receipt_sha256", "contracts_receipt_sha256", "card_reference_receipt_sha256"}
    if set(refs) != counts | hashes:
        raise ValueError("Unexpected reference fields")
    for key, value in refs.items():
        if value is not None:
            (checked_hash if key in hashes else integer)(value)


def prepare_research(root):
    """Prepare allowlisted local reference/control evidence before full integration."""
    config = read(root / "config/targets.json")["targets"]
    gate_hash = digest(root / "Tools/Matching/build_and_match.py")
    control_path = root / "Results/selftest_mismatch.json"
    control = optional_json(control_path)
    negative = dict(status="unknown", receipt_sha256=None, gate_sha256=gate_hash, target_sha256=None)
    if (control and control.get("status") == "mismatch"
            and control.get("matchingGate", {}).get("sha256") == gate_hash
            and control.get("target", {}).get("sha256") == config.get(control.get("targetName"), {}).get("sha256")
            and control.get("dependencies") and control.get("functions")
            and all(f.get("status") == "mismatch" and f.get("firstDifferentByte") is not None for f in control["functions"])):
        negative.update(status="passed", receipt_sha256=digest(control_path), target_sha256=control["target"]["sha256"])
    data = dict(schema_version=1, targets={key: value["sha256"] for key, value in config.items()},
                references=references(root, config), negative_control=negative)
    validate_research(root, data)
    integrate.write(root / "config/research.json", data)
    return data


def validate_research(root, data):
    if set(data) != {"schema_version", "targets", "references", "negative_control"} or data["schema_version"] != 1:
        raise ValueError("Unexpected research evidence fields")
    config = read(root / "config/targets.json")["targets"]
    if data["targets"] != {key: value["sha256"] for key, value in config.items()}:
        raise ValueError("Research target pins changed")
    validate_references(data["references"])
    control = data["negative_control"]
    if set(control) != {"status", "receipt_sha256", "gate_sha256", "target_sha256"} or control["status"] not in {"passed", "unknown"}:
        raise ValueError("Unexpected negative-control evidence")
    if control["gate_sha256"] != digest(root / "Tools/Matching/build_and_match.py"):
        raise ValueError("Negative-control gate changed; prepare references again")
    if control["status"] == "passed":
        checked_hash(control["receipt_sha256"])
        if control["target_sha256"] not in data["targets"].values():
            raise ValueError("Negative-control target changed")
    elif control["receipt_sha256"] is not None or control["target_sha256"] is not None:
        raise ValueError("Unknown negative control cannot claim proof")
    return data


def integrated_units(root):
    """Map only validated integration evidence to the compact public match ledger."""
    accepted = integrate.validate_snapshot(root, read(root / "config/integration.json"))
    result = []
    for unit in accepted["units"]:
        inputs = [{"path": item["path"], "sha256": item["sha256"]} for item in unit["inputs"]]
        source = next(item for item in inputs if item["path"] == unit["source"])
        result.append(dict(name=unit["name"], target=unit["target"], status="matched",
                           body_bytes=unit["body_bytes"], boundary=unit["boundary"],
                           original_rva=unit["original_rva"], body_sha256=unit["body_sha256"],
                           target_sha256=unit["target_sha256"], source=source, inputs=inputs,
                           receipt_sha256=unit["receipt_sha256"], gate_sha256=accepted["bindings"]["matcher"]["sha256"],
                           recipe_sha256=unit["recipe_binding"]["local_sha256"]))
    return sorted(result, key=lambda u: (u["target"], int(u["original_rva"], 16)))


def export(root: Path, repo_url: str):
    if not REPO.fullmatch(repo_url):
        raise ValueError("Expected a public GitHub owner/repository URL without credentials")
    config = read(root / "config/targets.json")["targets"]
    targets = []
    for name, spec in config.items():
        if name not in LABELS:
            continue
        label, platform, note = LABELS[name]
        if spec["format"] not in {"pe", "elf"} or spec["architecture"] not in {"amd64", "arm64"}:
            raise ValueError("Unsupported public target architecture")
        targets.append(dict(id=name, label=label, platform=platform, format=spec["format"],
                            architecture=spec["architecture"], sha256=checked_hash(spec["sha256"]),
                            image_bytes=integer(spec["bytes"]), toolchain_note=note))
    # Only the latest successful full rebuild can supply public acceptance.
    # Arbitrary JSON files in Results are never an acceptance source.
    integrate.current_local_receipts(root)
    units = integrated_units(root)
    ignored = 0
    research = validate_research(root, read(root / "config/research.json"))
    negative_control = research["negative_control"]["status"] == "passed"
    data = dict(schema_version=1, updated=datetime.now(timezone.utc).date().isoformat(),
                project=dict(name="Duel Links Native Decompilation", repo_url=repo_url, branch="main"),
                summary=dict(verified_functions=len(units), matched_body_bytes=sum(u["body_bytes"] for u in units),
                             engine_total_functions=None, engine_total_bytes=None, completion_percent=None,
                             ignored_receipts=ignored, negative_control="passed" if negative_control else "unknown"),
                targets=targets, units=units, references=research["references"])
    validate(data)
    validate_checkout(data, root)
    return data


def validate(data):
    """Validate the committed public snapshot without private inputs (Pages CI)."""
    if set(data) != {"schema_version", "updated", "project", "summary", "targets", "units", "references"}:
        raise ValueError("Unexpected public snapshot fields")
    if data["schema_version"] != 1 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["updated"]):
        raise ValueError("Invalid public snapshot version/date")
    if set(data["project"]) != {"name", "repo_url", "branch"} or not REPO.fullmatch(data["project"]["repo_url"]):
        raise ValueError("Invalid public repository")
    if data["project"]["name"] != "Duel Links Native Decompilation" or data["project"]["branch"] != "main":
        raise ValueError("Unexpected project metadata")
    summary = data["summary"]
    if set(summary) != {"verified_functions", "matched_body_bytes", "engine_total_functions", "engine_total_bytes", "completion_percent", "ignored_receipts", "negative_control"}:
        raise ValueError("Unexpected summary fields")
    for key in ("engine_total_functions", "engine_total_bytes", "completion_percent"):
        if summary[key] is not None:
            raise ValueError("A whole-engine denominator has not been established")
    integer(summary["ignored_receipts"])
    if summary["negative_control"] not in {"passed", "unknown"}:
        raise ValueError("Invalid negative-control state")
    targets = {}
    for t in data["targets"]:
        if set(t) != {"id", "label", "platform", "format", "architecture", "sha256", "image_bytes", "toolchain_note"} or t["id"] not in LABELS:
            raise ValueError("Unexpected target fields")
        label, platform, note = LABELS[t["id"]]
        if (t["label"], t["platform"], t["toolchain_note"]) != (label, platform, note) or t["id"] in targets:
            raise ValueError("Invalid target metadata")
        if t["format"] not in {"pe", "elf"} or t["architecture"] not in {"amd64", "arm64"}:
            raise ValueError("Invalid target format")
        checked_hash(t["sha256"]); integer(t["image_bytes"])
        targets[t["id"]] = t
    ranges = {}
    for u in data["units"]:
        if set(u) != {"name", "target", "status", "body_bytes", "boundary", "original_rva", "body_sha256", "target_sha256", "source", "inputs", "receipt_sha256", "gate_sha256", "recipe_sha256"}:
            raise ValueError("Unexpected unit fields")
        if not SYMBOL.fullmatch(u["name"]) or u["status"] != "matched" or u["boundary"] not in BOUNDARIES or not RVA.fullmatch(u["original_rva"]):
            raise ValueError("Invalid verified unit")
        if u["target"] not in targets or u["target_sha256"] != targets[u["target"]]["sha256"]:
            raise ValueError("Unit target pin mismatch")
        for key in ("body_sha256", "target_sha256", "receipt_sha256", "gate_sha256", "recipe_sha256"):
            checked_hash(u[key])
        if integer(u["body_bytes"]) == 0:
            raise ValueError("Empty match")
        for s in [u["source"], *u["inputs"]]:
            if set(s) != {"path", "sha256"} or source_path(s["path"]) != s["path"]:
                raise ValueError("Private or unsupported source path")
            checked_hash(s["sha256"])
        if u["source"] not in u["inputs"]:
            raise ValueError("Source is not a declared input")
        ranges.setdefault(u["target"], []).append((int(u["original_rva"], 16), u["body_bytes"]))
    for items in ranges.values():
        end = -1
        for start, size in sorted(items):
            if start < end:
                raise ValueError("Duplicate/overlapping public ranges")
            end = start + size
    if summary["verified_functions"] != len(data["units"]) or summary["matched_body_bytes"] != sum(u["body_bytes"] for u in data["units"]):
        raise ValueError("Progress totals do not match the verified ledger")
    validate_references(data["references"])


def validate_checkout(data, root):
    """Bind the public receipt to source, matcher and target pins in this checkout.

    This detects stale declarations in CI. It does not re-run a native match:
    original binaries, local recipes and full receipts deliberately stay private.
    """
    config = read(root / "config/targets.json")["targets"]
    public_ids = {item["id"] for item in data["targets"]}
    if public_ids != set(config).intersection(LABELS):
        raise ValueError("Public target inventory is stale")
    for target in data["targets"]:
        spec = config[target["id"]]
        if any(target[public] != spec[local] for public, local in
               (("sha256", "sha256"), ("image_bytes", "bytes"),
                ("format", "format"), ("architecture", "architecture"))):
            raise ValueError(f"Public target pin is stale: {target['id']}")
    gate = digest(root / "Tools/Matching/build_and_match.py")
    for unit in data["units"]:
        if unit["gate_sha256"] != gate:
            raise ValueError(f"Matching gate changed after receipt: {unit['name']}")
        for item in unit["inputs"]:
            path = root / source_path(item["path"])
            if not path.is_file() or digest(path) != item["sha256"]:
                raise ValueError(f"Declared source/header changed after receipt: {item['path']}")
    research = validate_research(root, read(root / "config/research.json"))
    if data["references"] != research["references"] or data["summary"]["negative_control"] != research["negative_control"]["status"]:
        raise ValueError("Published research/control claims differ from integration-bound evidence")
    if data["units"] != integrated_units(root):
        raise ValueError("Public matches differ from the successful integration snapshot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--repo-url", default="https://github.com/ElderLich/Duel-Links-Decomp")
    parser.add_argument("--check", action="store_true", help="Validate committed public JSON without private evidence/binaries")
    parser.add_argument("--prepare-references", action="store_true", help="Prepare local research/control evidence before full integration")
    args = parser.parse_args()
    if args.prepare_references:
        prepare_research(args.root.resolve())
        print("Prepared integration-bound research and negative-control evidence.")
        return 0
    path = args.output or args.root / "site/progress.json"
    if args.check:
        data = read(path); validate(data); validate_checkout(data, args.root.resolve())
    else:
        data = export(args.root.resolve(), args.repo_url)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Public snapshot valid: {data['summary']['verified_functions']} functions; {data['summary']['matched_body_bytes']} matched body bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
