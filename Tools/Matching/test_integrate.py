"""Integration refusal paths use synthetic receipts; no private binaries/compiler."""
import copy
from datetime import datetime, timedelta
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("integration_under_test", Path(__file__).with_name("integrate.py"))
integration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integration)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.fail = False
        self.mutate = None
        self.body = bytes.fromhex("b807000000c3")
        for path in integration.BINDINGS.values():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fixture code\n")
        (root / "Source").mkdir()
        (root / "include").mkdir()
        (root / "config/recipes").mkdir()
        (root / "Source/pilot.cpp").write_text("unsigned pilot() { return 7; }\n")
        (root / "include/pilot.h").write_text("unsigned pilot();\n")
        self.target = root / "target.dll"
        self.target.write_bytes(b"fixture native target")
        self.compiler = root / "cc.exe"
        self.compiler.write_bytes(b"compiler fixture")
        self.component = root / "c1xx.dll"
        self.component.write_bytes(b"compiler component fixture")
        self.dependency_record = root / "compiler-dependencies.json"
        self.dependency_record.write_text('{"Version":"1.2"}')
        self.object = root / "pilot.obj"
        self.object.write_bytes(b"synthetic compiler object")
        self.target_spec = {"path": str(self.target), "sha256": integration.digest(self.target.read_bytes()),
                            "bytes": self.target.stat().st_size, "format": "pe", "architecture": "amd64"}
        integration.write(root / "config/targets.json", {"schemaVersion": 1, "targets": {"steam-current": self.target_spec}})
        self.scope = {"schema_version": 1, "name": "Fixture enrolled scope", "inventory_complete": False,
                      "engine_total_units": None, "engine_total_body_bytes": None, "units": []}
        self.add_unit("pilot", "0x1000")

    def add_unit(self, name, rva, recipe="pilot"):
        unit = {"id": "steam-current:" + name, "name": name, "target": "steam-current", "original_rva": rva,
                "body_bytes": 6, "body_sha256": integration.digest(self.body), "boundary": "leaf-return-u32",
                "source": "Source/pilot.cpp", "recipe": f"config/recipes/{recipe}.local.json",
                "recipe_template": f"config/recipes/{recipe}.example.json", "first_recorded_date": "2026-01-01",
                "date_basis": "published-progress-snapshot-date", "acceptance_evidence": {"receipt_sha256": "1" * 64, "publication_snapshot_sha256": "2" * 64},
                "contributor": None, "model": None}
        self.scope["units"].append(unit)
        integration.write(self.root / "config/scope.json", self.scope)
        own = [u for u in self.scope["units"] if u["recipe"] == unit["recipe"]]
        config = {"schemaVersion": 1, "buildProfile": "msvc-x64-closed-v1", "target": "steam-current",
                  "inputs": ["Source/pilot.cpp", "include/pilot.h"],
                  "tools": {"cc": {"path": str(self.compiler), "sha256": integration.digest(self.compiler.read_bytes())}},
                  "toolchainFiles": [{"path": str(self.component), "sha256": integration.digest(self.component.read_bytes())}],
                  "commands": [["{cc}", "{decomp}/Source/pilot.cpp"]], "output": "{build}/pilot.dll",
                  "functions": [{"name": u["name"], "original": {"rva": u["original_rva"], "boundary": "leaf-return-u32", "size": 6},
                                 "rebuilt": {"rva": "0x1000", "boundary": "leaf-return-u32"}} for u in own]}
        integration.write(self.root / unit["recipe"], config)
        integration.write(self.root / unit["recipe_template"], config)
        return unit

    def identity(self, path):
        return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": integration.digest(path.read_bytes())}

    def run_recipe(self, path, targets):
        self.calls.append(path.name)
        recipe = integration.read(path)
        functions = []
        for function in recipe["functions"]:
            original = {"rva": function["original"]["rva"], "size": 6, "sha256": integration.digest(self.body),
                        "hex": self.body.hex(), "boundary": "leaf-return-u32", "entryAnchor": "pe-export"}
            functions.append({"name": function["name"], "status": "matched", "firstDifferentByte": None,
                              "original": original, "rebuilt": dict(original)})
        report = {"status": "mismatch" if self.fail else "matched", "acceptancePolicy": "leaf-return-u32-v2",
                  "buildProfile": "msvc-x64-closed-v1", "declaredInputsClosed": True,
                  "targetName": "steam-current", "target": self.identity(self.target), "recipe": self.identity(path),
                  "matchingGate": self.identity(self.root / integration.BINDINGS["matcher"]),
                  "inputs": [self.identity(self.root / value) for value in recipe["inputs"]],
                  "tools": {"cc": self.identity(self.compiler)}, "toolchainFiles": [self.identity(self.component)],
                  "sourcePolicy": {"policy": "readable-cpp-heuristic-v1", "status": "passed", "inputCount": len(recipe["inputs"])},
                  "toolDependencies": {"policy": "msvc-static-delay-and-known-backends-v1", "localFileCount": 2},
                  "compilerObjects": [self.identity(self.object)],
                  "dependencies": [{"record": self.identity(self.dependency_record), "version": "1.2",
                                    "source": str(self.root / "Source/pilot.cpp"),
                                    "observedInputs": [str(self.root / value) for value in recipe["inputs"]]}], "functions": functions}
        if self.mutate:
            self.mutate(report)
        return report

    def run(self):
        with patch.object(integration, "load_gate", return_value=SimpleNamespace(run_recipe=self.run_recipe)):
            return integration.run_integration(self.root)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_every_enrolled_recipe_is_freshly_run_even_after_failure(self):
        self.fixture.add_unit("second", "0x2000", recipe="second")
        first = self.fixture.run()
        self.assertEqual(2, len(first["units"]))
        self.fixture.fail = True
        before = (self.root / "config/integration.json").read_bytes()
        for _ in range(2):
            with self.assertRaisesRegex(integration.IntegrationError, "failed for 2"):
                self.fixture.run()
            self.assertEqual(before, (self.root / "config/integration.json").read_bytes())
            with self.assertRaisesRegex(integration.IntegrationError, "Latest local integration"):
                integration.current_local_receipts(self.root)
        self.assertEqual(6, len(self.fixture.calls))

    def test_repeated_success_rebuilds_without_double_counting(self):
        first, second = self.fixture.run(), self.fixture.run()
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(2, len(self.fixture.calls))
        self.assertEqual(1, len(second["units"]))
        self.assertEqual(integration.digest(integration.canonical(first)), second["previous_integration_sha256"])
        self.assertEqual(1, len(integration.current_local_receipts(self.root)))

    def test_accepted_unit_cannot_disappear_shrink_or_rewrite_history(self):
        self.fixture.add_unit("second", "0x2000", recipe="second")
        self.fixture.run()
        original = copy.deepcopy(self.fixture.scope)
        for mutate in (lambda s: s["units"].pop(), lambda s: s["units"][0].update(body_bytes=3),
                       lambda s: s["units"][0].update(first_recorded_date="2026-02-01")):
            scope = copy.deepcopy(original)
            mutate(scope)
            integration.write(self.root / "config/scope.json", scope)
            with self.assertRaisesRegex(integration.IntegrationError, "disappeared|shrank"):
                self.fixture.run()

    def test_overlap_and_duplicate_units_cannot_inflate_scope(self):
        self.fixture.add_unit("overlap", "0x1003", recipe="second")
        with self.assertRaisesRegex(integration.IntegrationError, "overlap"):
            self.fixture.run()
        self.fixture.scope["units"][-1] = self.fixture.scope["units"][0]
        integration.write(self.root / "config/scope.json", self.fixture.scope)
        with self.assertRaisesRegex(integration.IntegrationError, "duplicate"):
            self.fixture.run()

    def test_stale_matcher_or_missing_dependency_receipt_fails(self):
        for mutate in (lambda r: r["matchingGate"].update(sha256="0" * 64), lambda r: r.pop("dependencies"),
                       lambda r: r.update(acceptancePolicy="old"), lambda r: r.update(functions=[])):
            self.fixture.mutate = mutate
            with self.assertRaises(integration.IntegrationError):
                self.fixture.run()
            self.assertFalse((self.root / "config/integration.json").exists())

    def test_source_changes_during_build_block_success(self):
        self.fixture.mutate = lambda r: (self.root / "Source/pilot.cpp").write_text("changed during compile")
        with self.assertRaises(integration.IntegrationError):
            self.fixture.run()
        self.assertFalse((self.root / "config/integration.json").exists())

    def test_export_checks_current_target_compiler_and_source(self):
        self.fixture.run()
        for path in (self.fixture.target, self.fixture.compiler, self.root / "Source/pilot.cpp",
                     self.fixture.dependency_record, self.fixture.object):
            original = path.read_bytes()
            path.write_bytes(b"changed")
            with self.assertRaises(integration.IntegrationError):
                integration.current_local_receipts(self.root)
            path.write_bytes(original)

    def test_dependency_closure_and_true_entry_are_required(self):
        for mutate in (lambda r: r["dependencies"][0]["observedInputs"].pop(),
                       lambda r: r["dependencies"].append(copy.deepcopy(r["dependencies"][0])),
                       lambda r: r.update(declaredInputsClosed=False),
                       lambda r: r["functions"][0]["original"].pop("entryAnchor"),
                       lambda r: r.update(compilerObjects=[])):
            self.fixture.mutate = mutate
            with self.assertRaises(integration.IntegrationError):
                self.fixture.run()
            self.assertFalse((self.root / "config/integration.json").exists())

    def test_public_check_rejects_scope_removed_in_committed_child(self):
        self.fixture.add_unit("second", "0x2000", recipe="second")
        data = self.fixture.run()

        def git(*args):
            result = subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args],
                                    cwd=self.root, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
        git("init")
        git("add", ".")
        git("commit", "-m", "Accepted fixture baseline")
        self.fixture.scope["units"].pop()
        integration.write(self.root / "config/scope.json", self.fixture.scope)
        data["units"].pop()
        data["bindings"]["scope"] = integration.file_identity(self.root, "config/scope.json")
        data["payload_sha256"] = integration.digest(integration.canonical({k: v for k, v in data.items() if k != "payload_sha256"}))
        integration.write(self.root / "config/integration.json", data)
        git("add", ".")
        git("commit", "-m", "Attempted accepted scope removal")
        with self.assertRaisesRegex(integration.IntegrationError, "disappeared"):
            integration.validate_snapshot(self.root, data)

    def test_git_errors_do_not_silently_forget_accepted_scope(self):
        error = SimpleNamespace(returncode=128, stderr="fatal: detected dubious ownership", stdout="")
        with patch.object(integration.subprocess, "run", return_value=error):
            with self.assertRaisesRegex(integration.IntegrationError, "Cannot inspect committed acceptance"):
                list(integration.committed_snapshots(self.root))

    def test_changed_research_receipt_requires_fresh_integration(self):
        data = self.fixture.run()
        (self.root / "config/research.json").write_text("changed references or control")
        with self.assertRaisesRegex(integration.IntegrationError, "research"):
            integration.validate_snapshot(self.root, data)

    def test_public_tamper_requires_valid_payload_and_enrolled_identity(self):
        data = self.fixture.run()
        for mutate in (lambda d: d["units"][0].update(body_bytes=600), lambda d: d["units"][0]["tools"][0].update(sha256="0" * 64),
                       lambda d: d.update(units=[]), lambda d: d.update(secret="absolute/private/path")):
            changed = copy.deepcopy(data)
            mutate(changed)
            changed["payload_sha256"] = integration.digest(integration.canonical({k: v for k, v in changed.items() if k != "payload_sha256"}))
            with self.assertRaises(integration.IntegrationError):
                integration.validate_snapshot(self.root, changed)

    def test_public_check_needs_no_private_binary_recipe_or_receipts(self):
        data = self.fixture.run()
        self.fixture.target.unlink()
        (self.root / "config/recipes/pilot.local.json").unlink()
        self.assertEqual(data, integration.validate_snapshot(self.root, data))
        with self.assertRaises(OSError):
            integration.current_local_receipts(self.root)

    def test_target_override_cannot_change_pinned_identity(self):
        override = self.root / "override.json"
        integration.write(override, {"targets": {"steam-current": {**self.fixture.target_spec, "sha256": "0" * 64}}})
        with self.assertRaisesRegex(integration.IntegrationError, "cannot change pinned identities"):
            integration.run_integration(self.root, override)

    def test_local_recipe_cannot_sneak_past_public_template(self):
        path = self.root / "config/recipes/pilot.local.json"
        recipe = integration.read(path)
        recipe["commands"].append(["{cc}", "unreviewed"])
        integration.write(path, recipe)
        with self.assertRaisesRegex(integration.IntegrationError, "differs from public template"):
            self.fixture.run()

    def prepare_enrollment(self, mutate=None):
        import enroll
        self.fixture.run()
        original = copy.deepcopy(self.fixture.scope)
        self.fixture.add_unit("second", "0x2000", recipe="second")
        self.fixture.scope = original
        integration.write(self.root / "config/scope.json", original)
        self.fixture.mutate = mutate
        with patch.object(enroll, "integration", integration), patch.object(integration, "load_gate", return_value=SimpleNamespace(run_recipe=self.fixture.run_recipe)):
            return enroll.enroll(self.root, "config/recipes/second.local.json", "config/recipes/second.example.json", "Source/pilot.cpp")

    def test_new_enrollment_uses_fresh_verified_receipt_before_full_integration(self):
        units = self.prepare_enrollment()
        self.assertEqual(1, len(units))
        self.assertEqual("verified-local-enrollment-date", units[0]["date_basis"])
        self.assertEqual(units[0]["first_recorded_date"], units[0]["acceptance_evidence"]["recorded_at"].split("T")[0])
        # Enrollment never updates the previously published success snapshot.
        self.assertEqual(1, len(integration.read(self.root / "config/integration.json")["units"]))
        result = self.fixture.run()
        self.assertEqual(2, len(result["units"]))
        self.assertEqual(2, len(self.fixture.run()["units"]))

    def test_new_enrollment_tampered_receipt_blocks_integration(self):
        units = self.prepare_enrollment()
        path = self.root / "Results/Enrollment" / (units[0]["acceptance_evidence"]["receipt_sha256"] + ".json")
        path.write_text("tampered")
        with self.assertRaisesRegex(integration.IntegrationError, "receipt changed"):
            self.fixture.run()
        self.assertEqual(1, len(integration.read(self.root / "config/integration.json")["units"]))

    def test_unhashed_sidecar_cannot_backdate_a_verified_enrollment(self):
        units = self.prepare_enrollment()
        scope = integration.read(self.root / "config/scope.json")
        unit = scope["units"][-1]
        evidence = unit["acceptance_evidence"]
        path = self.root / "Results/Enrollment" / (evidence["receipt_sha256"] + ".json")
        original = path.read_bytes()
        self.assertEqual(evidence["recorded_at"], integration.read(path)["recorded_at"])
        evidence["recorded_at"] = "2020-01-01T00:00:00Z"
        unit["first_recorded_date"] = "2020-01-01"
        integration.write(self.root / "config/scope.json", scope)
        integration.write(path.with_suffix(".record.json"), {"schema_version": 1,
                          "receipt_sha256": evidence["receipt_sha256"], "recorded_at": evidence["recorded_at"],
                          "unit_ids": [units[0]["id"]]})
        with self.assertRaisesRegex(integration.IntegrationError, "record differs"):
            self.fixture.run()
        self.assertEqual(original, path.read_bytes())

    def test_scope_and_template_edits_during_enrollment_are_not_overwritten(self):
        def edit_scope(report):
            scope = integration.read(self.root / "config/scope.json")
            scope["name"] = "Concurrent user edit"
            integration.write(self.root / "config/scope.json", scope)
        with self.assertRaisesRegex(integration.IntegrationError, "changed during compilation"):
            self.prepare_enrollment(edit_scope)
        self.assertEqual("Concurrent user edit", integration.read(self.root / "config/scope.json")["name"])
        self.assertEqual(1, len(integration.read(self.root / "config/scope.json")["units"]))

    def test_public_recipe_changed_during_compile_cannot_be_enrolled(self):
        def edit_template(report):
            path = self.root / "config/recipes/second.example.json"
            recipe = integration.read(path)
            recipe["commands"].append(["{cc}", "changed-template"])
            integration.write(path, recipe)
        with self.assertRaisesRegex(integration.IntegrationError, "public template changed"):
            self.prepare_enrollment(edit_template)
        self.assertEqual(1, len(integration.read(self.root / "config/scope.json")["units"]))

    def test_public_integration_cannot_predate_its_enrollment_timestamp(self):
        units = self.prepare_enrollment()
        data = self.fixture.run()
        recorded = datetime.fromisoformat(units[0]["acceptance_evidence"]["recorded_at"].replace("Z", "+00:00"))
        data["completed_at"] = (recorded - timedelta(microseconds=1)).isoformat().replace("+00:00", "Z")
        data["payload_sha256"] = integration.digest(integration.canonical({k: v for k, v in data.items() if k != "payload_sha256"}))
        with self.assertRaisesRegex(integration.IntegrationError, "after integration"):
            integration.validate_snapshot(self.root, data)

    def test_new_enrollment_cannot_forge_earlier_day_or_legacy_publication(self):
        self.prepare_enrollment()
        scope = integration.read(self.root / "config/scope.json")
        unit = scope["units"][-1]
        unit["first_recorded_date"] = "2020-01-01"
        integration.write(self.root / "config/scope.json", scope)
        with self.assertRaisesRegex(integration.IntegrationError, "UTC time"):
            self.fixture.run()
        unit.update(first_recorded_date="2020-01-01", date_basis="published-progress-snapshot-date",
                    acceptance_evidence={"receipt_sha256":"1" * 64,"publication_snapshot_sha256":"2" * 64})
        integration.write(self.root / "config/scope.json", scope)
        with self.assertRaisesRegex(integration.IntegrationError, "historical publication"):
            self.fixture.run()

    def test_failed_enrollment_leaves_scope_unchanged(self):
        import enroll
        self.fixture.fail = True
        prior = (self.root / "config/scope.json").read_bytes()
        with patch.object(enroll, "integration", integration), patch.object(integration, "load_gate", return_value=SimpleNamespace(run_recipe=self.fixture.run_recipe)):
            with self.assertRaisesRegex(integration.IntegrationError, "did not match"):
                enroll.enroll(self.root, "config/recipes/pilot.local.json", "config/recipes/pilot.example.json", "Source/pilot.cpp")
        self.assertEqual(prior, (self.root / "config/scope.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
