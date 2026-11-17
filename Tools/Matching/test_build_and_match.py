"""Failure-path tests with minimal PE/ELF fixtures, independent of proprietary inputs."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("matching_gate", Path(__file__).with_name("build_and_match.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def pe(value=7, relocation=None):
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 240, 0x2022)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<Q", data, opt + 24, 0x180000000)
    struct.pack_into("<I", data, opt + 108, 16)
    for pos, name, rva, raw, flags in [(0x188, b".text", 0x1000, 0x200, 0x60000020), (0x1B0, b".reloc", 0x2000, 0x400, 0x42000040)]:
        data[pos:pos + len(name)] = name
        struct.pack_into("<IIII", data, pos + 8, 0x200, rva, 0x200, raw)
        struct.pack_into("<I", data, pos + 36, flags)
    data[0x200:0x206] = b"\xB8" + struct.pack("<I", value) + b"\xC3"
    # Named export supplies an entry anchor independently of leaf instruction
    # decoding. Keep it separate from the relocation fixture at offset 0x400.
    struct.pack_into("<II", data, opt + 112, 0x2040, 0x80)
    struct.pack_into("<IIHHIIIIIII", data, 0x440, 0, 0, 0, 0, 0, 1, 1, 1, 0x2070, 0x2074, 0x2078)
    struct.pack_into("<IIH", data, 0x470, 0x1000, 0x207C, 0)
    data[0x47C:0x481] = b"leaf\0"
    if relocation is not None:
        struct.pack_into("<II", data, opt + 112 + 5 * 8, 0x2000, 12)
        struct.pack_into("<IIHH", data, 0x400, 0x1000, 12, relocation << 12 | 1, 0)
    return bytes(data)


def elf(value=8, relocation=None):
    data = bytearray(0x440)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, 183, 1)
    struct.pack_into("<Q", data, 40, 0x300)
    struct.pack_into("<HHH", data, 58, 64, 5, 1)
    struct.pack_into("<II", data, 0x100, 0x52800000 | value << 5, 0xD65F03C0)
    names = b"\0.shstrtab\0.text\0.rela.text\0.symtab\0leaf\0"
    data[0x200:0x200 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x340, 1, 3, 0, 0, 0x200, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x380, 11, 1, 6, 0x1000, 0x100, 8, 0, 0, 4, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x400, names.index(b".symtab"), 2, 0, 0, 0x240, 48, 1, 1, 8, 24)
    struct.pack_into("<IBBHQQ", data, 0x258, names.index(b"leaf"), 0x12, 0, 2, 0x1000, 8)
    if relocation is not None:
        struct.pack_into("<QQq", data, 0x280, 0x1000, relocation, 0)
        struct.pack_into("<IIQQQQIIQQ", data, 0x3C0, 17, 4, 0, 0, 0x280, 24, 0, 2, 8, 24)
    return bytes(data)


def pe_native(body: bytes, rva=0x1000):
    """Independent known-size PE fixture; .pdata deliberately legitimizes size,
    but does not legitimize moving PC-relative instruction operands unchanged.
    """
    data = bytearray(pe())
    struct.pack_into("<I", data, 0x188 + 12, rva)
    data[0x200:0x200 + len(body)] = body
    struct.pack_into("<II", data, 0x98 + 112 + 3 * 8, 0x2000, 12)
    struct.pack_into("<III", data, 0x400, rva, rva + len(body), 0)
    return bytes(data)


def elf_native(body: bytes, va=0x1000):
    data = bytearray(elf())
    data[0x100:0x100 + len(body)] = body
    struct.pack_into("<IIQQQQIIQQ", data, 0x380, 11, 1, 6, va, 0x100, len(body), 0, 0, 4, 0)
    struct.pack_into("<QQ", data, 0x258 + 8, va, len(body))
    return bytes(data)


def coff(directives=b" /EXPORT:leaf"):
    data = bytearray(0x1A0)
    struct.pack_into("<HHIIIHH", data, 0, 0x8664, 2, 0, 0x180, 1, 0, 0)
    struct.pack_into("<8sIIIIIIHHI", data, 20, b".text", 0, 0, 6, 0x100, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", data, 60, b".drectve", 0, 0, len(directives), 0x120, 0, 0, 0, 0, 0x00100A00)
    data[0x100:0x106] = b"\xB8\x07\0\0\0\xC3"
    data[0x120:0x120 + len(directives)] = directives
    struct.pack_into("<8sIhHBB", data, 0x180, b"leaf", 0, 1, 0x20, 2, 0)
    struct.pack_into("<I", data, 0x192, 4)
    return bytes(data)


class MatchingGateTests(unittest.TestCase):
    def test_exact_pe_leaf_matches_and_changed_immediate_fails(self):
        function = {"name": "leaf", "original": {"rva": "0x1000", "boundary": "leaf-return-u32"}, "rebuilt": {"rva": "0x1000", "boundary": "leaf-return-u32"}}
        self.assertEqual(gate.compare_functions(gate.Image(pe()), gate.Image(pe()), function)["status"], "matched")
        mismatch = gate.compare_functions(gate.Image(pe()), gate.Image(pe(9)), function)
        self.assertEqual(mismatch["status"], "mismatch")
        self.assertEqual(mismatch["firstDifferentByte"], 1)

    def test_pe_fixup_overlap_is_not_masked(self):
        with self.assertRaisesRegex(gate.GateError, "relocation fixup"):
            gate.Image(pe(relocation=10)).function({"rva": 0x1000, "boundary": "leaf-return-u32"})

    def test_unknown_relocation_refuses_comparison(self):
        with self.assertRaisesRegex(gate.GateError, "Unresolved relocation"):
            gate.Image(pe(relocation=7)).function({"rva": 0x1000, "boundary": "leaf-return-u32"})

    def test_unproven_or_truncated_sizes_cannot_pass(self):
        image = gate.Image(pe())
        with self.assertRaisesRegex(gate.GateError, "Unknown/unproven"):
            image.function({"rva": 0x1000, "size": 6})
        with self.assertRaisesRegex(gate.GateError, "disagrees"):
            image.function({"rva": 0x1000, "boundary": "leaf-return-u32", "size": 5})

    def test_missing_export_and_noncode_range_rejected(self):
        image = gate.Image(pe())
        with self.assertRaisesRegex(gate.GateError, "Missing local"):
            image.function({"export": "absent", "boundary": "leaf-return-u32"})
        image.exports["noncode"] = image.base + 0x2000
        with self.assertRaisesRegex(gate.GateError, "executable"):
            image.function({"export": "noncode", "boundary": "leaf-return-u32"})

    def test_elf_leaf_and_relocation_checks(self):
        function = {"va": 0x1000, "boundary": "leaf-return-u32"}
        self.assertEqual(gate.Image(elf()).function(function)["size"], 8)
        with self.assertRaisesRegex(gate.GateError, "relocation fixup"):
            gate.Image(elf(relocation=1027)).function(function)
        with self.assertRaisesRegex(gate.GateError, "Unresolved relocation"):
            gate.Image(elf(relocation=9999)).function(function)

    def test_wrong_target_digest_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.dll"
            path.write_bytes(pe())
            target = {"path": str(path), "sha256": "0" * 64, "bytes": path.stat().st_size, "format": "pe", "architecture": "amd64"}
            with self.assertRaisesRegex(gate.GateError, "identity mismatch"):
                gate.pinned_target({"fixture": target}, "fixture")

    def test_truncated_binary_rejected(self):
        with self.assertRaises(gate.GateError):
            gate.Image(pe()[:0x220])

    def test_architecture_mismatch_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "architecture"):
            gate.compare_functions(gate.Image(pe()), gate.Image(elf()), {})

    def test_equal_rel32_call_bytes_at_different_rvas_are_not_a_match(self):
        body = b"\xE8\x05\0\0\0\xC3"
        left, right = gate.Image(pe_native(body)), gate.Image(pe_native(body, 0x3000))
        self.assertEqual(left.data[0x200:0x206], right.data[0x200:0x206])
        self.assertNotEqual(left.base + 0x1000 + 5 + 5, right.base + 0x3000 + 5 + 5)
        spec = {"name": "unsafe", "original": {"rva": 0x1000, "boundary": "unwind"}, "rebuilt": {"rva": 0x3000, "boundary": "unwind"}}
        with self.assertRaisesRegex(gate.GateError, "PC-relative"):
            gate.compare_functions(left, right, spec)

    def test_rip_load_and_relative_branch_with_known_extent_are_unsupported(self):
        for body in (b"\x48\x8B\x05\x10\0\0\0\xC3", b"\xE9\x10\0\0\0", b"\xEB\x02\x90\x90\xC3"):
            with self.subTest(body=body), self.assertRaisesRegex(gate.GateError, "Unsupported acceptance"):
                gate.Image(pe_native(body)).function({"rva": 0x1000, "boundary": "unwind"})
            with self.assertRaisesRegex(gate.GateError, "instruction grammar"):
                gate.Image(pe_native(body)).function({"rva": 0x1000, "boundary": "leaf-return-u32"})

    def test_arm64_pc_relative_symbol_bodies_are_not_accepted(self):
        # BL, ADRP, and literal LDR each encode an address relative to placement.
        for instruction in (0x94000001, 0x90000000, 0x58000040):
            body = struct.pack("<II", instruction, 0xD65F03C0)
            left, right = gate.Image(elf_native(body)), gate.Image(elf_native(body, 0x3000))
            self.assertEqual(left.symbol_sizes[0x1000], 8)
            function = {"name": "unsafe", "original": {"va": 0x1000, "boundary": "symbol"}, "rebuilt": {"va": 0x3000, "boundary": "symbol"}}
            with self.subTest(instruction=instruction), self.assertRaisesRegex(gate.GateError, "Unsupported acceptance"):
                gate.compare_functions(left, right, function)

    def test_leaf_cannot_truncate_larger_symbol_or_unwind_range(self):
        for image, address in ((gate.Image(pe_native(b"\xB8\x07\0\0\0\xC3\x90")), {"rva": 0x1000}),
                               (gate.Image(elf_native(struct.pack("<III", 0x52800100, 0xD65F03C0, 0xD503201F))), {"va": 0x1000})):
            with self.assertRaisesRegex(gate.GateError, "extent"):
                image.function({**address, "boundary": "leaf-return-u32"})

    def test_complete_leaf_can_match_at_different_placements(self):
        body = b"\xB8\x07\0\0\0\xC3"
        spec = {"name": "leaf", "original": {"rva": 0x1000, "boundary": "leaf-return-u32"}, "rebuilt": {"rva": 0x3000, "boundary": "leaf-return-u32"}}
        self.assertEqual(gate.compare_functions(gate.Image(pe_native(body)), gate.Image(pe_native(body, 0x3000)), spec)["status"], "matched")

    def test_pe_interior_return_suffix_is_not_a_function(self):
        image = gate.Image(pe_native(b"\x90\xB8\x07\0\0\0\xC3"))
        self.assertEqual(image.unwind[image.base + 0x1000], 7)
        with self.assertRaisesRegex(gate.GateError, "inside a known function"):
            image.function({"rva": 0x1001, "boundary": "leaf-return-u32"})
        # A second export at the suffix cannot override a containing extent.
        image.exports["misleading_alias"] = image.base + 0x1001
        with self.assertRaisesRegex(gate.GateError, "inside a known function"):
            image.function({"export": "misleading_alias", "boundary": "leaf-return-u32"})

    def test_elf_interior_return_suffix_is_not_a_function(self):
        image = gate.Image(elf_native(struct.pack("<III", 0xD503201F, 0x52800100, 0xD65F03C0)))
        self.assertEqual(image.symbol_sizes[0x1000], 12)
        with self.assertRaisesRegex(gate.GateError, "inside a known function"):
            image.function({"va": 0x1004, "boundary": "leaf-return-u32"})
        image.symbol_sizes[0x1004] = 8
        with self.assertRaisesRegex(gate.GateError, "inside a known function"):
            image.function({"va": 0x1004, "boundary": "leaf-return-u32"})

    def test_unanchored_pe_return_block_cannot_match(self):
        raw = bytearray(pe())
        struct.pack_into("<II", raw, 0x98 + 112, 0, 0)
        image = gate.Image(bytes(raw))
        self.assertEqual(image.exports, {})
        with self.assertRaisesRegex(gate.GateError, "trusted start anchor"):
            image.function({"rva": 0x1000, "boundary": "leaf-return-u32"})

    def test_zero_sized_elf_symbol_cannot_anchor_a_return_block(self):
        raw = bytearray(elf())
        struct.pack_into("<Q", raw, 0x258 + 16, 0)
        image = gate.Image(bytes(raw))
        self.assertIn("leaf", image.exports)
        self.assertEqual(image.symbol_sizes, {})
        with self.assertRaisesRegex(gate.GateError, "trusted start anchor"):
            image.function({"export": "leaf", "boundary": "leaf-return-u32"})

    def test_return_leaf_reports_independent_entry_anchor(self):
        self.assertEqual(gate.Image(pe()).function({"export": "leaf", "boundary": "leaf-return-u32"})["entryAnchor"], "pe-export")
        self.assertEqual(gate.Image(elf()).function({"export": "leaf", "boundary": "leaf-return-u32"})["entryAnchor"], "elf-function-symbol")


class BuildClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "unit.cpp"
        self.source.write_text("unsigned int leaf() { return 7; }\n", encoding="utf-8")
        self.header = self.root / "unit.h"
        self.header.write_text("#pragma once\n", encoding="utf-8")
        self.build = self.root / "build"
        self.build.mkdir()
        self.tools = {"cc": {"path": str(self.root / "cl.exe")}, "link": {"path": str(self.root / "link.exe")}}
        self.object = self.build / "unit.obj"
        self.output = self.build / "unit.dll"
        self.commands = [[self.tools["cc"]["path"], "/c", "/Zl", "/O2", f"/Fo{self.object}", str(self.source)],
                         [self.tools["link"]["path"], "/DLL", "/NOENTRY", "/NODEFAULTLIB", "/MACHINE:X64", f"/OUT:{self.output}", str(self.object)]]

    def dependency(self, **changes):
        data = {"Source": str(self.source), "Includes": [str(self.header)], "ProvidedModule": "", "ImportedModules": [], "ImportedHeaderUnits": []}
        data.update(changes)
        path = self.build / "dependencies.json"
        path.write_text(json.dumps({"Version": "1.2", "Data": data}), encoding="utf-8")
        return path

    def plan(self, commands=None):
        return gate.closed_build_plan(commands or self.commands, self.tools, {self.source}, self.build, self.output)

    def test_dependency_record_closes_declared_source_and_transitive_headers(self):
        record, observed = gate.parse_source_dependencies(self.dependency(), self.source, {self.source, self.header})
        gate.require_closed_inputs({self.source, self.header}, observed)
        self.assertEqual(observed, {self.source, self.header})
        self.assertEqual(record["version"], "1.2")

    def test_undeclared_header_is_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "Undeclared"):
            gate.parse_source_dependencies(self.dependency(), self.source, {self.source})

    def test_unused_declared_header_is_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "not consumed"):
            gate.require_closed_inputs({self.source, self.header}, {self.source})

    def test_wrong_source_and_relative_dependencies_are_rejected(self):
        with self.assertRaisesRegex(gate.GateError, "Source differs"):
            gate.parse_source_dependencies(self.dependency(Source=str(self.header)), self.source, {self.source, self.header})
        with self.assertRaisesRegex(gate.GateError, "absolute"):
            gate.parse_source_dependencies(self.dependency(Includes=["unit.h"]), self.source, {self.source, self.header})

    def test_unknown_or_compiled_dependency_records_are_rejected(self):
        for changes in ({"PCH": "unit.pch"}, {"ImportedModules": [{"Name": "hidden", "BMI": "hidden.ifc"}]},
                        {"ImportedHeaderUnits": ["hidden.ifc"]}, {"ProvidedModule": "module"}, {"UnknownInput": "file.bin"}):
            with self.subTest(changes=changes), self.assertRaises(gate.GateError):
                gate.parse_source_dependencies(self.dependency(**changes), self.source, {self.source, self.header})
        path = self.dependency()
        path.write_text('{"Version":"99","Data":{}}', encoding="utf-8")
        with self.assertRaisesRegex(gate.GateError, "schema"):
            gate.parse_source_dependencies(path, self.source, {self.source})

    def test_missing_dependency_file_cannot_pass(self):
        with self.assertRaises(FileNotFoundError):
            gate.parse_source_dependencies(self.build / "missing.json", self.source, {self.source})

    def test_unix_absolute_source_argument_is_preserved(self):
        self.assertEqual(gate.source_arguments(["cc", "/nologo", "/tmp/project/unit.cpp"]), {Path("/tmp/project/unit.cpp").resolve()})

    def test_plan_adds_dependency_record_to_actual_compiler_command(self):
        plan = self.plan()
        self.assertEqual(plan[0]["source"], self.source)
        self.assertEqual(plan[0]["argv"][-2:], ["/sourceDependencies", str(self.build / "source-dependencies-0.json")])

    def test_compiler_injection_and_opaque_inputs_are_rejected(self):
        for flag in ("@hidden.rsp", "/B1evil.exe", "/B2evil.exe", "/GL", "/Yuheader.h", "/FIhidden.h", "/sourceDependencies", "/clr", "/link"):
            commands = [list(self.commands[0]) + [flag], list(self.commands[1])]
            with self.subTest(flag=flag), self.assertRaisesRegex(gate.GateError, "Unsupported compiler"):
                self.plan(commands)

    def test_linker_rejects_prebuilt_objects_libraries_and_reference_rewrites(self):
        for arg in (str(self.root / "hidden.obj"), str(self.root / "hidden.lib"), "/DEFAULTLIB:evil", "/ALTERNATENAME:leaf=evil", "/SECTION:.data,ERW", "@hidden.rsp"):
            with self.subTest(arg=arg), self.assertRaisesRegex(gate.GateError, "Unsupported linker"):
                self.plan([self.commands[0], self.commands[1] + [arg]])

    def test_missing_or_duplicate_source_cannot_pass(self):
        with self.assertRaisesRegex(gate.GateError, "one declared source"):
            self.plan([self.commands[0][:-1], self.commands[1]])
        with self.assertRaisesRegex(gate.GateError, "Duplicate compiler source"):
            self.plan([self.commands[0] + [str(self.source)], self.commands[1]])

    def test_outputs_cannot_escape_fresh_build(self):
        commands = [list(self.commands[0]), self.commands[1]]
        commands[0][4] = f"/Fo{self.root / 'outside.obj'}"
        with self.assertRaisesRegex(gate.GateError, "fresh build"):
            self.plan(commands)

    def test_byte_emission_heuristics_and_comment_handling(self):
        self.source.write_text("// __asm and _emit describe discarded experiments\nunsigned int leaf(){return 7;}\n", encoding="utf-8")
        self.assertEqual(gate.readable_source_policy([gate.identity(self.source)])["status"], "passed")
        for source in ('__asm { _emit 0xc3 }', '__a\\\nsm { nop }', '#pragma section(".text",execute)',
                       '__declspec(allocate(".text")) int code;', '__pragma(comment(linker,"/section:.data,ERW"))',
                       'unsigned char code[] = {0xb8, 7, 0, 0, 0, 0xc3};', '#define JOIN(a,b) a ## b', '#import "hidden.tlb"'):
            self.source.write_text(source, encoding="utf-8")
            with self.subTest(source=source), self.assertRaisesRegex(gate.GateError, "heuristic"):
                gate.readable_source_policy([gate.identity(self.source)])

    def test_compiler_dependency_omission_is_rejected(self):
        required = [self.root / "cl.exe", self.root / "link.exe", self.root / "backend.dll"]
        with mock.patch.object(gate, "discover_msvc_dependencies", return_value=(required, [], [])):
            with self.assertRaisesRegex(gate.GateError, "undeclared"):
                gate.validate_tool_dependencies(self.tools, [], {self.source})
            self.assertEqual(gate.validate_tool_dependencies(self.tools, [{"path": str(required[-1])}], {self.source})["localFileCount"], 3)

    def test_only_ordinary_compiler_coff_without_injected_directives_is_accepted(self):
        self.object.write_bytes(coff())
        self.assertEqual(gate.validate_coff(self.object)["path"], str(self.object))
        for raw in (pe(), b"not an object", coff(b" /DEFAULTLIB:evil.lib"), coff(b" /EXPORT:leaf=forged")):
            self.object.write_bytes(raw)
            with self.subTest(raw=raw[:8]), self.assertRaises(gate.GateError):
                gate.validate_coff(self.object)


if __name__ == "__main__":
    unittest.main()
