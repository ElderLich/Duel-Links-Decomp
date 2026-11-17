"""Failure-path tests with minimal PE/ELF fixtures, independent of proprietary inputs."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

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
    if relocation is not None:
        struct.pack_into("<II", data, opt + 112 + 5 * 8, 0x2000, 12)
        struct.pack_into("<IIHH", data, 0x400, 0x1000, 12, relocation << 12 | 1, 0)
    return bytes(data)


def elf(value=8, relocation=None):
    data = bytearray(0x400)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, 183, 1)
    struct.pack_into("<Q", data, 40, 0x300)
    struct.pack_into("<HHH", data, 58, 64, 4, 1)
    struct.pack_into("<II", data, 0x100, 0x52800000 | value << 5, 0xD65F03C0)
    names = b"\0.shstrtab\0.text\0.rela.text\0"
    data[0x200:0x200 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", data, 0x340, 1, 3, 0, 0, 0x200, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 0x380, 11, 1, 6, 0x1000, 0x100, 8, 0, 0, 4, 0)
    if relocation is not None:
        struct.pack_into("<QQq", data, 0x280, 0x1000, relocation, 0)
        struct.pack_into("<IIQQQQIIQQ", data, 0x3C0, 17, 4, 0, 0, 0x280, 24, 0, 2, 8, 24)
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
        with self.assertRaisesRegex(gate.GateError, "executable"):
            image.function({"rva": 0x2000, "boundary": "leaf-return-u32"})

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


if __name__ == "__main__":
    unittest.main()
