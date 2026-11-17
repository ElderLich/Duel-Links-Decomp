"""Embedded switch data must not become invented numeric card references."""
import struct
import unittest

from Decomp.Tools.Native.NativeCardRecords import PeImage
from Decomp.Tools.Native.NativeJumpTables import find_jump_tables


class SwitchImage(PeImage):
    def __init__(self, copy_index=True):
        self.base = 0x180000000
        self.data = bytearray(b"\xcc" * 0x300)
        self.sections = [dict(name=".text", address=self.base, offset=0,
                              size=len(self.data), fileSize=len(self.data), flags=0x60000020)]
        # As in the real 4F9690 dispatcher, the 64-bit copied index was first
        # sign-extended from a dword. Unsigned ECX <=6 then proves high bits 0.
        self.data[0xf9:0x100] = bytes.fromhex("48 63 88 d4 0b 00 00")
        compare = bytes.fromhex("83 f9 06" if copy_index else "83 f8 06")
        code = compare + bytes.fromhex("0f 87") + struct.pack("<i", 0x230 - 0x109)
        if copy_index:
            code += bytes.fromhex("48 8b c1")
        lea = 0x100 + len(code)
        code += bytes.fromhex("48 8d 0d") + struct.pack("<i", -(lea + 7))
        if not copy_index:
            code += bytes.fromhex("48 98")
        code += bytes.fromhex("8b 94 81") + struct.pack("<I", 0x200)
        code += bytes.fromhex("48 03 d1 ff e2")
        self.data[0x100:0x100+len(code)] = code
        # Real switch arms continue after earlier RETs. A first-RET cutoff
        # would incorrectly discard these code paths.
        for i in range(7):
            offset = 0x140 + i * 0x10
            self.data[offset:offset+6] = b"\xb8" + struct.pack("<I", 23380+i) + b"\xc3"
        struct.pack_into("<7I", self.data, 0x200, *[0x140+i*0x10 for i in range(7)])

    def function_ranges(self):
        return [(self.base+0xf9, self.base+0x230)]


class NativeJumpTableTests(unittest.TestCase):
    @staticmethod
    def remapped_image():
        image = SwitchImage()
        # CMP R8D,28; JA default; LEA RCX,imagebase; MOVSXD RAX,R8D;
        # MOVZX EAX,byte [RCX+RAX+remap]; MOV EDX,[RCX+RAX*4+targets].
        # This is the real 23985 false-positive switch shape, with small RVAs.
        image.data[0xf9:0x140] = b"\x90" * (0x140-0xf9)
        code = bytes.fromhex("41 83 f8 1c 0f 87") + struct.pack("<i", 0x230-0x10a)
        code += bytes.fromhex("48 8d 0d") + struct.pack("<i", -(0x10a+7))
        code += bytes.fromhex("49 63 c0 0f b6 84 01") + struct.pack("<I", 0x260)
        code += bytes.fromhex("8b 94 81") + struct.pack("<I", 0x200)
        code += bytes.fromhex("48 03 d1 ff e2")
        image.data[0x100:0x100+len(code)] = code
        image.data[0x260:0x27d] = bytes(range(7))*4 + b"\x06"
        # Executable arm between the target and index tables must survive.
        image.data[0x240:0x246] = b"\xb8" + struct.pack("<I",23940) + b"\xc3"
        image.function_ranges = lambda: [(image.base+0xf9,image.base+0x290)]
        return image

    def test_remapped_switch_excludes_only_both_exact_tables_and_keeps_intervening_code(self):
        from Decomp.Tools.Native.NativeInstructionInventory import scan_pe_immediates
        image = self.remapped_image()
        tables = find_jump_tables(image)
        self.assertEqual(1,len(tables))
        self.assertEqual(7,tables[0]["entries"])
        self.assertEqual((image.base+0x260,image.base+0x27d),
                         (tables[0]["indexTables"][0]["tableVA"],tables[0]["indexTables"][0]["endVA"]))
        result, coverage = scan_pe_immediates(image)
        self.assertEqual(1, result[23940]["count"])
        self.assertTrue(all(result[cid]["count"] == 1 for cid in range(23380,23387)))
        self.assertEqual(57,coverage["excludedJumpTableBytes"])
        self.assertEqual(1,coverage["excludedSwitchIndexTables"])

    def test_remap_rejects_unknown_high_bits_wrong_base_unbacked_or_overlapping_tables(self):
        for mutation in ("unknown-high-bits", "wrong-remap-base", "signed-remap", "unbacked-remap",
                         "overlap", "target-in-remap", "out-of-range-remap-value", "signed-bound"):
            with self.subTest(mutation=mutation):
                image = self.remapped_image()
                if mutation == "unknown-high-bits":
                    image.data[0x111:0x114] = bytes.fromhex("49 8b c0")  # MOV RAX,R8
                elif mutation == "wrong-remap-base":
                    image.data[0x117] = 0x02  # RDX + RAX instead of RCX + RAX
                elif mutation == "signed-remap":
                    image.data[0x115] = 0xbe  # MOVSX may produce negative indices
                elif mutation == "unbacked-remap":
                    struct.pack_into("<I",image.data,0x118,0x2f0)
                elif mutation == "overlap":
                    struct.pack_into("<I",image.data,0x118,0x204)
                elif mutation == "target-in-remap":
                    struct.pack_into("<I",image.data,0x200,0x260)
                elif mutation == "out-of-range-remap-value":
                    image.data[0x260] = 255
                else:
                    image.data[0x105] = 0x8f
                self.assertEqual([],find_jump_tables(image))

    def test_copied_index_and_signed_extension_forms_have_exact_table_bounds(self):
        for copy_index in (True, False):
            with self.subTest(copy_index=copy_index):
                image = SwitchImage(copy_index)
                rows = find_jump_tables(image)
                self.assertEqual(1, len(rows))
                self.assertEqual((0x200, 7, image.base+0x21c),
                                 (rows[0]["tableRVA"], rows[0]["entries"], rows[0]["endVA"]))
                self.assertEqual([image.base+0x140+i*0x10 for i in range(7)], rows[0]["targetVAs"])

    def test_without_unsigned_bound_or_image_base_proof_nothing_is_hidden(self):
        for mutation in ("signed-branch", "wrong-base", "unbounded", "changed-index", "intervening-call"):
            with self.subTest(mutation=mutation):
                image = SwitchImage()
                if mutation == "signed-branch":
                    image.data[0x104] = 0x8f  # JG is not the required unsigned bound.
                elif mutation == "wrong-base":
                    image.data[0x10f] ^= 1
                elif mutation == "unbounded":
                    image.data[0x100:0x103] = b"\x90"*3
                elif mutation == "changed-index":
                    image.data[0x109:0x10c] = bytes.fromhex("48 ff c0")
                else:
                    image.data[0x109:0x10e] = b"\xe8\0\0\0\0"
                self.assertEqual([], find_jump_tables(image))

    def test_out_of_image_or_self_referential_targets_reject_entire_table(self):
        for target in (0x9999, 0x200, 0x80):
            with self.subTest(target=target):
                image = SwitchImage()
                struct.pack_into("<I", image.data, 0x208, target)
                self.assertEqual([], find_jump_tables(image))

    def test_loaded_target_cannot_clobber_image_base_before_add(self):
        image = SwitchImage()
        # MOV ECX,[RCX+RAX*4+table]; ADD RCX,RCX; JMP RCX is not an
        # image-relative branch, because MOV ECX destroyed the image base.
        image.data[0x114] = 0x8c
        image.data[0x11c] = 0xc9
        image.data[0x11e] = 0xe1
        self.assertEqual([], find_jump_tables(image))

    def test_32_bit_compare_does_not_bound_unknown_high_index_bits(self):
        image = SwitchImage()
        image.data[0xf9:0x100] = b"\x90" * 7
        self.assertEqual([], find_jump_tables(image))
        # An actual dword copy clears RAX's high half and is safe.
        image.data[0x109:0x10c] = bytes.fromhex("8b c1 90")
        self.assertEqual(1, len(find_jump_tables(image)))

    def test_index_definition_survives_unrelated_prologue_saves_but_not_clobber(self):
        image = SwitchImage()
        # Same MOVSXD proof as the original fixture, before six unrelated
        # register saves as in the real 28416 switch-data false positive.
        image.data[0xd0:0xd7] = bytes.fromhex("48 63 88 d4 0b 00 00")
        image.data[0xd7:0xf5] = bytes.fromhex("48 89 5c 24 10") * 6
        image.data[0xf5:0x100] = bytes.fromhex("0f 1f 84 00 00 00 00 00 0f 1f 00")
        image.function_ranges = lambda: [(image.base+0xd0,image.base+0x230)]
        self.assertEqual(1,len(find_jump_tables(image)))
        image.data[0xfd:0x100] = bytes.fromhex("48 8b ce")  # Unknown 64-bit RCX
        self.assertEqual([],find_jump_tables(image))

    def test_32_bit_add_or_image_base_lea_is_not_64_bit_address_arithmetic(self):
        for offset in (0x10c, 0x11a):
            with self.subTest(offset=offset):
                image = SwitchImage()
                image.data[offset] = 0x40  # REX without W: truncate the base.
                self.assertEqual([], find_jump_tables(image))

    def test_data_must_fit_a_single_executable_section(self):
        image = SwitchImage()
        image.sections[0]["fileSize"] = 0x210
        self.assertEqual([], find_jump_tables(image))
        image = SwitchImage()
        image.sections[0]["flags"] = 0x40000040
        self.assertEqual([], find_jump_tables(image))


if __name__ == "__main__":
    unittest.main()
