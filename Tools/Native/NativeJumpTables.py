"""Recognize bounded AMD64 RVA switch tables before decoding them as code.

PE unwind spans can include a compiler's jump-table bytes after an epilogue.
Only checked compare/JA, image-base LEA, indexed load, ADD and indirect JMP
forms are recognized, optionally with a bounded byte-index remap before the
RVA load. Unrecognized indirect branches remain unclassified.
"""
from bisect import bisect_right

from Decomp.Tools.Native.NativeCardRecords import executable, section_at


def _family(name):
    aliases = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "ebx": "rbx",
               "esp": "rsp", "ebp": "rbp", "esi": "rsi", "edi": "rdi"}
    if name.startswith("r") and name[1:-1].isdigit() and name.endswith("d"):
        return name[:-1]
    return aliases.get(name, name)


_REG64 = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"} | {f"r{i}" for i in range(8, 16)}


def find_jump_tables(image, ranges=None):
    """Return exact, evidence-backed data spans with their dispatch and targets.

    The table length comes from the unsigned upper-bound check, never from a
    run of pointer-looking bytes. All entries must point into file-backed code
    covered by PE unwind ranges, outside the table. Tables and targets must be
    within 64 KiB of the dispatch; this is a conservative supported-form limit.
    """
    import capstone
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

    ranges = sorted(ranges if ranges is not None else image.function_ranges())
    starts = [start for start, _ in ranges]
    lite = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    detail = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    detail.detail = True
    found = {}

    def covered(address):
        index = bisect_right(starts, address) - 1
        return index >= 0 and address < ranges[index][1]

    def reg(instruction, operand):
        return _family(instruction.reg_name(operand.reg)) if operand.type == X86_OP_REG else None

    def decode(item):
        address, size, _, _ = item
        return next(detail.disasm(image.span(image.file_offset(address), size), address), None)

    def bounded_high_bits(instructions, compare_index, family):
        # A 32-bit compare does not constrain the upper half of a 64-bit
        # address index. Require a preceding defining write, not just an alias.
        # Prologues can save several non-index registers between MOVSXD and
        # CMP. Stop at control flow or the first index write, not four items.
        for item in reversed(instructions[max(0, compare_index - 16):compare_index]):
            instruction = decode(item)
            if not instruction or instruction.mnemonic.startswith("j") or instruction.mnemonic in ("call", "ret", "retf"):
                return False
            _, writes = instruction.regs_access()
            if family not in {_family(instruction.reg_name(register)) for register in writes}:
                continue
            operands = instruction.operands
            if not operands or reg(instruction, operands[0]) != family:
                return False
            if operands[0].size == 4:
                return True  # An AMD64 32-bit register write clears high bits.
            return (instruction.mnemonic == "movsxd" and len(operands) == 2
                    and operands[0].size == 8 and operands[1].size == 4)
        return False

    for start, end in ranges:
        offset = image.file_offset(start)
        if offset is None or image.file_offset(end - 1) is None:
            continue
        instructions = list(lite.disasm_lite(image.span(offset, end - start), start))
        for index, item in enumerate(instructions):
            if item[2] != "jmp" or index < 4 or instructions[index - 1][2] != "add" or instructions[index - 2][2] != "mov":
                continue
            jump, add, load = map(decode, (item, instructions[index - 1], instructions[index - 2]))
            if not (jump and add and load and len(jump.operands) == 1
                    and len(add.operands) == len(load.operands) == 2):
                continue
            destination = reg(jump, jump.operands[0])
            if (not destination or reg(add, add.operands[0]) != destination
                    or reg(load, load.operands[0]) != destination
                    or load.operands[0].size != 4 or load.operands[1].type != X86_OP_MEM):
                continue
            memory = load.operands[1].mem
            base = _family(load.reg_name(memory.base))
            source_index = _family(load.reg_name(memory.index))
            if (memory.scale != 4 or not memory.index or not memory.base
                    or load.reg_name(memory.base) not in _REG64 or load.reg_name(memory.index) not in _REG64
                    or memory.segment or base == source_index or destination == base
                    or jump.operands[0].size != 8 or any(op.size != 8 for op in add.operands)
                    or reg(add, add.operands[1]) != base):
                continue
            # Trace the bounded index through register copies / CDQE only;
            # independently require an image-base LEA for the address base.
            bound = None
            base_proven = False
            index_from_32_bits = False
            remap = None
            cursor = index - 3
            for previous_index in range(cursor, max(-1, cursor - 9), -1):
                previous = decode(instructions[previous_index])
                if previous is None:
                    break
                operands = previous.operands
                if previous.mnemonic == "lea" and len(operands) == 2 and reg(previous, operands[0]) == base:
                    mem = operands[1].mem if operands[1].type == X86_OP_MEM else None
                    if (base_proven or operands[0].size != 8 or not mem or previous.reg_name(mem.base) != "rip"
                            or mem.index or previous.address + previous.size + mem.disp != image.base
                            or source_index == base):
                        break
                    base_proven = True
                elif previous.mnemonic == "movzx" and len(operands) == 2:
                    mem = operands[1].mem if operands[1].type == X86_OP_MEM else None
                    # One byte lookup produces the target-table index. Prove
                    # its own input bound separately; MOVZX cannot repair an
                    # unbounded address used to read that byte.
                    if (remap is not None or reg(previous, operands[0]) != source_index
                            or operands[0].size != 4 or operands[1].size != 1 or not mem
                            or previous.reg_name(mem.base) not in _REG64
                            or previous.reg_name(mem.index) not in _REG64
                            or _family(previous.reg_name(mem.base)) != base
                            or mem.scale != 1 or mem.segment or source_index == base):
                        break
                    remap = image.base + mem.disp
                    source_index = _family(previous.reg_name(mem.index))
                    index_from_32_bits = False
                    if source_index == base:
                        break
                elif previous.mnemonic == "movsxd" and len(operands) == 2:
                    if (reg(previous, operands[0]) != source_index or operands[0].size != 8
                            or operands[1].type != X86_OP_REG or operands[1].size != 4):
                        break
                    source_index = reg(previous, operands[1])
                    index_from_32_bits = True
                elif previous.mnemonic == "mov" and len(operands) == 2 and all(o.type == X86_OP_REG for o in operands):
                    dst, src = (reg(previous, operand) for operand in operands)
                    if dst == source_index:
                        if operands[0].size not in (4, 8) or operands[1].size != operands[0].size:
                            break
                        index_from_32_bits |= operands[0].size == 4
                        source_index = src
                    elif dst == base:
                        break
                elif previous.mnemonic == "cdqe" and source_index == "rax":
                    index_from_32_bits = True
                elif previous.mnemonic == "nop":
                    pass
                elif previous.mnemonic == "ja" and previous_index > 0 and len(operands) == 1 and operands[0].type == X86_OP_IMM:
                    compare = decode(instructions[previous_index - 1])
                    if (compare and compare.mnemonic == "cmp" and len(compare.operands) == 2
                            and reg(compare, compare.operands[0]) == source_index
                            and (compare.operands[0].size == 8
                                 or compare.operands[0].size == 4 and (index_from_32_bits
                                     or bounded_high_bits(instructions, previous_index - 1, source_index)))
                            and compare.operands[1].type == X86_OP_IMM
                            and 0 <= compare.operands[1].imm < 4096
                            and not previous.address + previous.size <= operands[0].imm < jump.address + jump.size):
                        bound = compare.operands[1].imm + 1
                    break
                else:
                    break
            if bound is None or not base_proven:
                continue
            section = section_at(image, jump.address)
            remap_span = None
            remap_values = None
            if remap is not None:
                remap_end = remap + bound
                remap_offset = image.file_offset(remap)
                if (remap_offset is None or remap <= jump.address or remap_end - jump.address > 65536
                        or image.file_offset(remap_end - 1) != remap_offset + bound - 1
                        or section_at(image, remap) != section or section_at(image, remap_end - 1) != section):
                    continue
                remap_values = list(image.span(remap_offset, bound))
                remap_span = (remap, remap_end)
                bound = max(remap_values) + 1
            table = image.base + memory.disp
            table_end = table + bound * 4
            file_offset = image.file_offset(table)
            if (file_offset is None or table <= jump.address or table_end - jump.address > 65536
                    or image.file_offset(table_end - 1) != file_offset + bound * 4 - 1
                    or section_at(image, table) != section or section_at(image, table_end - 1) != section
                    or not executable(image, section)):
                continue
            if remap_span and max(table, remap_span[0]) < min(table_end, remap_span[1]):
                continue
            targets = [image.base + value for value in image.unpack("I" * bound, file_offset)]
            if any(not covered(target) or image.file_offset(target) is None
                   or section_at(image, target) != section or table <= target < table_end
                   or remap_span and remap_span[0] <= target < remap_span[1]
                   or abs(target - jump.address) > 65536 for target in targets):
                continue
            key = table, table_end
            row = found.setdefault(key, {"tableVA": table, "endVA": table_end,
                                         "tableRVA": table - image.base, "entries": bound,
                                         "targetVAs": targets, "dispatchRVAs": [],
                                         "evidence": "bounded-image-base-rva-switch-table"})
            if remap_span:
                # Keep disjoint spans separate: unrelated intervening code
                # must never be hidden with the two tables.
                row.setdefault("indexTables", [])
                entry = {"tableVA": remap_span[0], "endVA": remap_span[1], "indices": remap_values}
                if entry not in row["indexTables"]:
                    row["indexTables"].append(entry)
            row["dispatchRVAs"].append(jump.address - image.base)
    return [found[key] for key in sorted(found)]
