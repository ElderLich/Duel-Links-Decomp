"""Inventory positive uint16 immediates without a per-CID byte-pattern prefilter.

Decode PE unwind ranges and reachable out-of-range leaf blocks. Numeric operands
are evidence, not a determination that a particular number is a card identifier.
"""
from bisect import bisect_right
from collections import defaultdict, deque
import hashlib
from pathlib import Path

from Decomp.Tools.Native.NativeCardRecords import PeImage, executable, section_at
from Decomp.Tools.Native import NativeJumpTables


def scanner_identities():
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__), Path(NativeJumpTables.__file__))}


def scan_pe_immediates(image: PeImage, entry_points=(), sample_limit=8):
    import capstone
    from capstone.x86_const import X86_OP_IMM

    ranges = image.function_ranges()
    starts = [start for start, _ in ranges]
    jump_tables = NativeJumpTables.find_jump_tables(image, ranges)
    data_spans = []
    spans = [(part["tableVA"], part["endVA"])
             for table in jump_tables for part in [table, *table.get("indexTables", [])]]
    for left, right in sorted(spans):
        if data_spans and left <= data_spans[-1][1]:
            data_spans[-1] = (data_spans[-1][0], max(right, data_spans[-1][1]))
        else:
            data_spans.append((left, right))
    data_starts = [left for left, _ in data_spans]

    def is_table(address):
        index = bisect_right(data_starts, address) - 1
        return index >= 0 and address < data_spans[index][1]

    def code_spans(start, end):
        cursor = start
        for left, right in data_spans[max(0, bisect_right(data_starts, start) - 1):]:
            if left >= end:
                break
            if right <= cursor:
                continue
            if cursor < left:
                yield cursor, left
            cursor = max(cursor, right)
        if cursor < end:
            yield cursor, end
    lite = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    detail = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    detail.detail = True
    result = {}
    occurrences = defaultdict(list)
    queue, queued, leaf_seen = deque(), set(), set()
    scanned = decoded_bytes = incomplete = leaf_blocks = 0

    def in_function(address):
        pos = bisect_right(starts, address) - 1
        return pos >= 0 and address < ranges[pos][1]

    def enqueue(address):
        if address not in queued and not in_function(address) and not is_table(address) and executable(image, section_at(image, address)):
            if image.file_offset(address) is not None:
                queued.add(address)
                queue.append(address)

    def record(address, size, mnemonic, operands, start, boundary):
        # Capstone's operand text is only a cheap prefilter. Values are taken
        # from decoded IMM operands, never from displacements or printed text.
        parts = [part.strip().lstrip("-") for part in operands.split(",")]
        if not any(part.startswith("0x") or part.isdigit() for part in parts):
            return
        offset = image.file_offset(address)
        instruction = next(detail.disasm(image.span(offset, size), address), None)
        if instruction is None:
            return
        branch = mnemonic.startswith("j") or mnemonic in ("call", "loop", "loope", "loopne")
        values = {op.imm for op in instruction.operands if op.type == X86_OP_IMM}
        if branch:
            for target in values:
                enqueue(target)
            return  # Branch destinations are addresses, not card IDs.
        for value in values:
            if not 1 <= value <= 65535:
                continue
            row = result.setdefault(value, {"count": 0, "samples": [], "boundaryCounts": {}})
            row["count"] += 1
            occurrences[value].append(f"{address - image.base:08x}:{image.span(offset, size).hex()}\n")
            row["boundaryCounts"][boundary] = row["boundaryCounts"].get(boundary, 0) + 1
            if len(row["samples"]) < sample_limit:
                row["samples"].append({"instructionRVA": address - image.base,
                                       "instructionFileOffset": offset, "mnemonic": mnemonic,
                                       "operands": operands, "entryRVA": start - image.base,
                                       "boundaryEvidence": boundary})

    for start, end in ranges:
        offset = image.file_offset(start)
        if offset is None or image.file_offset(end - 1) is None:
            incomplete += 1
            continue
        for code_start, code_end in code_spans(start, end):
            last = code_start
            for address, size, mnemonic, operands in lite.disasm_lite(image.span(image.file_offset(code_start), code_end - code_start), code_start):
                scanned += 1
                decoded_bytes += size
                last = address + size
                record(address, size, mnemonic, operands, start, "PE-unwind-range")
            if last != code_end:
                incomplete += 1

    for entry in entry_points:
        enqueue(entry)
    while queue:
        start = queue.popleft()
        if start in leaf_seen:
            continue
        section = section_at(image, start)
        size = min(65536, section["address"] + min(section["size"], section["fileSize"]) - start)
        next_table = bisect_right(data_starts, start)
        if next_table < len(data_starts):
            size = min(size, data_starts[next_table] - start)
        stopped = False
        leaf_blocks += 1
        for address, length, mnemonic, operands in lite.disasm_lite(image.span(image.file_offset(start), size), start):
            if in_function(address) or address in leaf_seen:
                stopped = True
                break
            leaf_seen.add(address)
            scanned += 1
            decoded_bytes += length
            record(address, length, mnemonic, operands, start, "direct-control-flow-or-native-callback")
            if mnemonic in ("ret", "retf", "jmp", "int3", "ud2", "hlt"):
                stopped = True
                break
        if not stopped and not is_table(start + size):
            incomplete += 1

    for value, row in result.items():
        row["occurrencesSha256"] = hashlib.sha256("".join(sorted(occurrences[value])).encode("ascii")).hexdigest()

    return result, {
        "status": "decoded", "minIdInclusive": 1, "maxIdExclusive": 65536,
        "unwindRanges": len(ranges), "reachableLeafBlocks": leaf_blocks,
        "decodedInstructions": scanned, "decodedBytes": decoded_bytes,
        "incompleteRangesOrBlocks": incomplete, "sampleLimitPerId": sample_limit,
        "excludedJumpTables": len(jump_tables), "excludedJumpTableBytes": sum(right-left for left, right in data_spans),
        "excludedSwitchIndexTables": sum(len(table.get("indexTables", [])) for table in jump_tables),
        "coverage": "PE unwind ranges excluding structurally verified RVA switch-table spans, plus direct branch/call targets and native callback entries outside those ranges; includes 16-bit immediate operands. No CID list, score, presence or byte-pattern prefilter.",
        "limits": "Not a complete proof of implemented cards: numeric immediates can be gameplay constants. Unreachable leaf code, indirect-only targets, data tables, computed/split IDs, and undecodable tails can remain unidentified. Negative/signed encodings are not remapped to unsigned IDs.",
    }
