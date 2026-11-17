"""Relocation-backed native card-like records, with explicit evidence limits.

A matching row is a CID-like integer next to metadata and an executable pointer.
It is not proof of a complete card effect, availability, or a unique card script.
Supports ELF64/AArch64 and PE32+/AMD64 without executing the input.
"""
from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path
import struct

from Decomp.Tools.Native.InspectNativeBuild import ElfImage


class PeImage:
    def __init__(self, data: bytes):
        self.data = data
        self.endian = "<"
        self.bits = 64
        if data[:2] != b"MZ":
            raise ValueError("Expected a PE image")
        pe = self.unpack("I", 0x3C)[0]
        if self.span(pe, 4) != b"PE\0\0":
            raise ValueError("Invalid PE signature")
        self.machine, count, self.timestamp, _, _, optional_size, _ = self.unpack("HHIIIHH", pe + 4)
        optional = pe + 24
        self.span(optional, optional_size)
        if self.machine != 0x8664 or self.unpack("H", optional)[0] != 0x20B or optional_size < 160:
            raise ValueError("Only PE32+/AMD64 is supported")
        self.base = self.unpack("Q", optional + 24)[0]
        self.image_size = self.unpack("I", optional + 56)[0]
        directory_count = self.unpack("I", optional + 108)[0]
        if directory_count > (optional_size - 112) // 8:
            raise ValueError("PE data directories exceed optional header")
        self.directories = [self.unpack("II", optional + 112 + i * 8) for i in range(directory_count)]
        self.sections = []
        for i in range(count):
            offset = optional + optional_size + i * 40
            entry = self.span(offset, 40)
            size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", entry, 8)
            self.span(raw_offset, raw_size)
            characteristics = struct.unpack_from("<I", entry, 36)[0]
            self.sections.append(dict(name=entry[:8].split(b"\0", 1)[0].decode("ascii"),
                                      address=self.base + rva, offset=raw_offset, size=size or raw_size,
                                      fileSize=raw_size, flags=characteristics))

    def span(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError("PE range extends beyond file")
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int) -> tuple:
        return struct.unpack("<" + fmt, self.span(offset, struct.calcsize("<" + fmt)))

    def file_offset(self, address: int) -> int | None:
        for section in self.sections:
            if section["address"] <= address < section["address"] + min(section["size"], section["fileSize"]):
                return section["offset"] + address - section["address"]
        return None

    def relocations(self) -> dict[int, dict]:
        if len(self.directories) <= 5 or not self.directories[5][0]:
            return {}
        rva, size = self.directories[5]
        offset = self.file_offset(self.base + rva)
        if offset is None:
            raise ValueError("PE base relocation directory is not file-backed")
        end = offset + size
        self.span(offset, size)
        result = {}
        while offset < end:
            page, block_size = self.unpack("II", offset)
            if block_size < 8 or block_size % 2 or offset + block_size > end:
                raise ValueError("Invalid PE base relocation block")
            for entry_offset in range(offset + 8, offset + block_size, 2):
                entry = self.unpack("H", entry_offset)[0]
                if entry >> 12 != 10:  # IMAGE_REL_BASED_DIR64
                    continue
                slot = self.base + page + (entry & 0xFFF)
                file_offset = self.file_offset(slot)
                if file_offset is None:
                    continue
                result[slot] = dict(value=self.unpack("Q", file_offset)[0],
                                    relocationFileOffset=entry_offset, kind="PE_DIR64")
            offset += block_size
        return result

    def function_ranges(self) -> list[tuple[int, int]]:
        if len(self.directories) <= 3 or not self.directories[3][0]:
            return []
        rva, size = self.directories[3]
        offset = self.file_offset(self.base + rva)
        if offset is None or size % 12:
            raise ValueError("Invalid PE runtime function directory")
        result = []
        for pos in range(offset, offset + size, 12):
            start, end, _ = self.unpack("III", pos)
            if start < end and self.file_offset(self.base + start) is not None:
                result.append((self.base + start, self.base + end))
        return sorted(set(result))


def load_image(path: Path):
    data = path.read_bytes()
    if data[:4] == b"\x7fELF":
        image = ElfImage(data)
        if image.bits != 64 or image.machine != 183 or image.endian != "<":
            raise ValueError("Only ELF64 little-endian AArch64 is supported")
        image.base = 0
        kind = "ELF64-AArch64"
        relocations = {}
        for section in image.sections:
            if section["type"] != 4:
                continue
            if section["entrySize"] != 24 or section["size"] % 24:
                raise ValueError("Unsupported ELF64 RELA stride")
            for off in range(section["offset"], section["offset"] + section["size"], 24):
                address, info, addend = image.unpack("QQq", off)
                if info == 1027:
                    relocations[address] = dict(value=addend, relocationFileOffset=off, kind="R_AARCH64_RELATIVE")
    elif data[:2] == b"MZ":
        image = PeImage(data)
        kind = "PE32+-AMD64"
        relocations = image.relocations()
    else:
        raise ValueError("Unsupported binary format")
    return data, image, kind, relocations


def section_at(image, address: int) -> dict | None:
    return next((s for s in image.sections if s["address"] <= address < s["address"] + s["size"]), None)


def executable(image, section: dict | None) -> bool:
    return bool(section and section["flags"] & (0x20000000 if isinstance(image, PeImage) else 4))


def extractor_sha256() -> str:
    """Invalidate inventories when the record selection rules change."""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _complete_stride32_record(image, row, relocations) -> bool:
    """Validate the tail before using a record to establish a 32-byte array."""
    start, offset = row["recordVA"], row["recordFileOffset"]
    if (image.file_offset(start + 31) != offset + 31
            or section_at(image, start + 31) != section_at(image, start)):
        return False
    _, padding, predicate = image.unpack("IIQ", offset + 16)
    if padding:
        return False
    # ELF uses the RELA addend; the on-disk pointer may still be zero.
    relocation = relocations.get(start + 24)
    if relocation:
        predicate = relocation["value"]
        return (image.file_offset(predicate) is not None
                and executable(image, section_at(image, predicate)))
    return predicate == 0


def _bounded_parameter_records(image, candidates, relocations):
    """Recover parameterized rows only inside established, ordered arrays.

    The word at +4 is not a fixed marker. Steam's registration wrapper loads it
    as a signed parameter, replacing -1 with its caller's argument. Accepting
    every relocation with a different value would confuse other table layouts.
    Require a complete 32-byte row, a known callback, ascending CID order and
    sentinel rows on both sides of an uninterrupted run instead.
    """
    phases = defaultdict(list)
    for row in candidates:
        if _complete_stride32_record(image, row, relocations):
            # A relocated predicate at +24 can also resemble a row at +16.
            # It must not split the actual array or supply its anchors.
            phases[row["section"], row["recordVA"] % 32].append(row)
    runs = []
    for complete in phases.values():
        run = []
        for row in complete:
            if run and (row["recordVA"] != run[-1]["recordVA"] + 32 or row["cid"] < run[-1]["cid"]):
                runs.append(run)
                run = []
            run.append(row)
        if run:
            runs.append(run)
    recovered = []
    for run in runs:
        anchors = [row for row in run if row["marker"] == 0xFFFF]
        if len(anchors) < 2:
            continue
        callbacks = Counter(row["callbackVA"] for row in anchors)
        first, last = anchors[0]["recordVA"], anchors[-1]["recordVA"]
        for row in run:
            if (row["marker"] != 0xFFFF and first < row["recordVA"] < last
                    and callbacks[row["callbackVA"]] >= 2):
                row["recordSelection"] = "bounded-stride32-parameter-record"
                row["arrayFirstAnchorVA"] = first
                row["arrayLastAnchorVA"] = last
                recovered.append(row)
    return recovered


def inspect_records(path: Path, min_cid: int = 3000, max_cid: int = 40000) -> dict:
    if not 0 <= min_cid < max_cid <= 65536:
        raise ValueError("CID range must satisfy 0 <= min < max <= 65536")
    data, image, kind, relocations = load_image(path)
    candidates = []
    for slot, relocation in sorted(relocations.items()):
        source_section = section_at(image, slot)
        callback = relocation["value"]
        if not source_section or executable(image, source_section) or not executable(image, section_at(image, callback)):
            continue
        # Require the full eight-byte metadata prefix in the same file-backed
        # non-code section. Do not reinterpret ARM64 pointers as guessed u32s.
        start = slot - 8
        offset = image.file_offset(start)
        if start < source_section["address"] or offset is None or image.file_offset(slot + 7) != offset + 15:
            continue
        cid, related, marker, flags = image.unpack("4H", offset)
        # Discover array anchors independently of the requested output range.
        # Otherwise a one-CID inspection cannot recover an interior row.
        if not (0 < cid < 65536 and flags <= 0x100):
            continue
        row = dict(cid=cid, relatedValue=related, marker=marker, flags=flags,
                   recordFileOffset=offset, recordVA=start, recordRVA=start - image.base,
                   pointerVA=slot, callbackVA=callback, callbackRVA=callback - image.base,
                   callbackFileOffset=image.file_offset(callback), section=source_section["name"],
                   pointerEvidence=relocation["kind"], relocationFileOffset=relocation["relocationFileOffset"])
        candidates.append(row)
    records = [row for row in candidates if row["marker"] == 0xFFFF]
    records += _bounded_parameter_records(image, candidates, relocations)
    records.sort(key=lambda row: row["recordVA"])
    # Neighbor support is a stronger structural clue than an isolated match.
    by_start = {r["recordVA"]: r for r in records}
    for row in records:
        neighbors = [by_start[va]["cid"] for va in (row["recordVA"] - 32, row["recordVA"] + 32) if va in by_start]
        row["adjacentStride32Records"] = len(neighbors)
        row["evidenceClass"] = "relocation-backed-function-record"
    records = [row for row in records if min_cid <= row["cid"] < max_cid]
    binary = dict(path=str(path.resolve()), sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                  format=kind, machine=image.machine, pointerSize=8, imageBase=image.base,
                  relocationSlots=len(relocations))
    return dict(schemaVersion=2, binary=binary, records=records, recordCount=len(records),
                uniqueCids=len({r["cid"] for r in records}),
                selection=dict(minCidInclusive=min_cid, maxCidExclusive=max_cid,
                               anchorMarker=0xFFFF, maximumFlags=0x100,
                               parameterRecords="Complete ordered stride-32 runs bounded by sentinel anchors; callback shared by at least two anchors in the run"),
                limit="Records link numeric card-like keys to executable pointers; not proof of complete card effects or availability.")
