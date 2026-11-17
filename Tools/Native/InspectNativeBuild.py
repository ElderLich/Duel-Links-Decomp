#!/usr/bin/env python3
"""Read ELF build evidence, symbols and dependencies without loading the binary.

Offsets are file offsets; symbol values and segment addresses are link-time VAs.
No external Python packages or native executable tools are required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path


class ElfImage:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 16 or data[:4] != b"\x7fELF":
            raise ValueError("Not an ELF image")
        if data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
            raise ValueError("Unsupported ELF encoding/version")
        self.bits = 32 if data[4] == 1 else 64
        self.endian = "<" if data[5] == 1 else ">"
        header = self.unpack("HHIIIIIHHHHHH" if self.bits == 32 else "HHIQQQIHHHHHH", 16)
        self.type, self.machine, _, self.entry, phoff, shoff, self.flags, _, phsize, phnum, shsize, shnum, shstr = header
        shfmt = "IIIIIIIIII" if self.bits == 32 else "IIQQQQIIQQ"
        if shoff and shnum == 0:
            raise ValueError("Extended ELF section counts are not supported")
        if shnum and shsize < struct.calcsize(self.endian + shfmt):
            raise ValueError("Invalid section entry size")
        self.span(shoff, shnum * shsize)
        self.sections = []
        for i in range(shnum):
            values = self.unpack(shfmt, shoff + i * shsize)
            row = dict(zip(("nameOffset", "type", "flags", "address", "offset", "size", "link", "info", "alignment", "entrySize"), values))
            if row["type"] != 8:  # SHT_NOBITS has no file bytes.
                self.span(row["offset"], row["size"])
            self.sections.append(row)
        if shnum:
            if shstr >= shnum:
                raise ValueError("Invalid section-name table")
            names = self.section_data(self.sections[shstr])
            for section in self.sections:
                section["name"] = self.string(names, section["nameOffset"])
        self.segments = []
        phfmt = "IIIIIIII" if self.bits == 32 else "IIQQQQQQ"
        if phnum and phsize < struct.calcsize(self.endian + phfmt):
            raise ValueError("Invalid program-header entry size")
        self.span(phoff, phnum * phsize)
        for i in range(phnum):
            fields = self.unpack(phfmt, phoff + i * phsize)
            if self.bits == 32:
                kind, off, va, pa, filesz, memsz, flags, align = fields
            else:
                kind, flags, off, va, pa, filesz, memsz, align = fields
            self.span(off, filesz)
            self.segments.append(dict(type=kind, offset=off, address=va, fileSize=filesz, memorySize=memsz, flags=flags, alignment=align))

    def span(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError(f"ELF range outside file: 0x{offset:x}+0x{size:x}")
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int) -> tuple:
        fmt = self.endian + fmt
        return struct.unpack(fmt, self.span(offset, struct.calcsize(fmt)))

    @staticmethod
    def string(data: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(data):
            raise ValueError(f"String offset outside table: {offset}")
        end = data.find(b"\0", offset)
        if end < 0:
            raise ValueError("Unterminated ELF string")
        return data[offset:end].decode("utf-8", errors="replace")

    def section_data(self, section: dict) -> bytes:
        return b"" if section["type"] == 8 else self.span(section["offset"], section["size"])

    def linked_strings(self, section: dict) -> bytes:
        if section["link"] >= len(self.sections):
            raise ValueError("ELF section link outside table")
        return self.section_data(self.sections[section["link"]])

    def file_offset(self, address: int) -> int | None:
        for segment in self.segments:
            if segment["type"] == 1 and segment["address"] <= address < segment["address"] + segment["fileSize"]:
                return segment["offset"] + address - segment["address"]
        return None

    def dynamic_symbols(self) -> list[dict]:
        result = []
        fmt = "IIIBBH" if self.bits == 32 else "IBBHQQ"
        size = struct.calcsize(self.endian + fmt)
        for section in self.sections:
            if section["type"] != 11:
                continue
            strings = self.linked_strings(section)
            stride = section["entrySize"]
            if stride < size or section["size"] % stride:
                raise ValueError("Invalid dynamic symbol stride")
            for off in range(section["offset"], section["offset"] + section["size"], stride):
                fields = self.unpack(fmt, off)
                if self.bits == 32:
                    nameoff, value, length, info, other, shndx = fields
                else:
                    nameoff, info, other, shndx, value, length = fields
                if not nameoff:
                    continue
                result.append(dict(name=self.string(strings, nameoff), value=value, size=length,
                                   binding=info >> 4, type=info & 15, visibility=other & 3,
                                   defined=shndx != 0, sectionIndex=shndx,
                                   symbolFileOffset=off, fileOffset=self.file_offset(value) if shndx else None))
        return result

    def notes(self) -> list[dict]:
        result = []
        for section in self.sections:
            if section["type"] != 7:
                continue
            data = self.section_data(section)
            cursor = 0
            while cursor < len(data):
                start = cursor
                if len(data) - cursor < 12:
                    if not any(data[cursor:]):
                        break
                    raise ValueError("Truncated ELF note header")
                namesz, descsz, kind = struct.unpack_from(self.endian + "III", data, cursor)
                cursor += 12
                nameend = cursor + namesz
                descend = ((nameend + 3) & ~3) + descsz
                if descend > len(data):
                    raise ValueError("Truncated ELF note body")
                name = data[cursor:nameend].rstrip(b"\0").decode("ascii", errors="replace")
                desc = data[(nameend + 3) & ~3:descend]
                row = dict(section=section["name"], offset=section["offset"] + start, name=name, type=kind)
                if name == "GNU" and kind == 3:
                    row["buildId"] = desc.hex()
                elif name == "GNU" and kind == 4:
                    row["linkerVersion"] = desc.rstrip(b"\0").decode("ascii", errors="replace")
                elif name == "Android" and kind == 1 and len(desc) >= 4:
                    row["api"] = struct.unpack_from(self.endian + "I", desc)[0]
                    if len(desc) >= 132:
                        row["ndkVersion"] = desc[4:68].split(b"\0", 1)[0].decode("ascii", errors="replace")
                        row["ndkBuild"] = desc[68:132].split(b"\0", 1)[0].decode("ascii", errors="replace")
                else:
                    row["descriptionHex"] = desc.hex()
                result.append(row)
                cursor = (descend + 3) & ~3
        return result

    def dynamic(self) -> dict:
        result = {"needed": [], "soname": None, "flags": 0, "flags1": 0}
        fmt = "iI" if self.bits == 32 else "qQ"
        size = struct.calcsize(self.endian + fmt)
        for section in self.sections:
            if section["type"] != 6:
                continue
            strings = self.linked_strings(section)
            stride = section["entrySize"] or size
            if stride < size or section["size"] % stride:
                raise ValueError("Invalid dynamic entry stride")
            for offset in range(section["offset"], section["offset"] + section["size"], stride):
                tag, value = self.unpack(fmt, offset)
                if tag == 0:
                    break
                if tag == 1:
                    result["needed"].append(self.string(strings, value))
                elif tag == 14:
                    result["soname"] = self.string(strings, value)
                elif tag == 30:
                    result["flags"] = value
                elif tag == 0x6ffffffb:
                    result["flags1"] = value
        return result


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    elf = ElfImage(data)
    symbols = elf.dynamic_symbols()
    exports = [s for s in symbols if s["defined"] and s["binding"] in (1, 2) and s["visibility"] in (0, 3)]
    imports = [s for s in symbols if not s["defined"] and s["binding"] in (1, 2)]
    strings = []
    pattern = re.compile(r"(?i)clang version|GCC:|LLVM|Linker:|wasm3/|ndk-release|(?:/|\\)[^\s]+\.(?:cpp|c|h|hpp)$|wasm.*(?:version|runtime)")
    for section in elf.sections:
        # Executable bytes produce fake strings; NOBITS contains no file data.
        if section["type"] != 1 or section["flags"] & 4:
            continue
        for match in re.finditer(rb"[\x20-\x7e]{6,}", elf.section_data(section)):
            value = match.group().decode("ascii")
            if pattern.search(value):
                strings.append(dict(section=section["name"], offset=section["offset"] + match.start(), text=value))
    sections = [{k: v for k, v in section.items() if k != "nameOffset"} for section in elf.sections]
    return dict(schemaVersion=1, path=str(path.resolve()), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                bits=elf.bits, byteOrder="little" if elf.endian == "<" else "big", machine=elf.machine,
                architecture={40: "ARM", 183: "AArch64", 62: "x86-64"}.get(elf.machine, "unknown"),
                elfType=elf.type, entry=elf.entry, flags=elf.flags,
                hasStaticSymbolTable=any(s["type"] == 2 for s in sections),
                debugSections=[s["name"] for s in sections if s["name"].startswith((".debug", ".zdebug", ".gnu_debug"))],
                notes=elf.notes(), dynamic=elf.dynamic(), compilerAndSourceStrings=strings,
                sections=sections, segments=elf.segments, exportCount=len(exports), importCount=len(imports),
                exports=sorted(exports, key=lambda s: s["name"]), imports=sorted(imports, key=lambda s: s["name"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", type=Path, nargs="+")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    reports = [inspect(path) for path in args.binaries]
    comparisons = []
    for previous, current in zip(reports, reports[1:]):
        old = {s["name"]: s for s in previous["exports"]}
        new = {s["name"]: s for s in current["exports"]}
        comparisons.append(dict(previous=previous["path"], current=current["path"],
                                identical=previous["sha256"] == current["sha256"],
                                exportsAdded=sorted(new.keys() - old.keys()), exportsRemoved=sorted(old.keys() - new.keys()),
                                commonExports=len(old.keys() & new.keys()),
                                commonExportValuesChanged=sum(old[n]["value"] != new[n]["value"] for n in old.keys() & new.keys())))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dict(schemaVersion=1, binaries=reports, comparisons=comparisons), indent=2) + "\n", encoding="utf-8")
    for report in reports:
        print(f"{report['architecture']} {report['bytes']} bytes {report['sha256']} {report['path']}")
        print(f"  {report['exportCount']} exports, {report['importCount']} imports; {report['notes']}")
    print(f"Report: {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
