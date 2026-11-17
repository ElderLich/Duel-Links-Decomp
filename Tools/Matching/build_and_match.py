#!/usr/bin/env python3
"""Build declared C/C++ inputs and compare exact, proven native function ranges.

No byte masking, binary execution, copied-byte source generation, or inferred sizes.
Python standard library only. PE32+/AMD64 and ELF64/AArch64 can be inspected.
Acceptance currently supports only the complete leaf-return-u32 grammar. Unwind
and symbol lengths alone cannot prove PC-relative references at a new placement.
The closed build adapter currently supports MSVC x64 only. Source rejection rules
are deliberately conservative heuristics, not proof of original source or a
security boundary against a malicious compiler, operating system, or recipe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile

DECOMP = Path(__file__).resolve().parents[2]
ROOT = DECOMP.parent
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}
TEXT_EXTENSIONS = SOURCE_EXTENSIONS | {".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"}
ACCEPTANCE_POLICY = "leaf-return-u32-v2"
BUILD_PROFILE = "msvc-x64-closed-v1"


class GateError(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def number(value) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": sha(data)}


class Image:
    def __init__(self, data: bytes):
        self.data = data
        self.sections = []
        self.exports = {}
        self.symbol_sizes = {}
        self.unwind = {}
        self.relocations = []
        self.relocation_unknowns = []
        self.imports = []
        self.delay_imports = []
        self.clues = {}
        if data[:2] == b"MZ":
            self._pe()
        elif data[:4] == b"\x7fELF":
            self._elf()
        else:
            raise GateError("Expected PE32+/AMD64 or ELF64/AArch64")

    def span(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise GateError("Artifact range is outside the file")
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack("<" + fmt, self.span(offset, struct.calcsize("<" + fmt)))

    def offset(self, va: int, size: int = 1, executable=False) -> int:
        matches = [s for s in self.sections if s["va"] <= va and va + size <= s["va"] + s["file_size"]]
        if len(matches) != 1 or (executable and not matches[0]["exec"]):
            raise GateError("Range must lie in exactly one file-backed executable section" if executable else "Unmapped or ambiguous range")
        return matches[0]["offset"] + va - matches[0]["va"]

    def cstring(self, offset: int) -> str:
        end = self.data.find(b"\0", offset, min(offset + 4096, len(self.data)))
        if end < 0:
            raise GateError("Unterminated artifact string")
        return self.span(offset, end - offset).decode("utf-8", errors="strict")

    def _pe(self):
        pe = self.unpack("I", 60)[0]
        if self.span(pe, 4) != b"PE\0\0":
            raise GateError("Invalid PE signature")
        machine, count, timestamp, symptr, symbols, optional_size, flags = self.unpack("HHIIIHH", pe + 4)
        opt = pe + 24
        if machine != 0x8664 or self.unpack("H", opt)[0] != 0x20B or optional_size < 112:
            raise GateError("Only PE32+/AMD64 is supported")
        self.kind, self.arch = "pe", "amd64"
        self.base = self.unpack("Q", opt + 24)[0]
        n = self.unpack("I", opt + 108)[0]
        if n > (optional_size - 112) // 8:
            raise GateError("PE directories exceed optional header")
        directories = [self.unpack("II", opt + 112 + 8 * i) for i in range(n)]
        for i in range(count):
            pos = opt + optional_size + 40 * i
            vs, rva, raw_size, raw = self.unpack("IIII", pos + 8)
            characteristics = self.unpack("I", pos + 36)[0]
            self.span(raw, raw_size)
            self.sections.append({"name": self.span(pos, 8).split(b"\0")[0].decode("ascii"), "va": self.base + rva,
                                  "offset": raw, "file_size": min(vs or raw_size, raw_size), "exec": bool(characteristics & 0x20000000)})
        self.clues = {"linkerVersion": f"{self.data[opt + 2]}.{self.data[opt + 3]}", "coffTimestamp": timestamp,
                      "coffSymbolCount": symbols, "richHeader": self._rich(pe),
                      "limit": "Header/linker metadata does not recover exact compiler flags or a per-function compiler."}
        # Library names only: used to close the compiler's local DLL dependencies.
        for index, stride in ((1, 20), (13, 32)):
            if len(directories) <= index or not directories[index][0]:
                continue
            rva, length = directories[index]
            off = self.offset(self.base + rva, length)
            terminated = False
            for pos in range(off, off + length - stride + 1, stride):
                row = self.unpack("I" * (stride // 4), pos)
                if not any(row):
                    terminated = True
                    break
                name_rva = row[3] if index == 1 else row[1]
                if index == 13:
                    if row[0] not in (0, 1):
                        raise GateError("Unsupported delay-import attributes")
                    if not row[0]:
                        name_rva -= self.base
                name = self.cstring(self.offset(self.base + name_rva)).lower()
                self.imports.append(name)
                if index == 13:
                    self.delay_imports.append(name)
            if not terminated:
                raise GateError("Unterminated PE import directory")
        if directories and directories[0][0]:
            rva, length = directories[0]
            off = self.offset(self.base + rva, 40)
            _, _, _, _, _, ordinal, funcs, names, addresses, namelist, ordinals = self.unpack("IIHHIIIIIII", off)
            if funcs > 1000000 or names > funcs:
                raise GateError("Invalid PE export counts")
            for i in range(names):
                nrva = self.unpack("I", self.offset(self.base + namelist + 4 * i, 4))[0]
                index = self.unpack("H", self.offset(self.base + ordinals + 2 * i, 2))[0]
                if index >= funcs:
                    raise GateError("Export ordinal outside table")
                target = self.unpack("I", self.offset(self.base + addresses + 4 * index, 4))[0]
                name = self.cstring(self.offset(self.base + nrva))
                if not rva <= target < rva + length:  # forwarded exports have no local body
                    self.exports[name] = self.base + target
        if len(directories) > 3 and directories[3][0]:
            rva, length = directories[3]
            if length % 12:
                raise GateError("Malformed PE runtime function directory")
            off = self.offset(self.base + rva, length)
            for pos in range(off, off + length, 12):
                start, end, _ = self.unpack("III", pos)
                if end <= start:
                    raise GateError("Invalid runtime function bounds")
                self.unwind[self.base + start] = end - start
        if len(directories) > 5 and directories[5][0]:
            rva, length = directories[5]
            off = self.offset(self.base + rva, length)
            end = off + length
            while off < end:
                page, size = self.unpack("II", off)
                if size < 8 or size % 2 or off + size > end:
                    raise GateError("Malformed PE base relocations")
                for pos in range(off + 8, off + size, 2):
                    raw = self.unpack("H", pos)[0]
                    kind, rel = raw >> 12, raw & 4095
                    if kind == 0:
                        continue
                    width = {3: 4, 10: 8}.get(kind)
                    if width is None:
                        self.relocation_unknowns.append(kind)
                    else:
                        self.relocations.append((self.base + page + rel, width))
                off += size

    def _rich(self, pe):
        rich = self.data.find(b"Rich", 0, pe)
        if rich < 0 or rich + 8 > pe:
            return {"present": False}
        key = self.unpack("I", rich + 4)[0]
        start = None
        for pos in range(rich - 4, 63, -4):
            if self.unpack("I", pos)[0] ^ key == 0x536E6144:
                start = pos
                break
        if start is None or (rich - start - 16) % 8:
            return {"present": True, "decoded": False}
        entries = []
        for pos in range(start + 16, rich, 8):
            comp, count = self.unpack("II", pos)
            comp ^= key
            entries.append({"productId": comp >> 16, "build": comp & 65535, "count": count ^ key})
        return {"present": True, "decoded": True, "entries": entries, "sha256": sha(self.span(start, rich + 8 - start))}

    def _elf(self):
        if self.span(4, 3) != b"\x02\x01\x01" or self.unpack("H", 18)[0] != 183:
            raise GateError("Only ELF64 little-endian AArch64 is supported")
        self.kind, self.arch, self.base = "elf", "arm64", 0
        shoff = self.unpack("Q", 40)[0]
        entsize, count, names_index = self.unpack("HHH", 58)
        if not count or entsize != 64 or names_index >= count:
            raise GateError("ELF section inventory required; extended/absent tables unsupported")
        sections = [self.unpack("IIQQQQIIQQ", shoff + i * 64) for i in range(count)]
        strings = sections[names_index]
        for s in sections:
            name, kind, flags, va, offset, size, link, info, align, stride = s
            label = self.cstring(strings[4] + name)
            if kind != 8 and size:
                self.span(offset, size)
                if flags & 2:
                    self.sections.append({"name": label, "va": va, "offset": offset, "file_size": size, "exec": bool(flags & 4)})
            if label == ".comment":
                self.clues["commentStrings"] = [x.decode("utf-8", errors="replace") for x in self.span(offset, size).split(b"\0") if x]
            if kind in (2, 11):
                if stride != 24 or size % 24 or link >= count:
                    raise GateError("Malformed ELF symbol table")
                strtab = sections[link]
                for pos in range(offset, offset + size, 24):
                    nm, sinfo, other, index, address, length = self.unpack("IBBHQQ", pos)
                    if index and sinfo & 15 == 2:
                        label = self.cstring(strtab[4] + nm)
                        if label:
                            self.exports[label] = address
                        if length:
                            self.symbol_sizes[address] = length
            if kind in (4, 9):
                wanted = 24 if kind == 4 else 16
                if stride != wanted or size % stride:
                    raise GateError("Malformed ELF relocation table")
                for pos in range(offset, offset + size, stride):
                    address, info = self.unpack("QQ", pos)
                    relkind = info & 0xFFFFFFFF
                    if relkind == 0:
                        continue
                    width = {257: 8, 258: 4, 259: 2, 260: 8, 261: 4, 262: 2, 1025: 8, 1026: 8, 1027: 8, 1032: 8}.get(relkind)
                    if width is None:
                        self.relocation_unknowns.append(relkind)
                    else:
                        self.relocations.append((address, width))

    def function(self, spec: dict) -> dict:
        if "export" in spec:
            if spec["export"] not in self.exports:
                raise GateError(f"Missing local function symbol/export: {spec['export']}")
            address = self.exports[spec["export"]]
        elif "rva" in spec and self.kind == "pe":
            address = self.base + number(spec["rva"])
        elif "va" in spec:
            address = number(spec["va"])
        else:
            raise GateError("Function needs an export, PE RVA or explicit VA")
        boundary = spec.get("boundary")
        if boundary in ("unwind", "symbol"):
            raise GateError("Unsupported acceptance boundary: unwind/symbol size does not verify decoded PC-relative targets or COFF relocations; use a complete supported leaf grammar")
        elif boundary == "leaf-return-u32":
            ranges = self.unwind if self.kind == "pe" else self.symbol_sizes
            if any(start < address < start + length for start, length in ranges.items()):
                raise GateError("Requested leaf starts inside a known function extent; a return suffix is not a complete function")
            # A recognizable instruction sequence proves neither its entry point
            # nor its ownership. PE named exports/runtime entries, or nonzero ELF
            # STT_FUNC sizes, supply independent start anchors. Zero-sized ELF
            # symbols and arbitrary caller-supplied RVAs/VAs cannot supply one.
            anchored = address in ranges or (self.kind == "pe" and address in self.exports.values())
            if not anchored:
                raise GateError("Leaf entry has no trusted start anchor: require a PE export/unwind entry or nonzero-sized ELF function symbol")
            entry_anchor = ("pe-export" if address in self.exports.values() else "pe-unwind") if self.kind == "pe" else "elf-function-symbol"
            off = self.offset(address, 1, executable=True)
            if self.arch == "amd64" and self.span(off, 1) == b"\xB8" and self.span(off + 5, 1) == b"\xC3":
                size = 6
            elif self.arch == "amd64" and self.span(off, 3) == b"\x31\xC0\xC3":
                size = 3
            elif self.arch == "arm64" and self.unpack("I", off)[0] & 0xFFE0001F == 0x52800000 and self.unpack("I", off + 4)[0] == 0xD65F03C0:
                size = 8
            else:
                raise GateError("Leaf body does not match the complete supported return-u32 instruction grammar")
            known_size = self.unwind.get(address) if self.kind == "pe" else self.symbol_sizes.get(address)
            if known_size is not None and known_size != size:
                raise GateError("Leaf grammar disagrees with declared native symbol/unwind extent")
        else:
            raise GateError("Unknown/unproven function size: acceptance requires the complete supported leaf-return-u32 grammar")
        if "size" in spec and number(spec["size"]) != size:
            raise GateError("Requested size disagrees with proven function range")
        off = self.offset(address, size, executable=True)
        if self.relocation_unknowns:
            raise GateError(f"Unresolved relocation kinds: {sorted(set(self.relocation_unknowns))}")
        if any(start < address + size and address < start + width for start, width in self.relocations):
            raise GateError("Function intersects a relocation fixup; strict gate does not mask or normalize it")
        data = self.span(off, size)
        return {"va": hex(address), "rva": hex(address - self.base), "fileOffset": off,
                "size": size, "boundary": boundary, "entryAnchor": entry_anchor, "sha256": sha(data), "hex": data.hex()}


def load_targets(path: Path) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schemaVersion") != 1:
        raise GateError("Unsupported target schema")
    return config["targets"]


def pinned_target(targets: dict, name: str) -> tuple[Path, Image, dict]:
    target = targets[name]
    path = (ROOT / target["path"]).resolve()
    actual = identity(path)
    if actual["sha256"] != target["sha256"] or actual["bytes"] != target["bytes"]:
        raise GateError(f"Target identity mismatch: {name}; update deliberately after auditing the new build")
    image = Image(path.read_bytes())
    if image.arch != target["architecture"] or image.kind != target["format"]:
        raise GateError("Target architecture/format mismatch")
    return path, image, actual


def compare_functions(original: Image, rebuilt: Image, spec: dict) -> dict:
    if (original.kind, original.arch) != (rebuilt.kind, rebuilt.arch):
        raise GateError("Rebuilt image format/architecture differs from target")
    left, right = original.function(spec["original"]), rebuilt.function(spec["rebuilt"])
    matched = left["size"] == right["size"] and left["hex"] == right["hex"]
    return {"name": spec["name"], "status": "matched" if matched else "mismatch", "original": left, "rebuilt": right,
            "firstDifferentByte": next((i for i, (a, b) in enumerate(zip(bytes.fromhex(left["hex"]), bytes.fromhex(right["hex"]))) if a != b), None)}


def readable_source_policy(inputs: list[dict]) -> dict:
    """Review aid, NOT a C++ parser or proof against obfuscated byte emission."""
    forbidden = [
        (r"\b(?:asm|__asm|__asm__|_asm|_emit|__emit|__emitbyte|__emitword)\b", "inline assembly or byte emission"),
        (r"\b(?:__pragma|_Pragma)\s*\(", "computed pragma"),
        (r"\b__declspec\s*\(\s*(?:naked|allocate)\b", "naked function or explicit section allocation"),
        (r"\b__attribute__\s*\(.*?\b(?:naked|section)\b", "explicit executable allocation"),
        (r"#\s*pragma\s+(?:section|code_seg|data_seg|const_seg|comment)\b", "section or linker directive pragma"),
        (r"#\s*(?:embed|include_next|import|using)\b", "untracked binary/preprocessor/type-library input"),
        (r"##|%:|\?\?", "preprocessor token synthesis"),
        (r"\b(?:unsigned\s+char|u?int8_t|std\s*::\s*byte)\s+\w+\s*\[[^]]*\]\s*=", "initialized byte array requiring manual review"),
    ]
    for item in inputs:
        path = Path(item["path"])
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            raise GateError(f"Only readable C/C++ source/header inputs are supported: {path}")
        source = path.read_text(encoding="utf-8-sig")
        if "\0" in source:
            raise GateError(f"NUL/binary data in declared C/C++ input: {path}")
        source = re.sub(r"\\\r?\n", "", source)
        # Preserve string literals while removing comments, to avoid hiding tokens
        # with // embedded in a string. Raw strings may over-reject: fail closed.
        source = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
                        lambda m: " " if m.group().startswith(("/*", "//")) else m.group(), source, flags=re.S)
        for pattern, reason in forbidden:
            if re.search(pattern, source, flags=re.I | re.S):
                raise GateError(f"Readable-source heuristic rejected {reason}: {path}")
    return {"policy": "readable-cpp-heuristic-v1", "status": "passed", "inputCount": len(inputs),
            "limit": "Conservative textual heuristics, not a C++ parser or proof against obfuscation; human source review remains required."}


def source_arguments(argv: list[str]) -> set[Path]:
    # Do not discard slash-prefixed strings: /tmp/file.cpp is a valid Unix path.
    return {Path(arg).resolve() for arg in argv[1:] if Path(arg).suffix.lower() in SOURCE_EXTENSIONS}


def discover_msvc_dependencies(tool_directory: Path, suffixes: set[str]) -> tuple[list[Path], list[str], list[str]]:
    """Static/delay imports plus explicit dynamically loaded compiler backends.

    This is a bounded dependency model for the allowlisted profile below; it is
    not runtime DLL-load tracing. OS DLLs remain a stated trusted boundary.
    """
    pending = [tool_directory / name for name in ("cl.exe", "link.exe", "c2.dll", "msobj140.dll", "mspdb140.dll", "mspdbcore.dll")]
    pending += [tool_directory / ("c1.dll" if ext == ".c" else "c1xx.dll") for ext in suffixes]
    local, system, inactive = set(), set(), set()
    while pending:
        path = pending.pop().resolve()
        if path in local:
            continue
        if not path.is_file():
            raise GateError(f"Missing compiler dependency: {path}")
        local.add(path)
        image = Image(path.read_bytes())
        if (image.kind, image.arch) != ("pe", "amd64"):
            raise GateError(f"Expected an AMD64 MSVC tool/dependency: {path}")
        for name in image.imports:
            if not re.fullmatch(r"[a-z0-9_.-]+\.dll", name):
                raise GateError(f"Unsupported tool import name: {name}")
            sibling = tool_directory / name
            if sibling.is_file():
                pending.append(sibling)
            elif name.startswith(("api-ms-win-", "ext-ms-win-")):
                system.add(name)
            elif (Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / name).is_file():
                system.add(name)
            elif name == "tlbref.dll" and name in image.delay_imports:
                # Optional COM type-library service; #import/#using and /clr
                # are rejected by this profile. Do not call it a pinned DLL.
                inactive.add(name)
            else:
                raise GateError(f"Unresolved compiler DLL dependency: {name}")
    for name in ("cl.exe.config", "link.exe.config"):
        companion = tool_directory / name
        if companion.is_file():
            local.add(companion.resolve())
    return sorted(local, key=str), sorted(system), sorted(inactive)


def validate_tool_dependencies(tools: dict, toolchain_files: list[dict], source_paths: set[Path]) -> dict:
    if set(tools) != {"cc", "link"}:
        raise GateError("Closed MSVC profile requires exactly the pinned tools cc and link")
    cc, linker = Path(tools["cc"]["path"]), Path(tools["link"]["path"])
    if cc.name.lower() != "cl.exe" or linker.name.lower() != "link.exe" or cc.parent != linker.parent:
        raise GateError("Closed MSVC profile requires cl.exe and link.exe from one tool directory")
    required, system, inactive = discover_msvc_dependencies(cc.parent, {p.suffix.lower() for p in source_paths})
    declared = {Path(item["path"]) for item in list(tools.values()) + toolchain_files}
    if len(declared) != len(tools) + len(toolchain_files):
        raise GateError("Duplicate declared compiler dependency")
    if declared != set(required):
        missing, extra = set(required) - declared, declared - set(required)
        raise GateError(f"Compiler dependency set differs; undeclared: {sorted(map(str, missing))}; unused: {sorted(map(str, extra))}")
    return {"policy": "msvc-static-delay-and-known-backends-v1", "localFileCount": len(required), "systemImports": system,
            "inactiveOptionalImports": inactive,
            "limit": "Hashes cover declared compiler/linker, local static/delay imports and known dynamically loaded backends. Windows loader/system DLLs and unobserved dynamic loads are trusted, not hermetically traced."}


def parse_source_dependencies(path: Path, source: Path, declared: set[Path]) -> tuple[dict, set[Path]]:
    record = json.loads(path.read_text(encoding="utf-8-sig"))
    if set(record) != {"Version", "Data"} or record["Version"] not in ("1.0", "1.1", "1.2"):
        raise GateError("Unsupported compiler sourceDependencies schema")
    data = record["Data"]
    if not isinstance(data, dict) or not {"Source", "Includes"} <= set(data):
        raise GateError("Compiler dependency record lacks Source/Includes")
    if set(data) - {"Source", "Includes", "PCH", "ProvidedModule", "ImportedModules", "ImportedHeaderUnits"}:
        raise GateError("Unknown compiler dependency fields; closure cannot be established")
    if any(data.get(key) for key in ("PCH", "ProvidedModule", "ImportedModules", "ImportedHeaderUnits")):
        raise GateError("PCH/modules/header units are unsupported compiled dependencies")
    if not isinstance(data["Source"], str) or not isinstance(data["Includes"], list) or not all(isinstance(x, str) for x in data["Includes"]):
        raise GateError("Malformed compiler dependency paths")
    names = [data["Source"], *data["Includes"]]
    if not all(Path(name).is_absolute() for name in names):
        raise GateError("Compiler dependency paths must be absolute")
    if Path(data["Source"]).resolve() != source:
        raise GateError("Compiler dependency Source differs from actual command source")
    observed = {Path(name).resolve() for name in names}
    if not observed <= declared:
        raise GateError(f"Undeclared compiler source/header dependencies: {sorted(map(str, observed - declared))}")
    return {"record": identity(path), "version": record["Version"], "source": str(source),
            "observedInputs": sorted(map(str, observed))}, observed


def require_closed_inputs(declared: set[Path], observed: set[Path]):
    if declared != observed:
        raise GateError(f"Declared inputs were not consumed by the compiler: {sorted(map(str, declared - observed))}")


def validate_coff(path: Path) -> dict:
    """Require a fresh ordinary AMD64 compiler object, with no linker injection."""
    data = path.read_bytes()
    if len(data) < 20:
        raise GateError("Compiler did not produce a COFF object")
    machine, count, _, symptr, symcount, optional, _ = struct.unpack_from("<HHIIIHH", data)
    if machine != 0x8664 or optional or not count or len(data) < 20 + 40 * count:
        raise GateError("Expected ordinary AMD64 COFF compiler output; LTCG/bigobj unsupported")
    if not symcount or symptr < 20 + count * 40 or symptr + symcount * 18 + 4 > len(data):
        raise GateError("COFF compiler output lacks a valid symbol table")
    code = False
    for i in range(count):
        name, _, _, size, off, _, _, _, _, flags = struct.unpack_from("<8sIIIIIIHHI", data, 20 + i * 40)
        if size and off and off + size > len(data):
            raise GateError("Truncated COFF section")
        if flags & 0x20000000 and size:
            code = True
        if name.rstrip(b"\0") == b".drectve":
            directives = data[off:off + size].decode("ascii")
            for directive in shlex.split(directives, posix=False):
                if not re.fullmatch(r"[-/]EXPORT:[A-Za-z_?@$][A-Za-z0-9_?@$]*", directive, flags=re.I):
                    raise GateError(f"Unsupported compiler-object linker directive: {directive}")
    if not code:
        raise GateError("Compiler object contains no executable code")
    return identity(path)


COMPILE_FLAGS = {"/nologo", "/c", "/o1", "/o2", "/od", "/os", "/ot", "/oi", "/oi-", "/oy", "/oy-", "/gs", "/gs-",
                 "/gr", "/gr-", "/ehsc", "/ehs", "/ehc", "/zl", "/gy", "/gy-", "/gw", "/gw-", "/gf", "/gf-", "/utf-8", "/permissive-",
                 "/wx", "/wx-", "/w0", "/w1", "/w2", "/w3", "/w4", "/wall", "/ob0", "/ob1", "/ob2", "/ob3",
                 "/std:c++14", "/std:c++17", "/std:c++20", "/std:c++latest", "/fp:precise", "/fp:strict", "/fp:fast"}
LINK_FLAGS = {"/nologo", "/dll", "/noentry", "/nodefaultlib", "/machine:x64", "/opt:ref", "/opt:noref", "/opt:icf", "/opt:noicf", "/incremental:no", "/manifest:no"}


def build_output_path(arg: str, prefix: str, build: Path) -> Path:
    path = Path(arg[len(prefix):]).resolve()
    if not path.is_relative_to(build) or path.parent != build:
        raise GateError("Build outputs must be direct children of the fresh build directory")
    return path


def closed_build_plan(commands: list[list[str]], tools: dict, sources: set[Path], build: Path, output: Path) -> list[dict]:
    if len(commands) < 2:
        raise GateError("Closed profile requires compiler command(s), then one linker command")
    compiled, objects, plan = set(), set(), []
    for index, argv in enumerate(commands):
        if not argv or not all(isinstance(x, str) and x for x in argv):
            raise GateError("Invalid build command")
        is_compile = index < len(commands) - 1
        tool = tools["cc" if is_compile else "link"]["path"]
        if Path(argv[0]).resolve() != Path(tool):
            raise GateError("Expected pinned compiler command(s) followed by the pinned linker")
        if is_compile:
            direct = source_arguments(argv)
            if len(direct) != 1 or not direct <= sources or direct & compiled:
                raise GateError("Each compiler command must consume one declared source exactly once")
            source = next(iter(direct))
            if sum(Path(arg).resolve() == source for arg in argv[1:]) != 1:
                raise GateError("Duplicate compiler source argument")
            flags, object_paths = set(), []
            for arg in argv[1:]:
                if Path(arg).resolve() == source:
                    continue
                lower = arg.lower()
                if lower in COMPILE_FLAGS:
                    flags.add(lower)
                elif lower.startswith("/fo"):
                    object_paths.append(build_output_path(arg, "/Fo", build))
                elif arg.startswith("/I") and len(arg) > 2 and Path(arg[2:]).is_dir():
                    pass  # Actual includes must still appear in the dependency record.
                else:
                    raise GateError(f"Unsupported compiler argument in closed profile: {arg}")
            if not {"/c", "/zl"} <= flags or len(object_paths) != 1 or object_paths[0].suffix.lower() != ".obj" or object_paths[0] in objects:
                raise GateError("Compiler needs /c, /Zl and one unique /Fo object output")
            dependency = build / f"source-dependencies-{index}.json"
            plan.append({"kind": "compile", "argv": argv + ["/sourceDependencies", str(dependency)], "source": source,
                         "object": object_paths[0], "dependency": dependency})
            compiled |= direct
            objects.add(object_paths[0])
        else:
            inputs, outputs, flags = [], [], set()
            for arg in argv[1:]:
                lower = arg.lower()
                if lower in LINK_FLAGS:
                    flags.add(lower)
                elif lower.startswith(("/out:", "/implib:")):
                    prefix = "/out:" if lower.startswith("/out:") else "/implib:"
                    outputs.append((prefix, build_output_path(arg, prefix, build)))
                elif Path(arg).resolve() in objects:
                    inputs.append(Path(arg).resolve())
                else:
                    raise GateError(f"Unsupported linker argument/prebuilt input in closed profile: {arg}")
            if not {"/dll", "/noentry", "/nodefaultlib", "/machine:x64"} <= flags or set(inputs) != objects or len(inputs) != len(objects):
                raise GateError("Linker must consume exactly the newly compiled objects without default libraries")
            if [p for key, p in outputs if key == "/out:"] != [output] or len(outputs) != len({key for key, p in outputs}) or any(p in objects for key, p in outputs):
                raise GateError("Linker /OUT must name the recipe output and must not overwrite an object")
            plan.append({"kind": "link", "argv": argv, "outputs": [p for key, p in outputs]})
    if compiled != sources:
        raise GateError("Every declared C/C++ source must appear as a direct compiler argument")
    return plan


def run_recipe(recipe_path: Path, targets: dict) -> dict:
    recipe_bytes = recipe_path.read_bytes()
    recipe = json.loads(recipe_bytes)
    if recipe.get("schemaVersion") != 1 or not recipe.get("functions"):
        raise GateError("Recipe needs schemaVersion 1 and at least one function")
    if recipe.get("buildProfile") != BUILD_PROFILE:
        raise GateError(f"Recipe requires buildProfile {BUILD_PROFILE}; other compiler adapters are not implemented")
    target_path, original, original_id = pinned_target(targets, recipe["target"])
    if (original.kind, original.arch) != ("pe", "amd64"):
        raise GateError("The closed MSVC build profile supports only PE32+/AMD64 targets")
    inputs = [identity((DECOMP / name).resolve()) for name in recipe["inputs"]]
    declared = {Path(item["path"]) for item in inputs}
    source_paths = {path for path in declared if path.suffix.lower() in SOURCE_EXTENSIONS}
    if not source_paths or len(declared) != len(inputs):
        raise GateError("Recipe must declare C/C++ source inputs")
    if any(Path(x["path"]) == target_path for x in inputs):
        raise GateError("Original binary is not a source input")
    source_policy = readable_source_policy(inputs)
    # Prove original boundaries before running any compiler. Duplicate entries
    # cannot inflate a receipt's matched count/bytes.
    originals, names = set(), set()
    for function in recipe["functions"]:
        body = original.function(function["original"])
        span = (number(body["va"]), number(body["va"]) + body["size"])
        if function["name"] in names or any(start < span[1] and span[0] < end for start, end in originals):
            raise GateError("Duplicate names/overlapping original function ranges are not independent matches")
        originals.add(span)
        names.add(function["name"])
    tools = {}
    for name, tool in recipe["tools"].items():
        found = identity(Path(tool["path"]))
        if found["sha256"] != tool["sha256"]:
            raise GateError(f"Compiler/tool digest mismatch: {name}")
        tools[name] = found
    toolchain_files = []
    for expected in recipe.get("toolchainFiles", []):
        found = identity(Path(expected["path"]))
        if found["sha256"] != expected["sha256"]:
            raise GateError(f"Toolchain component digest mismatch: {expected['path']}")
        toolchain_files.append(found)
    tool_dependencies = validate_tool_dependencies(tools, toolchain_files, source_paths)
    (DECOMP / "Build").mkdir(exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix=recipe_path.stem + "-", dir=DECOMP / "Build"))
    replacements = {"root": str(ROOT), "decomp": str(DECOMP), "build": str(build), **{k: v["path"] for k, v in tools.items()}}
    expanded = [[arg.format_map(replacements) for arg in command] for command in recipe["commands"]]
    output = Path(recipe["output"].format_map(replacements)).resolve()
    if not output.is_relative_to(build) or output.suffix.lower() != ".dll":
        raise GateError("Output must be a fresh DLL inside this attempt's build directory")
    plan = closed_build_plan(expanded, tools, source_paths, build, output)
    environment = dict(os.environ)
    # Prevent invisible command-line, header or library injection through MSVC env vars.
    for key in list(environment):
        if key.upper() in ("CL", "_CL_", "LINK", "_LINK_", "INCLUDE", "LIB", "LIBPATH", "PATH", "DEVPATH", "COMPILER_PATH", "GCC_EXEC_PREFIX"):
            environment.pop(key)
    system = Path(os.environ.get("SystemRoot", "C:/Windows"))
    environment["PATH"] = os.pathsep.join((str(Path(tools["cc"]["path"]).parent), str(system / "System32"), str(system)))
    environment["VSCMD_SKIP_SENDTELEMETRY"] = "1"
    commands, dependencies, objects, observed = [], [], [], set()
    base_receipt = {"schemaVersion": 1, "acceptancePolicy": ACCEPTANCE_POLICY, "buildProfile": BUILD_PROFILE,
                    "targetName": recipe["target"], "target": original_id, "recipe": {"path": str(recipe_path.resolve()), "sha256": sha(recipe_bytes)},
                    "matchingGate": identity(Path(__file__)), "inputs": inputs, "tools": tools, "toolchainFiles": toolchain_files,
                    "toolDependencies": tool_dependencies, "sourcePolicy": source_policy, "buildDirectory": str(build)}
    for step in plan:
        argv = step["argv"]
        if step["kind"] == "compile":
            if step["object"].exists() or step["dependency"].exists():
                raise GateError("Compiler outputs already exist; freshness cannot be established")
        else:
            require_closed_inputs(declared, observed)
            if any(path.exists() for path in step["outputs"]):
                raise GateError("Linker outputs already exist; freshness cannot be established")
        result = subprocess.run(argv, cwd=build, env=environment, capture_output=True, text=True, errors="replace", timeout=120, shell=False)
        commands.append({"argv": argv, "exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            return {**base_receipt, "status": "build-failed", "commands": commands, "dependencies": dependencies,
                    "functions": [], "matchedFunctionCount": 0, "matchedBodyBytes": 0}
        if step["kind"] == "compile":
            record, consumed = parse_source_dependencies(step["dependency"], step["source"], declared)
            dependencies.append(record)
            observed |= consumed
            objects.append(validate_coff(step["object"]))
    if not output.is_relative_to(build) or not output.is_file():
        raise GateError("Output must be freshly built inside this attempt's build directory")
    for item in inputs + list(tools.values()) + toolchain_files + [original_id] + objects + [x["record"] for x in dependencies]:
        if identity(Path(item["path"])) != item:
            raise GateError("A declared input/tool/target changed during the build")
    if recipe_path.read_bytes() != recipe_bytes:
        raise GateError("Recipe changed during the build")
    validate_tool_dependencies(tools, toolchain_files, source_paths)
    rebuilt = Image(output.read_bytes())
    results = [compare_functions(original, rebuilt, item) for item in recipe["functions"]]
    return {**base_receipt, "status": "matched" if all(x["status"] == "matched" for x in results) else "mismatch",
            "commands": commands, "rebuilt": identity(output), "dependencies": dependencies, "compilerObjects": objects,
            "declaredInputsClosed": True,
            "functions": results, "matchedFunctionCount": sum(x["status"] == "matched" for x in results),
            "matchedBodyBytes": sum(x["original"]["size"] for x in results if x["status"] == "matched"),
            "limit": "Exact bytes only for complete position-independent scalar-return leaf bodies. General unwind/symbol ranges, decoded references and relocation reconstruction are unsupported. Not whole-image equality, original source identity, runtime validation, or recovered engine percentage."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, default=DECOMP / "config/targets.json")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("verify-targets")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("binary", type=Path)
    run = commands.add_parser("run")
    run.add_argument("recipe", type=Path)
    run.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "inspect":
            image = Image(args.binary.read_bytes())
            result = {"artifact": identity(args.binary), "format": image.kind, "architecture": image.arch,
                      "exportCount": len(image.exports), "toolchainClues": image.clues, "unresolvedRelocationKinds": sorted(set(image.relocation_unknowns))}
        elif args.action == "verify-targets":
            targets = load_targets(args.targets)
            result = {"status": "verified", "targets": [pinned_target(targets, key)[2] for key in targets]}
        else:
            result = run_recipe(args.recipe, load_targets(args.targets))
    except (GateError, OSError, ValueError, KeyError, struct.error, subprocess.TimeoutExpired) as error:
        result = {"status": "rejected", "reason": str(error)}
    if args.action == "run":
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") not in ("rejected", "mismatch", "build-failed") else 1


if __name__ == "__main__":
    sys.exit(main())
