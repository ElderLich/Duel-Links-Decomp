#!/usr/bin/env python3
"""Build declared C/C++ inputs and compare exact, proven native function ranges.

No byte masking, binary execution, copied-byte source generation, or inferred sizes.
Python standard library only. PE32+/AMD64 and ELF64/AArch64 are supported.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

DECOMP = Path(__file__).resolve().parents[2]
ROOT = DECOMP.parent


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
        if boundary == "unwind" and address in self.unwind:
            size = self.unwind[address]
        elif boundary == "symbol" and address in self.symbol_sizes:
            size = self.symbol_sizes[address]
        elif boundary == "leaf-return-u32":
            off = self.offset(address, 1, executable=True)
            if self.arch == "amd64" and self.span(off, 1) == b"\xB8" and self.span(off + 5, 1) == b"\xC3":
                size = 6
            elif self.arch == "amd64" and self.span(off, 3) == b"\x31\xC0\xC3":
                size = 3
            elif self.arch == "arm64" and self.unpack("I", off)[0] & 0xFFE0001F == 0x52800000 and self.unpack("I", off + 4)[0] == 0xD65F03C0:
                size = 8
            else:
                raise GateError("Leaf body does not match the complete supported return-u32 instruction grammar")
        else:
            raise GateError("Unknown/unproven function size: require exact unwind range, nonzero ELF symbol size, or supported leaf grammar")
        if "size" in spec and number(spec["size"]) != size:
            raise GateError("Requested size disagrees with proven function range")
        off = self.offset(address, size, executable=True)
        if self.relocation_unknowns:
            raise GateError(f"Unresolved relocation kinds: {sorted(set(self.relocation_unknowns))}")
        if any(start < address + size and address < start + width for start, width in self.relocations):
            raise GateError("Function intersects a relocation fixup; strict gate does not mask or normalize it")
        data = self.span(off, size)
        return {"va": hex(address), "rva": hex(address - self.base), "fileOffset": off,
                "size": size, "boundary": boundary, "sha256": sha(data), "hex": data.hex()}


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


def run_recipe(recipe_path: Path, targets: dict) -> dict:
    recipe_bytes = recipe_path.read_bytes()
    recipe = json.loads(recipe_bytes)
    if recipe.get("schemaVersion") != 1 or not recipe.get("functions"):
        raise GateError("Recipe needs schemaVersion 1 and at least one function")
    target_path, original, original_id = pinned_target(targets, recipe["target"])
    inputs = [identity((DECOMP / name).resolve()) for name in recipe["inputs"]]
    if not inputs or not any(Path(x["path"]).suffix.lower() in (".c", ".cc", ".cpp", ".cxx") for x in inputs):
        raise GateError("Recipe must declare C/C++ source inputs")
    if any(Path(x["path"]) == target_path for x in inputs):
        raise GateError("Original binary is not a source input")
    # Prove original boundaries before running any compiler.
    for function in recipe["functions"]:
        original.function(function["original"])
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
    (DECOMP / "Build").mkdir(exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix=recipe_path.stem + "-", dir=DECOMP / "Build"))
    replacements = {"root": str(ROOT), "decomp": str(DECOMP), "build": str(build), **{k: v["path"] for k, v in tools.items()}}
    expanded = [[arg.format_map(replacements) for arg in command] for command in recipe["commands"]]
    source_paths = {Path(item["path"]) for item in inputs if Path(item["path"]).suffix.lower() in (".c", ".cc", ".cpp", ".cxx")}
    command_paths = {Path(arg).resolve() for command in expanded for arg in command}
    if not source_paths <= command_paths:
        raise GateError("Every declared C/C++ source must appear as a direct build-command argument")
    environment = dict(os.environ)
    # Prevent invisible command-line, header or library injection through MSVC env vars.
    for key in ("CL", "_CL_", "LINK", "_LINK_", "INCLUDE", "LIB", "LIBPATH"):
        environment.pop(key, None)
    commands = []
    for argv in expanded:
        if not argv or Path(argv[0]).resolve() not in {Path(t["path"]) for t in tools.values()}:
            raise GateError("Each build command must start with a pinned tool")
        result = subprocess.run(argv, cwd=build, env=environment, capture_output=True, text=True, errors="replace", timeout=120, shell=False)
        commands.append({"argv": argv, "exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        if result.returncode:
            return {"status": "build-failed", "target": original_id, "inputs": inputs, "tools": tools, "commands": commands, "buildDirectory": str(build)}
    output = Path(recipe["output"].format_map(replacements)).resolve()
    if not output.is_relative_to(build) or not output.is_file():
        raise GateError("Output must be freshly built inside this attempt's build directory")
    for item in inputs + list(tools.values()) + toolchain_files + [original_id]:
        if identity(Path(item["path"])) != item:
            raise GateError("A declared input/tool/target changed during the build")
    rebuilt = Image(output.read_bytes())
    results = [compare_functions(original, rebuilt, item) for item in recipe["functions"]]
    return {"schemaVersion": 1, "status": "matched" if all(x["status"] == "matched" for x in results) else "mismatch",
            "targetName": recipe["target"], "target": original_id, "recipe": {"path": str(recipe_path.resolve()), "sha256": sha(recipe_bytes)},
            "matchingGate": identity(Path(__file__)), "inputs": inputs, "tools": tools, "toolchainFiles": toolchain_files, "commands": commands, "rebuilt": identity(output), "buildDirectory": str(build),
            "functions": results, "matchedFunctionCount": sum(x["status"] == "matched" for x in results),
            "matchedBodyBytes": sum(x["original"]["size"] for x in results if x["status"] == "matched"),
            "limit": "Exact bytes for only these proven function ranges. Not whole-image equality, original source identity, runtime validation, or recovered engine percentage."}


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
