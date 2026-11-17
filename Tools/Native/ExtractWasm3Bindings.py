#!/usr/bin/env python3
"""Recover hash-pinned ARM64 wasm3 host registrations by static constant tracking.

Supply a reviewed straight-line registration range and the link-function VA.
This never executes native code. Requires the optional `capstone` package.
Names identify WASM callbacks, not automatically the callbacks' native callees.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path

from Decomp.Tools.Native.InspectNativeBuild import ElfImage


def recover(path: Path, expected_sha256: str, start: int, end: int, link_target: int) -> dict:
    import capstone
    from capstone import arm64_const as arm

    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest.lower() != expected_sha256.lower():
        raise ValueError(f"Binary hash mismatch: expected {expected_sha256}, found {digest}; review addresses for this build")
    elf = ElfImage(data)
    if elf.bits != 64 or elf.endian != "<" or elf.machine != 183:
        raise ValueError("This extractor requires little-endian AArch64 ELF")
    start_offset, end_offset = elf.file_offset(start), elf.file_offset(end - 1)
    if start_offset is None or end_offset is None or end_offset - start_offset != end - start - 1:
        raise ValueError("Registration range must be contiguous file-backed memory")
    code_sections = [s for s in elf.sections if s["flags"] & 4]
    def executable(va):
        return any(s["address"] <= va < s["address"] + s["size"] for s in code_sections)
    if not executable(start) or not executable(end - 1) or not executable(link_target):
        raise ValueError("Registration/link addresses must be executable")

    relocations = {}
    for section in elf.sections:
        if section["type"] != 4:
            continue
        if section["entrySize"] != 24 or section["size"] % 24:
            raise ValueError("Unsupported ELF64 RELA stride")
        for offset in range(section["offset"], section["offset"] + section["size"], 24):
            address, info, addend = elf.unpack("QQq", offset)
            # All relocation destinations are recorded, so unresolved symbol
            # relocations never fall back to a misleading zero/on-disk value.
            relocations[address] = (addend if info == 1027 else None, offset)

    def cstring(va):
        offset = elf.file_offset(va)
        if offset is None:
            raise ValueError(f"String VA not backed by file: 0x{va:x}")
        tail = data[offset:offset + 512]
        terminal = tail.find(b"\0")
        if terminal < 0:
            raise ValueError("Registration string exceeds 511 bytes")
        value = tail[:terminal].decode("ascii")
        return value, offset

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    constants = {}  # Capstone register id -> (constant, pointer-source, relocation)
    rows, unresolved = [], []
    calls = 0
    last_end = start
    last_mnemonic = None
    for instruction in md.disasm(data[start_offset:end_offset + 1], start):
        if instruction.address != last_end:
            raise ValueError("Disassembly skipped bytes")
        last_end = instruction.address + instruction.size
        ops = instruction.operands
        old = constants.copy()
        _, writes = instruction.regs_access()
        for reg in writes:
            constants.pop(reg, None)
        name = instruction.mnemonic
        last_mnemonic = name
        if name in ("adrp", "adr") and len(ops) == 2 and ops[1].type == arm.ARM64_OP_IMM:
            constants[ops[0].reg] = (ops[1].imm, None, None)
        elif name == "add" and len(ops) == 3 and ops[1].type == arm.ARM64_OP_REG and ops[2].type == arm.ARM64_OP_IMM:
            value = old.get(ops[1].reg)
            if value is not None and instruction.reg_name(ops[0].reg).startswith("x"):
                constants[ops[0].reg] = (value[0] + (ops[2].imm << ops[2].shift.value), None, None)
        elif name == "mov" and len(ops) == 2:
            if ops[1].type == arm.ARM64_OP_REG and ops[1].reg in old:
                constants[ops[0].reg] = old[ops[1].reg]
            elif ops[1].type == arm.ARM64_OP_IMM:
                constants[ops[0].reg] = (ops[1].imm, None, None)
        elif name == "ldr" and len(ops) == 2 and ops[1].type == arm.ARM64_OP_MEM and not instruction.writeback:
            base = old.get(ops[1].mem.base)
            if base is not None and not ops[1].mem.index and instruction.reg_name(ops[0].reg).startswith("x"):
                address = base[0] + ops[1].mem.disp
                if address in relocations:
                    value, relocation = relocations[address]
                else:
                    offset = elf.file_offset(address)
                    value = elf.unpack("Q", offset)[0] if offset is not None else None
                    relocation = None
                if value is not None:
                    constants[ops[0].reg] = (value, address, relocation)
        elif name == "bl":
            if len(ops) == 1 and ops[0].type == arm.ARM64_OP_IMM and ops[0].imm == link_target:
                calls += 1
                args = [old.get(reg) for reg in (arm.ARM64_REG_X1, arm.ARM64_REG_X2, arm.ARM64_REG_X3, arm.ARM64_REG_X4)]
                if any(value is None for value in args):
                    unresolved.append(dict(callVA=instruction.address, reason="one or more arguments are not statically known"))
                else:
                    module, module_offset = cstring(args[0][0])
                    function, name_offset = cstring(args[1][0])
                    signature, signature_offset = cstring(args[2][0])
                    callback, slot, relocation = args[3]
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function) or not re.fullmatch(r"[viIfFdD*]\([iIfFdD* ]*\)", signature) or not executable(callback):
                        raise ValueError(f"Invalid binding at 0x{instruction.address:x}: {function}, {signature}, {callback:x}")
                    rows.append(dict(name=function, module=module, signature=signature, callbackVA=callback,
                                     callbackFileOffset=elf.file_offset(callback), callVA=instruction.address,
                                     nameFileOffset=name_offset, signatureFileOffset=signature_offset,
                                     moduleFileOffset=module_offset, pointerSlotVA=slot, relocationFileOffset=relocation))
            # AAPCS64 caller-saved registers cannot be assumed to survive BL.
            for reg in list(constants):
                register = instruction.reg_name(reg)
                if register.startswith(("x", "w")) and register[1:].isdigit() and int(register[1:]) <= 18:
                    constants.pop(reg)
        elif name == "ret":
            if instruction.address + instruction.size != end:
                raise ValueError("Range contains an early return; provide one straight-line registration function")
        elif instruction.group(capstone.CS_GRP_JUMP) or instruction.group(capstone.CS_GRP_CALL):
            raise ValueError(f"Non-linear control flow at 0x{instruction.address:x}; cannot claim exact bindings")
    if last_end != end:
        raise ValueError("Disassembly did not consume the entire requested range")
    if last_mnemonic != "ret":
        raise ValueError("Registration range must end at its return instruction")
    if not calls:
        raise ValueError("No registration calls found")
    # A useful next anchor, deliberately labelled as a candidate: a simple
    # wrapper with one BL often delegates to the named native implementation.
    # Never infer a prototype or propagate names across ambiguous control flow.
    for row in rows:
        callback = row["callbackVA"]
        offset = row["callbackFileOffset"]
        direct_calls, branches, returned = [], False, False
        for instruction in md.disasm(data[offset:offset + 1024], callback):
            if instruction.mnemonic == "ret":
                returned = True
                break
            if instruction.mnemonic == "bl" and instruction.operands[0].type == arm.ARM64_OP_IMM:
                direct_calls.append(instruction.operands[0].imm)
            elif instruction.group(capstone.CS_GRP_JUMP) or instruction.group(capstone.CS_GRP_CALL):
                branches = True
                break
        row["singleCallTargetCandidateVA"] = direct_calls[0] if returned and not branches and len(direct_calls) == 1 else None
    return dict(schemaVersion=1, binary=str(path.resolve()), sha256=digest,
                rangeStart=start, rangeEndExclusive=end, linkFunctionVA=link_target,
                registrationCalls=calls, recovered=len(rows), unresolved=unresolved, bindings=rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--sha256", required=True)
    for flag in ("start", "end", "link-target"):
        parser.add_argument("--" + flag, type=lambda value: int(value, 0), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = recover(args.binary, args.sha256, args.start, args.end, args.link_target)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with args.out.with_suffix(".csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(report["bindings"][0]) if report["bindings"] else ["name"])
        writer.writeheader()
        writer.writerows(report["bindings"])
    print(f"Recovered {report['recovered']}/{report['registrationCalls']} bindings; unresolved={len(report['unresolved'])}")
    print(args.out.resolve())
    return 1 if report["unresolved"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
