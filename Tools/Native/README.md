# Native parsers retained for the clean start

Only the five production modules used by comparison or CN bridge verification remain:

| Module | Purpose |
| --- | --- |
| `InspectNativeBuild.py` | Bounds-checked ELF reader and build metadata inspection. |
| `NativeCardRecords.py` | PE/ELF numeric records backed by relocations and executable pointers. |
| `NativeInstructionInventory.py` | PE integer-operand inventory; numbers alone are not card identities. |
| `NativeJumpTables.py` | Exclude recognized PE switch-table data from instruction decoding. |
| `ExtractWasm3Bindings.py` | Recover hash-pinned CN ARM64 wasm3 host registrations. |

Run from the repository root:

```powershell
python -m Decomp.Tools.Native.InspectNativeBuild --help
python -m Decomp.Tools.Native.ExtractWasm3Bindings --help
python -m unittest Decomp.Tools.Native.test_native_jump_tables -v
```

Instruction scanning and wasm3 registration recovery require `capstone`. The ELF/PE file readers use only Python's standard library. The CN registration range, link target and input SHA256 are pinned in `Decomp/Evidence/CN_10.10.1032/BuildAndBindingsSummary.json`.

After the move, the ten switch-table regression tests pass and the retained CN extractor independently recovered all 3,969 main and 11 support bindings from the selected `libduel.so`. These are static callback mappings; they do not certify complete effects or identical Steam implementations.
