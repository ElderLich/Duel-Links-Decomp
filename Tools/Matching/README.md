# Native build and byte-matching gate

Run from the Decomp repository root with Python 3.11 or newer. The gate uses only the standard library and does not execute a game library.

```powershell
python Tools/Matching/build_and_match.py verify-targets
python Tools/Matching/build_and_match.py run config/recipes/steam_revision.local.json --report Results/steam_revision.json
python -m unittest discover -s Tools/Matching -p 'test_*.py' -v
```

`verify-targets` checks the exact SHA-256, byte count, architecture and format of CN ARM64, current Steam and previous Steam. `inspect <binary>` prints PE linker/Rich-header clues or ELF compiler strings. `run` builds declared C/C++ source inputs with an explicit recipe, then compares exact executable bytes. Exit 0 means every requested range matched; mismatch, build failure or an unproven input exits 1 and writes the reason.

## Current result

`Source/revision.cpp` is a real C++ reconstruction of current Steam's exported `DLL_GetRevision`, which returns `0x1456b`. Installed MSVC 14.44.35207 compiles it to the same six-byte body as current Steam RVA `0x2060`. The original entry is an exported `mov eax,imm32; ret` leaf followed by alignment padding; the gate independently validates this complete instruction grammar. Padding is outside the compared body.

`Results/steam_revision.json` records source/header hashes, pinned compiler/linker/backend identities, commands, generated output, original and rebuilt addresses, sizes and exact bytes. This is one six-byte function-body match. The reconstructed DLL has its own layout and exports; it is not a replacement for the game DLL, a whole-image match, or a measurement of engine completion. No game runtime test has been performed.

## Recipes and limits

`config/recipes/steam_revision.local.json` contains the discovered local Visual Studio paths. A missing or changed compiler is rejected. For another machine, explicitly set the intended compiler/linker paths and their SHA-256 values, plus relevant compiler backend components in `toolchainFiles`. Do not silently bless a different toolchain. The exact original MSVC compiler remains uncertain even though the target reports linker 14.44 and the installed toolchain matches the pilot.

Each recipe declares:

- One pinned target name from `config/targets.json`.
- `inputs`: C/C++ source and all local header/dependency paths relative to Decomp (absolute paths also work). Every source must appear directly in a build command.
- `buildProfile`: `msvc-x64-closed-v1`, the currently supported native build profile.
- `tools`: pinned `cc` and `link` executable paths; `toolchainFiles` pins the compiler's local dependency closure, including backends and configuration files.
- `commands`: argument arrays, with `{decomp}`, `{root}`, `{build}` and named tool placeholders. Commands run without a shell in a fresh build directory. Ambient MSVC `CL`, `_CL_`, `LINK`, `_LINK_`, `INCLUDE`, `LIB` and `LIBPATH` overrides are cleared.
- `output`: a newly generated PE/AMD64 DLL inside that attempt's build directory.
- `functions`: each has a name and separate original/rebuilt selectors. A selector uses `export`, PE `rva`, or explicit `va`, plus a supported boundary rule. Optional `size` must agree with the independently derived range.

Only complete supported return-u32 leaf grammars can earn acceptance. PE runtime-function ranges (`boundary: unwind`) and ELF function-symbol sizes (`boundary: symbol`) do not prove reference destinations, exception behavior or all fragments, so these selectors are refused for matching. Unknown boundaries and supplied guesses are rejected. The parser retains PE/ELF metadata for inspection; there is no certified ARM64 compile profile yet.

A leaf must start at an independently identified entry: a PE export or runtime-function entry, or an ELF function symbol with a nonzero size. An arbitrary RVA containing return instructions is insufficient. Starting inside another known function range is rejected, even if the selected suffix looks like a complete leaf.

Any overlapping dynamic/base relocation rejects the range; unsupported relocation kinds reject the image. Equal raw bytes are insufficient for address-sensitive instructions: the same relative displacement at a different address can reference a different object. The leaf grammar excludes those instructions. There are no wildcard, relocation-masking, percentage-similarity, padding-filling or forced-match modes. General relocation-aware comparison requires new verified tooling.

The gate injects MSVC `/sourceDependencies` and requires the compiler-observed source/header set to equal the declared inputs. It checks fresh ordinary AMD64 COFF outputs and permits only the closed compile/link argument profile. Response files, prebuilt object/library inputs, forced includes, PCH, modules and unsupported compiler/linker options are rejected. Ambient option variables are cleared and identities are checked again after compilation.

Local static/delay DLL imports, known compiler backends and compiler configuration files are pinned. Windows system libraries remain a trusted boundary; this is not a hermetic operating-system image or runtime DLL-load trace. Source checks reject recognizable assembly, byte emission and section-allocation tricks, but they are conservative textual heuristics, not a complete C++ parser. Human source and tooling review remains required.

## Integrate and publish

From the Decomp repository root, `python Tools/refresh.py` runs tests, rebuilds every enrolled recipe, exports public data, and checks both snapshots. `python Tools/refresh.py --check` runs fixture tests and public consistency checks without private binaries.

`config/scope.json` defines the enrolled target-specific units. `Tools/Matching/integrate.py` rebuilds them all afresh and verifies their complete original ranges and body hashes. Previous accepted units cannot silently disappear or shrink. A successful integration writes sanitized `config/integration.json`; full receipts and attempt state stay under ignored `Results/Integration/`.

Both public exporters require the latest local integration to have passed. A failure leaves the last successful public snapshot intact and blocks new local export. Public `--check` validates source, scope, recipes, target and verification-tool identities, not the original binary itself. See [the matching policy](../../docs/MatchingPolicy.md) for the explicit trust boundary.

The refresh command first prepares `config/research.json` from the local CN reference evidence and deliberately wrong compile receipt. Integration also binds this sanitized record, so public reference counts and negative-control status cannot change independently of the accepted snapshot. For the individual commands, run `python Tools/export_progress.py --prepare-references` before integration.

## Next native source work

Use `Evidence/CN_10.10.1032/SharedExportContracts.json` for 154 verified CN host-name/shared-export anchors. Keep original symbols, CN reference names and inferred internal names distinct. Begin with small helpers, preserve source and native provenance, establish the entire compared boundary, then build and inspect failures. Reconstruct functions from behavior; copying native machine bytes into data arrays is not restoration.

For CN, `NativeBuildClues.json` records API 23/NDK r21d and mixed Clang 9.0.8/18.0.4 objects. Configure a specific NDK and try bounded ARM64 helpers before expanding. No Android compiler recipe has been certified. REA Wasm validation separately requires WABT 1.0.42 configured in its launch environment; that does not supply an Android compiler.

`Build/` holds replaceable attempt artifacts. `Results/` is the audit receipt; preserve a receipt together with its source/recipe/toolchain identities. Do not report a whole-engine completion percentage from this pilot.
