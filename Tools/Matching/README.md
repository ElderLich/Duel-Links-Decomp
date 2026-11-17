# Native build and byte-matching gate

Run from `DLL Research` with Python 3.10 or newer. The gate uses only the standard library and does not execute a game library.

```powershell
python Decomp/Tools/Matching/build_and_match.py verify-targets
python Decomp/Tools/Matching/build_and_match.py run Decomp/config/recipes/steam_revision.local.json --report Decomp/Results/steam_revision.json
python -m unittest discover -s Decomp/Tools/Matching -p 'test_*.py' -v
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
- `tools`: named executable paths with exact SHA-256 values; `toolchainFiles` pins additional compiler components.
- `commands`: argument arrays, with `{decomp}`, `{root}`, `{build}` and named tool placeholders. Commands run without a shell in a fresh build directory. Ambient MSVC `CL`, `_CL_`, `LINK`, `_LINK_`, `INCLUDE`, `LIB` and `LIBPATH` overrides are cleared.
- `output`: a newly generated PE/ELF inside that attempt's build directory.
- `functions`: each has a name and separate original/rebuilt selectors. A selector uses `export`, PE `rva`, or explicit `va`, plus a supported boundary rule. Optional `size` must agree with the independently derived range.

The gate accepts complete supported return-u32 leaf grammars, PE runtime-function ranges (`boundary: unwind`), or nonzero ELF function-symbol sizes (`boundary: symbol`). An unwind range is a bounded native range and can be a compiler fragment; matching it does not establish all source-level function fragments. Unknown boundaries and supplied guesses are rejected. Raw COFF/object files and stripped ELF files without section inventories are not currently supported.

Any overlapping dynamic/base relocation rejects the range; unsupported relocation kinds reject the image. There are no wildcard, relocation-masking, percentage-similarity, padding-filling or forced-match modes. Link-dependent displacement mismatches remain failures. Relocation-aware object/link comparison is future work, separately scoped from this strict gate.

The build recipe and declared toolchain are trusted local inputs. Declaring a source file is not proof of original source identity or complete transitive dependency discovery. Record every build dependency, inspect the source and compiler commands, and add compiler-produced dependency records when more complex source is introduced. The report describes only the compiled inputs and exact ranges observed.

## Next native source work

Use `Evidence/CN_10.10.1032/SharedExportContracts.json` for 154 verified CN host-name/shared-export anchors. Keep original symbols, CN reference names and inferred internal names distinct. Begin with small helpers, preserve source and native provenance, establish the entire compared boundary, then build and inspect failures. Reconstruct functions from behavior; copying native machine bytes into data arrays is not restoration.

For CN, `NativeBuildClues.json` records API 23/NDK r21d and mixed Clang 9.0.8/18.0.4 objects. Configure a specific NDK and try bounded ARM64 helpers before expanding. No Android compiler recipe has been certified. REA Wasm validation separately requires WABT 1.0.42 configured in its launch environment; that does not supply an Android compiler.

`Build/` holds replaceable attempt artifacts. `Results/` is the audit receipt; preserve a receipt together with its source/recipe/toolchain identities. Do not report a whole-engine completion percentage from this pilot.
