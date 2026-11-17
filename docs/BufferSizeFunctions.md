# Buffer allocation queries

The current Steam target has two additional complete constant-return exports reconstructed in `Source/buffer_sizes.cpp`.

| Export | Client return type | Steam result | Native RVA | Body bytes |
| --- | --- | ---: | --- | ---: |
| DLL_DuelGetBackupSize | signed 32-bit integer | 3,520,264 bytes | 0x4f70 | 6 |
| DLL_CardRareGetBufferSize | unsigned 32-bit integer | 4,096 bytes | 0x5d90 | 6 |

Recovered Steam and CN client declarations agree on the argument-free signatures and distinguish signed from unsigned results. CN client allocation sites consume these values as byte-array lengths. The declarations and call sites have locally retained file hashes; they are static recovered-source evidence, not an independently pinned client execution test.

The ordinary C++ bodies were freshly compiled by the pinned MSVC profile. The unchanged strict matcher verified both complete export-anchored ranges with exact byte equality. A separate review rechecked native and rebuilt ranges, signatures, source, tool identities and compiler dependency records before enrollment. Full integration remains the source of published acceptance.

CN gives a useful counterexample to assuming identical behavior across builds: its backup-size query returns **3,519,712**, 552 bytes smaller than current Steam. Its rarity-buffer query resolves through a branch to a helper returning 4,096. The CN Wasm host contract names that helper `CARDRARE_GetBufferSize` with signature `i()`. These CN observations provide reference evidence, not accepted CN source matches.

The candidate scan screened all 234 export entries and 33,488 runtime entries, yielding 33,686 unique available entry anchors. Only the revision and these two buffer queries fit the current constant-leaf grammar. This is an inventory of available anchors for one narrow grammar, not an engine-wide function count. More substantial matching requires verified reference resolution and complete boundaries; card callback decompilation does not satisfy that requirement.

The buffer layouts, their serialized fields and whole-engine runtime behavior remain unresolved. No card-effect implementation is counted by these two API queries.
