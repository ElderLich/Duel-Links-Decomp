# What earns a match

A model may suggest incorrect code. It cannot award itself a match. A candidate must pass a real compile and the acceptance pipeline below.

1. Verify the original file's SHA-256, byte count, architecture and format against the reviewed target configuration.
2. Compile the declared readable C/C++ using the pinned compiler, linker and required backend components in a fresh build directory. Reject undeclared dependencies, prebuilt input objects and unsupported build profiles.
3. Derive both complete native ranges using a supported boundary rule. Check the original entry and byte count against the enrolled scope.
4. Compare every byte. A size difference, unknown reference or one wrong byte is a failure. No similarity threshold, wildcard bytes, forced acceptance or partial-region credit exists.
5. Rebuild **all** enrolled units. A failure prevents a new integration snapshot from replacing the last successful one and blocks local progress export.
6. Export public facts from that integration, then validate their hashes and totals in a clean checkout. Review source and proof together before publication.

## Current acceptance envelope

The certified pilot is the complete address-independent `leaf-return-u32` grammar. It establishes the constant-return body of Steam's `DLL_GetRevision`. General PE unwind ranges and ELF symbol sizes remain useful inventory evidence, but are not sufficient acceptance proofs.

Identical bytes alone are unsafe for code with relative references at different addresses: the same displacement can point to different callees or data. A future general matcher must reconstruct and verify those targets, all relevant data, exception metadata and fragments. Until then such candidates fail closed.

Compiler-produced dependency information checks which source/header inputs were used. The closed build profile and source checks reduce accidental or deliberate byte-emission shortcuts. They are not a proof that arbitrary C++ is benign, or that a determined maintainer cannot alter the trusted tools. Source and tooling review remain part of acceptance.

## Scope and counting

Scope is a reviewed list of target-specific native units, not a count inferred from the largest card ID, exports, Wasm imports or `.pdata` entries. Accepted entries cannot quietly disappear or shrink during integration. Aliases and overlapping ranges cannot inflate the totals.

An enrolled-scope percentage describes that list only. The entire engine's function and byte denominators remain unknown. CN naming references, decompiled pseudocode and card research are never added to matched-source totals.

Daily charts use first-recorded acceptance dates, not the day a snapshot is regenerated. Rebuilding a unit again earns no additional function or byte credit. Unknown historical contributors and models stay unattributed. The site has no visitor collection or billing telemetry.

## Trust boundary

The original game binaries and exact compiler are local inputs. Full integration verifies against them on the maintainer's machine. Public CI runs fixture tests and validates snapshot consistency; it does not possess or execute the game and cannot independently reproduce the original comparison.

Hash commitments detect stale inputs and accidental editing, but do not authenticate who ran a build. The current public receipt is a maintainer-published record, not a signed independent attestation. No absolute claim of hallucination prevention is made: unsupported or uncertain work must remain uncounted, and defects in the checker itself require review and regression tests.

The current result is function-body reconstruction, not original-source recovery, whole-DLL identity, runtime equivalence of an entire engine, or a playable replacement.
