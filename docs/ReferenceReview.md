# F3 / FNV workflow review

Reviewed on 2026-11-17. This implementation is independent; no FNV source or checker code is incorporated.

## Sources actually inspected

- [F3 method](https://f3decomp.com/how): reconstruct C++, compile, compare, preserve failed attempts, then rebuild accepted work together.
- [F3 contributor guide](https://f3decomp.com/join) and [agent protocol](https://f3decomp.com/agents.md): version checks, bounded work packets, local compilation, separate host verification, attribution, and explicit failure reasons.
- [FNV repository at 402ce2c8e41cd587d79376ab0e497d330ce94e61](https://github.com/momusdigital/fnv_decomp/tree/402ce2c8e41cd587d79376ab0e497d330ce94e61): README, `tools/build_and_match.py`, `tools/compare.py`, `tools/compare_builds.py`, `tools/function_spans.py`, `.github/workflows/match.yml`, and LICENSE.

F3's HOW page says its reconstruction source remains private until completion. The public FNV repository is the implementation reference available for this review. Its license grants no license to reuse the contributors' code; the local tools below were written independently.

## Findings and application

| Observed mechanism | Duel Links implementation |
| --- | --- |
| Exact compiler output, not a model's verdict | The native gate compiles declared source with pinned tools and compares original and rebuilt bytes. |
| Canonical function extents | Scope records identify target, entry, boundary and size. Uncertain boundaries do not earn progress. |
| Relocation targets resolved to original symbols | General linked-image comparisons are refused. Currently only a complete, address-independent return-u32 leaf grammar can earn a match. |
| Header changes rebuild dependent units | Full integration rebuilds every enrolled unit, including shared-header consumers. No incremental shortcut is needed at the current scale. |
| Accepted work is checked again after integration | Public progress comes from a successful full integration, not from searching a folder for files claiming `matched`. |
| Original-version identity | Every target is pinned by SHA-256, size, architecture and format; CN and Steam remain separate. |
| Contributor/model statistics | Aggregate accepted units once. Missing historical attribution stays unknown. There are no invented model names, token totals, costs or visits. |
| Agent instructions and contribution packets | The public `agents.md` describes the real local CLI and GitHub PR process. There is no hosted claim/authentication service yet. |

The FNV comparator does not simply ignore relocation bytes. It first resolves each supported COFF relocation and checks its destination against the original image. Its PR checker also considers dependent translation units and exception-handling references. Those x86-specific mechanisms cannot be transplanted unchanged into AMD64 Steam or ARM64 CN binaries.

## Remaining differences

The exact original Duel Links compiler and link recipe are unresolved. Installed MSVC 14.44.35207 reproduces the six-byte pilot, which is evidence for that body only. General COFF relocation handling, data-object equivalence, exception tables, function fragments, original section layout and whole-image reproduction still require implementation and validation.

GitHub's public checks validate the committed source/evidence relationships without a game binary. The original-binary integration runs locally. A committed receipt is an auditable maintainer claim, not a cryptographic attestation from an independent build host. The dashboard labels these two forms of verification separately.

We do not connect contributors to F3's service, copy its progress, adopt its compiler, or infer a full-engine denominator from its design.
