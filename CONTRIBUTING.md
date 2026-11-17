# Contributing

Begin with the [agent guide](site/agents.md) and [matching policy](docs/MatchingPolicy.md). The same evidence requirements apply to humans and agents.

## Source changes

Keep changes bounded to a named target and complete native unit. Use original-symbol names when available; label inferred names. Check observed field widths, signedness, calling conventions, control flow and dependencies before reconstructing them. Decompiled pseudocode is a starting hypothesis.

Run the local compiler gate, then full integration. A shared-header change rebuilds every enrolled unit. Keep failed attempts locally, including the reason and the first remaining mismatch. Do not delete accepted units, truncate ranges or weaken comparisons to turn a failure into success.

Include in a PR description:

- Target identity and the unit or dependency changed.
- Evidence supporting the implementation and any uncertainty.
- Exact checks run and their results; distinguish fixture tests, local original-binary matching and public snapshot validation.
- Known contributor/model attribution, if available. Do not estimate unmeasured token or cost totals.

New functions, changed compiler recipes and new acceptance mechanisms need maintainer review and original-binary integration. Until accepted they remain proposals, not progress.

## Acceptance and publication

```powershell
python -m unittest discover -s Tools/Matching -p 'test_*.py' -v
python -m unittest discover -s Tools -p 'test_export*.py' -v
python Tools/export_progress.py --prepare-references
python Tools/Matching/integrate.py
python Tools/export_progress.py
python Tools/export_dashboard.py
python Tools/export_progress.py --check
python Tools/export_dashboard.py --check
```

Review the sanitized output before committing it with source. The integration ledger binds scope, target, source, compiler and verification tooling. Do not edit generated acceptance records by hand. The public workflow tests the verifier and checks these relationships without private game files; this is explicitly a consistency check, not independent native reproduction.

Original binaries, Wasm, decompiler output, raw native receipts, local compiler paths, credentials and compiler binaries stay outside Git. Check `git diff --cached` before publishing.

## Website changes

Preserve readable mobile and desktop layouts, keyboard access and accurate empty states. Derive charts from generated acceptance records. Keep full-engine totals unknown until an independently reviewed inventory establishes them. Do not add fake visitors, account sign-ups, contributor scores, model attribution, token use or costs.

## Checker changes

Add a test demonstrating the false acceptance or rejection being fixed. In particular, equal instruction bytes must not excuse different referenced addresses, partial function extents, missing headers, stale output or stale target identities. Rerun the real pilot and an intentionally wrong candidate after changing the gate. General address-sensitive functions remain unsupported until reference resolution is verified.
