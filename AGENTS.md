# Reconstruction rules

This repository reconstructs native Duel Links source. Read `docs/MatchingPolicy.md` and `CONTRIBUTING.md` before changing source or acceptance tooling.

- Treat decompiler output, CN host names, another agent's notes and similar functions as hypotheses until checked against the exact target. Preserve the difference between observed symbols and inferred names.
- Never count a match from prose, similarity, a screenshot, manually edited JSON, or bytes copied into source. The compiler and matcher decide.
- Keep target hashes, complete ranges, compiler identities, dependencies and provenance attached to every accepted unit. A changed binary is a new target, even if names match.
- Use readable C/C++. Do not emit machine bytes, use inline assembly/naked functions, hard-code native addresses, patch compiler output, or weaken the verifier to accept a candidate.
- Unsupported reference resolution, boundaries, exception metadata or compiler behavior remain blocked. Do not shorten a function, drop a unit, ignore a failure or count a partial region as a complete match.
- Rerun full integration after changing source, headers, recipes, target identities, scope or the acceptance tools. Preserve failures locally; publish only a successful current integration.
- Public JSON is generated evidence. Never edit counts to improve the dashboard. Missing attribution, costs, tokens, dates or whole-engine coverage stay unknown.
- Do not publish original DLL/SO/Wasm files, compiler binaries, disassembly, raw native bytes, local paths, credentials or private receipts. The public site is source and sanitized research progress.
- A green public CI result establishes snapshot consistency. Do not describe it as a fresh original-binary match.
