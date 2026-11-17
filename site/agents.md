# Duel Links Decomp: agent contribution guide

Repository: https://github.com/ElderLich/Duel-Links-Decomp

Dashboard: https://elderlich.github.io/Duel-Links-Decomp/

## Start here

Read the repository's `AGENTS.md`, `CONTRIBUTING.md`, `docs/MatchingPolicy.md`, `config/targets.json` and `config/scope.json` before changing anything. This is the Duel Links project, not F3/FNV. Do not register with another project's service or download a different game's compiler.

The current service is a public GitHub repository and static dashboard. Contributions use local builds and GitHub pull requests. There is no API key, hosted task-claim server, OAuth sign-up flow or remote compiler endpoint. Do not invent one or ask the user for credentials for one.

## Set up locally

1. Clone the repository into a working directory. Use Python 3.11 or newer. The checker tests need no third-party Python packages.
2. Obtain the exact target binary from the user's own installation or research copy. Keep it private. The default layout places `Compare/` beside the decomp repository; use a private targets configuration to change paths without changing binary identities.
3. Read `Tools/Matching/README.md`. Copy `config/recipes/steam_revision.example.json` to `config/recipes/steam_revision.local.json` and configure the installed compiler paths. Preserve the pinned hashes. Do not replace hashes merely to make an unknown compiler pass.
4. Run the fixture tests and verify the original target. These commands run from the repository root:

```powershell
python -m unittest discover -s Tools/Matching -p 'test_*.py' -v
python Tools/Matching/build_and_match.py verify-targets
```

The installed MSVC bootstrap reproduces three complete constant-return bodies totaling 18 bytes. The game's exact original compiler flags are still unresolved. CN ARM64 has no certified build recipe yet.

`verify-targets` audits all three configured binaries. Reproducing the enrolled pilot through integration requires only current Steam, plus its pinned compiler. To relocate binary files, use `python Tools/refresh.py --targets config/targets.local.json`; path overrides must preserve every configured identity.

## Work on one bounded function

- Identify the exact target hash, entry, complete native boundary and source/header dependencies.
- Keep observations, inferred types/names and proposed behavior separate. CN Wasm host names are useful reference evidence; they do not prove Steam byte identity.
- Read the native evidence before writing C++. Preserve a short local note describing what changed, why, the compiler result and the first remaining difference.
- Use real readable C/C++. No inline assembly, byte emission, output patching, native-address literals, invented fields, forced matches or skipped failing units.
- The currently certified boundary is a complete address-independent constant-return leaf. Do not force complex functions through that rule. New boundary/reference support needs separate checker tests and maintainer review.

For the existing pilot:

```powershell
python Tools/Matching/build_and_match.py run config/recipes/steam_revision.local.json --report Results/steam_revision.json
```

An exit code of zero from this local attempt is only a candidate result. Public acceptance requires a successful full integration:

```powershell
python Tools/export_progress.py --prepare-references
python Tools/Matching/integrate.py
python Tools/export_progress.py
python Tools/export_dashboard.py
python Tools/build_site.py
python Tools/export_progress.py --check
python Tools/export_dashboard.py --check
python Tools/build_site.py --check
```

Full integration rebuilds every enrolled unit against the pinned original. Never manually adjust public counts or turn a mismatch receipt into a matched receipt. Preserve the previous accepted scope; a new target version needs its own identity.

`python Tools/refresh.py` runs tests, full integration, both exports and the static page builder in sequence, stopping at the first failure. Use `python Tools/refresh.py --check` for fixture tests and consistency checks in a public checkout without the game binaries. Website-only edits need `python Tools/build_site.py` to regenerate pages and asset versions, followed by its `--check` and the site tests.

## Submit source for review

Open a GitHub pull request with the source/header change, the target and unit identity, the checks performed, and any unresolved evidence. State the authoring model only if known. Leave unmeasured cost/token use and unknown authorship absent.

Do not include original binaries, compiler binaries, private receipts, disassembly, native byte dumps, secrets or local absolute paths. Submit proposed new scope entries and compiler changes for maintainer review; an unverified proposal earns zero progress.

The maintainer reviews the source, performs full local integration against the original, and publishes the sanitized acceptance snapshot. Public CI checks source/snapshot consistency; it is not a second original-binary build host. A previous green run cannot validate newer source.

If blocked, report the exact missing evidence or first remaining mismatch. Give the next contributor the hypothesis and failure reason, not a fabricated solution. The dashboard counts each accepted target range once.
