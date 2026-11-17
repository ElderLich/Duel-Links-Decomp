# Duel Links Decomp

Native C++ reconstruction of Duel Links, with a function-by-function byte-matching gate and a [public progress dashboard](https://elderlich.github.io/Duel-Links-Decomp/).

The bootstrap currently matches **one function body, six bytes**: current Steam's exported DLL_GetRevision. The full engine denominator is not established, so no engine completion percentage is reported. This is not a rebuilt or playable engine.

## Repository

- Source/ and include/: reconstructed C++.
- Tools/Matching/: native matching, full-scope integration and failure-path tests.
- Tools/Native/: supporting native parsers used by the adjacent Duel Atlas workspace.
- config/: binary identities, enrolled scope, integration evidence and an example MSVC recipe.
- site/: the public dashboard and its sanitized progress snapshot.
- Tools/export_progress.py and Tools/export_dashboard.py: derive public progress from successful integration.

Raw binaries, Wasm, decompiler evidence, build attempts and machine-local recipes are excluded. Local Evidence/ and Results/ directories may exist in a research checkout; they are not required to view the website or run the matcher fixture tests.

## Run the checks

From this repository root:

`python Tools/refresh.py --check` runs all public checks. Once the local target and compiler are configured, `python Tools/refresh.py` also rebuilds the entire enrolled scope and regenerates the site data.

~~~powershell
python -m unittest discover -s Tools/Matching -p 'test_*.py' -v
python -m unittest discover -s Tools -p 'test_export*.py' -v
python Tools/export_progress.py --check
python Tools/export_dashboard.py --check
~~~

GitHub Actions runs these checks and publishes only site/. It validates the committed progress snapshot against its declared source and integration hashes. Matching against the original game binary is performed locally, with the pinned original inputs. Public CI is a consistency check, not an independent original-binary rebuild.

## Reproduce a native match

Use Python 3.11+ and your own exact target binaries. The default config/targets.json expects Compare/ beside this repository, matching the local DLL Research layout. Alternatively create a private targets configuration with absolute binary paths; preserve the expected SHA-256 identities.

Copy config/recipes/steam_revision.example.json to config/recipes/steam_revision.local.json and set the compiler component paths. The example retains the MSVC 14.44.35207 component digests used for the pilot. A different toolchain must be selected and audited explicitly; it is not silently accepted.

~~~powershell
python Tools/Matching/build_and_match.py verify-targets
python Tools/Matching/build_and_match.py run config/recipes/steam_revision.local.json --report Results/steam_revision.json
python Tools/export_progress.py --prepare-references
python Tools/Matching/integrate.py
python Tools/export_progress.py
python Tools/export_dashboard.py
~~~

For a custom targets file, pass --targets config/targets.local.json before the subcommand. See [the gate documentation](Tools/Matching/README.md) for function boundaries, relocation handling, recipe requirements and refusal conditions.

## Why CN helps

The current CN build exposes 3,980 Wasm host registrations. Local analysis establishes 154 host-to-native contracts reaching exports shared with Steam, and all 234 current Steam export names occur in CN. These are useful naming and API anchors. The Wasm payload is a skill/hotfix layer, not the complete native engine, and addresses cannot be transferred across architectures.

The next stage is to reconstruct small shared helpers, establish C++ types and complete boundaries, and implement verified reference resolution before counting address-sensitive functions. Only the complete address-independent return-u32 leaf grammar is currently certified for acceptance. See the [F3/FNV source review](docs/ReferenceReview.md) and [matching policy](docs/MatchingPolicy.md) for the mechanisms adopted and the remaining differences.

## Contribute with an agent

> Read https://elderlich.github.io/Duel-Links-Decomp/agents.md and set yourself up to contribute to Duel Links Decomp.

The [agent guide](site/agents.md) describes the actual local build and GitHub PR workflow. There is no hosted claim or authentication service. See [CONTRIBUTING.md](CONTRIBUTING.md) for source, checker and website changes.

## Publishing

The main branch publishes the Yu-Gi-Oh-inspired progress site through GitHub Pages. To refresh progress, rebuild every enrolled unit with the integration command, export both sanitized snapshots, inspect the changes, and commit source plus generated evidence together. A failed integration blocks new local exports. Do not increment progress counters manually. Enrollment percentages describe the reviewed scope only; the whole engine's denominator remains unknown.
