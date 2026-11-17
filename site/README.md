# Public progress website

This is a buildless GitHub Pages site. HTML, CSS, JavaScript and the original SVG mark are local assets; no npm packages, external fonts or third-party services are needed. All URLs work below a repository subpath.

From the repository root, refresh the public snapshot after a successful local matching run:

```console
python Tools/export_progress.py
python Tools/export_progress.py --check
python -m http.server 8766 --bind 127.0.0.1 --directory site
```

Open `http://127.0.0.1:8766/`. Opening `index.html` directly as a file may prevent the browser from fetching `progress.json`.

The exporter reads local matching Results, pinned targets and optional research receipts. It emits only approved fields: counts, target identities, repository-relative source paths, hashes and complete-boundary match records. Original binary bytes, tool commands, local paths, private evidence and game binaries are excluded. Duplicate ranges are counted once; overlapping or contradictory matches are rejected. Source inputs must still match their receipt. The whole-engine denominator remains unknown.

The committed `progress.json` is a public snapshot of local verification. `--check` validates its schema, totals, unique ranges, target pins, declared source/header hashes and matching-gate hash against the checkout. CI does not rebuild or independently reverify the original binaries. Changing source, headers, matcher or target pins requires updating the relevant local receipts and exporting again before the snapshot can pass.

The repository Pages workflow publishes this directory. GitHub links point to `ElderLich/Duel-Links-Decomp`; a fork can update them by passing `--repo-url https://github.com/OWNER/REPOSITORY` when exporting, and changing the fallback links in `index.html`.

The geometric artwork was created for this site in SVG and CSS. No official card art or game assets are distributed. Site interactions include keyboard-operable workflow/platform tabs, function search, evidence disclosures and expandable hashes. Reduced-motion preferences are respected.
