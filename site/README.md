# Public progress website

This is a static multi-page GitHub Pages site. A small standard-library Python generator renders HTML from local templates and the published evidence. CSS, JavaScript and the original SVG mark are local assets; no npm packages, external fonts or third-party services are needed. All URLs work below a repository subpath.

From the repository root, the full local workflow rebuilds every enrolled unit before publishing updated evidence:

```console
python Tools/refresh.py
```

After changing only the presentation, regenerate the pages and check their freshness:

```console
python Tools/build_site.py
python Tools/build_site.py --check
python -m http.server 8766 --bind 127.0.0.1 --directory site
```

Open `http://127.0.0.1:8766/`. Opening `index.html` directly as a file may prevent the browser from fetching `progress.json`.

The exporter accepts only the latest successful full integration, its private receipts, and the integration-bound research record. It never scans arbitrary JSON files for `matched` claims. It emits only approved fields: counts, target identities, repository-relative source paths, hashes and complete-boundary match records. Original binary bytes, tool commands, local paths, private evidence and game binaries are excluded. Overlapping or contradictory matches are rejected. Source inputs must still match their receipt. The whole-engine denominator remains unknown.

The committed `progress.json` is a public snapshot of local verification. `--check` validates its schema, totals, unique ranges, target pins, source/header hashes, reference/control evidence and integration-tool hashes against the checkout. CI does not rebuild or independently reverify the original binaries. Run `python Tools/refresh.py` from the repository root after changing accepted source, headers, recipes, checker tools or target pins. Run `python Tools/refresh.py --check` for the public-checkout tests only.

The repository Pages workflow publishes this directory. The source templates are `site/templates/layout.html` and `site/templates/sections.html`; edit them instead of the generated page HTML. `Tools/build_site.py` owns the route list, navigation, breadcrumbs and evidence-derived static views. GitHub links and the published agent prompt currently point to `ElderLich/Duel-Links-Decomp`; a fork should update these project links deliberately.

The nine generated routes are `/`, `/progress/`, `/progress/matches/`, `/progress/history/`, `/progress/scope/`, `/progress/contributors/`, `/how/`, `/research/` and `/join/`. These are real nested HTML pages, not hash routing. The homepage contains the introduction, headline facts and links to the separate reports.

Each page declares `data-root` and `data-page` on its `html` element. Asset URLs carry the first 12 characters of their content SHA-256; edits to CSS or JavaScript therefore require regeneration. `--check` compares all nine outputs byte for byte with their current inputs without writing. Every page embeds the exact public JSON snapshots and pre-renders the visible facts, tables and initial plots. Data remains readable before JavaScript runs or when a refresh request fails.

The geometric artwork was created for this site in SVG and CSS. No official card art or game assets are distributed. Site interactions include keyboard-operable workflow/platform tabs, function search, evidence disclosures and expandable hashes. Reduced-motion preferences are respected.

## Research dashboard

`dashboard.json` supplies the integration report separately from `progress.json`. The page reads its `scope`, `targets`, `size_map`, `daily_trend`, `contributors`, `models`, `milestones` and `integration` records. These are committed evidence-derived data, not live browser analytics. The match ledger remains usable when the dashboard is unavailable.

- The history page shows separate cumulative byte and function plots, plus daily accepted bytes grouped by explicitly recorded model attribution. One recorded publication date produces one point, with no invented trend or forecast. Tables expose the exact dated values.
- The scope map uses proportional SVG tile areas for measured body sizes within the selected enrolled target. A tile opens and highlights its inventory row. Unmeasured engine code is not represented as an estimated remainder.
- The percentage refers only to integrated bytes divided by enrolled body bytes. Whole-engine completion remains unknown even when all enrolled units match.
- Contributor and model totals use explicit attribution records. The contribution table leaves unknown authorship unranked. Model bars and daily plots identify unrecorded attribution explicitly. Visitor counts, token usage and project costs are marked as not collected.
- Milestone events come from recorded integrations; the longer-term roadmap describes planned work separately.

The join section links the published `agents.md`, provides a copyable agent prompt, and explains the local CLI plus GitHub pull-request workflow. Clipboard failure selects the prompt for manual copying. There is no website account system, signup service or remote job runner.

All charts and controls are native SVG/HTML/CSS/JavaScript; no chart library or analytics provider is loaded. The static data tables, keyboard controls, disclosures, target filter and responsive charts support inspecting the same facts without relying on color alone.
