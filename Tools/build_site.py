#!/usr/bin/env python3
"""Render the static multi-page report from published evidence and local templates.

No compiler, native binary, external service or frontend build dependency is used.
Run again after changing public data, templates, CSS or JavaScript. --check never
writes: it rejects any generated page that differs from the current inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
PAGES = (
    {"key": "home", "route": "", "label": "Home", "sections": ("hero", "stats")},
    {"key": "progress", "route": "progress/", "label": "Progress", "sections": ()},
    {"key": "matches", "route": "progress/matches/", "label": "Match ledger", "sections": ("ledger",)},
    {"key": "history", "route": "progress/history/", "label": "History", "sections": ("trend",)},
    {"key": "scope", "route": "progress/scope/", "label": "Enrolled scope", "sections": ("scope",)},
    {"key": "contributors", "route": "progress/contributors/", "label": "Leaderboard", "sections": ("contributors",)},
    {"key": "how", "route": "how/", "label": "How it works", "sections": ("method", "evidence")},
    {"key": "research", "route": "research/", "label": "Research", "sections": ("bridge", "roadmap")},
    {"key": "join", "route": "join/", "label": "Contribute", "sections": ("join",)},
)
ROUTES = tuple(page["route"] for page in PAGES)
DESCRIPTIONS = {
    "home": "An independent reconstruction of the Duel Links native engine, one verified function at a time.",
    "progress": "Explore the verified match ledger, recorded history, enrolled scope and contribution evidence.",
    "matches": "Target-pinned native function matches with source links, proven boundaries and evidence hashes.",
    "history": "Recorded publication dates and cumulative verified function bytes, with no invented growth estimates.",
    "scope": "The measured enrolled function inventory, distinct from the unknown size of the complete native engine.",
    "contributors": "Recorded contribution and model attribution, including explicitly unrecorded authorship.",
    "how": "How readable source, pinned compilers and strict byte comparison establish a native function match.",
    "research": "CN and Wasm research anchors, shared contracts and the native decompilation roadmap.",
    "join": "Set up a local contribution, give your agent the guide, and submit a reviewable pull request.",
}


def esc(value):
    return html.escape(str(value), quote=True)


def count(value):
    return "Unverified" if value is None else f"{value:,}"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def asset_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


class ElementContent(HTMLParser):
    """Locate one element's inner HTML while respecting nested elements."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, source, wanted):
        super().__init__(convert_charrefs=False)
        self.source, self.wanted = source, wanted
        self.offsets, position = [], 0
        for line in source.splitlines(keepends=True):
            self.offsets.append(position)
            position += len(line)
        self.stack, self.found = [], None
        self.feed(source)

    def position(self):
        line, column = self.getpos()
        return self.offsets[line - 1] + column

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append((tag, dict(attrs).get("id"), self.position() + len(self.get_starttag_text())))

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                _, identity, start = self.stack[index]
                self.stack = self.stack[:index]
                if identity == self.wanted:
                    self.found = (start, self.position())
                break


def fill(source, identity, content):
    found = ElementContent(source, identity).found
    if found is None:
        return source
    start, end = found
    return source[:start] + str(content) + source[end:]


def table(caption, headings, rows, identities=None):
    parts = ['<table class="report-table"><caption>' + esc(caption) + '</caption><thead><tr>']
    parts.extend('<th scope="col">' + esc(value) + '</th>' for value in headings)
    parts.append('</tr></thead><tbody>')
    for index, values in enumerate(rows):
        identity = f' data-scope-id="{esc(identities[index])}"' if identities else ''
        parts.append('<tr' + identity + '>')
        for value in values:
            numeric = isinstance(value, int)
            parts.append(('<td class="number">' if numeric else '<td>') + esc(count(value) if numeric else value) + '</td>')
        parts.append('</tr>')
    return ''.join(parts) + '</tbody></table>'


def source_link(progress, path, label):
    url = progress["project"]["repo_url"] + '/blob/main/' + quote(path, safe='/')
    return f'<a class="text-link" href="{esc(url)}">{esc(label)}</a>'


def unit_cards(progress):
    units = [unit for unit in progress["units"] if unit["target"].startswith("steam-")]
    result = []
    for unit in units:
        proof = [("Complete boundary", unit["boundary"]), ("Original RVA", unit["original_rva"]),
                 ("Body SHA-256", unit["body_sha256"]), ("Target SHA-256", unit["target_sha256"])]
        proof += [(item["path"], item["sha256"]) for item in unit["inputs"]]
        proof += [("Receipt SHA-256", unit["receipt_sha256"]), ("Gate SHA-256", unit["gate_sha256"]), ("Recipe SHA-256", unit["recipe_sha256"])]
        facts = ''.join(f'<dt>{esc(label)}</dt><dd><code>{esc(value)}</code></dd>' for label, value in proof)
        result.append(f'''<article class="unit"><div class="unit-header"><div class="unit-heading"><span class="unit-symbol" aria-hidden="true">◇</span><div><h3>{esc(unit["name"])}</h3><p class="unit-subtitle">{esc(unit["target"])} · {esc(unit["original_rva"])}</p></div></div><div class="unit-measure"><strong>{count(unit["body_bytes"])}</strong><small>BYTES MATCHED</small></div></div><div class="unit-meta"><span class="badge badge-cyan">Exact body match</span><span class="badge">{esc(unit["boundary"])}</span>{source_link(progress, unit["source"]["path"], "Read the source ↗")}</div><details><summary>Inspect the proof</summary><dl class="proof-grid">{facts}</dl><p class="proof-note">These hashes identify locally checked evidence. Public CI checks source and ledger consistency; it does not independently rebuild the private game binaries.</p></details></article>''')
    return ''.join(result) or '<div class="empty-state"><h3>No verified Steam functions yet.</h3><p>No missing matches are estimated.</p></div>'


def target_cards(progress):
    result = []
    for target in progress["targets"]:
        if target["platform"] != "steam":
            continue
        result.append(f'''<article class="target"><div class="target-header"><h3>{esc(target["label"])}</h3><span class="target-format">{esc(target["format"].upper())} · {esc(target["architecture"].upper())}</span></div><details class="static-hash"><summary>SHA-256 · {esc(target["sha256"][:12])}…{esc(target["sha256"][-8:])}</summary><code>{esc(target["sha256"])}</code></details><p>{count(target["image_bytes"])} image bytes · {esc(target["toolchain_note"])}</p></article>''')
    return ''.join(result)


def history_chart(dashboard, metric="cumulative_body_bytes", suffix="bytes"):
    points = dashboard["daily_trend"]
    if not points:
        return '<p class="report-placeholder">No dated snapshots have been published yet.</p>'
    maximum = max(1, *(point[metric] for point in points))
    left, right, top, bottom = 45, 525, 40, 188
    from datetime import date
    days = [date.fromisoformat(point["date"]).toordinal() for point in points]
    span = max(days) - min(days)
    positions = [left + (day - days[0]) / span * (right - left) if span else (left + right) / 2 for day in days]
    ys = [bottom - point[metric] / maximum * (bottom - top) for point in points]
    svg = [f'<svg viewBox="0 0 560 230" role="img" aria-labelledby="trend-{suffix}-svg-title trend-{suffix}-svg-description"><title id="trend-{suffix}-svg-title">Recorded cumulative matched {suffix}</title><desc id="trend-{suffix}-svg-description">Exact dates and values are in the history table. No activity is inferred between recorded dates.</desc>']
    for value in (0, maximum):
        y = bottom - value / maximum * (bottom - top)
        svg.append(f'<line class="chart-grid" x1="{left}" x2="{right}" y1="{y}" y2="{y}"/><text class="chart-axis" x="{left-12}" y="{y+4}" text-anchor="end">{count(value)}</text>')
    if len(points) > 1:
        path = ' '.join(f'M{x} {ys[index]}' if index == 0 else f'H{x} V{ys[index]}' for index, x in enumerate(positions))
        svg.append(f'<path class="chart-line" d="{path}"/>')
    for index, point in enumerate(points):
        x, y = positions[index], ys[index]
        if len(points) == 1:
            svg.append(f'<circle class="chart-halo" cx="{x}" cy="{y}" r="17"/>')
        svg.append(f'<circle class="chart-dot" cx="{x}" cy="{y}" r="6"><title>{esc(point["date"])}: {count(point[metric])} {suffix}</title></circle>')
        if index in (0, len(points)-1):
            svg.append(f'<text class="chart-axis" x="{x}" y="215" text-anchor="middle">{esc(point["date"])}</text><text class="chart-value" x="{x}" y="{y-25}" text-anchor="middle">{count(point[metric])} {"B" if suffix == "bytes" else "fn"}</text>')
    return ''.join(svg) + '</svg>'


def daily_chart(dashboard):
    from collections import defaultdict
    days = defaultdict(lambda: defaultdict(int))
    for unit in dashboard["units"]:
        days[unit["first_accepted_date"]][unit["model"] or "Unknown / unrecorded"] += unit["body_bytes"]
    if not days:
        return '<p class="report-placeholder">No daily acceptance records have been published.</p>'
    models = sorted({model for day in days.values() for model in day})
    colors = {model: ("#b2a0ed" if model == "Unknown / unrecorded" else ["#83e7f4", "#e6c584", "#77c5a0", "#e59c91"][index % 4]) for index, model in enumerate(models)}
    maximum = max(1, *(sum(values.values()) for values in days.values()))
    width = min(90, 440 / len(days))
    svg = ['<svg viewBox="0 0 560 230" role="img" aria-label="Daily accepted bytes by explicitly recorded model; unknown attribution is shown separately."><line class="chart-grid" x1="45" x2="525" y1="188" y2="188"/>']
    for index, (day, values) in enumerate(sorted(days.items())):
        x = 285 if len(days) == 1 else 75 + index / (len(days)-1) * 420
        y = 188
        for model in models:
            value = values.get(model, 0)
            height = value / maximum * 145
            y -= height
            svg.append(f'<rect x="{x-width/2}" y="{y}" width="{width}" height="{height}" fill="{colors[model]}"><title>{esc(day)} · {esc(model)} · {count(value)} B</title></rect>')
        svg.append(f'<text class="chart-value" x="{x}" y="{y-15}" text-anchor="middle">{count(sum(values.values()))} B</text><text class="chart-axis" x="{x}" y="215" text-anchor="middle">{esc(day)}</text>')
    return ''.join(svg) + '</svg>'


def state(value):
    return ("matched", "Matched") if value in {"integrated", "matched"} else ("blocked", "Blocked") if value == "blocked" else ("open", "Open")


def scope_map(dashboard):
    items = [item for item in dashboard["size_map"] if item["body_bytes"] and item["body_bytes"] > 0]
    total = sum(item["body_bytes"] for item in items)
    if not total:
        return '<p class="report-placeholder">No measured function boundaries have been enrolled.</p>'
    parts = [f'<svg class="scope-svg" viewBox="0 0 1000 210" role="img" aria-label="{len(items)} enrolled functions, {total} measured body bytes. Exact values follow in the scope table.">']
    offset = 0
    for item in items:
        width = item["body_bytes"] / total * 1000
        style, label = state(item["status"])
        parts.append(f'<g class="scope-rect {style}"><rect class="scope-cell" x="{offset}" y="0" width="{width}" height="210"/><title>{esc(item["name"])} · {count(item["body_bytes"])} B · {label}</title>')
        if width > 220:
            parts.append(f'<text class="scope-svg-state" x="{offset+22}" y="34">{label.upper()}</text><text class="scope-svg-name" x="{offset+22}" y="88">{esc(item["name"])}</text><text class="scope-svg-target" x="{offset+22}" y="113">{esc(item["target"])}</text><text class="scope-svg-size" x="{offset+22}" y="185">{count(item["body_bytes"])} B</text>')
        parts.append('</g>')
        offset += width
    return ''.join(parts) + '</svg>'


def attribution(items):
    if not items:
        return '<p class="attribution-empty">No verified attribution has been recorded.</p>'
    total = sum(item["body_bytes"] for item in items)
    result = []
    for item in items:
        note = "Verified work with no recorded attribution." if item["id"] == "unknown" else "Explicitly recorded attribution."
        share = item["body_bytes"] / total * 100 if total else 0
        result.append(f'<div class="attribution-row"><div><div class="attribution-name">{esc(item["label"])}</div><p class="attribution-role">{note}</p></div><div class="attribution-count">{count(item["units"])} fn · {count(item["body_bytes"])} B</div><div class="attribution-bar" aria-hidden="true"><span style="width:{share:g}%"></span></div></div>')
    return ''.join(result)


def contributor_table(items):
    rank = 0
    rows = []
    for item in sorted(items, key=lambda item: (item["id"] == "unknown", -item["body_bytes"], item["label"])):
        if item["id"] == "unknown":
            position = "—"
        else:
            rank += 1
            position = rank
        rows.append([position, item["label"], item["units"], item["body_bytes"]])
    return table("Verified contribution totals. Unrecorded authorship is shown without a rank.", ["Rank", "Contributor", "Functions", "Body bytes"], rows)


def milestone_log(dashboard):
    parts = ['<div id="recorded-milestones" class="milestone-log"><span class="eyebrow">Recorded milestones</span>']
    for item in dashboard["milestones"]:
        parts.append(f'<article class="milestone-event"><time datetime="{esc(item["date"])}">{esc(item["date"][:10])}</time><h4>{esc(item["label"])}</h4><p>{count(item["units"])} functions · {count(item["body_bytes"])} body bytes</p></article>')
    return ''.join(parts) + '</div>'


def prerender(fragment, progress, dashboard):
    summary, refs, scope = progress["summary"], progress["references"], dashboard["scope"]
    percent = scope["integrated_body_bytes"] / scope["enrolled_body_bytes"] * 100 if scope["enrolled_body_bytes"] else None
    steam = [unit for unit in progress["units"] if unit["target"].startswith("steam-")]
    values = {
        "function-count": count(summary["verified_functions"]), "function-plural": "" if summary["verified_functions"] == 1 else "s",
        "byte-count": count(summary["matched_body_bytes"]), "target-count": count(len(progress["targets"])),
        "binding-count": count(refs["host_bindings"]), "contract-count": count(refs["verified_export_contracts"]), "export-count": count(refs["shared_exports"]),
        "reference-count": count(refs["newly_recovered_card_references"]),
        "negative-status": "negative control passed" if summary["negative_control"] == "passed" else "negative-control evidence unavailable",
        "enrolled-bytes": count(scope["enrolled_body_bytes"]), "enrolled-functions": count(scope["enrolled_units"]),
        "enrolled-function-label": "function with an enrolled boundary" if scope["enrolled_units"] == 1 else "functions with enrolled boundaries",
        "enrolled-percent": f'{percent:g}% of enrolled bytes' if percent is not None else "No enrolled bytes",
        "scope-meter-fill": "", "scope-meter-caption": f'{count(scope["integrated_body_bytes"])} of {count(scope["enrolled_body_bytes"])} enrolled body bytes integrated. {count(scope["pending_units"])} enrolled units pending.',
        "platform-status": f'{count(len(steam))} verified {"function" if len(steam)==1 else "functions"} · {count(sum(unit["body_bytes"] for unit in steam))} matched bytes',
        "unit-list": unit_cards(progress), "target-list": target_cards(progress), "trend-bytes-chart": history_chart(dashboard),
        "trend-functions-chart": history_chart(dashboard, "cumulative_units", "functions"), "daily-model-chart": daily_chart(dashboard),
        "trend-note": "One recorded publication date. A single point cannot establish pace, daily growth or a forecast." if len(dashboard["daily_trend"]) == 1 else "Only recorded publication dates are shown. No activity is inferred between snapshots.",
        "history-table": table("Recorded publication dates from accepted integration records.", ["Date", "Total functions", "Total bytes", "New functions", "New bytes"], [[p["date"],p["cumulative_units"],p["cumulative_body_bytes"],p["accepted_units"],p["accepted_body_bytes"]] for p in dashboard["daily_trend"]]),
        "scope-target": '<option value="all">All enrolled targets</option>' + ''.join(f'<option value="{esc(target["id"])}">{esc(target["label"])}</option>' for target in dashboard["targets"]),
        "scope-map": scope_map(dashboard),
        "scope-map-note": f'{count(scope["enrolled_units"])} measured functions · {count(scope["enrolled_body_bytes"])} enrolled body bytes. Areas represent the enrolled scope only; the complete engine remains unmeasured.',
        "scope-table": table("Enrolled function boundaries; this is not a complete engine inventory.", ["Function", "Target", "Body bytes", "State", "Source"], [[u["name"],u["target"],u["body_bytes"],state(u["status"])[1],u["source"]] for u in dashboard["size_map"]], [u["id"] for u in dashboard["size_map"]]),
        "contributor-list": contributor_table(dashboard["contributors"]), "model-list": attribution(dashboard["models"]),
        "attribution-note": "Model and tool credit requires explicit records. Unknown attribution is never inferred from the source code.",
        "dashboard-status": f'Published integration · {esc(dashboard["integration"]["completed_at"][:10])}. Full enrolled scope passed locally; public CI checks consistency.',
    }
    for identity, content in values.items():
        fragment = fill(fragment, identity, content)
    fragment = fragment.replace('id="scope-meter-fill"', f'id="scope-meter-fill" style="width:{percent or 0:g}%"')
    if 'id="roadmap"' in fragment:
        fragment = fragment.rsplit('</section>',1)[0] + milestone_log(dashboard) + '</section>'
    return fragment


def nav(page, prefix):
    def link(key, label=None):
        target = next(item for item in PAGES if item["key"] == key)
        current = ' aria-current="page"' if page["key"] == key else ''
        return f'<a href="{prefix}{target["route"]}"{current}>{esc(label or target["label"])}</a>'
    active = ' class="is-active"' if page["route"].startswith("progress/") else ''
    return '<nav class="main-nav" aria-label="Main navigation">' + link("home") + f'<details class="nav-dropdown"><summary{active}>Progress <span aria-hidden="true">▾</span></summary><div class="nav-dropdown-menu">' + ''.join(link(key, "Overview" if key == "progress" else None) for key in ("progress","matches","history","scope","contributors")) + '</div></details>' + link("how") + link("research") + link("join") + '<a class="nav-github repo-link" href="https://github.com/ElderLich/Duel-Links-Decomp">GitHub <span aria-hidden="true">↗</span></a></nav>'


def breadcrumbs(page, prefix):
    if page["key"] == "home":
        return ''
    trail = f'<a href="{prefix}">Home</a>'
    if page["route"].count('/') > 1:
        trail += f'<span aria-hidden="true">/</span><a href="{prefix}progress/">Progress</a>'
    return '<nav class="breadcrumbs section-shell" aria-label="Breadcrumb">' + trail + f'<span aria-hidden="true">/</span><span aria-current="page">{esc(page["label"])}</span></nav>'


def directory(prefix, keys, heading=None):
    cards = []
    for index, key in enumerate(keys, 1):
        page = next(item for item in PAGES if item["key"] == key)
        cards.append(f'<a class="directory-card" href="{prefix}{page["route"]}"><span class="eyebrow">0{index} / {esc(page["label"])}</span><h3>{esc(page["label"])} <span aria-hidden="true">↗</span></h3><p>{esc(DESCRIPTIONS[key])}</p></a>')
    title = f'<div class="section-heading compact"><div><span class="eyebrow">Explore the project</span><h2>{esc(heading)}</h2></div></div>' if heading else ''
    return f'<section class="section-shell directory-section">{title}<div class="page-directory">' + ''.join(cards) + '</div></section>'


def progress_overview(dashboard):
    scope = dashboard["scope"]
    rows = (
        f'<div class="report-stat"><span>Functions matched</span><strong id="integrated-unit-count">{count(scope["integrated_units"])}</strong><small>of <span id="enrolled-unit-count">{count(scope["enrolled_units"])}</span> enrolled functions</small></div>'
        f'<div class="report-stat"><span>Body bytes matched</span><strong id="integrated-byte-count">{count(scope["integrated_body_bytes"])}</strong><small>of <span id="enrolled-byte-count">{count(scope["enrolled_body_bytes"])}</span> enrolled body bytes</small></div>'
        f'<div class="report-stat"><span>Still to do in enrolled scope</span><strong id="pending-unit-count">{count(scope["pending_units"])}</strong><small>functions · <span id="pending-byte-count">{count(scope["pending_body_bytes"])}</span> body bytes</small></div>'
    )
    bars = []
    for name, matched, total in (("functions",scope["integrated_units"],scope["enrolled_units"]),("bytes",scope["integrated_body_bytes"],scope["enrolled_body_bytes"])):
        percent = matched / total * 100 if total else 0
        label = f'{count(matched)} / {count(total)} · {percent:g}%' if total else f'No enrolled {name}'
        bars.append(f'<div class="scope-progress-row"><span>{name.capitalize()}</span><div class="segmented-track" aria-hidden="true"><div class="segmented-fill" id="{name}-scope-fill" style="width:{percent:g}%"></div></div><strong id="{name}-scope-label">{label}</strong></div>')
    return '<section class="section-shell progress-overview"><div class="report-stat-grid">' + rows + '</div><div class="scope-progress-bars" aria-label="Matched proportions of the enrolled scope"><span class="eyebrow">Matched within the enrolled scope</span>' + ''.join(bars) + '</div><div class="unknown-engine"><span aria-hidden="true">◇</span><div><strong>Whole-engine completion: unknown</strong><p>Remaining means enrolled work still open. Unenrolled engine code has not been counted, so these scope bars do not describe the complete engine.</p></div></div></section>'


def render_pages(root=ROOT):
    root = Path(root).resolve()
    site = root / "site"
    progress, dashboard = read_json(site / "progress.json"), read_json(site / "dashboard.json")
    if progress["schema_version"] != 1 or dashboard["schema_version"] != 1:
        raise ValueError("Unsupported public data schema")
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', progress["project"]["repo_url"]):
        raise ValueError("Expected a public GitHub repository URL")
    if (progress["summary"]["verified_functions"], progress["summary"]["matched_body_bytes"]) != (dashboard["scope"]["integrated_units"], dashboard["scope"]["integrated_body_bytes"]):
        raise ValueError("Match and dashboard snapshots disagree")
    if progress["summary"]["completion_percent"] is not None or dashboard["scope"]["engine_completion_percent"] is not None:
        raise ValueError("Whole-engine completion is not established")
    raw = (site / "templates/sections.html").read_text(encoding="utf-8")
    fragments = dict(re.findall(r'<!-- fragment:([a-z-]+) -->\s*(.*?)(?=<!-- fragment:|\Z)', raw, re.S))
    layout = (site / "templates/layout.html").read_text(encoding="utf-8")
    common = {"CSS_HASH": asset_hash(site / "style.css"), "JS_HASH": asset_hash(site / "app.js"), "MARK_HASH": asset_hash(site / "mark.svg"),
              "UPDATED": esc(progress["updated"]), "PROGRESS_JSON": json.dumps(progress, ensure_ascii=False, separators=(',',':')).replace('<','\\u003c'),
              "DASHBOARD_JSON": json.dumps(dashboard, ensure_ascii=False, separators=(',',':')).replace('<','\\u003c')}
    rendered = {}
    for page in PAGES:
        prefix = '../' * page["route"].count('/') or './'
        content = '\n'.join(prerender(fragments[key], progress, dashboard) for key in page["sections"])
        if page["key"] == "home":
            content += directory(prefix, ("progress","how","research","join"), "Choose your next move.")
        elif page["key"] == "progress":
            content = '<section class="section-shell page-intro"><span class="eyebrow">The research report</span><h1>Decompilation progress</h1><p>Explore each part of the report. Enrolled scope is measurable; whole-engine completion remains unknown.</p></section>'
            content += progress_overview(dashboard)
            content += directory(prefix, ("matches","history","scope","contributors"))
        else:
            content = re.sub(r'<h2(\s[^>]*)?>', lambda m: '<h1' + (m.group(1) or '') + '>', content, count=1)
            content = content.replace('</h2>', '</h1>', 1)
        replacements = {**common, "ROOT": prefix, "PAGE": page["key"], "TITLE": esc((page["label"] + " · " if page["key"] != "home" else "") + "Duel Links Native Decompilation"),
                        "DESCRIPTION": esc(DESCRIPTIONS[page["key"]]), "NAV": nav(page, prefix), "BREADCRUMBS": breadcrumbs(page,prefix),
                        "MAIN_CLASS": "home-main" if page["key"] == "home" else "page-main", "CONTENT": content}
        result = layout
        # CONTENT contains the ROOT token used by the guide and hero links.
        for key, value in replacements.items():
            if key != "ROOT":
                result = result.replace('{{'+key+'}}', value)
        result = result.replace('{{ROOT}}', prefix)
        if re.search(r'\{\{[A-Z_]+\}\}', result):
            raise ValueError(f"Unresolved template token in {page['route']}")
        if re.search(r'Loading|checking receipt|Scope figures are loading|Snapshot loading', result):
            raise ValueError(f"Unrendered loading placeholder in {page['route']}")
        rendered['site/' + page["route"] + 'index.html'] = '\n'.join(line.rstrip() for line in result.splitlines()) + '\n'
    return rendered


def build(root=ROOT, check=False):
    root = Path(root).resolve()
    rendered = render_pages(root)
    stale = []
    for relative, content in rendered.items():
        path = root / relative
        encoded = content.encode('utf-8')
        if not path.is_file() or path.read_bytes() != encoded:
            stale.append(relative)
            if not check:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(encoded)
    if check and stale:
        raise ValueError("Generated pages are stale; run python Tools/build_site.py: " + ', '.join(stale))
    return list(rendered)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--check', action='store_true', help='Reject stale generated pages without writing')
    args = parser.parse_args()
    paths = build(args.root, args.check)
    print(f"{'Validated' if args.check else 'Generated'} {len(paths)} static pages from published evidence.")


if __name__ == '__main__':
    main()
