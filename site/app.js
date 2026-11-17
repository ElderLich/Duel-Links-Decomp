"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const format = new Intl.NumberFormat("en");
  const count = (value) => value === null || value === undefined ? "Unverified" : format.format(value);
  let progress;
  let platform = "steam";
  let dashboard;
  let trendMetric = "cumulative_body_bytes";

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function sourceLink(path, label) {
    const link = element("a", "text-link", label);
    link.href = `${progress.project.repo_url}/blob/${progress.project.branch}/${path.split("/").map(encodeURIComponent).join("/")}`;
    return link;
  }

  function hashToggle(hash, label = "SHA-256") {
    const button = element("button", "hash-toggle");
    button.type = "button";
    button.setAttribute("aria-expanded", "false");
    const prefix = element("span", "hash-label", label);
    const value = element("span", "hash-value", `${hash.slice(0, 12)}…${hash.slice(-8)}`);
    const icon = element("span", "hash-expand", "+");
    icon.setAttribute("aria-hidden", "true");
    button.append(prefix, value, icon);
    button.setAttribute("aria-label", `Show full ${label} hash`);
    button.addEventListener("click", () => {
      const expanded = button.getAttribute("aria-expanded") !== "true";
      button.setAttribute("aria-expanded", String(expanded));
      button.setAttribute("aria-label", `${expanded ? "Shorten" : "Show full"} ${label} hash`);
      value.textContent = expanded ? hash : `${hash.slice(0, 12)}…${hash.slice(-8)}`;
      icon.textContent = expanded ? "−" : "+";
    });
    return button;
  }

  function proofRow(list, title, value) {
    list.append(element("dt", "", title));
    const cell = element("dd");
    if (typeof value === "string") cell.textContent = value;
    else cell.append(value);
    list.append(cell);
  }

  function renderUnit(unit) {
    const card = element("article", "unit");
    const header = element("div", "unit-header");
    const heading = element("div", "unit-heading");
    const symbol = element("span", "unit-symbol", "◇");
    symbol.setAttribute("aria-hidden", "true");
    const title = element("div");
    title.append(element("h3", "", unit.name), element("p", "unit-subtitle", `${unit.target} · ${unit.original_rva.toUpperCase().replace("0X", "0x")}`));
    heading.append(symbol, title);
    const measure = element("div", "unit-measure");
    measure.append(element("strong", "", count(unit.body_bytes)), element("small", "", "BYTES MATCHED"));
    header.append(heading, measure);
    const meta = element("div", "unit-meta");
    meta.append(element("span", "badge badge-cyan", "Exact body match"), element("span", "badge", unit.boundary), sourceLink(unit.source.path, "Read the source ↗"));
    const details = element("details");
    details.append(element("summary", "", "Inspect the proof"));
    const proof = element("dl", "proof-grid");
    proofRow(proof, "Complete boundary", unit.boundary);
    proofRow(proof, "Original RVA", unit.original_rva);
    proofRow(proof, "Body identity", hashToggle(unit.body_sha256, "Body SHA-256"));
    proofRow(proof, "Target identity", hashToggle(unit.target_sha256, "Target SHA-256"));
    for (const input of unit.inputs) proofRow(proof, input.path, hashToggle(input.sha256, "Input SHA-256"));
    proofRow(proof, "Match receipt", hashToggle(unit.receipt_sha256, "Receipt SHA-256"));
    proofRow(proof, "Matching gate", hashToggle(unit.gate_sha256, "Gate SHA-256"));
    proofRow(proof, "Compile recipe", hashToggle(unit.recipe_sha256, "Recipe SHA-256"));
    details.append(proof, element("p", "proof-note", "Public hashes identify the locally checked evidence. CI checks the declared source, header, gate and target pins. It does not rebuild the private original binaries."));
    card.append(header, meta, details);
    return card;
  }

  function renderLedger() {
    if (!progress) return;
    const targets = progress.targets.filter((target) => target.platform === platform);
    const ids = new Set(targets.map((target) => target.id));
    const units = progress.units.filter((unit) => ids.has(unit.target));
    const query = $("unit-search").value.trim().toLowerCase();
    const shown = units.filter((unit) => `${unit.name} ${unit.source.path} ${unit.target}`.toLowerCase().includes(query));
    $("platform-panel").setAttribute("aria-labelledby", `${platform}-tab`);
    $("platform-title").textContent = platform === "steam" ? "Steam / AMD64" : "China / ARM64";
    $("platform-status").textContent = `${count(units.length)} verified ${units.length === 1 ? "function" : "functions"} · ${count(units.reduce((sum, unit) => sum + unit.body_bytes, 0))} matched bytes`;
    $("unit-list").replaceChildren(...shown.map(renderUnit));
    if (!shown.length) {
      const empty = element("div", "empty-state");
      const glyph = element("span", "empty-glyph", "◇");
      glyph.setAttribute("aria-hidden", "true");
      empty.append(glyph, element("h3", "", query && units.length ? "No matching function" : "The next match is still ahead."), element("p", "", query && units.length ? "Try a function name, target name, or source filename." : "This target has no compiled function match yet. CN bindings and shared contracts are research anchors; they do not count as reconstructed code."));
      $("unit-list").append(empty);
    }
    $("target-list").replaceChildren(...targets.map((target) => {
      const card = element("article", "target");
      const header = element("div", "target-header");
      header.append(element("h3", "", target.label), element("span", "target-format", `${target.format.toUpperCase()} · ${target.architecture.toUpperCase()}`));
      card.append(header, hashToggle(target.sha256), element("p", "", `${count(target.image_bytes)} image bytes · ${target.toolchain_note}`));
      return card;
    }));
  }

  function activateTabs(selector, callback) {
    const tabs = [...document.querySelectorAll(selector)];
    function activate(tab, focus) {
      for (const item of tabs) {
        const selected = item === tab;
        item.classList.toggle("active", selected);
        item.setAttribute("aria-selected", String(selected));
        item.tabIndex = selected ? 0 : -1;
      }
      if (focus) tab.focus();
      callback(tab);
    }
    for (const [index, tab] of tabs.entries()) {
      tab.addEventListener("click", () => activate(tab, false));
      tab.addEventListener("keydown", (event) => {
        const destinations = { ArrowRight: (index + 1) % tabs.length, ArrowLeft: (index - 1 + tabs.length) % tabs.length, Home: 0, End: tabs.length - 1 };
        if (event.key in destinations) {
          event.preventDefault();
          activate(tabs[destinations[event.key]], true);
        }
      });
    }
  }

  const method = [
    ["Pin the input SHA-256, architecture and compiler. Establish a complete function boundary before selecting anything to compare.", "verify-targets → inspect → prove the boundary"],
    ["Write readable C++ and declare its source and header inputs. Compile and link with an explicit toolchain in a fresh build directory, recording the recipe and compiler identity.", "declared source → compiler → linked artifact"],
    ["Compare the entire established body. A single changed byte rejects the match. Padding, wildcard masks and a familiar function name never turn a mismatch into a verified result.", "rebuilt body === original body → matching receipt"]
  ];
  activateTabs(".method-step", (tab) => {
    const [copy, command] = method[Number(tab.dataset.step)];
    $("method-copy").textContent = copy;
    $("method-command").textContent = command;
    $("method-detail").setAttribute("aria-labelledby", tab.id);
  });
  activateTabs(".platform-tabs button", (tab) => {
    platform = tab.dataset.platform;
    renderLedger();
  });
  $("unit-search").addEventListener("input", renderLedger);

  function publicTable(caption, headings, rows, ids = []) {
    const table = element("table", "report-table");
    table.append(element("caption", "", caption));
    const head = element("thead");
    const heading = element("tr");
    for (const text of headings) {
      const cell = element("th", "", text);
      cell.scope = "col";
      heading.append(cell);
    }
    head.append(heading);
    const body = element("tbody");
    rows.forEach((values, index) => {
      const row = element("tr");
      if (ids[index]) row.dataset.scopeId = ids[index];
      values.forEach((value) => row.append(element("td", typeof value === "number" ? "number" : "", typeof value === "number" ? count(value) : value)));
      body.append(row);
    });
    table.append(head, body);
    return table;
  }

  function svgElement(tag, attributes = {}, text) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function shortDate(value) {
    return new Intl.DateTimeFormat("en", { day: "numeric", month: "short", timeZone: "UTC" }).format(new Date(`${value.slice(0, 10)}T12:00:00Z`));
  }

  function renderTrend() {
    if (!dashboard) return;
    const points = dashboard.daily_trend;
    const holder = $("trend-chart");
    holder.replaceChildren();
    if (!points.length) {
      holder.append(element("p", "report-placeholder", "No dated snapshots have been published yet."));
      $("trend-note").textContent = "History begins with a recorded integration. No historical values are estimated.";
      return;
    }
    const bytes = trendMetric === "cumulative_body_bytes";
    const width = Math.max(280, holder.clientWidth), height = 230, left = 45, right = width - 35, top = 40, bottom = 188;
    const values = points.map((point) => point[trendMetric]);
    const max = Math.max(1, ...values);
    const times = points.map((point) => Date.parse(`${point.date}T00:00:00Z`));
    const span = Math.max(...times) - Math.min(...times);
    const x = (index) => span ? left + (times[index] - times[0]) / span * (right - left) : (left + right) / 2;
    const y = (value) => bottom - value / max * (bottom - top);
    const svg = svgElement("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-labelledby": "trend-svg-title trend-svg-description" });
    svg.append(svgElement("title", { id: "trend-svg-title" }, `Cumulative verified ${bytes ? "body bytes" : "functions"}`));
    svg.append(svgElement("desc", { id: "trend-svg-description" }, points.length === 1 ? `One recorded snapshot on ${points[0].date}: ${values[0]} ${bytes ? "bytes" : "functions"}. There is not yet a measured trend.` : `${points.length} recorded dates. Latest: ${values.at(-1)} ${bytes ? "bytes" : "functions"}. The exact values are available in the history table.`));
    for (const fraction of [0, .5, 1]) {
      const value = max * fraction;
      svg.append(svgElement("line", { class: "chart-grid", x1: left, x2: right, y1: y(value), y2: y(value) }));
      if (Number.isInteger(value)) svg.append(svgElement("text", { class: "chart-axis", x: left - 12, y: y(value) + 4, "text-anchor": "end" }, count(value)));
    }
    if (points.length > 1) {
      const path = points.map((point, index) => `${index ? "H" : "M"}${x(index)}${index ? ` V${y(point[trendMetric])}` : ` ${y(point[trendMetric])}`}`).join(" ");
      svg.append(svgElement("path", { class: "chart-line", d: path }));
    }
    points.forEach((point, index) => {
      const cx = x(index), cy = y(point[trendMetric]);
      if (points.length === 1) svg.append(svgElement("circle", { class: "chart-halo", cx, cy, r: 17 }));
      const dot = svgElement("circle", { class: "chart-dot", cx, cy, r: 6 });
      dot.append(svgElement("title", {}, `${point.date}: ${count(point[trendMetric])} ${bytes ? "bytes" : "functions"}`));
      svg.append(dot);
      if (index === 0 || index === points.length - 1) {
        svg.append(svgElement("text", { class: "chart-axis", x: cx, y: bottom + 27, "text-anchor": "middle" }, shortDate(point.date)));
        svg.append(svgElement("text", { class: "chart-value", x: cx, y: cy - 25, "text-anchor": "middle" }, `${count(point[trendMetric])} ${bytes ? "B" : "fn"}`));
      }
    });
    holder.append(svg);
    $("trend-note").textContent = points.length === 1 ? "One recorded publication date. A single point cannot establish pace, daily growth or a forecast." : "Step changes mark recorded publication dates. No activity is inferred between snapshots.";
    $("history-table").replaceChildren(publicTable("Recorded publication dates; counts come from accepted integration records.", ["Date", "Total functions", "Total bytes", "New functions", "New bytes"], points.map((point) => [point.date, point.cumulative_units, point.cumulative_body_bytes, point.accepted_units, point.accepted_body_bytes])));
  }

  function scopeState(value) {
    return value === "integrated" || value === "matched" ? ["matched", "Matched"] : value === "blocked" ? ["blocked", "Blocked"] : ["open", "Open"];
  }

  function renderScope() {
    if (!dashboard) return;
    const filter = $("scope-target").value;
    const items = dashboard.size_map.filter((item) => filter === "all" || item.target === filter);
    const measured = items.filter((item) => Number.isFinite(item.body_bytes) && item.body_bytes > 0);
    const total = measured.reduce((sum, item) => sum + item.body_bytes, 0);
    const holder = $("scope-map");
    holder.replaceChildren();
    $("scope-table").replaceChildren(publicTable("Enrolled function boundaries. This inventory does not cover the entire engine.", ["Function", "Target", "Body bytes", "State", "Source"], items.map((item) => [item.name, item.target, item.body_bytes ?? "Unmeasured", scopeState(item.status)[1], item.source]), items.map((item) => item.id)));
    if (!total) {
      holder.append(element("p", "report-placeholder", "No measured function boundaries are enrolled for this target."));
      $("scope-map-note").textContent = "Unmeasured functions cannot be drawn to scale. The full engine denominator remains unknown.";
      return;
    }
    const mapWidth = Math.max(280, holder.clientWidth - 12);
    const svg = svgElement("svg", { viewBox: `0 0 ${mapWidth} 210`, class: "scope-svg", role: "group", "aria-label": `${measured.length} measured functions, ${total} enrolled body bytes` });
    const defs = svgElement("defs");
    svg.append(defs);
    let offset = 0;
    measured.forEach((item, index) => {
      const width = item.body_bytes / total * mapWidth;
      const [state, label] = scopeState(item.status);
      const group = svgElement("g", { class: `scope-rect ${state}`, role: "button", tabindex: "0", "aria-pressed": "false", "aria-label": `${item.name}, ${item.target}, ${item.body_bytes} bytes, ${label}. Highlight inventory row.` });
      const clip = svgElement("clipPath", { id: `scope-clip-${index}` });
      clip.append(svgElement("rect", { x: offset + 2, y: 2, width: Math.max(0, width - 4), height: 206 }));
      defs.append(clip);
      group.append(svgElement("rect", { x: offset, y: 0, width, height: 210, class: "scope-cell" }));
      group.append(svgElement("title", {}, `${item.name} · ${item.target} · ${count(item.body_bytes)} B · ${label}`));
      const text = svgElement("g", { "clip-path": `url(#scope-clip-${index})` });
      if (width > 85) {
        text.append(svgElement("text", { x: offset + 22, y: 34, class: "scope-svg-state" }, label.toUpperCase()));
        text.append(svgElement("text", { x: offset + 22, y: 185, class: "scope-svg-size" }, `${count(item.body_bytes)} B`));
      }
      if (width > 180) {
        text.append(svgElement("text", { x: offset + 22, y: 88, class: "scope-svg-name" }, item.name));
        text.append(svgElement("text", { x: offset + 22, y: 113, class: "scope-svg-target" }, item.target));
      }
      group.append(text);
      function select() {
        for (const tile of svg.querySelectorAll('[role="button"]')) tile.setAttribute("aria-pressed", String(tile === group));
        for (const row of $("scope-table").querySelectorAll("tr")) row.classList.toggle("highlight-row", row.dataset.scopeId === item.id);
        $("scope-table").closest("details").open = true;
        $("scope-map-note").textContent = `${item.name}: ${count(item.body_bytes)} body bytes, ${label.toLowerCase()}, ${item.target}. Highlighted in the inventory below.`;
      }
      group.addEventListener("click", select);
      group.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); } });
      svg.append(group);
      offset += width;
    });
    holder.append(svg);
    $("scope-map-note").textContent = `${count(measured.length)} measured ${measured.length === 1 ? "function" : "functions"} · ${count(total)} body bytes. Tile areas are proportional only within the selected enrolled scope. Select a tile to inspect its record.`;
  }

  function renderAttribution(items, holder, kind) {
    holder.replaceChildren();
    if (!items.length) {
      holder.append(element("p", "attribution-empty", `No verified ${kind} attribution has been recorded yet.`));
      return;
    }
    const total = items.reduce((sum, item) => sum + item.body_bytes, 0);
    for (const item of items) {
      const row = element("div", "attribution-row");
      const name = element("div");
      name.append(element("div", "attribution-name", item.label), element("p", "attribution-role", item.id === "unknown" ? "Verified work with no recorded attribution." : `${count(item.units)} verified ${item.units === 1 ? "function" : "functions"}`));
      const amount = element("div", "attribution-count", `${count(item.units)} fn · ${count(item.body_bytes)} B`);
      const track = element("div", "attribution-bar");
      track.setAttribute("aria-hidden", "true");
      const fill = element("span");
      fill.style.width = `${total ? item.body_bytes / total * 100 : 0}%`;
      track.append(fill);
      row.append(name, amount, track);
      holder.append(row);
    }
  }

  function renderDashboard() {
    const scope = dashboard.scope;
    $("enrolled-bytes").textContent = count(scope.enrolled_body_bytes);
    $("enrolled-functions").textContent = count(scope.enrolled_units);
    $("enrolled-function-label").textContent = scope.enrolled_units === 1 ? "function with an enrolled boundary" : "functions with enrolled boundaries";
    const percent = scope.enrolled_body_bytes > 0 ? scope.integrated_body_bytes / scope.enrolled_body_bytes * 100 : null;
    $("enrolled-percent").textContent = percent === null ? "No enrolled bytes" : `${new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(percent)}% of enrolled bytes`;
    $("scope-meter-fill").style.width = `${percent ?? 0}%`;
    $("scope-meter-caption").textContent = `${count(scope.integrated_body_bytes)} of ${count(scope.enrolled_body_bytes)} enrolled body bytes integrated. ${count(scope.pending_units)} enrolled ${scope.pending_units === 1 ? "unit" : "units"} pending.`;
    $("scope-target").replaceChildren(new Option("All enrolled targets", "all"), ...dashboard.targets.map((target) => new Option(target.label, target.id)));
    renderTrend();
    renderScope();
    renderAttribution(dashboard.contributors, $("contributor-list"), "contributor");
    renderAttribution(dashboard.models, $("model-list"), "model or tool");
    const unknown = dashboard.models.find((item) => item.id === "unknown");
    $("attribution-note").textContent = unknown ? `${count(unknown.units)} verified ${unknown.units === 1 ? "function has" : "functions have"} no recorded model attribution. Unknown is a disclosure, not a model family.` : "Model and tool credit comes from explicit contribution records. Bytes measure accepted output, not model quality.";
    if (dashboard.milestones.length) {
      const log = element("div", "milestone-log");
      log.append(element("span", "eyebrow", "Recorded milestones"));
      for (const item of dashboard.milestones) {
        const entry = element("article", "milestone-event");
        const date = element("time", "", item.date.slice(0, 10));
        date.dateTime = item.date;
        entry.append(date, element("h4", "", item.label), element("p", "", `${count(item.units)} ${item.units === 1 ? "function" : "functions"} · ${count(item.body_bytes)} body bytes`));
        log.append(entry);
      }
      $("roadmap").append(log);
    }
    $("dashboard-status").textContent = `Integration ${dashboard.integration.id} · ${dashboard.integration.completed_at.slice(0, 10)} · Full enrolled scope passed locally. Public CI checks consistency; game binaries are not available in CI.`;
  }

  document.querySelectorAll("[data-trend-metric]").forEach((button) => button.addEventListener("click", () => {
    trendMetric = button.dataset.trendMetric === "matched_body_bytes" ? "cumulative_body_bytes" : "cumulative_units";
    for (const item of document.querySelectorAll("[data-trend-metric]")) {
      const selected = item === button;
      item.classList.toggle("active", selected);
      item.setAttribute("aria-pressed", String(selected));
    }
    renderTrend();
  }));
  $("scope-target").addEventListener("change", renderScope);
  let resizeFrame;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(() => { renderTrend(); renderScope(); });
  });
  $("copy-agent-prompt").addEventListener("click", async () => {
    const prompt = $("agent-prompt-text");
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(prompt.value);
      $("copy-status").textContent = "Copied. Paste the prompt into your coding agent.";
      $("copy-agent-prompt").textContent = "Prompt copied ✓";
    } catch {
      prompt.focus();
      prompt.select();
      $("copy-status").textContent = "Prompt selected. Press Ctrl+C (or Command+C) to copy.";
    }
  });

  async function loadDashboard() {
    try {
      const response = await fetch("./dashboard.json", { cache: "no-cache" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.schema_version !== 1 || !data.scope || !data.integration || data.integration.status !== "passed" || ![data.daily_trend, data.size_map, data.contributors, data.models, data.targets, data.milestones].every(Array.isArray)) throw new Error("Unsupported dashboard");
      if (data.scope.engine_completion_percent !== null || data.scope.engine_total_units !== null || data.scope.engine_total_body_bytes !== null) throw new Error("Engine denominator requires explicit review");
      dashboard = data;
      renderDashboard();
    } catch {
      $("dashboard-status").textContent = "The research dashboard could not be loaded. The verified match ledger below loads independently. No missing dashboard values are estimated.";
      $("dashboard-status").classList.add("error");
      for (const id of ["trend-chart", "scope-map", "contributor-list", "model-list"]) $(id).replaceChildren(element("p", "report-placeholder", "Dashboard data unavailable. Please reload or inspect the public data file."));
      $("scope-meter-caption").textContent = "Enrolled scope data unavailable.";
    }
  }

  async function load() {
    try {
      const response = await fetch("./progress.json", { cache: "no-cache" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.schema_version !== 1 || !Array.isArray(data.units) || !Array.isArray(data.targets) || !data.summary || !data.references || !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(data.project?.repo_url) || data.project.branch !== "main") throw new Error("Unsupported snapshot");
      progress = data;
      $("function-count").textContent = count(data.summary.verified_functions);
      $("function-plural").textContent = data.summary.verified_functions === 1 ? "" : "s";
      $("byte-count").textContent = count(data.summary.matched_body_bytes);
      $("target-count").textContent = count(data.targets.length);
      $("binding-count").textContent = count(data.references.host_bindings);
      $("contract-count").textContent = count(data.references.verified_export_contracts);
      $("export-count").textContent = count(data.references.shared_exports);
      $("reference-count").textContent = count(data.references.newly_recovered_card_references);
      $("negative-status").textContent = data.summary.negative_control === "passed" ? "negative control passed" : "negative-control receipt unavailable";
      for (const link of document.querySelectorAll(".repo-link")) link.href = data.project.repo_url;
      for (const link of document.querySelectorAll(".repo-doc-link")) link.href = `${data.project.repo_url}/blob/main/${link.dataset.repoPath}`;
      const date = new Date(`${data.updated}T12:00:00Z`);
      $("updated-at").textContent = `Snapshot · ${new Intl.DateTimeFormat("en", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" }).format(date)}`;
      renderLedger();
      $("load-status").textContent = "Verified snapshot loaded. Counts are derived from the public match ledger.";
      $("load-status").classList.add("loaded");
    } catch (error) {
      $("load-status").classList.add("load-error");
      $("load-status").textContent = "The progress snapshot could not be loaded. Please reload or read the public progress data linked below.";
      $("platform-status").textContent = "Snapshot unavailable";
      $("updated-at").textContent = "Snapshot unavailable";
    }
  }
  load();
  loadDashboard();
})();
