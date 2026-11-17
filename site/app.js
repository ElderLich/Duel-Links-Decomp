"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const format = new Intl.NumberFormat("en");
  const count = (value) => value === null || value === undefined ? "Unverified" : format.format(value);
  let progress;
  let platform = "steam";

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
})();
