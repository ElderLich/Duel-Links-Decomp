"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const dataRoot = new URL(document.documentElement.dataset.root || "./", location.href);
  const setText = (id, value) => { if ($(id)) $(id).textContent = value; };
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
    if (!progress || !$("unit-list")) return;
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
  $("unit-search")?.addEventListener("input", renderLedger);

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

  function drawTrend(holder, points, metric, label, color) {
    if (!holder) return;
    holder.replaceChildren();
    if (!points.length) { holder.append(element("p", "report-placeholder", "No dated acceptances have been recorded.")); return; }
    const width = Math.max(280, holder.clientWidth || 460), height = 240, left = 45, right = width - 35, top = 38, bottom = 193;
    const max = Math.max(1, ...points.map((point) => point[metric]));
    const times = points.map((point) => Date.parse(`${point.date}T00:00:00Z`));
    const span = times.at(-1) - times[0];
    const x = (index) => span ? left + (times[index] - times[0]) / span * (right - left) : (left + right) / 2;
    const y = (value) => bottom - value / max * (bottom - top);
    const svg = svgElement("svg", {viewBox:`0 0 ${width} ${height}`,role:"img","aria-label":`${label}: ${count(points.at(-1)[metric])}. ${points.length} recorded dates.`});
    svg.append(svgElement("title", {}, label));
    for (const fraction of [0, .5, 1]) {
      const value = max * fraction;
      svg.append(svgElement("line", {class:"chart-grid",x1:left,x2:right,y1:y(value),y2:y(value)}));
      if (Number.isInteger(value)) svg.append(svgElement("text", {class:"chart-axis",x:left - 12,y:y(value) + 4,"text-anchor":"end"},count(value)));
    }
    if (points.length > 1) {
      const path = points.map((point,index) => `${index ? "H" : "M"}${x(index)}${index ? ` V${y(point[metric])}` : ` ${y(point[metric])}`}`).join(" ");
      svg.append(svgElement("path", {class:"chart-area",d:`${path} L${x(points.length-1)} ${bottom} L${x(0)} ${bottom} Z`}));
      svg.append(svgElement("path", {class:"chart-line",d:path,style:`stroke:${color}`}));
    }
    points.forEach((point,index) => {
      const dot = svgElement("circle", {class:"chart-dot",cx:x(index),cy:y(point[metric]),r:5,style:`fill:${color}`});
      dot.append(svgElement("title",{},`${point.date}: ${count(point[metric])}`));svg.append(dot);
      if (index === 0 || index === points.length - 1) {
        svg.append(svgElement("text", {class:"chart-axis",x:x(index),y:bottom+27,"text-anchor":"middle"},shortDate(point.date)));
        svg.append(svgElement("text", {class:"chart-value",x:x(index),y:y(point[metric])-20,"text-anchor":"middle",style:`fill:${color}`},count(point[metric])));
      }
    });
    holder.append(svg);
  }

  function renderDaily() {
    const holder = $("daily-model-chart");
    if (!holder || !dashboard) return;
    holder.replaceChildren();
    const days = new Map();
    for (const unit of dashboard.units) {
      const model = unit.model || "Unknown / unrecorded";
      if (!days.has(unit.first_accepted_date)) days.set(unit.first_accepted_date,new Map());
      const values = days.get(unit.first_accepted_date);
      const item = values.get(model) || {bytes:0,functions:0};
      item.bytes += unit.body_bytes; item.functions += 1; values.set(model,item);
    }
    const dates = [...days.keys()].sort();
    if (!dates.length) { holder.append(element("p","report-placeholder","No dated model attribution has been recorded.")); return; }
    const models = [...new Set([...days.values()].flatMap((day) => [...day.keys()]))].sort();
    const colors = ["#e6c584","#83e7f4","#b2a0ed","#d79978","#8fba9a"];
    const color = (name) => name === "Unknown / unrecorded" ? "#77899f" : colors[models.indexOf(name) % colors.length];
    const legend = element("div","chart-model-legend");
    for (const model of models) {
      const item=element("span"); const swatch=element("i","legend-swatch");swatch.style.backgroundColor=color(model);item.append(swatch,document.createTextNode(model));legend.append(item);
    }
    holder.append(legend);
    const width=Math.max(280,holder.clientWidth||850),height=270,left=45,right=width-25,top=35,bottom=215;
    const totals=dates.map((day)=>[...days.get(day).values()].reduce((sum,item)=>sum+item.bytes,0));
    const max=Math.max(1,...totals),slot=(right-left)/dates.length,bar=Math.min(100,slot*.7);
    const svg=svgElement("svg",{viewBox:`0 0 ${width} ${height}`,role:"img","aria-label":"Accepted bytes by first recorded date and reported model; unknown models are shown separately."});
    for(const fraction of [0,.5,1]) {
      const v=max*fraction,y=bottom-fraction*(bottom-top);svg.append(svgElement("line",{class:"chart-grid",x1:left,x2:right,y1:y,y2:y}));
      if(Number.isInteger(v))svg.append(svgElement("text",{class:"chart-axis",x:left-10,y:y+4,"text-anchor":"end"},count(v)));
    }
    const rows=[];
    dates.forEach((day,index)=>{
      const x=left+slot*(index+.5),values=days.get(day);let offset=0;
      for(const model of models){
        const item=values.get(model);if(!item)continue;
        const h=item.bytes/max*(bottom-top);const rect=svgElement("rect",{class:"chart-bar",x:x-bar/2,y:bottom-offset-h,width:bar,height:h,fill:color(model)});
        rect.append(svgElement("title",{},`${day} · ${model} · ${count(item.bytes)} B · ${count(item.functions)} functions`));svg.append(rect);offset+=h;rows.push([day,model,item.functions,item.bytes]);
      }
      if(dates.length<=8||index===0||index===dates.length-1)svg.append(svgElement("text",{class:"chart-axis",x,y:bottom+25,"text-anchor":"middle"},shortDate(day)));
      svg.append(svgElement("text",{class:"chart-value",x,y:bottom-offset-12,"text-anchor":"middle"},`${count(totals[index])} B`));
    });
    holder.append(svg);
    const disclosure=element("details","data-disclosure");disclosure.append(element("summary","","Read daily attribution data"),publicTable("One credit per accepted target range. Missing model attribution is unrecorded.",["Date","Model","Functions","Bytes"],rows));holder.append(disclosure);
  }

  function renderTrend() {
    if (!dashboard) return;
    const points = dashboard.daily_trend;
    drawTrend($("trend-bytes-chart"),points,"cumulative_body_bytes","Bytes matched, cumulative","#e6c584");
    drawTrend($("trend-functions-chart"),points,"cumulative_units","Functions matched, cumulative","#83e7f4");
    drawTrend($("trend-chart"),points,trendMetric,"Verified history","#e6c584");
    setText("trend-note",points.length===1?"One recorded day. These charts show the first verified result; no earlier activity or growth rate is invented.":"Acceptance is counted once, on its first recorded date. Rebuilds do not earn additional credit.");
    if($("history-table"))$("history-table").replaceChildren(publicTable("Recorded acceptance dates.",["Date","Total functions","Total bytes","New functions","New bytes"],points.map((p)=>[p.date,p.cumulative_units,p.cumulative_body_bytes,p.accepted_units,p.accepted_body_bytes])));
    renderDaily();
  }

  function scopeState(value) {
    return value === "integrated" || value === "matched" ? ["matched", "Matched"] : value === "blocked" ? ["blocked", "Blocked"] : ["open", "Open"];
  }

  function renderScope() {
    if (!dashboard || !$("scope-map")) return;
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
    if (!holder) return;
    holder.replaceChildren();
    if (!items.length) {
      holder.append(element("p", "attribution-empty", `No verified ${kind} attribution has been recorded yet.`));
      return;
    }
    if (kind === "contributor") {
      let rank = 0;
      const rows = [...items].sort((a,b) => (a.id === "unknown") - (b.id === "unknown") || b.body_bytes-a.body_bytes).map((item) => [item.id === "unknown" ? "—" : ++rank,item.label,item.units,item.body_bytes]);
      holder.append(publicTable("Contributors credited by accepted body bytes. Unrecorded authorship is not ranked.",["Rank","Contributor","Functions","Bytes"],rows));
      holder.append(element("p","unranked-note","Only explicitly recorded contributors receive a rank. Unknown authorship is not assigned to a person."));
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
    for (const [id,value] of Object.entries({"integrated-unit-count":scope.integrated_units,"enrolled-unit-count":scope.enrolled_units,"pending-unit-count":scope.pending_units,"integrated-byte-count":scope.integrated_body_bytes,"enrolled-byte-count":scope.enrolled_body_bytes,"pending-byte-count":scope.pending_body_bytes})) setText(id,count(value));
    for (const [name,done,total] of [["functions",scope.integrated_units,scope.enrolled_units],["bytes",scope.integrated_body_bytes,scope.enrolled_body_bytes]]) {
      const ratio=total?done/total*100:0;
      if($(name+"-scope-fill"))$(name+"-scope-fill").style.width=`${ratio}%`;
      setText(name+"-scope-label",total?`${count(done)} / ${count(total)} · ${new Intl.NumberFormat("en",{maximumFractionDigits:1}).format(ratio)}%`:"No enrolled scope");
    }
    setText("enrolled-bytes", count(scope.enrolled_body_bytes));
    setText("enrolled-functions", count(scope.enrolled_units));
    setText("enrolled-function-label", scope.enrolled_units === 1 ? "function with an enrolled boundary" : "functions with enrolled boundaries");
    const percent = scope.enrolled_body_bytes > 0 ? scope.integrated_body_bytes / scope.enrolled_body_bytes * 100 : null;
    setText("enrolled-percent", percent === null ? "No enrolled bytes" : `${new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(percent)}% of enrolled bytes`);
    if ($("scope-meter-fill")) $("scope-meter-fill").style.width = `${percent ?? 0}%`;
    setText("scope-meter-caption", `${count(scope.integrated_body_bytes)} of ${count(scope.enrolled_body_bytes)} enrolled body bytes integrated. ${count(scope.pending_units)} enrolled ${scope.pending_units === 1 ? "unit" : "units"} pending.`);
    if ($("scope-target")) $("scope-target").replaceChildren(new Option("All enrolled targets", "all"), ...dashboard.targets.map((target) => new Option(target.label, target.id)));
    renderTrend();
    renderScope();
    renderAttribution(dashboard.contributors, $("contributor-list"), "contributor");
    renderAttribution(dashboard.models, $("model-list"), "model or tool");
    const unknown = dashboard.models.find((item) => item.id === "unknown");
    setText("attribution-note", unknown ? `${count(unknown.units)} verified ${unknown.units === 1 ? "function has" : "functions have"} no recorded model attribution. Unknown is a disclosure, not a model family.` : "Model and tool credit comes from explicit contribution records. Bytes measure accepted output, not model quality.");
    if ($("roadmap") && dashboard.milestones.length) {
      $("roadmap").querySelector(".milestone-log")?.remove();
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
    setText("dashboard-status", `Integration ${dashboard.integration.id} · ${dashboard.integration.completed_at.slice(0, 10)} · Full enrolled scope passed locally. Public CI checks consistency; game binaries are not available in CI.`);
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
  $("scope-target")?.addEventListener("change", renderScope);
  let resizeFrame;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(() => { renderTrend(); renderScope(); });
  });
  $("copy-agent-prompt")?.addEventListener("click", async () => {
    const prompt = $("agent-prompt-text");
    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(prompt.value);
      setText("copy-status", "Copied. Paste the prompt into your coding agent.");
      setText("copy-agent-prompt", "Prompt copied ✓");
    } catch {
      prompt.focus();
      prompt.select();
      setText("copy-status", "Prompt selected. Press Ctrl+C (or Command+C) to copy.");
    }
  });
  const menus = [...document.querySelectorAll(".nav-dropdown")];
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") for (const menu of menus) {
      if (menu.open) { menu.open = false; menu.querySelector("summary").focus(); }
    }
  });
  document.addEventListener("click", (event) => {
    for (const menu of menus) if (!menu.contains(event.target)) menu.open = false;
  });

  async function getData(name) {
    const abort = new AbortController();
    const timeout = setTimeout(() => abort.abort(), 10000);
    try {
      const response = await fetch(new URL(name, dataRoot), { cache: "no-cache", signal: abort.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } finally { clearTimeout(timeout); }
  }

  async function loadDashboard(initial = null) {
    try {
      const data = initial || await getData("dashboard.json");
      if (data.schema_version !== 1 || !data.scope || !data.integration || data.integration.status !== "passed" || ![data.daily_trend, data.size_map, data.contributors, data.models, data.targets, data.milestones].every(Array.isArray)) throw new Error("Unsupported dashboard");
      if (data.scope.engine_completion_percent !== null || data.scope.engine_total_units !== null || data.scope.engine_total_body_bytes !== null) throw new Error("Engine denominator requires explicit review");
      dashboard = data;
      renderDashboard();
      document.documentElement.dataset.dashboard = "ready";
    } catch {
      // The generated HTML contains the committed snapshot. Keep those facts and tables.
      setText("dashboard-status", "Showing the published snapshot. Live data refresh is unavailable.");
      document.documentElement.dataset.dashboard = "snapshot";
    }
  }

  async function load(initial = null) {
    try {
      const data = initial || await getData("progress.json");
      if (data.schema_version !== 1 || !Array.isArray(data.units) || !Array.isArray(data.targets) || !data.summary || !data.references || !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(data.project?.repo_url) || data.project.branch !== "main") throw new Error("Unsupported snapshot");
      progress = data;
      setText("function-count", count(data.summary.verified_functions));
      setText("function-plural", data.summary.verified_functions === 1 ? "" : "s");
      setText("byte-count", count(data.summary.matched_body_bytes));
      setText("target-count", count(data.targets.length));
      setText("binding-count", count(data.references.host_bindings));
      setText("contract-count", count(data.references.verified_export_contracts));
      setText("export-count", count(data.references.shared_exports));
      setText("reference-count", count(data.references.newly_recovered_card_references));
      setText("negative-status", data.summary.negative_control === "passed" ? "negative control passed" : "negative-control receipt unavailable");
      for (const link of document.querySelectorAll(".repo-link")) link.href = data.project.repo_url;
      for (const link of document.querySelectorAll(".repo-doc-link")) link.href = `${data.project.repo_url}/blob/main/${link.dataset.repoPath}`;
      const date = new Date(`${data.updated}T12:00:00Z`);
      setText("updated-at", `Snapshot · ${new Intl.DateTimeFormat("en", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" }).format(date)}`);
      renderLedger();
      setText("load-status", "Verified snapshot loaded. Counts are derived from the public match ledger.");
      $("load-status")?.classList.add("loaded");
      document.documentElement.dataset.progress = "ready";
    } catch {
      setText("load-status", "Showing the published snapshot. Live data refresh is unavailable.");
      document.documentElement.dataset.progress = "snapshot";
    }
  }
  function initialData(id) {
    try { return JSON.parse($(id)?.textContent || "null"); } catch { return null; }
  }
  const initialProgress = initialData("initial-progress");
  if (initialProgress) load(initialProgress);
  load();
  if (["integrated-unit-count", "enrolled-bytes", "trend-chart", "trend-bytes-chart", "scope-map", "contributor-list", "roadmap"].some((id) => $(id))) {
    const initialDashboard = initialData("initial-dashboard");
    if (initialDashboard) loadDashboard(initialDashboard);
    loadDashboard();
  }
})();
