"""Exercise the published pages below a project subpath, without game files.

The small DOM fixture checks startup/rendering contracts, not visual layout or a
full browser. Real browser interaction and layout checks remain separate.
"""
from collections import Counter
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROUTES = {"": "home", "progress/": "progress", "progress/matches/": "matches",
          "progress/history/": "history", "progress/scope/": "scope", "progress/contributors/": "contributors",
          "how/": "how", "research/": "research", "join/": "join"}


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.nodes, self.ids, self.urls, self.scripts = [], [], [], {}
        self.html = {}
        self.current_script = None
        self.stack = []
        self.feed(text)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        node = {"tag": tag, "attrs": attrs, "text": ""}
        self.nodes.append(node)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(node)
        if tag == "html":
            self.html = attrs
        if "id" in attrs:
            self.ids.append(attrs["id"])
        for attr in ("href", "src"):
            if attrs.get(attr):
                self.urls.append((tag, attr, attrs[attr]))
        if tag == "script" and attrs.get("id"):
            self.current_script = attrs["id"]
            self.scripts[self.current_script] = ""

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break
        if tag == "script":
            self.current_script = None

    def handle_data(self, data):
        for node in self.stack:
            node["text"] += data
        if self.current_script:
            self.scripts[self.current_script] += data


# Null IDs really return null: a page-global handler for an absent widget fails
# here just as in a browser. This deliberately does not manufacture missing IDs.
DOM_RUNNER = r'''
const fs = require("node:fs");
const vm = require("node:vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const failures = [], requests = [];
process.on("unhandledRejection", error => failures.push(String(error.stack || error)));
class Node {
  constructor(tag="div", attrs={}) {
    this.tagName=tag.toUpperCase(); this.attrs={...attrs}; this.children=[];
    this.dataset={}; this.style={}; this.value=attrs.value || ""; this.clientWidth=640;
    this.textContent=""; this.innerHTML=""; this.parentElement=null;
    this.className=attrs.class || "";
    for(const [key,value] of Object.entries(attrs)) if(key.startsWith("data-"))
      this.dataset[key.slice(5).replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]=value;
    const names=new Set(this.className.split(/\s+/).filter(Boolean));
    this.classList={add:(...values)=>values.forEach(v=>names.add(v)), remove:(...values)=>values.forEach(v=>names.delete(v)),
      contains:value=>names.has(value), toggle:(value,on)=>{const yes=on ?? !names.has(value); yes?names.add(value):names.delete(value); return yes;}};
  }
  append(...nodes){ this.children.push(...nodes); for(const node of nodes) if(node && typeof node==="object") node.parentElement=this; }
  appendChild(node){this.append(node); return node;}
  replaceChildren(...nodes){this.children=[]; this.append(...nodes); if(this.tagName==="SELECT"&&nodes[0]) this.value=nodes[0].value;}
  setAttribute(key,value){this.attrs[key]=String(value);}
  getAttribute(key){return this.attrs[key] ?? null;}
  addEventListener(){} focus(){} select(){} scrollIntoView(){}
  querySelectorAll(){return [];}
  querySelector(){return null;}
  closest(){return new Node("details");}
}
const nodes=input.nodes.map(node=>{const result=new Node(node.tag,node.attrs);result.textContent=node.text;return result;});
const ids=new Map(nodes.filter(node=>node.attrs.id).map(node=>[node.attrs.id,node]));
for(const [id,text] of Object.entries(input.scripts)) if(ids.has(id)) ids.get(id).textContent=text;
const html=nodes.find(node=>node.tagName==="HTML");
const matches=(node, selector)=>{
  if(selector.includes(" ") || selector.includes(":")) return false;
  if(selector.startsWith(".")) return node.className.split(/\s+/).includes(selector.slice(1));
  const attr=selector.match(/^\[([^=\]]+)(?:=["']?([^"'\]]+)["']?)?\]$/);
  if(attr) return attr[1] in node.attrs && (attr[2]===undefined || node.attrs[attr[1]]===attr[2]);
  return node.tagName.toLowerCase()===selector;
};
const document={documentElement:html, body:nodes.find(node=>node.tagName==="BODY"), baseURI:input.url,
  getElementById:id=>ids.get(id)||null, createElement:tag=>new Node(tag), createElementNS:(_,tag)=>new Node(tag),
  createTextNode:text=>{const node=new Node("#text");node.textContent=text;return node;},
  querySelectorAll:selector=>nodes.filter(node=>matches(node,selector)),
  querySelector:selector=>nodes.find(node=>matches(node,selector))||null, addEventListener(){}};
const context={document, console, Intl, URL, URLSearchParams, AbortController, Date, Set, Map, Option:function(text,value){const n=new Node("option");n.textContent=text;n.value=value;return n;},
  navigator:{}, location:new URL(input.url), setTimeout, clearTimeout,
  requestAnimationFrame:callback=>setTimeout(callback,0), cancelAnimationFrame:clearTimeout,
  fetch:async raw=>{const url=new URL(String(raw),input.url);requests.push(url.href);
    const file=url.pathname.split("/").pop();
    const valid=url.pathname===input.prefix+file && ["progress.json","dashboard.json"].includes(file);
    if(!valid) throw new Error("Incorrect public data URL: "+url.href);
    if(input.failFetch) return {ok:false,status:503,json:async()=>{throw new Error("Unavailable");}};
    return {ok:true,status:200,json:async()=>input.data[file]};}};
context.window=context; context.addEventListener=()=>{};
vm.createContext(context);
try{vm.runInContext(input.code,context,{filename:"app.js",timeout:3000});}catch(error){failures.push(String(error.stack||error));}
setTimeout(()=>{
  const visible={};for(const [id,node] of ids) visible[id]={text:node.textContent,children:node.children.length};
  process.stdout.write(JSON.stringify({failures,requests,visible,state:html.dataset}));
},25);
'''


class SiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("site_builder_under_test", ROOT / "Tools/build_site.py")
        cls.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.builder)
        cls.rendered = cls.builder.render_pages(ROOT)
        cls.pages = {path: Page(text) for path, text in cls.rendered.items()}

    def test_nine_real_pages_have_unique_ids_and_correct_base(self):
        expected = {f"site/{route}index.html" for route in ROUTES}
        self.assertEqual(expected, set(self.rendered))
        for route, key in ROUTES.items():
            page = self.pages[f"site/{route}index.html"]
            with self.subTest(route=route):
                self.assertEqual(key, page.html["data-page"])
                self.assertEqual("../" * route.count("/") if route else "./", page.html["data-root"])
                self.assertEqual([], [value for value, count in Counter(page.ids).items() if count > 1])
                self.assertIn("main", page.ids)
                self.assertEqual(1, sum(node["tag"] == "h1" for node in page.nodes))

    def test_internal_links_assets_and_fragments_resolve_below_subpath(self):
        self.assertFalse([path for path in self.rendered if not (ROOT / path).is_file()], "Run the builder before validating published destinations")
        for prefix in ("/", "/Duel-Links-Decomp/"):
            for path, page in self.pages.items():
                route = path.removeprefix("site/").removesuffix("index.html")
                current = f"https://example.test{prefix}{route}"
                for tag, attr, value in page.urls:
                    target = urlsplit(urljoin(current, value))
                    if target.scheme in {"mailto", "tel", "data"} or target.netloc != "example.test":
                        continue
                    with self.subTest(prefix=prefix, page=path, url=value):
                        self.assertTrue(target.path.startswith(prefix), "Link escaped the GitHub repository subpath")
                        relative = unquote(target.path[len(prefix):])
                        local = ROOT / "site" / relative
                        if target.path.endswith("/"):
                            relative += "index.html"
                            local /= "index.html"
                        self.assertTrue(local.is_file(), f"Missing destination: {local}")
                        if target.fragment and relative.endswith(".html"):
                            destination = self.pages.get("site/" + relative) or Page(local.read_text(encoding="utf-8"))
                            self.assertIn(unquote(target.fragment), destination.ids, "Broken fragment destination")

    def test_page_widgets_and_accessible_references_are_complete(self):
        groups = {
            "progress/matches/": {"unit-search", "platform-panel", "platform-title", "platform-status", "unit-list", "target-list", "steam-tab", "cn-tab"},
            "progress/": {"integrated-unit-count", "enrolled-unit-count", "pending-unit-count", "integrated-byte-count", "enrolled-byte-count", "pending-byte-count", "functions-scope-fill", "bytes-scope-fill"},
            "progress/history/": {"trend-bytes-chart", "trend-functions-chart", "daily-model-chart", "trend-note", "history-table"},
            "progress/scope/": {"scope-target", "scope-map", "scope-map-note", "scope-table"},
            "progress/contributors/": {"contributor-list", "model-list", "attribution-note"},
            "how/": {"method-detail", "method-copy", "method-command"},
            "research/": {"binding-count", "contract-count", "export-count"},
            "join/": {"agent-prompt-text", "copy-agent-prompt", "copy-status"},
        }
        for route, required in groups.items():
            self.assertTrue(required <= set(self.pages[f"site/{route}index.html"].ids), f"Incomplete {route} widget: {required}")
        for path, page in self.pages.items():
            for node in page.nodes:
                for attribute in ("for", "aria-labelledby", "aria-describedby", "aria-controls"):
                    for referenced in (node["attrs"].get(attribute) or "").split():
                        with self.subTest(page=path, attribute=attribute, reference=referenced):
                            self.assertIn(referenced, page.ids)

    def test_styles_and_runtime_use_current_content_hashes(self):
        for path, page in self.pages.items():
            for name in ("style.css", "app.js"):
                links = [value for _, _, value in page.urls if urlsplit(value).path.endswith("/" + name)]
                with self.subTest(page=path, asset=name):
                    self.assertEqual(1, len(links))
                    expected = hashlib.sha256((ROOT / "site" / name).read_bytes()).hexdigest()[:12]
                    self.assertEqual([expected], parse_qs(urlsplit(links[0]).query).get("v"))

    def test_embedded_evidence_is_exact_public_data_not_fallback_counts(self):
        for path, page in self.pages.items():
            for element, filename in (("initial-progress", "progress.json"), ("initial-dashboard", "dashboard.json")):
                with self.subTest(page=path, evidence=element):
                    self.assertIn(element, page.scripts)
                    expected = json.loads((ROOT / "site" / filename).read_text(encoding="utf-8"))
                    self.assertEqual(expected, json.loads(page.scripts[element]))

    def test_page_and_runtime_text_have_no_double_encoded_symbols(self):
        sources = {**self.rendered, "site/app.js": (ROOT / "site/app.js").read_text(encoding="utf-8")}
        for path, source in sources.items():
            with self.subTest(path=path):
                for damaged in ("\u00c2\u00b7", "\u00e2\u0153\u201c", "\u00e2\u2020", "\ufffd"):
                    self.assertNotIn(damaged, source, "UTF-8 text was decoded and encoded again incorrectly")

    def test_generated_pages_are_current_and_deterministic(self):
        self.assertEqual(self.rendered, self.builder.render_pages(ROOT))
        self.builder.build(ROOT, check=True)
        for path, text in self.rendered.items():
            self.assertEqual(text, (ROOT / path).read_text(encoding="utf-8"))
        actual = {path.relative_to(ROOT).as_posix() for path in (ROOT / "site").rglob("*.html")
                  if "templates" not in path.relative_to(ROOT / "site").parts}
        self.assertEqual(set(self.rendered), actual, "An obsolete generated HTML page is still publishable")

    def test_stale_html_and_asset_changes_require_regeneration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "site", root / "site")
            self.builder.build(root)
            (root / "site/progress/history/index.html").write_text("obsolete page", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.builder.build(root, check=True)
            self.builder.build(root)
            original = (root / "site/progress/matches/index.html").read_text(encoding="utf-8")
            with (root / "site/style.css").open("a", encoding="utf-8") as output:
                output.write("\n/* changed asset must invalidate every page */\n")
            with self.assertRaises(ValueError):
                self.builder.build(root, check=True)
            self.builder.build(root)
            self.assertNotEqual(original, (root / "site/progress/matches/index.html").read_text(encoding="utf-8"))
            self.builder.build(root, check=True)

    def test_inconsistent_counts_and_invented_engine_percentage_cannot_render(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "site", root / "site")
            path = root / "site/progress.json"
            original = json.loads(path.read_text(encoding="utf-8"))
            changed = json.loads(json.dumps(original))
            changed["summary"]["verified_functions"] += 1
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "disagree"):
                self.builder.render_pages(root)
            original["summary"]["completion_percent"] = 100
            path.write_text(json.dumps(original), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Whole-engine"):
                self.builder.render_pages(root)

    @unittest.skipUnless(shutil.which("node"), "Node is required for the runtime contract checks")
    def test_each_page_initializes_with_real_data_and_explicit_network_failure(self):
        code = (ROOT / "site/app.js").read_text(encoding="utf-8")
        data = {name: json.loads((ROOT / "site" / name).read_text(encoding="utf-8")) for name in ("progress.json", "dashboard.json")}
        for route in ROUTES:
            page = self.pages[f"site/{route}index.html"]
            for failed in (False, True):
                with self.subTest(route=route, unavailable=failed):
                    request = {"nodes": page.nodes, "scripts": page.scripts, "code": code, "data": data,
                               "url": f"https://example.test/Duel-Links-Decomp/{route}", "prefix": "/Duel-Links-Decomp/", "failFetch": failed}
                    result = subprocess.run(["node", "-e", DOM_RUNNER], input=json.dumps(request), text=True,
                                            capture_output=True, timeout=10, encoding="utf-8")
                    self.assertEqual(0, result.returncode, result.stderr)
                    outcome = json.loads(result.stdout)
                    self.assertEqual([], outcome["failures"])
                    self.assertTrue(outcome["requests"], "Runtime never requested current public evidence")
                    self.assertEqual("snapshot" if failed else "ready", outcome["state"].get("progress"))
                    if any(identity in page.ids for identity in ("integrated-unit-count", "enrolled-bytes", "trend-bytes-chart", "scope-map", "contributor-list", "roadmap")):
                        self.assertEqual("snapshot" if failed else "ready", outcome["state"].get("dashboard"))
                    for identity, value in (("function-count", data["progress.json"]["summary"]["verified_functions"]),
                                            ("byte-count", data["progress.json"]["summary"]["matched_body_bytes"]),
                                            ("enrolled-bytes", data["dashboard.json"]["scope"]["enrolled_body_bytes"]),
                                            ("integrated-unit-count", data["dashboard.json"]["scope"]["integrated_units"]),
                                            ("integrated-byte-count", data["dashboard.json"]["scope"]["integrated_body_bytes"])):
                        if identity in outcome["visible"]:
                            self.assertEqual(f"{value:,}", outcome["visible"][identity]["text"])
                    for identity in ("load-status", "dashboard-status", "updated-at"):
                        if identity in outcome["visible"]:
                            text = outcome["visible"][identity]["text"].lower()
                            self.assertNotIn("loading", text)


if __name__ == "__main__":
    unittest.main()
