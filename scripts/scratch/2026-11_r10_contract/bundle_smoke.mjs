// r10_bundle_smoke.mjs — SDK-side shape check for the three R10 bundles.
//
// NOT `neo check`: the SDK gate needs an authoring project (tsconfig.json + src/main.ts)
// and runs tsc + esbuild; these bundles are hand-written JS on purpose, so the SDK gate
// is not applicable (sdk/node_modules absent as well).
//
// What this does instead, with zero npm dependencies:
//   1. manifest field set = the loader's strict 7 (src/dll/c2/neo_js_loader.zig:168-194);
//   2. the static forbidden-pattern scan `neo check` layer 2 uses (sdk/src/check.ts);
//   3. eval the bundle with a mocked host and drive the handler with a fake id,
//      asserting the exact log lines the live criterion is written against.
//
// Usage: node scripts/scratch/2026-11_r10_contract/bundle_smoke.mjs .
import { readFileSync } from "node:fs";
import vm from "node:vm";
import path from "node:path";

const root = process.argv[2] ?? ".";
const BASE = path.join(root, "scripts/scratch/2026-11_r10_contract");

const ALLOWED = new Set(["id", "entry", "scope", "permissions", "engine", "runtime", "flags"]);
const REQUIRED = ["id", "entry", "scope", "permissions", "engine", "runtime"];
const FORBIDDEN = [
  ["require(", /\brequire\s*\(/],
  ["process.", /\bprocess\s*\./],
  ["window.", /\bwindow\s*\./],
  ["document.", /\bdocument\s*\./],
  ["import(", /\bimport\s*\(/],
];

const TARGETS = [
  { id: "r10good", dir: path.join(BASE, "neo") },
  { id: "r10timeout", dir: path.join(BASE, "bad/r10timeout") },
  { id: "r10throw", dir: path.join(BASE, "bad/r10throw") },
];

let failures = 0;
const say = (ok, text) => {
  if (!ok) failures += 1;
  console.log(`${ok ? "ok  " : "FAIL"} ${text}`);
};

function loadManifest(dir) {
  const raw = JSON.parse(readFileSync(path.join(dir, "mod.json"), "utf8"));
  return raw;
}

function mockHost(kind) {
  const lines = [];
  const flags = new Set();
  let handler = null;
  const sandbox = {
    globalThis: undefined,
    console,
    __neo_log: (s) => lines.push(String(s)),
    __neo_register_system: (fn) => { handler = fn; },
    __neo_system_degree: () => 3,
    __neo_system_neighbors: () => [1, 2, 3],
    __neo_system_has_flag: (_id, name) => flags.has(name),
    __neo_system_set_flag: (_id, name) => { flags.add(name); },
  };
  sandbox.globalThis = sandbox;
  return { sandbox, lines, get handler() { return handler; } };
}

for (const target of TARGETS) {
  const label = target.id;
  const manifest = loadManifest(target.dir);
  const keys = Object.keys(manifest);
  say(keys.every((k) => ALLOWED.has(k)), `${label} manifest field set (${keys.join(",")})`);
  say(REQUIRED.every((k) => keys.includes(k)), `${label} manifest required fields present`);
  say(manifest.entry === "main.js", `${label} manifest entry=main.js`);
  say(manifest.engine === "4.4.4", `${label} manifest engine=4.4.4`);
  say(JSON.stringify(manifest.scope) === JSON.stringify(["system"]), `${label} manifest scope=[system]`);

  const src = readFileSync(path.join(target.dir, "main.js"), "utf8");
  for (const [label2, re] of FORBIDDEN) {
    say(!re.test(src), `${label} bundle has no "${label2}"`);
  }

  if (label === "r10timeout") {
    // Running it would hang the checker on purpose; assert the shape instead.
    say(/while\s*\(\s*true\s*\)/.test(src), `${label} bundle carries the unbounded loop`);
    continue;
  }

  const host = mockHost(label);
  const context = vm.createContext(host.sandbox);
  vm.runInContext(src, context, { filename: `${label}/main.js`, timeout: 5000 });
  say(typeof host.handler === "function", `${label} registered a system handler`);

  if (label === "r10good") {
    host.handler(7);
    say(host.lines[0] === "R10_NBR id=7 deg=3 n=3 first=1", `${label} line1 = ${host.lines[0]}`);
    say(host.lines[1] === "R10_FLAG id=7 before=false after=true", `${label} line2 = ${host.lines[1]}`);
    host.handler(7);
    say(host.lines[3] === "R10_FLAG id=7 before=true after=true", `${label} line4 (2nd call) = ${host.lines[3]}`);
  }

  if (label === "r10throw") {
    let message = null;
    try { host.handler(7); } catch (err) { message = String(err && err.message); }
    say(message !== null && message.includes("R10_INTENTIONAL"),
      `${label} handler throws R10_INTENTIONAL (got ${JSON.stringify(message)})`);
  }
}

console.log(failures === 0 ? "SMOKE ok" : `SMOKE fail=${failures}`);
process.exit(failures === 0 ? 0 : 1);
