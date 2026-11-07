// B3 — `neo check`: bundle, statically reject Node/browser globals, then run
// the bundle in a REAL QuickJS context with the mock host (no Node eval).
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { runCheck, scanBundle } from "../dist/check.js";
import { mockHostSource } from "../dist/mock-host.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..");
const sdkRoot = path.join(repo, "sdk");
const exampleDir = path.join(repo, "examples", "chokepoint");

function writeProject(source) {
  const dir = mkdtempSync(path.join(tmpdir(), "neo-check-"));
  mkdirSync(path.join(dir, "src"), { recursive: true });
  mkdirSync(path.join(dir, "neo"), { recursive: true });
  writeFileSync(path.join(dir, "src", "main.ts"), source);
  writeFileSync(
    path.join(dir, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          target: "ES2020",
          module: "ESNext",
          moduleResolution: "Bundler",
          strict: true,
          noEmit: true,
          skipLibCheck: true,
          baseUrl: ".",
          paths: { "@neo/runtime": [path.join(sdkRoot, "src", "runtime.ts")] },
        },
        include: ["src/**/*.ts"],
      },
      null,
      2,
    ),
  );
  writeFileSync(path.join(dir, "neo", "mod.json"), '{"id":"tmp","entry":"main.js"}\n');
  return dir;
}

test("check passes the chokepoint example and records the example's calls", async () => {
  const result = await runCheck({ dir: exampleDir });
  assert.equal(result.ok, true, result.error);
  assert.equal(result.dir, exampleDir);
  assert.equal(result.registrations, 1);
  assert.equal(result.apiVersion, 1);
  assert.deepEqual(result.calls, [
    { fn: "__neo_graph_betweenness", id: 7 },
    { fn: "__neo_system_set_var", id: 7, name: "neo_score", value: 250 },
    { fn: "__neo_log", message: "NEO_HUB 7 250" },
    { fn: "__neo_api_version" },
  ]);
});

test("check catches a missing native API", async () => {
  const dir = writeProject(
    'import { onSystem, graph } from "@neo/runtime";\nonSystem((s) => { graph.betweenness(s); });\n',
  );
  const result = await runCheck({
    dir,
    hostSource: mockHostSource({ omit: ["__neo_graph_betweenness"] }),
  });
  assert.equal(result.ok, false);
  assert.match(String(result.error), /__neo_graph_betweenness/);
});

test("check rejects a bundle that touches process", async () => {
  const dir = writeProject(
    'import { onSystem } from "@neo/runtime";\ndeclare const process: { exit(code: number): never };\nonSystem(() => { process.exit(1); });\n',
  );
  const result = await runCheck({ dir });
  assert.equal(result.ok, false);
  assert.match(String(result.error), /process\./);
});

test("check rejects a bundle that touches window or document", async () => {
  for (const [global_, snippet] of [
    ["window", 'import { onSystem } from "@neo/runtime";\ndeclare const window: { focus(): void };\nonSystem(() => { window.focus(); });'],
    ["document", 'import { onSystem } from "@neo/runtime";\ndeclare const document: { title: string };\nonSystem(() => { document.title; });'],
  ]) {
    const dir = writeProject(snippet);
    const result = await runCheck({ dir });
    assert.equal(result.ok, false, global_);
    assert.match(String(result.error), new RegExp(`${global_}\\.`), global_);
  }
});

test("check rejects dynamic import and require", () => {
  assert.deepEqual(scanBundle("const x = 1;\n"), []);
  assert.match(scanBundle("const m = require('fs');\n")[0], /require\(/);
  assert.match(scanBundle("import('fs');\n")[0], /import\(/);
});

test("check fails on a TypeScript syntax error", async () => {
  const dir = writeProject("onSystem((s) => { s.\n");
  const result = await runCheck({ dir });
  assert.equal(result.ok, false);
  assert.match(String(result.error), /tsc/);
});

test("check fails when no handler is registered", async () => {
  const dir = writeProject('import { log } from "@neo/runtime";\nlog("no handler");\n');
  const result = await runCheck({ dir });
  assert.equal(result.ok, false);
  assert.match(String(result.error), /handler/);
});

test("the CLI prints one NEO_CHECK line and exits 0 for the example", () => {
  const stdout = execFileSync(
    process.execPath,
    [path.join(sdkRoot, "dist", "cli.js"), "check", "--dir", exampleDir],
    { encoding: "utf8" },
  );
  const line = stdout.trim().split("\n").at(-1);
  assert.match(line, /^NEO_CHECK ok dir=.* handler=1 calls=4$/);
});

test("the CLI exits 2 with a fail line for a broken project", () => {
  const dir = writeProject(
    'import { onSystem } from "@neo/runtime";\ndeclare const process: { exit(code: number): never };\nonSystem(() => { process.exit(1); });\n',
  );
  try {
    execFileSync(process.execPath, [path.join(sdkRoot, "dist", "cli.js"), "check", "--dir", dir], {
      encoding: "utf8",
    });
    assert.fail("expected a non-zero exit");
  } catch (error) {
    assert.equal(error.status, 2);
    assert.match(String(error.stderr), /^NEO_CHECK fail: /);
  }
});
