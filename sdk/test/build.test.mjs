// B2 — `neo build`: type-check the authoring project, then bundle it for the
// host's IIFE evaluator.  A missing export must fail before any bytes ship.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { runBuild } from "../dist/build.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..");
const sdkRoot = path.join(repo, "sdk");
const exampleDir = path.join(repo, "examples", "chokepoint");

function tempDir(prefix) {
  return mkdtempSync(path.join(tmpdir(), prefix));
}

function writeProject(dir, source) {
  mkdirSync(path.join(dir, "src"), { recursive: true });
  mkdirSync(path.join(dir, "neo"), { recursive: true });
  writeFileSync(path.join(dir, "src", "main.ts"), source);
  writeTsconfig(dir);
  writeFileSync(path.join(dir, "neo", "mod.json"), '{"id":"tmp","entry":"main.js"}\n');
}

function writeTsconfig(dir) {
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
}

/** A project with a full manifest (`id: demo`) so tests can read the written fields back. */
function makeProject({ main, flags } = {}) {
  const dir = tempDir("neo-build-flags-");
  mkdirSync(path.join(dir, "src"), { recursive: true });
  mkdirSync(path.join(dir, "neo"), { recursive: true });
  writeFileSync(
    path.join(dir, "src", "main.ts"),
    `import { onSystem } from "@neo/runtime";\n${main}\n`,
  );
  writeTsconfig(dir);
  const manifest = {
    id: "demo",
    entry: "main.js",
    scope: ["system"],
    permissions: ["flag.read", "flag.write"],
    engine: "4.4.4",
    runtime: ">=0.1",
  };
  if (flags !== undefined) manifest.flags = flags;
  writeFileSync(path.join(dir, "neo", "mod.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return dir;
}

test("builds the chokepoint example to an IIFE bundle", async () => {
  const outfile = path.join(tempDir("neo-build-"), "main.js");
  const result = await runBuild({ dir: exampleDir, outfile });
  assert.equal(result.outfile, outfile);

  const text = readFileSync(outfile, "utf8");
  assert.match(text, /__neo_register_system/);
  assert.match(text, /__neo_graph_betweenness/);
  assert.match(text, /neo_score/);
  assert.doesNotMatch(text, /^\s*import\s/m);
  assert.doesNotMatch(text, /^\s*export\s/m);
});

test("the built example survives a plain node syntax check", async () => {
  const outfile = path.join(tempDir("neo-build-"), "main.js");
  await runBuild({ dir: exampleDir, outfile });
  execFileSync(process.execPath, ["--check", outfile]);
});

test("neo build writes the literal flag names into neo/mod.json", async () => {
  const dir = makeProject({
    main: 'onSystem((s) => { if (!s.hasStarFlag("neo_hub")) s.setStarFlag("neo_hub"); s.setStarFlag("neo_choke"); });',
  });
  await runBuild({ dir });
  const manifest = JSON.parse(readFileSync(path.join(dir, "neo", "mod.json"), "utf8"));
  assert.deepEqual(manifest.flags, ["neo_choke", "neo_hub"]);
  // 其它字段原样保留
  assert.equal(manifest.id, "demo");
});

test("a missing export fails the build with the tsc diagnostic", async () => {
  const dir = tempDir("neo-build-bad-");
  writeProject(
    dir,
    'import { onSystem, notARealExport } from "@neo/runtime";\nonSystem(() => { notARealExport(); });\n',
  );
  await assert.rejects(
    () => runBuild({ dir, outfile: path.join(dir, "neo", "main.js") }),
    (error) => {
      assert.match(String(error.message), /tsc/);
      assert.match(String(error.message), /notARealExport/);
      return true;
    },
  );
});

test("a project without src/main.ts is rejected", async () => {
  const dir = tempDir("neo-build-empty-");
  writeFileSync(path.join(dir, "tsconfig.json"), '{"include":[]}\n');
  await assert.rejects(
    () => runBuild({ dir, outfile: path.join(dir, "neo", "main.js") }),
    /src\/main\.ts/,
  );
});
