// B2 — `neo new`: the generated project is the acceptance surface.  It must
// type-check, bundle, and pass the real-QuickJS check on the first try; a
// scaffold that only looks complete would be worse than no scaffold.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(here, "..");
const cli = path.join(sdkRoot, "dist", "cli.js");

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

function tempRoot() {
  return mkdtempSync(path.join(tmpdir(), "neo-new-"));
}

function read(dir, ...parts) {
  return readFileSync(path.join(dir, ...parts), "utf8");
}

test("neo new scaffolds a complete project and prints one NEO_NEW line", () => {
  const root = tempRoot();
  const dir = path.join(root, "mods", "my_mod");
  const result = run(["new", dir, "--id", "my_mod", "--name", "My Mod"]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout.trim(), /^NEO_NEW ok dir=.* id=my_mod files=\d+$/);

  for (const file of [
    "tsconfig.json",
    "src/main.ts",
    "neo/mod.json",
    "descriptor.mod",
    "common/on_actions/my_mod_on_actions.txt",
    "events/my_mod_events.txt",
    "README.md",
  ]) {
    assert.ok(existsSync(path.join(dir, file)), `missing ${file}`);
  }

  const manifest = JSON.parse(read(dir, "neo", "mod.json"));
  assert.equal(manifest.id, "my_mod");
  assert.equal(manifest.entry, "main.js");
  assert.deepEqual(manifest.scope, ["system"]);
  assert.deepEqual(manifest.permissions, ["graph.read", "flag.read", "flag.write", "log"]);
  assert.equal(manifest.engine, "4.4.4");
  assert.equal(manifest.runtime, ">=0.1");

  const main = read(dir, "src", "main.ts");
  assert.match(main, /onSystem/);
  assert.match(main, /s\.neighbors/);
  assert.match(main, /s\.setStarFlag/);
  assert.match(main, /s\.hasStarFlag/);

  const pathMap = JSON.parse(read(dir, "tsconfig.json")).compilerOptions.paths["@neo/runtime"];
  assert.equal(pathMap.length, 1);
  assert.ok(path.isAbsolute(path.resolve(dir, pathMap[0])), pathMap[0]);
  assert.ok(existsSync(path.resolve(dir, pathMap[0])), pathMap[0]);

  assert.match(read(dir, "descriptor.mod"), /name = "My Mod"/);
  assert.match(read(dir, "events", "my_mod_events.txt"), /namespace = my_mod/);
  assert.match(read(dir, "events", "my_mod_events.txt"), /every_system = \{/);
  assert.match(read(dir, "events", "my_mod_events.txt"), /neo_action = \{ \}/);
  assert.match(read(dir, "common", "on_actions", "my_mod_on_actions.txt"), /on_monthly_pulse = \{/);
  assert.match(read(dir, "README.md"), /neo build/);
  assert.match(read(dir, "README.md"), /neo check/);
  assert.match(read(dir, "README.md"), /neo pack/);
});

test("a generated project builds and checks with no hand edits", () => {
  const root = tempRoot();
  const dir = path.join(root, "plugged_in");
  assert.equal(run(["new", dir, "--id", "plugged_in"]).status, 0);

  const build = run(["build", "--dir", dir]);
  assert.equal(build.status, 0, build.stderr);
  assert.match(build.stdout.trim(), /^NEO_BUILD ok dir=.* out=.*neo\/main\.js$/);
  assert.ok(existsSync(path.join(dir, "neo", "main.js")));

  const check = run(["check", "--dir", dir]);
  assert.equal(check.status, 0, check.stderr);
  assert.match(check.stdout.trim(), /^NEO_CHECK ok dir=.* handler=1 calls=6$/);
});

test("neo new refuses a non-empty target and a manifest-breaking id", () => {
  const root = tempRoot();
  const occupied = path.join(root, "occupied");
  mkdirSync(occupied);
  writeFileSync(path.join(occupied, "keep.txt"), "x\n");
  const refused = run(["new", occupied, "--id", "occupied"]);
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /^NEO_NEW fail: .*not empty/);
  assert.deepEqual(readdirSync(occupied), ["keep.txt"]);

  for (const id of ["Bad Id", "../escape", "", "-lead", "A"]) {
    const dir = path.join(root, `bad-${id.replace(/\W/g, "_") || "empty"}`);
    const result = run(["new", dir, `--id=${id}`]);
    assert.equal(result.status, 2, `id ${JSON.stringify(id)} must be rejected`);
    assert.match(result.stderr, /^NEO_NEW fail: /);
  }
});

test("neo new rejects a name that cannot go into descriptor.mod", () => {
  const root = tempRoot();
  const dir = path.join(root, "quoted");
  const result = run(["new", dir, "--id", "quoted", "--name", 'Bad "Name"']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /^NEO_NEW fail: /);
});
