// B3 — `neo pack`: the artifact is a whitelist, not a directory copy.  The
// tests drive the real CLI (build + real-QuickJS check included) and then read
// the zip back, because "the packer said ok" is not evidence about its bytes.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { listZip, readZipEntry } from "../dist/zip.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(here, "..");
const cli = path.join(sdkRoot, "dist", "cli.js");

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

function scaffold(id) {
  const root = mkdtempSync(path.join(tmpdir(), "neo-pack-"));
  const dir = path.join(root, id);
  const created = run(["new", dir, "--id", id, "--name", id.toUpperCase()]);
  assert.equal(created.status, 0, created.stderr);
  return dir;
}

test("neo pack stages a whitelist and round-trips it through the zip", () => {
  const id = "pack_ok";
  const dir = scaffold(id);

  // Junk that must not reach the artifact, even though it sits in the project.
  mkdirSync(path.join(dir, "node_modules", "left-pad"), { recursive: true });
  writeFileSync(path.join(dir, "node_modules", "left-pad", "index.js"), "module.exports = 1;\n");
  mkdirSync(path.join(dir, "dist", "old"), { recursive: true });
  writeFileSync(path.join(dir, "dist", "old", "stale.js"), "stale\n");
  writeFileSync(path.join(dir, "scratch.txt"), "not shipped\n");

  const out = path.join(dir, "..", `${id}.zip`);
  const packed = run(["pack", "--dir", dir, "--out", out]);
  assert.equal(packed.status, 0, packed.stderr);
  assert.match(packed.stdout.trim(), new RegExp(`^NEO_PACK ok dir=.* out=.*${id}\\.zip entries=6$`));
  assert.ok(existsSync(out));

  const archive = readFileSync(out);
  const names = listZip(archive).map((entry) => entry.name);
  assert.deepEqual(names.sort(), [
    "README.md",
    "common/on_actions/pack_ok_on_actions.txt",
    "descriptor.mod",
    `events/${id}_events.txt`,
    "neo/main.js",
    "neo/mod.json",
  ]);
  for (const name of names) {
    assert.doesNotMatch(name, /(^|\/)(node_modules|dist|\.git)(\/|$)/, name);
  }
  assert.ok(!names.includes("scratch.txt"));

  assert.deepEqual(readZipEntry(archive, "neo/main.js"), readFileSync(path.join(dir, "neo", "main.js")));
  const readme = readZipEntry(archive, "README.md").toString("utf8");
  assert.match(readme, /This is \*\*not\*\* a regular Workshop mod/);
  assert.match(readme, /C:\/temp\/neo_mods\/<id>\/neo\//);
  assert.match(readme, /id\b/);

  // The staged tree mirrors the archive (authors inspect it before uploading).
  const stage = path.join(dir, "dist", id);
  assert.ok(existsSync(path.join(stage, "descriptor.mod")));
  assert.ok(existsSync(path.join(stage, "neo", "main.js")));
  assert.deepEqual(readdirSync(path.join(stage, "common", "on_actions")), [`${id}_on_actions.txt`]);
});

test("neo pack is byte-identical on a second run", () => {
  const id = "pack_twice";
  const dir = scaffold(id);
  const first = path.join(dir, "dist", "a.zip");
  const second = path.join(dir, "dist", "b.zip");
  assert.equal(run(["pack", "--dir", dir, "--out", first]).status, 0);
  assert.equal(run(["pack", "--dir", dir, "--out", second]).status, 0);
  assert.deepEqual(readFileSync(first), readFileSync(second));
});

test("neo pack defaults the zip to <project>/dist/<id>.zip and keeps the author README", () => {
  const id = "pack_default";
  const dir = scaffold(id);
  writeFileSync(path.join(dir, "README.md"), "# Mine\n\nauthor words\n");
  const packed = run(["pack", "--dir", dir]);
  assert.equal(packed.status, 0, packed.stderr);
  const out = path.join(dir, "dist", `${id}.zip`);
  assert.match(packed.stdout, new RegExp(`out=${out.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  const readme = readZipEntry(readFileSync(out), "README.md").toString("utf8");
  assert.match(readme, /^# Mine\n\nauthor words\n/);
  assert.match(readme, /Known limitations/);
});

test("neo pack refuses a project that fails neo check", () => {
  const id = "pack_bad";
  const dir = scaffold(id);
  writeFileSync(
    path.join(dir, "src", "main.ts"),
    'import { onSystem } from "@neo/runtime";\ndeclare const process: { exit(code: number): never };\nonSystem(() => { process.exit(1); });\n',
  );
  const out = path.join(dir, "..", `${id}.zip`);
  const packed = run(["pack", "--dir", dir, "--out", out]);
  assert.equal(packed.status, 2);
  assert.match(packed.stderr, /^NEO_PACK fail: .*check failed/);
  assert.ok(!existsSync(out));
});

test("neo pack refuses a project without neo/mod.json", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "neo-pack-empty-"));
  const packed = run(["pack", "--dir", dir, "--out", path.join(dir, "x.zip")]);
  assert.equal(packed.status, 2);
  assert.match(packed.stderr, /^NEO_PACK fail: .*mod\.json/);
});
