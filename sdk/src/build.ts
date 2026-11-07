// build.ts — `neo build`: type-check the authoring project with tsc, then
// bundle `src/main.ts` into one IIFE that the host can `JS_Eval` directly.
//
// The bundle contract is the host's, not the browser's: `format=iife`,
// `platform=neutral`, `target=es2020`.  There is no module loader in QuickJS,
// so anything that survives as an `import`/`require` is a build failure.

import { build as esbuild } from "esbuild";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";

export interface BuildOptions {
  /** Project directory: expects `tsconfig.json` + `src/main.ts`. */
  dir: string;
  /** Output file; defaults to `<dir>/neo/<manifest entry or main.js>`. */
  outfile?: string;
}

export interface BuildResult {
  dir: string;
  outfile: string;
}

export interface BundleResult {
  dir: string;
  text: string;
}

const require = createRequire(import.meta.url);

function tscPath(): string {
  const pkg = require.resolve("typescript/package.json");
  return path.join(path.dirname(pkg), "lib", "tsc.js");
}

export function projectDir(dir: string): string {
  return path.resolve(dir);
}

function manifestEntry(dir: string): string {
  const manifest = path.join(dir, "neo", "mod.json");
  if (!existsSync(manifest)) return "main.js";
  try {
    const parsed = JSON.parse(readFileSync(manifest, "utf8")) as { entry?: unknown };
    return typeof parsed.entry === "string" && parsed.entry.length > 0 ? parsed.entry : "main.js";
  } catch {
    return "main.js";
  }
}

/** Run `tsc --noEmit -p <dir>`; throws with the compiler's own diagnostics. */
export function typecheck(dir: string): void {
  const tsconfig = path.join(dir, "tsconfig.json");
  if (!existsSync(tsconfig)) {
    throw new Error(`tsc: no tsconfig.json in ${dir}`);
  }
  const run = spawnSync(process.execPath, [tscPath(), "--noEmit", "-p", tsconfig], {
    encoding: "utf8",
  });
  if (run.error) {
    throw new Error(`tsc: failed to start: ${run.error.message}`);
  }
  if (run.status !== 0) {
    const detail = `${run.stdout ?? ""}${run.stderr ?? ""}`.trim();
    throw new Error(`tsc: type check failed for ${dir}\n${detail}`);
  }
}

async function bundle(dir: string, write: false): Promise<string>;
async function bundle(dir: string, write: true, outfile: string): Promise<string>;
async function bundle(dir: string, write: boolean, outfile?: string): Promise<string> {
  const entry = path.join(dir, "src", "main.ts");
  if (!existsSync(entry)) {
    throw new Error(`build: missing ${entry}`);
  }
  const result = await esbuild({
    entryPoints: [entry],
    bundle: true,
    format: "iife",
    platform: "neutral",
    target: "es2020",
    tsconfig: path.join(dir, "tsconfig.json"),
    logLevel: "silent",
    write,
    outfile,
  });
  if (!write) {
    const file = result.outputFiles?.[0];
    if (!file) throw new Error("build: esbuild produced no output");
    return file.text;
  }
  return outfile as string;
}

function requireEntry(dir: string): string {
  const entry = path.join(dir, "src", "main.ts");
  if (!existsSync(entry)) {
    throw new Error(`build: missing ${entry}`);
  }
  return entry;
}

/** Type-check and bundle a project to disk. */
export async function runBuild(options: BuildOptions): Promise<BuildResult> {
  const dir = projectDir(options.dir);
  requireEntry(dir);
  typecheck(dir);
  const outfile = path.resolve(
    options.outfile ?? path.join(dir, "neo", `${path.parse(manifestEntry(dir)).name}.js`),
  );
  mkdirSync(path.dirname(outfile), { recursive: true });
  await bundle(dir, true, outfile);
  return { dir, outfile };
}

/** Type-check and bundle a project in memory (used by `neo check`). */
export async function bundleProject(dir: string): Promise<BundleResult> {
  const abs = projectDir(dir);
  requireEntry(abs);
  typecheck(abs);
  return { dir: abs, text: await bundle(abs, false) };
}
