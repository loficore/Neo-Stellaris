// new.ts — `neo new`: scaffold an authoring project from `sdk/templates/neo-mod`.
//
// The template is data, not a generator: every file is copied verbatim except
// for three substitutions (`{{ID}}`, `{{NAME}}`, `{{RUNTIME_TS}}`), so what
// `neo new` writes is what a reader of `sdk/templates/neo-mod/` sees.  The
// generated project is expected to pass `neo build` and `neo check` with no
// hand edits — `sdk/test/new.test.mjs` holds that promise.
//
// `{{RUNTIME_TS}}` is resolved at generation time (relative to the target
// directory) because v1 is source-distributed: the project maps `@neo/runtime`
// straight at the SDK's `src/runtime.ts`, there is no registry install.

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface NewOptions {
  /** Target project directory (created if absent). */
  dir: string;
  /** Manifest id: also the loader directory (`C:/temp/neo_mods/<id>`) and the event namespace. */
  id: string;
  /** Human-readable name for `descriptor.mod` / README; defaults to `id`. */
  name?: string;
}

export interface NewResult {
  dir: string;
  id: string;
  /** Project-relative paths written, sorted. */
  files: string[];
}

/**
 * The id is three things at once: the `neo/mod.json` id, a directory name under
 * `C:/temp/neo_mods/`, and the Clausewitz `namespace` in `events/`.  Lowercase
 * letters, digits and underscore is the intersection of what all three accept.
 */
const ID_PATTERN = /^[a-z0-9][a-z0-9_]{0,63}$/;

export function sdkRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function templateRoot(): string {
  return path.join(sdkRoot(), "templates", "neo-mod");
}

function validateId(id: string): void {
  if (!ID_PATTERN.test(id)) {
    throw new Error(`id ${JSON.stringify(id)} must match ${ID_PATTERN.source}`);
  }
}

function validateName(name: string): void {
  if (name.length === 0 || name.length > 120) {
    throw new Error("name must be 1..120 characters");
  }
  if (/[\u0000-\u001f"]/.test(name)) {
    throw new Error(`name ${JSON.stringify(name)} contains a quote or control character`);
  }
}

/** The `paths` value: `src/runtime.ts` relative to the generated project, POSIX slashes. */
function runtimeTsPath(dir: string): string {
  const rel = path.relative(dir, path.join(sdkRoot(), "src", "runtime.ts"));
  return rel.split(path.sep).join("/");
}

function walk(root: string, rel = ""): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const next = rel === "" ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) out.push(...walk(root, next));
    else if (entry.isFile()) out.push(next);
  }
  return out.sort();
}

export function runNew(options: NewOptions): NewResult {
  const id = options.id;
  const name = (options.name ?? id).trim();
  validateId(id);
  validateName(name);

  const dir = path.resolve(options.dir);
  if (existsSync(dir) && readdirSync(dir).length > 0) {
    throw new Error(`new: ${dir} is not empty`);
  }
  const template = templateRoot();
  if (!existsSync(template)) {
    throw new Error(`new: template missing at ${template}`);
  }

  const runtime = runtimeTsPath(dir);
  const files: string[] = [];
  for (const rel of walk(template)) {
    const targetRel = rel.split("{{ID}}").join(id);
    const text = readFileSync(path.join(template, rel), "utf8")
      .split("{{ID}}")
      .join(id)
      .split("{{NAME}}")
      .join(name)
      .split("{{RUNTIME_TS}}")
      .join(runtime);
    const target = path.join(dir, ...targetRel.split("/"));
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, text);
    files.push(targetRel);
  }
  return { dir, id, files };
}
