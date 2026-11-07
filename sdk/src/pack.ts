// pack.ts — `neo pack`: build, check, stage the shippable tree, and zip it.
//
// The zip is a whitelist, not a directory copy: `node_modules/`, `dist/`,
// `.git/` and anything else the author happens to keep in the project cannot
// reach the artifact.  What goes in is exactly what the injector and the
// launcher need:
//
//   descriptor.mod  common/**  events/**  neo/{mod.json,<entry>}  README.md
//
// The README in the package always ends with the known-limitation block: a
// runtime JS mod is inert without the injected host, and a package that only
// says "install me" would be misleading.

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import { runBuild } from "./build.js";
import { runCheck } from "./check.js";
import { createZip, listZip, readZipEntry } from "./zip.js";

export interface PackOptions {
  /** Project directory (tsconfig.json + src/main.ts + neo/mod.json). */
  dir: string;
  /** Zip path; defaults to `<project>/dist/<id>.zip`. */
  out?: string;
}

export interface PackResult {
  dir: string;
  id: string;
  stage: string;
  outfile: string;
  /** Project-relative paths inside the archive, sorted. */
  entries: string[];
}

/** Directories that must never reach an artifact, wherever they appear. */
const NEVER = new Set(["node_modules", "dist", ".git"]);

const LIMITATIONS = [
  "## Known limitations (runtime JS)",
  "",
  "This is **not** a regular Workshop mod. A normal Stellaris mod is parsed by the",
  "Clausewitz script engine; this one carries a JavaScript bundle (`neo/`) that only",
  "runs when the injected QuickJS host loads it from `C:/temp/neo_mods/<id>/neo/`.",
  "Without that injection the files are inert, and the script parser logs `neo_action`",
  "as an unknown effect. Only Stellaris 4.4.4 (Windows, x86_64) is supported.",
].join("\n");

interface Manifest {
  id: string;
  entry: string;
}

function readManifest(dir: string): Manifest {
  const file = path.join(dir, "neo", "mod.json");
  if (!existsSync(file)) throw new Error(`pack: missing ${file}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`pack: ${file} is not JSON: ${(error as Error).message}`);
  }
  const obj = parsed as { id?: unknown; entry?: unknown };
  const id = typeof obj.id === "string" ? obj.id : "";
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id) || id === "." || id === "..") {
    throw new Error(`pack: manifest id ${JSON.stringify(obj.id)} is not a safe directory name`);
  }
  const entry = typeof obj.entry === "string" && obj.entry.length > 0 ? obj.entry : "main.js";
  return { id, entry };
}

/** Project-relative files under `rel`, skipping {@link NEVER} at any depth. */
function walkProject(dir: string, rel: string): string[] {
  const abs = path.join(dir, rel);
  if (!existsSync(abs)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(abs, { withFileTypes: true })) {
    const next = `${rel}/${entry.name}`;
    if (entry.isDirectory()) {
      if (!NEVER.has(entry.name)) out.push(...walkProject(dir, next));
    } else if (entry.isFile()) {
      out.push(next);
    }
  }
  return out.sort();
}

function packageReadme(dir: string, id: string): string {
  const own = path.join(dir, "README.md");
  const head = existsSync(own)
    ? readFileSync(own, "utf8").replace(/\s*$/, "\n\n")
    : `# ${id}\n\n`;
  return `${head}${LIMITATIONS}\n`;
}

export async function runPack(options: PackOptions): Promise<PackResult> {
  const dir = path.resolve(options.dir);
  const manifest = readManifest(dir);

  await runBuild({ dir });
  const check = await runCheck({ dir });
  if (!check.ok) throw new Error(`pack: neo check failed: ${check.error ?? "unknown failure"}`);

  const stage = path.join(dir, "dist", manifest.id);
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });

  const wanted = [
    "descriptor.mod",
    ...walkProject(dir, "common"),
    ...walkProject(dir, "events"),
    "neo/mod.json",
    `neo/${manifest.entry}`,
  ];
  const entries: { name: string; data: Buffer }[] = [];
  for (const rel of wanted) {
    const source = path.join(dir, ...rel.split("/"));
    if (!existsSync(source)) {
      throw new Error(`pack: missing ${rel} (needed for the package layout)`);
    }
    const data = readFileSync(source);
    entries.push({ name: rel, data });
    const target = path.join(stage, ...rel.split("/"));
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, data);
  }
  const readme = Buffer.from(packageReadme(dir, manifest.id), "utf8");
  entries.push({ name: "README.md", data: readme });
  writeFileSync(path.join(stage, "README.md"), readme);

  const archive = createZip(entries);
  // Write-back verification: the artifact is what the author ships, so a
  // mismatch between intent and bytes must fail here, not on the game box.
  const listed = listZip(archive).map((entry) => entry.name);
  for (const entry of entries) {
    if (!listed.includes(entry.name)) throw new Error(`pack: ${entry.name} missing from the archive`);
    if (!readZipEntry(archive, entry.name).equals(entry.data)) {
      throw new Error(`pack: ${entry.name} did not round-trip through the archive`);
    }
  }

  const outfile = path.resolve(options.out ?? path.join(dir, "dist", `${manifest.id}.zip`));
  mkdirSync(path.dirname(outfile), { recursive: true });
  writeFileSync(outfile, archive);

  return {
    dir,
    id: manifest.id,
    stage,
    outfile,
    entries: listed.sort(),
  };
}
