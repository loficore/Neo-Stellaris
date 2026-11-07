#!/usr/bin/env node
// cli.ts — `neo new` / `neo build` / `neo check`.
//
// Exit codes are the CI/author contract: 0 = ok, 2 = the project (or the
// request) is not shippable.  Diagnostics go to stderr on exactly one line;
// success is one line on stdout, so a log cannot hide which step ran.
//
// `build`/`check` take `--dir <project>`; the project owns
// `tsconfig.json`, `src/main.ts` and `neo/mod.json`.  `new` takes the target
// directory as its positional argument.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { runBuild } from "./build.js";
import { runCheck } from "./check.js";
import { runNew } from "./new.js";

const USAGE = `neo — runtime JS SDK for the Neo-Stellaris QuickJS host

usage:
  neo new <dir> --id <id> [--name <name>]
  neo build --dir <project> [--outfile <file>]
  neo check --dir <project>

new scaffolds <dir> from the SDK template (TypeScript + manifest + the monthly
event driver).  The result must already pass "neo build" and "neo check".

build writes <project>/neo/<manifest entry> (default neo/main.js).
check bundles in memory and runs the bundle in a real QuickJS context with the
mock host installed.
`;

interface Parsed {
  command: string | undefined;
  dir: string | undefined;
  outfile: string | undefined;
  id: string | undefined;
  name: string | undefined;
  help: boolean;
}

function parse(argv: string[]): Parsed {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      dir: { type: "string" },
      outfile: { type: "string" },
      id: { type: "string" },
      name: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  return {
    command: positionals[0],
    dir: positionals[1] ?? values.dir,
    outfile: values.outfile,
    id: values.id,
    name: values.name,
    help: values.help === true,
  };
}

const COMMANDS = new Set(["new", "build", "check"]);

function fail(prefix: string, message: string): number {
  process.stderr.write(`${prefix} fail: ${message}\n`);
  return 2;
}

async function main(argv: string[]): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = parse(argv);
  } catch (error) {
    process.stderr.write(`NEO_CLI fail: ${(error as Error).message}\n`);
    return 2;
  }
  if (parsed.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (parsed.command === undefined) {
    process.stderr.write(USAGE);
    return 2;
  }
  if (!COMMANDS.has(parsed.command)) {
    process.stderr.write(`NEO_CLI fail: unknown command '${parsed.command}'\n${USAGE}`);
    return 2;
  }
  if (!parsed.dir) {
    process.stderr.write(`NEO_CLI fail: --dir is required\n${USAGE}`);
    return 2;
  }

  if (parsed.command === "new") {
    if (!parsed.id) return fail("NEO_NEW", "new: --id is required");
    try {
      const result = runNew({ dir: parsed.dir, id: parsed.id, name: parsed.name });
      process.stdout.write(`NEO_NEW ok dir=${result.dir} id=${result.id} files=${result.files.length}\n`);
      return 0;
    } catch (error) {
      return fail("NEO_NEW", (error as Error).message);
    }
  }

  if (parsed.command === "build") {
    try {
      const result = await runBuild({ dir: parsed.dir, outfile: parsed.outfile });
      process.stdout.write(`NEO_BUILD ok dir=${result.dir} out=${result.outfile}\n`);
      return 0;
    } catch (error) {
      return fail("NEO_BUILD", (error as Error).message);
    }
  }

  // `check` is the build-time gate: real QuickJS + mock host.
  try {
    const result = await runCheck({ dir: parsed.dir });
    if (result.ok) {
      process.stdout.write(
        `NEO_CHECK ok dir=${result.dir} handler=${result.registrations} calls=${result.calls.length}\n`,
      );
      return 0;
    }
    return fail("NEO_CHECK", result.error ?? "unknown failure");
  } catch (error) {
    return fail("NEO_CHECK", (error as Error).message);
  }
}

function invokedAsScript(): boolean {
  const entry = process.argv[1];
  return entry !== undefined && path.resolve(entry) === fileURLToPath(import.meta.url);
}

if (invokedAsScript()) {
  process.exitCode = await main(process.argv.slice(2));
}
