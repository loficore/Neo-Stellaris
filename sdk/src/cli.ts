#!/usr/bin/env node
// cli.ts — `neo build` / `neo check`.
//
// Both commands take `--dir <project>`; the project owns `tsconfig.json`,
// `src/main.ts` and `neo/mod.json`.  Exit codes are the CI/author contract:
// 0 = ok, 2 = the project is not shippable (diagnostics go to stderr).

import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { runBuild } from "./build.js";

const USAGE = `neo — runtime JS SDK for the Neo-Stellaris QuickJS host

usage:
  neo build --dir <project> [--outfile <file>]
  neo check --dir <project>

Both commands expect <project>/tsconfig.json and <project>/src/main.ts.
\`build\` writes <project>/neo/<manifest entry> (default neo/main.js).
\`check\` bundles in memory and runs the bundle in a real QuickJS context
with the mock host installed.
`;

interface Parsed {
  command: string | undefined;
  dir: string | undefined;
  outfile: string | undefined;
  help: boolean;
}

function parse(argv: string[]): Parsed {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      dir: { type: "string" },
      outfile: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  return {
    command: positionals[0],
    dir: values.dir,
    outfile: values.outfile,
    help: values.help === true,
  };
}

async function main(argv: string[]): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = parse(argv);
  } catch (error) {
    process.stderr.write(`NEO_CLI fail: ${(error as Error).message}\n`);
    return 2;
  }
  if (parsed.help || parsed.command === undefined) {
    process.stdout.write(USAGE);
    return parsed.command === undefined && !parsed.help ? 2 : 0;
  }
  if (parsed.command !== "build" && parsed.command !== "check") {
    process.stderr.write(`NEO_CLI fail: unknown command '${parsed.command}'\n${USAGE}`);
    return 2;
  }
  if (!parsed.dir) {
    process.stderr.write(`NEO_CLI fail: --dir is required\n${USAGE}`);
    return 2;
  }

  if (parsed.command === "build") {
    try {
      const result = await runBuild({ dir: parsed.dir, outfile: parsed.outfile });
      process.stdout.write(`NEO_BUILD ok dir=${result.dir} out=${result.outfile}\n`);
      return 0;
    } catch (error) {
      process.stderr.write(`NEO_BUILD fail: ${(error as Error).message}\n`);
      return 2;
    }
  }

  // `check` is implemented in check.ts (B3).
  process.stderr.write("NEO_CHECK fail: check is not wired yet\n");
  return 2;
}

function invokedAsScript(): boolean {
  const entry = process.argv[1];
  return entry !== undefined && path.resolve(entry) === fileURLToPath(import.meta.url);
}

if (invokedAsScript()) {
  process.exitCode = await main(process.argv.slice(2));
}
