#!/usr/bin/env node
// Repository lint for the TypeScript packages.
//
// `typecheck` already runs `tsc --noEmit`, so this deliberately checks only
// things the type system cannot see:
//
//   1. Relative imports carry an explicit `.ts` extension. The packages run
//      under `node --experimental-strip-types`, which does no extension
//      resolution, so an extensionless relative import type-checks and then
//      fails at run time.
//   2. Non-test source does not call `console.*`. Specification §26.6 forbids
//      putting request bodies, tokens, or stack traces into Worker
//      observability; the reliable way to keep that true is to keep ad-hoc
//      logging out of the Worker entirely.
//
// Usage: node scripts/lint-ts.mjs [dir...]   (defaults to ./src)

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const roots = (process.argv.slice(2).length ? process.argv.slice(2) : ["src"]).map((d) =>
  resolve(process.cwd(), d),
);

/** Relative specifier in an import/export/dynamic-import position. */
const RELATIVE_SPECIFIER =
  /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.[^"']*)["']/g;
const CONSOLE_CALL = /\bconsole\s*\.\s*[a-zA-Z]+\s*\(/;

function walk(dir) {
  const out = [];
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
      out.push(...walk(full));
    } else if (entry.isFile() && /\.(ts|mts|tsx)$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function stripCommentsAndStrings(line) {
  // Good enough to avoid flagging `console.log` inside a comment or a doc
  // string; a false negative here only means the lint is quiet, never wrong.
  return line.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "");
}

const problems = [];

for (const root of roots) {
  let rootStat;
  try {
    rootStat = statSync(root);
  } catch {
    continue;
  }
  if (!rootStat.isDirectory()) continue;

  for (const file of walk(root)) {
    const rel = relative(process.cwd(), file);
    const isTest = /\.test\.(ts|mts|tsx)$/.test(file);
    const source = readFileSync(file, "utf8");
    const lines = source.split("\n");

    for (const [index, rawLine] of lines.entries()) {
      const line = stripCommentsAndStrings(rawLine);
      const lineNo = index + 1;

      RELATIVE_SPECIFIER.lastIndex = 0;
      let match;
      while ((match = RELATIVE_SPECIFIER.exec(line)) !== null) {
        const specifier = match[1];
        if (!/\.(ts|mts|tsx|json)$/.test(specifier)) {
          problems.push(
            `${rel}:${lineNo}: relative import "${specifier}" needs an explicit ` +
              `.ts extension (node --experimental-strip-types does not resolve it)`,
          );
        }
      }

      if (!isTest && CONSOLE_CALL.test(line)) {
        problems.push(
          `${rel}:${lineNo}: console.* in non-test source; keep request data out ` +
            `of observability (specification §26.6)`,
        );
      }
    }
  }
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`lint: ${problem}`);
  console.error(`lint: ${problems.length} problem(s)`);
  process.exit(1);
}
