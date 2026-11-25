#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runScan } from "./checks.js";
import type { Finding, ScanResult } from "./types.js";

/** Read from package.json so --version cannot drift from what is published. */
function version(): string {
  try {
    const pkg = fileURLToPath(new URL("../package.json", import.meta.url));
    const parsed: unknown = JSON.parse(readFileSync(pkg, "utf8"));
    const v = (parsed as { version?: unknown })?.version;
    return typeof v === "string" ? v : "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * Exit codes are chosen so this is usable in CI:
 *   0  nothing found, or only informational
 *   1  the scan could not run (bad address, host unreachable)
 *   2  a critical or high finding
 * With --fail-on=medium, a medium finding also exits 2.
 */

const COLOR = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, s: string) => (COLOR ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = (s: string) => c("1", s);
const dim = (s: string) => c("2", s);
const red = (s: string) => c("31", s);
const yellow = (s: string) => c("33", s);
const green = (s: string) => c("32", s);
const cyan = (s: string) => c("36", s);

const SEVERITY_LABEL: Record<Finding["severity"], string> = {
  critical: red("CRITICAL"),
  high: red("HIGH"),
  medium: yellow("MEDIUM"),
  info: dim("INFO"),
};

const HELP = `
${bold("leakprobe")} — is your deployed app leaking anything?

  ${bold("npx leakprobe")} <url> [options]

Checks what a stranger can already see: secret keys in your JavaScript,
database tables that answer anonymous requests, downloadable .env files,
public source maps, and missing security headers.

Everything it reads is already public. Nothing is exploited, nothing is
brute forced, and your row data is never printed or sent anywhere.

${bold("Options")}
  --json              Machine-readable output
  --fix               Print the paste-ready fix prompt for each finding
  --fail-on=<level>   critical | high | medium  (default: high)
  --max-tables=<n>    How many database tables to probe (default: 25)
  --all-tables        Probe every table, however many there are
  --quiet             Only print findings, not what passed
  -h, --help          This text
  -v, --version       Print version

${bold("Examples")}
  npx leakprobe https://myapp.vercel.app
  npx leakprobe myapp.com --fix
  npx leakprobe myapp.com --json > report.json
  npx leakprobe myapp.com --all-tables

${bold("Exit codes")}
  0  clean
  1  could not run
  2  found something at or above the --fail-on level

Only point this at a site you own or are authorised to test.
${dim("Built by Stackwrights · https://stackwrights.com")}
`;

function parseArgs(argv: string[]) {
  const flags = new Set<string>();
  const opts = new Map<string, string>();
  const positional: string[] = [];
  for (const a of argv) {
    if (a.startsWith("--") && a.includes("=")) {
      const [k, ...rest] = a.slice(2).split("=");
      if (k) opts.set(k, rest.join("="));
    } else if (a.startsWith("-")) {
      flags.add(a.replace(/^--?/, ""));
    } else {
      positional.push(a);
    }
  }
  return { flags, opts, positional };
}

function printHuman(r: ScanResult, { fix, quiet }: { fix: boolean; quiet: boolean }) {
  console.log("");
  console.log(`${bold("leakprobe")}  ${cyan(r.url)}`);
  if (r.stack.length) console.log(dim(`detected: ${r.stack.join(", ")}`));
  console.log("");

  if (r.findings.length === 0) {
    console.log(green("Nothing found. "), dim(`${r.passed.length} checks passed.`));
  }

  for (const f of r.findings) {
    console.log(`${SEVERITY_LABEL[f.severity]}  ${bold(f.title)}`);
    console.log(`  ${f.what}`);
    console.log(dim(`  ${f.risk}`));
    for (const e of f.evidence ?? []) console.log(dim(`    · ${e}`));
    if (fix) {
      console.log("");
      console.log(dim("  ── paste this into Claude Code, Cursor, Lovable or Bolt ──"));
      for (const line of f.fixPrompt.split("\n")) console.log(`  ${line}`);
      console.log(dim("  ──"));
    }
    console.log("");
  }

  if (!quiet) {
    for (const p of r.passed) console.log(`${green("ok")}  ${dim(p)}`);
    for (const s of r.skipped) console.log(`${dim("--")}  ${dim(`${s.check}: ${s.reason}`)}`);
    console.log("");
  }

  if (r.findings.length > 0 && !fix) {
    console.log(dim("Run again with --fix for paste-ready instructions to fix each one."));
  }
  console.log(dim(`Scanned in ${(r.durationMs / 1000).toFixed(1)}s. Nothing was stored or sent anywhere.`));
  console.log("");
}

async function main() {
  const { flags, opts, positional } = parseArgs(process.argv.slice(2));

  // Version first: --version takes no positional argument, so checking
  // the no-arguments case before it printed help instead.
  if (flags.has("v") || flags.has("version")) {
    console.log(version());
    process.exit(0);
  }
  if (flags.has("h") || flags.has("help")) {
    console.log(HELP);
    process.exit(0);
  }
  if (positional.length === 0) {
    console.log(HELP);
    process.exit(1);
  }

  const url = positional[0];
  if (!url) {
    console.error("No address given.");
    process.exit(1);
  }

  const maxTablesRaw = opts.get("max-tables");
  let maxTables: number | undefined;
  if (flags.has("all-tables")) {
    maxTables = Number.MAX_SAFE_INTEGER;
  } else if (maxTablesRaw !== undefined) {
    const n = Number(maxTablesRaw);
    if (!Number.isInteger(n) || n < 1) {
      console.error(`--max-tables needs a whole number of 1 or more, got: ${maxTablesRaw}`);
      process.exit(1);
    }
    maxTables = n;
  }

  const result = await runScan(url, maxTables === undefined ? {} : { maxTables });

  if ("error" in result) {
    console.error(red(`\n  ${result.error}\n`));
    process.exit(1);
  }

  if (flags.has("json")) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printHuman(result, { fix: flags.has("fix"), quiet: flags.has("quiet") });
  }

  const threshold = opts.get("fail-on") ?? "high";
  const ranked = ["info", "medium", "high", "critical"];
  const floor = ranked.indexOf(threshold);
  if (floor === -1) {
    console.error(`Unknown --fail-on value: ${threshold}`);
    process.exit(1);
  }
  const breached = result.findings.some((f) => ranked.indexOf(f.severity) >= floor);
  process.exit(breached ? 2 : 0);
}

main().catch((err: unknown) => {
  console.error(red(`\n  Unexpected failure: ${err instanceof Error ? err.message : String(err)}\n`));
  process.exit(1);
});
