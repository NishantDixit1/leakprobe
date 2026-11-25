import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const exec = promisify(execFile);
// The built artifact, not the test build: this is what actually ships,
// and version() resolves package.json relative to its own location.
const CLI = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));

async function run(args: string[]) {
  try {
    const { stdout } = await exec(process.execPath, [CLI, ...args], { timeout: 60_000 });
    return { code: 0, stdout };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: err.code ?? 1, stdout: (err.stdout ?? "") + (err.stderr ?? "") };
  }
}

test("--version prints a version, not the help text", async () => {
  const r = await run(["--version"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+$/, `got: ${r.stdout.trim()}`);
});

test("-v is the same as --version", async () => {
  assert.match((await run(["-v"])).stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test("--help exits 0", async () => {
  const r = await run(["--help"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /leakprobe/);
});

test("no arguments prints help and exits 1", async () => {
  const r = await run([]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /npx leakprobe/);
});

test("an unreachable host exits 1", async () => {
  assert.equal((await run(["http://127.0.0.1:1"])).code, 1);
});

test("an unusable address exits 1", async () => {
  assert.equal((await run(["file:///etc/passwd"])).code, 1);
});

test("an unknown --fail-on value is rejected", async () => {
  const r = await run(["https://example.com", "--fail-on=banana"]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /Unknown --fail-on/);
});
