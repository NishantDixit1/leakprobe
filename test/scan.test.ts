import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runScan } from "../src/checks.js";
import type { ScanResult } from "../src/types.js";

/**
 * A deliberately broken app, served locally.
 *
 * End to end matters more than unit coverage here: the checks are
 * mostly about what a real HTTP response looks like, and a mocked fetch
 * would be asserting my own assumptions rather than the behaviour.
 */
function jwt(role: string): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "HS256" })}.${b64({ role, iss: "supabase" })}.c2lnbmF0dXJlX3BsYWNlaG9sZGVy`;
}

let server: http.Server;
let base: string;

/** Flip these per test to change what the fake app exposes. */
const state = {
  serveEnv: true,
  leakKey: true,
  headers: false,
};

before(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? "/";

    if (url === "/.env" || url === "/.env.local" || url === "/.env.production") {
      if (!state.serveEnv) return void res.writeHead(404).end("nope");
      return void res.writeHead(200, { "content-type": "text/plain" })
        .end("DATABASE_URL=postgres://u:p@host/db\nSTRIPE_KEY=sk_live_x");
    }
    if (url === "/.git/config") return void res.writeHead(404).end("nope");

    if (url === "/app.js") {
      const secret = state.leakKey ? `const k="sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";` : "";
      return void res.writeHead(200, { "content-type": "application/javascript" })
        .end(`${secret}\nconst sb=createClient("https://abcdefghijklmnopqrst.supabase.co","${jwt("anon")}");`);
    }

    const headers: Record<string, string> = { "content-type": "text/html" };
    if (state.headers) {
      headers["content-security-policy"] = "default-src 'self'; frame-ancestors 'none'";
      headers["strict-transport-security"] = "max-age=63072000";
      headers["x-content-type-options"] = "nosniff";
    }
    res.writeHead(200, headers).end(
      `<!doctype html><html><body><script src="/app.js"></script></body></html>`,
    );
  });

  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => server.close());

const ok = (r: ScanResult | { error: string }): ScanResult => {
  assert.ok(!("error" in r), `scan failed: ${"error" in r ? r.error : ""}`);
  return r as ScanResult;
};
const ids = (r: ScanResult) => r.findings.map((f) => f.id);

test("finds the leaked key, the served .env and the missing headers", async () => {
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false });
  const r = ok(await runScan(base));
  assert.ok(ids(r).includes("secrets"), "missed the API key in the bundle");
  assert.ok(ids(r).includes("exposed-files"), "missed the served .env");
  assert.ok(ids(r).includes("headers"), "missed the absent headers");
});

test("the anon key alone is not reported as a leak", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true });
  const r = ok(await runScan(base));
  assert.deepEqual(ids(r), [], `clean app reported: ${JSON.stringify(r.findings.map((f) => f.title))}`);
  assert.ok(r.passed.some((p) => p.includes("No secret keys")));
});

test("a clean app passes the header check", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true });
  const r = ok(await runScan(base));
  assert.ok(r.passed.some((p) => p.includes("Security headers")));
});

test("findings never contain row data, and secrets are redacted", async () => {
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false });
  const r = ok(await runScan(base));
  const dump = JSON.stringify(r);
  assert.ok(!dump.includes("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"), "full secret leaked into the report");
  assert.ok(!dump.includes("postgres://u:p@host/db"), ".env contents leaked into the report");
});

test("every finding carries a fix prompt", async () => {
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false });
  const r = ok(await runScan(base));
  for (const f of r.findings) {
    assert.ok(f.fixPrompt.length > 40, `${f.id} has no usable fix prompt`);
    assert.ok(f.risk.length > 0 && f.what.length > 0, `${f.id} is missing copy`);
  }
});

test("critical findings sort above medium", async () => {
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false });
  const r = ok(await runScan(base));
  const rank = ["critical", "high", "medium", "info"];
  const seq = r.findings.map((f) => rank.indexOf(f.severity));
  assert.deepEqual(seq, [...seq].sort((a, b) => a - b), "findings are not ordered by severity");
});

test("Supabase is detected and reported in the stack", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true });
  const r = ok(await runScan(base));
  assert.ok(r.stack.includes("Supabase"), `stack was ${JSON.stringify(r.stack)}`);
});

test("an unreachable host returns an error rather than throwing", async () => {
  const r = await runScan("http://127.0.0.1:1");
  assert.ok("error" in r);
});

test("a bad address returns an error rather than throwing", async () => {
  const r = await runScan("file:///etc/passwd");
  assert.ok("error" in r);
});
