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
  /** Answer 200 with index.html for every unknown path, like a Vite SPA. */
  spa: false,
  /** Echo back whatever Origin is sent, with credentials allowed. */
  reflectOrigin: false,
  /** Serve a real-looking database dump. */
  serveBackup: false,
  /** Answer like bot protection rather than like the app. */
  shield: false,
  /** Pretend to be a Supabase project exposing this many tables. */
  tables: 0,
};

before(async () => {
  server = http.createServer((req, res) => {
    const url = req.url ?? "/";

    if (state.shield) {
      return void res
        .writeHead(403, { "content-type": "text/html", "x-vercel-mitigated": "challenge" })
        .end("<html><body>Checking your browser</body></html>");
    }

    const INDEX = `<!doctype html><html lang="en"><head><meta charset="UTF-8" /></head><body><script src="/app.js"></script></body></html>`;

    if (url === "/.env" || url === "/.env.local" || url === "/.env.production") {
      if (state.serveEnv) {
        return void res.writeHead(200, { "content-type": "text/plain" })
          .end("DATABASE_URL=postgres://u:p@host/db\nAPI_TOKEN=abc123");
      }
      if (state.spa) return void res.writeHead(200, { "content-type": "text/html" }).end(INDEX);
      return void res.writeHead(404).end("nope");
    }
    if (url === "/.git/config") {
      if (state.spa) return void res.writeHead(200, { "content-type": "text/html" }).end(INDEX);
      return void res.writeHead(404).end("nope");
    }
    if (state.spa && url !== "/" && url !== "/app.js") {
      return void res.writeHead(200, { "content-type": "text/html" }).end(INDEX);
    }

    if (url === "/app.js") {
      const secret = state.leakKey ? `const k="sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";` : "";
      const project = state.tables > 0 ? base : "https://abcdefghijklmnopqrst.supabase.co";
      return void res.writeHead(200, { "content-type": "application/javascript" })
        .end(`${secret}\nconst sb=createClient("${project}","${jwt("anon")}");`);
    }

    if (state.tables > 0 && url === "/rest/v1/") {
      const definitions: Record<string, object> = {};
      for (let i = 0; i < state.tables; i++) definitions[`table_${i}`] = {};
      return void res.writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ definitions }));
    }
    if (state.tables > 0 && url.startsWith("/rest/v1/table_")) {
      // Every table refuses, so the only thing under test is coverage.
      return void res.writeHead(401, { "content-type": "application/json" })
        .end(JSON.stringify({ message: "permission denied" }));
    }

    if (url === "/backup.sql") {
      if (!state.serveBackup) return void res.writeHead(404).end("nope");
      return void res.writeHead(200, { "content-type": "application/sql" })
        .end("-- PostgreSQL database dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);");
    }

    const headers: Record<string, string> = { "content-type": "text/html" };
    if (state.reflectOrigin && req.headers.origin) {
      headers["access-control-allow-origin"] = String(req.headers.origin);
      headers["access-control-allow-credentials"] = "true";
    }
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
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false, spa: false, reflectOrigin: false, serveBackup: false, shield: false, tables: 0 });
  const r = ok(await runScan(base));
  assert.ok(ids(r).includes("secrets"), "missed the API key in the bundle");
  assert.ok(ids(r).includes("exposed-files"), "missed the served .env");
  assert.ok(ids(r).includes("headers"), "missed the absent headers");
});

test("the anon key alone is not reported as a leak", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, reflectOrigin: false, serveBackup: false, shield: false, tables: 0 });
  const r = ok(await runScan(base));
  assert.deepEqual(ids(r), [], `clean app reported: ${JSON.stringify(r.findings.map((f) => f.title))}`);
  assert.ok(r.passed.some((p) => p.includes("No secret keys")));
});

test("a clean app passes the header check", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, reflectOrigin: false, serveBackup: false, shield: false, tables: 0 });
  const r = ok(await runScan(base));
  assert.ok(r.passed.some((p) => p.includes("Security headers")));
});

test("findings never contain row data, and secrets are redacted", async () => {
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false, spa: false, reflectOrigin: false, serveBackup: false, shield: false, tables: 0 });
  const r = ok(await runScan(base));
  const dump = JSON.stringify(r);
  assert.ok(!dump.includes("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"), "full secret leaked into the report");
  assert.ok(!dump.includes("postgres://u:p@host/db"), ".env contents leaked into the report");
});

test("every finding carries a fix prompt", async () => {
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false, spa: false, reflectOrigin: false, serveBackup: false, shield: false, tables: 0 });
  const r = ok(await runScan(base));
  for (const f of r.findings) {
    assert.ok(f.fixPrompt.length > 40, `${f.id} has no usable fix prompt`);
    assert.ok(f.risk.length > 0 && f.what.length > 0, `${f.id} is missing copy`);
  }
});

test("critical findings sort above medium", async () => {
  Object.assign(state, { serveEnv: true, leakKey: true, headers: false, spa: false, reflectOrigin: false, serveBackup: false, shield: false, tables: 0 });
  const r = ok(await runScan(base));
  const rank = ["critical", "high", "medium", "info"];
  const seq = r.findings.map((f) => rank.indexOf(f.severity));
  assert.deepEqual(seq, [...seq].sort((a, b) => a - b), "findings are not ordered by severity");
});

test("Supabase is detected and reported in the stack", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, reflectOrigin: false, serveBackup: false, shield: false, tables: 0 });
  const r = ok(await runScan(base));
  assert.ok(r.stack.includes("Supabase"), `stack was ${JSON.stringify(r.stack)}`);
});

// ── The regression that mattered most ───────────────────────────────
// A single-page app answers 200 with index.html for every unknown path.
// Testing status alone reported every Vite, React Router, Lovable and
// Bolt app as serving a .env file, which is most of the audience.

test("an SPA catch-all route is not reported as an exposed .env", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: true });
  const r = ok(await runScan(base));
  assert.ok(
    !ids(r).includes("exposed-files"),
    "reported a config file on a host that answers 200 for everything",
  );
});

test("an SPA says the file check was skipped rather than claiming it passed", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: true });
  const r = ok(await runScan(base));
  assert.ok(
    r.skipped.some((x) => x.check === "Exposed configuration files"),
    "silently dropped the check instead of reporting it as skipped",
  );
  assert.ok(!r.passed.some((p) => p.includes("No configuration files")));
});

test("a genuinely served .env is still caught on an SPA host", async () => {
  Object.assign(state, { serveEnv: true, leakKey: false, headers: true, spa: true });
  const r = ok(await runScan(base));
  assert.ok(ids(r).includes("exposed-files"), "missed a real .env behind an SPA fallback");
});

// ── The newer checks ────────────────────────────────────────────────

test("an app that reflects any Origin with credentials is reported", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, reflectOrigin: true });
  const r = ok(await runScan(base));
  const cors = r.findings.find((f) => f.id === "cors");
  assert.ok(cors, "missed a reflected Origin with credentials allowed");
  assert.equal(cors.severity, "high");
  state.reflectOrigin = false;
});

test("an app that sets no CORS headers is not reported", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, reflectOrigin: false });
  const r = ok(await runScan(base));
  assert.ok(!ids(r).includes("cors"));
});

test("a served database dump is caught", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, serveBackup: true });
  const r = ok(await runScan(base));
  const f = r.findings.find((x) => x.id === "exposed-files");
  assert.ok(f, "missed a served backup.sql");
  assert.ok(f.evidence?.some((e) => e.includes("backup.sql")));
  state.serveBackup = false;
});

test("a backup path that 404s is not reported", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, serveBackup: false });
  const r = ok(await runScan(base));
  assert.ok(!ids(r).includes("exposed-files"));
});

// ── Bot protection ──────────────────────────────────────────────────
// Scanning the challenge page and reporting on it is worse than not
// scanning: every check would describe the protection, not the app, and
// would say so confidently.

test("a site behind bot protection is refused, not reported on", async () => {
  Object.assign(state, { shield: true });
  const r = await runScan(base);
  assert.ok("error" in r, "reported findings for a challenge page");
  assert.match((r as { error: string }).error, /bot protection/i);
  state.shield = false;
});

test("a normal site is still scanned once protection is off", async () => {
  Object.assign(state, { serveEnv: false, leakKey: false, headers: true, spa: false, shield: false });
  const r = await runScan(base);
  assert.ok(!("error" in r));
});

test("an unreachable host returns an error rather than throwing", async () => {
  const r = await runScan("http://127.0.0.1:1");
  assert.ok("error" in r);
});

test("a bad address returns an error rather than throwing", async () => {
  const r = await runScan("file:///etc/passwd");
  assert.ok("error" in r);
});
