import { test } from "node:test";
import assert from "node:assert/strict";
import { findSecrets, findAnonKey, jwtRole, redact } from "../src/secrets.js";

/** Build an unsigned JWT with the given role claim. */
function jwt(role: string): string {
  const b64 = (o: object) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ role, iss: "supabase" })}.c2lnbmF0dXJlX3BsYWNlaG9sZGVy`;
}

// ── The rule the whole tool depends on ──────────────────────────────
// A false positive on a security report is worse than a miss: tell
// someone their public anon key is a leak and they stop believing the
// rest of the report, including the parts that are real.

test("the Supabase anon key is NOT reported as a leak", () => {
  const bundle = `const supabase = createClient(url, "${jwt("anon")}")`;
  assert.deepEqual(findSecrets(bundle), []);
});

test("a service_role key IS reported", () => {
  const hits = findSecrets(`const admin = "${jwt("service_role")}"`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.name, "Supabase service_role key");
});

test("an unrelated JWT is not reported", () => {
  assert.deepEqual(findSecrets(`session=${jwt("authenticated")}`), []);
});

test("findAnonKey returns the anon key and ignores others", () => {
  const anon = jwt("anon");
  const bundle = `${jwt("service_role")} ... ${anon}`;
  assert.equal(findAnonKey(bundle), anon);
});

test("findAnonKey returns null when there is none", () => {
  assert.equal(findAnonKey("no tokens here"), null);
});

test("jwtRole survives malformed input instead of throwing", () => {
  for (const bad of ["", "a", "a.b", "a.b.c", "....", "eyJ.eyJ.eyJ"]) {
    assert.doesNotThrow(() => jwtRole(bad));
  }
});

// ── Provider keys ───────────────────────────────────────────────────

/**
 * Fixtures are assembled at runtime rather than written as literals.
 *
 * These are all fake, but they are shaped like the real thing, which is
 * the point. A key-shaped literal committed to the repo trips GitHub's
 * push protection and every scanner anyone else runs over their clone.
 * Joining the parts keeps the test honest without shipping the shape.
 */
const j = (...parts: string[]) => parts.join("");
const ALPHA = "abcdefghijklmnopqrstuvwxyz";

const REAL: [string, string][] = [
  ["OpenAI API key", j("sk", "-proj-", ALPHA, "0123456789")],
  ["Anthropic API key", j("sk", "-ant-", "api03-", ALPHA, "0123")],
  ["Stripe secret key", j("sk", "_live", "_", ALPHA, "0123456789")],
  ["AWS access key", j("AKIA", "IOSFODNN7EXAMPLE")],
  ["Google API key", j("AIza", "SyAbCdEfGhIjKlMnOpQrStUvWxYz0123456")],
  ["GitHub token", j("ghp", "_", ALPHA, "0123456789")],
  ["SendGrid API key", j("SG", ".", ALPHA.slice(0, 18), ".", ALPHA, "012345")],
];

for (const [name, key] of REAL) {
  test(`detects ${name}`, () => {
    const hits = findSecrets(`const k = "${key}";`);
    assert.equal(hits.length, 1, `expected one hit, got ${JSON.stringify(hits)}`);
    assert.equal(hits[0]?.name, name);
  });
}

test("detects a private key block", () => {
  const hits = findSecrets("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
  assert.equal(hits[0]?.name, "Private key file");
});

// ── Things that must NOT trip it ────────────────────────────────────

const INNOCENT = [
  `const publishable = "${j("pk", "_live", "_", ALPHA)}";`,   // Stripe publishable, must not trip
  'VITE_SUPABASE_URL="https://abcdefghijklmnopqrst.supabase.co"',
  "// sk- is the prefix OpenAI uses for keys",
  'className="sk-skeleton-loader"',
  "import { sk } from './locales/sk';",
  "const AKIAI = 'not a key';",
  "background: linear-gradient(90deg, #AIza00 0%, #fff 100%)",
];

for (const [i, src] of INNOCENT.entries()) {
  test(`no false positive on innocent source #${i + 1}`, () => {
    assert.deepEqual(findSecrets(src), [], `tripped on: ${src}`);
  });
}

test("the same key appearing twice is reported once", () => {
  const k = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
  assert.equal(findSecrets(`${k} and again ${k}`).length, 1);
});

// ── Redaction ───────────────────────────────────────────────────────

test("redact never returns the whole secret", () => {
  for (const s of ["short", "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"]) {
    const out = redact(s);
    assert.ok(!out.includes(s), `redact leaked the full value: ${out}`);
    assert.ok(out.length < s.length + 2);
  }
});

test("a redacted secret keeps enough to be identifiable", () => {
  const out = redact("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789");
  assert.ok(out.startsWith("sk-pro"));
  assert.ok(out.endsWith("6789"));
});
