import { test } from "node:test";
import assert from "node:assert/strict";
import { cookieCheck, tableCoverage } from "../src/extra-checks.js";

// ── Cookie flags ────────────────────────────────────────────────────
// Only cookies that plausibly carry a session are judged. Flagging a
// theme preference for missing HttpOnly is noise, and noise is how a
// report stops being read.

test("a session cookie with every flag passes", () => {
  assert.equal(
    cookieCheck(["sb-access-token=abc; Path=/; HttpOnly; Secure; SameSite=Lax"], true),
    null,
  );
});

test("a session cookie missing HttpOnly is reported", () => {
  const f = cookieCheck(["session=abc; Path=/; Secure; SameSite=Lax"], true);
  assert.ok(f);
  assert.match(f.evidence?.[0] ?? "", /HttpOnly/);
});

test("Secure is only required over https", () => {
  const cookie = ["auth_token=abc; Path=/; HttpOnly; SameSite=Lax"];
  assert.equal(cookieCheck(cookie, false), null, "demanded Secure on a plain http site");
  assert.ok(cookieCheck(cookie, true), "did not demand Secure on an https site");
});

test("a non-session cookie is ignored", () => {
  assert.equal(cookieCheck(["theme=dark; Path=/"], true), null);
  assert.equal(cookieCheck(["locale=en-GB; Path=/"], true), null);
});

test("no cookies at all is not a finding", () => {
  assert.equal(cookieCheck([], true), null);
});

test("several bad cookies are reported together, not one each", () => {
  const f = cookieCheck(
    ["sid=a; Path=/", "jwt=b; Path=/", "theme=dark; Path=/"],
    true,
  );
  assert.ok(f);
  assert.equal(f.evidence?.length, 2, "counted the theme cookie, or split the findings");
});

test("the cookie finding carries a usable fix prompt", () => {
  const f = cookieCheck(["session=abc; Path=/"], true);
  assert.ok(f);
  assert.ok(f.fixPrompt.length > 40);
  assert.equal(f.severity, "medium");
});

// ── Table probe coverage ────────────────────────────────────────────
// Reported by a reader: the probe stopped at 25 tables and said nothing
// about the rest, so a project with 40 could print "nothing found" and
// exit 0 in CI with 15 never asked.

test("a capped probe states what it covered", () => {
  const c = tableCoverage(40, 25);
  assert.equal(c.checked, 25);
  assert.equal(c.unchecked, 15);
  assert.equal(c.label, "checked 25 of 40 tables");
});

test("the uncovered tables are reported, not dropped", () => {
  const note = tableCoverage(40, 25).note;
  assert.ok(note, "15 unprobed tables were dropped silently");
  assert.match(note.reason, /15 of 40/);
  assert.match(note.reason, /--all-tables/);
});

test("nothing is flagged when every table was covered", () => {
  const c = tableCoverage(10, 25);
  assert.equal(c.checked, 10);
  assert.equal(c.unchecked, 0);
  assert.equal(c.note, null);
  assert.equal(c.label, "checked 10 of 10 tables");
});

test("lifting the cap covers everything", () => {
  const c = tableCoverage(400, Number.MAX_SAFE_INTEGER);
  assert.equal(c.unchecked, 0);
  assert.equal(c.note, null);
});

test("a schema with no tables is not described as partially covered", () => {
  assert.equal(tableCoverage(0, 25).note, null);
});
