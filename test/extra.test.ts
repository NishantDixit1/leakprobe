import { test } from "node:test";
import assert from "node:assert/strict";
import { cookieCheck } from "../src/extra-checks.js";

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
