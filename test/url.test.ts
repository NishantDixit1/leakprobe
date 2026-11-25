import { test } from "node:test";
import assert from "node:assert/strict";
import { parseTarget } from "../src/fetch.js";

test("a bare hostname is upgraded to https", () => {
  const r = parseTarget("example.com");
  assert.ok(r.ok);
  assert.equal(r.url.toString(), "https://example.com/");
});

test("an explicit scheme is kept", () => {
  const r = parseTarget("http://example.com/app");
  assert.ok(r.ok);
  assert.equal(r.url.protocol, "http:");
});

test("non-web schemes are refused", () => {
  for (const bad of ["file:///etc/passwd", "ftp://example.com", "javascript:alert(1)"]) {
    const r = parseTarget(bad);
    assert.equal(r.ok, false, `accepted ${bad}`);
  }
});

test("nonsense is refused rather than throwing", () => {
  assert.equal(parseTarget("http://").ok, false);
  assert.equal(parseTarget(" ").ok, false);
});
