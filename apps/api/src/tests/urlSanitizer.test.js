import test from "node:test";
import assert from "node:assert/strict";
import { isSafeUrl, sanitizeUrl, isPrivateHostname } from "../utils/urlSanitizer.js";

test("valid public URLs pass validation", () => {
  assert.equal(isSafeUrl("https://freelanceflow.dev/profiles/dev1"), true);
  assert.equal(isSafeUrl("http://example.com/portfolio?sort=asc"), true);
  assert.equal(sanitizeUrl("https://example.com/project"), "https://example.com/project");
});

test("dangerous script pseudo-protocols are rejected", () => {
  assert.equal(isSafeUrl("javascript:alert(1)"), false);
  assert.equal(isSafeUrl("JAVASCRIPT:alert('xss')"), false);
  assert.equal(isSafeUrl("data:text/html,<script>alert(1)</script>"), false);
  assert.equal(isSafeUrl("file:///etc/passwd"), false);
  assert.equal(isSafeUrl("vbscript:msgbox(1)"), false);
  assert.equal(sanitizeUrl("javascript:void(0)", "https://default.com"), "https://default.com");
});

test("SSRF and private / loopback IP ranges are rejected", () => {
  assert.equal(isSafeUrl("http://127.0.0.1:3000/api"), false);
  assert.equal(isSafeUrl("http://localhost:8080"), false);
  assert.equal(isSafeUrl("http://169.254.169.254/latest/meta-data/"), false);
  assert.equal(isSafeUrl("http://10.0.0.1"), false);
  assert.equal(isSafeUrl("http://172.16.0.1"), false);
  assert.equal(isSafeUrl("http://192.168.1.1"), false);
  assert.equal(isSafeUrl("http://[::1]:8080"), false);
});

test("CRLF injection is rejected", () => {
  assert.equal(isSafeUrl("https://example.com\r\nSet-Cookie:admin=1"), false);
  assert.equal(isSafeUrl("https://example.com\nLocation:evil.com"), false);
});

test("malformed URLs and null inputs return fallback safely", () => {
  assert.equal(isSafeUrl(""), false);
  assert.equal(isSafeUrl(null), false);
  assert.equal(isSafeUrl("not a valid url"), false);
  assert.equal(sanitizeUrl("invalid", null), null);
});
