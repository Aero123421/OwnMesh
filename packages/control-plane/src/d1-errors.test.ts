/**
 * D1 error classification fixtures for Issue #224 (C-1-2).
 *
 * The classifier must stay fail-closed: unrecognized messages (including
 * future Cloudflare wording changes) fall through to `unknown`, never to a
 * category that would hide a real outage or quota event.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { classifyD1Error } from "./d1-errors.ts";

test("classifyD1Error detects write-quota exhaustion", () => {
  assert.equal(classifyD1Error(new Error("D1_ERROR: rows written limit exceeded")), "quota_exceeded");
  assert.equal(classifyD1Error("Daily D1 write quota exceeded for account"), "quota_exceeded");
  assert.equal(classifyD1Error(new Error("Too many writes in this request")), "quota_exceeded");
  assert.equal(classifyD1Error({ message: "row limit reached" }), "quota_exceeded");
});

test("classifyD1Error detects transient contention", () => {
  assert.equal(classifyD1Error(new Error("SQLITE_BUSY: database is locked")), "transient_unavailable");
  assert.equal(classifyD1Error("database table is locked"), "transient_unavailable");
  assert.equal(classifyD1Error(new Error("D1_ERROR: request timed out")), "transient_unavailable");
});

test("classifyD1Error detects schema drift", () => {
  assert.equal(classifyD1Error(new Error("no such table: oauth_tokens")), "schema_missing");
  assert.equal(classifyD1Error("no such column: action_json"), "schema_missing");
});

test("classifyD1Error detects integrity conflicts", () => {
  assert.equal(
    classifyD1Error(new Error("UNIQUE constraint failed: oauth_tokens.refresh_token_hash")),
    "constraint_conflict",
  );
  assert.equal(classifyD1Error("FOREIGN KEY constraint failed"), "constraint_conflict");
});

test("classifyD1Error detects malformed statements", () => {
  assert.equal(classifyD1Error(new Error("syntax error near SELECT")), "invalid_query");
  assert.equal(classifyD1Error("datatype mismatch"), "invalid_query");
});

test("classifyD1Error is fail-closed on unknown input", () => {
  assert.equal(classifyD1Error(new Error("something entirely new from D1")), "unknown");
  assert.equal(classifyD1Error(""), "unknown");
  assert.equal(classifyD1Error(undefined), "unknown");
  assert.equal(classifyD1Error(null), "unknown");
  assert.equal(classifyD1Error(42), "unknown");
});
