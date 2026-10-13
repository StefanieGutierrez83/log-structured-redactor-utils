import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parsePath,
  redactWithRules,
  createRedactor,
} from "../src/core.js";

test("parsePath: simple dot path", () => {
  assert.deepEqual(parsePath("a.b.c"), [
    { kind: "key", value: "a" },
    { kind: "key", value: "b" },
    { kind: "key", value: "c" },
  ]);
});

test("parsePath: numeric index in dot form", () => {
  assert.deepEqual(parsePath("items.0.name"), [
    { kind: "key", value: "items" },
    { kind: "index", value: 0 },
    { kind: "key", value: "name" },
  ]);
});

test("parsePath: bracket index form", () => {
  assert.deepEqual(parsePath("items[0].name"), [
    { kind: "key", value: "items" },
    { kind: "index", value: 0 },
    { kind: "key", value: "name" },
  ]);
});

test("parsePath: wildcard segment", () => {
  assert.deepEqual(parsePath("users.*.token"), [
    { kind: "key", value: "users" },
    { kind: "wildcard" },
    { kind: "key", value: "token" },
  ]);
});

test("redact: replaces a simple nested value", () => {
  const out = redactWithRules(
    { user: { password: "hunter2", name: "alice" } },
    [{ path: "user.password", replacement: "###" }],
  );
  assert.deepEqual(out, { user: { password: "###", name: "alice" } });
});

test("redact: does not mutate the input", () => {
  const input = { a: { b: 1 } };
  redactWithRules(input, [{ path: "a.b", replacement: "###" }]);
  assert.equal(input.a.b, 1);
});

test("redact: wildcard matches all object children", () => {
  const out = redactWithRules(
    { users: { u1: { token: "t1" }, u2: { token: "t2" } } },
    [{ path: "users.*.token", replacement: "[MASK]" }],
  );
  assert.deepEqual(out, {
    users: { u1: { token: "[MASK]" }, u2: { token: "[MASK]" } },
  });
});

test("redact: wildcard matches all array elements", () => {
  const out = redactWithRules(
    { items: [{ id: 1, secret: "x" }, { id: 2, secret: "y" }] },
    [{ path: "items.*.secret", replacement: "[MASK]" }],
  );
  assert.deepEqual(out, {
    items: [
      { id: 1, secret: "[MASK]" },
      { id: 2, secret: "[MASK]" },
    ],
  });
});

test("redact: index segment targets a specific array element", () => {
  const out = redactWithRules(
    { items: [{ s: "a" }, { s: "b" }, { s: "c" }] },
    [{ path: "items.1.s", replacement: "###" }],
  );
  assert.deepEqual(out, {
    items: [{ s: "a" }, { s: "###" }, { s: "c" }],
  });
});

test("redact: missing key leaves payload unchanged", () => {
  const input = { a: { b: 1 } };
  const out = redactWithRules(input, [
    { path: "a.nonexistent", replacement: "###" },
  ]);
  assert.deepEqual(out, input);
});

test("redact: key segment against an array does not match", () => {
  const input = { items: [{ s: "a" }] };
  const out = redactWithRules(input, [
    { path: "items.s", replacement: "###" },
  ]);
  assert.deepEqual(out, input);
});

test("redact: replacement defaults to [REDACTED]", () => {
  const out = redactWithRules({ a: { b: 1 } }, [{ path: "a.b" }]);
  assert.deepEqual(out, { a: { b: "[REDACTED]" } });
});

test("redact: terminal replacement replaces entire value", () => {
  const out = redactWithRules(
    { headers: { auth: { scheme: "Bearer", token: "xyz" } } },
    [{ path: "headers.auth", replacement: "[REDACTED]" }],
  );
  assert.deepEqual(out, { headers: { auth: "[REDACTED]" } });
});

test("createRedactor: reusable instance", () => {
  const r = createRedactor({
    rules: [{ path: "password", replacement: "###" }],
  });
  const out = r.redact({ password: "hunter2", user: "alice" });
  assert.deepEqual(out, { password: "###", user: "alice" });
});

test("createRedactor: empty rules returns the input unchanged", () => {
  const r = createRedactor({ rules: [] });
  const input = { a: 1 };
  assert.equal(r.redact(input), input);
});
