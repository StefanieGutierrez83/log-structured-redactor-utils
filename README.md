# log-structured-redactor-utils

Walks structured log payloads (parsed objects) and masks values at configured JSON paths before emission.

## Usage

```js
import { redact, createRedactor } from "log-structured-redactor-utils";

const redactor = createRedactor({
  rules: [
    { path: "user.password", replacement: "[REDACTED]" },
    { path: "request.headers.authorization", replacement: "[REDACTED]" },
  ],
});

const log = {
  user: { password: "hunter2", name: "alice" },
  request: { headers: { authorization: "Bearer xyz" } },
};

console.log(redactor.redact(log));
// { user: { password: '[REDACTED]', name: 'alice' },
//   request: { headers: { authorization: '[REDACTED]' } } }
```

The default export-style convenience function `redact(payload, rules)` is also available for one-off use.

## Why

Structured logging systems emit objects that frequently carry secrets nested deep inside headers, session metadata, or credentials. Attempting to scrub these via regex against a serialized string is brittle: JSON escaping, key ordering, and numeric formatting all defeat naive string replacement. This library operates on the parsed object graph directly so it is immune to those serialization ambiguities.

The trade-off: the caller must parse the JSON before calling `redact`. This library intentionally does not parse or serialize — it works on objects and arrays only, so the caller controls the serialization format.

## Path syntax

A subset of JSONPath is supported, deliberately minimal to avoid ambiguity:

- Dot notation: `a.b.c`
- Numeric index segments: `items.0.name` or `items[0].name`
- Single-level wildcard `*` matching all values of an object or array: `users.*.token`

The wildcard `*` does NOT recurse into descendants. It matches immediate children only. A path like `a.*.b` matches `a.x.b` and `a.y.b` but will not match `a.x.y.b`. This is the single most common point of confusion: if you need deep recursion you must enumerate the keys explicitly.

The awkward edge: the wildcard `*` applies to a single segment. `users.*.token` redacts tokens under every key of `users`. It will not reach tokens nested two levels deeper.

## Convenience function

```js
import { redact } from "log-structured-redactor-utils";

redact({ a: { b: 1 } }, [{ path: "a.b", replacement: "###" }]);
// { a: { b: '###' } }
```

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

