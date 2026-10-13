/**
 * Path parsing and redaction logic for structured log payloads.
 *
 * Supported path syntax (deliberately minimal to avoid ambiguity):
 *   - Dot notation:        a.b.c
 *   - Numeric index:       items.0.name  OR  items[0].name
 *   - Single-level wildcard:  users.*.token
 *
 * The wildcard '*' matches immediate children of an object or array only.
 * It does NOT recurse into descendants. This restriction is intentional:
 * a deep-recursive wildcard creates surprising, hard-to-audit redaction
 * behaviour in security-sensitive code, so we force the caller to be
 * explicit about depth.
 */

/**
 * Parse a path expression into an ordered array of segment descriptors.
 *
 * Each segment is either:
 *   { kind: 'key', value: string }    — a literal property key
 *   { kind: 'index', value: number }  — an array index
 *   { kind: 'wildcard' }              — matches all immediate children
 *
 * Whitespace is trimmed from dot-separated segments so 'a . b' parses the
 * same as 'a.b'. This is a convenience for hand-written config files; it is
 * documented in the README so callers are not surprised.
 *
 * @param {string} path
 * @returns {Array<{kind:'key',value:string}|{kind:'index',value:number}|{kind:'wildcard'}>}
 */
export function parsePath(path) {
  if (typeof path !== "string" || path.length === 0) {
    return [];
  }

  const segments = [];
  let i = 0;
  const n = path.length;

  while (i < n) {
    if (path[i] === ".") {
      // Leading/consecutive dots are silently skipped. An empty segment
      // carries no information and rejecting it would surprise users who
      // accidentally write 'a..b'.
      i += 1;
      continue;
    }

    if (path[i] === "[") {
      // Bracket index form: [123]
      let end = path.indexOf("]", i + 1);
      if (end === -1) {
        // Unterminated bracket — treat the remainder of the string as a
        // literal key. This avoids throwing on malformed config; the path
        // simply will not match anything unexpected.
        const rest = path.slice(i);
        segments.push({ kind: "key", value: rest });
        break;
      }
      const inner = path.slice(i + 1, end).trim();
      if (inner === "*") {
        segments.push({ kind: "wildcard" });
      } else if (/^-?\d+$/.test(inner)) {
        segments.push({ kind: "index", value: Number(inner) });
      } else {
        // Quoted or bare bracketed key, e.g. [foo] or ["foo"]. Strip one
        // layer of surrounding quotes if present.
        let key = inner;
        if (
          (key.startsWith('"') && key.endsWith('"')) ||
          (key.startsWith("'") && key.endsWith("'"))
        ) {
          key = key.slice(1, -1);
        }
        segments.push({ kind: "key", value: key });
      }
      i = end + 1;
      continue;
    }

    // Dot-form segment: read until next '.' or '['.
    let j = i;
    while (j < n && path[j] !== "." && path[j] !== "[") {
      j += 1;
    }
    const raw = path.slice(i, j).trim();
    if (raw === "") {
      i = j;
      continue;
    }
    if (raw === "*") {
      segments.push({ kind: "wildcard" });
    } else if (/^-?\d+$/.test(raw)) {
      // A bare numeric segment is treated as an array index. This mirrors
      // the common shorthand 'items.0.name'.
      segments.push({ kind: "index", value: Number(raw) });
    } else {
      segments.push({ kind: "key", value: raw });
    }
    i = j;
  }

  return segments;
}

/**
 * Apply redaction to a (shallow-cloned) value, returning the masked result.
 *
 * We shallow-clone objects and arrays at each level so the original payload
 * is never mutated. Deep cloning the entire input would be wasteful when
 * only a few paths are redacted, so we clone lazily: only branches that
 * contain a match are copied.
 *
 * @param {*} value
 * @param {Array} segments - parsed path segments
 * @param {string} replacement
 * @returns {*}
 */
function applySegments(value, segments, replacement) {
  if (segments.length === 0) {
    // Terminal: this position matched the full path. Replace the value
    // entirely, regardless of its type. Replacing objects/arrays with the
    // replacement string is intentional — a matched path means the caller
    // wants the whole thing gone.
    return replacement;
  }

  const [head, ...rest] = segments;

  if (Array.isArray(value)) {
    let changed = false;
    const next = new Array(value.length);

    if (head.kind === "wildcard") {
      for (let k = 0; k < value.length; k++) {
        const redacted = applySegments(value[k], rest, replacement);
        next[k] = redacted;
        if (redacted !== value[k]) changed = true;
      }
    } else if (head.kind === "index") {
      for (let k = 0; k < value.length; k++) {
        if (k === head.value) {
          const redacted = applySegments(value[k], rest, replacement);
          next[k] = redacted;
          if (redacted !== value[k]) changed = true;
        } else {
          next[k] = value[k];
        }
      }
    } else {
      // 'key' segment against an array: no match possible. Return original.
      return value;
    }

    return changed ? next : value;
  }

  if (value !== null && typeof value === "object") {
    let changed = false;
    const next = {};

    if (head.kind === "wildcard") {
      for (const key of Object.keys(value)) {
        const redacted = applySegments(value[key], rest, replacement);
        next[key] = redacted;
        if (redacted !== value[key]) changed = true;
      }
    } else if (head.kind === "key") {
      for (const key of Object.keys(value)) {
        if (key === head.value) {
          const redacted = applySegments(value[key], rest, replacement);
          next[key] = redacted;
          if (redacted !== value[key]) changed = true;
        } else {
          next[key] = value[key];
        }
      }
    } else {
      // 'index' segment against a plain object: objects keyed by strings
      // cannot have integer-indexed segments in this model. We DO NOT
      // fall back to string-coercion matching (e.g. key "0") because that
      // would create ambiguity: 'items.0' would then match both
      // arrays[0] and objects{"0":...}. Explicit is safer.
      return value;
    }

    return changed ? next : value;
  }

  // Primitives (string/number/boolean/null/undefined) at a non-terminal
  // position: the path cannot descend further, so nothing matches.
  return value;
}

/**
 * Convenience: redact a payload against an array of rules.
 *
 * @param {*} payload
 * @param {Array<{path:string, replacement:string}>} rules
 * @returns {*} a redacted copy (the input is never mutated)
 */
export function redactWithRules(payload, rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    return payload;
  }
  let result = payload;
  for (const rule of rules) {
    if (!rule || typeof rule.path !== "string") continue;
    const replacement =
      rule.replacement === undefined ? "[REDACTED]" : rule.replacement;
    const segments = parsePath(rule.path);
    if (segments.length === 0) continue;
    result = applySegments(result, segments, replacement);
  }
  return result;
}

/**
 * Build a reusable redactor bound to a fixed rule set.
 *
 * @param {{rules: Array<{path:string, replacement:string}>}} options
 * @returns {{redact: function(*): *}}
 */
export function createRedactor(options) {
  const opts = options || {};
  const rules = Array.isArray(opts.rules) ? opts.rules : [];
  return {
    redact(payload) {
      return redactWithRules(payload, rules);
    },
  };
}
