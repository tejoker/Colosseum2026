"use client";

// Lightweight client-side policy validator.
//
// Why hand-rolled (no `@apidevtools/json-schema-ref-parser`, no `ajv`):
// - Authoritative validation is the server's job (`POST /v1/policy/upload`
//   parses + compiles and surfaces structured errors). This widget is just
//   a fast pre-flight so users see obvious mistakes before round-tripping.
// - Adding a real JSON-schema validator pulls ~200 KB into the client bundle
//   for what is at most a sanity check.
// - The full grammar lives in `schemas/policy.schema.json` — kept in sync
//   with the Rust side. We mirror only the load-bearing constraints here.
//
// Upgrade path: swap `validatePolicyText` with an `ajv`-backed validator
// loaded dynamically (`await import("ajv")`) when the editor mounts.

import { useMemo } from "react";

export interface ValidationIssue {
  severity: "error" | "warning";
  message: string;
  /** 1-based line number (best-effort; 0 means no specific line). */
  line: number;
}

export interface ValidationResult {
  issues: ValidationIssue[];
  /** Parsed object (if YAML/JSON parsing succeeded) — for downstream use. */
  parsed?: Record<string, unknown>;
}

// ── Minimal YAML → JS object parser ────────────────────────────────────
// Full YAML 1.2 is out of scope. We accept the subset the fixtures use:
//   - top-level mappings
//   - nested mappings (2-space indented)
//   - flow sequences `[a, b, c]` and block sequences (`- item`)
//   - scalars: strings (quoted or bare), numbers, booleans
// On failure we fall back to "could not parse YAML" instead of throwing.

function tinyYamlParse(text: string): Record<string, unknown> | null {
  // Try JSON first — it's a strict subset and we accept either.
  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      // Fall through to YAML.
    }
  }

  // Strip comments (a `#` outside a quoted string up to EOL).
  const lines = text.split("\n").map(stripComment);

  // A frame is an "open" container being filled at a known indent.
  // `pendingKey` is the key in the parent waiting for content (either
  // an object child or an array child — decided by the first child line).
  type Frame = {
    indent: number;
    container: Record<string, unknown> | unknown[];
    /** Set when this container itself is the value of a key in some parent;
     * if the first child line is a sequence item, we replace the placeholder
     * with an array. */
    parent?: Record<string, unknown> | unknown[];
    parentKey?: string | number; // numeric for arrays (inserting at idx)
    /** True if we still need to commit the placeholder to its parent. */
    placeholder?: boolean;
  };

  const root: Record<string, unknown> = {};
  const stack: Frame[] = [{ indent: -1, container: root }];
  let folding: { indent: number; key: string; parent: Record<string, unknown>; buf: string[] } | null = null;

  function top(): Frame {
    return stack[stack.length - 1];
  }

  /** Commit a placeholder frame's container into its parent if not yet. */
  function commitPlaceholder(frame: Frame): void {
    if (!frame.placeholder) return;
    if (frame.parent === undefined || frame.parentKey === undefined) {
      frame.placeholder = false;
      return;
    }
    if (Array.isArray(frame.parent)) {
      frame.parent[frame.parentKey as number] = frame.container;
    } else {
      (frame.parent as Record<string, unknown>)[frame.parentKey as string] =
        frame.container;
    }
    frame.placeholder = false;
  }

  /** Convert the current top frame's container to an array (called when the
   * first child line is a sequence item and the placeholder was an object). */
  function promoteTopToArray(): unknown[] {
    const f = top();
    if (Array.isArray(f.container)) return f.container;
    const arr: unknown[] = [];
    f.container = arr;
    if (f.placeholder && f.parent !== undefined && f.parentKey !== undefined) {
      if (Array.isArray(f.parent)) {
        f.parent[f.parentKey as number] = arr;
      } else {
        (f.parent as Record<string, unknown>)[f.parentKey as string] = arr;
      }
      f.placeholder = false;
    }
    return arr;
  }

  for (const rawLine of lines) {
    if (folding) {
      const m = /^(\s*)(\S.*)$/.exec(rawLine);
      if (!m || (m[1].length <= folding.indent && rawLine.trim() !== "")) {
        (folding.parent as Record<string, unknown>)[folding.key] = folding.buf.join(" ").trim();
        folding = null;
        // fall through to re-process this line
      } else if (rawLine.trim() === "") {
        continue;
      } else {
        folding.buf.push(rawLine.trim());
        continue;
      }
    }

    if (rawLine.trim() === "") continue;
    const indentMatch = /^(\s*)(.*)$/.exec(rawLine);
    if (!indentMatch) continue;
    const indent = indentMatch[1].length;
    const content = indentMatch[2];

    // Pop frames whose indent is >= current indent (we've left them).
    while (stack.length > 1 && indent <= top().indent) {
      // Closing the frame: commit its placeholder (object placeholder stays an object).
      commitPlaceholder(top());
      stack.pop();
    }

    // Block sequence item: `- value` or `- key: value`
    if (content.startsWith("- ") || content === "-") {
      // The top container must be (or become) an array.
      const arr = promoteTopToArray();
      const itemText = content.slice(2).trim();
      const colonIdx = findColon(itemText);
      if (colonIdx >= 0) {
        // `- key: value` (sequence of mappings)
        const obj: Record<string, unknown> = {};
        const k = itemText.slice(0, colonIdx).trim();
        const v = itemText.slice(colonIdx + 1).trim();
        const idx = arr.length;
        arr.push(obj);
        if (v !== "") {
          obj[k] = parseScalar(v);
          // Next nested key will need a child frame; push a frame for the seq item.
          stack.push({ indent, container: obj });
        } else {
          // Need a child placeholder for `k`.
          stack.push({ indent, container: obj });
          stack.push({
            indent: indent + 1, // arbitrary > indent; will be overridden by first child indent
            container: {},
            parent: obj,
            parentKey: k,
            placeholder: true,
          });
        }
        void idx;
      } else if (itemText === "") {
        const obj: Record<string, unknown> = {};
        arr.push(obj);
        stack.push({ indent, container: obj });
      } else {
        arr.push(parseScalar(itemText));
      }
      continue;
    }

    // Mapping entry: `key: value`
    const colonIdx = findColon(content);
    if (colonIdx < 0) {
      return null;
    }

    // Now we're adding a key to the top frame's container. If that container
    // is currently a placeholder (waiting to become an array OR object), commit
    // it as an object now.
    const f = top();
    if (Array.isArray(f.container)) {
      // Can't add a key to an array — must be at wrong indent. Soft-fail.
      return null;
    }
    commitPlaceholder(f);

    const key = content.slice(0, colonIdx).trim();
    const valueRaw = content.slice(colonIdx + 1).trim();

    if (valueRaw === "") {
      // Nested block follows. Push a placeholder frame; first child decides
      // whether it becomes an object or an array.
      const obj: Record<string, unknown> = {};
      stack.push({
        indent,
        container: obj,
        parent: f.container,
        parentKey: key,
        placeholder: true,
      });
    } else if (valueRaw === ">" || valueRaw === "|" || valueRaw === ">-" || valueRaw === "|-") {
      folding = {
        indent,
        key,
        parent: f.container as Record<string, unknown>,
        buf: [],
      };
      (f.container as Record<string, unknown>)[key] = "";
    } else {
      (f.container as Record<string, unknown>)[key] = parseScalar(valueRaw);
    }
  }

  // Commit any leftover placeholders.
  while (stack.length > 1) {
    commitPlaceholder(top());
    stack.pop();
  }

  if (folding) {
    (folding.parent as Record<string, unknown>)[folding.key] = folding.buf.join(" ").trim();
  }

  return root;
}

function stripComment(line: string): string {
  // Naively strip `#` not inside quotes.
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "#" && !inSingle && !inDouble) {
      return line.slice(0, i);
    }
  }
  return line;
}

function findColon(s: string): number {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === ":" && !inSingle && !inDouble) {
      // YAML colon must be followed by whitespace or EOL to count as mapping.
      if (i === s.length - 1 || /\s/.test(s[i + 1])) return i;
    }
  }
  return -1;
}

function parseScalar(s: string): unknown {
  // Flow sequence `[a, b, c]` — naive split (no nested flow).
  if (s.startsWith("[") && s.endsWith("]")) {
    const inner = s.slice(1, -1).trim();
    if (inner === "") return [];
    return inner.split(",").map((p) => parseScalar(p.trim()));
  }
  // Quoted strings.
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  if (s === "true") return true;
  if (s === "false") return false;
  if (s === "null" || s === "~") return null;
  // Numbers (no exponent for simplicity).
  if (/^-?\d+$/.test(s)) return parseInt(s, 10);
  if (/^-?\d+\.\d+$/.test(s)) return parseFloat(s);
  return s;
}

// ── Schema-shape checks ───────────────────────────────────────────────

export function validatePolicyText(text: string): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (text.trim() === "") {
    return { issues: [{ severity: "error", message: "Policy is empty.", line: 0 }] };
  }
  const parsed = tinyYamlParse(text);
  if (!parsed) {
    return {
      issues: [
        {
          severity: "error",
          message: "Could not parse YAML/JSON. Server-side validation will give a precise error on upload.",
          line: 0,
        },
      ],
    };
  }
  if (typeof parsed !== "object" || Array.isArray(parsed)) {
    issues.push({
      severity: "error",
      message: "Policy root must be a mapping.",
      line: 0,
    });
    return { issues, parsed: undefined };
  }
  const lineOf = (key: string): number => findLineForKey(text, key);

  if (!("version" in parsed)) {
    issues.push({
      severity: "error",
      message: 'Missing required field: "version".',
      line: 0,
    });
  } else if (parsed.version !== "1") {
    issues.push({
      severity: "error",
      message: 'Field "version" must be the string "1".',
      line: lineOf("version"),
    });
  }

  if (!("agent" in parsed)) {
    issues.push({
      severity: "error",
      message: 'Missing required field: "agent".',
      line: 0,
    });
  } else if (typeof parsed.agent !== "string" || (parsed.agent as string).trim() === "") {
    issues.push({
      severity: "error",
      message: 'Field "agent" must be a non-empty string.',
      line: lineOf("agent"),
    });
  }

  if ("description" in parsed && typeof parsed.description !== "string") {
    issues.push({
      severity: "error",
      message: 'Field "description" must be a string.',
      line: lineOf("description"),
    });
  }

  if ("invariants" in parsed) {
    const inv = parsed.invariants;
    if (!Array.isArray(inv)) {
      issues.push({
        severity: "error",
        message: 'Field "invariants" must be an array of strings.',
        line: lineOf("invariants"),
      });
    } else {
      inv.forEach((entry, idx) => {
        if (typeof entry !== "string") {
          issues.push({
            severity: "error",
            message: `invariants[${idx}] must be a string.`,
            line: lineOf("invariants"),
          });
        }
      });
    }
  }

  if ("binding" in parsed) {
    const b = parsed.binding;
    if (typeof b !== "object" || b === null || Array.isArray(b)) {
      issues.push({
        severity: "error",
        message: 'Field "binding" must be an object.',
        line: lineOf("binding"),
      });
    } else {
      const binding = b as Record<string, unknown>;
      if ("max_budget_usd" in binding && typeof binding.max_budget_usd !== "number") {
        issues.push({
          severity: "error",
          message: 'binding.max_budget_usd must be a number.',
          line: lineOf("max_budget_usd"),
        });
      }
      if ("allowed_tools" in binding && !Array.isArray(binding.allowed_tools)) {
        issues.push({
          severity: "error",
          message: 'binding.allowed_tools must be an array.',
          line: lineOf("allowed_tools"),
        });
      }
      if ("rate_limit" in binding) {
        const r = binding.rate_limit as Record<string, unknown> | null | undefined;
        if (r && typeof r === "object") {
          if (typeof r.requests_per_minute !== "number" || (r.requests_per_minute as number) < 1) {
            issues.push({
              severity: "error",
              message: 'binding.rate_limit.requests_per_minute must be a positive integer.',
              line: lineOf("requests_per_minute"),
            });
          }
        }
      }
      if ("time_window" in binding) {
        const tw = binding.time_window as Record<string, unknown> | null | undefined;
        if (tw && typeof tw === "object") {
          const hhmm = /^(?:[01][0-9]|2[0-3]):[0-5][0-9]$/;
          if (typeof tw.start !== "string" || !hhmm.test(tw.start as string)) {
            issues.push({
              severity: "error",
              message: 'binding.time_window.start must be HH:MM (24h).',
              line: lineOf("start"),
            });
          }
          if (typeof tw.end !== "string" || !hhmm.test(tw.end as string)) {
            issues.push({
              severity: "error",
              message: 'binding.time_window.end must be HH:MM (24h).',
              line: lineOf("end"),
            });
          }
          if (typeof tw.timezone !== "string" || (tw.timezone as string).trim() === "") {
            issues.push({
              severity: "error",
              message: 'binding.time_window.timezone must be a non-empty IANA tz.',
              line: lineOf("timezone"),
            });
          }
        }
      }
    }
  }

  return { issues, parsed };
}

function findLineForKey(text: string, key: string): number {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:/.exec(lines[i]);
    if (m && m[1] === key) return i + 1;
  }
  return 0;
}

interface PolicyValidatorProps {
  text: string;
}

export function PolicyValidator({ text }: PolicyValidatorProps) {
  const result = useMemo(() => validatePolicyText(text), [text]);
  const errors = result.issues.filter((i) => i.severity === "error");
  const warnings = result.issues.filter((i) => i.severity === "warning");
  if (errors.length === 0 && warnings.length === 0) {
    return (
      <p className="text-mono-sm text-[var(--status-ok)]">
        Pre-flight checks pass. Server will run authoritative validation on upload.
      </p>
    );
  }
  return (
    <ul className="space-y-1 text-mono-sm">
      {errors.map((e, i) => (
        <li key={`e-${i}`} className="text-[var(--status-stopped)]">
          {e.line > 0 ? `line ${e.line}: ` : ""}
          {e.message}
        </li>
      ))}
      {warnings.map((w, i) => (
        <li key={`w-${i}`} className="text-[var(--status-warning)]">
          {w.line > 0 ? `line ${w.line}: ` : ""}
          {w.message}
        </li>
      ))}
    </ul>
  );
}
