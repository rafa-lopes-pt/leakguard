// `leakguard ignore` -- exempt files or directories from leakguard scans, via CLI.
// No hand-editing of config files required.
//
// Two scans use path-based config, and a path may need both:
//   - secret scan  -> .gitleaks.toml  [allowlist] paths   (regex, files OR dirs)
//   - filetype scan -> .security-filetypes [allowed-files] (exact path, files only)
//
// A FILE is added to both (so a blocked filetype like an auto-generated .svg is
// allowed AND skipped by the secret scanner). A DIRECTORY is added to gitleaks
// only -- [allowed-files] is exact-path per-file and cannot match a directory.

import { existsSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "./lib/rc.js";
import { ok, warn, error, skip, hint, info } from "./lib/ui.js";

const TOML_PATH = join(REPO_ROOT, ".gitleaks.toml");
const FILETYPES_PATH = join(REPO_ROOT, ".security-filetypes");
const MARKER = "# Added by leakguard ignore";

// The `paths = [ ... ]` block inside [allowlist].
const PATHS_BLOCK = /^(paths = \[\n)([\s\S]*?)(^\])/m;
// A single quoted gitleaks entry line: '''...'''
const ENTRY_LINE = /^\s*'''(.*)''',?\s*$/;

// ---------------------------------------------------------------------------
// Path classification
// ---------------------------------------------------------------------------

function cleanPath(input) {
  return input.replace(/^\.\//, "").replace(/\/+$/, "");
}

function isDirectory(input) {
  if (input.endsWith("/")) return true;
  const clean = cleanPath(input);
  try {
    return existsSync(join(REPO_ROOT, clean)) && statSync(join(REPO_ROOT, clean)).isDirectory();
  } catch {
    return false;
  }
}

// Convert a path into a gitleaks path regex: dirs get a trailing slash,
// files are anchored with $. Literal regex chars are escaped.
function toRegex(input) {
  const clean = cleanPath(input);
  const escaped = clean.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return isDirectory(input) ? `${escaped}/` : `${escaped}$`;
}

// ---------------------------------------------------------------------------
// gitleaks .gitleaks.toml
// ---------------------------------------------------------------------------

function readToml() {
  if (!existsSync(TOML_PATH)) {
    error("No .gitleaks.toml found in this repo.");
    hint("Run `leakguard init` first to set up the repo.");
    process.exit(1);
  }
  return readFileSync(TOML_PATH, "utf-8");
}

function matchPathsBlock(content) {
  const m = content.match(PATHS_BLOCK);
  if (!m) {
    error("Could not find a `paths = [ ... ]` block in .gitleaks.toml.");
    hint("Add an [allowlist] paths array, or run `leakguard init` to restore the template.");
    process.exit(1);
  }
  return m;
}

function parseGitleaksEntries(body) {
  return body
    .split("\n")
    .map((line) => (line.match(ENTRY_LINE) || [])[1])
    .filter((e) => e != null);
}

// Returns the regexes actually added.
function addGitleaks(regexes) {
  const content = readToml();
  const [, open, body, close] = matchPathsBlock(content);
  const existing = new Set(parseGitleaksEntries(body));

  const toAdd = regexes.filter((rx) => !existing.has(rx));
  if (toAdd.length === 0) return [];

  let newBody = body.endsWith("\n") ? body : body + "\n";
  const lines = [];
  if (!body.includes(MARKER)) lines.push(`    ${MARKER}`);
  for (const rx of toAdd) lines.push(`    '''${rx}''',`);
  newBody += lines.join("\n") + "\n";

  writeFileSync(TOML_PATH, content.replace(PATHS_BLOCK, () => open + newBody + close));
  return toAdd;
}

// Returns count removed.
function removeGitleaks(regexes) {
  const content = readToml();
  const [, open, body, close] = matchPathsBlock(content);
  const targets = new Set(regexes);

  let removed = 0;
  const newBody = body
    .split("\n")
    .filter((line) => {
      const m = line.match(ENTRY_LINE);
      if (m && targets.has(m[1])) {
        removed++;
        return false;
      }
      return true;
    })
    .join("\n");

  if (removed > 0) {
    writeFileSync(TOML_PATH, content.replace(PATHS_BLOCK, () => open + newBody + close));
  }
  return removed;
}

// ---------------------------------------------------------------------------
// filetype .security-filetypes [allowed-files]
// ---------------------------------------------------------------------------

function readFiletypesLines() {
  if (!existsSync(FILETYPES_PATH)) return null;
  return readFileSync(FILETYPES_PATH, "utf-8").split("\n");
}

// Range [start, end) of value lines under [allowed-files]; headerIdx is the
// header line index (-1 if section absent).
function allowedFilesRange(lines) {
  const headerIdx = lines.findIndex((l) => l.trim() === "[allowed-files]");
  if (headerIdx === -1) return { headerIdx, start: -1, end: -1, entries: new Set() };
  let end = lines.length;
  for (let i = headerIdx + 1; i < lines.length; i++) {
    if (/^\[.+]$/.test(lines[i].trim())) {
      end = i;
      break;
    }
  }
  const entries = new Set();
  for (let i = headerIdx + 1; i < end; i++) {
    const v = lines[i].replace(/#.*/, "").trim();
    if (v) entries.add(v);
  }
  return { headerIdx, start: headerIdx + 1, end, entries };
}

function parseAllowedFiles() {
  const lines = readFiletypesLines();
  if (!lines) return [];
  return [...allowedFilesRange(lines).entries];
}

// Returns the paths actually added (empty array if config missing).
function addAllowedFiles(paths) {
  const lines = readFiletypesLines();
  if (!lines) {
    warn("No .security-filetypes config found -- filetype exemption skipped.");
    return [];
  }
  const { headerIdx, end, entries } = allowedFilesRange(lines);
  const toAdd = paths.filter((p) => !entries.has(p));
  if (toAdd.length === 0) return [];

  if (headerIdx === -1) {
    while (lines.length && lines[lines.length - 1].trim() === "") lines.pop();
    lines.push("", "[allowed-files]", ...toAdd);
  } else {
    let insertAt = end;
    while (insertAt > headerIdx + 1 && lines[insertAt - 1].trim() === "") insertAt--;
    lines.splice(insertAt, 0, ...toAdd);
  }
  writeFileSync(FILETYPES_PATH, lines.join("\n").replace(/\n*$/, "\n"));
  return toAdd;
}

function removeAllowedFiles(paths) {
  const lines = readFiletypesLines();
  if (!lines) return 0;
  const { start, end } = allowedFilesRange(lines);
  if (start === -1) return 0;
  const targets = new Set(paths);

  let removed = 0;
  for (let i = end - 1; i >= start; i--) {
    const v = lines[i].replace(/#.*/, "").trim();
    if (v && targets.has(v)) {
      lines.splice(i, 1);
      removed++;
    }
  }
  if (removed > 0) writeFileSync(FILETYPES_PATH, lines.join("\n").replace(/\n*$/, "\n"));
  return removed;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function addIgnore(inputs) {
  for (const p of inputs) {
    if (!existsSync(join(REPO_ROOT, cleanPath(p)))) {
      warn(`Path not found in repo: ${p}  (added anyway -- check for typos)`);
    }
  }

  const files = [];
  const dirs = [];
  for (const p of inputs) {
    (isDirectory(p) ? dirs : files).push(cleanPath(p));
  }

  const addedGitleaks = addGitleaks(inputs.map(toRegex));
  const addedAllowed = addAllowedFiles(files);

  if (addedGitleaks.length === 0 && addedAllowed.length === 0) {
    skip("Everything was already ignored.");
    return;
  }

  for (const p of dirs) ok(`Ignored directory ${p}/  (secret scan)`);
  for (const p of files) {
    const inFt = addedAllowed.includes(p);
    ok(`Ignored file ${p}  (secret scan${inFt ? " + filetype" : ""})`);
  }
  hint("Commit .gitleaks.toml and .security-filetypes so your team shares the exemptions.");
}

export function removeIgnore(inputs) {
  const removed =
    removeGitleaks(inputs.map(toRegex)) +
    removeAllowedFiles(inputs.map(cleanPath));
  if (removed === 0) {
    warn("No matching ignore entries found.");
    hint("Use `leakguard ignore --list` to see current entries.");
    return;
  }
  ok(`Removed ${removed} ignore ${removed === 1 ? "entry" : "entries"}.`);
}

export function listIgnore() {
  const gitleaks = parseGitleaksEntries(matchPathsBlock(readToml())[2]);
  const allowed = parseAllowedFiles();

  info(`Secret-scan ignore paths -- .gitleaks.toml (${gitleaks.length}):`);
  if (gitleaks.length === 0) console.log("    (none)");
  for (const e of gitleaks) console.log(`    ${e}`);

  info(`Allowed files -- .security-filetypes (${allowed.length}):`);
  if (allowed.length === 0) console.log("    (none)");
  for (const e of allowed) console.log(`    ${e}`);
}
