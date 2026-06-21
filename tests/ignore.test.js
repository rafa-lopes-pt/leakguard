import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TOML_TEMPLATE = `title = "test"

[allowlist]
description = "test"
paths = [
    '''node_modules/''',
    '''dist/''',
]
`;

const FILETYPES_TEMPLATE = `[extensions]
.exe

[mime-types]
image/

[allowed-types]
application/x-7z-compressed

[allowed-files]
# docs/example.pdf
`;

describe("ignore", () => {
  let tmpDir, origCwd;
  let addIgnore, removeIgnore;
  const tomlPath = () => join(tmpDir, ".gitleaks.toml");
  const ftPath = () => join(tmpDir, ".security-filetypes");
  const toml = () => readFileSync(tomlPath(), "utf-8");
  const ft = () => readFileSync(ftPath(), "utf-8");

  before(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "leakguard-ignore-test-"));
    origCwd = process.cwd();
    process.chdir(tmpDir);
    // Dynamic import so REPO_ROOT (and the config paths derived from it) pick up tmpDir
    const mod = await import("../scripts/ignore.js");
    addIgnore = mod.addIgnore;
    removeIgnore = mod.removeIgnore;
  });

  after(() => {
    process.chdir(origCwd);
    rmSync(tmpDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    writeFileSync(tomlPath(), TOML_TEMPLATE);
    writeFileSync(ftPath(), FILETYPES_TEMPLATE);
    // create a real dir so directory detection works without a trailing slash
    mkdirSync(join(tmpDir, "generated"), { recursive: true });
  });

  it("adds a file to both gitleaks paths and allowed-files", () => {
    addIgnore(["docs/deps.svg"]);
    assert.match(toml(), /'''docs\/deps\\\.svg\$'''/);
    assert.match(ft(), /^docs\/deps\.svg$/m);
  });

  it("adds a directory to gitleaks only (not allowed-files)", () => {
    addIgnore(["generated"]);
    assert.match(toml(), /'''generated\/'''/);
    assert.doesNotMatch(ft(), /^generated/m);
  });

  it("treats a trailing-slash path as a directory even if it does not exist", () => {
    addIgnore(["nope/"]);
    assert.match(toml(), /'''nope\/'''/);
    assert.doesNotMatch(ft(), /nope/);
  });

  it("escapes regex metacharacters in file paths", () => {
    addIgnore(["a+b/c.d.txt"]);
    assert.match(toml(), /'''a\\\+b\/c\\\.d\\\.txt\$'''/);
    // allowed-files stores the literal path, unescaped
    assert.match(ft(), /^a\+b\/c\.d\.txt$/m);
  });

  it("does not duplicate existing entries", () => {
    addIgnore(["docs/deps.svg"]);
    addIgnore(["docs/deps.svg"]);
    const tomlMatches = toml().match(/docs\/deps/g) || [];
    const ftMatches = ft().match(/docs\/deps/g) || [];
    assert.equal(tomlMatches.length, 1);
    assert.equal(ftMatches.length, 1);
  });

  it("adds the marker comment once", () => {
    addIgnore(["a.svg"]);
    addIgnore(["b.svg"]);
    const markers = (toml().match(/Added by leakguard ignore/g) || []).length;
    assert.equal(markers, 1);
  });

  it("removes a file from both configs", () => {
    addIgnore(["docs/deps.svg"]);
    removeIgnore(["docs/deps.svg"]);
    assert.doesNotMatch(toml(), /docs\/deps/);
    assert.doesNotMatch(ft(), /docs\/deps/);
  });

  it("removes a directory from gitleaks", () => {
    addIgnore(["generated"]);
    removeIgnore(["generated"]);
    assert.doesNotMatch(toml(), /'''generated\/'''/);
  });

  it("preserves pre-existing entries when adding and removing", () => {
    addIgnore(["docs/deps.svg"]);
    removeIgnore(["docs/deps.svg"]);
    assert.match(toml(), /'''node_modules\/'''/);
    assert.match(toml(), /'''dist\/'''/);
  });

  it("keeps the toml paths block well-formed after edits", () => {
    addIgnore(["x.svg", "y/"]);
    // still a single closing bracket on its own line
    assert.match(toml(), /^]/m);
    assert.match(toml(), /paths = \[/);
  });
});
