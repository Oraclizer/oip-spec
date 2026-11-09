// SPDX-License-Identifier: Apache-2.0
//
// Repository health checks for the public surface of oip-spec. Adapted from the
// repository health checker of Oraclizer/formal-verification.
//
// Usage: node .github/scripts/verify-repository-health.mjs [--visibility public|private]
//
// Without --visibility the public rules apply. Under the private rules, the
// known findings in pendingFindings and the publication marker are reported as
// notices, and every workflow job must be skipped on a private repository.
// Under the public rules those findings fail, and the Dependabot configuration
// is required.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, extname, posix, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const failures = [];
const notices = [];

let visibility = "public";
const args = process.argv.slice(2);
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--visibility" && index + 1 < args.length) {
    visibility = args[index + 1];
    index += 1;
  } else {
    console.error(`unknown argument: ${args[index]}`);
    process.exit(2);
  }
}
if (visibility !== "public" && visibility !== "private") {
  console.error(`--visibility must be public or private, not ${JSON.stringify(visibility)}`);
  process.exit(2);
}
const strict = visibility === "public";

// This file holds the scan patterns, so it is excluded from the content scans.
const scannerFiles = new Set([".github/scripts/verify-repository-health.mjs"]);

const required = [
  "LICENSE",
  "go/LICENSE",
  "README.md",
  "CHANGELOG.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "CODE_OF_CONDUCT.md",
  "SUPPORT.md",
  "GOVERNANCE.md",
  "DISCLAIMER.md",
  "CITATION.cff",
  ".github/CODEOWNERS",
  ".github/PULL_REQUEST_TEMPLATE.md",
  ".github/ISSUE_TEMPLATE/config.yml",
  ".github/ISSUE_TEMPLATE/bug.yml",
  ".github/ISSUE_TEMPLATE/specification.yml",
  ".github/ISSUE_TEMPLATE/documentation.yml",
  ".github/workflows/repository-health.yml",
  ".github/workflows/tests.yml",
  "docs/assets/oip-spec-banner.svg",
  "docs/assets/oip-spec-banner-mobile.svg",
  "docs/assets/architecture-overview.svg",
  "docs/assets/architecture-overview-mobile.svg",
  "docs/assets/verification-architecture.svg",
  "docs/assets/verification-architecture-mobile.svg",
  "Cargo.toml",
  "Cargo.lock",
  "go/go.mod",
  "go/go.sum",
];
// A private copy has no Dependabot configuration, because update pull requests
// would accumulate there without review.
if (strict) required.push(".github/dependabot.yml");

const textExtensions = new Set([
  ".cff", ".go", ".json", ".jsonl", ".lock", ".md", ".mjs", ".mod", ".proto", ".py", ".rs",
  ".sha256", ".sum", ".svg", ".toml", ".tsv", ".txt", ".yaml", ".yml",
]);
const textNames = new Set(["CODEOWNERS", "LICENSE", "NOTICE", ".gitattributes", ".gitignore"]);
// Lock files and checksum lists hold encoded digests, not prose.
const digestFiles = /(?:^|\/)(?:Cargo\.lock|go\.sum)$|\.sha256$/;

// Labels of the private development process. Public text uses descriptive names.
const internalLabelPatterns = [
  /(?<![A-Za-z])round[-_ ]?\d+/i,
  /(?<![A-Za-z0-9])R\d{3}(?!\d)/,
  /\b(?:M[1-9]\d*|G[1-9]\d*|FV\d+)\b/,
  /(?:^|[^A-Za-z0-9])(?:FV|RL)[-_]\d+(?!\d)/i,
  /\bMain\d+\b/,
  /\b(?:EC|P)0\d{2}\b/,
  /\bPHASE[-_ ]?\d+/,
];
const toolNamePattern = /\b(?:codex|claude|anthropic|openai|chatgpt|copilot)\b|\bgpt-\d/i;
const markerNames = new Set(["PROOF-LINK-PENDING"]);
const placeholderPattern = /\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-PENDING\b|\bPENDING_[A-Z0-9_]+\b|\bTBD\b/g;
const localPathPattern = /\b[A-Za-z]:\\Users\\|\/Users\/[^/\s]+\/|\/home\/[^/\s]+\//;
const credentialPattern =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bAKIA[0-9A-Z]{16}\b/;
const char = (code) => String.fromCodePoint(code);
const hangulPattern = new RegExp(`[${char(0x1100)}-${char(0x11ff)}${char(0x3130)}-${char(0x318f)}${char(0xac00)}-${char(0xd7af)}]`);

// Known internal labels in test fixture names and ignore reasons. Each entry
// is a file and the SHA-256 of one of its lines, so this list does not repeat
// the labels.
const pendingFindings = new Map();
const pendingSeen = new Set();

// One deliberate unknown-output token in a negative parser test. Only the
// exact file bytes, line number, line bytes and matched token qualify. The
// remaining checks still scan that line and every other byte in the file.
const placeholderFixtureExceptions = new Map([
  ["scripts/test-reference-contract.py", {
    fileSha256: "4caf94a2a0da18e2d318534e87b926c2c17ac578211e18d0b24ec52b7803f7bb",
    lineNumber: 94,
    lineSha256: "e16d130d367065f7489453bae6a028d49cc486388e02fd655f8098739fb28d21",
    token: "OIP-PENDING",
  }],
]);
const placeholderFixtureSeen = new Map();

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const read = (path) => readFileSync(resolve(root, path), "utf8");
const isFile = (path) => {
  try {
    return statSync(resolve(root, path)).isFile();
  } catch {
    return false;
  }
};

function walk(path) {
  const rel = relative(root, path).replaceAll("\\", "/");
  if (rel && rel.split("/").some((part) => [".git", "target", "node_modules"].includes(part))) return [];
  if (statSync(path).isFile()) return [rel];
  return readdirSync(path)
    .sort()
    .flatMap((entry) => walk(resolve(path, entry)));
}

// Tracked files plus new files that are not ignored; a plain directory walk
// outside a Git checkout.
function listFiles() {
  try {
    const output = execFileSync(
      "git",
      ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
      { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
    );
    return [...new Set(output.split("\0").filter(Boolean))].filter(isFile).sort();
  } catch {
    return walk(root);
  }
}

const files = listFiles();
const fileSet = new Set(files);

for (const path of required) {
  if (!isFile(path)) failures.push(`missing required file: ${path}`);
}

for (const path of files) {
  for (const segment of path.split("/")) {
    if (internalLabelPatterns.some((pattern) => pattern.test(segment))) {
      failures.push(`internal label in path: ${path}`);
      break;
    }
  }
  const extension = extname(path).toLowerCase();
  if (!textExtensions.has(extension) && !textNames.has(basename(path))) continue;

  const bytes = readFileSync(resolve(root, path));
  const text = bytes.toString("utf8");
  const placeholderFixture = placeholderFixtureExceptions.get(path);
  const placeholderFixtureFileMatches = Boolean(
    placeholderFixture && sha256(bytes) === placeholderFixture.fileSha256,
  );
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    failures.push(`UTF-8 BOM is not allowed: ${path}`);
  }
  if (text.includes(char(0xfffd))) failures.push(`Unicode replacement character: ${path}`);
  if (text.includes(char(0))) failures.push(`NUL byte in text file: ${path}`);
  if (text.includes("\r\n")) failures.push(`CRLF line ending (the repository stores LF): ${path}`);

  // In SVG files only text nodes are prose; path data and attributes are not.
  const scanned = extension === ".svg"
    ? text.replace(/<[^>]*>/g, (tag) => tag.replace(/[^\n]/g, " "))
    : text;
  const lines = scanned.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const where = `${path}:${index + 1}`;
    if (line.includes(char(0x2014))) failures.push(`em dash: ${where}`);
    if (hangulPattern.test(line)) failures.push(`Hangul text in an English repository: ${where}`);
    if (scannerFiles.has(path)) continue;
    if (localPathPattern.test(line)) failures.push(`local absolute path: ${where}`);
    if (credentialPattern.test(line)) failures.push(`possible credential: ${where}`);
    if (toolNamePattern.test(line)) failures.push(`AI tool name: ${where}`);
    for (const match of line.matchAll(placeholderPattern)) {
      if (placeholderFixtureFileMatches
          && index + 1 === placeholderFixture.lineNumber
          && sha256(line) === placeholderFixture.lineSha256
          && match[0] === placeholderFixture.token) {
        placeholderFixtureSeen.set(path, (placeholderFixtureSeen.get(path) ?? 0) + 1);
        continue;
      }
      if (!markerNames.has(match[0])) failures.push(`placeholder ${match[0]}: ${where}`);
      else (strict ? failures : notices).push(`publication marker ${match[0]}: ${where}`);
    }
    if (digestFiles.test(path)) continue;
    const label = internalLabelPatterns.map((pattern) => line.match(pattern)).find(Boolean);
    if (!label) continue;
    const digest = sha256(line);
    if (pendingFindings.get(path)?.has(digest)) {
      pendingSeen.add(`${path} ${digest}`);
      (strict ? failures : notices).push(`known internal label awaiting a source change: ${where}`);
    } else {
      failures.push(`internal label ${label[0]}: ${where}`);
    }
  }
}

for (const [path, fixture] of placeholderFixtureExceptions) {
  if (placeholderFixtureSeen.get(path) !== 1) {
    failures.push(`stale negative-fixture placeholder exception: ${path}:${fixture.lineNumber}`);
  }
}

for (const [path, digests] of pendingFindings) {
  for (const digest of digests) {
    if (!pendingSeen.has(`${path} ${digest}`)) {
      notices.push(`pending entry no longer matches and can be removed: ${path} ${digest.slice(0, 12)}`);
    }
  }
}
if (strict && pendingFindings.size > 0) {
  failures.push("pendingFindings must be empty when the public rules apply");
}

// Vector checksum lists: '<sha256>  <file>' relative to the list's directory.
for (const path of files.filter((file) => file.endsWith(".sha256"))) {
  const directory = posix.dirname(path);
  for (const line of read(path).split("\n").filter(Boolean)) {
    const match = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
    if (!match) {
      failures.push(`unreadable checksum line: ${path}`);
      continue;
    }
    const target = posix.join(directory, match[2]);
    if (!isFile(target)) failures.push(`checksum names a missing file: ${path} -> ${match[2]}`);
    else if (sha256(readFileSync(resolve(root, target))) !== match[1]) failures.push(`checksum mismatch: ${target}`);
  }
}

function anchorsFor(path) {
  const counts = new Map();
  const anchors = new Set();
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const match = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (!match) continue;
    const base = match[2]
      .replace(/<[^>]*>/g, "")
      .replace(/[`*_~]/g, "")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s-]/gu, "")
      .trim()
      .replace(/\s+/g, "-");
    const duplicate = counts.get(base) ?? 0;
    counts.set(base, duplicate + 1);
    anchors.add(duplicate === 0 ? base : `${base}-${duplicate}`);
  }
  return anchors;
}

const anchorCache = new Map();
for (const path of files.filter((file) => extname(file).toLowerCase() === ".md")) {
  const source = resolve(root, path);
  const text = readFileSync(source, "utf8").replace(/```[\s\S]*?```/g, "");
  const targets = [
    ...[...text.matchAll(/!?\[[^\]]*]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)].map((match) => match[1]),
    ...[...text.matchAll(/\b(?:src|srcset|href)="([^"]+)"/g)].map((match) => match[1]),
  ];
  for (const rawTarget of targets) {
    if (/^(?:https?:|mailto:)/i.test(rawTarget)) continue;
    const [rawPath, rawFragment = ""] = rawTarget.split("#", 2);
    const target = rawPath ? resolve(dirname(source), decodeURIComponent(rawPath)) : source;
    const label = `${path} -> ${rawTarget}`;
    const targetPath = relative(root, target).replaceAll("\\", "/");
    if (targetPath.startsWith("..")) {
      failures.push(`link leaves the repository: ${label}`);
      continue;
    }
    // A link must reach a file that is part of the repository, or a directory
    // that contains one; ignored build output does not count.
    const published = targetPath === ""
      ? files.length > 0
      : fileSet.has(targetPath) || files.some((file) => file.startsWith(`${targetPath.replace(/\/$/, "")}/`));
    if (!published) {
      failures.push(`missing link target: ${label}`);
      continue;
    }
    if (rawFragment && fileSet.has(targetPath) && extname(target).toLowerCase() === ".md") {
      const anchors = anchorCache.get(target) ?? anchorsFor(target);
      anchorCache.set(target, anchors);
      if (!anchors.has(decodeURIComponent(rawFragment).toLowerCase())) {
        failures.push(`missing heading anchor: ${label}`);
      }
    }
  }
}

const readme = read("README.md");
for (const marker of [
  "Unaudited. Not for production.",
  "## Why OIP",
  "## Quickstart",
  "## Architecture",
  "## Versions and compatibility",
  "## Formal verification",
  "## Assurance",
  "## Specification documents",
  "## Repository map",
  "## Security, contributing and support",
  "## License and citation",
]) {
  if (!readme.includes(marker)) failures.push(`README missing required marker: ${marker}`);
}
const banner =
  /<picture>\s*<source media="\(max-width: 900px\)" srcset="docs\/assets\/oip-spec-banner-mobile\.svg">\s*<img src="docs\/assets\/oip-spec-banner\.svg" alt="[^"]+" width="\d+">\s*<\/picture>/;
if (!banner.test(readme)) {
  failures.push("README banner must be a <picture> with the 900px mobile source and the desktop image");
}
for (const match of readme.matchAll(/github\.com\/Oraclizer\/oip-spec\/actions\/workflows\/([^/)\s]+)\/badge\.svg(\?[^)\s]*)?/g)) {
  if (!isFile(`.github/workflows/${match[1]}`)) failures.push(`badge names a missing workflow: ${match[1]}`);
  if (match[2] !== "?branch=main") failures.push(`workflow badge must show the main branch: ${match[1]}`);
}
// A status badge for a workflow in another repository also shows its main branch.
for (const match of readme.matchAll(/img\.shields\.io\/github\/actions\/workflow\/status\/[^)\s]+/g)) {
  if (!/[?&]branch=main(?:&|$)/.test(match[0])) failures.push(`workflow status badge must show the main branch: ${match[0]}`);
}

// Every README diagram is a <picture>: a 900px mobile source next to its
// desktop file, with the mobile canvas 600 units wide.
const diagrams = ["architecture-overview", "verification-architecture"];
const pictures = [...readme.matchAll(/<picture>[\s\S]*?<\/picture>/g)].map((match) => match[0]);
for (const block of pictures.filter((entry) => !entry.includes("oip-spec-banner"))) {
  const pair = /^<picture>\s*<source media="\(max-width: 900px\)" srcset="docs\/assets\/([a-z0-9-]+)-mobile\.svg">\s*<img src="docs\/assets\/\1\.svg" alt="[^"]+" width="\d+">\s*<\/picture>$/.exec(block);
  if (!pair) {
    failures.push(`README picture must pair docs/assets/<name>-mobile.svg with docs/assets/<name>.svg: ${block.slice(0, 120)}`);
    continue;
  }
  const mobile = `docs/assets/${pair[1]}-mobile.svg`;
  if (isFile(mobile) && !/\bviewBox="0 0 600 \d+(?:\.\d+)?"/.test(read(mobile))) {
    failures.push(`mobile diagram canvas must be 600 units wide: ${mobile}`);
  }
}
for (const name of diagrams) {
  if (!pictures.some((block) => block.includes(`srcset="docs/assets/${name}-mobile.svg"`))) {
    failures.push(`README missing the diagram: docs/assets/${name}.svg`);
  }
}

for (const path of files.filter((file) => extname(file).toLowerCase() === ".svg")) {
  const text = read(path);
  for (const [name, pattern] of [
    ["title", /<title[\s>]/],
    ["desc", /<desc[\s>]/],
    ["viewBox", /\bviewBox="/],
    ['role="img"', /\brole="img"/],
  ]) {
    if (!pattern.test(text)) failures.push(`SVG missing ${name}: ${path}`);
  }
  if (/<script[\s>]|<foreignObject[\s>]|<image[\s>]|\bhref="(?:https?:)?\/\//i.test(text)) {
    failures.push(`SVG must be self-contained: ${path}`);
  }
}
for (const [path, viewBox] of [
  ["docs/assets/oip-spec-banner.svg", "0 0 1200 300"],
  ["docs/assets/oip-spec-banner-mobile.svg", "0 0 640 320"],
]) {
  if (isFile(path) && !read(path).includes(`viewBox="${viewBox}"`)) {
    failures.push(`banner canvas must be ${viewBox}: ${path}`);
  }
}

function jobsOf(text) {
  const lines = text.split("\n");
  const jobs = new Map();
  let current = null;
  for (const line of lines.slice(lines.findIndex((entry) => /^jobs:\s*$/.test(entry)) + 1)) {
    const key = /^ {2}([A-Za-z0-9_-]+):\s*$/.exec(line);
    if (key) {
      current = [];
      jobs.set(key[1], current);
    } else if (/^\S/.test(line)) {
      break;
    } else {
      current?.push(line);
    }
  }
  return new Map([...jobs].map(([name, body]) => [name, body.join("\n")]));
}

function needsOf(body) {
  const inline = /^ {4}needs:\s*\[([^\]]*)\]/m.exec(body);
  if (inline) return inline[1].split(",").map((entry) => entry.trim()).filter(Boolean);
  const block = /^ {4}needs:\s*\n((?: {6}- .*\n?)+)/m.exec(body);
  if (block) return block[1].split("\n").map((entry) => entry.replace(/^ {6}- /, "").trim()).filter(Boolean);
  const single = /^ {4}needs:\s*([A-Za-z0-9_-]+)\s*$/m.exec(body);
  return single ? [single[1]] : [];
}

const workflows = files.filter((file) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(file));
for (const path of workflows) {
  const text = read(path);
  if (!/^permissions:\s*\n {2}contents: read\s*$/m.test(text)) {
    failures.push(`workflow must set top-level permissions to contents: read: ${path}`);
  }
  if (!/^concurrency:/m.test(text)) failures.push(`workflow missing concurrency: ${path}`);
  if (/\bpull_request_target\b/.test(text)) failures.push(`workflow must not use pull_request_target: ${path}`);
  if (/^\s+paths(?:-ignore)?:/m.test(text)) failures.push(`workflow must not filter by path: ${path}`);
  for (const match of text.matchAll(/^\s*(?:-\s+)?uses:\s*([^#\s]+)(.*)$/gm)) {
    if (!/@[0-9a-f]{40}$/.test(match[1]) || !/#\s*v\d/.test(match[2])) {
      failures.push(`action must be pinned to a full commit with a version comment: ${path}: ${match[1]}`);
    }
  }
  const checkouts = [...text.matchAll(/uses:\s*actions\/checkout@/g)].length;
  const withoutCredentials = [...text.matchAll(/persist-credentials:\s*false/g)].length;
  if (checkouts !== withoutCredentials) failures.push(`every checkout must set persist-credentials: false: ${path}`);

  const jobs = jobsOf(text);
  for (const [name, body] of jobs) {
    if (!/^ {4}runs-on:/m.test(body)) failures.push(`job missing runs-on: ${path}: ${name}`);
    if (!/^ {4}timeout-minutes:\s*\d+/m.test(body)) failures.push(`job missing timeout-minutes: ${path}: ${name}`);
    // Private development is checked locally, so a private copy uses no
    // hosted runner time.
    const condition = /^ {4}if:\s*(.+)$/m.exec(body)?.[1] ?? "";
    const skipsPrivate = /^\$\{\{.*!\s*github\.event\.repository\.private\b.*\}\}\s*$/.test(condition) && !condition.includes("||");
    if (!strict && !skipsPrivate) {
      failures.push(`job must be skipped on a private repository: ${path}: ${name}`);
    }
  }
  const aggregate = [...jobs].find(([, body]) => /^ {4}if:\s*(?:\$\{\{\s*always\(\)[^}\n]*\}\}|always\(\))\s*$/m.test(body));
  if (!aggregate) {
    failures.push(`workflow needs an aggregate job that runs with always(): ${path}`);
  } else {
    const [name, body] = aggregate;
    const needs = needsOf(body);
    for (const job of jobs.keys()) {
      if (job === name) continue;
      if (!needs.includes(job)) failures.push(`aggregate job ${name} must need ${job}: ${path}`);
      if (!body.includes(`needs.${job}.result`)) failures.push(`aggregate job ${name} must check the result of ${job}: ${path}`);
    }
  }
}

if (isFile(".github/dependabot.yml")) {
  const dependabot = read(".github/dependabot.yml");
  if (/^\s*ignore:/m.test(dependabot)) failures.push("dependabot.yml must not ignore dependencies");
  const entries = new Map();
  for (const block of dependabot.split(/^\s*-\s+package-ecosystem:/m).slice(1)) {
    const name = /^\s*"?([a-z-]+)"?\s*$/m.exec(block);
    if (name) entries.set(name[1], block);
  }
  for (const ecosystem of ["cargo", "gomod", "github-actions"]) {
    if (!entries.has(ecosystem)) failures.push(`dependabot.yml missing ecosystem: ${ecosystem}`);
  }
  // The Cargo and Go manifests are part of the runtime fingerprint that the
  // pinned models carry, so a version change needs a new model export. Those
  // ecosystems take security updates only, and the proof-crypto group applies
  // to those updates.
  for (const ecosystem of ["cargo", "gomod"]) {
    const block = entries.get(ecosystem);
    if (block && !/^\s+open-pull-requests-limit:\s*0\s*$/m.test(block)) {
      failures.push(`dependabot.yml must limit ${ecosystem} to security updates with open-pull-requests-limit: 0`);
    }
  }
  const cargoUpdates = entries.get("cargo") ?? "";
  if (!/^\s+proof-crypto:\s*$/m.test(cargoUpdates)) {
    failures.push("dependabot.yml missing the proof-crypto group");
  } else if (!/^\s+applies-to:\s*security-updates\s*$/m.test(cargoUpdates)) {
    failures.push("dependabot.yml proof-crypto group must apply to security updates");
  }
}

// One version across the package, the citation, the changelog and the README.
const cargo = read("Cargo.toml");
const packageStart = cargo.search(/^\[package\]\s*$/m);
const packageEnd = cargo.slice(packageStart + 1).search(/^\[/m);
const packageSection = packageEnd < 0 ? cargo.slice(packageStart) : cargo.slice(packageStart, packageStart + 1 + packageEnd);
const version = /^version\s*=\s*"([^"]+)"/m.exec(packageSection)?.[1];
const citationVersion = /^version:\s*"?([^"\s]+)"?\s*$/m.exec(read("CITATION.cff"))?.[1];
const changelogVersion = /^## \[(\d+\.\d+\.\d+)\]/m.exec(read("CHANGELOG.md"))?.[1];
if (!version) failures.push("Cargo.toml has no package version");
if (citationVersion !== version) failures.push(`CITATION.cff version ${citationVersion} differs from Cargo.toml ${version}`);
if (changelogVersion !== version) failures.push(`newest CHANGELOG version ${changelogVersion} differs from Cargo.toml ${version}`);
if (version && !readme.includes(`v${version}`)) failures.push(`README does not name v${version}`);

// One license across the license files, the package, the citation and the
// README. Both license files hold the unmodified Apache License 2.0 text.
const apacheLicenseSha256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
for (const path of ["LICENSE", "go/LICENSE"]) {
  if (isFile(path) && sha256(readFileSync(resolve(root, path))) !== apacheLicenseSha256) {
    failures.push(`${path} is not the unmodified Apache License 2.0 text`);
  }
}
const cargoLicense = /^license\s*=\s*"([^"]+)"/m.exec(packageSection)?.[1];
const citationLicense = /^license:\s*"?([^"\s]+)"?\s*$/m.exec(read("CITATION.cff"))?.[1];
const readmeLicense = /img\.shields\.io\/badge\/license-((?:[^-)\s]|--)+)-/.exec(readme)?.[1]?.replaceAll("--", "-");
if (cargoLicense !== "Apache-2.0") failures.push(`Cargo.toml license ${cargoLicense} is not Apache-2.0`);
if (citationLicense !== cargoLicense) failures.push(`CITATION.cff license ${citationLicense} differs from Cargo.toml ${cargoLicense}`);
if (readmeLicense !== cargoLicense) failures.push(`README license badge ${readmeLicense} differs from Cargo.toml ${cargoLicense}`);

// Toolchain badges state facts that the Tests workflow enforces.
const testsWorkflow = isFile(".github/workflows/tests.yml") ? read(".github/workflows/tests.yml") : "";
const rustPins = new Set(
  [...testsWorkflow.matchAll(/(?:cargo \+|rustup toolchain install )(\d+\.\d+\.\d+)/g)].map((match) => match[1]),
);
const goModVersion = /^go (\d+\.\d+\.\d+)\s*$/m.exec(read("go/go.mod"))?.[1];
const goPin = /^\s+GO_VERSION:\s*"?(\d+\.\d+\.\d+)"?\s*$/m.exec(testsWorkflow)?.[1];
if (rustPins.size !== 1) {
  failures.push(`tests.yml must use one Rust toolchain, found: ${[...rustPins].join(", ") || "none"}`);
}
if (goPin !== goModVersion) failures.push(`tests.yml Go ${goPin} differs from go.mod ${goModVersion}`);
for (const [tool, expected] of [["rust", [...rustPins][0]], ["go", goModVersion]]) {
  const badge = new RegExp(`img\\.shields\\.io/badge/${tool}-(\\d+\\.\\d+\\.\\d+)-`).exec(readme)?.[1];
  if (badge && badge !== expected) failures.push(`README ${tool} badge ${badge} differs from the pinned ${expected}`);
}

for (const notice of notices) console.log(`notice: ${notice}`);
if (failures.length) {
  for (const failure of failures) console.error(failure);
  console.error(`repository health FAIL under the ${visibility} rules: ${failures.length} finding(s)`);
  process.exit(1);
}
console.log(`repository health PASS under the ${visibility} rules: ${files.length} files, ${notices.length} notice(s)`);
