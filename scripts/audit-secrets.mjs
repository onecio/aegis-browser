import { readdir, readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = process.cwd();
const textExtensions = new Set([".cjs", ".css", ".csv", ".html", ".js", ".json", ".md", ".mjs", ".svg", ".ts", ".txt", ".xml", ".yaml", ".yml"]);
// Test fixtures may contain synthetic bearer/Jev values; the shipped dist bundle has a separate credential-pattern audit.
const skippedDirectories = new Set([".git", "coverage", "dist", "node_modules", "tests"]);
const patterns = [
  {
    name: "named API credential",
    regex: /\b(TYPESAFE_API_KEY|(?:api[_-]?(?:key|secret)|client[_-]?secret|access[_-]?token|refresh[_-]?token|secret[_-]?key|private[_-]?key))\s*[:=]\s*(["']?)([A-Za-z0-9._~+/=-]{24,})\2/gi,
    valueIndex: 3,
    quoteIndex: 2
  },
  {
    name: "bearer credential",
    regex: /\bBearer\s+([A-Za-z0-9._~-]{24,})\b/gi,
    valueIndex: 1
  },
  {
    name: "prefixed API token",
    regex: /\b(?:sk|ts|api)[_-]([A-Za-z0-9_-]{24,})\b/gi,
    valueIndex: 1
  }
];

function shannonEntropy(value) {
  const counts = new Map();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function looksLikeCredential(value) {
  return value.length >= 24 && shannonEntropy(value) >= 3.45;
}

export function findSecretIndicators(source) {
  const findings = new Set();
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern.regex)) {
      // A runtime environment lookup is code, not a literal credential.
      if (pattern.quoteIndex && !match[pattern.quoteIndex] && /^process\.env\.[A-Z0-9_]+$/.test(match[pattern.valueIndex])) continue;
      if (looksLikeCredential(match[pattern.valueIndex])) findings.add(pattern.name);
    }
  }
  return [...findings];
}

async function collectTextFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      if (!skippedDirectories.has(entry.name)) files.push(...await collectTextFiles(path));
      continue;
    }
    if (entry.isFile() && (textExtensions.has(extname(entry.name).toLowerCase()) || entry.name === ".env" || entry.name.startsWith(".env."))) files.push(path);
  }
  return files;
}

async function audit() {
  const failures = [];
  for (const path of await collectTextFiles(root)) {
    const findings = findSecretIndicators(await readFile(path, "utf8"));
    for (const finding of findings) failures.push(`${path.slice(root.length + 1)}: ${finding}`);
  }

  if (failures.length) {
    process.stderr.write(`Source secret-pattern audit failed:\n${failures.map((failure) => `- ${failure}`).join("\n")}\n`);
    process.exitCode = 1;
  } else process.stdout.write("Source secret-pattern audit passed; no high-entropy API, bearer, or named credentials were found.\n");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await audit();
