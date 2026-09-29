import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";

const root = process.cwd();
const outputDirectory = resolve(root, "dist");
const sbomPath = "aegis.spdx.json";
const npmCli = process.env.npm_execpath;

if (!npmCli) throw new Error("Run this check through `npm run verify:repro`.");

function build() {
  const result = spawnSync(process.execPath, [npmCli, "run", "build"], { cwd: root, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Build failed with exit code ${result.status ?? "unknown"}.`);
}

async function packageDigest() {
  const files = [];

  async function collect(directory, prefix = "") {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) await collect(absolutePath, relativePath);
      else if (entry.isFile() && relativePath !== sbomPath) files.push({ absolutePath, relativePath });
    }
  }

  await collect(outputDirectory);
  files.sort((left, right) => (left.relativePath < right.relativePath ? -1 : left.relativePath > right.relativePath ? 1 : 0));
  const hash = createHash("sha256");
  for (const file of files) {
    hash.update(file.relativePath);
    hash.update(Buffer.from([0]));
    hash.update(await readFile(file.absolutePath));
    hash.update(Buffer.from([0]));
  }
  return { fileCount: files.length, hash: hash.digest("hex") };
}

build();
const first = await packageDigest();
build();
const second = await packageDigest();

if (first.fileCount !== second.fileCount || first.hash !== second.hash) {
  throw new Error(`Extension package is not reproducible: first=${first.fileCount}/${first.hash}, second=${second.fileCount}/${second.hash}.`);
}

console.log(`Reproducible extension build verified: ${second.fileCount} files, SHA-256 ${second.hash}. SBOM excluded because it contains generation metadata.`);
