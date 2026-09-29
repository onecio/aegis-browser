import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const root = process.cwd();
const npmCliPath = process.env.npm_execpath;
if (!npmCliPath) {
  process.stderr.write("SBOM generation must run through npm so npm's CLI path is available.\n");
  process.exit(1);
}

const result = spawnSync(process.execPath, [npmCliPath, "sbom", "--sbom-format=spdx", "--sbom-type=application"], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 16 * 1024 * 1024,
  windowsHide: true
});

if (result.error || result.status !== 0) {
  if (result.stderr) process.stderr.write(result.stderr);
  process.stderr.write("npm could not generate the SPDX SBOM.\n");
  process.exit(1);
}

let document;
try {
  document = JSON.parse(result.stdout);
} catch {
  process.stderr.write("npm returned an invalid SBOM document.\n");
  process.exit(1);
}

if (document.spdxVersion !== "SPDX-2.3" || !Array.isArray(document.packages) || !document.packages.length || !Array.isArray(document.documentDescribes) || !document.documentDescribes.length) {
  process.stderr.write("The generated SBOM is missing required SPDX project or package metadata.\n");
  process.exit(1);
}

const outputPath = resolve(root, "dist", "aegis.spdx.json");
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
process.stdout.write(`SPDX SBOM written to ${outputPath.slice(root.length + 1)} (${document.packages.length} packages).\n`);
