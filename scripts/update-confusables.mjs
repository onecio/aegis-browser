import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const version = "18.0.0";
const sourceUrl = "https://www.unicode.org/Public/security/latest/confusables.txt";
const licenseUrl = "https://www.unicode.org/license.txt";
const dataDir = resolve(process.cwd(), "data/unicode");
const mapPath = resolve(process.cwd(), "src/core/confusables-map.json");

const sourceResponse = await fetch(sourceUrl, { redirect: "error", cache: "no-store" });
if (!sourceResponse.ok) throw new Error(`Unicode data download failed: HTTP ${sourceResponse.status}`);
const source = await sourceResponse.text();
if (!source.includes(`# Version: ${version}`)) throw new Error(`Expected Unicode security data ${version}; review and update the pinned version before regenerating.`);

const mappings = {};
for (const line of source.split(/\r?\n/)) {
  const fields = line.split("#", 1)[0].split(";").map((field) => field.trim());
  if (fields.length < 3 || fields[2] !== "MA") continue;
  const sourcePoints = fields[0].split(/\s+/).filter(Boolean);
  const targetPoints = fields[1].split(/\s+/).filter(Boolean);
  if (sourcePoints.length !== 1 || !targetPoints.length) throw new Error(`Unexpected confusable mapping: ${line}`);
  const from = String.fromCodePoint(Number.parseInt(sourcePoints[0], 16));
  const to = targetPoints.map((point) => String.fromCodePoint(Number.parseInt(point, 16))).join("");
  mappings[from] = to;
}
if (Object.keys(mappings).length < 4_000) throw new Error(`Unexpectedly small Unicode map: ${Object.keys(mappings).length}`);

const licenseResponse = await fetch(licenseUrl, { redirect: "error", cache: "no-store" });
if (!licenseResponse.ok) throw new Error(`Unicode license download failed: HTTP ${licenseResponse.status}`);
const license = await licenseResponse.text();
if (!license.includes("UNICODE LICENSE V3") || !license.includes("Copyright © 1991-2026 Unicode, Inc.")) throw new Error("Unexpected Unicode license text");

await mkdir(dataDir, { recursive: true });
await writeFile(resolve(dataDir, `confusables-${version}.txt`), source, "utf8");
await writeFile(resolve(dataDir, "LICENSE.txt"), license, "utf8");
await writeFile(mapPath, `${JSON.stringify(mappings)}\n`, "utf8");
process.stdout.write(`Updated Unicode ${version} MA confusables: ${Object.keys(mappings).length} mappings.\n`);
