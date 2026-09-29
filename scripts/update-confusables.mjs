import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const version = "18.0.0";
const dataDir = resolve(process.cwd(), "data/unicode");
const sourcePath = resolve(dataDir, `confusables-${version}.txt`);
const mapPath = resolve(process.cwd(), "src/core/confusables-map.json");

const source = await readFile(sourcePath, "utf8");
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

await writeFile(mapPath, `${JSON.stringify(mappings)}\n`, "utf8");
process.stdout.write(`Rebuilt Unicode ${version} MA confusables map from the checked-in source: ${Object.keys(mappings).length} mappings.\n`);
