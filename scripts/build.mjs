import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { build } from "esbuild";
import { resolve } from "node:path";

const root = process.cwd();
const outdir = resolve(root, "dist");
await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

const bundles = [
  ["src/background/service-worker.js", "service-worker.js", "esm"],
  ["src/content/content-script.js", "content.js", "iife"],
  ["src/ui/popup.js", "popup.js", "iife"],
  ["src/ui/sidepanel.js", "sidepanel.js", "iife"],
  ["src/ui/options.js", "options.js", "iife"]
];

for (const [entry, outfile, format] of bundles) {
  await build({
    entryPoints: [resolve(root, entry)],
    outfile: resolve(outdir, outfile),
    bundle: true,
    format,
    platform: "browser",
    target: ["chrome120"],
    sourcemap: false,
    minify: true,
    legalComments: "none"
  });
}

await cp(resolve(root, "extension"), outdir, { recursive: true });
const manifest = JSON.parse(await readFile(resolve(outdir, "manifest.json"), "utf8"));
const packageMetadata = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
manifest.version = process.env.AEGIS_VERSION ?? packageMetadata.version;
await writeFile(resolve(outdir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Built AEGIS ${manifest.version} to dist/`);
