import { readFile, readdir, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { findSecretIndicators } from "./audit-secrets.mjs";

const root = process.cwd();
const dist = resolve(root, "dist");
const manifest = JSON.parse(await readFile(resolve(dist, "manifest.json"), "utf8"));
const failures = [];
if (manifest.manifest_version !== 3) failures.push("manifest_version must be 3");
if (manifest.host_permissions?.length) failures.push("required host_permissions must remain empty");
if (!manifest.optional_host_permissions?.includes("https://*/*") || !manifest.optional_host_permissions?.includes("http://*/*")) failures.push("continuous web access must stay runtime-optional");
if (manifest.permissions?.some((value) => ["cookies", "history", "webRequest", "debugger"].includes(value))) failures.push("unexpected high-privilege browser permission");
if (!String(manifest.content_security_policy?.extension_pages ?? "").includes("object-src 'none'")) failures.push("extension CSP must block plugin objects");
if (manifest.content_scripts?.length) failures.push("content scripts must be registered only after permission is granted");

async function walk(path) {
  const entries = await readdir(path, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = resolve(path, entry.name);
    if (entry.isDirectory()) files.push(...await walk(full));
    else files.push(full);
  }
  return files;
}

for (const relative of ["service-worker.js", "content.js", "popup.js", "sidepanel.js", "options.js", "popup.html", "sidepanel.html", "options.html", "aegis.css"]) {
  try { await stat(resolve(dist, relative)); } catch { failures.push(`missing build artifact: ${relative}`); }
}

for (const path of await walk(dist)) {
  if (!path.endsWith(".js")) continue;
  const source = await readFile(path, "utf8");
  const name = path.slice(dist.length + 1);
  if (/\beval\s*\(|\bnew\s+Function\s*\(/.test(source)) failures.push(`${name} contains dynamic code evaluation`);
  if (/https?:\/\/(?:unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com)\//i.test(source)) failures.push(`${name} references remotely hosted executable code`);
  for (const pattern of findSecretIndicators(source)) failures.push(`${name} contains a ${pattern} pattern`);
  if (/\bBearer\s+[A-Za-z0-9._~-]{24,}/.test(source)) failures.push(`${name} contains a literal bearer credential`);
  if (/\b(?:ts|sk|api)[_-][A-Za-z0-9_-]{32,}\b/.test(source)) failures.push(`${name} contains a token-shaped literal`);
  if (/console\.(?:log|error|warn)\s*\(/.test(source)) failures.push(`${name} contains console logging`);
}

if (failures.length) {
  process.stderr.write(`Bundle audit failed:\n${failures.map((issue) => `- ${issue}`).join("\n")}\n`);
  process.exitCode = 1;
} else process.stdout.write("Bundle audit passed: MV3, optional hosts, CSP, local scripts, and no credential/logging patterns.\n");
