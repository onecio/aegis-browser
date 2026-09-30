import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, relative, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import puppeteer from "puppeteer-core";

if (!process.env.TYPESAFE_API_KEY) throw new Error("Supply TYPESAFE_API_KEY in the environment; do not put credentials in arguments.");
const source = resolve(process.env.AEGIS_EXTENSION_PATH ?? "dist");
const reportRoot = resolve("release/evolution-0.3.0");
await mkdir(reportRoot, { recursive: true });
const ownedRoot = await mkdtemp(join(reportRoot, ".jev-extension-fixture-"));
const fixture = join(ownedRoot, "extension");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const originalManifest = await readFile(join(source, "manifest.json"));
const bundles = ["service-worker.js", "options.js", "content.js", "popup.js", "sidepanel.js"];
const bundleHashes = {};
let browser;
try {
  await cp(source, fixture, { recursive: true });
  for (const file of bundles) {
    bundleHashes[file] = hash(await readFile(join(source, file)));
    assert.equal(hash(await readFile(join(fixture, file))), bundleHashes[file]);
  }
  const manifest = JSON.parse(originalManifest);
  manifest.host_permissions = ["https://api.typesafe.ai/*"];
  await writeFile(join(fixture, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  const candidates = process.env.AEGIS_CHROME_PATH ? [resolve(process.env.AEGIS_CHROME_PATH)] : process.platform === "win32"
    ? ["C:/Program Files/Google/Chrome/Application/chrome.exe", "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"]
    : process.platform === "darwin" ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
      : ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"];
  const executablePath = candidates.find(existsSync);
  assert.ok(executablePath, "Set AEGIS_CHROME_PATH to an installed Chrome executable");
  browser = await puppeteer.launch({
    browser: "chrome", executablePath, headless: false, enableExtensions: true,
    userDataDir: join(ownedRoot, "profile"),
    args: ["--window-position=-32000,-32000", "--window-size=1280,900"], timeout: 20_000
  });
  const extensionId = await browser.installExtension(fixture);
  const options = await browser.newPage();
  await options.goto(`chrome-extension://${extensionId}/options.html`, { waitUntil: "domcontentloaded" });
  await options.waitForFunction(() => document.querySelector("#organizationKnowledgeBase")?.value.includes('"brands"'));
  await options.select("#connectionMode", "byok");
  await options.select("#privacyMode", "STRICT");
  await options.evaluate((key) => { document.querySelector("#byokKey").value = key; }, process.env.TYPESAFE_API_KEY);
  await options.click("#saveByok");
  await options.waitForFunction(async () => {
    const result = await chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" });
    return result.hasByok === true && result.settings.jevEnabled === true && document.querySelector("#byokKey").value === "";
  }, { timeout: 7000 });
  const permitted = await options.evaluate(() => chrome.permissions.contains({ origins: ["https://api.typesafe.ai/*"] }));
  assert.equal(permitted, true);
  const workerTarget = await browser.waitForTarget((target) => target.type() === "service_worker" && target.url() === `chrome-extension://${extensionId}/service-worker.js`);
  const network = [];
  const responses = [];
  const observeNetwork = async (target) => {
    const session = await target.createCDPSession();
    await session.send("Network.enable");
    session.on("Network.requestWillBeSent", ({ request }) => {
      const url = new URL(request.url);
      if (url.origin === "https://api.typesafe.ai") network.push({ origin: url.origin, method: request.method });
    });
    session.on("Network.responseReceived", ({ response }) => {
      const url = new URL(response.url);
      if (url.origin === "https://api.typesafe.ai") responses.push({ origin: url.origin, status: response.status });
    });
    return session;
  };
  const initialNetwork = await observeNetwork(workerTarget);
  const started = performance.now();
  const result = await options.evaluate(() => chrome.runtime.sendMessage({ type: "AEGIS_TEST_JEV" }));
  const inferenceLatencyMs = Number((performance.now() - started).toFixed(1));
  assert.equal(result.ok, true, `Actual worker inference failed: ${result.errorCode ?? "unknown"}`);
  const validated = await options.evaluate(() => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }));
  assert.equal(validated.connectionRuntime.status, "connected");
  assert.equal(validated.connectionRuntime.lastTest.model, result.model);
  assert.equal(network.filter((entry) => entry.method === "POST").length, 1);
  assert.ok(responses.some((entry) => entry.status === 200));
  await initialNetwork.detach();
  const lifecycle = await options.createCDPSession();
  let versions = [];
  lifecycle.on("ServiceWorker.workerVersionUpdated", (event) => { versions = [...versions.filter((previous) => !event.versions.some((entry) => entry.versionId === previous.versionId)), ...event.versions]; });
  await lifecycle.send("ServiceWorker.enable");
  const until = Date.now() + 3500;
  while (!versions.some((entry) => entry.scriptURL === workerTarget.url() && entry.runningStatus === "running") && Date.now() < until) await new Promise((resolve) => setTimeout(resolve, 30));
  const version = versions.find((entry) => entry.scriptURL === workerTarget.url() && entry.runningStatus === "running");
  assert.ok(version, "The actual extension worker version must be observable before stopping it");
  await lifecycle.send("ServiceWorker.stopWorker", { versionId: version.versionId });
  const stopDeadline = Date.now() + 3500;
  while (browser.targets().includes(workerTarget) && Date.now() < stopDeadline) await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(browser.targets().includes(workerTarget), false, "The original worker target must terminate");
  const restarted = await options.evaluate(() => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }));
  assert.equal(restarted.hasByok, true, "Session credential survives actual worker restart");
  assert.equal(restarted.connectionRuntime.lastTest?.model, result.model);
  const nextWorker = await browser.waitForTarget((target) => target.type() === "service_worker" && target.url() === workerTarget.url());
  assert.notEqual(nextWorker, workerTarget);
  const nextNetwork = await observeNetwork(nextWorker);
  const disabled = await options.evaluate(() => chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: { jevEnabled: false } }));
  assert.equal(disabled.ok, true);
  const off = await options.evaluate(() => chrome.runtime.sendMessage({ type: "AEGIS_TEST_JEV" }));
  assert.deepEqual(off, { ok: false, errorCode: "JEV_DISABLED" });
  const cleared = await options.evaluate(() => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }));
  assert.equal(cleared.hasByok, false);
  assert.equal(cleared.connectionRuntime.status, "off");
  assert.equal(network.filter((entry) => entry.method === "POST").length, 1, "Disabled JEV cannot send another provider request");
  await nextNetwork.detach();
  await lifecycle.detach();
  assert.equal(hash(await readFile(join(source, "manifest.json"))), hash(originalManifest), "Shipping manifest remains unchanged");
  for (const file of bundles) assert.equal(hash(await readFile(join(source, file))), bundleHashes[file], "Shipping bundles remain unchanged during the proof");
  const report = {
    generatedAt: new Date().toISOString(), status: "passed", actualMv3WorkerInference: true,
    model: result.model, inferenceLatencyMs, providerRequests: network, providerResponses: responses,
    workerStopRestartVerified: true, sessionCredentialRetainedAcrossWorkerRestart: true,
    jevOffClearsCredential: true, jevOffProviderRequests: 0,
    shippingManifestSha256: hash(originalManifest), sourceBundleSha256: bundleHashes,
    provenance: { profile: "owned temporary Chrome profile", productionProfile: false, permissionFixture: "only https://api.typesafe.ai/* predeclared in copied manifest", nativePermissionPromptValidated: false, shippingManifestModified: false },
    limits: ["One real JEV request executed by the MV3 worker using built-in synthetic STRICT connection-test metadata.", "A copied manifest predeclared the provider host for this contract fixture; native permission prompts and the installed personal browser profile were not tested.", "The browser-session credential survives worker restart and is removed when JEV is disabled; persistence across browser restarts is not offered."]
  };
  await writeFile(join(reportRoot, "jev-extension-proof.json"), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} finally {
  if (browser) await browser.close();
  const location = relative(reportRoot, ownedRoot);
  assert.ok(location.startsWith(".jev-extension-fixture-") && !location.includes("..") && !location.includes("\\") && !location.includes("/"), "Cleanup is restricted to the owned temporary fixture");
  await rm(ownedRoot, { recursive: true, force: true });
}
