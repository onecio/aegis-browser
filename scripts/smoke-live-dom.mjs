import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import puppeteer from "puppeteer-core";

const extensionPath = resolve(process.env.AEGIS_EXTENSION_PATH ?? "dist");
assert.ok(existsSync(resolve(extensionPath, "manifest.json")), "Run npm run build before the live DOM smoke test");

function browserPath(kind) {
  const override = process.env[`AEGIS_${kind.toUpperCase()}_PATH`];
  const candidates = override ? [resolve(override)] : process.platform === "win32"
    ? kind === "chrome"
      ? ["C:/Program Files/Google/Chrome/Application/chrome.exe", "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"]
      : ["C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "C:/Program Files/Microsoft/Edge/Application/msedge.exe"]
    : process.platform === "darwin"
      ? [kind === "chrome" ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" : "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]
      : kind === "chrome" ? ["/usr/bin/google-chrome", "/usr/bin/chromium"] : ["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"];
  const path = candidates.find(existsSync);
  assert.ok(path, `Set AEGIS_${kind.toUpperCase()}_PATH to an installed browser executable`);
  return path;
}

async function inspectPublicPage(kind) {
  const browser = await puppeteer.launch({
    browser: "chrome",
    executablePath: browserPath(kind),
    headless: false,
    enableExtensions: true,
    args: ["--window-position=-32000,-32000", "--window-size=1280,900"],
    timeout: 20_000
  });
  try {
    const extensionId = await browser.installExtension(extensionPath);
    const extension = (await browser.extensions()).get(extensionId);
    assert.equal(extension?.name, "AEGIS Browser", `${kind}: the preview installs in an isolated profile`);
    const page = await browser.newPage();
    const response = await page.goto("https://www.iana.org/help/example-domains", { waitUntil: "domcontentloaded", timeout: 30_000 });
    const domShape = await page.evaluate(() => ({
      hostname: location.hostname,
      hasHeading: Boolean(document.querySelector("h1")),
      linkCount: document.querySelectorAll("a[href]").length
    }));
    assert.equal(response?.status(), 200, `${kind}: public page returned HTTP 200`);
    assert.equal(domShape.hostname, "www.iana.org", `${kind}: reached the public test origin without redirect`);
    assert.equal(domShape.hasHeading, true, `${kind}: the live page contains a heading element`);
    assert.ok(domShape.linkCount > 0, `${kind}: the live page contains a navigable link`);

    const popupTargetPromise = browser.waitForTarget(
      (target) => target.type() === "page" && target.url() === `chrome-extension://${extensionId}/popup.html`,
      { timeout: 10_000 }
    );
    await extension.triggerAction(page);
    const popup = await (await popupTargetPromise).asPage();
    await popup.waitForSelector("#analyzePage");
    await popup.click("#analyzePage");
    await popup.waitForFunction(() => /concluída/i.test(document.querySelector("#status")?.textContent ?? ""), { timeout: 10_000 });
    process.stdout.write(`${kind}: live DOM analysis passed on ${domShape.hostname}; HTTP ${response.status()}, h1=${domShape.hasHeading}, links=${domShape.linkCount}. No page text or URLs were recorded.\n`);
  } finally {
    await browser.close();
  }
}

for (const kind of ["chrome", "edge"]) await inspectPublicPage(kind);
