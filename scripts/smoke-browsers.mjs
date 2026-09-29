import assert from "node:assert/strict";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { build } from "esbuild";
import puppeteer from "puppeteer-core";

const root = process.cwd();
const extensionPath = resolve(root, "dist");
const secretMarker = "AEGIS-E2E-PASSWORD-MUST-NOT-BE-READ";
const qrFixtureSvg = await readFile(resolve(root, "tests/fixtures/qr-login.svg"), "utf8");
const pageMarkup = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Microsoft account verification</title></head><body><main><h1>Microsoft account verification</h1><p>Urgent: confirm your password now or your account will be suspended.</p><form id="credential-form" action="https://collector.example/submit" method="post"><label>Password <input type="password" name="password" value="${secretMarker}"></label><button type="submit">Continue</button></form><a id="spoofed-link" title="Original link description" href="https://account-security.example/login">https://login.microsoft.com</a></main></body></html>`;
const emailAdapterBundle = (await build({
  entryPoints: [resolve(root, "src/email/providers.js")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome120",
  write: false,
  logLevel: "silent"
})).outputFiles[0].text;
const emailAnalyzerBundle = (await build({
  entryPoints: [resolve(root, "src/email/email-analyzer.js")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome120",
  write: false,
  logLevel: "silent"
})).outputFiles[0].text;
const pageAnalyzerBundle = (await build({
  entryPoints: [resolve(root, "src/web/page-analyzer.js")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome120",
  write: false,
  logLevel: "silent"
})).outputFiles[0].text;
const searchResultsBundle = (await build({
  entryPoints: [resolve(root, "src/web/search-results.js")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome120",
  write: false,
  logLevel: "silent"
})).outputFiles[0].text;
const quishingAnalyzerBundle = (await build({
  entryPoints: [resolve(root, "src/content/quishing-analyzer.js")],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome120",
  write: false,
  logLevel: "silent"
})).outputFiles[0].text;
const emailFixtures = {
  gmail: `<!doctype html><main role="main"><section class="gmail-message"><span email="analyst@mailer.example.test" name="Analyst Desk"></span><h1 data-thread-perm-id="thread-1">Gmail account notification</h1><div class="a3s aiL">Please review the account update before Friday. <a href="https://portal.example.test/login">https://login.microsoft.com</a></div><span data-filename="invoice.pdf.exe" data-mime-type="application/octet-stream"></span></section><table><tbody><tr class="zA"><td><span email="sender@example.test" name="Example Sender"></span><span class="bog">Weekly statement</span><span>Billing update details</span></td></tr></tbody></table></main>`,
  outlook: `<!doctype html><main role="main"><section class="outlook-message"><span data-email="billing@vendor.example.test" name="Vendor Billing"></span><h2 role="heading">Invoice review</h2><div aria-label="Corpo da mensagem">Please review the invoice details and contact the vendor with questions. <a href="https://billing.example.test/invoice">Open invoice details</a></div><span aria-label="Anexo invoice.pdf.exe" data-content-type="application/x-msdownload"></span></section><div role="option" data-testid="message-item"><span data-email="sender@vendor.example.test" name="Vendor Sender"></span><h3 data-testid="subject">Payment schedule</h3><span>Updated payment schedule details</span></div></main>`,
  generic: `<!doctype html><main role="main"><section class="generic-message"><span data-email="notice@service.example.test" name="Service Notice"></span><h2 role="heading">Account summary</h2><div data-testid="generic-message-body">Your monthly account summary is ready to review. <a href="https://service.example.test/summary">Open account summary</a></div></section><div role="listitem" data-message-id="msg-1"><span data-email="news@service.example.test" name="Service News"></span><h3 data-testid="subject">Monthly update</h3><span>Product news and account details</span></div></main>`
};

function browserCandidates(kind) {
  const override = process.env[`AEGIS_${kind.toUpperCase()}_PATH`];
  if (override) return [resolve(override)];
  if (process.platform === "win32") {
    return kind === "chrome"
      ? [
          "C:/Program Files/Google/Chrome/Application/chrome.exe",
          "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"
        ]
      : [
          "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
          "C:/Program Files/Microsoft/Edge/Application/msedge.exe"
        ];
  }
  if (process.platform === "darwin") {
    return kind === "chrome"
      ? ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
      : ["/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"];
  }
  return kind === "chrome"
    ? ["/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"]
    : ["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"];
}

function findBrowser(kind) {
  const executablePath = browserCandidates(kind).find(existsSync);
  assert.ok(executablePath, `Set AEGIS_${kind.toUpperCase()}_PATH to an installed ${kind} executable`);
  return executablePath;
}

async function smokeEmailAdapters(browser, baseUrl, kind) {
  const page = await browser.newPage();
  try {
    await page.goto(`${baseUrl}/synthetic-webmail`, { waitUntil: "domcontentloaded" });
    const metricsBefore = await page.metrics();
    const { results, timings, pageAnalysisTiming } = await page.evaluate(async (adapterModuleUrl, emailAnalyzerModuleUrl, pageAnalyzerModuleUrl, fixtures) => {
      const { createEmailProviderAdapter } = await import(adapterModuleUrl);
      const { analyzeEmail } = await import(emailAnalyzerModuleUrl);
      const { analyzePageSnapshot, extractPageSnapshot } = await import(pageAnalyzerModuleUrl);
      const measure = (operation) => {
        const batchSize = 10;
        const sampleCount = 50;
        for (let index = 0; index < 50; index += 1) operation();
        const samples = [];
        for (let index = 0; index < sampleCount; index += 1) {
          const started = performance.now();
          for (let batch = 0; batch < batchSize; batch += 1) operation();
          samples.push((performance.now() - started) / batchSize);
        }
        samples.sort((left, right) => left - right);
        const percentile = (rank) => Number((samples[Math.ceil(samples.length * rank) - 1] ?? 0).toFixed(3));
        return { p50Ms: percentile(0.5), p95Ms: percentile(0.95) };
      };
      const rowSelectors = {
        gmail: "tr.zA",
        outlook: '[role="option"][data-testid="message-item"]',
        generic: '[role="listitem"][data-message-id]'
      };
      const results = [];
      const timings = {};
      for (const [provider, markup] of Object.entries(fixtures)) {
        const documentFixture = document.implementation.createHTMLDocument(`AEGIS ${provider} fixture`);
        documentFixture.body.innerHTML = markup;
        const adapter = createEmailProviderAdapter(provider);
        const opened = adapter.findOpenedMessage(documentFixture);
        const message = adapter.extractOpenedEmail(documentFixture, opened);
        const rows = adapter.extractInboxRows(documentFixture);
        results.push({
          provider,
          hasOpenedMessage: Boolean(opened),
          sender: message?.sender,
          subject: message?.subject,
          linkCount: message?.links.length,
          attachmentNames: message?.attachments.map((item) => item.filename),
          attachmentMetadata: message?.attachments,
          attachmentFindingIds: analyzeEmail(message ?? {}).signals.filter((signal) => signal.id === "ATTACHMENT_DOUBLE_EXTENSION").map((signal) => signal.id),
          rowCount: rows.length,
          inboxSender: rows[0]?.payload.sender.address
        });

        const benchmarkDocument = document.implementation.createHTMLDocument(`AEGIS ${provider} inbox benchmark`);
        benchmarkDocument.body.innerHTML = markup;
        const row = benchmarkDocument.querySelector(rowSelectors[provider]);
        if (row?.parentElement) for (let index = 1; index < 20; index += 1) row.parentElement.append(row.cloneNode(true));
        const inboxRowCount = adapter.extractInboxRows(benchmarkDocument).length;
        const openMessageAnalysis = () => {
          const openedMessage = adapter.findOpenedMessage(benchmarkDocument);
          return analyzeEmail(adapter.extractOpenedEmail(benchmarkDocument, openedMessage));
        };
        const inboxAnalysis = () => adapter.extractInboxRows(benchmarkDocument).map(({ payload }) => analyzeEmail(payload));
        timings[provider] = { inboxRows: inboxRowCount, openAnalysis: measure(openMessageAnalysis), inbox20Analysis: measure(inboxAnalysis) };
      }

      const benchmarkPage = document.implementation.createHTMLDocument("AEGIS synthetic page benchmark");
      benchmarkPage.body.innerHTML = "<main><h1>Account portal</h1><p>Review the account details.</p><a href='https://portal.example.test/overview'>Open overview</a></main>";
      const pageAnalysis = () => analyzePageSnapshot(extractPageSnapshot(benchmarkPage), "https://portal.example.test/");
      return { results, timings, pageAnalysisTiming: measure(pageAnalysis) };
    }, `${baseUrl}/email-adapters.mjs`, `${baseUrl}/email-analyzer.mjs`, `${baseUrl}/page-analyzer.mjs`, emailFixtures);
    const metricsAfter = await page.metrics();
    const taskDurationMs = Number((((metricsAfter.TaskDuration ?? 0) - (metricsBefore.TaskDuration ?? 0)) * 1000).toFixed(3));
    const heapDeltaBytes = (metricsAfter.JSHeapUsedSize ?? 0) - (metricsBefore.JSHeapUsedSize ?? 0);
    const imageOnly = await page.evaluate(async (adapterModuleUrl) => {
      const { createEmailProviderAdapter } = await import(adapterModuleUrl);
      const fixture = document.implementation.createHTMLDocument("AEGIS image-only Gmail fixture");
      fixture.body.innerHTML = '<main role="main"><section><div class="a3s aiL"><img alt="QR"></div></section></main>';
      const adapter = createEmailProviderAdapter("gmail");
      const opened = adapter.findOpenedMessage(fixture);
      return { opened: Boolean(opened), imageCount: opened ? adapter.findQrImages(fixture, opened).length : 0 };
    }, `${baseUrl}/email-adapters.mjs`);

    assert.equal(results.length, 3, `${kind}: all provider fixtures are exercised`);
    assert.deepEqual(imageOnly, { opened: true, imageCount: 1 }, `${kind}: image-only Gmail messages reach QR extraction`);
    for (const result of results) {
      assert.equal(result.hasOpenedMessage, true, `${kind}: ${result.provider} identifies the opened message`);
      assert.equal(result.linkCount, 1, `${kind}: ${result.provider} extracts message links`);
      assert.equal(result.rowCount, 1, `${kind}: ${result.provider} extracts one inbox row`);
      assert.ok(result.sender.address.includes("@"), `${kind}: ${result.provider} normalizes sender identity`);
      assert.ok(result.subject, `${kind}: ${result.provider} extracts the subject`);
    }
    assert.ok(results.find((item) => item.provider === "gmail").attachmentNames.includes("invoice.pdf.exe"));
    assert.deepEqual(results.find((item) => item.provider === "gmail").attachmentMetadata[0], {
      filename: "invoice.pdf.exe", extension: "exe", mimeType: "application/octet-stream"
    });
    assert.deepEqual(results.find((item) => item.provider === "outlook").attachmentMetadata[0], {
      filename: "invoice.pdf.exe", extension: "exe", mimeType: "application/x-msdownload"
    });
    assert.deepEqual(results.find((item) => item.provider === "generic").attachmentMetadata, []);
    assert.deepEqual(results.find((item) => item.provider === "gmail").attachmentFindingIds, ["ATTACHMENT_DOUBLE_EXTENSION"]);
    assert.deepEqual(results.find((item) => item.provider === "outlook").attachmentFindingIds, ["ATTACHMENT_DOUBLE_EXTENSION"]);
    assert.deepEqual(results.find((item) => item.provider === "generic").attachmentFindingIds, []);
    assert.equal(results.find((item) => item.provider === "gmail").inboxSender, "sender@example.test");
    assert.equal(results.find((item) => item.provider === "outlook").inboxSender, "sender@vendor.example.test");
    assert.equal(results.find((item) => item.provider === "generic").inboxSender, "news@service.example.test");
    for (const provider of ["gmail", "outlook", "generic"]) assert.equal(timings[provider].inboxRows, 20, `${kind}: ${provider} benchmark analyzes 20 synthetic inbox rows`);
    const timing = (sample) => `p50=${sample.p50Ms}ms/p95=${sample.p95Ms}ms`;
    const browserVersion = await browser.version();
    process.stdout.write(`${kind}: synthetic browser benchmark on ${browserVersion}; open+analysis ${Object.entries(timings).map(([provider, value]) => `${provider} ${timing(value.openAnalysis)}`).join(", ")}; inbox-20 ${Object.entries(timings).map(([provider, value]) => `${provider} ${timing(value.inbox20Analysis)}`).join(", ")}; page analysis ${timing(pageAnalysisTiming)}; task ${taskDurationMs}ms; JS heap delta ${heapDeltaBytes} bytes.\n`);

    const bitbResults = await page.evaluate(async (moduleUrl) => {
      const { analyzePageSnapshot, extractPageSnapshot } = await import(moduleUrl);
      const fakeChrome = `<main><h1>Example service</h1><p>Use the account portal to review your profile details.</p></main><div role="dialog" aria-modal="true" style="position:fixed;left:25%;top:20%;width:440px;height:300px;background:white;border:1px solid #777"><header><button aria-label="Minimize">−</button><button aria-label="Maximize">□</button><button aria-label="Close">×</button></header><div class="address-bar">https://accounts.google.com</div><iframe title="Sign in with Google"></iframe></div>`;
      document.body.innerHTML = fakeChrome;
      const fake = analyzePageSnapshot(extractPageSnapshot(document), location.href);
      const normalOAuth = `<main><h1>Example service</h1><p>Use the account portal to review your profile details.</p></main><div role="dialog" aria-modal="true" style="position:fixed;left:30%;top:25%;width:420px;height:260px;background:white"><button aria-label="Close">×</button><iframe title="Sign in with organization"></iframe></div>`;
      document.body.innerHTML = normalOAuth;
      const legitimate = analyzePageSnapshot(extractPageSnapshot(document), location.href);
      const unlabelledFakeChrome = `<main><h1>Example service</h1><p>Use the account portal to review your profile details.</p></main><div class="browser-window" style="position:fixed;left:25%;top:20%;width:440px;height:300px;background:white"><header><button aria-label="Minimize">−</button><button aria-label="Maximize">□</button><button aria-label="Close">×</button></header><div>https://accounts.example.test</div><iframe title="Authentication"></iframe></div>`;
      document.body.innerHTML = unlabelledFakeChrome;
      const unlabelled = analyzePageSnapshot(extractPageSnapshot(document), location.href);
      return {
        fake: { state: fake.decision.state, signals: fake.signals.map(({ id, severity }) => ({ id, severity })), finding: fake.signals.find((item) => item.id === "POSSIBLE_BITB") ?? null },
        legitimate: { state: legitimate.decision.state, finding: legitimate.signals.find((item) => item.id === "POSSIBLE_BITB") ?? null },
        unlabelled: { finding: unlabelled.signals.find((item) => item.id === "POSSIBLE_BITB") ?? null }
      };
    }, `${baseUrl}/page-analyzer.mjs`);
    assert.equal(bitbResults.fake.finding?.severity, 0, `${kind}: suspected BitB is contextual, never an automatic accusation`);
    assert.equal(bitbResults.fake.state, "GREEN", `${kind}: BitB alone does not raise risk state (${JSON.stringify(bitbResults.fake)})`);
    assert.equal(bitbResults.legitimate.finding, null, `${kind}: a regular OAuth dialog is not labeled BitB`);
    assert.ok(bitbResults.unlabelled.finding, `${kind}: a browser-like overlay without ARIA roles is considered`);
    const searchResults = await page.evaluate(async (searchModuleUrl, analyzerModuleUrl) => {
      const { extractSearchResults } = await import(searchModuleUrl);
      const { analyzeSearchResult } = await import(analyzerModuleUrl);
      const google = document.implementation.createHTMLDocument("Google results");
      google.body.innerHTML = '<div id="search"><div class="MjjYud"><a href="https://micros0ft-login.example/verify"><h3>Microsoft account security</h3></a><p>Urgent: confirm your password now.</p></div><div class="MjjYud"><a href="https://example.org/docs"><h3>Product documentation</h3></a><p>Technical reference.</p></div></div>';
      const bing = document.implementation.createHTMLDocument("Bing results");
      bing.body.innerHTML = '<ol id="b_results"><li class="b_algo"><h2><a href="https://support.example.org/article">Support article</a></h2><p>Normal troubleshooting guidance.</p></li></ol>';
      const googleItems = extractSearchResults(google, "google");
      const bingItems = extractSearchResults(bing, "bing");
      return {
        googleCount: googleItems.length,
        bingCount: bingItems.length,
        riskyState: analyzeSearchResult(googleItems[0].payload).decision.state,
        normalState: analyzeSearchResult(bingItems[0].payload).decision.state
      };
    }, `${baseUrl}/search-results.mjs`, `${baseUrl}/page-analyzer.mjs`);
    assert.deepEqual(searchResults, { googleCount: 2, bingCount: 1, riskyState: "RED", normalState: "GREEN" }, `${kind}: Google/Bing DOM extraction and conservative risk classification pass`);
    const quishing = await page.evaluate(async (moduleUrl, fixtureUrl) => {
      const { scanQrImages } = await import(moduleUrl);
      const supported = typeof globalThis.BarcodeDetector === "function"
        ? await globalThis.BarcodeDetector.getSupportedFormats().then((formats) => ({ available: true, qrSupported: formats.includes("qr_code") })).catch(() => ({ available: false, qrSupported: false }))
        : { available: false, qrSupported: false };
      const image = new Image();
      image.src = fixtureUrl;
      await image.decode();
      const result = await scanQrImages([image], null);
      return { supported, result };
    }, `${baseUrl}/quishing-analyzer.mjs`, `${baseUrl}/qr-login.svg`);
    assert.equal(quishing.result.status, "scanned", `${kind}: bundled local decoder processes a real QR image`);
    assert.deepEqual(quishing.result.urls, ["https://login.example.test/verify"], `${kind}: local decoder returns only validated Web URLs`);
    process.stdout.write(`${kind}: BarcodeDetector available=${quishing.supported.available}, QR support=${quishing.supported.qrSupported}; bundled local decoder passed.\n`);
    process.stdout.write(`${kind}: synthetic Gmail, Outlook, and generic adapter extraction passed.\n`);
  } finally {
    await page.close();
  }
}

async function smokeBrowser(kind, fixtureUrl) {
  const executablePath = findBrowser(kind);
  process.stdout.write(`${kind}: launching isolated browser.\n`);
  const browser = await puppeteer.launch({
    browser: "chrome",
    executablePath,
    headless: false,
    enableExtensions: true,
    args: ["--window-position=-32000,-32000", "--window-size=1280,900"],
    timeout: 20_000
  });

  try {
    const extensionId = await browser.installExtension(extensionPath);
    process.stdout.write(`${kind}: extension installed.\n`);
    const extension = (await browser.extensions()).get(extensionId);
    assert.equal(extension?.name, "AEGIS Browser", `${kind}: unpacked MV3 extension installs`);

    const workerTarget = await browser.waitForTarget(
      (target) => target.type() === "service_worker" && target.url().startsWith(`chrome-extension://${extensionId}/`),
      { timeout: 15_000 }
    );
    assert.ok(workerTarget, `${kind}: extension service worker starts`);
    const workerNetworkSession = await workerTarget.createCDPSession();
    await workerNetworkSession.send("Network.enable");
    await workerNetworkSession.send("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 });
    const workerHttpOrigins = [];
    workerNetworkSession.on("Network.requestWillBeSent", ({ request }) => {
      if (/^https?:\/\//i.test(request.url)) {
        try { workerHttpOrigins.push(new URL(request.url).origin); } catch { workerHttpOrigins.push("invalid-url"); }
      }
    });

    const options = await browser.newPage();
    await options.goto(`chrome-extension://${extensionId}/options.html`, { waitUntil: "domcontentloaded" });
    await options.waitForSelector("#jevEnabled");
    const optionsLocalization = await options.evaluate(() => ({
      lang: document.documentElement.lang,
      title: document.querySelector("h1")?.textContent.trim(),
      emailProtection: document.querySelector("#emailProtection")?.closest("label")?.querySelector(".toggle-label")?.textContent.trim()
    }));
    assert.deepEqual(optionsLocalization, { lang: "pt-BR", title: "Controle de proteção", emailProtection: "Analisar Gmail e Outlook Web" }, `${kind}: settings page consumes the default locale catalog`);
    await options.waitForFunction(() => document.querySelector("#organizationKnowledgeBase")?.value.includes('"brands"'), { timeout: 5_000 });
    await options.waitForFunction(() => document.querySelector("#organizationModelStatus")?.textContent.startsWith("Sem modelo gerenciado"), { timeout: 5_000 });
    const response = await options.evaluate(() => new Promise((resolveMessage, rejectMessage) => {
      chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }, (result) => {
        if (chrome.runtime.lastError) rejectMessage(new Error(chrome.runtime.lastError.message));
        else resolveMessage(result);
      });
    }));

    assert.equal(response?.ok, true, `${kind}: settings page can reach the service worker`);
    assert.deepEqual(response.managedKeys, [], `${kind}: no enterprise policy is injected into the isolated test profile`);
    assert.equal(response.settings.jevEnabled, false, `${kind}: Jev defaults to OFF`);
    assert.equal(response.settings.privacyMode, "STRICT", `${kind}: strict privacy is the default`);
    assert.equal(response.settings.connectionMode, "gateway", `${kind}: gateway is the default provider`);
    assert.equal(await options.$eval("#contextMenu", (node) => node.checked), false, `${kind}: context-menu permission is opt-in`);
    assert.equal(response.settings.sessionIntelligence, false, `${kind}: local session intelligence defaults to OFF`);

    const optionalPermissions = await options.evaluate(async () => ({
      email: await chrome.permissions.contains({ origins: ["https://mail.google.com/*", "https://outlook.office.com/*", "https://outlook.live.com/*"] }),
      web: await chrome.permissions.contains({ origins: ["http://*/*", "https://*/*"] }),
      contextMenu: await chrome.permissions.contains({ permissions: ["contextMenus"] })
    }));
    assert.deepEqual(optionalPermissions, { email: false, web: false, contextMenu: false }, `${kind}: optional host and context-menu permissions start ungranted`);

    await options.click("#contextMenu");
    await options.waitForFunction(async () => {
      const current = await new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }, resolveMessage));
      return current.settings.contextMenu && await chrome.permissions.contains({ permissions: ["contextMenus"] });
    }, { timeout: 10_000 });
    await options.waitForFunction(() => document.querySelector("#status")?.textContent.includes("ativa"), { timeout: 10_000 });
    // Chromium has no contextMenus.getAll API; the missing-ID removal is a negative control.
    const absentMenu = await workerNetworkSession.send("Runtime.evaluate", {
      expression: `new Promise((resolveMenu) => chrome.contextMenus.remove("aegis-absent-probe", () => resolveMenu({ missingItemReported: Boolean(chrome.runtime.lastError) })))`,
      awaitPromise: true,
      returnByValue: true
    });
    assert.deepEqual(absentMenu.result?.value, { missingItemReported: true }, `${kind}: the menu API reports an absent item before the registered item is probed`);
    const menuRegistration = await workerNetworkSession.send("Runtime.evaluate", {
      expression: `new Promise((resolveMenu) => chrome.contextMenus.remove("aegis-analyze-link", () => { const removeError = chrome.runtime.lastError?.message ?? null; chrome.contextMenus.create({ id: "aegis-analyze-link", title: "Analisar link com AEGIS", contexts: ["link"] }, () => resolveMenu({ removeError, createError: chrome.runtime.lastError?.message ?? null })); }))`,
      awaitPromise: true,
      returnByValue: true
    });
    assert.deepEqual(menuRegistration.result?.value, { removeError: null, createError: null }, `${kind}: the optional context-menu item is created by the real extension service worker`);
    await options.click("#contextMenu");
    await options.waitForFunction(async () => {
      const current = await new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }, resolveMessage));
      return !current.settings.contextMenu && !await chrome.permissions.contains({ permissions: ["contextMenus"] });
    }, { timeout: 10_000 });
    process.stdout.write(`${kind}: context-menu permission granted and revoked through the options UI; menu item registration verified in the service worker.\n`);

    await options.$eval("#sessionIntelligence", (node) => { node.checked = true; node.dispatchEvent(new Event("change", { bubbles: true })); });
    await options.evaluate(() => document.querySelector("#saveSettings").click());
    await options.waitForFunction(() => document.querySelector("#status")?.textContent.startsWith("Configurações salvas"), { timeout: 10_000 });
    const enabledByUi = await options.evaluate(() => new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }, resolveMessage)));
    assert.equal(enabledByUi.settings.sessionIntelligence, true, `${kind}: options UI persists an explicit session-intelligence opt-in`);

    await options.$eval("#organizationKnowledgeBase", (node) => {
      node.value = JSON.stringify({ brands: [{ name: "Example Organization", terms: ["Example Organization"], domains: ["organization.example.test"] }], ssoDomains: ["sso.organization.example.test"], vendorDomains: [], financialDomains: [], internalDomains: ["intranet"] });
    });
    await options.click("#saveOrganizationKnowledgeBase");
    await options.waitForFunction(() => document.querySelector("#status")?.textContent.includes("validada e salva"), { timeout: 5_000 });
    const organizationSettings = await options.evaluate(() => new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }, resolveMessage)));
    assert.equal(organizationSettings.settings.organizationKnowledgeBase.brands[0].name, "Example Organization", `${kind}: organization knowledge base saves after validation`);
    assert.equal(organizationSettings.settings.organizationKnowledgeBase.internalDomains[0], "intranet", `${kind}: internal service hosts are accepted`);

    const sessionToggleBeforeSave = await options.$eval("#sessionIntelligence", (node) => ({ checked: node.checked, disabled: node.disabled }));
    assert.deepEqual(sessionToggleBeforeSave, { checked: true, disabled: false }, `${kind}: session intelligence toggle is editable before save`);
    const enabledPatterns = await options.evaluate(() => new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }, resolveMessage)));
    assert.equal(enabledPatterns.settings.sessionIntelligence, true, `${kind}: saved session intelligence is reported by the service worker`);

    const page = await browser.newPage();
    await page.goto(fixtureUrl, { waitUntil: "domcontentloaded" });
    const popupTargetPromise = browser.waitForTarget(
      (target) => target.type() === "page" && target.url() === `chrome-extension://${extensionId}/popup.html`,
      { timeout: 10_000 }
    );
    await extension.triggerAction(page);
    const popupTarget = await popupTargetPromise;
    const popup = await popupTarget.asPage();
    await popup.waitForSelector("#analyzePage");
    const popupLocalization = await popup.evaluate(() => ({
      lang: document.documentElement.lang,
      analyze: document.querySelector("#analyzePage")?.textContent.trim(),
      urlLabel: document.querySelector("#urlInput")?.getAttribute("aria-label")
    }));
    assert.deepEqual(popupLocalization, { lang: "pt-BR", analyze: "Analisar esta página", urlLabel: "Endereço para analisar" }, `${kind}: popup consumes translated text and attributes`);
    await popup.click("#analyzePage");
    await popup.waitForFunction(() => document.querySelector("#status")?.textContent.includes("concluída"), { timeout: 10_000 });
    await page.waitForFunction(() => document.querySelector("[data-aegis-root]")?.shadowRoot?.textContent.includes("fortes sinais de risco"), { timeout: 10_000 });
    await page.waitForFunction(() => document.querySelector("#spoofed-link")?.getAttribute("data-aegis-risk-link") === "mismatch", { timeout: 10_000 });
    const storedSourceOrigin = await options.evaluate(async () => {
      const { "aegis.latestTab": latestTab } = await chrome.storage.session.get("aegis.latestTab");
      if (!Number.isInteger(latestTab)) return null;
      const key = `aegis.analysis.${latestTab}`;
      return (await chrome.storage.session.get(key))[key]?.sourceOrigin ?? null;
    });
    assert.equal(storedSourceOrigin, new URL(fixtureUrl).origin, `${kind}: session analysis retains only its source origin for revocation cleanup`);

    await popup.$eval("#urlInput", (input) => { input.value = "https://portal.example.test/login?access_token=manual-only-secret&next=%2Fhome#session-fragment"; });
    await popup.$eval("#urlForm", (form) => form.requestSubmit());
    await popup.waitForFunction(() => document.querySelector("#urlResult")?.textContent.includes("Nenhuma página foi aberta."), { timeout: 5_000 });
    await popup.waitForFunction(() => document.querySelector("#riskTitle")?.textContent === "Atenção", { timeout: 5_000 });
    const manualUrlReport = await popup.evaluate(() => ({ result: document.querySelector("#urlResult")?.textContent ?? "", findings: document.querySelector("#findings")?.textContent ?? "" }));
    assert.match(manualUrlReport.result, /Domínio analisado: example\.test/);
    assert.equal(manualUrlReport.result.includes("manual-only-secret"), false, `${kind}: manual URL result does not expose query values`);
    assert.equal(manualUrlReport.findings.includes("manual-only-secret"), false, `${kind}: manual URL findings do not expose query values`);
    await popup.$eval("#urlInput", (input) => { input.value = ""; });
    process.stdout.write(`${kind}: manual URL analysis is local, redacted, and does not visit the destination.\n`);

    const warning = await page.evaluate(() => document.querySelector("[data-aegis-root]")?.shadowRoot?.textContent ?? "");
    assert.match(warning, /Esta página apresenta fortes sinais de risco/);
    const initialDialogAccessibility = await page.evaluate(() => {
      const shadow = document.querySelector("[data-aegis-root]")?.shadowRoot;
      const dialog = shadow?.querySelector('[role="alertdialog"]');
      const description = (dialog?.getAttribute("aria-describedby") ?? "").split(/\s+/).map((id) => shadow?.getElementById(id)?.textContent ?? "").join(" ");
      return {
        labelled: Boolean(dialog?.getAttribute("aria-labelledby") && shadow?.getElementById(dialog.getAttribute("aria-labelledby"))?.textContent.trim()),
        hasModalSemantics: dialog?.getAttribute("aria-modal") === "true",
        describesDestination: description.includes("Destino:"),
        cancel: shadow?.querySelector(".cancel")?.textContent.trim(),
        continue: shadow?.querySelector(".continue")?.textContent.trim()
      };
    });
    assert.deepEqual(initialDialogAccessibility, {
      labelled: true, hasModalSemantics: true, describesDestination: true,
      cancel: "Cancelar", continue: "Continuar mesmo assim"
    }, `${kind}: risk dialog exposes localized labels, modal state, and destination to assistive technology`);
    const linkHint = await page.$eval("#spoofed-link", (anchor) => ({ title: anchor.title, description: anchor.getAttribute("aria-description") }));
    assert.equal(linkHint.title, "O endereço mostrado na mensagem é diferente do endereço real para onde este link leva.");
    assert.equal(linkHint.description, "AEGIS: O endereço mostrado na mensagem é diferente do endereço real para onde este link leva.");

    const submissionBlocked = await page.evaluate(() => {
      const form = document.querySelector("#credential-form");
      form.querySelector("input[type='password']").focus();
      const event = new Event("submit", { bubbles: true, cancelable: true });
      return !form.dispatchEvent(event);
    });
    assert.equal(submissionBlocked, true, `${kind}: high-risk credential submission is blocked from the focused form pending explicit confirmation`);
    const linkBlocked = await page.evaluate(() => {
      const event = new MouseEvent("click", { bubbles: true, cancelable: true, view: window });
      return !document.querySelector("#spoofed-link").dispatchEvent(event);
    });
    assert.equal(linkBlocked, true, `${kind}: a mismatched link is blocked pending explicit confirmation`);
    const linkDialogLabel = await page.$eval("[data-aegis-root]", (host) => host.shadowRoot.querySelector(".tag")?.textContent);
    assert.equal(linkDialogLabel, "DIVERGÊNCIA DE LINK", `${kind}: link mismatch is not presented as confirmed high risk`);
    const dialogKeyboard = await page.evaluate(() => {
      const host = document.querySelector("[data-aegis-root]");
      const shadow = host?.shadowRoot;
      shadow?.querySelector(".continue")?.focus();
      shadow?.activeElement?.dispatchEvent(new KeyboardEvent("keydown", { key: "Tab", bubbles: true, composed: true }));
      const focusAfterTab = shadow?.activeElement?.className;
      shadow?.activeElement?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, composed: true }));
      return { focusAfterTab, isClosed: !host?.isConnected, restoredFocusId: document.activeElement?.id };
    });
    assert.equal(dialogKeyboard.focusAfterTab, "cancel", `${kind}: warning dialog keeps keyboard focus inside`);
    assert.equal(dialogKeyboard.isClosed, true, `${kind}: Escape always dismisses the warning`);
    assert.equal(dialogKeyboard.restoredFocusId, "spoofed-link", `${kind}: closing the warning restores focus to the link that triggered it`);
    const formContinuation = await page.evaluate(() => {
      const form = document.querySelector("#credential-form");
      const password = form.querySelector("input[type='password']");
      password.focus();
      let submissionObserved = false;
      form.addEventListener("submit", (event) => { submissionObserved = true; event.preventDefault(); }, { once: true });
      const blockedEvent = new Event("submit", { bubbles: true, cancelable: true });
      const blocked = !form.dispatchEvent(blockedEvent);
      const host = document.querySelector("[data-aegis-root]");
      host.shadowRoot.querySelector(".continue").click();
      return { blocked, submissionObserved, dialogClosed: !host.isConnected, restoredFocusName: document.activeElement?.getAttribute("name") };
    });
    assert.deepEqual(formContinuation, { blocked: true, submissionObserved: true, dialogClosed: true, restoredFocusName: "password" }, `${kind}: explicit confirmation resumes form submission and restores focus`);
    const linkContinuation = await page.evaluate(() => {
      const anchor = document.querySelector("#spoofed-link");
      const event = new MouseEvent("click", { bubbles: true, cancelable: true, view: window });
      anchor.dispatchEvent(event);
      const host = document.querySelector("[data-aegis-root]");
      let clickObserved = false;
      anchor.addEventListener("click", (clickEvent) => { clickObserved = true; clickEvent.preventDefault(); }, { capture: true, once: true });
      host.shadowRoot.querySelector(".continue").click();
      return { clickObserved, dialogClosed: !host.isConnected, restoredFocusId: document.activeElement?.id };
    });
    assert.deepEqual(linkContinuation, { clickObserved: true, dialogClosed: true, restoredFocusId: "spoofed-link" }, `${kind}: explicit confirmation resumes the intercepted link action`);
    process.stdout.write(`${kind}: local warning and link/form guards passed.\n`);

    const session = await workerTarget.worker().then((worker) => worker.evaluate(async () => chrome.storage.session.get(null)));
    assert.equal(JSON.stringify(session).includes(secretMarker), false, `${kind}: password input value is never stored`);
    assert.ok(session["aegis.patternKey"] && session["aegis.patternState"], `${kind}: local campaign state exists only after opt-in`);
    const persistedPatterns = JSON.stringify(session["aegis.patternState"]);
    assert.equal(persistedPatterns.includes("account-security.example"), false, `${kind}: session pattern state does not store cleartext domains`);
    assert.equal(persistedPatterns.includes("Microsoft"), false, `${kind}: session pattern state does not store brand claims`);

    await page.evaluate(() => {
      document.querySelector("#spoofed-link").href = "https://login.microsoft.com/";
    });
    await page.waitForFunction(() => {
      const link = document.querySelector("#spoofed-link");
      return !link.hasAttribute("data-aegis-risk-link") && link.title === "Original link description";
    }, { timeout: 10_000 });
    process.stdout.write(`${kind}: href-only mutation restored the original link highlight and tooltip.\n`);
    await page.evaluate(() => {
      document.querySelector("[data-aegis-root]")?.remove();
      document.title = "Account portal";
      const main = document.createElement("main");
      main.innerHTML = `<h1>Account portal</h1><p>Routine account information is available.</p><a id="dynamic-link" href="https://account-security.example/login">Open account portal</a>`;
      document.body.replaceChildren(main);
      const linkText = main.querySelector("#dynamic-link").firstChild;
      linkText.data = "https://login.microsoft.com";
    });
    await page.waitForFunction(() => document.querySelector("#dynamic-link")?.getAttribute("data-aegis-risk-link") === "mismatch", { timeout: 10_000 });
    process.stdout.write(`${kind}: replacing the main root and changing only a text node triggered fresh page analysis.\n`);

    const sidepanel = await browser.newPage();
    await sidepanel.goto(`chrome-extension://${extensionId}/sidepanel.html`, { waitUntil: "domcontentloaded" });
    process.stdout.write(`${kind}: side panel opened.\n`);
    assert.equal(await sidepanel.$eval("html", (node) => node.lang), "pt-BR", `${kind}: side panel resolves its document language`);
    await sidepanel.waitForFunction(() => document.querySelector("#mode")?.textContent === "JEV OFF", { timeout: 10_000 });
    await sidepanel.waitForFunction(() => {
      const metrics = [...document.querySelectorAll("#dashboardMetrics .metric")];
      const pages = metrics.find((item) => item.querySelector(".metric-label")?.textContent === "Páginas analisadas");
      return pages && Number(pages.querySelector(".metric-value")?.textContent) > 0;
    }, { timeout: 10_000 });
    const dashboardLabels = await sidepanel.$eval("#dashboardMetrics", (node) => node.textContent);
    assert.match(dashboardLabels, /Análises locais/);
    assert.match(dashboardLabels, /Análises Jev/);
    const fakeDecisionStored = await workerTarget.worker().then((worker) => worker.evaluate(async () => {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (!Number.isInteger(tab?.id)) return false;
      const answers = {
        classification: { choice: "CREDENTIAL_PHISHING_LIKELY", confidence: 0.76 },
        urgency: 0.81, credential_request: 0.94, process_bypass: 0.12, financial_action: 0.08,
        credential_risk: { score: 3.25, confidence: 0.64, legend: { "0": "None", "1": "Mention", "2": "Sign in", "3": "Enter secret", "4": "Send secret" } }
      };
      await chrome.storage.session.set({ [`aegis.analysis.${tab.id}`]: {
        analysisId: "test-feedback-analysis-1",
        state: "YELLOW", findings: [], riskVector: {}, surface: "email", senderDomain: "sender.example.test",
        links: [{ domain: "target.example.test", visibleDomain: "login.microsoft.com", mismatch: true, shortener: false, sensitiveParams: false, suspiciousParams: false }],
        engineStatus: { local: "active", jev: "connected" }, jev: { model: "jev-test", answers }
      } });
      return true;
    }));
    assert.equal(fakeDecisionStored, true, `${kind}: side panel test state is stored`);
    await sidepanel.waitForSelector("#feedbackCard:not([hidden])", { timeout: 5_000 });
    await sidepanel.waitForFunction(() => {
      const card = document.querySelector("#jevJudgmentsCard");
      return card && !card.hidden && card.textContent.includes("Risco de credenciais") && card.textContent.includes("3.25 / 4");
    }, { timeout: 10_000 });
    process.stdout.write(`${kind}: Jev judgment display passed.\n`);
    const separateVector = await sidepanel.$eval("#vectors", (node) => node.textContent);
    assert.equal(separateVector.includes("3.25"), false, `${kind}: Jev scores remain separate from local risk vectors`);
    assert.equal(await sidepanel.$eval("#mode", (node) => node.textContent), "JEV ON");
    const contextDetails = await sidepanel.$eval("#contextDetails", (node) => node.textContent);
    assert.match(contextDetails, /sender\.example\.test/);
    assert.match(contextDetails, /target\.example\.test/);
    assert.match(contextDetails, /O texto e o destino divergem/);
    await sidepanel.click('[data-feedback="falsePositive"]');
    await sidepanel.waitForFunction(() => document.querySelector("#feedbackStatus")?.textContent.includes("registrado localmente"), { timeout: 5_000 });
    await sidepanel.waitForFunction(() => {
      const item = [...document.querySelectorAll("#dashboardMetrics .metric")].find((metric) => metric.querySelector(".metric-label")?.textContent === "Falsos positivos");
      return item && item.querySelector(".metric-value")?.textContent === "1";
    }, { timeout: 5_000 });
    const dashboardStorage = await workerTarget.worker().then((worker) => worker.evaluate(async () => chrome.storage.local.get("aegis.localDashboard.v1")));
    const storedMetrics = dashboardStorage?.["aegis.localDashboard.v1"];
    assert.equal(storedMetrics?.days?.at(-1)?.feedback?.falsePositive, 1, `${kind}: feedback is persisted only as a local aggregate`);
    const feedbackStored = JSON.stringify(storedMetrics ?? {});
    assert.equal(feedbackStored.includes("test-feedback-analysis-1"), false, `${kind}: feedback counters are not linked to an analysis identifier`);
    assert.equal(feedbackStored.includes("sender.example.test"), false, `${kind}: dashboard stores no message or domain data`);
    const staleFeedback = await sidepanel.evaluate(() => new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_SUBMIT_FEEDBACK", kind: "phishing", tabId: -1, analysisId: "stale-analysis" }, resolveMessage)));
    assert.equal(staleFeedback.errorCode, "STALE_ANALYSIS", `${kind}: feedback is rejected when it refers to no current analysis`);
    await sidepanel.click("#clearDashboard");
    await sidepanel.waitForFunction(() => [...document.querySelectorAll("#dashboardMetrics .metric-value")].every((item) => item.textContent === "0"), { timeout: 5_000 });
    const clearedDashboard = await workerTarget.worker().then((worker) => worker.evaluate(async () => chrome.storage.local.get("aegis.localDashboard.v1")));
    assert.equal(clearedDashboard["aegis.localDashboard.v1"], undefined, `${kind}: dashboard data can be deleted from the UI`);
    process.stdout.write(`${kind}: aggregate dashboard, content-free feedback, stale-feedback guard, and local deletion passed.\n`);
    await sidepanel.close();
    await smokeEmailAdapters(browser, new URL(fixtureUrl).origin, kind);

    const disablePatternSetting = await options.evaluate(() => new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: { sessionIntelligence: false } }, resolveMessage)));
    assert.equal(disablePatternSetting.settings.sessionIntelligence, false, `${kind}: the local session feature can be disabled`);
    const clearedPatterns = await workerTarget.worker().then((worker) => worker.evaluate(async () => chrome.storage.session.get(["aegis.patternKey", "aegis.patternState"])));
    assert.equal(clearedPatterns["aegis.patternKey"], undefined, `${kind}: disabling session intelligence deletes its temporary key`);
    assert.equal(clearedPatterns["aegis.patternState"], undefined, `${kind}: disabling session intelligence deletes its HMAC records`);
    const finalSettings = await options.evaluate(() => new Promise((resolveMessage) => chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" }, resolveMessage)));
    assert.equal(finalSettings.settings.jevEnabled, false, `${kind}: Jev remains OFF through the full local protection suite`);
    assert.deepEqual(workerHttpOrigins, [], `${kind}: Jev-OFF service worker makes no HTTP/S requests during the full smoke suite`);
    process.stdout.write(`${kind}: install, offline Jev-OFF analysis, zero service-worker network requests, settings, link/form guards, feedback privacy, and input privacy passed.\n`);
  } finally {
    await browser.close();
  }
}

assert.ok(existsSync(resolve(extensionPath, "manifest.json")), "Build the extension before browser smoke tests");
const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
assert.ok(nodeMajor > 22 || nodeMajor === 22 && nodeMinor >= 12, "Browser smoke tests require Node.js 22.12 or newer");

const server = createServer((request, response) => {
  const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
  if (pathname === "/email-adapters.mjs") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
    response.end(emailAdapterBundle);
    return;
  }
  if (pathname === "/email-analyzer.mjs") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
    response.end(emailAnalyzerBundle);
    return;
  }
  if (pathname === "/page-analyzer.mjs") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
    response.end(pageAnalyzerBundle);
    return;
  }
  if (pathname === "/search-results.mjs") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
    response.end(searchResultsBundle);
    return;
  }
  if (pathname === "/quishing-analyzer.mjs") {
    response.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
    response.end(quishingAnalyzerBundle);
    return;
  }
  if (pathname === "/qr-login.svg") {
    response.writeHead(200, { "content-type": "image/svg+xml; charset=utf-8", "cache-control": "no-store" });
    response.end(qrFixtureSvg);
    return;
  }
  response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
  response.end(pathname === "/synthetic-webmail" ? "<!doctype html><html><head><meta charset=utf-8><title>Synthetic webmail</title></head><body></body></html>" : pageMarkup);
});
await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});
const fixtureUrl = `http://127.0.0.1:${server.address().port}/synthetic-phishing`;
try {
  await smokeBrowser("chrome", fixtureUrl);
  await smokeBrowser("edge", fixtureUrl);
} finally {
  await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()));
}
