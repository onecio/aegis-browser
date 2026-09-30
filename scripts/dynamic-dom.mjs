import assert from "node:assert/strict";
import { build } from "esbuild";
import { existsSync } from "node:fs";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import puppeteer from "puppeteer-core";

const executablePath = process.env.AEGIS_CHROME_PATH ?? [
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"
].find(existsSync);
assert.ok(executablePath, "Chrome executable is required");
const content = (await build({ entryPoints: ["src/content/content-script.js"], bundle: true, format: "iife", write: false })).outputFiles[0].text;
const engine = (await build({ stdin: { contents: 'export { analyzeEmail } from "./src/email/email-analyzer.js"; export { analyzePageSnapshot, analyzeSearchResult } from "./src/web/page-analyzer.js"; export { createEmailProviderAdapter } from "./src/email/providers.js"; export { extractSearchResults } from "./src/web/search-results.js";', resolveDir: process.cwd() }, bundle: true, format: "iife", globalName: "FixtureEngine", write: false })).outputFiles[0].text;
await mkdir("release/evolution-0.3.0", { recursive: true });
const messages = JSON.parse(await readFile("extension/_locales/pt_BR/messages.json", "utf8"));
const css = await readFile("extension/content.css", "utf8");
const browser = await puppeteer.launch({ executablePath, headless: true, args: ["--disable-extensions", "--no-first-run"] });
const runtimeEvidence = [];
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1000, height: 600 });
  await page.setRequestInterception(true);
  page.on("request", (request) => {
    if (request.isNavigationRequest()) {
      const rows = Array.from({ length: 60 }, (_, index) => `<tr class="zA" id="row-${index}"><td><span email="colleague@example.test">Colleague</span><span class="bog">Meeting ${index}</span><span class="y2">Routine minutes and unsubscribe preferences.</span></td></tr>`).join("");
      const searchRows = Array.from({ length: 60 }, (_, index) => `<div class="MjjYud"><div class="g b_algo" id="result-${index}"><a href="https://example.test/resource-${index}"><h3>Project documentation ${index}</h3></a><p>Routine project reference.</p></div></div>`).join("");
      const outlookRows = Array.from({ length: 60 }, (_, index) => `<div role="option" data-convid="${index}" id="row-${index}"><span title="colleague@example.test">Colleague</span><span data-testid="subject">Meeting ${index}</span><span data-testid="preview">Routine minutes and unsubscribe preferences.</span></div>`).join("");
      let body = `<table><tbody>${rows}</tbody></table>`;
      if (request.url().includes("/scoped-forms")) body = '<main><p>Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.</p><form id="benign-form" action="https://example.test/session"><p>Routine project access.</p><input type="password"></form><form id="risk-form" action="https://collector.example/submit"><p>Account entry.</p><input type="password"></form></main>';
      else if (request.url().includes("/long-page")) body = `<main><p>${"Routine project reference and meeting minutes. ".repeat(700)}</p><section id="end-risk"><p>Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.</p></section></main>`;
      else if (request.url().includes("/educational")) body = '<main><h1>Incident report</h1><p>Attack example: to verify you are human, open PowerShell, paste the command and press Enter. Do not run these commands.</p></main>';
      else if (request.url().includes("/clickfix")) body = '<main>Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.</main>';
      else if (request.url().includes("/search")) body = `<div id="tads"><div data-text-ad id="advertisement"><a href="https://www.google.com/aclk?adurl=https%3A%2F%2Fcollector.example%2Flogin"><h3>Verification</h3></a><p>Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.</p></div></div><div id="search">${searchRows}</div>`;
      else if (request.url().includes("/outlook")) body = `<main>${outlookRows}<section id="reading"><span title="notice@example.test">Notice</span><div data-testid="message-body">Routine notification with a link to project documentation.</div></section></main>`;
      else if (request.url().includes("/conversation")) body = '<main><article><span email="alice@example.test">Alice</span><div class="a3s aiL">Routine meeting agenda and minutes from Alice.</div></article><article><span email="bob@example.test">Bob</span><div class="a3s aiL">Routine project documentation and reference from Bob.</div></article></main>';
      else if (request.url().includes("/bing")) body = `<ul id="b_results">${Array.from({ length: 60 }, (_, index) => `<li class="b_algo" id="result-${index}"><h2><a href="https://www.bing.com/ck/a?u=a1${btoa(`https://example.test/resource-${index}`)}">Project documentation ${index}</a></h2><p>Routine reference.</p></li>`).join("")}</ul>`;
      void request.respond({ status: 200, contentType: "text/html", body: `<!doctype html><html><head><meta charset="utf-8"></head><body><input id="focus-target">${body}</body></html>` });
    } else void request.abort();
  });
  await page.goto("https://mail.google.com/aegis-synthetic-fixture");
  const initializeFixture = (engineCode, contentCode, stylesheet, catalog) => {
    // The transport is a controlled local test double; this is not a live Jev test.
    // eslint-disable-next-line no-eval -- Execute the bundled fixture engine in the isolated browser test context.
    (0, eval)(engineCode);
    const sheet = new CSSStyleSheet();
    sheet.replaceSync("tr,[role='option']{min-height:48px;height:48px}.g,li.b_algo{min-height:100px} .y2{display:block}#reading{position:fixed;top:30px;left:600px;width:300px;background:white}" + stylesheet);
    document.adoptedStyleSheets = [sheet];
    globalThis.fixtureRequests = 0;
    globalThis.fixtureMessages = [];
    globalThis.fixtureDelay = false;
    globalThis.fixtureFailure = false;
    globalThis.fixturePayloads = [];
    globalThis.fixtureConcurrent = 0;
    globalThis.fixtureMaximumConcurrent = 0;
    globalThis.fixtureLongTasks = [];
    if (globalThis.PerformanceObserver?.supportedEntryTypes?.includes("longtask")) {
      new PerformanceObserver((entries) => globalThis.fixtureLongTasks.push(...entries.getEntries().map(({ duration }) => Math.round(duration)))).observe({ type: "longtask" });
    }
    globalThis.chrome = {
      i18n: { getMessage: (key, substitutions) => (catalog[key]?.message ?? key).replace(/\$(\d+)/g, (_match, index) => substitutions?.[Number(index) - 1] ?? "") },
      runtime: {
        onMessage: { addListener: (handler) => globalThis.fixtureMessages.push(handler) },
        sendMessage: async (message) => {
          globalThis.fixtureRequests += 1;
          globalThis.fixturePayloads.push(message);
          if (globalThis.fixtureFailure) return { ok: false, errorCode: "FIXTURE_OFFLINE" };
          if (message.type === "AEGIS_ANALYZE_PAGE") return { ok: true, analysisId: "fixture-page", decision: globalThis.FixtureEngine.analyzePageSnapshot(message.payload, location.href).decision };
          if (message.type === "AEGIS_ANALYZE_EMAIL") {
            const analysis = globalThis.FixtureEngine.analyzeEmail(message.payload);
            return { ok: true, analysisId: "fixture-email", decision: analysis.decision, links: analysis.links };
          }
          globalThis.fixtureConcurrent += 1;
          globalThis.fixtureMaximumConcurrent = Math.max(globalThis.fixtureMaximumConcurrent, globalThis.fixtureConcurrent);
          const results = (message.payloads ?? []).map((payload, index) => {
            const decision = (message.type === "AEGIS_TRIAGE_SEARCH_RESULTS" ? globalThis.FixtureEngine.analyzeSearchResult(payload) : globalThis.FixtureEngine.analyzeEmail(payload)).decision;
            return { ...decision, index, kind: decision.state === "RED" ? "phishing" : "review" };
          });
          if (globalThis.fixtureDelay) await new Promise((resolve) => { globalThis.fixtureRelease = resolve; });
          globalThis.fixtureConcurrent -= 1;
          return { ok: true, results };
        }
      }
    };
    document.querySelector("#focus-target").focus();
    // eslint-disable-next-line no-eval -- Exercise the actual bundled content entrypoint in the isolated fixture.
    (0, eval)(contentCode);
  };
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForFunction(() => globalThis.fixtureRequests > 0);
  assert.equal(await page.$$eval("[data-aegis-row-label]", (nodes) => nodes.length), 0, "routine inbox stays visually clean");
  await page.evaluate(() => {
    const row = document.querySelector("#row-40");
    row.querySelector(".y2").textContent = "Confirm your password immediately or your account will be suspended.";
    row.querySelector(".y2").insertAdjacentHTML("beforeend", ' <a href="https://collector.example/login">https://login.microsoft.com</a>');
    row.scrollIntoView();
  });
  await page.waitForSelector("#row-40 [data-aegis-row-label]");
  assert.equal(await page.$eval("#row-40", (node) => node.dataset.aegisRisk), "red", "scroll identifies a risky row beyond the initial twenty");
  assert.equal(await page.$eval("#focus-target", (node) => document.activeElement === node), true, "scroll does not steal keyboard focus");
  await page.screenshot({ path: "release/evolution-0.3.0/inbox-sanitized.png" });
  assert.equal(await page.$eval("#row-40", (node) => getComputedStyle(node).outlineStyle), "none", "native rows have no AEGIS outline");
  await page.evaluate(() => { document.querySelector("#row-40").classList.add("native-selected"); });
  await page.waitForSelector("#row-40 [data-aegis-row-label]");
  await page.evaluate(() => {
    document.querySelector("#row-40 .y2").textContent = "Routine project minutes and meeting agenda.";
  });
  await page.waitForFunction(() => !document.querySelector("#row-40 [data-aegis-row-label]"));
  await page.waitForFunction(() => globalThis.fixtureMaximumConcurrent === 1);
  await page.evaluate(() => {
    document.querySelector("#row-40 .y2").innerHTML = 'Confirm your password immediately. <a href="https://collector.example/login">https://login.microsoft.com</a>';
  });
  await page.waitForSelector("#row-40 [data-aegis-row-label]");
  await page.evaluate(() => { document.querySelector("#row-40 .y2").textContent = "Routine project minutes and meeting agenda."; });
  await page.waitForFunction(() => !document.querySelector("#row-40 [data-aegis-row-label]"));
  await page.evaluate(() => {
    globalThis.fixtureDelay = true;
    const snippet = document.querySelector("#row-40 .y2");
    snippet.innerHTML = 'Confirm your password immediately or your account will be closed. <a href="https://collector.example/login">https://login.microsoft.com</a>';
  });
  await page.waitForFunction(() => typeof globalThis.fixtureRelease === "function");
  await page.evaluate(() => {
    document.querySelector("#row-40 .y2").textContent = "Routine minutes of the next project meeting.";
    globalThis.fixtureDelay = false;
    globalThis.fixtureRelease();
  });
  await page.waitForFunction(() => !document.querySelector("#row-40 [data-aegis-row-label]"));
  await page.evaluate(() => {
    for (const listener of globalThis.fixtureMessages) listener({ type: "AEGIS_STOP_MONITORING" }, {}, () => {});
  });
  assert.equal(await page.$$eval("[data-aegis-row-label], [data-aegis-root]", (nodes) => nodes.length), 0);
  const pausedStatus = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_GET_MONITOR_STATUS" }, {}, resolve)));
  assert.equal(pausedStatus.monitoring, false);
  assert.equal(pausedStatus.surface, "gmail");
  await page.evaluate(() => { globalThis.fixtureFailure = true; });
  const offlineScan = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_REQUEST_SCAN" }, {}, resolve)));
  assert.equal(offlineScan.ok, false, "manual scan reports worker failure");
  assert.equal(offlineScan.errorCode, "FIXTURE_OFFLINE");
  const pausedAfterManual = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_GET_MONITOR_STATUS" }, {}, resolve)));
  assert.equal(pausedAfterManual.monitoring, false, "manual scan preserves the user's paused state");
  await page.evaluate(() => { globalThis.fixtureFailure = false; });
  const manualOnly = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_REQUEST_SCAN", continuousProtection: false }, {}, resolve)));
  assert.equal(manualOnly.ok, true);
  const manualOnlyStatus = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_GET_MONITOR_STATUS" }, {}, resolve)));
  assert.equal(manualOnlyStatus.manualOnly, true);
  assert.equal(manualOnlyStatus.markedItems, 0);
  await page.goto("https://outlook.live.com/outlook-fixture");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForFunction(() => globalThis.fixtureRequests >= 2);
  assert.ok(await page.evaluate(() => globalThis.fixturePayloads.some(({ type }) => type === "AEGIS_ANALYZE_EMAIL") && globalThis.fixturePayloads.some(({ type }) => type === "AEGIS_TRIAGE_EMAILS")), "reading pane and inbox are scanned independently");
  assert.equal(await page.evaluate(() => globalThis.fixturePayloads.find(({ type }) => type === "AEGIS_ANALYZE_EMAIL").payload.senderAddress), "notice@example.test", "Outlook reading-pane sender is not borrowed from an inbox row");
  await page.evaluate(() => {
    document.querySelector("#row-40 [data-testid='preview']").innerHTML = 'Confirm your password immediately. <a href="https://collector.example/login">https://login.microsoft.com</a>';
    document.querySelector("#row-40").scrollIntoView();
  });
  await page.waitForSelector("#row-40 [data-aegis-row-label]");
  await page.screenshot({ path: "release/evolution-0.3.0/outlook-sanitized.png" });
  await page.goto("https://mail.google.com/conversation-fixture");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForFunction(() => globalThis.fixturePayloads.filter(({ type }) => type === "AEGIS_ANALYZE_EMAIL").length === 2);
  const extractedMessages = await page.evaluate(() => globalThis.fixturePayloads.filter(({ type }) => type === "AEGIS_ANALYZE_EMAIL").map(({ payload }) => ({ sender: payload.senderAddress, body: payload.bodyText })));
  assert.deepEqual(extractedMessages.map(({ sender }) => sender), ["alice@example.test", "bob@example.test"]);
  assert.equal(extractedMessages[0].body.includes("Bob"), false, "conversation evidence is not fused across senders");
  await page.evaluate(() => { document.querySelectorAll(".a3s")[1].textContent = "Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter."; });
  await page.waitForSelector("article:nth-child(2) [data-aegis-row-label]");
  assert.equal(await page.$$eval("article:first-child [data-aegis-row-label]", (nodes) => nodes.length), 0, "opened-message risk stays scoped to the corresponding message");
  await page.goto("https://www.google.com/search?aegis=fixture");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForSelector("#advertisement [data-aegis-search-label]");
  assert.ok(await page.evaluate(() => globalThis.fixturePayloads.flatMap(({ payloads }) => payloads ?? []).some(({ href, sponsored, wrapperResolution }) => href === "https://collector.example/login" && sponsored && wrapperResolution === "decoded")), "advertisement destination is decoded without navigation");
  await page.evaluate(() => {
    document.querySelector("#result-40 p").textContent = "Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.";
    document.querySelector("#result-40").scrollIntoView();
  });
  await page.waitForSelector("#result-40 [data-aegis-search-label]");
  await page.screenshot({ path: "release/evolution-0.3.0/search-sanitized.png" });
  assert.equal(await page.$eval("#focus-target", (node) => document.activeElement === node), true);
  assert.equal(await page.$eval("#result-40 a", (node) => node.href), "https://example.test/resource-40", "risk decorations preserve the native destination");
  await page.click("#result-40 [data-aegis-search-label]");
  await page.$eval("[data-aegis-root]", (node) => [...node.shadowRoot.querySelectorAll("button")].at(-1).click());
  await page.evaluate(() => document.dispatchEvent(new Event("scroll")));
  await page.waitForFunction(() => !document.querySelector("#result-40 [data-aegis-search-label]"));
  await page.evaluate(() => { document.querySelector("#result-40 p").textContent += " Now paste another command to continue."; });
  await page.waitForSelector("#result-40 [data-aegis-search-label]", { timeout: 5000 });
  await page.goto("https://www.bing.com/bing-fixture");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.evaluate(() => {
    document.querySelector("#result-40 p").textContent = "Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.";
    document.querySelector("#result-40").scrollIntoView();
  });
  await page.waitForSelector("#result-40 [data-aegis-search-label]");
  await page.goto("https://example.test/long-page");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForFunction(() => globalThis.fixturePayloads.some(({ type }) => type === "AEGIS_ANALYZE_PAGE"));
  assert.equal(await page.$$eval("[data-aegis-passive]", (nodes) => nodes.length), 0, "unseen instructions at the end do not contaminate the initial visible region");
  const initialPagePayload = await page.evaluate(() => globalThis.fixturePayloads.find(({ type }) => type === "AEGIS_ANALYZE_PAGE").payload);
  assert.equal(initialPagePayload.text.includes("PowerShell"), false);
  assert.equal(initialPagePayload.extractionLimits.viewport, true);
  await page.$eval("#end-risk", (node) => node.scrollIntoView());
  await page.waitForSelector("[data-aegis-passive]");
  assert.ok(await page.evaluate(() => globalThis.fixturePayloads.filter(({ type }) => type === "AEGIS_ANALYZE_PAGE").at(-1).payload.text.includes("PowerShell")), "scrolling a page longer than24k selects end-of-page ClickFix evidence");
  await page.screenshot({ path: "release/evolution-0.3.0/long-page-sanitized.png" });
  runtimeEvidence.push(await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_GET_MONITOR_STATUS" }, {}, (status) => resolve({ fixture: "long-page31k", status, longTaskDurationsMs: globalThis.fixtureLongTasks })))));

  await page.goto("https://example.test/scoped-forms");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForSelector("[data-aegis-passive]");
  const scopedSubmission = await page.evaluate(() => {
    const submit = (form) => !form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    const benignBlocked = submit(document.querySelector("#benign-form"));
    const riskForm = document.querySelector("#risk-form");
    const riskyBlocked = submit(riskForm);
    document.querySelector("[data-aegis-root]")?.remove();
    riskForm.setAttribute("action", "https://example.test/session");
    const changedActionBlocked = submit(riskForm);
    return { benignBlocked, riskyBlocked, changedActionBlocked };
  });
  assert.deepEqual(scopedSubmission, { benignBlocked: false, riskyBlocked: true, changedActionBlocked: false }, "guards bind the exact risky form and reject stale action bindings; unrelated ClickFix does not block a routine form");
  await page.goto("https://example.test/educational");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForFunction(() => globalThis.fixtureRequests > 0);
  assert.equal(await page.$$eval("[data-aegis-passive]", (nodes) => nodes.length), 0, "visible educational narrative retains its explicit warning context");
  await page.goto("https://example.test/clickfix");
  await page.evaluate(initializeFixture, engine, content, css, messages);
  await page.waitForSelector("[data-aegis-passive]");
  assert.equal(await page.$eval("#focus-target", (node) => document.activeElement === node), true, "ClickFix warning remains passive");
  await page.screenshot({ path: "release/evolution-0.3.0/clickfix-sanitized.png" });
  assert.equal(await page.$eval("[data-aegis-passive]", (node) => node.shadowRoot.querySelectorAll("style").length), 0, "warning uses constructed stylesheets");
  await page.$eval("[data-aegis-passive]", (node) => node.shadowRoot.querySelectorAll("button")[1].click());
  assert.equal(await page.$$eval("[data-aegis-passive]", (nodes) => nodes.length), 0, "passive warning can be dismissed");
  await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_STOP_MONITORING" }, {}, resolve)));
  const pausedClickFix = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_REQUEST_SCAN", continuousProtection: true }, {}, resolve)));
  assert.equal(pausedClickFix.ok, true);
  assert.equal(await page.$$eval("[data-aegis-root], [data-aegis-row-label], [data-aegis-search-label]", (nodes) => nodes.length), 0, "paused manual ClickFix analysis does not create page warnings");
  await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_REQUEST_SCAN", continuousProtection: false }, {}, resolve)));
  const beforeMutationRequests = await page.evaluate(() => globalThis.fixtureRequests);
  await page.evaluate(() => { document.querySelector("main").textContent += " Paste another command to repair the browser."; document.dispatchEvent(new Event("scroll")); });
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(await page.evaluate(() => globalThis.fixtureRequests), beforeMutationRequests, "manual-only analysis leaves no continuous mutation or scroll scan");
  const disabledResume = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_RESUME_MONITORING" }, {}, resolve)));
  assert.deepEqual(disabledResume, { ok: false, errorCode: "CONTINUOUS_PROTECTION_DISABLED" });
  const authorizedResume = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_RESUME_MONITORING", continuousProtection: true }, {}, resolve)));
  assert.equal(authorizedResume.ok, true);
  await page.waitForFunction((count) => globalThis.fixtureRequests > count, {}, beforeMutationRequests);
  const resumedStatus = await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_GET_MONITOR_STATUS" }, {}, resolve)));
  assert.equal(resumedStatus.monitoring, true);
  assert.equal(resumedStatus.continuousProtection, true);
  await page.setViewport({ width: 500, height: 300, deviceScaleFactor: 2 });
  await page.emulateMediaFeatures([{ name: "prefers-color-scheme", value: "dark" }]);
  await page.evaluate(() => {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync("@media(prefers-color-scheme:dark){body{background:#101827;color:#f1f5fa}}");
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    document.dispatchEvent(new Event("scroll"));
  });
  await page.waitForSelector("[data-aegis-passive]");
  await page.screenshot({ path: "release/evolution-0.3.0/clickfix-dark-compact-sanitized.png" });
  runtimeEvidence.push(await page.evaluate(() => new Promise((resolve) => globalThis.fixtureMessages[0]({ type: "AEGIS_GET_MONITOR_STATUS" }, {}, (status) => resolve({ fixture: "clickfix-dark-compact500x300-dpr2", status, longTaskDurationsMs: globalThis.fixtureLongTasks })))));
  await writeFile("release/evolution-0.3.0/dynamic-dom-evidence.json", JSON.stringify({ generatedAt: new Date().toISOString(), browser: await browser.version(), provenance: "Synthetic DOM; actual bundled content+local engine; mocked worker transport. Compact viewport/dpr2 is a responsive rendering probe, not native browser zoom. Long tasks include fixture initialization and DOM automation.", runtimeEvidence }, null, 2) + "\n");
  process.stdout.write("Chrome DOM fixtures: Gmail/Outlook independent rows and messages, Google/Bing deep scroll and wrappers, long-page viewport evidence and educational context, temporary scoped dismissal, focus/native destination preservation, serialized stale recovery, pause/manual failure/status and disable cleanup passed. Transport mocked; no live mailbox or Jev efficacy claim.\n");
} finally { await browser.close(); }
