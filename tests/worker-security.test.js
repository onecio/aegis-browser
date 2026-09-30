import test from "node:test";
import assert from "node:assert/strict";
import { buildJevQuestions } from "../src/intelligence/jev-client.js";

function event() {
  const listeners = [];
  return { addListener: (listener) => listeners.push(listener), emit: (...args) => Promise.all(listeners.map((listener) => listener(...args))), listeners };
}

function storage(initial = {}) {
  const values = { ...initial };
  return {
    values,
    get: async (keys) => keys == null ? { ...values } : Object.fromEntries((Array.isArray(keys) ? keys : [keys]).map((key) => [key, values[key]])),
    set: async (patch) => Object.assign(values, patch),
    remove: async (keys) => { for (const key of Array.isArray(keys) ? keys : [keys]) delete values[key]; },
    setAccessLevel: async () => undefined
  };
}

let serial = 0;
async function worker(t, initialSettings = {}) {
  const id = "abcdefghijklmnopabcdefghijklmnop";
  const local = storage({ "aegis.settings": { emailProtection: true, webProtection: true, jevEnabled: true, connectionMode: "byok", privacyMode: "STRICT", ...initialSettings } });
  const session = storage({ "aegis.secret.byok": "test-credential-value" });
  const tab = { id: 7, url: "https://mail.google.com/mail/u/0/#inbox" };
  let permitted = true;
  globalThis.chrome = {
    runtime: { id, onInstalled: event(), onStartup: event(), onMessage: event() },
    storage: { local, session, managed: storage(), onChanged: event() },
    tabs: { get: async () => ({ ...tab }), query: async () => [tab], sendMessage: async () => ({}), onRemoved: event(), onUpdated: event() },
    permissions: { contains: async () => permitted, getAll: async () => ({ origins: permitted ? ["https://*/*", "http://*/*", "https://mail.google.com/*"] : [] }), onRemoved: event() },
    scripting: { getRegisteredContentScripts: async () => [], unregisterContentScripts: async () => undefined, registerContentScripts: async () => undefined, insertCSS: async () => undefined, executeScript: async () => undefined },
    sidePanel: { open: async () => undefined },
    contextMenus: { remove: (_id, callback) => callback(), create: (_details, callback) => callback(), onClicked: event() }
  };
  const currentChrome = globalThis.chrome;
  const oldFetch = globalThis.fetch;
  await import(`../src/background/service-worker.js?security-test=${serial++}`);
  t.after(() => { globalThis.fetch = oldFetch; delete globalThis.chrome; });
  const sender = { id, tab, frameId: 0, documentId: "document-7", url: tab.url };
  const ui = { id, url: `chrome-extension://${id}/options.html`, frameId: 0 };
  const send = (message, from = sender) => new Promise((resolve) => currentChrome.runtime.onMessage.listeners[0](message, from, resolve));
  return { send, sender, ui, local, session, tab, chrome: currentChrome, revoke: () => { permitted = false; } };
}

function validProviderResponse() {
  const answers = {};
  for (const [key, question] of Object.entries(buildJevQuestions())) {
    if (question.type === "noul") answers[key] = { type: "noul", noul: 0.9 };
    else if (question.type === "choice") answers[key] = { type: "choice", choice: "UNKNOWN", confidence: 1, probabilities: Object.fromEntries(Object.keys(question.criteria).map((option) => [option, option === "UNKNOWN" ? 1 : 0])) };
    else answers[key] = { type: "score", score: 0, confidence: 1, probabilities: Object.fromEntries(question.criteria.map((_level, index) => [String(index), index === 0 ? 1 : 0])), legend: Object.fromEntries(question.criteria.map((level, index) => [String(index), level])) };
  }
  return new Response(JSON.stringify({ model: "jev-test", answers }), { headers: { "content-type": "application/json" } });
}

const email = { subject: "Confirme sua senha agora", bodyText: "Envie sua senha imediatamente para desbloquear a conta.", senderEmail: "sender@example.test", links: [] };
const drain = () => new Promise((resolve) => setTimeout(resolve, 30));

test("automatic analysis rejects disabled protection, untrusted frames and a navigated document", async (t) => {
  const w = await worker(t, { emailProtection: false, webProtection: false, jevEnabled: false });
  assert.equal((await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email })).errorCode, "PROTECTION_DISABLED");
  assert.equal((await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email }, { ...w.sender, frameId: 2 })).errorCode, "UNTRUSTED_SENDER");
  w.tab.url = "https://example.org/new-page";
  assert.equal((await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email })).errorCode, "STALE_DOCUMENT");
});

test("late provider completion after a credential change cannot repopulate cache or trusted test status", async (t) => {
  const w = await worker(t);
  let resolveFetch;
  let started;
  const startedPromise = new Promise((resolve) => { started = resolve; });
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    if (calls > 1) return validProviderResponse();
    started();
    return new Promise((resolve) => { resolveFetch = resolve; });
  };
  await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email, userRequested: true });
  await startedPromise;
  assert.equal((await w.send({ type: "AEGIS_SAVE_SECRET", kind: "byok", value: "replacement-test-credential" }, w.ui)).ok, true);
  resolveFetch(validProviderResponse());
  await drain();
  await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email, userRequested: true });
  await drain();
  assert.equal(calls, 2, "the obsolete request must not refill the cache for the replacement credential");
});

test("last connection test is invalidated by a new credential and privacy excerpts need explicit consent", async (t) => {
  const w = await worker(t);
  globalThis.fetch = async () => validProviderResponse();
  assert.equal((await w.send({ type: "AEGIS_TEST_JEV" }, w.ui)).ok, true);
  const connected = await w.send({ type: "AEGIS_GET_SETTINGS" }, w.ui);
  assert.equal(connected.connectionRuntime.status, "connected");
  assert.equal(connected.lastJevTest.ok, true);
  assert.equal(JSON.stringify(connected).includes("test-credential-value"), false);
  assert.equal((await w.send({ type: "AEGIS_SAVE_SETTINGS", settings: { privacyMode: "BALANCED" } }, w.ui)).errorCode, "CONSENT_REQUIRED");
  await w.send({ type: "AEGIS_SAVE_SECRET", kind: "byok", value: "replacement-test-credential" }, w.ui);
  assert.equal((await w.send({ type: "AEGIS_GET_SETTINGS" }, w.ui)).lastJevTest, null);
  assert.equal((await w.send({ type: "AEGIS_SAVE_SETTINGS", settings: { privacyMode: "BALANCED", contentSharingConsent: true } }, w.ui)).ok, true);
});

test("a manually requested scan is bounded to the selected document and expires on navigation", async (t) => {
  const w = await worker(t, { emailProtection: false, webProtection: false, jevEnabled: false });
  assert.equal((await w.send({ type: "AEGIS_ANALYZE_ACTIVE_TAB" }, w.ui)).ok, true);
  assert.equal((await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email, userRequested: true })).ok, true);
  await w.chrome.tabs.onUpdated.emit(7, { status: "loading" });
  assert.equal((await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email, userRequested: true })).errorCode, "PROTECTION_DISABLED");
});

test("a stored decision is discarded when the current tab route no longer matches", async (t) => {
  const w = await worker(t, { jevEnabled: false });
  assert.equal((await w.send({ type: "AEGIS_ANALYZE_EMAIL", payload: email })).ok, true);
  assert.ok((await w.send({ type: "AEGIS_GET_CURRENT_ANALYSIS", tabId: 7 }, w.ui)).analysis);
  w.tab.url = "https://mail.google.com/mail/u/0/#another-message";
  assert.equal((await w.send({ type: "AEGIS_GET_CURRENT_ANALYSIS", tabId: 7 }, w.ui)).analysis, null);
});

test("an installed privacy setting without explicit consent falls back to strict minimization", async (t) => {
  const w = await worker(t, { privacyMode: "ENHANCED" });
  assert.equal((await w.send({ type: "AEGIS_GET_SETTINGS" }, w.ui)).settings.privacyMode, "STRICT");
});

test("refresh preserves an explicitly paused tab until protection is explicitly enabled", async (t) => {
  const w = await worker(t, { jevEnabled: false });
  const commands = [];
  w.chrome.tabs.sendMessage = async (_tabId, message) => {
    commands.push(message);
    if (message.type === "AEGIS_GET_MONITOR_STATUS") return { ok: true, monitoring: false, continuousProtection: true };
    return { ok: true };
  };
  assert.equal((await w.send({ type: "AEGIS_REFRESH_SCRIPTS" }, w.ui)).ok, true);
  assert.equal(commands.some((message) => message.type === "AEGIS_RESUME_MONITORING"), false);
  assert.equal((await w.send({ type: "AEGIS_REFRESH_SCRIPTS", resumePaused: true }, w.ui)).ok, true);
  assert.ok(commands.some((message) => message.type === "AEGIS_RESUME_MONITORING" && message.continuousProtection));
});

test("web protection excludes email surfaces when email protection is disabled", async (t) => {
  const w = await worker(t, { emailProtection: false, jevEnabled: false });
  const registrations = [];
  const injections = [];
  w.chrome.scripting.registerContentScripts = async (scripts) => registrations.push(...scripts);
  w.chrome.scripting.executeScript = async (details) => injections.push(details);
  assert.equal((await w.send({ type: "AEGIS_REFRESH_SCRIPTS" }, w.ui)).ok, true);
  assert.equal(injections.length, 0, "disabled webmail must not receive the broad web script");
  const web = registrations.find((item) => item.id === "aegis-web-monitor");
  assert.ok(web.excludeMatches.includes("https://mail.google.com/*"));
  assert.ok(web.excludeMatches.includes("https://outlook.cloud.microsoft/*"));
});
