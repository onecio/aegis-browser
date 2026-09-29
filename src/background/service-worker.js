import { analyzeEmail, analyzeManualUrl } from "../email/email-analyzer.js";
import { decideRisk } from "../core/decision-engine.js";
import { evaluateJev, shouldCallJev } from "../intelligence/jev-client.js";
import { makeJevState } from "../security/redaction.js";
import { analyzePageSnapshot, analyzeSearchResult } from "../web/page-analyzer.js";
import { normalizeOrganizationKnowledgeBase, resolveManagedConfiguration } from "../core/org-configuration.js";
import { SessionPatternAnalyzer } from "../intelligence/session-patterns.js";
import { FEEDBACK_TYPES, LocalDashboard } from "../analytics/local-dashboard.js";
import { clearRevokedOriginState, toSafeWebOrigin } from "./permission-cleanup.js";

const EMAIL_ORIGINS = ["https://mail.google.com/*", "https://outlook.office.com/*", "https://outlook.live.com/*"];
const SETTINGS_KEY = "aegis.settings";
const SECRET_KEYS = { byok: "aegis.secret.byok", gatewayToken: "aegis.secret.gatewayToken" };
const CONTEXT_MENU_ID = "aegis-analyze-link";
const CACHE_TTL_MS = 120_000;
const MAX_CACHE = 64;
const cache = new Map();
const inFlight = new Map();
const requestControllers = new Set();
let circuitState = null;

const DEFAULTS = Object.freeze({
  emailProtection: false,
  webProtection: false,
  jevEnabled: false,
  connectionMode: "gateway",
  privacyMode: "STRICT",
  gatewayUrl: "",
  contextMenu: false,
  sessionIntelligence: false
});
const sessionPatterns = new SessionPatternAnalyzer({ storage: chrome.storage.session, crypto });
const localDashboard = new LocalDashboard({ storage: chrome.storage.local });

async function readConfiguration() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  let managed;
  try { managed = await chrome.storage.managed?.get(null) ?? {}; } catch { managed = {}; }
  const resolved = resolveManagedConfiguration({ ...DEFAULTS, ...(stored[SETTINGS_KEY] ?? {}) }, managed);
  return { settings: resolved.settings, managedKeys: resolved.managedKeys, local: stored[SETTINGS_KEY] ?? {}, managed };
}

async function settings() {
  return (await readConfiguration()).settings;
}

async function resetStoredJev(status) {
  const stored = await chrome.storage.session.get(null);
  const updates = {};
  const notifications = [];
  for (const [key, analysis] of Object.entries(stored)) {
    if (!key.startsWith("aegis.analysis.") || !analysis?.engineStatus) continue;
    const local = analysis.localDecision ?? analysis;
    const decision = {
      ...analysis,
      ...local,
      analysisId: analysis.analysisId,
      localDecision: local,
      engineStatus: { ...local.engineStatus, jev: status },
      jev: null
    };
    delete decision.engineStatus.jevReason;
    updates[key] = decision;
    const tabId = Number(key.slice("aegis.analysis.".length));
    if (Number.isInteger(tabId)) notifications.push({ tabId, decision, links: analysis.links ?? [] });
  }
  if (Object.keys(updates).length) await chrome.storage.session.set(updates);
  await Promise.all(notifications.map(({ tabId, decision, links }) => chrome.tabs.sendMessage(tabId, { type: "AEGIS_DECISION_UPDATED", decision, links }).catch(() => undefined)));
}

function validateSettings(input = {}) {
  const allowed = ["emailProtection", "webProtection", "jevEnabled", "connectionMode", "privacyMode", "gatewayUrl", "contextMenu", "sessionIntelligence", "organizationKnowledgeBase"];
  const next = {};
  for (const key of allowed) if (key in input) next[key] = input[key];
  for (const key of ["emailProtection", "webProtection", "jevEnabled", "contextMenu", "sessionIntelligence"]) {
    if (key in next && typeof next[key] !== "boolean") throw new Error(`Invalid setting: ${key}`);
  }
  if (next.connectionMode && !["byok", "gateway"].includes(next.connectionMode)) throw new Error("Invalid connection mode");
  if (next.privacyMode && !["STRICT", "BALANCED", "ENHANCED"].includes(next.privacyMode)) throw new Error("Invalid privacy mode");
  if (next.gatewayUrl) {
    const url = new URL(next.gatewayUrl);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) throw new Error("Gateway URL must be an HTTPS origin without credentials or query parameters");
    next.gatewayUrl = url.origin;
  }
  if ("organizationKnowledgeBase" in next) next.organizationKnowledgeBase = normalizeOrganizationKnowledgeBase(next.organizationKnowledgeBase);
  return next;
}

async function saveSettings(patch) {
  const configuration = await readConfiguration();
  const current = configuration.settings;
  const validated = validateSettings(patch);
  for (const key of configuration.managedKeys) {
    if (Object.hasOwn(validated, key) && JSON.stringify(validated[key]) !== JSON.stringify(current[key])) {
      throw new Error(`Setting is managed by the organization: ${key}`);
    }
    delete validated[key];
  }
  const nextLocal = { ...DEFAULTS, ...configuration.local, ...validated };
  const next = resolveManagedConfiguration(nextLocal, configuration.managed).settings;
  const providerChanged = current.connectionMode !== next.connectionMode || current.gatewayUrl !== next.gatewayUrl || current.privacyMode !== next.privacyMode;
  if (current.jevEnabled && (!next.jevEnabled || providerChanged)) {
    for (const controller of requestControllers) controller.abort();
    cache.clear();
    circuitState = null;
  }
  await chrome.storage.local.set({ [SETTINGS_KEY]: nextLocal });
  if (current.jevEnabled && !next.jevEnabled) {
    await chrome.storage.session.remove([...Object.values(SECRET_KEYS), "aegis.jevCircuit"]);
    await resetStoredJev("off");
  } else if (providerChanged) {
    await chrome.storage.session.remove("aegis.jevCircuit");
    if (current.jevEnabled && next.jevEnabled) await resetStoredJev("idle");
  }
  if (current.connectionMode !== next.connectionMode) {
    const unusedSecret = current.connectionMode === "byok" ? SECRET_KEYS.byok : SECRET_KEYS.gatewayToken;
    await chrome.storage.session.remove(unusedSecret);
  }
  if (current.sessionIntelligence && !next.sessionIntelligence) await sessionPatterns.clear();
  await refreshContextMenu();
  return next;
}

function removeAegisContextMenu() {
  return new Promise((resolve) => {
    try {
      chrome.contextMenus.remove(CONTEXT_MENU_ID, () => {
        void chrome.runtime.lastError;
        resolve();
      });
    } catch { resolve(); }
  });
}

async function refreshContextMenu() {
  const current = await settings();
  let permissionGranted;
  try { permissionGranted = await chrome.permissions.contains({ permissions: ["contextMenus"] }); }
  catch { return false; }
  if (!permissionGranted) return false;
  await removeAegisContextMenu();
  if (!current.contextMenu) return false;
  return new Promise((resolve) => {
    try {
      chrome.contextMenus.create({ id: CONTEXT_MENU_ID, title: "Analisar link com AEGIS", contexts: ["link"] }, () => {
        const failed = Boolean(chrome.runtime.lastError);
        resolve(!failed);
      });
    } catch { resolve(false); }
  });
}

function hostForUrl(urlText) {
  try { return new URL(urlText).hostname; } catch { return ""; }
}

async function refreshContentScripts() {
  const current = await settings();
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.filter((tab) => Number.isInteger(tab.id)).map((tab) => chrome.tabs.sendMessage(tab.id, { type: "AEGIS_STOP_MONITORING" }).catch(() => undefined)));
  const registered = await chrome.scripting.getRegisteredContentScripts();
  const ids = registered.filter((item) => item.id.startsWith("aegis-")).map((item) => item.id);
  if (ids.length) await chrome.scripting.unregisterContentScripts({ ids });
  const grants = (await chrome.permissions.getAll()).origins ?? [];
  const emailPatterns = [];
  if (current.emailProtection) {
    for (const origin of EMAIL_ORIGINS) {
      if (!grants.includes(origin)) continue;
      const id = `aegis-email-${hostForUrl(origin.replace("/*", "/"))}`;
      await chrome.scripting.registerContentScripts([{ id, matches: [origin], js: ["content.js"], runAt: "document_idle", persistAcrossSessions: true }]);
      emailPatterns.push(origin);
    }
  }
  let webEnabled = false;
  if (current.webProtection) {
    const hasBroadPermission = grants.includes("https://*/*") && grants.includes("http://*/*");
    if (hasBroadPermission) {
      await chrome.scripting.registerContentScripts([{ id: "aegis-web-monitor", matches: ["https://*/*", "http://*/*"], js: ["content.js"], runAt: "document_idle", persistAcrossSessions: true }]);
      webEnabled = true;
    }
  }
  for (const tab of tabs) {
    if (!Number.isInteger(tab.id) || !tab.url) continue;
    try {
      const url = new URL(tab.url);
      if (!/^https?:$/.test(url.protocol)) continue;
      const pattern = `${url.origin}/*`;
      const granted = grants.some((item) => item === pattern || item === "https://*/*" && url.protocol === "https:" || item === "http://*/*" && url.protocol === "http:");
      const emailHost = EMAIL_ORIGINS.some((item) => new URL(item.replace("/*", "/")).hostname === url.hostname);
      const shouldRun = granted && (webEnabled || current.emailProtection && emailHost && emailPatterns.some((item) => new URL(item.replace("/*", "/")).hostname === url.hostname));
      if (!shouldRun) continue;
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      await chrome.tabs.sendMessage(tab.id, { type: "AEGIS_RESUME_MONITORING" });
    } catch { /* restricted or closed tab */ }
  }
}

async function safeStoreDecision(tabId, decision, info, analysisId = undefined, localDecision = decision, sourceUrl = "") {
  if (!Number.isInteger(tabId)) return;
  const safe = {
    ...decision,
    ...(analysisId ? { analysisId } : {}),
    sourceOrigin: toSafeWebOrigin(sourceUrl),
    localDecision,
    pageDomain: info.pageDomain ?? null,
    senderDomain: info.senderDomain ?? null,
    surface: info.surface,
    links: (info.links ?? []).slice(0, 30).map(({ domain, scheme, visibleDomain, mismatch, shortener, sensitiveParams, suspiciousParams, organizationDomain, organizationKinds, source }) => ({ domain, scheme, visibleDomain, mismatch, shortener, sensitiveParams, suspiciousParams, organizationDomain: Boolean(organizationDomain), organizationKinds: (organizationKinds ?? []).slice(0, 5), source: source === "qr" ? "qr" : source === "web" || info.surface === "web" ? "web" : "email" }))
  };
  await chrome.storage.session.set({ [`aegis.analysis.${tabId}`]: safe });
  await chrome.storage.session.set({ "aegis.latestTab": tabId });
}

async function digest(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const result = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(result)].map((item) => item.toString(16).padStart(2, "0")).join("");
}

async function readSecret(key) {
  const stored = await chrome.storage.session.get(key);
  return stored[key] ?? "";
}

async function maybeEvaluateJev(features, userRequested) {
  const current = await settings();
  if (!current.jevEnabled || !shouldCallJev(features, userRequested)) return { status: current.jevEnabled ? "idle" : "off", signals: [] };

  if (!circuitState) {
    const session = await chrome.storage.session.get("aegis.jevCircuit");
    circuitState = session["aegis.jevCircuit"] ?? { errors: 0, windowStart: Date.now(), openUntil: 0 };
  }
  if (circuitState.openUntil > Date.now()) return { status: "unavailable", errorCode: "CIRCUIT_OPEN", signals: [] };

  const gatewayMode = current.connectionMode === "gateway";
  if (gatewayMode && !current.gatewayUrl) return { status: "unavailable", errorCode: "GATEWAY_NOT_CONFIGURED", signals: [] };
  const endpoint = gatewayMode ? `${current.gatewayUrl}/v1/systemone` : "https://api.typesafe.ai/v1/systemone";
  const credentialKey = gatewayMode ? SECRET_KEYS.gatewayToken : SECRET_KEYS.byok;
  const requiredOrigin = gatewayMode ? `${current.gatewayUrl}/*` : "https://api.typesafe.ai/*";
  const credential = await readSecret(credentialKey);
  if (!credential || !(await chrome.permissions.contains({ origins: [requiredOrigin] }))) {
    return { status: "unavailable", errorCode: !credential ? "CREDENTIAL_NOT_CONFIGURED" : "HOST_PERMISSION_MISSING", signals: [] };
  }

  const key = await digest({ state: makeJevState(features, current.privacyMode), endpoint, connectionMode: current.connectionMode, privacyMode: current.privacyMode, model: "jev-latest", schemaVersion: "aegis-jev-v1", ruleVersion: "aegis-rules-0.1.0" });
  const cached = cache.get(key);
  if (cached && cached.until > Date.now()) return cached.result;
  if (inFlight.has(key)) return inFlight.get(key);

  const controller = new AbortController();
  requestControllers.add(controller);
  const pending = evaluateJev({ features, apiKey: credential, endpoint, privacyMode: current.privacyMode, signal: controller.signal }).then(async (result) => {
    void localDashboard.recordJevAnalysis().catch(() => undefined);
    if (result.status === "connected") {
      circuitState = { errors: 0, windowStart: Date.now(), openUntil: 0 };
      await chrome.storage.session.set({ "aegis.jevCircuit": circuitState });
      result.signals ??= [];
    } else {
      const at = Date.now();
      if (at - circuitState.windowStart >= 60_000) circuitState = { errors: 0, windowStart: at, openUntil: 0 };
      circuitState.errors += 1;
      circuitState.openUntil = circuitState.errors >= 3 ? at + 60_000 : 0;
      await chrome.storage.session.set({ "aegis.jevCircuit": circuitState });
      result = { status: "unavailable", errorCode: result.errorCode, signals: [] };
    }
    cache.set(key, { until: Date.now() + CACHE_TTL_MS, result });
    while (cache.size > MAX_CACHE) cache.delete(cache.keys().next().value);
    return result;
  }).finally(() => { inFlight.delete(key); requestControllers.delete(controller); });
  inFlight.set(key, pending);
  return pending;
}

function validatePayload(payload, maxBytes = 48_000) {
  if (!payload || typeof payload !== "object") throw new Error("Invalid analysis payload");
  const size = new TextEncoder().encode(JSON.stringify(payload)).byteLength;
  if (size > maxBytes) throw new Error("Analysis payload exceeded the local limit");
}

async function analyze(kind, payload, sender, userRequested = false, allowJev = true) {
  if (sender.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id)) throw new Error("Analysis requires a browser tab context");
  validatePayload(payload);
  const current = await settings();
  let result;
  if (kind === "email") result = analyzeEmail(payload, { organizationKnowledgeBase: current.organizationKnowledgeBase });
  else if (kind === "web") result = analyzePageSnapshot(payload, sender.url ?? sender.tab.url ?? "", current.organizationKnowledgeBase);
  else throw new Error("Unsupported analysis type");

  if (current.sessionIntelligence) {
    try {
      const pattern = await sessionPatterns.observe(result);
       if (pattern?.campaign.correlated) result.signals.push({ id: "CAMPAIGN_PATTERN_REPEATED", category: "context", severity: 0, location: "session", detail: `Um destino e sinais locais fortes coincidiram em ${pattern.campaign.observations} mensagens desta sessão. A correlação não confirma uma campanha maliciosa.`, evidence: { observations: pattern.campaign.observations } });
       if (pattern?.anomaly.detected) result.signals.push({ id: "LOCAL_DESTINATION_NOVELTY", category: "context", severity: 0, location: "session", detail: `${pattern.anomaly.novelTargetCount} de ${pattern.anomaly.totalTargetCount} destinos não apareceu nas ${pattern.anomaly.baselineObservations} observações locais anteriores do remetente. A novidade não confirma fraude.`, evidence: { baselineObservations: pattern.anomaly.baselineObservations, novelTargetCount: pattern.anomaly.novelTargetCount, totalTargetCount: pattern.anomaly.totalTargetCount } });
      if (pattern && (pattern.campaign.correlated || pattern.anomaly.detected)) result.decision = decideRisk({ signals: result.signals, coverage: result.coverage });
    } catch { /* session pattern analysis never blocks the local verdict */ }
  }

  const localDecision = result.decision;
  const shouldUseJev = allowJev && current.jevEnabled && shouldCallJev(result, userRequested);
  const initialDecision = { ...localDecision, engineStatus: { ...localDecision.engineStatus, jev: shouldUseJev ? "checking" : current.jevEnabled ? "idle" : "off" }, jev: null };
  const analysisId = crypto.randomUUID();
  const sourceUrl = sender.tab.url ?? sender.url ?? "";
  await safeStoreDecision(sender.tab.id, initialDecision, result, analysisId, localDecision, sourceUrl);
  void localDashboard.recordAnalyses([{ surface: result.decision.surface ?? kind, state: localDecision.state, engineStatus: { local: "active", jev: "off" } }]).catch(() => undefined);

  if (shouldUseJev) {
    const tabId = sender.tab.id;
    const originalState = localDecision.state;
    void (async () => {
      const jev = await maybeEvaluateJev(result, userRequested);
      const latestSettings = await settings();
      if (!latestSettings.jevEnabled || latestSettings.connectionMode !== current.connectionMode || latestSettings.gatewayUrl !== current.gatewayUrl || latestSettings.privacyMode !== current.privacyMode) return;
      const finalDecision = decideRisk({ signals: [...result.signals, ...(jev.signals ?? [])], coverage: result.coverage });
      finalDecision.engineStatus.jev = jev.status;
      if (jev.errorCode) finalDecision.engineStatus.jevReason = jev.errorCode;
      finalDecision.jev = jev.status === "connected" ? { model: jev.model, answers: jev.answers } : null;
      if (originalState === "RED" && finalDecision.state !== "RED") finalDecision.state = "RED";
      const stored = await chrome.storage.session.get(`aegis.analysis.${tabId}`);
      if (stored[`aegis.analysis.${tabId}`]?.analysisId !== analysisId) return;
      await safeStoreDecision(tabId, finalDecision, result, analysisId, localDecision, sourceUrl);
      await chrome.tabs.sendMessage(tabId, { type: "AEGIS_DECISION_UPDATED", decision: finalDecision, links: result.links ?? [] }).catch(() => undefined);
    })().catch(() => undefined);
  }

  return { ok: true, decision: initialDecision, localDecision: { state: localDecision.state, reason: localDecision.reason }, links: result.links ?? [] };
}

async function triageEmails(payloads, sender) {
  if (!Array.isArray(payloads) || payloads.length > 20) throw new Error("Inbox triage limit exceeded");
  if (sender.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id)) throw new Error("Inbox triage requires a browser tab context");
  const current = await settings();
  const analyses = [];
  for (let index = 0; index < payloads.length; index += 1) {
    validatePayload(payloads[index], 2400);
    const result = analyzeEmail(payloads[index], { organizationKnowledgeBase: current.organizationKnowledgeBase });
    if (current.sessionIntelligence) {
      try {
        const pattern = await sessionPatterns.observe(result);
        if (pattern?.campaign.correlated) result.signals.push({ id: "CAMPAIGN_PATTERN_REPEATED", category: "context", severity: 0, location: "session", detail: `Um destino e sinais locais fortes coincidiram em ${pattern.campaign.observations} mensagens desta sessão. A correlação não confirma uma campanha maliciosa.`, evidence: { observations: pattern.campaign.observations } });
        if (pattern?.anomaly.detected) result.signals.push({ id: "LOCAL_DESTINATION_NOVELTY", category: "context", severity: 0, location: "session", detail: `${pattern.anomaly.novelTargetCount} de ${pattern.anomaly.totalTargetCount} destinos não apareceu nas ${pattern.anomaly.baselineObservations} observações locais anteriores do remetente. A novidade não confirma fraude.`, evidence: { baselineObservations: pattern.anomaly.baselineObservations, novelTargetCount: pattern.anomaly.novelTargetCount, totalTargetCount: pattern.anomaly.totalTargetCount } });
        if (pattern && (pattern.campaign.correlated || pattern.anomaly.detected)) result.decision = decideRisk({ signals: result.signals, coverage: result.coverage });
      } catch { /* session pattern analysis never blocks the local verdict */ }
    }
    analyses.push(result);
  }
  const jevIndexes = new Set(current.jevEnabled ? analyses.map((analysis, index) => ({ analysis, index })).filter(({ analysis }) => shouldCallJev(analysis, false)).slice(0, 4).map(({ index }) => index) : []);
  const results = await Promise.all(analyses.map(async (result, index) => {
    let decision = result.decision;
    if (jevIndexes.has(index)) {
      const jev = await maybeEvaluateJev(result, false);
      decision = decideRisk({ signals: [...result.signals, ...(jev.signals ?? [])], coverage: result.coverage });
      decision.engineStatus.jev = jev.status;
      if (jev.errorCode) decision.engineStatus.jevReason = jev.errorCode;
    } else {
      decision.engineStatus.jev = current.jevEnabled ? "idle" : "off";
    }
    const vector = decision.riskVector ?? {};
    const kind = decision.state === "RED"
      ? "phishing"
      : decision.state === "YELLOW" && Number(vector.spam ?? 0) >= 2 && Number(vector.phishing ?? 0) < 3
        ? "spam"
        : "review";
    return { index, state: decision.state, kind, engineStatus: decision.engineStatus, findings: decision.findings.slice(0, 5).map(({ id, category, severity, location, detail, source }) => ({ id, category, severity, location, detail, ...(source ? { source } : {}) })) };
  }));
  const states = results.map((item) => item.state);
  const state = states.includes("RED") ? "RED" : states.includes("YELLOW") ? "YELLOW" : states.includes("UNKNOWN") ? "UNKNOWN" : "GREEN";
  const aggregate = {
    state, reason: "INBOX_FAST_TRIAGE", surface: "email-inbox", itemCount: results.length,
    highRiskCount: results.filter((item) => item.state === "RED").length,
    reviewCount: results.filter((item) => item.state === "YELLOW").length,
    engineStatus: { local: "active", jev: results.some((item) => item.engineStatus.jev === "connected") ? "connected" : results.find((item) => !["idle", "off"].includes(item.engineStatus.jev))?.engineStatus.jev ?? (current.jevEnabled ? "idle" : "off") },
    analyzedAt: new Date().toISOString(), ruleVersion: "aegis-rules-0.1.0",
    coverage: { sufficient: results.length > 0, reasons: results.length ? [] : ["Nenhuma mensagem reconhecida para triagem"] },
    findings: results.flatMap((item) => item.findings).slice(0, 24)
  };
  void localDashboard.recordAnalyses(results.map((item) => ({ surface: "email-inbox", state: item.state, engineStatus: item.engineStatus }))).catch(() => undefined);
  await safeStoreDecision(sender.tab.id, aggregate, { surface: "email-inbox" }, undefined, aggregate, sender.tab.url ?? sender.url ?? "");
  return { ok: true, results };
}

async function triageSearchResults(payloads, sender) {
  if (!Array.isArray(payloads) || payloads.length > 20) throw new Error("Search-result triage limit exceeded");
  if (sender.id !== chrome.runtime.id || !Number.isInteger(sender.tab?.id)) throw new Error("Search-result triage requires a browser tab context");
  const current = await settings();
  const analyses = payloads.map((payload) => {
    validatePayload(payload, 6000);
    return analyzeSearchResult(payload, current.organizationKnowledgeBase);
  });
  const jevIndexes = new Set(current.jevEnabled ? analyses.map((analysis, index) => ({ analysis, index })).filter(({ analysis }) => shouldCallJev(analysis, false)).slice(0, 4).map(({ index }) => index) : []);
  const results = await Promise.all(analyses.map(async (analysis, index) => {
    let decision = analysis.decision;
    if (jevIndexes.has(index)) {
      const jev = await maybeEvaluateJev(analysis, false);
      decision = decideRisk({ signals: [...analysis.signals, ...(jev.signals ?? [])], coverage: analysis.coverage });
      decision.engineStatus.jev = jev.status;
      if (jev.errorCode) decision.engineStatus.jevReason = jev.errorCode;
      decision.jev = jev.status === "connected" ? { model: jev.model, answers: jev.answers } : null;
    } else {
      decision.engineStatus.jev = current.jevEnabled ? "idle" : "off";
    }
    return {
      index,
      state: decision.state,
      engineStatus: decision.engineStatus,
      findings: decision.findings.slice(0, 5).map(({ id, category, severity, location, detail, source }) => ({ id, category, severity, location, detail, ...(source ? { source } : {}) }))
    };
  }));
  void localDashboard.recordAnalyses(results.map((item) => ({ surface: "search-result", state: item.state, engineStatus: item.engineStatus }))).catch(() => undefined);
  return { ok: true, results };
}

async function analyzeUrlOnly(raw) {
  const current = await settings();
  const result = analyzeManualUrl(String(raw ?? "").slice(0, 4096), current.organizationKnowledgeBase);
  void localDashboard.recordAnalyses([{ surface: "url", state: result.decision.state, engineStatus: { local: "active", jev: "off" } }]).catch(() => undefined);
  return { ok: true, decision: result.decision, pageDomain: result.pageDomain ?? null, signals: result.signals.map(({ id, category, severity, location, detail }) => ({ id, category, severity, location, detail })) };
}

async function testJevConnection() {
  const current = await settings();
  if (!current.jevEnabled) return { ok: false, errorCode: "JEV_DISABLED" };
  const gatewayMode = current.connectionMode === "gateway";
  if (gatewayMode && !current.gatewayUrl) return { ok: false, errorCode: "GATEWAY_NOT_CONFIGURED" };
  const endpoint = gatewayMode ? `${current.gatewayUrl}/v1/systemone` : "https://api.typesafe.ai/v1/systemone";
  const credentialKey = gatewayMode ? SECRET_KEYS.gatewayToken : SECRET_KEYS.byok;
  const origin = gatewayMode ? `${current.gatewayUrl}/*` : "https://api.typesafe.ai/*";
  const credential = await readSecret(credentialKey);
  if (!credential) return { ok: false, errorCode: "CREDENTIAL_NOT_CONFIGURED" };
  if (!(await chrome.permissions.contains({ origins: [origin] }))) return { ok: false, errorCode: "HOST_PERMISSION_MISSING" };
  const result = await evaluateJev({ endpoint, apiKey: credential, privacyMode: "STRICT", features: { surface: "web", pageDomain: "example.test", senderDomain: null, claimedBrands: [], links: [], forms: [], signals: [] } });
  if (result.status !== "connected") return { ok: false, errorCode: result.errorCode ?? "PROVIDER_UNAVAILABLE" };
  return { ok: true, model: result.model };
}

function isTrustedSidePanelSender(sender) {
  if (sender.id !== chrome.runtime.id || typeof sender.url !== "string") return false;
  try {
    const url = new URL(sender.url);
    return url.origin === `chrome-extension://${chrome.runtime.id}` && url.pathname === "/sidepanel.html";
  } catch { return false; }
}

async function submitFeedback(message, sender) {
  if (!isTrustedSidePanelSender(sender)) throw new Error("Feedback is accepted only from the AEGIS side panel");
  if (!FEEDBACK_TYPES.includes(message?.kind)) throw new Error("Unsupported feedback type");
  if (!Number.isInteger(message?.tabId) || typeof message?.analysisId !== "string") throw new Error("Feedback requires a current analysis");
  const key = `aegis.analysis.${message.tabId}`;
  const stored = await chrome.storage.session.get(key);
  if (stored[key]?.analysisId !== message.analysisId) return { ok: false, errorCode: "STALE_ANALYSIS" };
  await localDashboard.recordFeedback(message.kind);
  return { ok: true };
}

async function handleMessage(message, sender) {
  switch (message?.type) {
    case "AEGIS_GET_LOCAL_DASHBOARD": {
      if (!isTrustedSidePanelSender(sender)) throw new Error("Dashboard is available only in the AEGIS side panel");
      return { ok: true, dashboard: await localDashboard.snapshot() };
    }
    case "AEGIS_CLEAR_LOCAL_DASHBOARD": {
      if (!isTrustedSidePanelSender(sender)) throw new Error("Dashboard can be cleared only in the AEGIS side panel");
      await localDashboard.clear();
      return { ok: true };
    }
    case "AEGIS_SUBMIT_FEEDBACK": return submitFeedback(message, sender);
    case "AEGIS_GET_SETTINGS": {
      const { settings: current, managedKeys } = await readConfiguration();
      const secrets = await chrome.storage.session.get(Object.values(SECRET_KEYS));
      return { ok: true, settings: current, managedKeys, hasByok: Boolean(secrets[SECRET_KEYS.byok]), hasGatewayToken: Boolean(secrets[SECRET_KEYS.gatewayToken]) };
    }
    case "AEGIS_SAVE_SETTINGS": return { ok: true, settings: await saveSettings(message.settings) };
    case "AEGIS_SAVE_SECRET": {
      const { kind, value } = message;
      const key = SECRET_KEYS[kind];
      if (!key || typeof value !== "string" || value.length > 1024 || (value && value.length < 12)) throw new Error("Credential format is invalid");
      const current = await settings();
      if (value && !current.jevEnabled) throw new Error("Enable Jev before storing a session credential");
      if (value && (kind === "byok" ? current.connectionMode !== "byok" : current.connectionMode !== "gateway")) throw new Error("Select the matching Jev connection mode first");
      const previous = await chrome.storage.session.get(key);
      if (previous[key] !== value) {
        for (const controller of requestControllers) controller.abort();
        cache.clear();
        circuitState = null;
      }
      if (value) await chrome.storage.session.set({ [key]: value });
      else await chrome.storage.session.remove(key);
      if (previous[key] !== value) {
        await chrome.storage.session.remove("aegis.jevCircuit");
        await resetStoredJev(current.jevEnabled ? "idle" : "off");
      }
      return { ok: true, saved: Boolean(value) };
    }
    case "AEGIS_REFRESH_SCRIPTS": await refreshContentScripts(); return { ok: true };
    case "AEGIS_ANALYZE_EMAIL": return analyze("email", message.payload, sender, Boolean(message.userRequested));
    case "AEGIS_ANALYZE_PAGE": return analyze("web", message.payload, sender, Boolean(message.userRequested));
    case "AEGIS_TRIAGE_EMAILS": return triageEmails(message.payloads, sender);
    case "AEGIS_TRIAGE_SEARCH_RESULTS": return triageSearchResults(message.payloads, sender);
    case "AEGIS_ANALYZE_URL": return analyzeUrlOnly(message.url);
    case "AEGIS_TEST_JEV": return testJevConnection();
    case "AEGIS_GET_CURRENT_ANALYSIS": {
      const tabId = Number.isInteger(message.tabId) ? message.tabId : sender.tab?.id;
      const stored = await chrome.storage.session.get(`aegis.analysis.${tabId}`);
      return { ok: true, analysis: stored[`aegis.analysis.${tabId}`] ?? null };
    }
    case "AEGIS_OPEN_PANEL": {
      if (!Number.isInteger(sender.tab?.id)) throw new Error("No active tab");
      await chrome.sidePanel.open({ tabId: sender.tab.id });
      return { ok: true };
    }
    case "AEGIS_ANALYZE_ACTIVE_TAB": {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (!Number.isInteger(tab?.id)) throw new Error("No active tab");
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      return { ok: true, tabId: tab.id };
    }
    default: return { ok: false, error: "Unsupported request" };
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  try { await chrome.storage.managed?.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" }); } catch { /* managed storage is unavailable in unmanaged installs */ }
  const existing = await chrome.storage.local.get(SETTINGS_KEY);
  if (!existing[SETTINGS_KEY]) await chrome.storage.local.set({ [SETTINGS_KEY]: DEFAULTS });
  await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
  await refreshContextMenu();
});

chrome.runtime.onStartup.addListener(async () => {
  await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  try { await chrome.storage.managed?.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" }); } catch { /* managed storage is unavailable in unmanaged installs */ }
  await refreshContentScripts();
  await refreshContextMenu();
});

chrome.permissions.onRemoved.addListener(async (removed) => {
  for (const controller of requestControllers) controller.abort();
  cache.clear();
  circuitState = null;
  try { await chrome.storage.session.remove("aegis.jevCircuit"); } catch { /* proceed with scoped revocation cleanup */ }
  if (removed.origins?.length) {
    await clearRevokedOriginState({
      removedOrigins: removed.origins,
      storage: chrome.storage.session,
      permissions: chrome.permissions,
      secretKeys: SECRET_KEYS,
      readSettings: settings,
      clearPatterns: () => sessionPatterns.clear(),
      disableJev: () => saveSettings({ jevEnabled: false }),
      resetStoredJev
    });
  }
  if (removed.permissions?.includes("contextMenus")) {
    const current = await settings();
    await chrome.storage.local.set({ [SETTINGS_KEY]: { ...current, contextMenu: false } });
  }
  await refreshContextMenu();
  await refreshContentScripts();
});

chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "managed" && _changes.sessionIntelligence?.newValue === false) void sessionPatterns.clear();
  if (area === "managed") void refreshContentScripts();
});

chrome.contextMenus?.onClicked?.addListener((info, tab) => {
  if (info.menuItemId !== CONTEXT_MENU_ID || !info.linkUrl || !Number.isInteger(tab?.id)) return;
  void chrome.sidePanel.open({ tabId: tab.id }).catch(() => undefined);
  void settings().then((current) => {
    const result = analyzeManualUrl(info.linkUrl, current.organizationKnowledgeBase);
    void localDashboard.recordAnalyses([{ surface: "url", state: result.decision.state, engineStatus: { local: "active", jev: "off" } }]).catch(() => undefined);
    return safeStoreDecision(tab.id, result.decision, { surface: "url", pageDomain: result.pageDomain ?? null, links: [] }, undefined, result.decision, tab.url ?? "");
  }).catch(() => undefined);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.session.remove(`aegis.analysis.${tabId}`);
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === "loading") await chrome.storage.session.remove(`aegis.analysis.${tabId}`);
});

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  handleMessage(message, sender).then(respond).catch((error) => respond({ ok: false, error: String(error?.message ?? "Analysis failed").slice(0, 240) }));
  return true;
});
