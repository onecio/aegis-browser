import { makeJevState } from "../security/redaction.js";
import { summarizeConnection, connectionErrorText } from "./operational-status.js";
import { createI18n } from "../i18n.js";

const { t, localizeDocument } = createI18n(chrome.i18n);
localizeDocument(document);
const EMAIL_ORIGINS = ["https://mail.google.com/*", "https://outlook.office.com/*", "https://outlook.office365.com/*", "https://outlook.live.com/*", "https://outlook.cloud.microsoft/*"];
const WEB_ORIGINS = ["https://*/*", "http://*/*"];
const $ = (selector) => document.querySelector(selector);
const status = (text, kind = "") => { $("#status").textContent = text; $("#status").className = `message ${kind}`; };
let managedKeys = [];

function selectedSettings() {
  return {
    emailProtection: $("#emailProtection").checked,
    webProtection: $("#webProtection").checked,
    contextMenu: $("#contextMenu").checked,
    sessionIntelligence: $("#sessionIntelligence").checked,
    jevEnabled: $("#jevEnabled").checked,
    privacyMode: $("#privacyMode").value,
    contentSharingConsent: $("#privacyMode").value !== "STRICT" && $("#contentSharingConsent").checked,
    connectionMode: $("#connectionMode").value,
    gatewayUrl: $("#gatewayUrl").value.trim()
  };
}

function renderMode() {
  const gateway = $("#connectionMode").value === "gateway";
  $("#byokFields").hidden = gateway;
  $("#gatewayFields").hidden = !gateway;
}

function renderPrivacyPreview() {
  const mode = $("#privacyMode").value;
  $("#contentConsentRow").hidden = mode === "STRICT";
  if (mode === "STRICT") $("#contentSharingConsent").checked = false;
  const example = { surface: "email", senderDomain: "example.test", pageDomain: null, subject: "Aviso de acesso", semanticExcerpt: "Revise sua conta. contato@example.test https://example.test/?token=synthetic", claimedBrands: [], links: [], signals: [], forms: [] };
  $("#privacyPreview").textContent = JSON.stringify(makeJevState(example, mode), null, 2);
  $("#privacyPreviewLimit").textContent = t(mode === "STRICT" ? "privacyPreviewStrictLimit" : "privacyPreviewExcerptLimit");
  $("#diagnosticPrivacy").textContent = t(mode === "STRICT" ? "privacyStrict" : mode === "BALANCED" ? "privacyBalanced" : "privacyEnhanced");
}

function validateContentConsent(settings) {
  if (settings.privacyMode !== "STRICT" && !settings.contentSharingConsent) {
    status(t("diagnosticConsent"), "error");
    $("#contentSharingConsent").focus();
    return false;
  }
  return true;
}

async function refreshDiagnostic() {
  const config = await chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" });
  if (!config?.ok) return;
  $("#diagnosticAi").textContent = summarizeConnection(config, t).text;
  const last = config.connectionRuntime?.lastTest ?? config.lastJevTest;
  $("#diagnosticLastTest").textContent = last ? `${last.at} · ${last.mode} · ${last.ok ? t("diagnosticTestPassed", [last.model ?? "JEV"]) : connectionErrorText(last.errorCode, t)}` : t("diagnosticNoTest");
}

async function saveSecret(kind, input, successText) {
  try {
    const value = input.value.trim();
    if (value) {
      const next = selectedSettings();
      if (!validateContentConsent(next)) return;
      next.connectionMode = kind === "byok" ? "byok" : "gateway";
      next.jevEnabled = true;
      if (!(await requestProviderPermission(next))) { status(t("credentialSaveFailed"), "error"); return; }
      const saved = await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: next });
      if (!saved?.ok) { status(saved?.error ?? t("credentialSaveFailed"), "error"); return; }
      $("#connectionMode").value = next.connectionMode;
      $("#jevEnabled").checked = true;
      renderMode();
    }
    const result = await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SECRET", kind, value });
    if (!result?.ok) { status(result?.error ?? t("credentialSaveFailed"), "error"); return; }
    input.value = "";
    status(successText, "success");
    await refreshDiagnostic();
  } catch { status(t("credentialSaveFailed"), "error"); }
}

async function requestProviderPermission(settings) {
  if (!settings.jevEnabled) return true;
  if (settings.connectionMode === "byok") {
    return chrome.permissions.request({ origins: ["https://api.typesafe.ai/*"] });
  }
  if (!settings.gatewayUrl) return false;
  const origin = new URL(settings.gatewayUrl).origin;
  return chrome.permissions.request({ origins: [`${origin}/*`] });
}

async function load() {
  const result = await chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" });
  if (!result?.ok) { status(t("settingsLoadFailed"), "error"); return; }
  const config = result.settings;
  managedKeys = result.managedKeys ?? [];
  $("#emailProtection").checked = config.emailProtection;
  $("#webProtection").checked = config.webProtection;
  $("#contextMenu").checked = config.contextMenu;
  $("#sessionIntelligence").checked = config.sessionIntelligence ?? false;
  $("#jevEnabled").checked = config.jevEnabled;
  $("#privacyMode").value = config.privacyMode;
  $("#contentSharingConsent").checked = config.contentSharingConsent === true;
  renderPrivacyPreview();
  $("#connectionMode").value = config.connectionMode;
  $("#gatewayUrl").value = config.gatewayUrl;
  $("#organizationKnowledgeBase").value = JSON.stringify(config.organizationKnowledgeBase ?? { brands: [], ssoDomains: [], vendorDomains: [], financialDomains: [], internalDomains: [] }, null, 2);
  const organizationModel = config.organizationDetectionModel;
  $("#organizationModelStatus").textContent = organizationModel?.status === "active"
    ? t("organizationModelActive", [organizationModel.modelId, organizationModel.modelVersion])
    : organizationModel?.status === "invalid"
      ? t("organizationModelInvalid")
      : t("organizationModelLocal");
  for (const key of ["emailProtection", "webProtection", "sessionIntelligence"]) if (managedKeys.includes(key)) $(`#${key}`).disabled = true;
  if (managedKeys.includes("organizationKnowledgeBase")) {
    $("#organizationKnowledgeBase").disabled = true;
    $("#saveOrganizationKnowledgeBase").disabled = true;
    $("#organizationManagedNote").hidden = false;
  }
  renderMode();
  const emailGranted = await chrome.permissions.contains({ origins: EMAIL_ORIGINS });
  const webGranted = await chrome.permissions.contains({ origins: WEB_ORIGINS });
  if (config.emailProtection && !emailGranted) {
    if (!managedKeys.includes("emailProtection")) $("#emailProtection").checked = false;
    status(t(managedKeys.includes("emailProtection") ? "emailPermissionMissingManaged" : "emailPermissionRevoked"), "error");
  }
  if (config.webProtection && !webGranted) {
    if (!managedKeys.includes("webProtection")) $("#webProtection").checked = false;
    status(t(managedKeys.includes("webProtection") ? "webPermissionMissingManaged" : "webPermissionRevoked"), "error");
  }
  if (result.hasByok) status(t("byokSessionActive"));
  else if (result.hasGatewayToken) status(t("gatewayTokenSessionActive"));
  await refreshDiagnostic();
  if (result.lastJevTest && config.jevEnabled) {
    const last = result.lastJevTest;
    status(`${last.at} · ${last.mode} · ${last.ok ? t("connectionValidated", [last.model]) : t("connectionFailed", [last.errorCode])}`, last.ok ? "success" : "error");
  }
}

$("#saveOrganizationKnowledgeBase").addEventListener("click", async () => {
  try {
    const organizationKnowledgeBase = JSON.parse($("#organizationKnowledgeBase").value || "{}");
    const result = await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: { organizationKnowledgeBase } });
    if (!result?.ok) throw new Error("ORGANIZATION_SAVE_FAILED");
    $("#organizationKnowledgeBase").value = JSON.stringify(result.settings.organizationKnowledgeBase, null, 2);
    status(t("organizationSaved"), "success");
  } catch (error) { status(error instanceof SyntaxError ? t("invalidOrganizationJson") : t("organizationSaveFailed"), "error"); }
});

$("#connectionMode").addEventListener("change", renderMode);
$("#privacyMode").addEventListener("change", renderPrivacyPreview);

$("#emailProtection").addEventListener("change", async (event) => {
  if (event.target.checked) {
    const granted = await chrome.permissions.request({ origins: EMAIL_ORIGINS });
    if (!granted) { event.target.checked = false; status(t("emailPermissionRequired"), "error"); return; }
  } else {
    await chrome.permissions.remove({ origins: EMAIL_ORIGINS });
  }
  await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: { emailProtection: event.target.checked } });
  await chrome.runtime.sendMessage({ type: "AEGIS_REFRESH_SCRIPTS", resumePaused: event.target.checked });
  status(t(event.target.checked ? "emailProtectionEnabled" : "emailProtectionDisabled"), "success");
});

$("#webProtection").addEventListener("change", async (event) => {
  if (event.target.checked) {
    const granted = await chrome.permissions.request({ origins: WEB_ORIGINS });
    if (!granted) { event.target.checked = false; status(t("webPermissionRequired"), "error"); return; }
  } else {
    await chrome.permissions.remove({ origins: WEB_ORIGINS });
  }
  await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: { webProtection: event.target.checked } });
  await chrome.runtime.sendMessage({ type: "AEGIS_REFRESH_SCRIPTS", resumePaused: event.target.checked });
  status(t(event.target.checked ? "webProtectionEnabled" : "webProtectionDisabled"), "success");
});

$("#contextMenu").addEventListener("change", async (event) => {
  if (event.target.checked) {
    const granted = await chrome.permissions.request({ permissions: ["contextMenus"] });
    if (!granted) { event.target.checked = false; status(t("contextMenuPermissionRequired"), "error"); return; }
  }
  await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: { contextMenu: event.target.checked } });
  if (!event.target.checked) await chrome.permissions.remove({ permissions: ["contextMenus"] });
  status(t(event.target.checked ? "contextMenuEnabled" : "contextMenuDisabled"), "success");
});

$("#saveByok").addEventListener("click", () => void saveSecret("byok", $("#byokKey"), t("keySavedSession")));
$("#saveGatewayToken").addEventListener("click", () => void saveSecret("gatewayToken", $("#gatewayToken"), t("gatewayTokenSavedSession")));
$("#removeByok").addEventListener("click", () => void saveSecret("byok", { value: "" }, t("keyRemovedSession")));
$("#removeGatewayToken").addEventListener("click", () => void saveSecret("gatewayToken", { value: "" }, t("gatewayTokenRemovedSession")));

$("#saveSettings").addEventListener("click", async () => {
  const next = selectedSettings();
  if (!validateContentConsent(next)) return;
  try {
    const hasPermission = await requestProviderPermission(next);
    if (!hasPermission && next.jevEnabled) {
      $("#jevEnabled").checked = false;
      next.jevEnabled = false;
      status(t("jevNotActivated"), "error");
    }
    const saved = await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: next });
    if (!saved?.ok) throw new Error("SETTINGS_SAVE_FAILED");
    await chrome.runtime.sendMessage({ type: "AEGIS_REFRESH_SCRIPTS" });
    status(t(next.jevEnabled ? "settingsSavedJev" : "settingsSavedLocal"), "success");
    await refreshDiagnostic();
  } catch { status(t("settingsSaveFailed"), "error"); }
});

$("#testConnection").addEventListener("click", async () => {
  const button = $("#testConnection");
  const config = selectedSettings();
  if (!config.jevEnabled) { status(t("enableJevToTest"), "error"); return; }
  if (!validateContentConsent(config)) return;
  button.disabled = true;
  try {
    const permission = await requestProviderPermission(config);
    if (!permission) { status(t("providerPermissionMissing"), "error"); return; }
    const saved = await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: config });
    if (!saved?.ok) { status(t("settingsSaveFailed"), "error"); return; }
    status(t("sendingSyntheticState"));
    const result = await chrome.runtime.sendMessage({ type: "AEGIS_TEST_JEV" });
    if (result?.ok) status(t("connectionValidated", [result.model]), "success");
    else status(connectionErrorText(result?.errorCode, t), "error");
    await refreshDiagnostic();
  } catch { status(t("diagnosticUnavailable"), "error"); }
  finally { button.disabled = false; }
});

void load();
