import { createI18n } from "../i18n.js";

const { t, localizeDocument } = createI18n(chrome.i18n);
localizeDocument(document);
const EMAIL_ORIGINS = ["https://mail.google.com/*", "https://outlook.office.com/*", "https://outlook.live.com/*"];
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
    connectionMode: $("#connectionMode").value,
    gatewayUrl: $("#gatewayUrl").value.trim()
  };
}

function renderMode() {
  const gateway = $("#connectionMode").value === "gateway";
  $("#byokFields").hidden = gateway;
  $("#gatewayFields").hidden = !gateway;
}

async function saveSecret(kind, input, successText) {
  const result = await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SECRET", kind, value: input.value.trim() });
  if (!result?.ok) { status(t("credentialSaveFailed"), "error"); return; }
  input.value = "";
  status(successText, "success");
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

$("#emailProtection").addEventListener("change", async (event) => {
  if (event.target.checked) {
    const granted = await chrome.permissions.request({ origins: EMAIL_ORIGINS });
    if (!granted) { event.target.checked = false; status(t("emailPermissionRequired"), "error"); return; }
  } else {
    await chrome.permissions.remove({ origins: EMAIL_ORIGINS });
  }
  await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: { emailProtection: event.target.checked } });
  await chrome.runtime.sendMessage({ type: "AEGIS_REFRESH_SCRIPTS" });
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
  await chrome.runtime.sendMessage({ type: "AEGIS_REFRESH_SCRIPTS" });
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
  } catch { status(t("settingsSaveFailed"), "error"); }
});

$("#testConnection").addEventListener("click", async () => {
  const config = selectedSettings();
  if (!config.jevEnabled) { status(t("enableJevToTest"), "error"); return; }
  const permission = await requestProviderPermission(config);
  if (!permission) { status(t("providerPermissionMissing"), "error"); return; }
  await chrome.runtime.sendMessage({ type: "AEGIS_SAVE_SETTINGS", settings: config });
  status(t("sendingSyntheticState"));
  const result = await chrome.runtime.sendMessage({ type: "AEGIS_TEST_JEV" });
  if (result?.ok) status(t("connectionValidated", [result.model]), "success");
  else status(t("connectionFailed", [result?.errorCode ?? t("unknownErrorCode")]), "error");
});

void load();
