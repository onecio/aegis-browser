import { createI18n } from "../i18n.js";
import { localizeFindingLocation } from "./finding-copy.js";

const { t, localizeDocument } = createI18n(chrome.i18n);
localizeDocument(document);
const copy = {
  GREEN: [t("riskGreenTitle"), t("riskGreenCopy")],
  YELLOW: [t("riskYellowTitle"), t("riskYellowCopy")],
  RED: [t("riskRedTitle"), t("riskRedCopy")],
  UNKNOWN: [t("riskUnknownTitle"), t("riskUnknownCopy")]
};

const $ = (selector) => document.querySelector(selector);
const setStatus = (text, kind = "") => { const node = $("#status"); node.textContent = text; node.className = `message ${kind}`; };

function renderDecision(decision) {
  const state = copy[decision?.state] ? decision.state : "UNKNOWN";
  $("#riskIcon").className = `risk-icon ${state.toLowerCase()}`;
  $("#riskIcon").textContent = ({ GREEN: "✓", YELLOW: "!", RED: "!", UNKNOWN: "?" })[state];
  $("#riskTitle").textContent = copy[state][0];
  $("#riskCopy").textContent = copy[state][1];
  const list = $("#findings");
  list.replaceChildren();
  const findings = (decision?.findings ?? []).slice(0, 4);
  if (!findings.length) { list.hidden = true; return; }
  list.hidden = false;
  list.className = "eyebrow";
  list.textContent = t("popupFindingsHeading");
  for (const finding of findings) {
    const item = document.createElement("div");
    item.className = "finding";
    const detail = document.createElement("strong");
    detail.textContent = finding.detail;
    const where = document.createElement("small");
    where.textContent = t("findingLocation", [localizeFindingLocation(finding, t) || t("analysisLocation")]);
    item.append(detail, where);
    list.append(item);
  }
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab;
}

async function refresh() {
  const config = await chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" });
  if (config?.ok) {
    const jevOn = Boolean(config.settings.jevEnabled);
    $("#mode").textContent = jevOn ? t("modeIntelligence") : t("modeLocal");
    $("#engine").textContent = jevOn
      ? t(config.hasByok || config.hasGatewayToken ? "engineJevConfigured" : "engineJevCredentialMissing")
      : t("engineJevDisabled");
  }
  const tab = await activeTab();
  if (!Number.isInteger(tab?.id)) return;
  const response = await chrome.runtime.sendMessage({ type: "AEGIS_GET_CURRENT_ANALYSIS", tabId: tab.id });
  if (response?.analysis) renderDecision(response.analysis);
}

async function requestAnalysis(userRequested = true) {
  const tab = await activeTab();
  if (!Number.isInteger(tab?.id)) { setStatus(t("cannotIdentifyTab"), "error"); return; }
  try {
    try {
      await chrome.tabs.sendMessage(tab.id, { type: "AEGIS_REQUEST_SCAN", userRequested });
    } catch {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      await chrome.tabs.sendMessage(tab.id, { type: "AEGIS_REQUEST_SCAN", userRequested });
    }
    setStatus(t("localAnalysisComplete"), "success");
    await refresh();
  } catch {
    setStatus(t("pageAnalysisRestricted"), "error");
  }
}

$("#analyzePage").addEventListener("click", () => void requestAnalysis(true));
$("#openPanel").addEventListener("click", async () => {
  try { const tab = await activeTab(); await chrome.sidePanel.open({ tabId: tab.id }); }
  catch { setStatus(t("sidePanelOpenFailed"), "error"); }
});
$("#urlForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const resultNode = $("#urlResult");
  resultNode.className = "message";
  resultNode.textContent = t("checkingAddress");
  const result = await chrome.runtime.sendMessage({ type: "AEGIS_ANALYZE_URL", url: $("#urlInput").value });
  if (!result?.ok) { resultNode.textContent = t("addressAnalysisFailed"); resultNode.className = "message error"; return; }
  renderDecision(result.decision);
  resultNode.textContent = result.pageDomain ? t("domainAnalyzedNoNavigation", [result.pageDomain]) : t("invalidUnsupportedAddress");
  resultNode.className = `message ${result.decision.state === "RED" ? "error" : ""}`;
});

chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "session") void refresh();
});

void refresh();
