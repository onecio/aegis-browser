import { queryMonitor, summarizeConnection, summarizeMonitor } from "./operational-status.js";
import { createI18n } from "../i18n.js";
import { localizeFindingLocation, localizeFindingDetail, localizeObservedEvidence } from "./finding-copy.js";

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
  $("#riskIcon").textContent = ({ GREEN: "L", YELLOW: "!", RED: "!", UNKNOWN: "?" })[state];
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
    detail.textContent = localizeFindingDetail(finding, t);
    const where = document.createElement("small");
    where.textContent = t("findingLocation", [localizeFindingLocation(finding, t) || t("analysisLocation")]);
    item.append(detail, where);
    const observed = localizeObservedEvidence(finding, t);
    if (observed) { const evidence = document.createElement("small"); evidence.textContent = observed; item.append(evidence); }
    list.append(item);
  }
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab;
}

let currentMonitor = null;
let refreshRevision = 0;

async function refresh() {
  const revision = ++refreshRevision;
  try {
    const config = await chrome.runtime.sendMessage({ type: "AEGIS_GET_SETTINGS" });
    const tab = await activeTab();
    const monitor = await queryMonitor(tab?.id);
    if (revision !== refreshRevision) return;
    if (config?.ok) {
      $("#mode").textContent = t(config.settings.jevEnabled ? "modeIntelligence" : "modeLocal");
      $("#engine").textContent = summarizeConnection(config, t).text;
    }
    currentMonitor = monitor;
    const summary = summarizeMonitor(monitor, t);
    $("#monitorTitle").textContent = summary.title;
    $("#monitorDetail").textContent = summary.detail;
    $("#toggleMonitor").hidden = !summary.canPause;
    $("#toggleMonitor").textContent = t(monitor?.monitoring ? "monitorPauseAction" : "monitorResumeAction");
    $("#monitorCoverage").textContent = monitor?.ok ? t("monitorCoverageCopy") : "";
    if (!Number.isInteger(tab?.id)) return;
    const response = await chrome.runtime.sendMessage({ type: "AEGIS_GET_CURRENT_ANALYSIS", tabId: tab.id });
    if (revision !== refreshRevision) return;
    if (response?.analysis) renderDecision(response.analysis);
    else {
      $("#riskTitle").textContent = t("notAnalyzedTitle");
      $("#riskCopy").textContent = t("notAnalyzedCopy");
      $("#riskIcon").className = "risk-icon unknown";
      $("#riskIcon").textContent = "?";
      $("#findings").replaceChildren();
      $("#findings").hidden = true;
    }
  } catch { setStatus(t("settingsLoadFailed"), "error"); }
}

async function requestAnalysis() {
  const button = $("#analyzePage");
  button.disabled = true;
  setStatus(t("analysisInProgress"));
  try {
    const prepared = await chrome.runtime.sendMessage({ type: "AEGIS_ANALYZE_ACTIVE_TAB" });
    if (!prepared?.ok || !Number.isInteger(prepared.tabId)) throw new Error("PAGE_UNAVAILABLE");
    const scanned = await chrome.tabs.sendMessage(prepared.tabId, { type: "AEGIS_REQUEST_SCAN", userRequested: true, continuousProtection: prepared.continuousProtection });
    if (!scanned?.ok) { setStatus(t("analysisIncomplete"), "error"); return; }
    setStatus(t("localAnalysisComplete"), "success");
    await refresh();
  } catch { setStatus(t("pageAnalysisRestricted"), "error"); }
  finally { button.disabled = false; }
}

$("#toggleMonitor").addEventListener("click", async () => {
  const tab = await activeTab();
  if (!Number.isInteger(tab?.id) || !currentMonitor?.ok) return;
  const button = $("#toggleMonitor");
  button.disabled = true;
  try {
    const result = await chrome.tabs.sendMessage(tab.id, { type: currentMonitor.monitoring ? "AEGIS_STOP_MONITORING" : "AEGIS_RESUME_MONITORING" });
    if (!result?.ok) setStatus(t("monitorChangeFailed"), "error");
    await refresh();
  } catch { setStatus(t("monitorChangeFailed"), "error"); }
  finally { button.disabled = false; }
});

$("#analyzePage").addEventListener("click", () => void requestAnalysis());
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
