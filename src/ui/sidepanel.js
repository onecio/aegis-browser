import { createI18n } from "../i18n.js";
import { localizeFindingDetail, localizeFindingLocation } from "./finding-copy.js";

const { t, localizeDocument } = createI18n(chrome.i18n);
localizeDocument(document);
const stateCopy = {
  GREEN: [t("riskGreenTitle"), t("riskGreenCopy")],
  YELLOW: [t("riskYellowTitle"), t("riskYellowCopy")],
  RED: [t("riskRedTitle"), t("riskRedCopy")],
  UNKNOWN: [t("riskUnknownTitle"), t("riskUnknownCopy")]
};
const vectorNames = {
  phishing: t("vectorPhishing"), spam: t("vectorSpam"), credential: t("vectorCredential"), financial: t("vectorFinancial"),
  impersonation: t("vectorImpersonation"), socialEngineering: t("vectorSocialEngineering"), domain: t("vectorDomain"), link: t("vectorLink")
};
const jevScoreNames = {
  social_engineering_intensity: t("scoreSocialEngineering"),
  credential_risk: t("scoreCredentialRisk"),
  financial_fraud_risk: t("scoreFinancialFraud"),
  impersonation_risk: t("scoreImpersonation"),
  urgency_manipulation: t("scoreUrgency"),
  semantic_suspicion: t("scoreSemanticSuspicion")
};
const jevChoiceNames = {
  BENIGN: t("choiceBenign"), MARKETING: t("choiceMarketing"), SPAM: t("choiceSpam"), SUSPICIOUS: t("choiceSuspicious"),
  PHISHING_LIKELY: t("choicePhishingLikely"), SPEAR_PHISHING_LIKELY: t("choiceSpearPhishingLikely"), BEC_LIKELY: t("choiceBecLikely"),
  CREDENTIAL_PHISHING_LIKELY: t("choiceCredentialPhishingLikely"), QUISHING_LIKELY: t("choiceQuishingLikely"), UNKNOWN: t("choiceUnknown")
};
const jevNoulNames = {
  urgency: t("noulUrgency"), credential_request: t("noulCredentialRequest"),
  process_bypass: t("noulProcessBypass"), financial_action: t("noulFinancialAction")
};
const surfaceNames = {
  email: t("surfaceOpenedEmail"), "email-inbox": t("surfaceInbox"), web: t("surfaceWebPage"), url: t("surfaceManualUrl")
};
const $ = (selector) => document.querySelector(selector);
let currentAnalysisId = null;

function renderFeedback(decision) {
  const id = typeof decision?.analysisId === "string" ? decision.analysisId : null;
  const card = $("#feedbackCard");
  const actions = [...$("#feedbackActions").querySelectorAll("button")];
  card.hidden = !id;
  if (id !== currentAnalysisId) {
    currentAnalysisId = id;
    actions.forEach((button) => { button.disabled = false; });
    $("#feedbackStatus").textContent = "";
  }
}

function renderContext(decision) {
  const card = $("#contextCard");
  const container = $("#contextDetails");
  container.replaceChildren();
  const details = [];
  if (decision?.surface) details.push([t("contextSurface"), surfaceNames[decision.surface] ?? t("contextLocalAnalysis")]);
  if (decision?.senderDomain) details.push([t("contextSenderDomain"), decision.senderDomain]);
  if (decision?.pageDomain) details.push([t("contextPageDomain"), decision.pageDomain]);

  for (const [label, value] of details) {
    const item = document.createElement("div"); item.className = "finding";
    const title = document.createElement("strong"); title.textContent = label;
    const detail = document.createElement("small"); detail.textContent = value;
    item.append(title, detail); container.append(item);
  }

  for (const link of (decision?.links ?? []).slice(0, 8)) {
    const item = document.createElement("div"); item.className = "finding";
    const title = document.createElement("strong"); title.textContent = `${t(link.source === "qr" ? "linkQrDestination" : "linkDestination")}: ${link.domain ?? t("unresolvedAddress")}`;
    const notes = [];
    if (link.visibleDomain) notes.push(t("linkVisibleText", [link.visibleDomain]));
    if (link.mismatch) notes.push(t("linkMismatchObserved"));
    if (link.shortener) notes.push(t("linkShortenerNotFollowed"));
    if (link.organizationDomain) notes.push(t("linkOrganizationDomain", [link.organizationKinds?.length ? ` (${link.organizationKinds.join(", ")})` : ""]));
    if (link.sensitiveParams) notes.push(t("linkSensitiveParameterNames"));
    if (link.suspiciousParams) notes.push(t("linkRedirectParameter"));
    const detail = document.createElement("small"); detail.textContent = notes.join(" · ") || t("linkNoMismatchObserved");
    item.append(title, detail); container.append(item);
  }
  card.hidden = details.length === 0 && !(decision?.links?.length);
}

function renderJev(decision) {
  const card = $("#jevJudgmentsCard");
  const container = $("#jevJudgments");
  const answers = decision?.jev?.answers;
  container.replaceChildren();
  if (decision?.engineStatus?.jev !== "connected" || !answers) {
    card.hidden = true;
    return;
  }
  card.hidden = false;

  const addJudgment = (label, value, detail) => {
    const item = document.createElement("div"); item.className = "finding";
    const title = document.createElement("strong"); title.textContent = `${label}: ${value}`;
    item.append(title);
    if (detail) { const description = document.createElement("small"); description.textContent = detail; item.append(description); }
    container.append(item);
  };

  const choice = typeof answers.classification === "string" ? answers.classification : answers.classification?.choice;
  if (choice) {
    const confidence = Number(answers.classification?.confidence);
    addJudgment(t("jevClassification"), jevChoiceNames[choice] ?? t("choiceUnknown"), Number.isFinite(confidence) ? t("jevDistributionConcentration", [Math.round(confidence * 100)]) : "");
  }

  for (const [key, label] of Object.entries(jevNoulNames)) {
    const probability = answers[key];
    if (Number.isFinite(probability)) addJudgment(label, t("jevSemanticYesProbability", [Math.round(probability * 100)]), t("jevNoulEvidenceReply"));
  }

  for (const [key, label] of Object.entries(jevScoreNames)) {
    const answer = answers[key];
    if (!Number.isFinite(answer?.score)) continue;
    const nearestLevel = Math.max(0, Math.min(4, Math.round(answer.score)));
    const description = answer.legend?.[String(nearestLevel)] ?? t("jevLevelDescriptionUnavailable");
    const concentration = Number.isFinite(answer.confidence) ? t("jevConcentrationSuffix", [Math.round(answer.confidence * 100)]) : "";
    addJudgment(label, `${answer.score.toFixed(2)} / 4${concentration}`, t("jevNearestLevel", [description]));
  }
}

function render(decision) {
  const state = stateCopy[decision?.state] ? decision.state : "UNKNOWN";
  $("#riskIcon").className = `risk-icon ${state.toLowerCase()}`;
  $("#riskIcon").textContent = ({ GREEN: "✓", YELLOW: "!", RED: "!", UNKNOWN: "?" })[state];
  $("#riskTitle").textContent = stateCopy[state][0];
  $("#riskCopy").textContent = stateCopy[state][1];
  const engine = decision?.engineStatus ?? { local: "active", jev: "off" };
  $("#mode").textContent = engine.jev === "off" ? t("modeJevOff") : t("modeJevOn");
  $("#engineStatus").textContent = ({
    off: t("engineStatusJevOff"), idle: t("engineStatusJevIdle"), checking: t("engineStatusJevChecking"),
    connected: t("engineStatusJevConnected"), unavailable: t("engineStatusJevUnavailable"), error: t("engineStatusJevUnavailable")
  })[engine.jev] ?? t("engineStatusLocalOnly");
  const findings = $("#findings");
  findings.replaceChildren();
  const list = (decision?.findings ?? []).slice(0, 12);
  if (!list.length) {
    const empty = document.createElement("p"); empty.className = "note";
    empty.textContent = state === "GREEN" ? t("noMaterialIndicators") : t("noIndicatorsAvailable");
    findings.append(empty);
  } else {
    for (const finding of list) {
      const item = document.createElement("div"); item.className = "finding";
      const title = document.createElement("strong"); title.textContent = localizeFindingDetail(finding, t);
      const detail = document.createElement("small"); detail.textContent = `${vectorNames[finding.category] ?? t("genericSignal")} · ${localizeFindingLocation(finding, t) || t("analysisLocation")} · ${t(finding.source === "jev" ? "findingSourceJev" : "findingSourceLocal")}`;
      item.append(title, detail); findings.append(item);
    }
  }
  const vectors = $("#vectors");
  vectors.replaceChildren();
  for (const [key, label] of Object.entries(vectorNames)) {
    const value = Number(decision?.riskVector?.[key] ?? 0);
    const metric = document.createElement("div"); metric.className = "metric";
    const name = document.createElement("div"); name.className = "metric-label"; name.textContent = label;
    const level = document.createElement("div"); level.className = "metric-value"; level.textContent = value ? t("vectorObservedLevel", [value]) : t("vectorNoSignal");
    metric.append(name, level); vectors.append(metric);
  }
  renderContext(decision);
  renderJev(decision);
  renderFeedback(decision);
  const recommendation = $("#recommendation");
  recommendation.textContent = state === "RED"
    ? t("recommendationRed")
    : state === "YELLOW"
      ? t("recommendationYellow")
      : state === "UNKNOWN"
        ? t("recommendationUnknown")
        : t("recommendationGreen");
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab;
}

function renderDashboard(dashboard) {
  const values = [
    [t("dashboardEmailsAnalyzed"), dashboard.emailsAnalyzed],
    [t("dashboardPagesAnalyzed"), dashboard.pagesAnalyzed],
    [t("dashboardWarnings"), dashboard.warnings],
    [t("dashboardHighRiskEvents"), dashboard.highRiskEvents],
    [t("dashboardLocalAnalyses"), dashboard.localAnalyses],
    [t("dashboardJevAnalyses"), dashboard.jevAnalyses],
    [t("dashboardUsefulFeedback"), dashboard.feedback?.useful],
    [t("dashboardFalsePositives"), dashboard.feedback?.falsePositive],
    [t("dashboardSpamFeedback"), dashboard.feedback?.spam],
    [t("dashboardLegitimateFeedback"), dashboard.feedback?.legitimate],
    [t("dashboardPhishingFeedback"), dashboard.feedback?.phishing]
  ];
  const container = $("#dashboardMetrics");
  container.replaceChildren();
  for (const [label, value] of values) {
    const metric = document.createElement("div"); metric.className = "metric";
    const name = document.createElement("div"); name.className = "metric-label"; name.textContent = label;
    const count = document.createElement("div"); count.className = "metric-value"; count.textContent = String(Number.isSafeInteger(value) && value >= 0 ? value : 0);
    metric.append(name, count); container.append(metric);
  }
}

async function refreshDashboard() {
  const result = await chrome.runtime.sendMessage({ type: "AEGIS_GET_LOCAL_DASHBOARD" });
  if (!result?.ok) {
    $("#dashboardStatus").textContent = t("dashboardLoadFailed");
    return;
  }
  renderDashboard(result.dashboard);
  $("#dashboardStatus").textContent = t("dashboardStoredLocally");
}

async function refresh() {
  const tab = await currentTab();
  if (!Number.isInteger(tab?.id)) return;
  const result = await chrome.runtime.sendMessage({ type: "AEGIS_GET_CURRENT_ANALYSIS", tabId: tab.id });
  if (result?.analysis) render(result.analysis);
  else render({ state: "UNKNOWN", findings: [], riskVector: {}, engineStatus: { local: "active", jev: "off" } });
}

$("#analyze").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!Number.isInteger(tab?.id)) return;
  try {
    try { await chrome.tabs.sendMessage(tab.id, { type: "AEGIS_REQUEST_SCAN", userRequested: true }); }
    catch {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      await chrome.tabs.sendMessage(tab.id, { type: "AEGIS_REQUEST_SCAN", userRequested: true });
    }
    await refresh();
  } catch {
    $("#riskTitle").textContent = t("pageUnavailableTitle");
    $("#riskCopy").textContent = t("pageUnavailableCopy");
  }
});

$("#feedbackActions").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-feedback]");
  if (!button || !currentAnalysisId) return;
  const tab = await currentTab();
  if (!Number.isInteger(tab?.id)) return;
  const result = await chrome.runtime.sendMessage({
    type: "AEGIS_SUBMIT_FEEDBACK", kind: button.dataset.feedback,
    tabId: tab.id, analysisId: currentAnalysisId
  });
  if (!result?.ok) {
    $("#feedbackStatus").textContent = t(result?.errorCode === "STALE_ANALYSIS" ? "feedbackStaleAnalysis" : "feedbackCouldNotSave");
    return;
  }
  [...$("#feedbackActions").querySelectorAll("button")].forEach((item) => { item.disabled = true; });
  $("#feedbackStatus").textContent = t("feedbackSavedLocal");
  await refreshDashboard();
});

$("#clearDashboard").addEventListener("click", async () => {
  const result = await chrome.runtime.sendMessage({ type: "AEGIS_CLEAR_LOCAL_DASHBOARD" });
  if (!result?.ok) {
    $("#dashboardStatus").textContent = t("dashboardClearFailed");
    return;
  }
  await refreshDashboard();
});

chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === "session") void refresh();
  if (area === "local") void refreshDashboard();
});

void refresh();
void refreshDashboard();
