const ERROR_KEYS = Object.freeze({
  UNAUTHORIZED: "diagnosticUnauthorized", FORBIDDEN: "diagnosticForbidden",
  RATE_LIMITED: "diagnosticRateLimited", TIMEOUT: "diagnosticTimeout", NETWORK_ERROR: "diagnosticNetwork",
  INVALID_RESPONSE: "diagnosticInvalidResponse", PROVIDER_UNAVAILABLE: "diagnosticUnavailable",
  PROVIDER_ERROR: "diagnosticUnavailable", CREDENTIAL_NOT_CONFIGURED: "diagnosticCredential",
  HOST_PERMISSION_MISSING: "diagnosticPermission", GATEWAY_NOT_CONFIGURED: "diagnosticGateway",
  JEV_DISABLED: "diagnosticDisabled", BACKPRESSURE: "diagnosticBackpressure",
  STALE_CONFIGURATION: "diagnosticStale", PROTECTION_DISABLED: "diagnosticProtectionDisabled",
  CONSENT_REQUIRED: "diagnosticConsent", CIRCUIT_OPEN: "diagnosticCircuitOpen",
  CANCELLED: "diagnosticCancelled", RESPONSE_TOO_LARGE: "diagnosticInvalidResponse"
});

export function connectionErrorText(code, t) {
  return t(ERROR_KEYS[code] ?? "diagnosticUnknown");
}

export function summarizeConnection(config, t) {
  if (!config?.settings?.jevEnabled) return { text: t("diagnosticDisabled"), kind: "neutral" };
  const runtime = config.connectionRuntime;
  if (runtime?.reason && !["idle", "connected", "checking", "pending"].includes(runtime.status)) {
    return { text: connectionErrorText(runtime.reason, t), kind: "warning" };
  }
  const hasCredential = config.settings.connectionMode === "byok" ? config.hasByok : config.settings.connectionMode === "gateway" ? config.hasGatewayToken : config.hasByok || config.hasGatewayToken;
  if (!hasCredential) return { text: t("diagnosticCredential"), kind: "warning" };
  if (runtime?.activeRequests || runtime?.queueLength) return { text: t("diagnosticChecking"), kind: "neutral" };
  const last = runtime?.lastTest ?? config.lastJevTest;
  const evaluated = runtime?.lastEvaluation;
  if (evaluated?.status === "connected" && (!last || Date.parse(evaluated.at) >= Date.parse(last.at))) {
    return { text: t("diagnosticInferencePassed", [evaluated.model ?? "JEV", new Date(evaluated.at).toLocaleTimeString("pt-BR")]), kind: "neutral" };
  }
  if (last?.ok) return { text: t("diagnosticTestPassed", [last.model ?? "JEV"]), kind: "neutral" };
  if (last && !last.ok) return { text: connectionErrorText(last.errorCode, t), kind: "warning" };
  return { text: t("diagnosticUntested"), kind: "neutral" };
}

export function summarizeMonitor(monitor, t) {
  if (!monitor?.ok) return { title: t("monitorNotRunning"), detail: t("monitorNotRunningCopy"), canPause: false };
  if (monitor.manualOnly || monitor.continuousProtection === false) return { title: t("monitorManualOnly"), detail: t("monitorNotRunningCopy"), canPause: false };
  const surfaces = {
    gmail: "monitorGmail", outlook: "monitorOutlook", email: "monitorEmail",
    "email-inbox": "monitorEmail", "email-opened": "monitorEmail",
    google: "monitorGoogle", bing: "monitorBing", search: "monitorSearch",
    "search-result": "monitorSearch", web: "monitorWeb", page: "monitorWeb"
  };
  const title = monitor.monitoring ? t("monitorActive") : t("monitorPaused");
  const detail = t("monitorSummary", [t(surfaces[monitor.surface] ?? "monitorWeb"), String(monitor.scannedItems ?? 0), String(monitor.markedItems ?? 0)]);
  return { title, detail, canPause: true };
}

export async function queryMonitor(tabId) {
  if (!Number.isInteger(tabId)) return null;
  try { return await chrome.tabs.sendMessage(tabId, { type: "AEGIS_GET_MONITOR_STATUS" }); }
  catch { return null; }
}
