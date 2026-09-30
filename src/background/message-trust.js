const UI_PAGES = new Set(["/popup.html", "/options.html", "/sidepanel.html"]);

export function isTrustedUiSender(sender, extensionId, pages = UI_PAGES) {
  if (sender?.id !== extensionId || typeof sender.url !== "string" || sender.frameId != null && sender.frameId !== 0) return false;
  try {
    const url = new URL(sender.url);
    return url.protocol === "chrome-extension:" && url.hostname === extensionId && pages.has(url.pathname);
  } catch { return false; }
}

export function isTrustedContentSender(sender, extensionId) {
  if (sender?.id !== extensionId || !Number.isInteger(sender.tab?.id) || sender.frameId !== 0 || typeof sender.url !== "string") return false;
  try {
    const url = new URL(sender.url);
    return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password;
  } catch { return false; }
}

export function documentUrl(value) {
  try {
    const url = new URL(value);
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) return null;
    // Fragment changes do not create a new browser document; content has its own SPA item guards.
    url.hash = "";
    return url.href;
  } catch { return null; }
}

export const UI_ONLY_MESSAGES = new Set([
  "AEGIS_GET_CURRENT_ANALYSIS", "AEGIS_GET_SETTINGS", "AEGIS_SAVE_SETTINGS", "AEGIS_SAVE_SECRET", "AEGIS_REFRESH_SCRIPTS",
  "AEGIS_ANALYZE_URL", "AEGIS_TEST_JEV", "AEGIS_ANALYZE_ACTIVE_TAB",
  "AEGIS_GET_LOCAL_DASHBOARD", "AEGIS_CLEAR_LOCAL_DASHBOARD", "AEGIS_SUBMIT_FEEDBACK"
]);
