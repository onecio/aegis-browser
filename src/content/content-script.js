import { shouldMarkItem } from "./visible-risk.js";
import { createEmailProviderAdapter, detectEmailProvider } from "../email/providers.js";
import { createI18n } from "../i18n.js";
import { extractPageSnapshot, extractPageFormNodes, extractPageFormSnapshot } from "../web/page-analyzer.js";
import { highlightRiskyLinks } from "./link-highlighter.js";
import { scanQrImages } from "./quishing-analyzer.js";
import { detectSearchEngine, extractSearchResults } from "../web/search-results.js";
import { isCurrentItem, itemEvidenceKey } from "./item-version.js";

const { t } = createI18n(chrome.i18n);

if (!globalThis.__AEGIS_CONTENT_READY__) {
  globalThis.__AEGIS_CONTENT_READY__ = true;
  const detectedProvider = detectEmailProvider();
  const detectedSearchEngine = detectSearchEngine();
  const emailAdapter = detectedProvider ? createEmailProviderAdapter(detectedProvider) : null;
  let observer;
  let timer;
  let dismissalTimer;
  let monitoring = true;
  let continuousProtection = true;
  let activeDecision = null;
  let currentAnalysisId = null;
  const dismissedWarnings = new Map();
  let highRiskLinks = new WeakMap();
  let guardedForms = new WeakMap();
  const allowLink = new WeakSet();
  const allowForm = new WeakSet();
  const inFlight = new Set();
  const lastDigests = new Map();
  const cachedItems = new WeakMap();
  const nodeIds = new WeakMap();
  let nextNodeId = 0;
  function nodeId(node) {
    if (!nodeIds.has(node)) nodeIds.set(node, ++nextNodeId);
    return nodeIds.get(node);
  }
  let generation = 0;
  let scanRunning = false;
  let scanQueued = false;
  let scanCompletion = Promise.resolve();
  let scanStartedAt = 0;
  let scheduledAt = 0;
  let currentRoute = location.href;
  const monitorStatus = { lastScanAt: null, scannedItems: 0, scanState: "idle", localDurationMs: null, coverage: null, errorCode: null };
  const mutationObserverOptions = {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeOldValue: true,
    attributeFilter: [
      "action", "alt", "aria-label", "autocomplete", "class", "data-attachment-name", "data-content-type",
      "data-email", "data-extension", "data-filename", "data-hovercard-id", "data-message-id", "data-mime-type",
      "data-name", "data-testid", "data-thread-perm-id", "download", "email", "form", "formaction", "href",
      "name", "role", "src", "srcset", "type"
    ]
  };

  function digest(value) {
    const text = JSON.stringify(value);
    let hash = 2166136261;
    for (let index = 0; index < text.length; index += 1) hash = Math.imul(hash ^ text.charCodeAt(index), 16777619);
    return (hash >>> 0).toString(16);
  }

  function isAegisOwnedNode(node) {
    const selector = "[data-aegis-root], [data-aegis-row-label], [data-aegis-search-label]";
    if (node?.nodeType === Node.ELEMENT_NODE) return Boolean(node.matches(selector) || node.closest(selector));
    if (node?.nodeType === Node.TEXT_NODE) return Boolean(node.parentElement?.closest(selector));
    return false;
  }

  function startMutationObserver() {
    if (typeof MutationObserver === "undefined") return;
    observer ??= new MutationObserver((mutations) => {
      const relevant = mutations.some((mutation) => {
        if (isAegisOwnedNode(mutation.target)) return false;
        if (mutation.type === "attributes" && mutation.attributeName === "class") {
          const nativeClasses = (value) => String(value ?? "").split(/\s+/).filter((name) => name && !name.startsWith("aegis-")).sort().join(" ");
          if (nativeClasses(mutation.oldValue) === nativeClasses(mutation.target.className)) return false;
        }
        if (mutation.type === "childList") {
          return [...mutation.addedNodes, ...mutation.removedNodes].some((node) => !isAegisOwnedNode(node));
        }
        return mutation.type === "characterData" || mutation.type === "attributes";
      });
      if (relevant) {
        if (activeDecision) {
          document.querySelector("[data-aegis-passive]")?.remove();
          activeDecision = null;
          currentAnalysisId = null;
          highRiskLinks = new WeakMap();
          guardedForms = new WeakMap();
          highlightRiskyLinks(document, [], []);
          for (const key of lastDigests.keys()) if (key.startsWith("opened:") || key.startsWith("page:")) lastDigests.delete(key);
        }
        for (const mutation of mutations.slice(0, 96)) {
          const element = mutation.target.nodeType === Node.ELEMENT_NODE ? mutation.target : mutation.target.parentElement;
          const row = element?.closest?.("[data-aegis-risk], [data-aegis-search-risk]");
          if (row) {
            row.querySelector("[data-aegis-row-label]")?.remove();
            row.querySelector("[data-aegis-search-label]")?.remove();
            row.classList.remove("aegis-row-risk", "aegis-row-risk-red", "aegis-row-risk-yellow");
            row.classList.remove("aegis-search-risk");
            delete row.dataset.aegisRisk;
            delete row.dataset.aegisRiskTitle;
            delete row.dataset.aegisSearchRisk;
          }
        }
        scheduleScan();
      }
    });
    observer.disconnect();
    observer.observe(document.documentElement ?? document, mutationObserverOptions);
  }

  function mountHost() {
    let host = document.querySelector("[data-aegis-root]");
    if (host) return host;
    host = document.createElement("div");
    host.dataset.aegisRoot = "true";
    document.documentElement.append(host);
    return host;
  }

  function showWarning({ title, detail, domain = "", level = "high", onContinue = null, onDismiss = null, restoreFocusTo = document.activeElement }) {
    const host = mountHost();
    const shadow = host.shadowRoot ?? host.attachShadow({ mode: "open" });
    shadow.replaceChildren();
    const style = new CSSStyleSheet();
    let warningCss;
    warningCss = `:host{all:initial} .scrim{position:fixed;inset:0;background:rgba(9,17,31,.58);display:grid;place-items:center;padding:20px;font:14px/1.5 system-ui,sans-serif;color:#162131} .card{box-sizing:border-box;width:min(440px,calc(100vw - 32px));background:#fff;border:1px solid #d6dee8;border-radius:16px;box-shadow:0 18px 60px #07111f55;padding:24px} .tag{font-size:11px;font-weight:750;letter-spacing:.11em;color:#b43b35} h2{font-size:20px;line-height:1.25;margin:8px 0 10px} p{margin:8px 0;color:#405168} .domain{font-family:ui-monospace,monospace;overflow-wrap:anywhere;background:#f3f6fa;border-radius:7px;padding:7px 9px;color:#26364a} .actions{display:flex;justify-content:flex-end;gap:9px;margin-top:20px} button{border:1px solid #cdd6e2;background:#fff;border-radius:8px;padding:9px 13px;font:600 13px system-ui;cursor:pointer;color:#26364a} button:focus-visible{outline:3px solid #6ca8ef;outline-offset:2px}.continue{background:#a52f2a;color:#fff;border-color:#a52f2a}`;
    warningCss += ".tag.review{color:#76520d}.continue.review{background:#76520d;border-color:#76520d}";
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    scrim.innerHTML = `<section class="card" role="alertdialog" aria-modal="true" aria-labelledby="aegis-title" aria-describedby="aegis-detail"><div class="tag"></div><h2 id="aegis-title"></h2><p id="aegis-detail"></p><p class="domain" id="aegis-domain" hidden></p><div class="actions"><button type="button" class="cancel"></button><button type="button" class="continue"></button></div></section>`;
    style.replaceSync(warningCss);
    shadow.adoptedStyleSheets = [style];
    shadow.append(scrim);
    scrim.querySelector(".tag").textContent = t(level === "review" ? "alertTagLinkMismatch" : "alertTagHighRisk");
    scrim.querySelector(".cancel").textContent = t("alertCancel");
    scrim.querySelector(".continue").textContent = t("alertContinue");
    if (!onContinue) scrim.querySelector(".continue").hidden = true;
    if (level === "review") {
      scrim.querySelector(".tag").classList.add("review");
      scrim.querySelector(".continue").classList.add("review");
    }
    scrim.querySelector("#aegis-title").textContent = title;
    scrim.querySelector("#aegis-detail").textContent = detail;
    const domainNode = scrim.querySelector(".domain");
    if (domain) {
      domainNode.hidden = false;
      domainNode.textContent = t("alertDestination", [domain]);
      scrim.querySelector(".card").setAttribute("aria-describedby", "aegis-detail aegis-domain");
    }
    const close = () => {
      if (!host.isConnected) return;
      host.remove();
      const focusTarget = restoreFocusTo === document.body || restoreFocusTo?.closest?.("[data-aegis-root]") ? null : restoreFocusTo;
      if (focusTarget?.isConnected && typeof focusTarget.focus === "function") focusTarget.focus({ preventScroll: true });
    };
    scrim.querySelector(".cancel").addEventListener("click", close, { once: true });
    if (onDismiss) {
      const dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.textContent = t("itemDismiss");
      dismiss.addEventListener("click", () => { onDismiss(); close(); }, { once: true });
      scrim.querySelector(".actions").append(dismiss);
    }
    scrim.querySelector(".continue").addEventListener("click", () => { close(); onContinue?.(); }, { once: true });
    shadow.querySelector(".cancel").focus();
    scrim.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab") return;
      const controls = [...shadow.querySelectorAll("button")].filter((button) => !button.hidden);
      const first = controls[0];
      const last = controls.at(-1);
      if (event.shiftKey && shadow.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && shadow.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
  }

  function isItemDismissed(item, result) {
    const key = digest(itemEvidenceKey(item, location.href, nodeId(item.element), result.findings));
    return { key, dismissed: (dismissedWarnings.get(key) ?? 0) > Date.now() };
  }

  function dismissItem(item, result) {
    dismissedWarnings.set(isItemDismissed(item, result).key, Date.now() + 600_000);
    if (dismissedWarnings.size > 128) dismissedWarnings.delete(dismissedWarnings.keys().next().value);
    item.element.querySelector("[data-aegis-row-label], [data-aegis-search-label]")?.remove();
    item.element.classList.remove("aegis-row-risk", "aegis-row-risk-red", "aegis-row-risk-yellow", "aegis-search-risk");
    delete item.element.dataset.aegisRisk;
    delete item.element.dataset.aegisRiskTitle;
    delete item.element.dataset.aegisSearchRisk;
    clearTimeout(dismissalTimer);
    const nextExpiry = Math.min(...dismissedWarnings.values());
    dismissalTimer = setTimeout(() => {
      for (const [key, expires] of dismissedWarnings) if (expires <= Date.now()) dismissedWarnings.delete(key);
      scheduleScan();
    }, Math.max(0, nextExpiry - Date.now()));
  }

  function showPassiveWarning({ title, detail, domain, key }) {
    if ((dismissedWarnings.get(key) ?? 0) > Date.now()) return;
    const host = mountHost();
    host.dataset.aegisPassive = "true";
    const shadow = host.shadowRoot ?? host.attachShadow({ mode: "open" });
    const stylesheet = new CSSStyleSheet();
    stylesheet.replaceSync(":host{all:initial} .notice{display:flex;gap:6px;max-width:360px;background:#fff;border:1px solid #b73d35;border-radius:8px;padding:6px;box-shadow:0 4px 16px #0002} button{font:600 12px/1.4 system-ui;color:#8d2924;background:#fff;border:0;padding:6px;cursor:pointer}button:focus-visible{outline:2px solid #2862a8}");
    shadow.adoptedStyleSheets = [stylesheet];
    const notice = document.createElement("div");
    notice.className = "notice";
    const details = document.createElement("button");
    details.type = "button";
    details.textContent = `AEGIS · ${title}`;
    details.title = detail;
    details.onclick = () => showWarning({ title, detail, domain, restoreFocusTo: details });
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.textContent = t("passiveDismiss");
    dismiss.onclick = () => {
      dismissedWarnings.set(key, Date.now() + 600_000);
      const route = location.href;
      clearTimeout(dismissalTimer);
      dismissalTimer = setTimeout(() => {
        if (!monitoring || route !== location.href) return;
        lastDigests.delete(key);
        scheduleScan();
      }, 600_000);
      if (dismissedWarnings.size > 128) dismissedWarnings.delete(dismissedWarnings.keys().next().value);
      host.remove();
    };
    notice.append(details, dismiss);
    shadow.replaceChildren(notice);
  }

  function decorateRows(items, results, { openedMessage = false } = {}) {
    for (const item of items) {
      const result = results.find((candidate) => candidate.index === item.index);
      if (!result) continue;
      cachedItems.set(item.element, { route: location.href, payload: digest(item.payload), result });
      if (!shouldMarkItem(result) || isItemDismissed(item, result).dismissed) {
        item.element.classList.remove("aegis-row-risk", "aegis-row-risk-red", "aegis-row-risk-yellow");
        item.element.removeAttribute("data-aegis-risk");
        item.element.removeAttribute("data-aegis-risk-title");
        item.element.querySelector("[data-aegis-row-label]")?.remove();
        continue;
      }
      const category = result.riskCategory ?? result.kind;
      const stateLabel = t(category === "clickfix" ? "rowRiskClickFix" : category === "phishing" ? "rowRiskPhishing" : category === "spam" ? "rowRiskSpam" : result.state === "RED" ? "rowRiskHigh" : "rowRiskAttention");
      item.element.dataset.aegisRisk = result.state.toLowerCase();
      item.element.dataset.aegisRiskTitle = t("rowRiskTitle", [stateLabel]);
      item.element.classList.toggle("aegis-row-risk-red", result.state === "RED");
      item.element.classList.toggle("aegis-row-risk-yellow", result.state !== "RED");
      item.element.classList.add("aegis-row-risk");
      {
        const label = item.element.querySelector("[data-aegis-row-label]") ?? document.createElement("button");
        label.type = "button";
        label.dataset.aegisRowLabel = "true";
        label.textContent = t("rowRiskLabel", [stateLabel]);
        label.title = (result.findings ?? []).map((finding) => finding.detail).filter(Boolean).join(" ").slice(0, 1200) || stateLabel;
        label.onclick = (event) => {
          event.preventDefault();
          event.stopPropagation();
          showWarning({ title: stateLabel, detail: label.title, level: result.state === "RED" ? "high" : "review", restoreFocusTo: label, onDismiss: () => dismissItem(item, result) });
        };
        label.className = `aegis-row-label ${result.state === "RED" ? "aegis-row-label-red" : "aegis-row-label-yellow"}`;
        if (openedMessage) item.element.prepend(label);
        else (item.element.querySelector("td") ?? item.element).append(label);
      }
    }
  }

  function decorateSearchResults(items, results) {
    for (const item of items) {
      const result = results.find((candidate) => candidate.index === item.index);
      if (result) cachedItems.set(item.element, { route: location.href, payload: digest(item.payload), result });
      const existing = item.element.querySelector(":scope > [data-aegis-search-label]");
      if (!result || result.state !== "RED" || !shouldMarkItem(result) || isItemDismissed(item, result).dismissed) {
        existing?.remove();
        item.element.classList.remove("aegis-search-risk");
        delete item.element.dataset.aegisSearchRisk;
        continue;
      }
      item.element.dataset.aegisSearchRisk = "red";
      item.element.classList.add("aegis-search-risk");
      {
        const label = existing ?? document.createElement("button");
        label.type = "button";
        label.dataset.aegisSearchLabel = "true";
        label.textContent = `AEGIS · ${t("searchRiskEvidence")}`;
        label.title = (result.findings ?? []).map((finding) => finding.detail).filter(Boolean).join(" ").slice(0, 1200) || t("searchRiskEvidence");
        label.onclick = (event) => {
          event.preventDefault();
          event.stopPropagation();
          showWarning({ title: t("searchRiskEvidence"), detail: label.title, domain: new URL(item.payload.href).hostname, restoreFocusTo: label, onDismiss: () => dismissItem(item, result) });
        };
        label.className = "aegis-search-label";
        item.element.prepend(label);
      }
    }
  }

  function clearDecorations() {
    for (const element of document.querySelectorAll("[data-aegis-risk]")) {
      element.classList.remove("aegis-row-risk", "aegis-row-risk-red", "aegis-row-risk-yellow");
      element.querySelector("[data-aegis-row-label]")?.remove();
      delete element.dataset.aegisRisk;
      delete element.dataset.aegisRiskTitle;
    }
    for (const element of document.querySelectorAll("[data-aegis-search-risk]")) {
      element.classList.remove("aegis-search-risk");
      element.querySelector(":scope > [data-aegis-search-label]")?.remove();
      delete element.dataset.aegisSearchRisk;
    }
  }

  function guardRiskLink(event) {
      if (!monitoring) return;
      const anchor = event.target?.closest?.("a[href]");
      if (!anchor) return;
      const expectedHref = highRiskLinks.get(anchor);
      if (!expectedHref) return;
      if (allowLink.has(anchor)) { allowLink.delete(anchor); return; }
      let actualHref;
      try { actualHref = new URL(anchor.href, location.href).href; } catch { return; }
      if (actualHref !== expectedHref) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      let host = "destino externo";
      try { host = new URL(actualHref).hostname; } catch { /* use a neutral label */ }
      showWarning({
        title: t("warningLinkMismatchTitle"),
        detail: t("warningLinkMismatchDetail"),
        domain: host,
        level: "review",
        restoreFocusTo: anchor,
        onContinue: () => { allowLink.add(anchor); anchor.click(); }
      });
  }

  function guardCredentialSubmit(event) {
      if (!monitoring) return;
      const form = event.target;
      const binding = guardedForms.get(form);
      if (!binding || binding.route !== location.href || binding.snapshot !== digest(extractPageFormSnapshot(form))) return;
      let actualAction;
      try { actualAction = new URL(form.getAttribute("action") || location.href, location.href).href; } catch { return; }
      if (actualAction !== binding.action) return;
      if (allowForm.has(form)) { allowForm.delete(form); return; }
      if (!form.querySelector("input[type='password']")) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      const action = form.getAttribute("action") || location.href;
      let destination = t("currentDomain");
      try { destination = new URL(action, location.href).hostname; } catch { /* use the page origin */ }
      showWarning({
        title: t("warningCredentialFormTitle"),
        detail: t("warningCredentialFormDetail"),
        domain: destination,
        restoreFocusTo: event.submitter ?? (document.activeElement === document.body ? form.querySelector("input[type='password']") : document.activeElement),
        onContinue: () => { allowForm.add(form); form.requestSubmit(); }
      });
  }

  function installGuards() {
    document.addEventListener("click", guardRiskLink, true);
    document.addEventListener("submit", guardCredentialSubmit, true);
  }

  function removeGuards() {
    document.removeEventListener("click", guardRiskLink, true);
    document.removeEventListener("submit", guardCredentialSubmit, true);
  }

  function recordResponse(result, coverage) {
    if (!result?.ok) {
      monitorStatus.scanState = "unavailable";
      monitorStatus.errorCode = result?.errorCode ?? "WORKER_UNAVAILABLE";
      return false;
    }
    if (monitorStatus.localDurationMs === null) monitorStatus.localDurationMs = Math.round(performance.now() - scanStartedAt);
    monitorStatus.coverage = coverage;
    if (monitorStatus.scanState !== "unavailable") monitorStatus.scanState = "completed";
    if (result.decision?.coverage?.sufficient === false || result.results?.some((item) => item.coverage?.sufficient === false || item.engineStatus?.jev === "pending")) {
      if (monitorStatus.scanState !== "unavailable") monitorStatus.scanState = "partial";
    }
    return true;
  }

  async function analyzeOpenedEmail(userRequested = false) {
    const messages = emailAdapter.findOpenedMessages(document);
    monitorStatus.scannedItems += messages.length;
    for (const opened of messages) {
      const route = location.href;
      const version = generation;
      const payload = emailAdapter.extractOpenedEmail(document, opened);
      const originalPayload = digest(payload);
      const qrScan = await scanQrImages(emailAdapter.findQrImages(document, opened));
      if (route !== location.href || version !== generation || !opened.body.isConnected || digest(emailAdapter.extractOpenedEmail(document, opened)) !== originalPayload) continue;
      payload.qrUrls = qrScan.urls;
      payload.qrScanStatus = qrScan.status;
      const key = "opened:" + digest({ route, node: nodeId(opened.body), payload });
      if (inFlight.has(key) || !userRequested && lastDigests.has(key)) continue;
      inFlight.add(key);
      lastDigests.set(key, true);
      if (lastDigests.size > 128) lastDigests.delete(lastDigests.keys().next().value);
      try {
        const result = await chrome.runtime.sendMessage({ type: "AEGIS_ANALYZE_EMAIL", payload, userRequested });
        if (!recordResponse(result, "opened-message")) lastDigests.delete(key);
        if (result?.ok && (monitoring || userRequested) && version === generation && route === location.href && opened.body.isConnected && digest(emailAdapter.extractOpenedEmail(document, opened)) === originalPayload) {
          activeDecision = result.decision;
          currentAnalysisId = result.analysisId ?? null;
          if (monitoring) {
            decorateRows([{ element: opened.root, index: 0, payload }], [{ ...result.decision, index: 0 }], { openedMessage: true });
            const marked = highlightRiskyLinks(opened.body, payload.links, result.links ?? [], { hint: t("linkMismatchHint") });
            for (const anchor of marked) highRiskLinks.set(anchor, new URL(anchor.href, location.href).href);
          }
        }
      } catch { lastDigests.delete(key); recordResponse(null, "opened-message"); }
      finally {
        inFlight.delete(key);
        if (monitoring && version !== generation) scheduleScan();
      }
    }
    return messages.length > 0;
  }

  async function analyzeInbox(userRequested = false) {
    const items = emailAdapter.extractInboxRows(document);
    monitorStatus.scannedItems += items.length;
    if (!items.length) return;
    const payloads = items.map((item) => item.payload);
    if (monitoring) decorateRows(items, items.flatMap((item) => {
      const cached = cachedItems.get(item.element);
      return cached?.route === location.href && cached.payload === digest(item.payload) ? [{ ...cached.result, index: item.index }] : [];
    }));
    const key = "items:" + digest({ route: location.href, nodes: items.map((item) => nodeId(item.element)), payloads });
    if (inFlight.has(key) || (!userRequested && lastDigests.has(key))) return;
    inFlight.add(key);
    lastDigests.set(key, true);
    if (lastDigests.size > 128) lastDigests.delete(lastDigests.keys().next().value);
    const route = location.href;
    const version = generation;
    try {
      let result = await chrome.runtime.sendMessage({ type: "AEGIS_TRIAGE_EMAILS", payloads });
      if (!recordResponse(result, "inbox-preview")) lastDigests.delete(key);
      if (result?.ok && (monitoring || userRequested) && version === generation) {
        const current = emailAdapter.extractInboxRows(document);
        const currentItems = items.filter((item) => isCurrentItem(item, current, route, location.href));
        if (monitoring) decorateRows(currentItems, result.results ?? []);
        if (currentItems.length !== items.length) { scanQueued = true; return; }
        if (result.results?.some((item) => item.engineStatus?.jev === "pending")) {
          result = await chrome.runtime.sendMessage({ type: "AEGIS_TRIAGE_EMAILS", payloads, enrich: true });
          if (!recordResponse(result, "inbox-preview")) lastDigests.delete(key);
          if (result?.ok && monitoring && version === generation) {
            const fresh = emailAdapter.extractInboxRows(document);
            decorateRows(items.filter((item) => isCurrentItem(item, fresh, route, location.href)), result.results ?? []);
          }
        }
      }
    } catch { lastDigests.delete(key); recordResponse(null, "inbox-preview"); }
    finally {
      inFlight.delete(key);
      if (monitoring && version !== generation) scheduleScan();
    }
  }

  async function analyzeWebPage(userRequested = false) {
    monitorStatus.scannedItems += 1;
    const payload = extractPageSnapshot(document);
    const pageFormNodes = extractPageFormNodes(document).slice(0, 40);
    const root = document.querySelector("main, [role='main']") ?? document.body;
    const route = location.href;
    const version = generation;
    const snapshotKey = digest(payload);
    const key = "page:" + digest({ route, node: nodeId(root), payload });
    if (inFlight.has(key) || (!userRequested && lastDigests.has(key))) return;
    highlightRiskyLinks(root, [], []);
    highRiskLinks = new WeakMap();
    guardedForms = new WeakMap();
    inFlight.add(key);
    lastDigests.set(key, true);
    if (lastDigests.size > 128) lastDigests.delete(lastDigests.keys().next().value);
    try {
      const result = await chrome.runtime.sendMessage({ type: "AEGIS_ANALYZE_PAGE", payload, userRequested });
      if (!recordResponse(result, "page-visible")) { lastDigests.delete(key); return; }
      if (!(monitoring || userRequested) || version !== generation || route !== location.href || !root.isConnected || snapshotKey !== digest(extractPageSnapshot(document))) return;
      activeDecision = result.decision;
      currentAnalysisId = result.analysisId ?? null;
      if (monitoring) {
        guardedForms = new WeakMap(pageFormNodes.flatMap((form, index) => {
          if (!result.decision.credentialGuardScopes?.includes(`form:${index}`)) return [];
          const snapshot = extractPageFormSnapshot(form);
          return [[form, { route, snapshot: digest(snapshot), action: new URL(snapshot.action || route, route).href }]];
        }));
        const marked = highlightRiskyLinks(root, payload.links, result.links ?? [], { hint: t("linkMismatchHint") });
        highRiskLinks = new WeakMap(marked.map((anchor) => [anchor, new URL(anchor.href, location.href).href]));
      }
      const dangerousForm = payload.forms.some((form) => form.hasPassword);
      const clickFix = activeDecision.findings?.some((finding) => finding.id === "CLICKFIX_EXECUTION_INSTRUCTIONS");
      if (!userRequested && activeDecision.state === "RED" && (clickFix || dangerousForm)) {
        showPassiveWarning({ title: t(clickFix ? "warningClickFixTitle" : "warningPageCredentialTitle"), detail: t(clickFix ? "warningClickFixDetail" : "warningPageCredentialDetail"), domain: new URL(location.href).hostname, key });
      } else if (document.querySelector("[data-aegis-passive]")) document.querySelector("[data-aegis-passive]").remove();
      if (monitoring && userRequested && activeDecision.state === "RED" && clickFix) {
        showWarning({ title: t("warningClickFixTitle"), detail: t("warningClickFixDetail"), domain: new URL(location.href).hostname });
      } else if (monitoring && userRequested && activeDecision.state === "RED" && dangerousForm) {
        showWarning({ title: t("warningPageCredentialTitle"), detail: t("warningPageCredentialDetail"), domain: new URL(location.href).hostname });
      }
    } catch { lastDigests.delete(key); recordResponse(null, "page-visible"); }
    finally {
      inFlight.delete(key);
      if (monitoring && version !== generation) scheduleScan();
    }
  }

  async function analyzeSearchPage(userRequested = false) {
    const items = extractSearchResults(document, detectedSearchEngine);
    monitorStatus.scannedItems += items.length;
    if (!items.length) return;
    const payloads = items.map((item) => item.payload);
    if (monitoring) decorateSearchResults(items, items.flatMap((item) => {
      const cached = cachedItems.get(item.element);
      return cached?.route === location.href && cached.payload === digest(item.payload) ? [{ ...cached.result, index: item.index }] : [];
    }));
    const key = "items:" + digest({ route: location.href, nodes: items.map((item) => nodeId(item.element)), payloads });
    if (inFlight.has(key) || !userRequested && lastDigests.has(key)) return;
    inFlight.add(key);
    lastDigests.set(key, true);
    if (lastDigests.size > 128) lastDigests.delete(lastDigests.keys().next().value);
    const route = location.href;
    const version = generation;
    try {
      let result = await chrome.runtime.sendMessage({ type: "AEGIS_TRIAGE_SEARCH_RESULTS", payloads });
      if (!recordResponse(result, "search-preview")) lastDigests.delete(key);
      if (result?.ok && (monitoring || userRequested) && version === generation) {
        const current = extractSearchResults(document, detectedSearchEngine);
        const currentItems = items.filter((item) => isCurrentItem(item, current, route, location.href));
        if (monitoring) decorateSearchResults(currentItems, result.results ?? []);
        if (currentItems.length !== items.length) { scanQueued = true; return; }
        if (result.results?.some((item) => item.engineStatus?.jev === "pending")) {
          result = await chrome.runtime.sendMessage({ type: "AEGIS_TRIAGE_SEARCH_RESULTS", payloads, enrich: true });
          if (!recordResponse(result, "search-preview")) lastDigests.delete(key);
          if (result?.ok && monitoring && version === generation) {
            const fresh = extractSearchResults(document, detectedSearchEngine);
            decorateSearchResults(items.filter((item) => isCurrentItem(item, fresh, route, location.href)), result.results ?? []);
          }
        }
      }
    } catch { lastDigests.delete(key); recordResponse(null, "search-preview"); }
    finally {
      inFlight.delete(key);
      if (monitoring && version !== generation) scheduleScan();
    }
  }

  async function scan(userRequested = false) {
    if (!monitoring && !userRequested) return { ok: false, errorCode: "MONITORING_PAUSED" };
    if (scanRunning) {
      scanQueued = true;
      if (!userRequested) return { ok: true, queued: true };
      await scanCompletion;
      return scan(true);
    }
    if (currentRoute !== location.href) routeChanged();
    scanRunning = true;
    scanQueued = false;
    scanStartedAt = performance.now();
    monitorStatus.scanState = "scanning";
    monitorStatus.scannedItems = 0;
    monitorStatus.localDurationMs = null;
    monitorStatus.errorCode = null;
    let finishScan;
    scanCompletion = new Promise((resolve) => { finishScan = resolve; });
    try {
      if (emailAdapter) await Promise.all([analyzeOpenedEmail(userRequested), analyzeInbox(userRequested)]);
      else if (detectedSearchEngine) await analyzeSearchPage(userRequested);
      else await analyzeWebPage(userRequested);
      if (monitorStatus.scanState === "scanning") monitorStatus.scanState = monitorStatus.scannedItems ? "completed" : "idle";
      monitorStatus.lastScanAt = new Date().toISOString();
      monitorStatus.totalDurationMs = Math.round(performance.now() - scanStartedAt);
      return { ok: monitorStatus.scanState !== "unavailable", errorCode: monitorStatus.errorCode };
    } finally {
      scanRunning = false;
      finishScan();
      if (monitoring && scanQueued) scheduleScan();
    }
  }

  function routeChanged() {
    currentRoute = location.href;
    document.querySelector("[data-aegis-passive]")?.remove();
    generation += 1;
    lastDigests.clear();
    clearDecorations();
    highlightRiskyLinks(document, [], []);
    highRiskLinks = new WeakMap();
    guardedForms = new WeakMap();
    activeDecision = null;
    currentAnalysisId = null;
    scheduleScan();
  }

  function attachNavigationListeners() {
    document.addEventListener("scroll", scheduleScan, { capture: true, passive: true });
    window.addEventListener("hashchange", routeChanged);
    window.addEventListener("popstate", routeChanged);
  }

  function scheduleScan() {
    if (!monitoring) return;
    if (currentRoute !== location.href) { routeChanged(); return; }
    if (scanRunning) { scanQueued = true; return; }
    if (!scheduledAt) scheduledAt = performance.now();
    clearTimeout(timer);
    timer = setTimeout(() => { scheduledAt = 0; void scan(false); }, Math.max(0, Math.min(160, 700 - (performance.now() - scheduledAt))));
  }

  chrome.runtime.onMessage.addListener((message, _sender, respond) => {
    if (message?.type === "AEGIS_GET_MONITOR_STATUS") {
      respond({ ok: true, surface: detectedProvider ?? detectedSearchEngine ?? "web", monitoring, continuousProtection, manualOnly: !continuousProtection, ...monitorStatus, markedItems: document.querySelectorAll("[data-aegis-row-label], [data-aegis-search-label], [data-aegis-passive]").length });
      return true;
    }
    if (message?.type === "AEGIS_DECISION_UPDATED") {
      if (monitoring && message.analysisId === currentAnalysisId && message.sourceUrl === location.href) activeDecision = message.decision;
      respond({ ok: true });
      return true;
    }
    if (message?.type === "AEGIS_STOP_MONITORING") {
      monitoring = false;
      generation += 1;
      clearTimeout(timer);
      scheduledAt = 0;
      scanQueued = false;
      clearTimeout(dismissalTimer);
      observer?.disconnect();
      removeGuards();
      document.removeEventListener("scroll", scheduleScan, true);
      window.removeEventListener("hashchange", routeChanged);
      window.removeEventListener("popstate", routeChanged);
      document.querySelector("[data-aegis-root]")?.remove();
      clearDecorations();
      highlightRiskyLinks(document, [], []);
      activeDecision = null;
      currentAnalysisId = null;
      highRiskLinks = new WeakMap();
      guardedForms = new WeakMap();
      lastDigests.clear();
      respond({ ok: true });
      return true;
    }
    if (message?.type === "AEGIS_RESUME_MONITORING") {
      if (message.continuousProtection === true) continuousProtection = true;
      if (!continuousProtection) { respond({ ok: false, errorCode: "CONTINUOUS_PROTECTION_DISABLED" }); return true; }
      monitoring = true;
      installGuards();
      attachNavigationListeners();
      startMutationObserver();
      scheduleScan();
      respond({ ok: true });
      return true;
    }
    if (message?.type !== "AEGIS_REQUEST_SCAN") return;
    if (typeof message.continuousProtection === "boolean") continuousProtection = message.continuousProtection;
    if (message.continuousProtection === false && monitoring) {
      monitoring = false;
      generation += 1;
      clearTimeout(timer);
      clearTimeout(dismissalTimer);
      scheduledAt = 0;
      scanQueued = false;
      observer?.disconnect();
      removeGuards();
      document.removeEventListener("scroll", scheduleScan, true);
      window.removeEventListener("hashchange", routeChanged);
      window.removeEventListener("popstate", routeChanged);
      clearDecorations();
      highlightRiskyLinks(document, [], []);
      document.querySelector("[data-aegis-root]")?.remove();
      highRiskLinks = new WeakMap();
      guardedForms = new WeakMap();
    }
    scan(true).then(respond).catch(() => respond({ ok: false, errorCode: "CONTENT_SCAN_FAILED" }));
    return true;
  });

  installGuards();
  attachNavigationListeners();
  scheduleScan();
  startMutationObserver();
}
