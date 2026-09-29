import { createEmailProviderAdapter, detectEmailProvider } from "../email/providers.js";
import { createI18n } from "../i18n.js";
import { extractPageSnapshot } from "../web/page-analyzer.js";
import { highlightRiskyLinks } from "./link-highlighter.js";
import { scanQrImages } from "./quishing-analyzer.js";

const { t } = createI18n(chrome.i18n);

if (!globalThis.__AEGIS_CONTENT_READY__) {
  globalThis.__AEGIS_CONTENT_READY__ = true;
  const detectedProvider = detectEmailProvider();
  const emailAdapter = detectedProvider ? createEmailProviderAdapter(detectedProvider) : null;
  let observer;
  let timer;
  let monitoring = true;
  let activeDecision = null;
  let highRiskLinks = new WeakMap();
  const allowLink = new WeakSet();
  const allowForm = new WeakSet();
  const inFlight = new Set();
  let lastDigest = "";
  const mutationObserverOptions = {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
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
    const selector = "[data-aegis-root], [data-aegis-row-label]";
    if (node?.nodeType === Node.ELEMENT_NODE) return Boolean(node.matches(selector) || node.closest(selector));
    if (node?.nodeType === Node.TEXT_NODE) return Boolean(node.parentElement?.closest(selector));
    return false;
  }

  function startMutationObserver() {
    if (typeof MutationObserver === "undefined") return;
    observer ??= new MutationObserver((mutations) => {
      const relevant = mutations.some((mutation) => {
        if (isAegisOwnedNode(mutation.target)) return false;
        if (mutation.type === "childList") {
          return [...mutation.addedNodes, ...mutation.removedNodes].some((node) => !isAegisOwnedNode(node));
        }
        return mutation.type === "characterData" || mutation.type === "attributes";
      });
      if (relevant) scheduleScan();
    });
    observer.disconnect();
    observer.observe(document.documentElement ?? document, mutationObserverOptions);
  }

  function mountHost() {
    let host = document.querySelector("[data-aegis-root]");
    if (host) return host;
    host = document.createElement("div");
    host.dataset.aegisRoot = "true";
    host.style.cssText = "all:initial;position:fixed;z-index:2147483647;inset:auto 18px 18px auto;font-family:system-ui,sans-serif";
    document.documentElement.append(host);
    return host;
  }

  function showWarning({ title, detail, domain = "", level = "high", onContinue = null, restoreFocusTo = document.activeElement }) {
    const host = mountHost();
    const shadow = host.shadowRoot ?? host.attachShadow({ mode: "open" });
    shadow.replaceChildren();
    const style = document.createElement("style");
    style.textContent = `:host{all:initial} .scrim{position:fixed;inset:0;background:rgba(9,17,31,.58);display:grid;place-items:center;padding:20px;font:14px/1.5 system-ui,sans-serif;color:#162131} .card{box-sizing:border-box;width:min(440px,calc(100vw - 32px));background:#fff;border:1px solid #d6dee8;border-radius:16px;box-shadow:0 18px 60px #07111f55;padding:24px} .tag{font-size:11px;font-weight:750;letter-spacing:.11em;color:#b43b35} h2{font-size:20px;line-height:1.25;margin:8px 0 10px} p{margin:8px 0;color:#405168} .domain{font-family:ui-monospace,monospace;overflow-wrap:anywhere;background:#f3f6fa;border-radius:7px;padding:7px 9px;color:#26364a} .actions{display:flex;justify-content:flex-end;gap:9px;margin-top:20px} button{border:1px solid #cdd6e2;background:#fff;border-radius:8px;padding:9px 13px;font:600 13px system-ui;cursor:pointer;color:#26364a} button:focus-visible{outline:3px solid #6ca8ef;outline-offset:2px}.continue{background:#a52f2a;color:#fff;border-color:#a52f2a}`;
    style.textContent += ".tag.review{color:#76520d}.continue.review{background:#76520d;border-color:#76520d}";
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    scrim.innerHTML = `<section class="card" role="alertdialog" aria-modal="true" aria-labelledby="aegis-title" aria-describedby="aegis-detail"><div class="tag"></div><h2 id="aegis-title"></h2><p id="aegis-detail"></p><p class="domain" id="aegis-domain" hidden></p><div class="actions"><button type="button" class="cancel"></button><button type="button" class="continue"></button></div></section>`;
    shadow.append(style, scrim);
    scrim.querySelector(".tag").textContent = t(level === "review" ? "alertTagLinkMismatch" : "alertTagHighRisk");
    scrim.querySelector(".cancel").textContent = t("alertCancel");
    scrim.querySelector(".continue").textContent = t("alertContinue");
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
    scrim.querySelector(".continue").addEventListener("click", () => { close(); onContinue?.(); }, { once: true });
    shadow.querySelector(".cancel").focus();
    scrim.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== "Tab") return;
      const first = shadow.querySelector(".cancel");
      const last = shadow.querySelector(".continue");
      if (event.shiftKey && shadow.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && shadow.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
  }

  function decorateRows(items, results) {
    for (const item of items) {
      const result = results.find((candidate) => candidate.index === item.index);
      if (!result) continue;
      if (result.state === "GREEN" || result.state === "UNKNOWN") {
        if (Object.hasOwn(item.element.dataset, "aegisOriginalOutline")) {
          item.element.style.outline = item.element.dataset.aegisOriginalOutline;
          item.element.style.outlineOffset = item.element.dataset.aegisOriginalOutlineOffset;
          item.element.title = item.element.dataset.aegisOriginalTitle;
          delete item.element.dataset.aegisRisk;
          delete item.element.dataset.aegisOriginalOutline;
          delete item.element.dataset.aegisOriginalOutlineOffset;
          delete item.element.dataset.aegisOriginalTitle;
          item.element.querySelector("[data-aegis-row-label]")?.remove();
        }
        continue;
      }
      const stateLabel = t(result.state === "RED" ? "rowRiskHigh" : "rowRiskAttention");
      if (!Object.hasOwn(item.element.dataset, "aegisOriginalOutline")) {
        item.element.dataset.aegisOriginalOutline = item.element.style.outline;
        item.element.dataset.aegisOriginalOutlineOffset = item.element.style.outlineOffset;
        item.element.dataset.aegisOriginalTitle = item.element.title;
      }
      item.element.dataset.aegisRisk = result.state.toLowerCase();
      item.element.style.outline = result.state === "RED" ? "2px solid #b73d35" : "2px solid #b88621";
      item.element.style.outlineOffset = "-2px";
      item.element.title = t("rowRiskTitle", [stateLabel]);
      if (!item.element.querySelector("[data-aegis-row-label]")) {
        const label = document.createElement("span");
        label.dataset.aegisRowLabel = "true";
        label.textContent = t("rowRiskLabel", [stateLabel]);
        label.style.cssText = `display:inline-block;margin:2px 6px;padding:2px 6px;border-radius:5px;font:700 10px system-ui;color:${result.state === "RED" ? "#8d2924" : "#76520d"};background:${result.state === "RED" ? "#fff0ed" : "#fff7df"}`;
        (item.element.querySelector("td") ?? item.element).append(label);
      }
    }
  }

  function installGuards() {
    document.addEventListener("click", (event) => {
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
    }, true);

    document.addEventListener("submit", (event) => {
      if (!monitoring) return;
      const form = event.target;
      if (!activeDecision || activeDecision.state !== "RED") return;
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
    }, true);
  }

  async function analyzeOpenedEmail(userRequested = false) {
    const opened = emailAdapter.findOpenedMessage(document);
    if (!opened) return false;
    const payload = emailAdapter.extractOpenedEmail(document, opened);
    const qrScan = await scanQrImages(emailAdapter.findQrImages(document, opened));
    payload.qrUrls = qrScan.urls;
    payload.qrScanStatus = qrScan.status;
    const key = digest(payload);
    if (inFlight.has(key) || key === lastDigest) return true;
    inFlight.add(key);
    lastDigest = key;
    try {
      const result = await chrome.runtime.sendMessage({ type: "AEGIS_ANALYZE_EMAIL", payload, userRequested });
      if (result?.ok) {
        activeDecision = result.decision;
      const marked = highlightRiskyLinks(opened.body, payload.links, result.links ?? [], { hint: t("linkMismatchHint") });
        highRiskLinks = new WeakMap(marked.map((anchor) => [anchor, new URL(anchor.href, location.href).href]));
      }
    } catch { /* local monitoring remains best-effort when the worker restarts */ }
    finally { inFlight.delete(key); }
    return true;
  }

  async function analyzeInbox(userRequested = false) {
    const items = emailAdapter.extractInboxRows(document);
    if (!items.length) return;
    const payloads = items.map((item) => item.payload);
    const key = digest(payloads);
    if (inFlight.has(key) || (!userRequested && key === lastDigest)) return;
    inFlight.add(key);
    lastDigest = key;
    try {
      const result = await chrome.runtime.sendMessage({ type: "AEGIS_TRIAGE_EMAILS", payloads });
      if (result?.ok) decorateRows(items, result.results ?? []);
    } catch { /* local monitoring remains best-effort when the worker restarts */ }
    finally { inFlight.delete(key); }
  }

  async function analyzeWebPage(userRequested = false) {
    const payload = extractPageSnapshot(document);
    const root = document.querySelector("main, [role='main']") ?? document.body;
    const key = digest({ title: payload.title, text: payload.text, forms: payload.forms, links: payload.links });
    if (inFlight.has(key) || (!userRequested && key === lastDigest)) return;
    highlightRiskyLinks(root, [], []);
    highRiskLinks = new WeakMap();
    inFlight.add(key);
    lastDigest = key;
    try {
      const result = await chrome.runtime.sendMessage({ type: "AEGIS_ANALYZE_PAGE", payload, userRequested });
      if (!result?.ok) return;
      activeDecision = result.decision;
      const marked = highlightRiskyLinks(root, payload.links, result.links ?? [], { hint: t("linkMismatchHint") });
      highRiskLinks = new WeakMap(marked.map((anchor) => [anchor, new URL(anchor.href, location.href).href]));
      const dangerousForm = payload.forms.some((form) => form.hasPassword);
      if (activeDecision.state === "RED" && dangerousForm) {
        showWarning({ title: t("warningPageCredentialTitle"), detail: t("warningPageCredentialDetail"), domain: new URL(location.href).hostname });
      }
    } catch { /* local analysis is unavailable only if the extension worker cannot be reached */ }
    finally { inFlight.delete(key); }
  }

  async function scan(userRequested = false) {
    if (!monitoring) return;
    if (emailAdapter) {
      if (!(await analyzeOpenedEmail(userRequested))) await analyzeInbox(userRequested);
      return;
    }
    await analyzeWebPage(userRequested);
  }

  function scheduleScan() {
    if (!monitoring) return;
    clearTimeout(timer);
    timer = setTimeout(() => { void scan(false); }, emailAdapter ? 650 : 900);
  }

  chrome.runtime.onMessage.addListener((message, _sender, respond) => {
    if (message?.type === "AEGIS_DECISION_UPDATED") {
      activeDecision = message.decision;
      respond({ ok: true });
      return true;
    }
    if (message?.type === "AEGIS_STOP_MONITORING") {
      monitoring = false;
      clearTimeout(timer);
      observer?.disconnect();
      document.querySelector("[data-aegis-root]")?.remove();
      activeDecision = null;
      highRiskLinks = new WeakMap();
      lastDigest = "";
      respond({ ok: true });
      return true;
    }
    if (message?.type === "AEGIS_RESUME_MONITORING") {
      monitoring = true;
      startMutationObserver();
      scheduleScan();
      respond({ ok: true });
      return true;
    }
    if (message?.type !== "AEGIS_REQUEST_SCAN") return;
    monitoring = true;
    startMutationObserver();
    scan(true).then(() => respond({ ok: true })).catch(() => respond({ ok: false }));
    return true;
  });

  installGuards();
  scheduleScan();
  startMutationObserver();
}
