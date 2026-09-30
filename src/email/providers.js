import { extractEmailFromDocument, normalizeAttachmentMetadata, parseEmailAddress } from "./email-analyzer.js";
import { selectDynamicWindow } from "../web/dynamic-window.js";

const SELECTORS = Object.freeze({
  gmail: Object.freeze({
    openedMessage: Object.freeze([".a3s.aiL", ".a3s"]),
    inboxRows: Object.freeze(["tr.zA", "[role='main'] tr[role='main']"]),
    snippet: Object.freeze([".y2", ".y6"])
  }),
  outlook: Object.freeze({
    openedMessage: Object.freeze(["[data-testid*='message-body' i]", "[data-testid*='reading-pane' i] [role='document']", "[aria-label*='Message body' i]", "[aria-label*='Corpo da mensagem' i]", "[role='main'] [role='document']"]),
    inboxRows: Object.freeze(["[role='option'][data-testid*='message' i]", "[role='option'][data-convid]", "[role='main'] [role='option']", "[data-testid*='mail-list-item' i]", "[data-testid='message-item']"]),
    snippet: Object.freeze(["[data-testid*='preview' i]", "[data-testid*='snippet' i]", "[class*='preview' i]"])
  }),
  generic: Object.freeze({
    openedMessage: Object.freeze(["[data-testid*='message-body' i]", "[aria-label*='Message body' i]", "[aria-label*='Corpo da mensagem' i]", "[role='main'] [role='document']"]),
    inboxRows: Object.freeze(["[role='main'] [role='listitem'][data-message-id]", "[role='main'] [data-testid*='mail-list-item' i]"]),
    snippet: Object.freeze(["[data-testid*='preview' i]", "[data-testid*='snippet' i]"])
  })
});

export function detectEmailProvider(hostname = location.hostname) {
  const host = String(hostname).toLowerCase();
  if (host === "mail.google.com" || host.endsWith(".mail.google.com")) return "gmail";
  if (["outlook.office.com", "outlook.office365.com", "outlook.live.com", "outlook.cloud.microsoft"].includes(host)) return "outlook";
  return null;
}

export function normalizeEmailPayload(input = {}) {
  const senderName = String(input.senderName ?? input.sender?.name ?? "").trim().slice(0, 160);
  const senderAddress = String(input.senderAddress ?? input.sender?.address ?? "").trim().slice(0, 254);
  const normalizedAddress = parseEmailAddress(senderAddress) || senderAddress;
  const senderDomain = String(input.senderDomain ?? input.sender?.domain ?? normalizedAddress.split("@").at(-1) ?? "").toLowerCase();
  const rawBodyText = String(input.bodyText ?? input.preview ?? "");
  const bodyText = rawBodyText.slice(0, 24_000);
  const linkInputs = Array.isArray(input.links) ? input.links : [];
  const qrUrlInputs = Array.isArray(input.qrUrls) ? input.qrUrls : [];
  const attachmentInputs = Array.isArray(input.attachments) ? input.attachments : [];
  return {
    sender: { name: senderName, address: normalizedAddress, domain: senderDomain || null },
    senderName,
    senderAddress: normalizedAddress,
    senderDomain: senderDomain || null,
    replyTo: String(input.replyTo ?? "").slice(0, 254),
    subject: String(input.subject ?? "").trim().slice(0, 200),
    preview: String(input.preview ?? bodyText).slice(0, 700),
    bodyText,
    links: linkInputs.slice(0, 80).map((link) => ({
      href: String(link.href ?? "").slice(0, 4096),
      visibleText: String(link.visibleText ?? "").slice(0, 400),
      contextText: String(link.contextText ?? "").slice(0, 500),
      source: link.source === "qr" ? "qr" : "email"
    })),
    qrUrls: qrUrlInputs.slice(0, 8).map((url) => String(url).slice(0, 4096)),
    qrScanStatus: ["no-images", "unsupported", "unavailable", "partial", "scanned"].includes(input.qrScanStatus) ? input.qrScanStatus : "not-scanned",
    attachments: attachmentInputs.slice(0, 30)
      .map(normalizeAttachmentMetadata)
      .filter((attachment) => attachment.filename || attachment.extension || attachment.mimeType),
    extractionLimits: {
      body: input.extractionLimits?.body === true || rawBodyText.length > 24_000,
      links: input.extractionLimits?.links === true || linkInputs.length > 80,
      attachments: input.extractionLimits?.attachments === true || attachmentInputs.length > 30,
      qrUrls: input.extractionLimits?.qrUrls === true || qrUrlInputs.length > 8
    },
    identity_signals: Array.isArray(input.identity_signals) ? input.identity_signals.slice(0, 20) : [],
    urgency_signals: Array.isArray(input.urgency_signals) ? input.urgency_signals.slice(0, 20) : [],
    financial_signals: Array.isArray(input.financial_signals) ? input.financial_signals.slice(0, 20) : [],
    credential_signals: Array.isArray(input.credential_signals) ? input.credential_signals.slice(0, 20) : []
  };
}

export function findOpenedMessages(document, provider = "generic") {
  const selectors = SELECTORS[provider]?.openedMessage ?? SELECTORS.generic.openedMessage;
  const candidates = [...new Set(selectors.flatMap((selector) => [...document.querySelectorAll(selector)]))];
  const nestedParents = new Set();
  const candidateSet = new Set(candidates);
  for (const candidate of candidates) {
    for (let parent = candidate.parentElement; parent; parent = parent.parentElement) if (candidateSet.has(parent)) nestedParents.add(parent);
  }
  const bodies = candidates.filter((candidate) => !nestedParents.has(candidate));
  const bodySet = new Set(bodies);
  const messages = [];
  for (const body of selectDynamicWindow(bodies, 8)) {
    if (body.closest("[hidden], [aria-hidden='true']") || document.defaultView && typeof body.checkVisibility === "function" && !body.checkVisibility({ checkVisibilityCSS: true })) continue;
    const visibleText = String(body?.innerText ?? body?.textContent ?? "").trim();
    const hasMessageContent = visibleText.length > 20 || Boolean(body?.querySelector?.("img, a[href], [download], [data-attachment-name]"));
    if (body && hasMessageContent) {
      let root = body;
      for (let i = 0; i < 6 && root.parentElement; i += 1) {
        if (root.querySelector("[email], [data-email], [data-hovercard-id], [title*='@']")) break;
        const parent = root.parentElement;
        if ([...parent.querySelectorAll(selectors.join(","))].filter((candidate) => bodySet.has(candidate)).length > 1) break;
        root = parent;
      }
      messages.push({ root, body });
    }
  }
  return messages;
}

export function findOpenedMessage(document, provider = "generic") {
  return findOpenedMessages(document, provider)[0] ?? null;
}

function adjacentLinkText(anchor, root) {
  const block = anchor.closest?.("p, li, td, [data-testid*='preview' i], .y2") ?? anchor.parentElement;
  const source = block && root.contains?.(block) ? block : anchor;
  return String(source?.innerText ?? source?.textContent ?? "").trim().slice(0, 500);
}

export function extractInboxRows(document, provider) {
  const selectors = SELECTORS[provider]?.inboxRows ?? [];
  let rows = [];
  for (const selector of selectors) {
    rows = [...document.querySelectorAll(selector)];
    if (rows.length) break;
  }
  return selectDynamicWindow(rows, 20).map((row, index) => {
    const cleanRow = row.cloneNode(true);
    cleanRow.querySelectorAll("[data-aegis-row-label]").forEach((label) => label.remove());
    const addressNode = row.querySelector("[email], [data-email], [data-hovercard-id], [title*='@']");
    const rowLabel = row.getAttribute("aria-label") ?? "";
    const rawAddress = addressNode?.getAttribute("email") || addressNode?.getAttribute("data-email") || addressNode?.getAttribute("data-hovercard-id") || addressNode?.getAttribute("title") || rowLabel.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || "";
    const senderAddress = parseEmailAddress(rawAddress) || rawAddress;
    const senderName = String(addressNode?.getAttribute("name") || addressNode?.textContent || "").trim().slice(0, 120);
    const subjectNode = row.querySelector(".bog, [data-testid*='subject' i], [role='heading'], [class*='subject' i]");
    const subject = String(subjectNode?.innerText ?? subjectNode?.textContent ?? "").trim().slice(0, 180);
    const snippetSelectors = SELECTORS[provider]?.snippet ?? [];
    const snippetNode = snippetSelectors.map((selector) => row.querySelector(selector)).find(Boolean);
    const fallbackRow = cleanRow.cloneNode(true);
    fallbackRow.querySelectorAll("button, [role='button'], [aria-hidden='true'], [hidden]").forEach((node) => node.remove());
    const preview = String(snippetNode?.innerText ?? snippetNode?.textContent ?? fallbackRow.innerText ?? fallbackRow.textContent ?? "").trim().slice(0, 700);
    const links = [...row.querySelectorAll("a[href]")].filter((anchor) => !anchor.closest("[data-aegis-row-label], [hidden], [aria-hidden='true']")).slice(0, 12).map((anchor) => ({ href: anchor.href, visibleText: String(anchor.innerText || anchor.textContent || "").slice(0, 200), contextText: adjacentLinkText(anchor, row) }));
    const payload = normalizeEmailPayload({ senderName, senderAddress, subject, preview, bodyText: preview, links, attachments: [] });
    return { element: row, index, payload };
  }).filter(({ payload }) => payload.senderAddress || payload.subject || payload.bodyText);
}

export class EmailProviderAdapter {
  constructor(id) {
    if (!Object.hasOwn(SELECTORS, id)) throw new Error("Unsupported email provider adapter");
    this.id = id;
    this.openedMessageSelectors = SELECTORS[id].openedMessage;
    this.inboxRowSelectors = SELECTORS[id].inboxRows;
  }

  findOpenedMessage(document) {
    return findOpenedMessage(document, this.id);
  }

  findOpenedMessages(document) {
    return findOpenedMessages(document, this.id);
  }

  extractOpenedEmail(document, opened) {
    if (!opened?.root) return null;
    const hasOwnedDecoration = Boolean(opened.body.querySelector("[data-aegis-row-label], [data-aegis-search-label], [data-aegis-root]"));
    const cleanBody = hasOwnedDecoration && opened.body.cloneNode ? opened.body.cloneNode(true) : opened.body;
    if (hasOwnedDecoration) cleanBody.querySelectorAll("[data-aegis-row-label], [data-aegis-search-label], [data-aegis-root], [hidden], [aria-hidden='true'], script, style").forEach((label) => label.remove());
    const extracted = extractEmailFromDocument(document, opened.root, cleanBody);
    const addressNode = opened.root.querySelector("[email], [data-email], [data-hovercard-id], [title*='@']");
    if (!extracted.senderAddress && addressNode) {
      const rawAddress = addressNode.getAttribute("title") ?? "";
      extracted.senderAddress = parseEmailAddress(rawAddress) || rawAddress.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || "";
      extracted.senderName = addressNode.getAttribute("name") || addressNode.textContent || "";
    }
    extracted.links = [...opened.body.querySelectorAll("a[href]")].slice(0, 80).map((anchor) => ({ href: anchor.href, visibleText: anchor.innerText || anchor.textContent || "", contextText: adjacentLinkText(anchor, opened.body) }));
    return normalizeEmailPayload(extracted);
  }

  findQrImages(_document, opened) {
    return opened?.body?.querySelectorAll("img") ?? [];
  }

  extractInboxRows(document) {
    return extractInboxRows(document, this.id);
  }

  normalizeMessage(input) {
    return normalizeEmailPayload(input);
  }
}

export class GmailAdapter extends EmailProviderAdapter {
  constructor() { super("gmail"); }
}

export class OutlookWebAdapter extends EmailProviderAdapter {
  constructor() { super("outlook"); }
}

export class GenericWebmailAdapter extends EmailProviderAdapter {
  constructor() { super("generic"); }
}

export function createEmailProviderAdapter(provider) {
  if (provider === "gmail") return new GmailAdapter();
  if (provider === "outlook") return new OutlookWebAdapter();
  if (provider === "generic") return new GenericWebmailAdapter();
  throw new Error("Unsupported email provider adapter");
}
