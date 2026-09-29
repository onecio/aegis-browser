import { analyzeDomainIdentity } from "../core/domain-analysis.js";
import { analyzeLink, analyzeUrl, registrableDomain } from "../core/domain.js";
import { decideRisk } from "../core/decision-engine.js";
import { extractTextSignals, findBrandClaims } from "../core/text-signals.js";
import { findOrganizationBrandClaims, normalizeOrganizationKnowledgeBase } from "../core/org-configuration.js";

const MIME_TYPE_PATTERN = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;

function replaceControlCharacters(value) {
  return Array.from(String(value ?? ""), (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint < 32 || (codePoint >= 127 && codePoint <= 159) ? " " : character;
  }).join("");
}

export function normalizeAttachmentMetadata(input = {}) {
  if (!input || typeof input !== "object") input = {};
  const rawFilename = replaceControlCharacters(input.filename).trim();
  const filename = rawFilename.split(/[\\/]/).at(-1).trim().slice(0, 180);
  const explicitExtension = String(input.extension ?? "").trim().replace(/^\./, "").toLowerCase();
  const derivedExtension = filename.match(/\.([^.]+)$/)?.[1]?.toLowerCase() ?? "";
  const extension = /^[a-z0-9][a-z0-9+-]{0,19}$/.test(explicitExtension) ? explicitExtension : derivedExtension.slice(0, 20);
  const rawMimeType = String(input.mimeType ?? "").split(";", 1)[0].trim().toLowerCase();
  const mimeType = MIME_TYPE_PATTERN.test(rawMimeType) ? rawMimeType.slice(0, 120) : "";
  return { filename, extension, mimeType };
}

function filenameFromAttachmentLabel(value) {
  const label = replaceControlCharacters(value).slice(0, 400);
  const match = label.match(/(?:^|[\s"'([{])([\p{L}\p{N}_-][\p{L}\p{N}._()-]{0,160}\.[\p{L}\p{N}]{1,10})(?=$|[\s)"'\]},;])/u);
  return match?.[1] ?? "";
}

export function analyzeEmail(input = {}, { organizationKnowledgeBase = {} } = {}) {
  const knowledgeBase = normalizeOrganizationKnowledgeBase(organizationKnowledgeBase);
  const senderName = String(input.senderName ?? input.sender?.name ?? "").slice(0, 160);
  const senderAddress = String(input.senderAddress ?? input.sender?.address ?? "").slice(0, 254);
  const subject = String(input.subject ?? "").slice(0, 200);
  const rawBodyText = String(input.bodyText ?? input.preview ?? "");
  const bodyText = rawBodyText.slice(0, 24_000);
  const senderDomain = senderAddress.includes("@") ? senderAddress.split("@").at(-1).toLowerCase() : null;
  const claimText = `${senderName} ${subject} ${bodyText}`;
  const claims = [...new Set([...findBrandClaims(claimText), ...findOrganizationBrandClaims(claimText, knowledgeBase).map(({ name }) => name)])];
  const signals = [
    ...extractTextSignals(subject, "subject"),
    ...extractTextSignals(bodyText, "body")
  ];

  if (senderDomain) signals.push(...analyzeDomainIdentity({ hostname: senderDomain, claims: claimText, organizationKnowledgeBase: knowledgeBase }).signals);
  if (input.replyTo && senderDomain) {
    const replyDomain = String(input.replyTo).split("@").at(-1)?.toLowerCase();
    if (replyDomain && registrableDomain(replyDomain) !== registrableDomain(senderDomain)) {
      signals.push({ id: "REPLY_TO_DOMAIN_MISMATCH", category: "identity", severity: 4, location: "sender", detail: "O domínio de resposta difere do domínio do remetente exibido.", evidence: { senderDomain: registrableDomain(senderDomain), replyToDomain: registrableDomain(replyDomain) } });
    }
  }

  const qrUrlInputs = Array.isArray(input.qrUrls) ? input.qrUrls : [];
  const qrUrls = qrUrlInputs.slice(0, 8).flatMap((href) => {
    const destination = analyzeUrl(href);
    return destination.valid && ["http", "https"].includes(destination.scheme) && !destination.hasCredentials
      ? [{ href, visibleText: "", source: "qr" }]
      : [];
  });
  const emailLinkInputs = Array.isArray(input.links) ? input.links : [];
  const emailLinkCapacity = Math.max(0, 80 - qrUrls.length);
  const linkInputs = [...emailLinkInputs.slice(0, emailLinkCapacity), ...qrUrls];
  const links = linkInputs.map((link) => analyzeLink({ ...link, organizationKnowledgeBase: knowledgeBase }));
  signals.push(...links.flatMap((link) => link.signals));
  const qrScanIncomplete = ["unsupported", "unavailable", "partial"].includes(input.qrScanStatus);
  if (qrUrls.length) signals.push({ id: "QR_CODE_URL_DECODED", category: "context", severity: 0, location: "message", detail: "Uma URL foi decodificada de QR localmente e analisada sem abrir o destino." });
  if (qrScanIncomplete) signals.push({ id: "QR_SCAN_INCOMPLETE", category: "context", severity: 0, location: "message", detail: "A verificação local de QR não cobriu todas as imagens da mensagem neste navegador." });

  const attachmentInputs = Array.isArray(input.attachments) ? input.attachments : [];
  const attachments = attachmentInputs.slice(0, 30);
  const extractionLimits = {
    body: input.extractionLimits?.body === true || rawBodyText.length > 24_000,
    links: input.extractionLimits?.links === true || emailLinkInputs.length > emailLinkCapacity,
    attachments: input.extractionLimits?.attachments === true || attachmentInputs.length > 30,
    qrUrls: input.extractionLimits?.qrUrls === true || qrUrlInputs.length > 8
  };
  const extractionIncomplete = Object.values(extractionLimits).some(Boolean);
  for (const attachment of attachments) {
    const { filename } = normalizeAttachmentMetadata(attachment);
    if (/\.(?:pdf|docx?|xlsx?|jpg|png)\.(?:exe|scr|js|vbs|bat|cmd|ps1|msi)$/i.test(filename)) {
      signals.push({ id: "ATTACHMENT_DOUBLE_EXTENSION", category: "attachment", severity: 5, location: "attachment", detail: "O nome do anexo contém uma extensão executável após uma extensão de documento." });
    }
  }

  const safeLinks = links.map(({ destination, visible, mismatch }, index) => ({
    domain: destination.domain,
    scheme: destination.scheme,
    visibleDomain: visible?.domain ?? null,
    mismatch,
    shortener: destination.shortener,
    sensitiveParams: destination.sensitiveParams,
    suspiciousParams: destination.suspiciousParams,
    organizationDomain: destination.organizationDomain,
    organizationKinds: destination.organizationKinds,
    source: linkInputs[index]?.source === "qr" ? "qr" : "email"
  }));
  const identitySignals = signals.filter((signal) => ["identity", "domain"].includes(signal.category));
  const urgencySignals = signals.filter((signal) => /URGENCY|THREAT|FEAR/.test(signal.id));
  const financialSignals = signals.filter((signal) => signal.category === "financial");
  const credentialSignals = signals.filter((signal) => signal.category === "credential");
  const normalizedAttachments = attachments.map(normalizeAttachmentMetadata).filter((attachment) => attachment.filename || attachment.extension || attachment.mimeType);
  const normalizedEmail = {
    sender: { name: senderName, address: senderAddress, domain: registrableDomain(senderDomain) },
    subject,
    preview: String(input.preview ?? bodyText).slice(0, 700),
    links: safeLinks,
    qrScanStatus: input.qrScanStatus ?? "not-scanned",
    attachments: normalizedAttachments,
    identity_signals: identitySignals,
    urgency_signals: urgencySignals,
    financial_signals: financialSignals,
    credential_signals: credentialSignals
  };
  const contentObserved = Boolean(bodyText.trim() || links.length || qrUrls.length || normalizedAttachments.length);
  const unresolvedRedirect = links.some((link) => link.destination.suspiciousParams);
  const coverageReasons = [];
  if (!contentObserved) coverageReasons.push("Nenhum corpo visível, link, QR ou anexo foi extraído");
  if (unresolvedRedirect) coverageReasons.push("Foi detectado parâmetro de redirecionamento e o destino subsequente não foi visitado");
  if (qrScanIncomplete) coverageReasons.push("A verificação local de QR não cobriu todas as imagens da mensagem");
  if (extractionIncomplete) coverageReasons.push("Parte do conteúdo excedeu o limite local de análise e não foi examinada");
  const coverage = {
    sufficient: contentObserved && !unresolvedRedirect && !qrScanIncomplete && !extractionIncomplete,
    reasons: coverageReasons
  };
  return {
    surface: "email",
    normalizedEmail,
    signals,
    links: safeLinks,
    senderDomain: registrableDomain(senderDomain),
    claimedBrands: claims,
    subject,
    semanticExcerpt: bodyText.slice(0, 2000),
    coverage,
    decision: decideRisk({ signals, coverage })
  };
}

export function parseEmailAddress(value) {
  const match = String(value ?? "").match(/(?:^|<)\s*([^<>\s]+@[^<>\s]+)\s*>?\s*$/);
  return match ? match[1].trim().toLowerCase() : "";
}

export function extractEmailFromDocument(document, rootOverride, bodyOverride) {
  const root = rootOverride ?? document.querySelector("[role='main']") ?? document.body;
  const senderNode = root.querySelector("[email], [data-email], [data-hovercard-id]");
  const senderAddress = senderNode?.getAttribute("email") || senderNode?.getAttribute("data-email") || senderNode?.getAttribute("data-hovercard-id") || "";
  const senderName = senderNode?.getAttribute("name") || senderNode?.getAttribute("data-name") || senderNode?.textContent?.trim() || "";
  const subjectNode = root.querySelector("h1[data-thread-perm-id], h2[role='heading'], [data-testid*='subject'], h1");
  const bodyNode = bodyOverride ?? root.querySelector(".a3s, [data-testid*='message-body'], [role='document']") ?? root;
  const rawBodyText = String(bodyNode.innerText ?? bodyNode.textContent ?? "");
  const bodyText = rawBodyText.slice(0, 24000);
  const linkNodes = bodyNode.querySelectorAll("a[href]");
  const links = Array.from({ length: Math.min(linkNodes.length, 80) }, (_, index) => linkNodes[index])
    .map((anchor) => ({ href: anchor.href, visibleText: anchor.innerText || anchor.textContent || "" }));
  const attachmentSelector = "[download], [data-filename], [data-attachment-name], [data-mime-type], [data-content-type], [aria-label*='attachment' i], [aria-label*='anexo' i], [aria-label*='arquivo' i], [data-testid*='attachment' i], [data-testid*='anexo' i]";
  const attachmentNodes = root.querySelectorAll(attachmentSelector);
  const attachments = Array.from({ length: Math.min(attachmentNodes.length, 30) }, (_, index) => attachmentNodes[index]).map((node) => {
    const ariaLabel = node.getAttribute("aria-label") || "";
    const filename = node.getAttribute("download") || node.getAttribute("data-filename") || node.getAttribute("data-attachment-name") || filenameFromAttachmentLabel(ariaLabel) || filenameFromAttachmentLabel(node.textContent);
    const mimeType = node.getAttribute("data-mime-type") || node.getAttribute("data-content-type") || (node.hasAttribute("download") ? node.getAttribute("type") : "") || "";
    return normalizeAttachmentMetadata({ filename, extension: node.getAttribute("data-extension"), mimeType });
  }).filter((attachment) => attachment.filename || attachment.mimeType);
  const replyNode = root.querySelector("[email][data-hovercard-id]");
  const replyTo = replyNode?.getAttribute("email") || "";
  return {
    senderName: senderName.slice(0, 160),
    senderAddress: parseEmailAddress(senderAddress) || senderAddress,
    replyTo: parseEmailAddress(replyTo),
    subject: String(subjectNode?.innerText ?? subjectNode?.textContent ?? "").slice(0, 200),
    bodyText,
    links,
    attachments,
    extractionLimits: { body: rawBodyText.length > 24_000, links: linkNodes.length > 80, attachments: attachmentNodes.length > 30 }
  };
}

export function analyzeManualUrl(url, organizationKnowledgeBase = {}) {
  const result = analyzeUrl(url);
  if (!result.valid || !["http", "https"].includes(result.scheme)) {
    return { surface: "url", coverage: { sufficient: false, reasons: ["URL inválida ou esquema não suportado"] }, signals: [], links: [], decision: decideRisk({ analysisError: true }) };
  }
  const identity = analyzeDomainIdentity({ hostname: result.host, organizationKnowledgeBase });
  const signals = [...identity.signals];
  if (result.sensitiveParams) signals.push({ id: "URL_SENSITIVE_PARAMETER", category: "link", severity: 2, location: "url", detail: "O endereço contém parâmetros que podem incluir dados sensíveis." });
  if (result.shortener) signals.push({ id: "OBSCURED_DESTINATION", category: "link", severity: 2, location: "url", detail: "O endereço pertence a um serviço encurtador." });
  if (result.suspiciousParams) signals.push({ id: "URL_REDIRECT_PARAMETER", category: "context", severity: 0, location: "url", detail: "A URL contém um parâmetro que pode indicar redirecionamento; o destino subsequente não foi visitado." });
  const coverage = result.suspiciousParams
    ? { sufficient: false, reasons: ["Foi detectado parâmetro de redirecionamento e o destino subsequente não foi visitado"] }
    : { sufficient: true, reasons: [] };
  return { surface: "url", pageDomain: result.domain, links: [], signals, coverage, decision: decideRisk({ signals, coverage }) };
}
