import { analyzeDomainIdentity } from "../core/domain-analysis.js";
import { analyzeLink, analyzeUrl } from "../core/domain.js";
import { decideRisk } from "../core/decision-engine.js";
import { extractTextSignals, findBrandClaims } from "../core/text-signals.js";
import { findOrganizationBrandClaims, matchOrganizationDomains, normalizeOrganizationKnowledgeBase } from "../core/org-configuration.js";
import { classifyBitBStructure, inspectBitBStructure } from "./bitb-analyzer.js";
import { analyzeClickFix } from "./clickfix-analyzer.js";

function withinPageWindow(element, height) {
  if (element.closest?.("[hidden], [aria-hidden='true'], [inert], [data-aegis-root]")) return false;
  if (typeof element.checkVisibility === "function" && !element.checkVisibility({ checkVisibilityCSS: true })) return false;
  const rect = element.getBoundingClientRect?.();
  return Boolean(rect && rect.height > 0 && rect.width > 0 && rect.bottom >= -240 && rect.top <= height + 480);
}

export function extractPageFormNodes(document) {
  const nodes = [...document.querySelectorAll("form")].filter((form) => !form.closest?.("[hidden], [aria-hidden='true']"));
  const height = document.defaultView?.innerHeight;
  return height === undefined ? nodes : nodes.filter((form) => withinPageWindow(form, height));
}

export function extractPageFormSnapshot(form) {
  const hasPassword = Boolean(form.querySelector("input[type='password']:not([disabled])"));
  const hasCredentialField = hasPassword || Boolean(form.querySelector("input[autocomplete*='username' i]:not([disabled]), input[type='email']:not([disabled])"));
  return { action: (form.getAttribute("action") || "").slice(0, 2048), hasPassword, hasCredentialField, contextText: String(form.innerText ?? form.textContent ?? "").slice(0, 500) };
}

function windowText(document, main, fallback) {
  if (!document.defaultView || !document.createTreeWalker || !document.createRange) return { text: fallback.slice(0, 24000), truncated: fallback.length > 24000, viewportLimited: false };
  const height = document.defaultView.innerHeight;
  const walker = document.createTreeWalker(main, 4);
  const range = document.createRange();
  const parts = [];
  let previousBlock = null;
  let length = 0;
  let examined = 0;
  let truncated = false;
  let viewportLimited = false;
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (++examined > 10000) { truncated = true; break; }
    const raw = String(node.textContent ?? "");
    const parent = node.parentElement;
    if (!raw.trim() || !parent || parent.closest("script, style, noscript, textarea, [hidden], [aria-hidden='true'], [inert], [data-aegis-root], [data-aegis-row-label], [data-aegis-search-label]")) continue;
    if (typeof parent.checkVisibility === "function" && !parent.checkVisibility({ checkVisibilityCSS: true })) continue;
    range.selectNodeContents(node);
    const rect = range.getBoundingClientRect();
    if (!rect.height || !rect.width || rect.bottom < -240 || rect.top > height + 480) { viewportLimited = true; continue; }
    let start = 0;
    let end = raw.length;
    // A long text node can span the entire document. Locate the visible lines
    // rather than repeatedly slicing its first characters on every scroll.
    if (raw.length > 3000 && (rect.top < -240 || rect.bottom > height + 480)) {
      const boundary = (isBefore) => {
        let lower = 0;
        let upper = raw.length;
        while (lower < upper) {
          const middle = Math.floor((lower + upper) / 2);
          range.setStart(node, middle);
          range.setEnd(node, Math.min(raw.length, middle + 1));
          if (isBefore(range.getBoundingClientRect())) lower = middle + 1;
          else upper = middle;
        }
        return lower;
      };
      start = Math.max(0, boundary((character) => character.bottom < -240) - 1000);
      end = Math.min(raw.length, boundary((character) => character.top <= height + 480) + 1000);
      viewportLimited ||= start > 0 || end < raw.length;
    }
    const block = parent.closest("p, li, td, th, pre, blockquote, h1, h2, h3, h4, h5, h6, div, section, article") ?? main;
    const separator = parts.length ? block === previousBlock ? " " : "\n\n" : "";
    const text = raw.slice(start, end).trim();
    const remaining = 24000 - length;
    if (text.length + separator.length > remaining) truncated = true;
    parts.push((separator + text).slice(0, remaining));
    length += Math.min(remaining, text.length + separator.length);
    previousBlock = block;
    if (length >= 24000) { truncated = true; break; }
  }
  return { text: parts.join(""), truncated, viewportLimited };
}

export function extractPageSnapshot(document) {
  const main = document.querySelector("main, [role='main']") ?? document.body;
  const rawText = String(main?.innerText ?? main?.textContent ?? "");
  const window = main ? windowText(document, main, rawText) : { text: "", truncated: false, viewportLimited: false };
  const pageText = window.text;
  const height = document.defaultView?.innerHeight;
  const formNodes = [...document.querySelectorAll("form")].filter((form) => !form.closest?.("[hidden], [aria-hidden='true']"));
  const windowForms = extractPageFormNodes(document);
  const forms = windowForms.slice(0, 40).map(extractPageFormSnapshot);
  const linkNodes = [...(main?.querySelectorAll("a[href]") ?? [])].filter((anchor) => !anchor.closest?.("[hidden], [aria-hidden='true']"));
  const windowLinks = height === undefined ? linkNodes : linkNodes.filter((anchor) => withinPageWindow(anchor, height));
  const links = windowLinks.slice(0, 100).map((anchor) => {
    const context = anchor.closest("p, li, td") ?? anchor.parentElement;
    return { href: anchor.href, visibleText: String(anchor.innerText || anchor.textContent || "").slice(0, 400), contextText: String(context?.innerText ?? context?.textContent ?? "").slice(0, 500) };
  });
  return { title: String(document.title ?? "").slice(0, 180), text: pageText, forms, links, extractionLimits: { text: window.truncated, viewport: window.viewportLimited || windowForms.length !== formNodes.length || windowLinks.length !== linkNodes.length, forms: windowForms.length > 40, links: windowLinks.length > 100 }, bitb: inspectBitBStructure(document) };
}

export function analyzePageSnapshot(snapshot = {}, locationHref = "", organizationKnowledgeBase = {}) {
  const knowledgeBase = normalizeOrganizationKnowledgeBase(organizationKnowledgeBase);
  const pageUrl = analyzeUrl(locationHref);
  const title = String(snapshot.title ?? "").slice(0, 180);
  const rawPageText = String(snapshot.text ?? "");
  const pageText = rawPageText.slice(0, 24000);
  const claimText = `${title}\n${pageText}`;
  const claims = [...new Set([...findBrandClaims(claimText), ...findOrganizationBrandClaims(claimText, knowledgeBase).map(({ name }) => name)])];
  const formInputs = Array.isArray(snapshot.forms) ? snapshot.forms : [];
  const linkInputs = Array.isArray(snapshot.links) ? snapshot.links : [];
  const forms = formInputs.slice(0, 40).map((form) => {
    const action = analyzeUrl(form.action || locationHref, locationHref);
    const configuredSso = matchOrganizationDomains(action.host, knowledgeBase).some((match) => match.kind === "ssoDomains");
    return { actionDomain: action.domain, actionScheme: action.scheme, configuredSso, hasPassword: Boolean(form.hasPassword), hasCredentialField: Boolean(form.hasCredentialField), contextText: String(form.contextText ?? "").slice(0, 500) };
  });
  const links = linkInputs.slice(0, 100).map((anchor) => analyzeLink({ href: anchor.href, visibleText: anchor.visibleText, baseUrl: locationHref, organizationKnowledgeBase: knowledgeBase }));
  const textSignals = [...extractTextSignals(pageText, "page", "page"), ...extractTextSignals(title, "title", "page")];
  const hasAction = textSignals.some((signal) => ["credential", "financial"].includes(signal.category) && signal.severity > 0);
  const credentialFormScopes = forms.flatMap((form, index) => form.hasPassword ? [`form:${index}`] : []);
  const identityClaims = `${title} ${forms.map((form) => form.contextText).join(" ")}`;
  const identitySignals = analyzeDomainIdentity({ hostname: pageUrl.host, claims: identityClaims, hasCredentialForm: credentialFormScopes.length > 0, organizationKnowledgeBase: knowledgeBase }).signals
    .map((signal) => ({ ...signal, scope: "page", relatedScopes: credentialFormScopes, ...(signal.id === "BRAND_DOMAIN_CONFLICT" && !hasAction && !credentialFormScopes.length ? { severity: 0 } : {}) }));
  const signals = [
    ...textSignals,
    ...links.flatMap((link, index) => [
      ...link.signals.map((signal) => ({ ...signal, scope: `link:${index}` })),
      ...extractTextSignals(String(linkInputs[index]?.contextText ?? "").slice(0, 500), "link", `link:${index}`)
    ]),
    ...identitySignals
  ];
  const clickFix = analyzeClickFix(claimText);
  if (clickFix.detected) {
    signals.push({ id: "CLICKFIX_EXECUTION_INSTRUCTIONS", category: "social", severity: 5, location: "page", scope: "page", detail: "A página orienta o usuário a abrir uma ferramenta do sistema e colar ou executar um comando sob pretexto de verificação ou correção. Esse padrão é compatível com ClickFix.", evidence: clickFix.evidence });
  }
  if (classifyBitBStructure(snapshot.bitb)) {
    signals.push({ id: "POSSIBLE_BITB", category: "context", severity: 0, location: "page", detail: "A estrutura visível se parece com uma janela de autenticação simulada dentro da página. Isso exige revisão e não confirma fraude." });
  }
  for (const [index, form] of forms.entries()) {
    const scope = `form:${index}`;
    if (form.hasPassword) signals.push({ id: "CREDENTIAL_FORM_PRESENT", category: "context", severity: 0, location: "form", scope, detail: "A página contém um campo de senha; o AEGIS não lê o valor digitado." });
    if (form.hasPassword && pageUrl.domain && form.actionDomain && pageUrl.domain !== form.actionDomain) {
      signals.push({ id: "CREDENTIAL_FORM_CROSS_DOMAIN", category: "credential", severity: form.configuredSso ? 2 : 5, location: "form", scope, detail: form.configuredSso ? "Um formulário com campo de senha envia os dados a um domínio de SSO cadastrado pela organização. O cadastro reduz a incerteza do destino; o contexto ainda exige revisão." : "Um formulário com campo de senha envia os dados a outro domínio.", evidence: { pageDomain: pageUrl.domain, actionDomain: form.actionDomain, destinationClassification: form.configuredSso ? "configured-sso" : "unconfigured" } });
    }
    if (form.hasPassword && form.actionScheme === "http") {
      signals.push({ id: "CREDENTIAL_FORM_INSECURE_TRANSPORT", category: "credential", severity: 4, location: "form", scope, detail: "Um formulário com campo de senha envia dados sem HTTPS." });
    }
  }

  const pageAnalyzable = pageUrl.valid && ["http", "https"].includes(pageUrl.scheme);
  const extractionIncomplete = rawPageText.length > 24000 || formInputs.length > 40 || linkInputs.length > 100 || Object.values(snapshot.extractionLimits ?? {}).some((value) => value === true);
  const unresolvedRedirect = links.some((link) => link.destination.suspiciousParams);
  const coverageReasons = [];
  if (!pageAnalyzable) coverageReasons.push("URL da página indisponível ou esquema não suportado");
  if (pageText.trim().length <= 20) coverageReasons.push("Conteúdo visível insuficiente");
  if (snapshot.extractionLimits?.viewport) coverageReasons.push("A análise cobre a região visível da página e seu contexto próximo; conteúdo fora dessa região não foi examinado");
  if (rawPageText.length > 24000 || formInputs.length > 40 || linkInputs.length > 100 || Object.entries(snapshot.extractionLimits ?? {}).some(([key, value]) => key !== "viewport" && value === true)) coverageReasons.push("Parte do conteúdo excedeu o limite local de análise e não foi examinada");
  if (unresolvedRedirect) coverageReasons.push("O destino subsequente de um parâmetro de redirecionamento não foi visitado");
  const coverage = { sufficient: pageAnalyzable && pageText.trim().length > 20 && !extractionIncomplete && !unresolvedRedirect, reasons: coverageReasons };
  const credentialGuardScopes = forms.flatMap((form, index) => {
    const scope = `form:${index}`;
    if (!form.hasPassword) return [];
    const scoped = signals.filter((signal) => signal.scope === scope || signal.relatedScopes?.includes(scope));
    return decideRisk({ signals: scoped, coverage: { sufficient: true, reasons: [] } }).state === "RED" ? [scope] : [];
  });
  return {
    surface: "web",
    pageDomain: pageUrl.domain,
    pageHost: pageUrl.host,
    pageTitle: title,
    claimedBrands: claims,
    forms: forms.map(({ actionDomain, actionScheme, hasPassword, hasCredentialField }) => ({ actionDomain, actionScheme, hasPassword, hasCredentialField })),
    links: links.map(({ destination, visible, mismatch }) => ({ domain: destination.domain, scheme: destination.scheme, visibleDomain: visible?.domain ?? null, mismatch, shortener: destination.shortener, sensitiveParams: destination.sensitiveParams, suspiciousParams: destination.suspiciousParams, organizationDomain: destination.organizationDomain, organizationKinds: destination.organizationKinds, source: "web" })),
    signals,
    coverage,
    semanticExcerpt: pageText.slice(0, 2000),
    decision: { ...decideRisk({ signals, coverage, analyzable: pageAnalyzable }), credentialGuardScopes }
  };
}

export function analyzeSearchResult(payload = {}, organizationKnowledgeBase = {}) {
  const href = String(payload.href ?? "").slice(0, 4096);
  const title = String(payload.title ?? "").slice(0, 180);
  const snippet = String(payload.snippet ?? "").slice(0, 700);
  const result = analyzePageSnapshot({ title, text: snippet, forms: [], links: [] }, href, organizationKnowledgeBase);
  result.surface = "search-result";
  result.decision.surface = "search-result";
  if (payload.wrapperResolution === "unresolved") {
    result.coverage = { sufficient: false, reasons: ["O wrapper do buscador não revelou um destino validável sem navegação"] };
    result.decision = { ...decideRisk({ signals: result.signals, coverage: result.coverage }), surface: "search-result" };
  }
  return result;
}

export function extractPageFeatures(document, locationHref = document.location?.href ?? "") {
  return analyzePageSnapshot(extractPageSnapshot(document), locationHref);
}
