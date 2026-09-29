import { analyzeDomainIdentity } from "../core/domain-analysis.js";
import { analyzeLink, analyzeUrl } from "../core/domain.js";
import { decideRisk } from "../core/decision-engine.js";
import { extractTextSignals, findBrandClaims } from "../core/text-signals.js";
import { findOrganizationBrandClaims, normalizeOrganizationKnowledgeBase } from "../core/org-configuration.js";
import { classifyBitBStructure, inspectBitBStructure } from "./bitb-analyzer.js";
import { analyzeClickFix } from "./clickfix-analyzer.js";

export function extractPageSnapshot(document) {
  const main = document.querySelector("main, [role='main']") ?? document.body;
  const pageText = String(main?.innerText ?? main?.textContent ?? "").slice(0, 24000);
  const forms = [...document.querySelectorAll("form")].slice(0, 40).map((form) => {
    const hasPassword = Boolean(form.querySelector("input[type='password']"));
    const hasCredentialField = hasPassword || Boolean(form.querySelector("input[autocomplete*='username' i], input[type='email']"));
    return { action: (form.getAttribute("action") || "").slice(0, 2048), hasPassword, hasCredentialField };
  });
  const links = [...main.querySelectorAll("a[href]")].slice(0, 100).map((anchor) => ({ href: anchor.href, visibleText: String(anchor.innerText || anchor.textContent || "").slice(0, 400) }));
  return { title: String(document.title ?? "").slice(0, 180), text: pageText, forms, links, bitb: inspectBitBStructure(document) };
}

export function analyzePageSnapshot(snapshot = {}, locationHref = "", organizationKnowledgeBase = {}) {
  const knowledgeBase = normalizeOrganizationKnowledgeBase(organizationKnowledgeBase);
  const pageUrl = analyzeUrl(locationHref);
  const title = String(snapshot.title ?? "").slice(0, 180);
  const pageText = String(snapshot.text ?? "").slice(0, 24000);
  const claimText = `${title} ${pageText}`;
  const claims = [...new Set([...findBrandClaims(claimText), ...findOrganizationBrandClaims(claimText, knowledgeBase).map(({ name }) => name)])];
  const forms = (snapshot.forms ?? []).slice(0, 40).map((form) => {
    const action = analyzeUrl(form.action || locationHref, locationHref);
    return { actionDomain: action.domain, actionScheme: action.scheme, hasPassword: Boolean(form.hasPassword), hasCredentialField: Boolean(form.hasCredentialField) };
  });
  const links = (snapshot.links ?? []).slice(0, 100).map((anchor) => analyzeLink({ href: anchor.href, visibleText: anchor.visibleText, baseUrl: locationHref, organizationKnowledgeBase: knowledgeBase }));
  const signals = [
    ...extractTextSignals(pageText, "page"),
    ...links.flatMap((link) => link.signals),
    ...analyzeDomainIdentity({ hostname: pageUrl.host, claims: claimText, hasCredentialForm: forms.some((form) => form.hasCredentialField), organizationKnowledgeBase: knowledgeBase }).signals
  ];
  const clickFix = analyzeClickFix(claimText);
  if (clickFix.detected) {
    signals.push({ id: "CLICKFIX_EXECUTION_INSTRUCTIONS", category: "social", severity: 5, location: "page", detail: "A página orienta o usuário a abrir uma ferramenta do sistema e colar ou executar um comando. Esse padrão é compatível com ClickFix.", evidence: clickFix.evidence });
  }
  if (classifyBitBStructure(snapshot.bitb)) {
    signals.push({ id: "POSSIBLE_BITB", category: "context", severity: 0, location: "page", detail: "A estrutura visível se parece com uma janela de autenticação simulada dentro da página. Isso exige revisão e não confirma fraude." });
  }
  for (const form of forms) {
    if (form.hasPassword) signals.push({ id: "CREDENTIAL_FORM_PRESENT", category: "context", severity: 0, location: "form", detail: "A página contém um campo de senha; o AEGIS não lê o valor digitado." });
    if (form.hasPassword && pageUrl.domain && form.actionDomain && pageUrl.domain !== form.actionDomain) {
      signals.push({ id: "CREDENTIAL_FORM_CROSS_DOMAIN", category: "credential", severity: 5, location: "form", detail: "Um formulário com campo de senha envia os dados a outro domínio." });
    }
    if (form.hasCredentialField && form.actionScheme === "http") {
      signals.push({ id: "CREDENTIAL_FORM_INSECURE_TRANSPORT", category: "credential", severity: 4, location: "form", detail: "Um formulário de autenticação envia dados sem HTTPS." });
    }
  }

  const coverage = {
    sufficient: Boolean(pageUrl.valid && pageText.length > 20),
    reasons: !pageUrl.valid ? ["URL da página indisponível"] : pageText.length <= 20 ? ["Conteúdo visível insuficiente"] : []
  };
  return {
    surface: "web",
    pageDomain: pageUrl.domain,
    pageHost: pageUrl.host,
    pageTitle: title,
    claimedBrands: claims,
    forms,
    links: links.map(({ destination, visible, mismatch }) => ({ domain: destination.domain, scheme: destination.scheme, visibleDomain: visible?.domain ?? null, mismatch, shortener: destination.shortener, sensitiveParams: destination.sensitiveParams, suspiciousParams: destination.suspiciousParams, organizationDomain: destination.organizationDomain, organizationKinds: destination.organizationKinds, source: "web" })),
    signals,
    coverage,
    semanticExcerpt: pageText.slice(0, 2000),
    decision: decideRisk({ signals, coverage })
  };
}

export function analyzeSearchResult(payload = {}, organizationKnowledgeBase = {}) {
  const href = String(payload.href ?? "").slice(0, 4096);
  const title = String(payload.title ?? "").slice(0, 180);
  const snippet = String(payload.snippet ?? "").slice(0, 700);
  const result = analyzePageSnapshot({ title, text: `${title} ${snippet}`, forms: [], links: [] }, href, organizationKnowledgeBase);
  result.surface = "search-result";
  result.decision.surface = "search-result";
  return result;
}

export function extractPageFeatures(document, locationHref = document.location?.href ?? "") {
  return analyzePageSnapshot(extractPageSnapshot(document), locationHref);
}
