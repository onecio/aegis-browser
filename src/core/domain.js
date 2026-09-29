import { getDomain, parse as parseDomain } from "tldts";
import { matchOrganizationDomains, normalizeOrganizationKnowledgeBase } from "./org-configuration.js";

const SHORTENERS = new Set([
  "bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "lnkd.in"
]);
const SENSITIVE_KEYS = /^(access[_-]?token|auth|authorization|code|id[_-]?token|jwt|key|password|passwd|refresh[_-]?token|session|sig|signature|token)$/i;
const SUSPICIOUS_KEYS = /^(continue|dest|destination|next|redirect|return|returnto|target|url|validate|verify)$/i;

export function normalizeHost(hostname) {
  return String(hostname ?? "").trim().replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
}

export function registrableDomain(hostname) {
  const host = normalizeHost(hostname);
  if (!host || !host.includes(".")) return host || null;
  return getDomain(host, { allowPrivateDomains: true }) ?? host;
}

export function analyzeUrl(raw, baseUrl) {
  const input = String(raw ?? "").trim().slice(0, 4096);
  let parsed;
  try {
    parsed = baseUrl ? new URL(input, baseUrl) : new URL(input);
  } catch {
    return { valid: false, scheme: null, host: null, domain: null, shortener: false, sensitiveParams: false, suspiciousParams: false };
  }

  const host = normalizeHost(parsed.hostname);
  const domain = registrableDomain(host);
  const suffix = parseDomain(host, { allowPrivateDomains: true }).publicSuffix;
  const queryKeys = [...parsed.searchParams.keys()];
  const sensitiveParams = queryKeys.some((key) => SENSITIVE_KEYS.test(key));

  return {
    valid: true,
    scheme: parsed.protocol.slice(0, -1).toLowerCase(),
    host,
    domain,
    publicSuffix: suffix ?? null,
    origin: parsed.origin,
    displayUrl: `${parsed.protocol}//${host}${parsed.port ? `:${parsed.port}` : ""}`,
    isHttp: parsed.protocol === "http:",
    hasCredentials: Boolean(parsed.username || parsed.password),
    shortener: SHORTENERS.has(domain ?? host),
    sensitiveParams,
    suspiciousParams: queryKeys.some((key) => SUSPICIOUS_KEYS.test(key)),
    queryPresent: queryKeys.length > 0
  };
}

function urlFromVisibleText(text) {
  const trimmed = String(text ?? "").trim();
  if (!trimmed || trimmed.length > 2048) return null;
  const match = trimmed.match(/^(?:https?:\/\/)?(?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,}(?::\d+)?(?:[/?#].*)?$/iu);
  if (!match) return null;
  return analyzeUrl(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`);
}

export function analyzeLink({ href, visibleText, baseUrl, organizationKnowledgeBase = {} }) {
  const parsedDestination = analyzeUrl(href, baseUrl);
  const knowledgeBase = normalizeOrganizationKnowledgeBase(organizationKnowledgeBase);
  const organizationMatches = parsedDestination.valid ? matchOrganizationDomains(parsedDestination.host, knowledgeBase) : [];
  const destination = {
    ...parsedDestination,
    organizationDomain: organizationMatches.length > 0,
    organizationKinds: [...new Set(organizationMatches.map(({ kind }) => kind))]
  };
  const visible = urlFromVisibleText(visibleText);
  const mismatch = Boolean(
    destination.valid && visible?.valid &&
    destination.domain && visible.domain && destination.domain !== visible.domain
  );

  const signals = [];
  if (!destination.valid || !["http", "https"].includes(destination.scheme)) {
    signals.push({ id: "INVALID_OR_UNSUPPORTED_LINK", category: "link", severity: 3, location: "link", detail: "O destino do link não usa um endereço Web reconhecido." });
  }
  if (destination.hasCredentials) {
    signals.push({ id: "URL_CONTAINS_CREDENTIALS", category: "link", severity: 4, location: "link", detail: "O endereço contém credenciais embutidas." });
  }
  if (destination.sensitiveParams) {
    signals.push({ id: "URL_SENSITIVE_PARAMETER", category: "link", severity: 2, location: "link", detail: "O endereço contém parâmetros que podem carregar dados sensíveis." });
  }
  if (destination.suspiciousParams) {
    signals.push({ id: "URL_REDIRECT_PARAMETER", category: "context", severity: 0, location: "link", detail: "A URL contém um parâmetro que pode indicar redirecionamento; o destino subsequente não foi visitado." });
  }
  if (destination.shortener && !destination.organizationDomain) {
    signals.push({ id: "OBSCURED_DESTINATION", category: "link", severity: 2, location: "link", detail: "O serviço encurtador oculta o destino final." });
  }
  if (destination.organizationDomain) {
    signals.push({ id: "ORGANIZATION_LINK_DOMAIN_RECOGNIZED", category: "context", severity: 0, location: "link", detail: "O domínio do link consta na base organizacional; isso não garante a legitimidade do conteúdo." });
  }
  if (mismatch) {
    signals.push({ id: "LINK_DISPLAY_DESTINATION_MISMATCH", category: "link", severity: 5, location: "link", detail: "O domínio mostrado no link difere do domínio de destino.", evidence: { displayedDomain: visible.domain, destinationDomain: destination.domain } });
  }
  if (destination.isHttp) {
    signals.push({ id: "LINK_USES_HTTP", category: destination.organizationDomain ? "context" : "link", severity: destination.organizationDomain ? 0 : 2, location: "link", detail: destination.organizationDomain ? "O link organizacional usa HTTP sem criptografia." : "O link não usa uma conexão HTTPS." });
  }
  return { destination, visible, mismatch, signals };
}
