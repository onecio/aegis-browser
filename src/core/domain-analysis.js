import { registrableDomain } from "./domain.js";
import { findOrganizationBrandClaims, matchOrganizationDomains, normalizeOrganizationKnowledgeBase } from "./org-configuration.js";
import confusables from "./confusables-map.json" with { type: "json" };
import punycode from "punycode/punycode.js";

export const BRAND_KNOWLEDGE_BASE = Object.freeze([
  { name: "Microsoft", terms: ["microsoft", "office 365", "office365", "outlook", "onedrive"], domains: ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"] },
  { name: "Google", terms: ["google", "gmail", "drive", "workspace"], domains: ["google.com", "googlemail.com"] },
  { name: "Apple", terms: ["apple", "icloud"], domains: ["apple.com", "icloud.com"] },
  { name: "PayPal", terms: ["paypal"], domains: ["paypal.com"] },
  { name: "Amazon", terms: ["amazon", "aws"], domains: ["amazon.com", "amazon.com.br", "amazonaws.com"] },
  { name: "Gov.br", terms: ["gov.br", "receita federal"], domains: ["gov.br"] }
]);

export function confusableSkeleton(value) {
  const decomposed = [...String(value ?? "").normalize("NFD")];
  return decomposed.map((char) => confusables[char] ?? char).join("").normalize("NFD").toLowerCase();
}

export function hasMixedLatinCyrillicOrGreek(value) {
  const text = String(value ?? "");
  return /\p{Script=Latin}/u.test(text) && (/\p{Script=Cyrillic}/u.test(text) || /\p{Script=Greek}/u.test(text));
}

function editDistance(left, right) {
  const a = [...left];
  const b = [...right];
  if (Math.abs(a.length - b.length) > 2) return 99;
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    previous = current;
  }
  return previous[b.length];
}

function claimedBrands(claims, organizationKnowledgeBase) {
  const normalized = String(claims ?? "").normalize("NFKC").toLowerCase();
  const known = BRAND_KNOWLEDGE_BASE.filter((brand) => brand.terms.some((term) => normalized.includes(term.normalize("NFKC").toLowerCase())));
  const organization = findOrganizationBrandClaims(normalized, organizationKnowledgeBase);
  return [...known, ...organization.filter((candidate) => !known.some((brand) => brand.name === candidate.name))];
}

export function analyzeDomainIdentity({ hostname, claims = "", hasCredentialForm = false, organizationKnowledgeBase = {} }) {
  const host = String(hostname ?? "").toLowerCase();
  const domain = registrableDomain(host);
  const unicodeHost = host.split(".").map((label) => punycode.toUnicode(label)).join(".");
  const unicodeDomain = domain?.split(".").map((label) => punycode.toUnicode(label)).join(".") ?? unicodeHost;
  const knowledgeBase = normalizeOrganizationKnowledgeBase(organizationKnowledgeBase);
  const claimed = claimedBrands(claims, knowledgeBase);
  const signals = [];
  const organizationMatches = matchOrganizationDomains(host, knowledgeBase);

  if (host.startsWith("xn--") || host.includes(".xn--")) {
    signals.push({ id: "IDN_PUNYCODE_DOMAIN", category: "context", severity: 0, location: "domain", detail: "O domínio usa uma representação internacionalizada; isso também é comum em domínios legítimos." });
  }
  if (hasMixedLatinCyrillicOrGreek(unicodeHost)) {
    signals.push({ id: "POSSIBLE_MIXED_SCRIPT_DOMAIN", category: "context", severity: 0, location: "domain", detail: "O domínio mistura alfabetos; esta observação exige contexto e não representa acusação de fraude." });
  }

  const skeleton = confusableSkeleton(unicodeDomain);
  const brands = claimed.length ? claimed : [...BRAND_KNOWLEDGE_BASE, ...knowledgeBase.brands];
  const lookalike = organizationMatches.length ? null : brands.find((brand) => brand.domains.some((official) => {
    const officialLabel = official.split(".")[0];
    const hostLabel = (domain ?? host).split(".")[0];
    const unicodeLabel = unicodeDomain.split(".")[0];
    const skeletonLabel = skeleton.split(".")[0];
    const labelSegments = unicodeLabel.split(/[-\d]+/).filter(Boolean);
    return (skeletonLabel === officialLabel && unicodeLabel !== officialLabel) || editDistance(unicodeLabel, officialLabel) <= 1 && hostLabel !== officialLabel || labelSegments.includes(officialLabel) && unicodeLabel !== officialLabel;
  }));
  if (lookalike) {
    signals.push({ id: "POSSIBLE_LOOKALIKE_DOMAIN", category: "domain", severity: 4, location: "domain", detail: `O domínio se parece com um domínio associado a ${lookalike.name}.`, evidence: { brand: lookalike.name, domain } });
  }

  for (const brand of claimed) {
    const matchesOfficial = brand.domains.some((official) => domain === official || domain?.endsWith(`.${official}`));
    if (!matchesOfficial && domain && !organizationMatches.length) {
      signals.push({ id: "BRAND_DOMAIN_CONFLICT", category: "identity", severity: hasCredentialForm ? 5 : 4, location: "domain", detail: `A página menciona ${brand.name}, mas o domínio registrável é diferente.`, evidence: { brand: brand.name, domain } });
    }
  }
  if (organizationMatches.length) {
    const kinds = [...new Set(organizationMatches.map(({ kind }) => ({ ssoDomains: "SSO", vendorDomains: "fornecedor", financialDomains: "financeiro", internalDomains: "serviço interno", brand: "marca oficial" })[kind] ?? "organizacional"))];
    signals.push({ id: "ORGANIZATION_DOMAIN_RECOGNIZED", category: "context", severity: 0, location: "domain", detail: `O domínio consta na base organizacional (${kinds.join(", ")}); esse cadastro não garante a legitimidade da mensagem ou página.`, evidence: { kinds } });
  }
  return { domain, claimedBrands: claimed.map(({ name }) => name), organizationMatches, signals };
}
