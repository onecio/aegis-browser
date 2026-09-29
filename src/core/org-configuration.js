const CATEGORY_KEYS = ["ssoDomains", "vendorDomains", "financialDomains", "internalDomains"];
const DOMAIN_LIMIT = 100;
const BRAND_LIMIT = 80;
const EMPTY_KNOWLEDGE_BASE = Object.freeze({
  brands: Object.freeze([]),
  ssoDomains: Object.freeze([]),
  vendorDomains: Object.freeze([]),
  financialDomains: Object.freeze([]),
  internalDomains: Object.freeze([])
});
const normalizedKnowledgeBases = new WeakSet([EMPTY_KNOWLEDGE_BASE]);
const MANAGED_SETTING_KEYS = ["emailProtection", "webProtection", "sessionIntelligence"];

function normalizedUniqueStrings(values, maxItems, maxLength, label) {
  if (!Array.isArray(values)) throw new Error(`${label} must be an array`);
  if (values.length > maxItems) throw new Error(`${label} exceeds its limit`);
  const result = [];
  const seen = new Set();
  for (const value of values) {
    if (typeof value !== "string" || !value.trim() || value.length > maxLength) throw new Error(`Invalid ${label} entry`);
    const normalized = value.trim().normalize("NFKC");
    const key = normalized.toLowerCase();
    if (!seen.has(key)) { seen.add(key); result.push(normalized); }
  }
  return result;
}

export function normalizeOrganizationDomain(value) {
  if (typeof value !== "string") throw new Error("Invalid organization domain");
  const input = value.trim();
  if (!input || input.length > 253 || /[\s/:?#@\\]/.test(input) || input.startsWith(".") || input.endsWith(".")) {
    throw new Error("Invalid organization domain");
  }
  let hostname;
  try { hostname = new URL(`https://${input}`).hostname.toLowerCase(); }
  catch { throw new Error("Invalid organization domain"); }
  if (!hostname || hostname.includes(":") || /^\d+(?:\.\d+){3}$/.test(hostname)) throw new Error("Invalid organization domain");
  const labels = hostname.split(".");
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    throw new Error("Invalid organization domain");
  }
  return hostname;
}

function normalizedDomains(values, label) {
  const entries = normalizedUniqueStrings(values, DOMAIN_LIMIT, 253, label);
  return [...new Set(entries.map(normalizeOrganizationDomain))];
}

export function normalizeOrganizationKnowledgeBase(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid organization knowledge base");
  if (normalizedKnowledgeBases.has(input)) return input;
  const allowed = new Set(["brands", ...CATEGORY_KEYS]);
  if (Object.keys(input).some((key) => !allowed.has(key))) throw new Error("Unknown organization knowledge base field");
  const brandsInput = input.brands ?? [];
  if (!Array.isArray(brandsInput) || brandsInput.length > BRAND_LIMIT) throw new Error("Invalid organization brands");
  const brandNames = new Set();
  const brands = brandsInput.map((brand) => {
    if (!brand || typeof brand !== "object" || Array.isArray(brand)) throw new Error("Invalid organization brand");
    if (Object.keys(brand).some((key) => !["name", "terms", "domains"].includes(key))) throw new Error("Unknown organization brand field");
    const name = typeof brand.name === "string" ? brand.name.trim().normalize("NFKC").slice(0, 80) : "";
    if (name.length < 2 || brandNames.has(name.toLowerCase())) throw new Error("Invalid or duplicate organization brand name");
    brandNames.add(name.toLowerCase());
    const terms = normalizedUniqueStrings(brand.terms ?? [name], 20, 100, "brand terms");
    if (!terms.length) throw new Error("Organization brands require at least one term");
    const domains = normalizedDomains(brand.domains ?? [], "brand domains");
    if (!domains.length) throw new Error("Organization brands require at least one official domain");
    return Object.freeze({ name, terms: Object.freeze(terms), domains: Object.freeze(domains) });
  });
  const normalized = { brands: Object.freeze(brands) };
  for (const key of CATEGORY_KEYS) normalized[key] = Object.freeze(normalizedDomains(input[key] ?? [], `${key} entries`));
  Object.freeze(normalized);
  normalizedKnowledgeBases.add(normalized);
  return normalized;
}

export function normalizeOrganizationDetectionModel(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Invalid organization detection model");
  const allowed = new Set(["schemaVersion", "modelId", "modelVersion", "knowledgeBase"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) throw new Error("Unknown organization detection model field");
  if (input.schemaVersion !== 1) throw new Error("Unsupported organization detection model schema");
  if (typeof input.modelId !== "string" || !/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(input.modelId)) throw new Error("Invalid organization detection model ID");
  if (typeof input.modelVersion !== "string" || !/^[a-z0-9][a-z0-9.+_-]{0,31}$/i.test(input.modelVersion)) throw new Error("Invalid organization detection model version");
  return Object.freeze({
    schemaVersion: 1,
    modelId: input.modelId,
    modelVersion: input.modelVersion,
    knowledgeBase: normalizeOrganizationKnowledgeBase(input.knowledgeBase)
  });
}

export function matchOrganizationDomains(hostname, knowledgeBase = EMPTY_KNOWLEDGE_BASE) {
  let host;
  try { host = normalizeOrganizationDomain(hostname); }
  catch { return []; }
  const kb = normalizeOrganizationKnowledgeBase(knowledgeBase);
  const matches = [];
  const add = (kind, name, domain) => {
    if ((host === domain || host.endsWith(`.${domain}`)) && !matches.some((item) => item.kind === kind && item.domain === domain)) {
      matches.push({ kind, name, domain });
    }
  };
  for (const brand of kb.brands) for (const domain of brand.domains) add("brand", brand.name, domain);
  for (const kind of CATEGORY_KEYS) for (const domain of kb[kind]) add(kind, kind, domain);
  return matches;
}

export function findOrganizationBrandClaims(text, knowledgeBase = EMPTY_KNOWLEDGE_BASE) {
  const normalizedText = String(text ?? "").normalize("NFKC").toLocaleLowerCase();
  const kb = normalizeOrganizationKnowledgeBase(knowledgeBase);
  return kb.brands.filter((brand) => brand.terms.some((term) => normalizedText.includes(term.normalize("NFKC").toLocaleLowerCase())));
}

export function resolveManagedConfiguration(local = {}, managed = {}) {
  const settings = { ...local };
  delete settings.organizationDetectionModel;
  const managedKeys = [];
  for (const key of MANAGED_SETTING_KEYS) {
    if (!Object.hasOwn(managed, key)) continue;
    if (typeof managed[key] !== "boolean") continue;
    settings[key] = managed[key];
    managedKeys.push(key);
  }

  if (Object.hasOwn(managed, "organizationDetectionModel")) {
    try {
      const model = normalizeOrganizationDetectionModel(managed.organizationDetectionModel);
      settings.organizationKnowledgeBase = model.knowledgeBase;
      settings.organizationDetectionModel = { status: "active", modelId: model.modelId, modelVersion: model.modelVersion };
    } catch {
      settings.organizationKnowledgeBase = EMPTY_KNOWLEDGE_BASE;
      settings.organizationDetectionModel = { status: "invalid" };
    }
    managedKeys.push("organizationDetectionModel", "organizationKnowledgeBase");
  } else if (Object.hasOwn(managed, "organizationKnowledgeBase")) {
    try { settings.organizationKnowledgeBase = normalizeOrganizationKnowledgeBase(managed.organizationKnowledgeBase); }
    catch { settings.organizationKnowledgeBase = EMPTY_KNOWLEDGE_BASE; }
    managedKeys.push("organizationKnowledgeBase");
  } else if (local.organizationKnowledgeBase) {
    settings.organizationKnowledgeBase = normalizeOrganizationKnowledgeBase(local.organizationKnowledgeBase);
  }
  return { settings, managedKeys };
}

export { EMPTY_KNOWLEDGE_BASE };
