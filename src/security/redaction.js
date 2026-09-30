const SENSITIVE_QUERY = /([?&](?:access[_-]?token|auth|authorization|code|id[_-]?token|jwt|key|password|passwd|refresh[_-]?token|session|sig|signature|token)=)[^&#]*/gi;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const LONG_ID = /\b[a-f0-9]{24,}\b/gi;

export function redactUrl(raw) {
  return String(raw ?? "").slice(0, 4096).replace(SENSITIVE_QUERY, "$1[redacted]").replace(/#.*$/, "");
}

export function redactText(raw) {
  return String(raw ?? "").slice(0, 4000)
    .replace(/https?:\/\/[^\s<>"']+/gi, "[link]")
    .replace(/\bBearer\s+[A-Za-z0-9._~-]{12,}/gi, "Bearer [redacted]")
    .replace(/\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?/g, "[token]")
    .replace(/\b(password|senha|passcode|access[_-]?token|refresh[_-]?token|session|jwt)\s*[:=]\s*[^\s,;]+/gi, "$1=[redacted]")
    .replace(EMAIL, "[email]")
    .replace(LONG_ID, "[id]")
    .slice(0, 2000);
}

export function makeJevState(features, privacyMode = "STRICT") {
  const base = {
    surface: features.surface,
    page_domain: features.pageDomain ?? null,
    sender_domain: features.senderDomain ?? null,
    claimed_brands: features.claimedBrands ?? [],
    link_count: features.links?.length ?? 0,
    link_mismatch_count: features.links?.filter((link) => link.mismatch).length ?? 0,
    has_credential_request: Boolean(features.signals?.some((signal) => signal.category === "credential" && signal.severity > 0)),
    has_financial_request: Boolean(features.signals?.some((signal) => signal.category === "financial" && signal.severity > 0)),
    has_process_bypass: Boolean(features.signals?.some((signal) => signal.id === "PROCESS_BYPASS_REQUEST")),
    has_urgency_language: Boolean(features.signals?.some((signal) => signal.id === "URGENCY_LANGUAGE")),
    has_clickfix_instructions: Boolean(features.signals?.some((signal) => signal.id === "CLICKFIX_EXECUTION_INSTRUCTIONS")),
    page_has_password_form: Boolean(features.forms?.some((form) => form.hasPassword))
  };
  if (privacyMode === "STRICT") return base;
  return {
    ...base,
    subject_excerpt: redactText(features.subject ?? "").slice(0, 120),
    body_excerpt: redactText(features.semanticExcerpt ?? "").slice(0, privacyMode === "ENHANCED" ? 1200 : 300)
  };
}
