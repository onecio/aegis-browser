const VERDICTS = new Set(["phishing", "malware", "spam", "suspicious", "benign", "unknown"]);
const DISABLED = Object.freeze({ status: "disabled" });
const UNAVAILABLE = Object.freeze({ status: "unavailable" });
const MAX_EVIDENCE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export class ThreatIntelProvider {
  async lookupDomain() { return { status: "unavailable" }; }
  async lookupUrl() { return { status: "unavailable" }; }
}

export class DisabledThreatIntelProvider extends ThreatIntelProvider {
  async lookupDomain() { return DISABLED; }
  async lookupUrl() { return DISABLED; }
}

export function validateThreatIntelEvidence(input, { indicator, now = Date.now() } = {}) {
  if (!input || typeof input !== "object" || input.status !== "hit" || typeof indicator !== "string") return UNAVAILABLE;
  if (typeof input.indicator !== "string" || input.indicator.toLowerCase() !== indicator.toLowerCase()) return UNAVAILABLE;
  if (!VERDICTS.has(input.verdict) || typeof input.source !== "string" || !input.source.trim() || input.source.length > 80) return UNAVAILABLE;
  const observedAt = Date.parse(input.observedAt);
  const expiresAt = Date.parse(input.expiresAt);
  if (!Number.isFinite(observedAt) || !Number.isFinite(expiresAt) || observedAt > now + 5 * 60_000 || expiresAt <= now || expiresAt - now > MAX_EVIDENCE_TTL_MS) return UNAVAILABLE;
  if (!Number.isFinite(input.confidence) || input.confidence < 0 || input.confidence > 1) return UNAVAILABLE;
  return {
    status: "hit",
    indicator: indicator.slice(0, 253),
    verdict: input.verdict,
    source: input.source.trim().slice(0, 80),
    observedAt: new Date(observedAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    confidence: input.confidence
  };
}
