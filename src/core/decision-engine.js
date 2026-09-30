const CATEGORIES = ["phishing", "spam", "credential", "financial", "impersonation", "socialEngineering", "domain", "link"];

function emptyVector() {
  return Object.fromEntries(CATEGORIES.map((category) => [category, 0]));
}

function toVector(signals) {
  const vector = emptyVector();
  for (const signal of signals) {
    const categories = {
      spam: ["spam"], credential: ["credential"], financial: ["financial"],
      identity: ["impersonation", "phishing"], domain: ["domain"], link: ["link"],
      social: ["socialEngineering"], attachment: ["phishing"]
    }[signal.category] ?? ["phishing"];
    for (const category of categories) vector[category] = Math.max(vector[category], signal.severity ?? 1);
    if (["identity", "domain", "link", "credential"].includes(signal.category)) vector.phishing = Math.max(vector.phishing, signal.severity ?? 1);
  }
  return vector;
}

function deduplicateSignals(signals) {
  const unique = new Map();
  for (const signal of Array.isArray(signals) ? signals : []) {
    if (!signal || typeof signal.id !== "string") continue;
    const key = JSON.stringify([signal.id, signal.scope ?? "item", signal.evidence ?? null, signal.source ?? "local"]);
    const previous = unique.get(key);
    if (!previous || (signal.severity ?? 0) > (previous.severity ?? 0)) unique.set(key, signal);
  }
  return [...unique.values()];
}

function groupByScope(signals) {
  const groups = new Map();
  for (const signal of signals) {
    // Unscoped legacy callers represent one item. Analyzed DOM items always
    // provide scopes, so unrelated forms, links and blocks cannot converge.
    const scopes = new Set([signal.scope ?? "item", ...(signal.relatedScopes ?? []).slice(0, 40)]);
    for (const scope of scopes) {
      if (!groups.has(scope)) groups.set(scope, []);
      groups.get(scope).push(signal);
    }
  }
  return [...groups.values()];
}

function convergingRisk(signals) {
  const material = signals.filter((signal) => (signal.severity ?? 0) > 0);
  const clickFix = material.some((item) => item.id === "CLICKFIX_EXECUTION_INSTRUCTIONS" && item.severity >= 5);
  const credentialExposure = material.some((item) => ["CREDENTIAL_FORM_CROSS_DOMAIN", "CREDENTIAL_FORM_INSECURE_TRANSPORT"].includes(item.id) && item.severity >= 4);
  const mismatch = material.some((item) => ["LINK_DISPLAY_DESTINATION_MISMATCH", "BRAND_DOMAIN_CONFLICT", "POSSIBLE_LOOKALIKE_DOMAIN"].includes(item.id));
  const credentials = material.some((item) => item.category === "credential") || signals.some((item) => item.id === "CREDENTIAL_FORM_PRESENT");
  const payment = material.some((item) => ["FINANCIAL_ACTION", "PAYMENT_DETAILS_CHANGE"].includes(item.id));
  const bypass = material.some((item) => item.id === "PROCESS_BYPASS_REQUEST");
  if (clickFix) return "clickfix";
  if (credentialExposure) return "credential-exposure";
  if (mismatch && credentials) return "phishing";
  if (payment && bypass && mismatch) return "financial-fraud";
  return null;
}

export function decideRisk({ signals = [], coverage = { sufficient: false, reasons: [] }, jev = null, analysisError = false, pending = false, analyzable = true } = {}) {
  const observedSignals = deduplicateSignals(signals);
  const localSignals = observedSignals.filter((signal) => signal.source !== "jev");
  const materialLocalSignals = localSignals.filter((signal) => (signal.severity ?? 0) > 0);
  const jevSignals = observedSignals.filter((signal) => signal.source === "jev" && (signal.severity ?? 0) > 0);
  const decisiveCategory = groupByScope(localSignals).map(convergingRisk).find(Boolean);

  let state = "UNKNOWN";
  let reason = "INSUFFICIENT_COVERAGE";
  if (decisiveCategory) {
    state = "RED";
    reason = "CONVERGING_HIGH_RISK_EVIDENCE";
  } else if (analysisError) {
    reason = "ANALYSIS_FAILED";
  } else if (!analyzable) {
    reason = "NOT_ANALYZABLE";
  } else if (pending) {
    reason = "ANALYSIS_PENDING";
  } else if (coverage.sufficient) {
    state = "GREEN";
    reason = "NO_MATERIAL_INDICATORS_OBSERVED";
    if (materialLocalSignals.length || jevSignals.length) {
      state = "YELLOW";
      reason = jevSignals.length && materialLocalSignals.length === 0 ? "SEMANTIC_REVIEW_SUGGESTED" : "INDICATORS_REQUIRE_REVIEW";
    }
  } else if (materialLocalSignals.length) {
    state = "YELLOW";
    reason = "INDICATORS_REQUIRE_REVIEW";
  }

  const findings = observedSignals.slice(0, 24).map(({ id, category, severity, location, detail, evidence, source, scope }) => ({
    id, category, severity, location, detail,
    ...(scope ? { scope } : {}),
    ...(source ? { source } : {}),
    ...(evidence ? { evidence } : {})
  }));
  return {
    state,
    reason,
    analysisStatus: analysisError ? "failure" : !analyzable ? "not-analyzable" : pending ? "pending" : coverage.sufficient ? "completed" : "insufficient",
    riskCategory: decisiveCategory ?? (state === "YELLOW" ? "review" : "none"),
    riskVector: toVector(observedSignals),
    findings,
    coverage: { sufficient: Boolean(coverage.sufficient), reasons: (coverage.reasons ?? []).slice(0, 8) },
    engineStatus: { local: analysisError ? "error" : "active", jev: jev?.status ?? "off" },
    analyzedAt: new Date().toISOString(),
    ruleVersion: "aegis-rules-0.3.0"
  };
}
