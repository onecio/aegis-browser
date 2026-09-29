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

function independentHighCategories(signals) {
  return new Set(signals.filter((item) => item.severity >= 4).map((item) => item.category));
}

export function decideRisk({ signals = [], coverage = { sufficient: false, reasons: [] }, jev = null, analysisError = false } = {}) {
  const localSignals = signals.filter((signal) => signal.source !== "jev");
  const materialLocalSignals = localSignals.filter((signal) => (signal.severity ?? 0) > 0);
  const jevSignals = signals.filter((signal) => signal.source === "jev");
  const hardFormRisk = materialLocalSignals.some((item) => ["CREDENTIAL_FORM_CROSS_DOMAIN", "CREDENTIAL_FORM_INSECURE_TRANSPORT"].includes(item.id));
  const mismatch = materialLocalSignals.some((item) => item.id === "LINK_DISPLAY_DESTINATION_MISMATCH" || item.id === "BRAND_DOMAIN_CONFLICT" || item.id === "POSSIBLE_LOOKALIKE_DOMAIN");
  const credentials = materialLocalSignals.some((item) => item.category === "credential");
  const credentialForm = localSignals.some((item) => item.id === "CREDENTIAL_FORM_PRESENT");
  const payment = materialLocalSignals.some((item) => ["FINANCIAL_ACTION", "PAYMENT_DETAILS_CHANGE"].includes(item.id));
  const bypass = materialLocalSignals.some((item) => item.id === "PROCESS_BYPASS_REQUEST");
  const highGroups = independentHighCategories(materialLocalSignals);
  const decisiveLocalRisk = hardFormRisk || (mismatch && (credentials || credentialForm)) || (payment && bypass && mismatch) || highGroups.size >= 3;

  let state = "UNKNOWN";
  let reason = "INSUFFICIENT_COVERAGE";
  if (decisiveLocalRisk) {
    state = "RED";
    reason = "CONVERGING_HIGH_RISK_EVIDENCE";
  } else if (analysisError) {
    reason = "ANALYSIS_FAILED";
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

  const findings = [...localSignals, ...jevSignals].slice(0, 24).map(({ id, category, severity, location, detail, evidence, source }) => ({
    id, category, severity, location, detail,
    ...(source ? { source } : {}),
    ...(evidence ? { evidence } : {})
  }));
  return {
    state,
    reason,
    riskVector: toVector(signals),
    findings,
    coverage: { sufficient: Boolean(coverage.sufficient), reasons: (coverage.reasons ?? []).slice(0, 8) },
    engineStatus: { local: analysisError ? "error" : "active", jev: jev?.status ?? "off" },
    analyzedAt: new Date().toISOString(),
    ruleVersion: "aegis-rules-0.1.0"
  };
}
