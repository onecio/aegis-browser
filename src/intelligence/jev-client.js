import { makeJevState } from "../security/redaction.js";

const API_URL = "https://api.typesafe.ai/v1/systemone";
export const JEV_MODEL = "jev-latest";
const TIMEOUT_MS = 5500;
const MAX_RESPONSE_BYTES = 48_000;
const MAX_API_CREDENTIAL_LENGTH = 1024;
const SERIALIZATION_HALF_STEP = 0.005;
const NUMERIC_EPSILON = 1e-9;
const SCORE_KEYS = [
  "social_engineering_intensity",
  "credential_risk",
  "financial_fraud_risk",
  "impersonation_risk",
  "urgency_manipulation",
  "semantic_suspicion"
];

function scoreQuestion(instructions, criteria) {
  return { type: "score", instructions, criteria };
}

export function buildJevQuestions() {
  return {
    urgency: { type: "noul", instructions: "Does the content use unusual urgency or fear to pressure the recipient into an immediate security or financial action?", criteria: { true: "The content applies pressure, urgency, or fear to cause action", false: "No meaningful pressure to act immediately" } },
    credential_request: { type: "noul", instructions: "Does the content ask the recipient to disclose, confirm, or enter authentication credentials or one-time codes?", criteria: { true: "A credential or authentication secret is requested", false: "No credential or authentication secret is requested" } },
    process_bypass: { type: "noul", instructions: "Does the content ask the recipient to bypass a normal verification or approval process?", criteria: { true: "The content asks to skip normal checks, approval, or independent contact", false: "No request to bypass a normal process" } },
    financial_action: { type: "noul", instructions: "Does the content ask for an unusual payment, transfer, invoice change, or financial account update?", criteria: { true: "An unusual or changed financial action is requested", false: "No unusual financial action is requested" } },
    clickfix_instruction: { type: "noul", instructions: "Does the content instruct the user to open an operating-system execution tool or terminal and paste or run a command as a supposed fix, CAPTCHA, verification, or access step?", criteria: { true: "The content asks the user to open a system tool and paste or execute a command", false: "No such command-execution instruction is present" } },
    classification: {
      type: "choice",
      instructions: "Which interpretation best describes the supplied content and features? This is a semantic judgment, not verification of the sender, organization, or destination.",
      criteria: {
        BENIGN: "No meaningful suspicious request is present",
        MARKETING: "Primarily an ordinary promotion or marketing message",
        SPAM: "Unsolicited or repetitive content that is not primarily credential or payment fraud",
        SUSPICIOUS: "Unusual or ambiguous; merits review",
        PHISHING_LIKELY: "Likely intended to harvest credentials or misdirect a link",
        SPEAR_PHISHING_LIKELY: "Likely targeted impersonation or manipulation aimed at a specific recipient or organization",
        BEC_LIKELY: "Likely a business payment or supplier impersonation attempt",
        CREDENTIAL_PHISHING_LIKELY: "Likely intended to obtain passwords, authentication codes, or account access",
        QUISHING_LIKELY: "Likely uses a QR code to direct the recipient to a deceptive destination",
        UNKNOWN: "Insufficient semantic evidence"
      }
    },
    social_engineering_intensity: scoreQuestion(
      "How strongly does the content use social influence or manipulation to induce an action, excluding urgency alone? Judge only the supplied features.",
      [
        "No persuasive pressure; informational or routine content.",
        "Ordinary persuasion or a routine request without unusual pressure.",
        "An unusual request or authority claim creates some pressure to act.",
        "Fear, authority, secrecy, or bypass language strongly pressures the recipient.",
        "Several coercive tactics converge to force action or evade normal safeguards."
      ]
    ),
    credential_risk: scoreQuestion(
      "How concerning is the authentication-related action requested by the content? Do not treat ordinary account references as a credential request.",
      [
        "No authentication action or credential is requested.",
        "Authentication is mentioned, but no account action is requested.",
        "The recipient is asked to sign in or verify an account, with no secret explicitly requested.",
        "The content asks the recipient to enter a password, one-time code, or other authentication secret.",
        "The content asks the recipient to send secrets to a person or to bypass normal authentication safeguards."
      ]
    ),
    financial_fraud_risk: scoreQuestion(
      "How concerning is the financial action requested by the content, based only on the supplied features?",
      [
        "No payment, transfer, invoice, or financial account action is requested.",
        "Financial information is mentioned without asking for a change or transfer.",
        "A routine payment or invoice action is requested without unusual pressure or changed details.",
        "The content requests a new payment, changed payment details, or an unusual transfer.",
        "An unusual or changed financial action is combined with impersonation, urgency, secrecy, or process bypass."
      ]
    ),
    impersonation_risk: scoreQuestion(
      "How strongly do the supplied content and identity metadata suggest impersonation? Do not verify facts beyond the supplied features.",
      [
        "No organization or person is represented as the sender.",
        "An organization is mentioned without a claim to represent it.",
        "The sender claims to represent an organization, with no supplied identity conflict.",
        "The claimed organization conflicts with the supplied sender or domain features.",
        "An identity conflict converges with a credential, payment, or safeguard-bypass request."
      ]
    ),
    urgency_manipulation: scoreQuestion(
      "How strongly does the content use urgency, deadlines, threats, or fear to force immediate action?",
      [
        "No time pressure or threatened consequence is expressed.",
        "A neutral date or ordinary deadline is stated without pressure.",
        "A deadline encourages action, but no threat or unusual pressure is used.",
        "Urgency or fear is tied to account access, payment, or another consequential action.",
        "Immediate threats or penalties are used to force action or prevent independent verification."
      ]
    ),
    semantic_suspicion: scoreQuestion(
      "Considering only the supplied content and features, how strongly do the semantic patterns suggest a need for security review? This is not a factual verdict.",
      [
        "The supplied content is routine and contains no meaningful suspicious request.",
        "One atypical detail appears, with a plausible benign interpretation.",
        "The content is ambiguous or contains a notable request that merits review.",
        "Several independent suspicious patterns appear to converge.",
        "Strong phishing, credential-harvesting, impersonation, or financial-manipulation patterns converge."
      ]
    )
  };
}

async function readJsonBounded(response, signal) {
  if (Number(response.headers.get("content-length")) > MAX_RESPONSE_BYTES) throw Object.assign(new Error("Jev response exceeded limit"), { errorCode: "RESPONSE_TOO_LARGE" });
  const reader = response.body?.getReader();
  if (!reader) return {};
  const chunks = [];
  let size = 0;
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal?.addEventListener("abort", cancel, { once: true });
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) { await reader.cancel(); throw Object.assign(new Error("Jev response exceeded limit"), { errorCode: "RESPONSE_TOO_LARGE" }); }
      chunks.push(value);
    }
  } finally { signal?.removeEventListener("abort", cancel); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function evaluateJev({ features, apiKey, endpoint = API_URL, privacyMode = "STRICT", fetchImpl = fetch, signal, timeoutMs = TIMEOUT_MS, maxCredentialLength = MAX_API_CREDENTIAL_LENGTH } = {}) {
  if (!apiKey || typeof apiKey !== "string" || apiKey.length < 12 || apiKey.length > Math.min(maxCredentialLength, 4096) || /\s/.test(apiKey)) {
    return { status: "error", errorCode: "MISSING_OR_INVALID_KEY" };
  }
  if (signal?.aborted) return { status: "error", errorCode: "CANCELLED" };
  const controller = new AbortController();
  let rejectAbort;
  const aborted = new Promise((_resolve, reject) => { rejectAbort = reject; });
  const abort = () => rejectAbort(new DOMException("Jev inference cancelled", "AbortError"));
  controller.signal.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const abortWithParent = () => controller.abort();
  if (signal?.aborted) controller.abort();
  else signal?.addEventListener("abort", abortWithParent, { once: true });
  try {
    if (controller.signal.aborted) return { status: "error", errorCode: "CANCELLED" };
    const response = await Promise.race([fetchImpl(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ state: makeJevState(features, privacyMode), model: JEV_MODEL, questions: buildJevQuestions() }),
      signal: controller.signal,
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer"
    }), aborted]);
    if (!response.ok) return { status: "error", errorCode: response.status === 401 ? "UNAUTHORIZED" : response.status === 403 ? "FORBIDDEN" : response.status === 429 ? "RATE_LIMITED" : response.status >= 500 ? "PROVIDER_UNAVAILABLE" : "PROVIDER_ERROR" };
    const data = await Promise.race([readJsonBounded(response, controller.signal), aborted]);
    return decodeJevResponse(data);
  } catch (error) {
    return { status: "error", errorCode: signal?.aborted ? "CANCELLED" : controller.signal.aborted || error?.name === "AbortError" ? "TIMEOUT" : error?.errorCode ?? (error instanceof SyntaxError ? "INVALID_RESPONSE" : "NETWORK_ERROR") };
  } finally {
    clearTimeout(timer);
    controller.signal.removeEventListener("abort", abort);
    signal?.removeEventListener("abort", abortWithParent);
  }
}

export function decodeJevResponse(data) {
  if (!data || !isRecord(data.answers) || typeof data.model !== "string" || !data.model.length || data.model.length > 120) return { status: "error", errorCode: "INVALID_RESPONSE" };
  const questions = buildJevQuestions();
  const answers = {};
  const signals = [];
  for (const key of ["urgency", "credential_request", "process_bypass", "financial_action", "clickfix_instruction"]) {
    const answer = data.answers[key];
    if (answer?.type !== "noul" || !Number.isFinite(answer.noul) || answer.noul < 0 || answer.noul > 1) return { status: "error", errorCode: "INVALID_RESPONSE" };
    answers[key] = answer.noul;
  }
  const choice = data.answers.classification;
  const choiceOptions = Object.keys(questions.classification.criteria);
  if (choice?.type !== "choice" || !choiceOptions.includes(choice.choice) || !validDistribution(choice.probabilities, choiceOptions) || !validProbability(choice.confidence)) return { status: "error", errorCode: "INVALID_RESPONSE" };
  const choiceMaximum = Math.max(...Object.values(choice.probabilities));
  if (choice.probabilities[choice.choice] + 0.000001 < choiceMaximum) return { status: "error", errorCode: "INVALID_RESPONSE" };
  answers.classification = {
    choice: choice.choice,
    probabilities: Object.fromEntries(choiceOptions.map((key) => [key, choice.probabilities[key]])),
    confidence: choice.confidence
  };

  for (const key of SCORE_KEYS) {
    const answer = data.answers[key];
    const levels = questions[key].criteria;
    const levelKeys = levels.map((_level, index) => String(index));
    if (answer?.type !== "score" || !Number.isFinite(answer.score) || answer.score < 0 || answer.score > levels.length - 1 || !validProbability(answer.confidence) || !validDistribution(answer.probabilities, levelKeys)) return { status: "error", errorCode: "INVALID_RESPONSE" };
    const legend = Object.fromEntries(levels.map((level, index) => [String(index), level]));
    if (!isRecord(answer.legend) || levelKeys.some((level) => answer.legend[level] !== legend[level]) || Object.keys(answer.legend).length !== levelKeys.length) return { status: "error", errorCode: "INVALID_RESPONSE" };
    const expectedScore = levelKeys.reduce((sum, level) => sum + Number(level) * answer.probabilities[level], 0);
    // The live provider serializes probabilities and scores to two decimals.
    // Bound their aggregate rounding error, retaining rubric/range/distribution checks.
    const serializationTolerance = SERIALIZATION_HALF_STEP * (1 + levelKeys.reduce((sum, level) => sum + Number(level), 0));
    if (Math.abs(answer.score - expectedScore) > serializationTolerance + NUMERIC_EPSILON) return { status: "error", errorCode: "INVALID_RESPONSE" };
    answers[key] = {
      score: answer.score,
      probabilities: Object.fromEntries(levelKeys.map((level) => [level, answer.probabilities[level]])),
      legend,
      confidence: answer.confidence
    };
  }
  // Provisional: Jev can add a review signal only. It cannot produce RED or lower local risk.
  for (const [key, category, detail] of [
    ["urgency", "social", "A análise semântica encontrou linguagem potencialmente pressionadora."],
    ["credential_request", "credential", "A análise semântica identificou possível pedido de credenciais."],
    ["process_bypass", "social", "A análise semântica identificou possível tentativa de evitar verificações."],
    ["financial_action", "financial", "A análise semântica identificou possível solicitação financeira incomum."],
    ["clickfix_instruction", "social", "A análise semântica identificou instruções compatíveis com ClickFix."]
  ]) {
    if (answers[key] >= 0.75) signals.push({ id: `JEV_${key.toUpperCase()}`, category, severity: 2, location: "semantic", detail, source: "jev" });
  }
  if (["SUSPICIOUS", "PHISHING_LIKELY", "SPEAR_PHISHING_LIKELY", "BEC_LIKELY", "CREDENTIAL_PHISHING_LIKELY", "QUISHING_LIKELY"].includes(answers.classification.choice) && !signals.length) {
    signals.push({ id: "JEV_REVIEW_SUGGESTED", category: "social", severity: 2, location: "semantic", detail: "A análise semântica sugere uma verificação adicional.", source: "jev" });
  }
  return { status: "connected", model: data.model, answers, signals, usage: sanitizeUsage(data.usage) };
}

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function validProbability(value) {
  return Number.isFinite(value) && value >= 0 && value <= 1;
}

function validDistribution(distribution, expectedKeys) {
  if (!isRecord(distribution) || Object.keys(distribution).length !== expectedKeys.length) return false;
  if (expectedKeys.some((key) => !validProbability(distribution[key]))) return false;
  const sum = expectedKeys.reduce((total, key) => total + distribution[key], 0);
  return Math.abs(sum - 1) <= 0.02 + NUMERIC_EPSILON;
}

function sanitizeUsage(usage) {
  if (!isRecord(usage)) return null;
  const output = {};
  for (const key of ["input_tokens", "output_tokens"]) {
    if (Number.isSafeInteger(usage[key]) && usage[key] >= 0) output[key] = usage[key];
  }
  return Object.keys(output).length ? output : null;
}

export function shouldCallJev(features, userRequested = false) {
  if (userRequested) return true;
  return (features.signals ?? []).some((signal) => signal.severity > 0 && (["credential", "financial", "social", "identity"].includes(signal.category) || signal.severity >= 3));
}
