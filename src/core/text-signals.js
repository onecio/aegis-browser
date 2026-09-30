const PATTERNS = [
  ["CREDENTIAL_REQUEST", "credential", 3, /\b(senha|password|passcode|login|sign\s?in|entrar na conta|revalidar credenciais|confirmar sua conta|confirm your account|verify your account|mfa|código de autenticação|authentication code)\b/i, "O conteúdo pede autenticação ou dados de acesso."],
  ["FINANCIAL_ACTION", "financial", 3, /\b(pix|transferência|transfer|wire transfer|pagamento|payment|invoice|fatura|dados bancários|bank account|conta bancária|gift card|cartão presente|criptomoeda|cryptocurrency)\b/i, "O conteúdo menciona uma ação financeira."],
  ["PAYMENT_DETAILS_CHANGE", "financial", 4, /\b(altere|alterar|mude|mudança|change|updated|update)\b.{0,80}\b(conta bancária|dados bancários|bank account|payment details|chave pix|pix key|dados de pagamento)\b/i, "O conteúdo pede mudança de dados de pagamento."],
  ["PROCESS_BYPASS_REQUEST", "social", 3, /\b(não ligue|não telefone|não confirme|não informe|mantenha em segredo|confidential|do not call|don't call|bypass|fora do processo|sem aprovação|urgente e confidencial)\b/i, "O conteúdo pede sigilo ou para evitar uma verificação normal."],
  ["URGENCY_LANGUAGE", "social", 2, /\b(urgente|imediatamente|agora mesmo|último aviso|expira hoje|immediately|urgent|final notice|within 24 hours|action required)\b/i, "A mensagem usa linguagem de urgência."],
  ["THREAT_OR_FEAR_LANGUAGE", "social", 2, /\b(conta será suspensa|acesso será bloqueado|perderá o acesso|legal action|account will be suspended|account will be closed|atividade suspeita detectada)\b/i, "O conteúdo usa ameaça ou medo para incentivar uma ação."],
  ["ATTACHMENT_DOUBLE_EXTENSION", "attachment", 5, /\b[^\s/\\]{1,100}\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|bat|cmd|ps1|msi)\b/i, "O nome de arquivo contém uma extensão executável após uma extensão de documento."],
  ["SPAM_PROMOTION", "spam", 2, /\b(grátis|free|promoção exclusiva|ganhe agora|sem custo|limited offer|claim your prize)\b/i, "Há linguagem promocional ou de envio em massa; isso não comprova que a mensagem seja indesejada."],
  ["BULK_MAIL_CONTROL", "context", 0, /\b(unsubscribe|cancelar inscri(?:ç[aã]o|ção)|descadastrar)\b/i, "A mensagem contém um controle típico de envio em massa; isoladamente, isso não indica spam."]
];

const ACTION_PATTERNS = {
  CREDENTIAL_REQUEST: /\b(?:sign\s?in|log\s?in|entrar na conta|(?:confirm|verify|enter|provide|send|share|validate|confirme|confirmar|verifique|validar|digite|informe|envie|compartilhe|revalidar)\b[^.!?\n]{0,70}\b(?:password|passcode|credentials|account|authentication code|senha|credenciais|conta|código de autenticação))\b/gi,
  FINANCIAL_ACTION: /\b(?:pay|transfer|send|wire|pague|pagar|transfira|transferir|envie|enviar)\b[^.!?\n]{0,70}\b(?:invoice|payment|money|funds|bank|gift card|cryptocurrency|pix|pagamento|fatura|dinheiro|bancári[oa]|cartão presente|criptomoeda)\b/gi,
  PAYMENT_DETAILS_CHANGE: /\b(?:change|update|altere|alterar|mude|mudança)\b[^.!?\n]{0,80}\b(?:bank account|payment details|conta bancária|dados bancários|chave pix|pix key|dados de pagamento)\b/gi
};
const NEGATED_ACTION_PREFIX = /\b(?:do not|don't|never|não|nunca)\s+(?:\w+\s+){0,2}$/i;

function hasAffirmativeAction(text, pattern) {
  pattern.lastIndex = 0;
  for (const match of text.matchAll(pattern)) {
    const prefix = text.slice(Math.max(0, match.index - 40), match.index);
    if (!NEGATED_ACTION_PREFIX.test(prefix)) return true;
  }
  return false;
}

export function extractTextSignals(text, location = "body", scope = location) {
  const normalized = String(text ?? "").slice(0, 24000);
  const signals = [];
  for (const [id, category, severity, pattern, detail] of PATTERNS) {
    if (!pattern.test(normalized)) continue;
    let observedSeverity = severity;
    if (ACTION_PATTERNS[id] && !hasAffirmativeAction(normalized, ACTION_PATTERNS[id])) observedSeverity = 0;
    if (id === "SPAM_PROMOTION" && !/\b(?:promoção exclusiva|ganhe agora|limited offer|claim your prize)\b/i.test(normalized)) observedSeverity = 0;
    const observedDetail = id === "CREDENTIAL_REQUEST" && observedSeverity === 0
      ? "O conteúdo menciona autenticação, sem demonstrar uma solicitação de credenciais."
      : detail;
    signals.push({ id, category, severity: observedSeverity, location, scope, detail: observedDetail });
  }
  return signals;
}

export function findBrandClaims(text) {
  const value = String(text ?? "").slice(0, 24000).toLowerCase();
  return ["microsoft", "office 365", "office365", "outlook", "onedrive", "google", "gmail", "drive", "apple", "icloud", "paypal", "amazon", "gov.br", "receita federal"]
    .filter((claim) => value.includes(claim));
}
