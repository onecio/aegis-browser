const PATTERNS = [
  ["CREDENTIAL_REQUEST", "credential", 3, /\b(senha|password|passcode|login|sign\s?in|entrar na conta|revalidar credenciais|confirmar sua conta|confirm your account|verify your account|mfa|código de autenticação|authentication code)\b/i, "O conteúdo pede autenticação ou dados de acesso."],
  ["FINANCIAL_ACTION", "financial", 3, /\b(pix|transferência|transfer|wire transfer|pagamento|payment|invoice|fatura|dados bancários|bank account|conta bancária|gift card|cartão presente|criptomoeda|cryptocurrency)\b/i, "O conteúdo menciona uma ação financeira."],
  ["PAYMENT_DETAILS_CHANGE", "financial", 4, /\b(altere|alterar|mude|mudança|change|updated|update)\b.{0,80}\b(conta bancária|dados bancários|bank account|payment details|chave pix|pix key|dados de pagamento)\b/i, "O conteúdo pede mudança de dados de pagamento."],
  ["PROCESS_BYPASS_REQUEST", "social", 3, /\b(não ligue|não telefone|não confirme|não informe|mantenha em segredo|confidential|do not call|don't call|bypass|fora do processo|sem aprovação|urgente e confidencial)\b/i, "O conteúdo pede sigilo ou para evitar uma verificação normal."],
  ["URGENCY_LANGUAGE", "social", 2, /\b(urgente|imediatamente|agora mesmo|último aviso|expira hoje|immediately|urgent|final notice|within 24 hours|action required)\b/i, "A mensagem usa linguagem de urgência."],
  ["THREAT_OR_FEAR_LANGUAGE", "social", 2, /\b(conta será suspensa|acesso será bloqueado|perderá o acesso|legal action|account will be suspended|account will be closed|atividade suspeita detectada)\b/i, "O conteúdo usa ameaça ou medo para incentivar uma ação."],
  ["ATTACHMENT_DOUBLE_EXTENSION", "attachment", 5, /\b[^\s/\\]{1,100}\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|bat|cmd|ps1|msi)\b/i, "O nome de arquivo contém uma extensão executável após uma extensão de documento."],
  ["SPAM_PROMOTION", "spam", 2, /\b(grátis|free|promoção exclusiva|ganhe agora|sem custo|limited offer|claim your prize|unsubscribe)\b/i, "Há linguagem promocional ou de envio em massa."]
];

export function extractTextSignals(text, location = "body") {
  const normalized = String(text ?? "").slice(0, 24000);
  const signals = [];
  for (const [id, category, severity, pattern, detail] of PATTERNS) {
    if (pattern.test(normalized)) signals.push({ id, category, severity, location, detail });
  }
  return signals;
}

export function findBrandClaims(text) {
  const value = String(text ?? "").slice(0, 24000).toLowerCase();
  return ["microsoft", "office 365", "office365", "outlook", "onedrive", "google", "gmail", "drive", "apple", "icloud", "paypal", "amazon", "gov.br", "receita federal"]
    .filter((claim) => value.includes(claim));
}
