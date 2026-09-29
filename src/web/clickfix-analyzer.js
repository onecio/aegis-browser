const EXECUTION_PROMPT = /\b(?:win(?:dows)?\s*\+\s*r|tecla\s+windows\s*\+\s*r|executar|run\s+dialog|powershell|terminal|prompt\s+de\s+comando|command\s+prompt|cmd(?:\.exe)?)\b/i;
const PASTE_PROMPT = /\b(?:cole|colar|paste|ctrl\s*\+\s*v|bot[aã]o\s+direito)\b/i;
const EXECUTE_PROMPT = /\b(?:pressione|aperte|press|digite|type|execute|executar)\b.{0,80}\b(?:enter|comando|command|script|c[oó]digo|code)\b/i;
const SOCIAL_PRETEXT = /\b(?:captcha|verifi(?:que|car)\s+que\s+(?:voc[eê]\s+)?(?:é|e)\s+humano|verify\s+(?:that\s+)?you\s+are\s+human|prova\s+de\s+humanidade|human\s+verification|verifica(?:ç[aã]o|r)\s+de\s+seguran[çc]a|security\s+verification|desbloque(?:ar|ie)\s+(?:a\s+)?conta|unlock\s+(?:your\s+)?account)\b/i;
const COMMAND_SHAPE = /(?:\bpowershell\b|\bcmd(?:\.exe)?\b|\bmshta\b|\brundll32\b|\bregsvr32\b|\bcurl\b|\bwget\b|\biwr\b|\biex\b|https?:\/\/\S+\.(?:ps1|bat|cmd|js|vbs|exe|msi)\b)/i;

export function analyzeClickFix(text) {
  const bounded = String(text ?? "").slice(0, 24_000);
  const evidence = {
    executionPrompt: EXECUTION_PROMPT.test(bounded),
    pastePrompt: PASTE_PROMPT.test(bounded),
    executePrompt: EXECUTE_PROMPT.test(bounded),
    socialPretext: SOCIAL_PRETEXT.test(bounded),
    commandShape: COMMAND_SHAPE.test(bounded)
  };
  const instructionCount = [evidence.executionPrompt, evidence.pastePrompt, evidence.executePrompt].filter(Boolean).length;
  return { detected: instructionCount >= 2 && evidence.socialPretext && evidence.commandShape && evidence.executionPrompt, evidence };
}
