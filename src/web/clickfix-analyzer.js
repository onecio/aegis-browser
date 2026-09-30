const EXECUTION_PROMPT = /\b(?:win(?:dows)?\s*(?:key\s*)?\+\s*r|windows\s+key\s+(?:and|then)\s+r|executar|run\s+dialog|powershell|terminal|prompt\s+de\s+comando|command\s+prompt|cmd(?:\.exe)?)\b/i;
const PASTE_PROMPT = /\b(?:cole|colar|paste|ctrl\s*\+\s*v|botao\s+direito|right[- ]click)\b/i;
const EXECUTE_PROMPT = /\b(?:pressione|aperte|press|hit|digite|type|execute|executar|run)\b[\s\S]{0,80}\b(?:enter|comando|command|script|codigo|code)\b/i;
const SOCIAL_PRETEXT = /\b(?:captcha|verifi(?:que|car)\s+que\s+(?:voce\s+)?e\s+humano|verify\s+(?:that\s+)?you\s+are\s+human|(?:not|nao sou)\s+(?:a\s+)?(?:robot|robo)|prova\s+de\s+humanidade|human\s+verification|verifica(?:cao|r)\s+de\s+seguranca|security\s+verification|desbloque(?:ar|ie)\s+(?:a\s+)?conta|unlock\s+(?:your\s+)?account)\b/i;
const REPAIR_PRETEXT = /\b(?:corrigir|correcao|reparar|repair|fix|resolve)\b[\s\S]{0,100}\b(?:erro|error|browser|navegador|acesso|access|update|atualizacao)\b/i;
const COMMAND_SHAPE = /(?:\bpowershell\b|\bcmd(?:\.exe)?\b|\bmshta\b|\brundll32\b|\bregsvr32\b|\bcurl\b|\bwget\b|\biwr\b|\biex\b|https?:\/\/\S+\.(?:ps1|bat|cmd|js|vbs|exe|msi)\b)/i;
const REMOTE_EXECUTION = /(?:\b(?:iwr|invoke-webrequest|downloadstring)\b[\s\S]{0,240}\b(?:iex|invoke-expression)\b|\b(?:curl|wget)\b[\s\S]{0,240}\|\s*(?:sh|bash|powershell)\b|\bmshta\s+https?:\/\/|\bpowershell\b[\s\S]{0,120}\s-(?:enc|encodedcommand)\b)/i;
const REPORTED_CONTEXT = /\b(?:exemplo de ataque|relato de incidente|analise de (?:ataque|incidente)|attack example|incident report|attack analysis|demonstracao educativa|educational demonstration)\b/i;
const EXPLICIT_WARNING = /\b(?:nao (?:execute|cole|rode)|nunca (?:execute|cole)|do not (?:run|paste|execute)|never (?:run|paste|execute))\b/i;
const NARRATIVE_LABEL = /(?:^|\n|[.!?]\s+)(?:exemplo de ataque|relato de incidente|analise de (?:ataque|incidente)|attack example|incident report|attack analysis):\s*/gi;
const REFERENCED_WARNING = /\b(?:do not|never)\s+(?:run|paste|execute)\s+(?:these|those|such)\s+(?:commands|instructions)|\b(?:nao|nunca)\s+(?:execute|cole|rode)\s+(?:esses|estes|tais)\s+(?:comandos|instrucoes)|\b(?:nao|nunca)\s+(?:execute|cole|rode)\s+(?:comandos|instrucoes)\s+(?:desse|deste)\s+tipo/i;

function measureInstruction(text) {
  const evidence = {
    executionPrompt: EXECUTION_PROMPT.test(text), pastePrompt: PASTE_PROMPT.test(text),
    executePrompt: EXECUTE_PROMPT.test(text), socialPretext: SOCIAL_PRETEXT.test(text),
    commandShape: COMMAND_SHAPE.test(text), remoteExecution: REMOTE_EXECUTION.test(text)
  };
  const hasPretext = evidence.socialPretext || (REPAIR_PRETEXT.test(text) && evidence.remoteExecution);
  return { evidence, candidate: hasPretext && evidence.executionPrompt && evidence.pastePrompt && evidence.executePrompt && evidence.commandShape };
}

export function analyzeClickFix(text) {
  const bounded = String(text ?? "").slice(0, 24_000).normalize("NFKD").replace(/\p{M}|[\u200B-\u200D\uFEFF]/gu, "");
  // Only quoted examples with an adjacent warning are excluded. An educational
  // label anywhere on the page cannot cancel an instruction outside that quote.
  const quotedRanges = [...bounded.matchAll(/["“]([^"”\n]{1,1200})["”]/g)]
    .filter((match) => {
      const context = bounded.slice(Math.max(0, match.index - 220), match.index + match[0].length + 220);
      return REPORTED_CONTEXT.test(context) && EXPLICIT_WARNING.test(context);
    });
  let operative = bounded;
  for (const match of quotedRanges.toReversed()) operative = `${operative.slice(0, match.index)}${" ".repeat(match[0].length)}${operative.slice(match.index + match[0].length)}`;
  const narrativeRanges = [];
  for (const match of bounded.matchAll(NARRATIVE_LABEL)) {
    const block = bounded.slice(match.index, match.index + 1600).split(/\n\s*\n/, 1)[0];
    const warning = block.match(REFERENCED_WARNING);
    if (!warning) continue;
    const end = match.index + warning.index + warning[0].length;
    if (measureInstruction(bounded.slice(match.index, end)).candidate) narrativeRanges.push({ start: match.index, end });
  }
  for (const { start, end } of narrativeRanges.toReversed()) operative = `${operative.slice(0, start)}${" ".repeat(end - start)}${operative.slice(end)}`;
  const pretextPattern = new RegExp(`${SOCIAL_PRETEXT.source}|${REPAIR_PRETEXT.source}`, "gi");
  const candidates = [...operative.matchAll(pretextPattern)].slice(0, 24).map((match) => {
    const start = Math.max(0, match.index - 240);
    const end = Math.min(operative.length, match.index + 1000);
    return { start, end, ...measureInstruction(operative.slice(start, end)) };
  });
  const actionable = candidates.find((candidate) => candidate.candidate);
  const evidence = actionable?.evidence ?? measureInstruction(bounded).evidence;
  const reportedOnly = !actionable && (narrativeRanges.length > 0 || quotedRanges.some((match) => measureInstruction(match[1]).candidate));
  return {
    detected: Boolean(actionable),
    evidence: { ...evidence, reportedOnly, ...(actionable ? { instructionRange: { start: actionable.start, end: actionable.end } } : {}) }
  };
}
