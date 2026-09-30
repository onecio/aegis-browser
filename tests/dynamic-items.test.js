import { analyzeEmail } from "../src/email/email-analyzer.js";
import test from "node:test";
import assert from "node:assert/strict";
import { isCurrentItem } from "../src/content/item-version.js";
import { selectDynamicWindow } from "../src/web/dynamic-window.js";
import { analyzeClickFix } from "../src/web/clickfix-analyzer.js";

test("a recycled email node rejects the old message result", () => {
  const element = { isConnected: true };
  const old = { element, payload: { subject: "Password verification", sender: "attacker" } };
  assert.equal(isCurrentItem(old, [{ element, payload: { subject: "Meeting minutes", sender: "colleague" } }], "inbox", "inbox"), false);
  assert.equal(isCurrentItem(old, [old], "inbox", "archive"), false);
  assert.equal(isCurrentItem(old, [old], "inbox", "inbox"), true);
  element.isConnected = false;
  assert.equal(isCurrentItem(old, [old], "inbox", "inbox"), false);
});

test("ClickFix reports with explicit warnings differ from direct execution instructions", () => {
  const instruction = "Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.";
  const report = `Exemplo de ataque: ${instruction} Nunca execute comandos desse tipo.`;
  assert.equal(analyzeClickFix(report).detected, false);
  assert.equal(analyzeClickFix(`${report}\n\n${instruction}`).detected, true);
  assert.equal(analyzeClickFix("Incident report: to verify you are human, open PowerShell, paste the command and press Enter. Do not run these commands.").detected, false);
});

test("scroll discovers visible items beyond the first twenty", () => {
  const items = Array.from({ length: 60 }, (_, index) => ({ index, getBoundingClientRect: () => ({ width: 500, height: 30, top: index * 40 - 1600, bottom: index * 40 - 1570 }) }));
  const selected = selectDynamicWindow(items, 20, 600);
  assert.ok(selected.some((item) => item.index === 40));
  assert.ok(selected.every((item) => item.index >= 34));
  assert.ok(selected.length <= 20);
});

test("email ClickFix execution instructions are identified without conflating a warning report", () => {
  const bodyText = "Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.";
  const message = { senderAddress: "notice@example.test", subject: "Verification", bodyText };
  assert.equal(analyzeEmail(message).decision.state, "RED");
  assert.ok(analyzeEmail(message).signals.some((finding) => finding.id === "CLICKFIX_EXECUTION_INSTRUCTIONS"));
  assert.equal(analyzeEmail({ ...message, bodyText: `Exemplo de ataque: ${bodyText} Nunca execute comandos desse tipo.` }).signals.some((finding) => finding.id === "CLICKFIX_EXECUTION_INSTRUCTIONS"), false);
});
