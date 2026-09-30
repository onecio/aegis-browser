import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { analyzeDomainIdentity, confusableSkeleton } from "../src/core/domain-analysis.js";
import { analyzeLink, analyzeUrl, registrableDomain } from "../src/core/domain.js";
import { decideRisk } from "../src/core/decision-engine.js";
import { analyzeEmail, analyzeManualUrl, extractEmailFromDocument } from "../src/email/email-analyzer.js";
import { createEmailProviderAdapter, GenericWebmailAdapter, GmailAdapter, normalizeEmailPayload, OutlookWebAdapter } from "../src/email/providers.js";
import { buildJevQuestions, evaluateJev, shouldCallJev } from "../src/intelligence/jev-client.js";
import { makeJevState, redactText, redactUrl } from "../src/security/redaction.js";
import { analyzePageSnapshot, analyzeSearchResult } from "../src/web/page-analyzer.js";
import { analyzeClickFix } from "../src/web/clickfix-analyzer.js";
import { clearRevokedJevCredential, clearRevokedOriginState, clearRevokedSessionAnalyses, originMatchesPermission, toSafeWebOrigin } from "../src/background/permission-cleanup.js";
import { matchOrganizationDomains, normalizeOrganizationDetectionModel, normalizeOrganizationKnowledgeBase, resolveManagedConfiguration } from "../src/core/org-configuration.js";
import { DisabledThreatIntelProvider, validateThreatIntelEvidence } from "../src/intelligence/threat-intel.js";
import { classifyBitBStructure } from "../src/web/bitb-analyzer.js";
import { scanQrImages } from "../src/content/quishing-analyzer.js";
import { SessionPatternAnalyzer } from "../src/intelligence/session-patterns.js";

function validJevAnswers() {
  const answers = {};
  for (const [key, question] of Object.entries(buildJevQuestions())) {
    if (question.type === "noul") {
      answers[key] = { type: "noul", noul: 0.1 };
    } else if (question.type === "choice") {
      const probabilities = Object.fromEntries(Object.keys(question.criteria).map((option) => [option, option === "UNKNOWN" ? 0.82 : 0.02]));
      answers[key] = { type: "choice", choice: "UNKNOWN", probabilities, confidence: 0.82 };
    } else if (question.type === "score") {
      const probabilities = Object.fromEntries(question.criteria.map((_level, index) => [String(index), index === 2 ? 1 : 0]));
      const legend = Object.fromEntries(question.criteria.map((level, index) => [String(index), level]));
      answers[key] = { type: "score", score: 2, probabilities, legend, confidence: 1 };
    }
  }
  return answers;
}

test("registrable domains include private suffixes and multi-label public suffixes", () => {
  assert.equal(registrableDomain("mail.login.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("tenant.appspot.com"), "tenant.appspot.com");
  assert.equal(registrableDomain("microsoft.login.example.com"), "example.com");
});

test("URL analysis reports key names without retaining query values or paths", () => {
  const result = analyzeUrl("https://example.com/reset?access_token=secret-value&next=%2Fhome#session-fragment");
  assert.equal(result.sensitiveParams, true);
  assert.equal(result.displayUrl, "https://example.com");
  assert.equal(JSON.stringify(result).includes("secret-value"), false);
  assert.equal(JSON.stringify(result).includes("session-fragment"), false);
});

test("manual URL analysis rejects unsupported schemes and never returns sensitive URL values", () => {
  const result = analyzeManualUrl("https://portal.example.test/login?access_token=manual-secret&next=%2Fhome#session-fragment");
  assert.equal(result.pageDomain, "example.test");
  assert.equal(result.decision.state, "YELLOW");
  assert.ok(result.signals.some((signal) => signal.id === "URL_SENSITIVE_PARAMETER"));
  assert.ok(result.signals.some((signal) => signal.id === "URL_REDIRECT_PARAMETER"));
  assert.equal(JSON.stringify(result).includes("manual-secret"), false);
  assert.equal(JSON.stringify(result).includes("session-fragment"), false);
  assert.equal(JSON.stringify(result).includes("/home"), false);

  const unsupported = analyzeManualUrl("javascript:alert(1)");
  assert.equal(unsupported.coverage.sufficient, false);
  assert.equal(unsupported.decision.state, "UNKNOWN");
});

test("a displayed URL on another registrable domain produces an explicit mismatch", () => {
  const result = analyzeLink({ href: "https://account-security.example/login", visibleText: "https://login.microsoft.com" });
  assert.equal(result.mismatch, true);
  assert.ok(result.signals.some((signal) => signal.id === "LINK_DISPLAY_DESTINATION_MISMATCH"));
});

test("shorteners are classified as an obscured destination, not phishing evidence", () => {
  const link = analyzeLink({ href: "https://bit.ly/opaque", visibleText: "Abrir documento" });
  assert.deepEqual(link.signals.map((signal) => signal.id), ["OBSCURED_DESTINATION"]);
  assert.equal(decideRisk({ signals: link.signals, coverage: { sufficient: true } }).state, "YELLOW");
});

test("redirect parameters are exposed as unresolved context and are never followed", () => {
  const link = analyzeLink({ href: "https://portal.example.test/login?next=https%3A%2F%2Foutside.test", visibleText: "Continue" });
  assert.equal(link.destination.suspiciousParams, true);
  assert.ok(link.signals.some((signal) => signal.id === "URL_REDIRECT_PARAMETER" && signal.severity === 0));
  assert.equal(JSON.stringify(link).includes("outside.test"), false);

  const email = analyzeEmail({
    senderAddress: "sender@example.test",
    subject: "Review this notice",
    bodyText: "Review the information using the link below.",
    links: [{ href: "https://portal.example.test/login?next=https%3A%2F%2Foutside.test", visibleText: "Review notice" }]
  });
  assert.equal(email.coverage.sufficient, false);
  assert.equal(email.decision.state, "UNKNOWN");

  const manual = analyzeManualUrl("https://portal.example.test/login?next=https%3A%2F%2Foutside.test");
  assert.equal(manual.coverage.sufficient, false);
  assert.equal(manual.decision.state, "UNKNOWN");

  const materialPartial = analyzeManualUrl("https://portal.example.test/login?access_token=synthetic&next=https%3A%2F%2Foutside.test");
  assert.equal(materialPartial.coverage.sufficient, false);
  assert.equal(materialPartial.decision.state, "YELLOW");
});

test("an unbranded IDN alone remains contextual rather than a risk finding", () => {
  const result = analyzeUrl("https://xn--bcher-kva.com");
  const identity = analyzeDomainIdentity({ hostname: result.host });
  assert.ok(identity.signals.some((signal) => signal.id === "IDN_PUNYCODE_DOMAIN"));
  assert.equal(decideRisk({ signals: identity.signals, coverage: { sufficient: true } }).state, "GREEN");
  assert.equal(confusableSkeleton("microsоft"), confusableSkeleton("microsoft"));
});

test("a Unicode lookalike of a known brand is a review signal with explicit attribution", () => {
  const identity = analyzeDomainIdentity({ hostname: "xn--80ak6aa92e.com" });
  assert.ok(identity.signals.some((signal) => signal.id === "POSSIBLE_LOOKALIKE_DOMAIN" && signal.evidence.brand === "Apple"));
  assert.equal(decideRisk({ signals: identity.signals, coverage: { sufficient: true } }).state, "YELLOW");
});

test("punscript IDN is decoded and full Unicode confusables detect a PayPal lookalike", () => {
  const result = analyzeDomainIdentity({ hostname: "xn--ypal-43d9g.com" });
  assert.ok(result.signals.some((signal) => signal.id === "POSSIBLE_LOOKALIKE_DOMAIN" && signal.evidence.brand === "PayPal"));
  assert.ok(result.signals.some((signal) => signal.id === "POSSIBLE_MIXED_SCRIPT_DOMAIN"));
});

test("a likely brand lookalike is a review signal and a password form raises it to red", () => {
  const domain = analyzeDomainIdentity({ hostname: "micros0ft.com" });
  assert.ok(domain.signals.some((signal) => signal.id === "POSSIBLE_LOOKALIKE_DOMAIN"));
  const features = analyzePageSnapshot({
    title: "Microsoft account sign in",
    text: "Microsoft account sign in. Confirm your account to continue.",
    forms: [{ action: "/login", hasPassword: true, hasCredentialField: true }],
    links: []
  }, "https://micros0ft.com/login");
  assert.equal(features.decision.state, "RED");
  assert.ok(features.signals.some((signal) => signal.id === "CREDENTIAL_FORM_PRESENT"));
  assert.equal(features.semanticExcerpt.includes("password-value"), false);
});

test("a credential form posting to a different registrable domain is high risk", () => {
  const features = analyzePageSnapshot({
    title: "Sign in to Microsoft",
    text: "Sign in to your Microsoft account.",
    forms: [{ action: "https://collector.example/submit", hasPassword: true, hasCredentialField: true }],
    links: []
  }, "https://microsoft.com/login");
  assert.equal(features.decision.state, "RED");
  assert.ok(features.signals.some((signal) => signal.id === "CREDENTIAL_FORM_CROSS_DOMAIN"));
});

test("ClickFix requires converging execution instructions and becomes a high-risk page finding", () => {
  const text = "Para verificar que você é humano, pressione Windows + R, cole o comando PowerShell e pressione Enter.";
  assert.equal(analyzeClickFix(text).detected, true);
  const result = analyzePageSnapshot({ title: "Verificação", text, forms: [], links: [] }, "https://support.example.test/check");
  assert.equal(result.decision.state, "RED");
  assert.ok(result.signals.some((signal) => signal.id === "CLICKFIX_EXECUTION_INSTRUCTIONS"));

  const benign = analyzePageSnapshot({ title: "Documentação", text: "Abra o PowerShell para administrar seu próprio ambiente de desenvolvimento.", forms: [], links: [] }, "https://docs.example.test/powershell");
  assert.equal(benign.signals.some((signal) => signal.id === "CLICKFIX_EXECUTION_INSTRUCTIONS"), false);
  const legitimateSupport = analyzePageSnapshot({ title: "Suporte de TI", text: "For legitimate IT support, open PowerShell, paste the signed diagnostic command, and press Enter to repair access.", forms: [], links: [] }, "https://docs.example.test/support");
  assert.equal(legitimateSupport.signals.some((signal) => signal.id === "CLICKFIX_EXECUTION_INSTRUCTIONS"), false);
});

test("search-result analysis flags only material destination or semantic evidence", () => {
  const risky = analyzeSearchResult({
    href: "https://micros0ft-login.example/verify",
    title: "Microsoft account verification",
    snippet: "Confirm your password immediately to keep access."
  });
  assert.equal(risky.surface, "search-result");
  assert.equal(risky.decision.state, "RED");

  const ordinary = analyzeSearchResult({ href: "https://example.com/", title: "Example", snippet: "Reference information and documentation." });
  assert.equal(ordinary.decision.state, "GREEN");
});

test("email link mismatch plus credential request produces red and explains evidence", () => {
  const result = analyzeEmail({
    senderName: "Microsoft Support",
    senderAddress: "support@micros0ft-alert.example",
    subject: "Urgent account verification",
    bodyText: "Confirm your password immediately or your account will be suspended.",
    links: [{ href: "https://account-security.example/login", visibleText: "https://login.microsoft.com" }]
  });
  assert.equal(result.decision.state, "RED");
  assert.ok(result.decision.findings.some((item) => item.id === "CREDENTIAL_REQUEST"));
  assert.equal(result.normalizedEmail.sender.address, "support@micros0ft-alert.example");
  assert.ok(result.normalizedEmail.credential_signals.some((item) => item.id === "CREDENTIAL_REQUEST"));
  assert.equal(JSON.stringify(result.normalizedEmail).includes("account-security.example/login"), false);
  assert.equal(JSON.stringify(result).includes("query=secret"), false);
});

test("attachment metadata is bounded and double document extensions require review", () => {
  const suspicious = analyzeEmail({
    senderAddress: "sender@example.test",
    bodyText: "Please review the attachment.",
    attachments: [{ filename: "C:\\private\\invoice.pdf.exe", mimeType: "application/x-msdownload; charset=binary" }]
  });
  const attachmentSignal = suspicious.signals.find((signal) => signal.id === "ATTACHMENT_DOUBLE_EXTENSION");
  assert.equal(attachmentSignal?.severity, 5);
  assert.equal(suspicious.decision.state, "YELLOW");
  assert.deepEqual(suspicious.normalizedEmail.attachments, [{
    filename: "invoice.pdf.exe", extension: "exe", mimeType: "application/x-msdownload"
  }]);
  assert.equal(JSON.stringify(suspicious.normalizedEmail).includes("private"), false);

  const ordinary = analyzeEmail({
    senderAddress: "sender@example.test",
    bodyText: "Please review the attachment.",
    attachments: [{ filename: "invoice.pdf", mimeType: "application/pdf" }]
  });
  assert.equal(ordinary.signals.some((signal) => signal.id === "ATTACHMENT_DOUBLE_EXTENSION"), false);
  assert.deepEqual(ordinary.normalizedEmail.attachments, [{
    filename: "invoice.pdf", extension: "pdf", mimeType: "application/pdf"
  }]);

  const oversized = createEmailProviderAdapter("gmail").normalizeMessage({
    attachments: Array.from({ length: 31 }, () => ({
      filename: `${"x".repeat(200)}.pdf`,
      mimeType: `application/${"a".repeat(140)}`
    }))
  }).attachments;
  assert.equal(oversized.length, 30);
  assert.equal(oversized[0].filename.length, 180);
  assert.equal(oversized[0].mimeType.length, 120);
  assert.deepEqual(createEmailProviderAdapter("gmail").normalizeMessage({ attachments: [null, { filename: "invoice.pdf" }] }).attachments, [{
    filename: "invoice.pdf", extension: "pdf", mimeType: ""
  }]);
});

test("revoking a host permission clears only associated session analyses and stale legacy entries", async () => {
  const values = new Map([
    ["aegis.analysis.10", { sourceOrigin: "https://mail.google.com", state: "YELLOW" }],
    ["aegis.analysis.11", { sourceOrigin: "https://portal.example.test", state: "GREEN" }],
    ["aegis.analysis.12", { state: "UNKNOWN" }],
    ["aegis.latestTab", 10],
    ["aegis.secret.byok", "session-only-value"]
  ]);
  const storage = {
    get: async () => Object.fromEntries(values),
    remove: async (keys) => { for (const key of keys) values.delete(key); }
  };

  assert.equal(originMatchesPermission("https://mail.google.com/inbox", "https://mail.google.com/*"), true);
  assert.equal(originMatchesPermission("https://sub.example.test", "https://*.example.test/*"), true);
  assert.equal(originMatchesPermission("https://evil-example.test", "https://*.example.test/*"), false);
  assert.equal(originMatchesPermission("http://portal.example.test", "https://*/*"), false);
  assert.equal(toSafeWebOrigin("https://user:password@portal.example.test/inbox?token=private#secret"), "https://portal.example.test");
  assert.equal(toSafeWebOrigin("chrome-extension://extension-id/options.html"), null);

  const removed = await clearRevokedSessionAnalyses({ storage, origins: ["https://mail.google.com/*"] });
  assert.deepEqual(removed, ["aegis.analysis.10", "aegis.analysis.12", "aegis.latestTab"]);
  assert.equal(values.has("aegis.analysis.10"), false);
  assert.equal(values.has("aegis.analysis.11"), true);
  assert.equal(values.has("aegis.analysis.12"), false);
  assert.equal(values.has("aegis.secret.byok"), true);
});

test("revoking the BYOK provider permission disables Jev and removes its session credential", async () => {
  const values = new Map([
    ["aegis.secret.byok", "session-only-value"],
    ["aegis.jevCircuit", { errors: 2 }]
  ]);
  const removedKeys = [];
  const storage = { remove: async (keys) => {
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      removedKeys.push(key);
      values.delete(key);
    }
  } };
  let disabled = 0;
  const reset = [];
  const cleared = await clearRevokedJevCredential({
    currentSettings: { connectionMode: "byok", jevEnabled: true },
    removedOrigins: ["https://api.typesafe.ai/*"],
    permissions: { contains: async ({ origins }) => {
      assert.deepEqual(origins, ["https://api.typesafe.ai/*"]);
      return false;
    } },
    storage,
    secretKeys: { byok: "aegis.secret.byok", gatewayToken: "aegis.secret.gatewayToken" },
    disableJev: async () => { disabled += 1; },
    resetStoredJev: async (status) => { reset.push(status); }
  });

  assert.equal(cleared, true);
  assert.equal(disabled, 1);
  assert.deepEqual(removedKeys, ["aegis.secret.byok", "aegis.jevCircuit"]);
  assert.equal(values.has("aegis.secret.byok"), false);
  assert.deepEqual(reset, ["off"]);
});

test("Jev credential cleanup preserves unrelated and still-granted provider access", async () => {
  for (const { removedOrigins, stillGranted } of [
    { removedOrigins: ["https://unrelated.example.test/*"], stillGranted: false },
    { removedOrigins: ["https://*/*"], stillGranted: true }
  ]) {
    const values = new Map([["aegis.secret.byok", "session-only-value"]]);
    let permissionChecks = 0;
    const result = await clearRevokedJevCredential({
      currentSettings: { connectionMode: "byok", jevEnabled: true },
      removedOrigins,
      permissions: { contains: async () => { permissionChecks += 1; return stillGranted; } },
      storage: { remove: async (keys) => { for (const key of keys) values.delete(key); } },
      secretKeys: { byok: "aegis.secret.byok", gatewayToken: "aegis.secret.gatewayToken" },
      disableJev: async () => assert.fail("Jev must remain enabled while provider access is retained"),
      resetStoredJev: async () => assert.fail("Jev state must remain unchanged")
    });

    assert.equal(result, false);
    assert.equal(permissionChecks, removedOrigins[0] === "https://*/*" ? 1 : 0);
    assert.equal(values.has("aegis.secret.byok"), true);
  }
});

test("revoking the configured gateway permission removes its token and disables Jev", async () => {
  const values = new Map([
    ["aegis.secret.gatewayToken", "session-only-token"],
    ["aegis.jevCircuit", { errors: 1 }]
  ]);
  let disabled = 0;
  let resetStatus = "";
  const cleared = await clearRevokedJevCredential({
    currentSettings: { connectionMode: "gateway", gatewayUrl: "https://gateway.example.test", jevEnabled: true },
    removedOrigins: ["https://gateway.example.test/*"],
    permissions: { contains: async () => false },
    storage: { remove: async (keys) => { for (const key of keys) values.delete(key); } },
    secretKeys: { byok: "aegis.secret.byok", gatewayToken: "aegis.secret.gatewayToken" },
    disableJev: async () => { disabled += 1; },
    resetStoredJev: async (status) => { resetStatus = status; }
  });

  assert.equal(cleared, true);
  assert.equal(disabled, 1);
  assert.equal(values.has("aegis.secret.gatewayToken"), false);
  assert.equal(values.has("aegis.jevCircuit"), false);
  assert.equal(resetStatus, "off");
});

test("origin revocation still removes the Jev secret when analysis and campaign cleanup fail", async () => {
  const removed = [];
  const order = [];
  const result = await clearRevokedOriginState({
    removedOrigins: ["https://api.typesafe.ai/*"],
    storage: {
      get: async () => { throw new Error("session storage unavailable"); },
      remove: async (keys) => { removed.push(...keys); }
    },
    permissions: { contains: async () => false },
    secretKeys: { byok: "aegis.secret.byok", gatewayToken: "aegis.secret.gatewayToken" },
    readSettings: async () => ({ connectionMode: "byok", jevEnabled: true }),
    clearPatterns: async () => { order.push("patterns"); throw new Error("pattern storage unavailable"); },
    disableJev: async () => { order.push("disable"); throw new Error("managed setting"); },
    resetStoredJev: async (status) => { order.push(`reset:${status}`); }
  });

  assert.equal(result, true);
  assert.deepEqual(order, ["patterns", "disable", "reset:off"]);
  assert.ok(removed.includes("aegis.secret.byok"));
  assert.ok(removed.includes("aegis.jevCircuit"));
});

test("sender metadata and subject alone do not make an image-only email GREEN", () => {
  const result = analyzeEmail({
    senderName: "Security Desk",
    senderAddress: "notice@service.example.test",
    subject: "Your account update",
    bodyText: "",
    links: [],
    attachments: [],
    qrScanStatus: "unavailable"
  });
  assert.equal(result.coverage.sufficient, false);
  assert.equal(result.decision.state, "UNKNOWN");
  assert.ok(result.decision.coverage.reasons.length > 0);
});

test("an incomplete QR scan limits coverage even when message text is visible", () => {
  const base = {
    senderAddress: "notice@example.test",
    bodyText: "Leia o aviso e confira a imagem anexada antes de prosseguir."
  };
  const incomplete = analyzeEmail({ ...base, qrScanStatus: "partial" });
  assert.equal(incomplete.coverage.sufficient, false);
  assert.equal(incomplete.decision.state, "UNKNOWN");
  assert.ok(incomplete.signals.some((signal) => signal.id === "QR_SCAN_INCOMPLETE"));

  const partiallyDecoded = analyzeEmail({
    ...base,
    qrScanStatus: "partial",
    qrUrls: ["https://account.example.test/login?token=synthetic-value"]
  });
  assert.equal(partiallyDecoded.coverage.sufficient, false);
  assert.equal(partiallyDecoded.decision.state, "YELLOW");
  assert.ok(partiallyDecoded.signals.some((signal) => signal.id === "QR_SCAN_INCOMPLETE"));
  assert.ok(partiallyDecoded.signals.some((signal) => signal.id === "QR_CODE_URL_DECODED"));
  assert.equal(JSON.stringify(partiallyDecoded).includes("synthetic-value"), false);

  const noImages = analyzeEmail({ ...base, qrScanStatus: "no-images" });
  assert.equal(noImages.coverage.sufficient, true);
  assert.equal(noImages.decision.state, "GREEN");
});

test("an opened image-only email reaches local QR analysis", async () => {
  const image = { complete: true, naturalWidth: 128, naturalHeight: 128 };
  const body = {
    innerText: "",
    textContent: "",
    parentElement: null,
    closest() { return null; },
    querySelector(selector) { return selector.startsWith("img") ? image : null; },
    querySelectorAll(selector) { return selector === "img" ? [image] : []; }
  };
  const document = { querySelector(selector) { return selector === ".a3s.aiL" ? body : null; }, querySelectorAll(selector) { return selector === ".a3s.aiL" ? [body] : []; } };
  const adapter = createEmailProviderAdapter("gmail");
  const opened = adapter.findOpenedMessage(document);
  assert.equal(opened?.body, body);

  const payload = adapter.extractOpenedEmail(document, opened);
  const detector = class {
    async detect() { return [{ format: "qr_code", rawValue: "https://login.example.test/?token=synthetic-value" }]; }
  };
  const qrScan = await scanQrImages(adapter.findQrImages(document, opened), detector);
  payload.qrUrls = qrScan.urls;
  payload.qrScanStatus = qrScan.status;
  const analysis = analyzeEmail(payload);

  assert.equal(qrScan.status, "scanned");
  assert.equal(analysis.decision.state, "YELLOW");
  assert.ok(analysis.signals.some((signal) => signal.id === "QR_CODE_URL_DECODED"));
  assert.equal(JSON.stringify(analysis).includes("synthetic-value"), false);
});

test("promotional spam is a review signal and does not imply phishing", () => {
  const result = analyzeEmail({
    senderName: "Daily Offers",
    senderAddress: "offers@bulk.example.test",
    subject: "Limited offer",
    bodyText: "Claim your prize today. Unsubscribe at any time.",
    links: [{ href: "https://bulk.example.test/unsubscribe", visibleText: "Unsubscribe" }]
  });
  assert.equal(result.decision.state, "YELLOW");
  assert.ok(result.signals.some((signal) => signal.id === "SPAM_PROMOTION"));
  assert.equal(result.decision.riskVector.spam, 2);
  assert.equal(result.decision.riskVector.phishing, 0);
});

test("credential phishing can be RED without urgency language", () => {
  const result = analyzeEmail({
    senderName: "Service Desk",
    senderAddress: "notice@service.example.test",
    subject: "Account access",
    bodyText: "Sign in to review your account details.",
    links: [{ href: "https://attacker.example/login", visibleText: "https://login.service.example" }]
  });
  assert.equal(result.decision.state, "RED");
  assert.ok(result.signals.some((signal) => signal.id === "CREDENTIAL_REQUEST"));
  assert.ok(result.signals.some((signal) => signal.id === "LINK_DISPLAY_DESTINATION_MISMATCH"));
  assert.equal(result.signals.some((signal) => signal.id === "URGENCY_LANGUAGE"), false);
});

test("Gmail, Outlook, and generic webmail adapters share a normalized extraction contract", () => {
  const adapters = [
    createEmailProviderAdapter("gmail"),
    createEmailProviderAdapter("outlook"),
    createEmailProviderAdapter("generic")
  ];
  assert.ok(adapters[0] instanceof GmailAdapter);
  assert.ok(adapters[1] instanceof OutlookWebAdapter);
  assert.ok(adapters[2] instanceof GenericWebmailAdapter);
  for (const adapter of adapters) {
    assert.equal(typeof adapter.findOpenedMessage, "function");
    assert.equal(typeof adapter.extractOpenedEmail, "function");
    assert.equal(typeof adapter.extractInboxRows, "function");
    const normalized = adapter.normalizeMessage({
      senderName: "Security Team", senderAddress: "alerts@example.test", subject: "Review required",
      bodyText: "Please review the account update.", links: [], attachments: []
    });
    assert.deepEqual(normalized.sender, { name: "Security Team", address: "alerts@example.test", domain: "example.test" });
    assert.equal(normalized.preview, "Please review the account update.");
    assert.equal(normalized.subject, "Review required");
  }
});

test("opened email extraction reports content omitted by bounded limits", () => {
  const anchors = Array.from({ length: 81 }, () => ({ href: "https://example.test/notice", innerText: "Notice" }));
  const attachments = Array.from({ length: 31 }, () => ({
    getAttribute(name) { return name === "download" ? "notice.pdf" : ""; },
    hasAttribute(name) { return name === "download"; },
    textContent: ""
  }));
  const body = { innerText: "Regular update. ".repeat(1601), querySelectorAll() { return anchors; } };
  const root = { querySelector() { return null; }, querySelectorAll() { return attachments; } };

  const extracted = extractEmailFromDocument({}, root, body);
  const normalized = normalizeEmailPayload(extracted);
  const analysis = analyzeEmail(normalized);

  assert.deepEqual(normalized.extractionLimits, { body: true, links: true, attachments: true, qrUrls: false });
  assert.equal(normalized.links.length, 80);
  assert.equal(normalized.attachments.length, 30);
  assert.equal(analysis.coverage.sufficient, false);
  assert.equal(analysis.decision.state, "UNKNOWN");
  assert.ok(analysis.coverage.reasons.some((reason) => reason.includes("limite")));
});

test("financial change and process bypass require converging evidence for red", () => {
  const signals = [
    { id: "PAYMENT_DETAILS_CHANGE", category: "financial", severity: 4 },
    { id: "PROCESS_BYPASS_REQUEST", category: "social", severity: 3 },
    { id: "BRAND_DOMAIN_CONFLICT", category: "identity", severity: 4 }
  ];
  assert.equal(decideRisk({ signals, coverage: { sufficient: true } }).state, "RED");
  assert.equal(decideRisk({ signals: signals.slice(0, 2), coverage: { sufficient: true } }).state, "YELLOW");
});

test("insufficient coverage never becomes green", () => {
  assert.equal(decideRisk({ signals: [], coverage: { sufficient: false } }).state, "UNKNOWN");
  assert.equal(decideRisk({ signals: [], coverage: { sufficient: true }, analysisError: true }).state, "UNKNOWN");
  assert.equal(decideRisk({ signals: [{ id: "URL_SENSITIVE_PARAMETER", category: "link", severity: 2 }], coverage: { sufficient: false } }).state, "YELLOW");
  assert.equal(decideRisk({ signals: [{ id: "URL_SENSITIVE_PARAMETER", category: "link", severity: 2 }], coverage: { sufficient: false }, analysisError: true }).state, "UNKNOWN");
});

test("incomplete coverage does not suppress decisive local red evidence", () => {
  const formRisk = [{ id: "CREDENTIAL_FORM_CROSS_DOMAIN", category: "credential", severity: 5 }];
  const convergingEmailRisk = [
    { id: "CREDENTIAL_REQUEST", category: "credential", severity: 4 },
    { id: "LINK_DISPLAY_DESTINATION_MISMATCH", category: "link", severity: 4 }
  ];
  const partialCoverage = { sufficient: false, reasons: ["A parte visível da página estava incompleta"] };

  assert.equal(decideRisk({ signals: formRisk, coverage: partialCoverage }).state, "RED");
  assert.equal(decideRisk({ signals: convergingEmailRisk, coverage: partialCoverage }).state, "RED");
  const partialFailure = decideRisk({ signals: formRisk, coverage: partialCoverage, analysisError: true });
  assert.equal(partialFailure.state, "RED");
  assert.equal(partialFailure.engineStatus.local, "error");
  assert.equal(decideRisk({ signals: [{ ...formRisk[0], source: "jev" }], coverage: partialCoverage }).state, "UNKNOWN");
});

test("Jev can add a review signal but cannot create RED or lower a local RED decision", () => {
  const jevOnly = [{ id: "JEV_REVIEW_SUGGESTED", category: "social", severity: 5, source: "jev" }];
  assert.equal(decideRisk({ signals: jevOnly, coverage: { sufficient: true } }).state, "YELLOW");

  const localRed = [
    { id: "CREDENTIAL_REQUEST", category: "credential", severity: 4 },
    { id: "LINK_DISPLAY_DESTINATION_MISMATCH", category: "link", severity: 4 }
  ];
  assert.equal(decideRisk({ signals: [...localRed, { ...jevOnly[0], severity: 0 }], coverage: { sufficient: true } }).state, "RED");
});

test("Jev asks separately for all required semantic scores", () => {
  const questions = buildJevQuestions();
  const scoreKeys = ["social_engineering_intensity", "credential_risk", "financial_fraud_risk", "impersonation_risk", "urgency_manipulation", "semantic_suspicion"];
  for (const key of scoreKeys) {
    assert.equal(questions[key]?.type, "score", `${key} uses the Score primitive`);
    assert.equal(questions[key].criteria.length, 5, `${key} has five descriptive levels`);
  }
  assert.equal(questions.classification.criteria.SPEAR_PHISHING_LIKELY !== undefined, true);
  assert.equal(questions.classification.criteria.CREDENTIAL_PHISHING_LIKELY !== undefined, true);
  assert.equal(questions.classification.criteria.QUISHING_LIKELY !== undefined, true);
});

test("STRICT Jev state excludes text, full URLs, mailbox identities, and secret values", () => {
  const state = makeJevState({
    surface: "email", senderDomain: "example.com", pageDomain: null, claimedBrands: ["Microsoft"],
    subject: "Alert for user@example.com", semanticExcerpt: "code=secret token abc",
    attachments: [{ filename: "private-payroll-case-927451.pdf" }],
    signals: [], links: [{ mismatch: false, url: "https://example.com/?access_token=secret" }], forms: []
  }, "STRICT");
  const serialized = JSON.stringify(state);
  assert.equal(serialized.includes("user@example.com"), false);
  assert.equal(serialized.includes("secret"), false);
  assert.equal(serialized.includes("private-payroll-case-927451.pdf"), false);
  assert.equal(serialized.includes("https://"), false);
});

test("balanced redaction removes email addresses, long identifiers, and sensitive URL values", () => {
  assert.equal(redactText("Contact user@example.com ref 0123456789abcdef0123456789abcdef"), "Contact [email] ref [id]");
  assert.equal(redactUrl("https://example.com/?access_token=secret&x=ok#fragment"), "https://example.com/?access_token=[redacted]&x=ok");
  assert.equal(redactText("Open https://example.org/?session=secret and password:abc123"), "Open [link] and password=[redacted]");
});

test("Jev call sends only the minimized state and never writes a key into logs or output", async () => {
  let sent;
  let sentUrl;
  const fetchImpl = async (url, request) => {
    sentUrl = url;
    sent = JSON.parse(request.body);
    assert.equal(request.headers.authorization, "Bearer user-provided-secret-key");
    return new Response(JSON.stringify({ model: "jev-test", answers: validJevAnswers(), usage: { input_tokens: 10, output_tokens: 8 } }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const result = await evaluateJev({
    fetchImpl, apiKey: "user-provided-secret-key",
    features: { surface: "email", senderDomain: "example.com", pageDomain: null, claimedBrands: [], links: [], forms: [], signals: [], semanticExcerpt: "private message" }
  });
  assert.equal(result.status, "connected");
  assert.equal(sentUrl, "https://api.typesafe.ai/v1/systemone", "the BYOK client targets the provider endpoint directly");
  assert.equal(result.model, "jev-test");
  assert.equal(result.answers.credential_risk.score, 2);
  assert.equal(result.answers.credential_risk.legend["2"], buildJevQuestions().credential_risk.criteria[2]);
  assert.equal(result.answers.classification.choice, "UNKNOWN");
  assert.equal(JSON.stringify(sent).includes("private message"), false);
  assert.equal(JSON.stringify(result).includes("user-provided-secret-key"), false);
});

test("Jev rejects malformed Score distributions instead of silently omitting dimensions", async () => {
  const answers = validJevAnswers();
  answers.credential_risk.probabilities = { "0": 0, "1": 0, "2": 0.4, "3": 0.1, "4": 0 };
  const result = await evaluateJev({
    apiKey: "user-provided-secret-key",
    features: {},
    fetchImpl: async () => new Response(JSON.stringify({ model: "jev-test", answers }), { status: 200, headers: { "content-type": "application/json" } })
  });
  assert.deepEqual(result, { status: "error", errorCode: "INVALID_RESPONSE" });
});

test("Jev reports ClickFix as a bounded semantic review signal", async () => {
  const answers = validJevAnswers();
  answers.clickfix_instruction = { type: "noul", noul: 0.91 };
  const result = await evaluateJev({
    apiKey: "user-provided-secret-key",
    features: { surface: "web", signals: [{ id: "LOCAL_CONTEXT", category: "context", severity: 1 }] },
    fetchImpl: async () => new Response(JSON.stringify({ model: "jev-test", answers }), { status: 200, headers: { "content-type": "application/json" } })
  });
  assert.equal(result.status, "connected");
  assert.ok(result.signals.some((signal) => signal.id === "JEV_CLICKFIX_INSTRUCTION" && signal.severity === 2));
  assert.equal(decideRisk({ signals: result.signals, coverage: { sufficient: true } }).state, "YELLOW", "Jev alone cannot produce RED");
});

test("Jev provider failure returns a local fallback status without exposing error text", async () => {
  const result = await evaluateJev({ apiKey: "user-provided-secret-key", features: {}, fetchImpl: async () => { throw new Error("Bearer user-provided-secret-key"); } });
  assert.equal(result.status, "error");
  assert.equal(JSON.stringify(result).includes("user-provided-secret-key"), false);
});

test("Jev requests are prefiltered and provider authorization failures remain typed", async () => {
  assert.equal(shouldCallJev({ signals: [] }), false);
  assert.equal(shouldCallJev({ signals: [{ category: "context", severity: 0 }] }), false);
  assert.equal(shouldCallJev({ signals: [{ category: "credential", severity: 0 }] }), false);
  assert.equal(shouldCallJev({ signals: [{ category: "credential", severity: 1 }] }), true);
  assert.equal(shouldCallJev({ signals: [] }, true), true);

  for (const [status, errorCode] of [[401, "UNAUTHORIZED"], [403, "FORBIDDEN"], [429, "RATE_LIMITED"], [500, "PROVIDER_UNAVAILABLE"], [400, "PROVIDER_ERROR"]]) {
    const result = await evaluateJev({
      apiKey: "user-provided-secret-key", features: {},
      fetchImpl: async () => new Response("provider error with no diagnostics", { status })
    });
    assert.deepEqual(result, { status: "error", errorCode });
    assert.equal(JSON.stringify(result).includes("provider error"), false);
  }
});

test("Jev timeouts abort the request and invalid keys never reach the provider", async () => {
  let called = false;
  const invalid = await evaluateJev({ apiKey: "short", features: {}, fetchImpl: async () => { called = true; } });
  assert.deepEqual(invalid, { status: "error", errorCode: "MISSING_OR_INVALID_KEY" });
  assert.deepEqual(await evaluateJev({ apiKey: "x".repeat(1025), features: {}, fetchImpl: async () => { called = true; } }), { status: "error", errorCode: "MISSING_OR_INVALID_KEY" });
  assert.equal(called, false);

  let requestSignal;
  const timeout = await evaluateJev({
    apiKey: "user-provided-secret-key", features: {}, timeoutMs: 10,
    fetchImpl: (_url, request) => new Promise((_resolve, reject) => {
      requestSignal = request.signal;
      request.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
    })
  });
  assert.deepEqual(timeout, { status: "error", errorCode: "TIMEOUT" });
  assert.equal(requestSignal.aborted, true);
});

test("seed dataset is parseable, synthetic, unique, and covers all decision states", async () => {
  const content = await readFile(new URL("../docs/golden_seed.csv", import.meta.url), "utf8");
  const lines = content.trim().split(/\r?\n/);
  const rows = lines.slice(1).map((line) => line.split(","));
  const ids = rows.map((row) => row[0]);
  const categories = rows.map((row) => row[2]).sort();
  assert.equal(rows.length, 18);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(categories, ["bec", "bitb", "brand_impersonation", "compromised_domain", "credential_phishing", "fake_login", "legitimate_personal", "legitimate_security", "low_urgency_phishing", "marketing", "phishing", "quishing", "redirect_adversarial", "shortener", "spam", "spear_phishing", "transactional_legitimate", "unicode_adversarial"]);
  for (const state of ["GREEN", "YELLOW", "RED", "UNKNOWN"]) assert.ok(content.includes(`,${state},`));
});

test("adversarial seed covers each specified attack shape without embedding live indicators", async () => {
  const content = await readFile(new URL("../docs/adversarial_seed.csv", import.meta.url), "utf8");
  const rows = content.trim().split(/\r?\n/).slice(1).map((line) => line.split(","));
  const categories = rows.map((row) => row[2]).sort();
  const ids = rows.map((row) => row[0]);
  assert.equal(rows.length, 8);
  assert.ok(rows.every((row) => row.length === 8));
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(categories, ["compromised_legitimate_looking_domain", "image_based_phishing", "legitimate_looking_language", "low_urgency_phishing", "nested_redirects", "qr_phishing", "unicode", "url_obfuscation"]);
  assert.ok(rows.every((row) => ["GREEN", "YELLOW", "RED", "UNKNOWN"].includes(row[5])));
  assert.doesNotMatch(content, /https?:\/\/|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/i);
});

test("organization knowledge base validates domains and maps official brands without treating allowlists as verdicts", () => {
  const knowledgeBase = normalizeOrganizationKnowledgeBase({
    brands: [{ name: "Example Bank", terms: ["Example Bank", "ExBank"], domains: ["login.example.test", "example-bank.test"] }],
    ssoDomains: ["sso.example.test"],
    vendorDomains: ["payments.vendor.test"],
    financialDomains: ["finance.example.test"],
    internalDomains: ["intranet"]
  });
  assert.deepEqual(knowledgeBase.brands[0].domains, ["login.example.test", "example-bank.test"]);
  assert.equal(matchOrganizationDomains("portal.login.example.test", knowledgeBase)[0].kind, "brand");
  assert.equal(matchOrganizationDomains("evilvendor.test", knowledgeBase).length, 0);
  assert.throws(() => normalizeOrganizationKnowledgeBase({ internalDomains: ["https://example.test/login"] }), /domain/i);
});

test("organization knowledge base adds brand impersonation evidence to email and web analysis", () => {
  const organizationKnowledgeBase = normalizeOrganizationKnowledgeBase({
    brands: [{ name: "Northwind Bank", terms: ["Northwind Bank", "Northwind"], domains: ["northwind.example"] }]
  });
  const page = analyzePageSnapshot({ title: "Northwind Bank sign in", text: "Northwind Bank account portal", forms: [], links: [] }, "https://northwind-login.example/", organizationKnowledgeBase);
  assert.ok(page.signals.some((signal) => signal.id === "BRAND_DOMAIN_CONFLICT" && signal.evidence.brand === "Northwind Bank"));
  const official = analyzePageSnapshot({ title: "Northwind Bank", text: "Northwind Bank account portal", forms: [], links: [] }, "https://login.northwind.example/", organizationKnowledgeBase);
  assert.equal(official.signals.some((signal) => signal.id === "BRAND_DOMAIN_CONFLICT"), false);
  const email = analyzeEmail({ senderName: "Northwind Bank", senderAddress: "notices@attacker.example", subject: "Northwind update", bodyText: "Review your account" }, { organizationKnowledgeBase });
  assert.ok(email.signals.some((signal) => signal.id === "BRAND_DOMAIN_CONFLICT" && signal.evidence.brand === "Northwind Bank"));
});

test("organization SSO and internal domains suppress weak identity conflicts but remain informational", () => {
  const organizationKnowledgeBase = normalizeOrganizationKnowledgeBase({ ssoDomains: ["login.company.example"], internalDomains: ["intranet"] });
  const page = analyzePageSnapshot({ title: "Microsoft sign in", text: "Microsoft account authentication is available here.", forms: [], links: [] }, "https://login.company.example/", organizationKnowledgeBase);
  assert.equal(page.signals.some((signal) => signal.id === "BRAND_DOMAIN_CONFLICT"), false);
  assert.ok(page.signals.some((signal) => signal.id === "ORGANIZATION_DOMAIN_RECOGNIZED" && signal.severity === 0));
  const ordinary = analyzePageSnapshot({ title: "Microsoft sign in", text: "Microsoft account authentication is available here.", forms: [], links: [] }, "https://attacker.example/", organizationKnowledgeBase);
  assert.ok(ordinary.signals.some((signal) => signal.id === "BRAND_DOMAIN_CONFLICT"));
});

test("organization domains reduce weak link warnings while preserving mismatch and credential evidence", () => {
  const organizationKnowledgeBase = normalizeOrganizationKnowledgeBase({ internalDomains: ["intranet"], vendorDomains: ["bit.ly"] });
  const internal = analyzeLink({ href: "http://intranet/reports", visibleText: "Open the internal report", organizationKnowledgeBase });
  assert.equal(internal.signals.some((signal) => signal.id === "LINK_USES_HTTP" && signal.severity > 0), false);
  assert.ok(internal.signals.some((signal) => signal.id === "ORGANIZATION_LINK_DOMAIN_RECOGNIZED" && signal.severity === 0));
  const shortener = analyzeLink({ href: "https://bit.ly/opaque", visibleText: "Vendor portal", organizationKnowledgeBase });
  assert.equal(shortener.signals.some((signal) => signal.id === "OBSCURED_DESTINATION"), false);
  const mismatch = analyzeLink({ href: "https://intranet/login", visibleText: "https://login.microsoft.com", organizationKnowledgeBase });
  assert.ok(mismatch.signals.some((signal) => signal.id === "LINK_DISPLAY_DESTINATION_MISMATCH"));
});

test("managed enterprise settings override user settings and managed knowledge base takes precedence", () => {
  const local = {
    emailProtection: false,
    webProtection: false,
    organizationKnowledgeBase: { brands: [{ name: "Local", terms: ["Local"], domains: ["local.test"] }] }
  };
  const managed = {
    emailProtection: true,
    organizationKnowledgeBase: { brands: [{ name: "Company", terms: ["Company"], domains: ["company.test"] }] }
  };
  const result = resolveManagedConfiguration(local, managed);
  assert.equal(result.settings.emailProtection, true);
  assert.equal(result.settings.webProtection, false);
  assert.deepEqual(result.settings.organizationKnowledgeBase.brands.map(({ name }) => name), ["Company"]);
  assert.deepEqual(result.managedKeys, ["emailProtection", "organizationKnowledgeBase"]);
  const invalidManaged = resolveManagedConfiguration(local, { organizationKnowledgeBase: { brands: [{ name: "broken", domains: ["https://bad.example/path"] }] } });
  assert.deepEqual(invalidManaged.settings.organizationKnowledgeBase, { brands: [], ssoDomains: [], vendorDomains: [], financialDomains: [], internalDomains: [] });
  assert.ok(invalidManaged.managedKeys.includes("organizationKnowledgeBase"));
});

test("versioned organization detection models are strictly validated and applied locally", () => {
  const local = { organizationKnowledgeBase: { brands: [{ name: "Local", domains: ["local.test"] }] } };
  const model = {
    schemaVersion: 1,
    modelId: "acme-mail-safety",
    modelVersion: "2.1.0",
    knowledgeBase: { brands: [{ name: "Acme", terms: ["Acme"], domains: ["acme.test"] }], financialDomains: ["pay.acme.test"] }
  };
  const resolved = resolveManagedConfiguration(local, { organizationDetectionModel: model });
  assert.equal(resolved.settings.organizationDetectionModel.status, "active");
  assert.equal(resolved.settings.organizationDetectionModel.modelId, "acme-mail-safety");
  assert.equal(resolved.settings.organizationDetectionModel.modelVersion, "2.1.0");
  assert.deepEqual(resolved.settings.organizationKnowledgeBase.brands.map(({ name }) => name), ["Acme"]);
  assert.ok(resolved.managedKeys.includes("organizationKnowledgeBase"));
  assert.ok(resolved.managedKeys.includes("organizationDetectionModel"));
  assert.throws(() => normalizeOrganizationDetectionModel({ ...model, executable: "return true" }), /Unknown organization detection model field/);

  const invalid = resolveManagedConfiguration(local, { organizationDetectionModel: { ...model, schemaVersion: 2 } });
  assert.equal(invalid.settings.organizationDetectionModel.status, "invalid");
  assert.deepEqual(invalid.settings.organizationKnowledgeBase.brands, []);
  assert.ok(invalid.managedKeys.includes("organizationKnowledgeBase"));
});

test("threat intelligence is disabled by default and accepts only fresh, typed, indicator-matched evidence", async () => {
  const provider = new DisabledThreatIntelProvider();
  assert.deepEqual(await provider.lookupDomain("example.test"), { status: "disabled" });
  const now = Date.now();
  const valid = validateThreatIntelEvidence({
    status: "hit", indicator: "example.test", verdict: "phishing", source: "organization-feed",
    observedAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), confidence: 0.8
  }, { indicator: "example.test", now });
  assert.equal(valid.status, "hit");
  assert.equal(valid.verdict, "phishing");
  assert.equal(validateThreatIntelEvidence({ ...valid, indicator: "other.test" }, { indicator: "example.test", now }).status, "unavailable");
  assert.equal(validateThreatIntelEvidence({ ...valid, expiresAt: new Date(now - 1).toISOString() }, { indicator: "example.test", now }).status, "unavailable");
});

test("BitB requires several structural signals and never changes the risk decision by itself", () => {
  const suspiciousStructure = { dialog: true, positionedOverlay: true, fakeAddressBar: true, windowControls: 3, authenticationSurface: true };
  assert.equal(classifyBitBStructure(suspiciousStructure), true);
  assert.equal(classifyBitBStructure({ ...suspiciousStructure, fakeAddressBar: false }), false);
  assert.equal(classifyBitBStructure({ ...suspiciousStructure, dialog: false }), false);
  const analysis = analyzePageSnapshot({ title: "Example", text: "A neutral page with enough visible content.", forms: [], links: [], bitb: suspiciousStructure }, "https://example.test/");
  assert.ok(analysis.signals.some((signal) => signal.id === "POSSIBLE_BITB" && signal.severity === 0));
  assert.equal(analysis.decision.state, "GREEN");
});

test("quishing scans loaded images locally, accepts only HTTP(S) QR values, and never opens them", async () => {
  let constructorOptions;
  const detector = class {
    constructor(options) { constructorOptions = options; }
    async detect(image) {
      if (image.id === "qr") return [{ format: "qr_code", rawValue: "https://login.example.test/verify?token=private" }];
      if (image.id === "text") return [{ format: "qr_code", rawValue: "WIFI:T:WPA;S:private;P:secret;;" }];
      return [{ format: "qr_code", rawValue: "javascript:alert(1)" }];
    }
  };
  const images = ["qr", "text", "unsafe"].map((id) => ({ id, complete: true, naturalWidth: 240, naturalHeight: 240 }));
  const result = await scanQrImages(images, detector);
  assert.deepEqual(constructorOptions.formats, ["qr_code"]);
  assert.deepEqual(result.urls, ["https://login.example.test/verify?token=private"]);
  assert.equal(result.status, "scanned");
  assert.deepEqual(await scanQrImages(images, null), { status: "unavailable", urls: [], scanned: 0 });
});

test("QR image and destination limits report incomplete coverage", async () => {
  const images = Array.from({ length: 13 }, (_, id) => ({ id, complete: true, naturalWidth: 128, naturalHeight: 128 }));
  const adapter = createEmailProviderAdapter("gmail");
  const opened = { body: { querySelectorAll(selector) { assert.equal(selector, "img"); return images; } } };
  const detector = class {
    async detect(image) { return [{ format: "qr_code", rawValue: `https://example.test/qr/${image.id}` }]; }
  };

  const imageLimited = await scanQrImages(adapter.findQrImages(null, opened), detector);
  assert.equal(imageLimited.scanned, 12);
  assert.equal(imageLimited.status, "partial");
  assert.equal(imageLimited.urls.length, 8);

  const destinationLimited = await scanQrImages(images.slice(0, 9), detector);
  assert.equal(destinationLimited.scanned, 9);
  assert.equal(destinationLimited.status, "partial");
  assert.equal(destinationLimited.urls.length, 8);
});

test("quishing falls back to bounded local pixel decoding without network or DOM image access", async () => {
  const image = { complete: true, naturalWidth: 1024, naturalHeight: 768 };
  let drawn;
  let decodeOptions;
  const document = {
    createElement(name) {
      assert.equal(name, "canvas");
      return {
        width: 0,
        height: 0,
        getContext() {
          return {
            drawImage(source, x, y, width, height) { drawn = { source, x, y, width, height }; },
            getImageData(x, y, width, height) { return { data: new Uint8ClampedArray(width * height * 4) }; }
          };
        }
      };
    }
  };
  const result = await scanQrImages([image], null, {
    document,
    decoder(_pixels, width, height, options) {
      decodeOptions = options;
      assert.equal(width, 512);
      assert.equal(height, 384);
      return { data: "https://login.example.test/verify?token=private" };
    }
  });
  assert.equal(result.status, "scanned");
  assert.deepEqual(result.urls, ["https://login.example.test/verify?token=private"]);
  assert.deepEqual(drawn, { source: image, x: 0, y: 0, width: 512, height: 384 });
  assert.deepEqual(decodeOptions, { inversionAttempts: "dontInvert" });
});

test("quishing marks cross-origin canvas failures as incomplete and caps synchronous decoder pixels", async () => {
  let attempts = 0;
  const images = Array.from({ length: 5 }, () => ({ complete: true, naturalWidth: 1024, naturalHeight: 768 }));
  const document = {
    createElement() {
      return {
        width: 0,
        height: 0,
        getContext() {
          return {
            drawImage() { throw new DOMException("Canvas is tainted", "SecurityError"); },
            getImageData() { throw new Error("must not read a tainted canvas"); }
          };
        }
      };
    }
  };
  const result = await scanQrImages(images, null, { document, decoder: () => { attempts += 1; return null; } });
  assert.equal(result.status, "partial");
  assert.equal(result.scanned, 4);
  assert.equal(attempts, 0);
});

test("decoded QR destinations are analyzed as URLs while query values remain ephemeral", () => {
  const result = analyzeEmail({
    senderAddress: "sender@example.test", bodyText: "Review this message carefully before following its instructions.",
    qrUrls: ["https://account.example.test/sign-in?token=qr-secret"], qrScanStatus: "scanned"
  });
  assert.equal(result.links[0].source, "qr");
  assert.equal(result.links[0].domain, "example.test");
  assert.ok(result.decision.findings.some((finding) => finding.id === "QR_CODE_URL_DECODED"));
  assert.equal(JSON.stringify(result).includes("qr-secret"), false);
});

test("session pattern intelligence correlates repeated campaigns and reports novelty without storing raw indicators", async () => {
  const storage = {
    values: {},
    async get(keys) { return Object.fromEntries(keys.filter((key) => Object.hasOwn(this.values, key)).map((key) => [key, this.values[key]])); },
    async set(values) { Object.assign(this.values, values); }
  };
  let now = Date.UTC(2026, 8, 28, 12);
  const analyzer = new SessionPatternAnalyzer({ storage, crypto: globalThis.crypto, now: () => now });
  const message = (subject, target = "outside.example", highRisk = true, senderDomain = "vendor.example", additionalTargets = []) => ({
    surface: "email", senderDomain, normalizedEmail: { sender: { address: `billing@${senderDomain}` }, subject },
    links: [target, ...additionalTargets].map((domain) => ({ domain })), claimedBrands: ["Northwind Bank"],
    signals: highRisk ? [{ id: "PAYMENT_DETAILS_CHANGE", category: "financial", severity: 4 }] : []
  });
  const first = await analyzer.observe(message("Invoice update 1", "outside.example", true, "vendor.example", ["backup.example"]));
  const second = await analyzer.observe(message("Invoice update 2", "outside.example", true, "accounts.example", ["tracking.example"]));
  assert.equal(first.campaign.correlated, false);
  assert.equal(second.campaign.correlated, true);
  assert.equal(second.campaign.observations, 2);

  await analyzer.observe(message("Invoice update 3", "old.example", false));
  await analyzer.observe(message("Invoice update 4", "old.example", false));
  await analyzer.observe(message("Invoice update 5", "old.example", false));
  now += 60_000;
  const anomaly = await analyzer.observe(message("Invoice update 6", "old.example", false, "vendor.example", ["new.example"]));
  assert.equal(anomaly.anomaly.detected, true);
  assert.equal(anomaly.anomaly.novelTargetCount, 1);
  assert.equal(anomaly.anomaly.totalTargetCount, 2);
  const persisted = JSON.stringify(storage.values);
  for (const rawValue of ["vendor.example", "accounts.example", "outside.example", "backup.example", "tracking.example", "old.example", "new.example", "Northwind Bank", "Invoice update", "billing@vendor.example"]) assert.equal(persisted.includes(rawValue), false);
});
