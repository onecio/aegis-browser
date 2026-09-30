import test from "node:test";
import assert from "node:assert/strict";
import { analyzeEmail } from "../src/email/email-analyzer.js";
import { makeJevState } from "../src/security/redaction.js";
import { shouldCallJev } from "../src/intelligence/jev-client.js";

test("documentation references remain context in Strict features, selection and finding copy", () => {
  const analysis = analyzeEmail({ subject: "Manual de autenticação", bodyText: "A documentação aborda senha, MFA e fatura. Não há solicitação de ação.", links: [] });
  const state = makeJevState(analysis, "STRICT");
  assert.equal(state.has_credential_request, false);
  assert.equal(state.has_financial_request, false);
  assert.equal(shouldCallJev(analysis), false);
  assert.ok(analysis.signals.find((finding) => finding.id === "CREDENTIAL_REQUEST").detail.includes("sem demonstrar"));
});
