import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { decodeJevResponse, evaluateJev, shouldCallJev } from "../src/intelligence/jev-client.js";
import { analyzeEmail } from "../src/email/email-analyzer.js";

const fixture = JSON.parse(await readFile(new URL("./fixtures/jev-provider-synthetic-20260930.json", import.meta.url), "utf8"));
const secondFixture = JSON.parse(await readFile(new URL("./fixtures/jev-provider-e14-synthetic-20260930.json", import.meta.url), "utf8"));
const rejected = { status: "error", errorCode: "INVALID_RESPONSE" };

test("actual synthetic Jev response survives independently rounded probability and score values", () => {
  const result = decodeJevResponse(fixture);
  assert.equal(result.status, "connected");
  assert.equal(result.model, "jev-1.13.0");
  assert.equal(result.answers.impersonation_risk.score, 2.45);
  assert.equal(result.answers.financial_fraud_risk.score, 0.02);
});

test("rounded provider score may differ by 0.03 from the serialized distribution", async () => {
  assert.equal(secondFixture.answers.urgency_manipulation.score, 0.03);
  const result = await evaluateJev({
    features: {}, apiKey: "synthetic-regression-key",
    fetchImpl: async () => new Response(JSON.stringify(secondFixture), { status: 200, headers: { "content-type": "application/json" } })
  });
  assert.equal(result.status, "connected");
  assert.equal(result.answers.urgency_manipulation.score, 0.03);
});

test("score inconsistency beyond the bounded serialization error is rejected", () => {
  const data = structuredClone(secondFixture);
  data.answers.urgency_manipulation.score = 0.06;
  assert.deepEqual(decodeJevResponse(data), rejected);
});

test("rounded-score compatibility retains strict typed answer validation", () => {
  const mutations = [
    (data) => { delete data.answers.credential_risk.probabilities["4"]; },
    (data) => { data.answers.credential_risk.probabilities["5"] = 0; },
    (data) => { data.answers.credential_risk.probabilities["4"] = -0.01; },
    (data) => { data.answers.credential_risk.probabilities["2"] = "0.18"; },
    (data) => { data.answers.credential_risk.probabilities["3"] = 0.2; },
    (data) => { data.answers.credential_risk.legend["2"] = "Altered rubric"; },
    (data) => { data.answers.credential_risk.confidence = 1.01; },
    (data) => { data.answers.credential_request.noul = -0.1; },
    (data) => { data.answers.classification.choice = "BENIGN"; },
    (data) => { data.answers.classification.probabilities.UNRECOGNIZED = 0; },
    (data) => { delete data.answers.clickfix_instruction; }
  ];
  for (const mutate of mutations) {
    const data = structuredClone(fixture);
    mutate(data);
    assert.deepEqual(decodeJevResponse(data), rejected);
  }
});

test("contextual authentication and invoice documentation does not trigger automatic Jev inference", () => {
  const documentation = analyzeEmail({
    senderAddress: "docs@example.test", subject: "Manual de autenticação",
    bodyText: "Documentação de segurança: senha, MFA, fatura e autenticação são termos usados no manual.",
    links: [], qrScanStatus: "no-images"
  });
  assert.ok(documentation.signals.some((signal) => signal.severity === 0 && ["credential", "financial"].includes(signal.category)));
  assert.equal(shouldCallJev(documentation), false);
  assert.equal(shouldCallJev(documentation, true), true, "an explicitly requested synthetic test remains available");
  assert.equal(shouldCallJev({ signals: [{ category: "financial", severity: 1 }] }), true);
  assert.equal(shouldCallJev({ signals: [{ category: "context", severity: 3 }] }), true);
});
