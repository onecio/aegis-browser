import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, SignJWT } from "jose";
import { createGatewayServer } from "../gateway/server.js";
import { buildJevQuestions } from "../src/intelligence/jev-client.js";

const origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const issuer = "https://identity.example.test";

function providerData() {
  const answers = Object.fromEntries(Object.entries(buildJevQuestions()).map(([key, question]) => {
    if (question.type === "noul") return [key, { type: "noul", noul: 0.1 }];
    if (question.type === "choice") return [key, { type: "choice", choice: "BENIGN", confidence: 1, probabilities: Object.fromEntries(Object.keys(question.criteria).map((option) => [option, option === "BENIGN" ? 1 : 0])) }];
    return [key, { type: "score", score: 0, confidence: 1, probabilities: Object.fromEntries(question.criteria.map((_level, index) => [String(index), index === 0 ? 1 : 0])), legend: Object.fromEntries(question.criteria.map((level, index) => [String(index), level])) }];
  }));
  return { model: "jev-test", answers, debug: "provider-private-diagnostic", usage: { input_tokens: 10, secrets: "private" } };
}

async function fixture(t, fetchImpl, options = {}) {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const server = createGatewayServer({ issuer, audience: "aegis-test", requiredScope: "aegis.analyze", jwksUrl: new URL(`${issuer}/keys`), allowedTenants: new Set(["org-one"]), allowedOrigins: new Set([origin]), requestsPerMinute: 30, maxUpstreamConcurrency: 1, typesafeApiKey: "test-provider-credential", typesafeModel: "jev-latest" }, { fetchImpl, jwks: async () => publicKey, ...options });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/v1/systemone`;
  return async ({ expires = true, state = { surface: "web", page_domain: "example.test", link_count: 0, link_mismatch_count: 0 } } = {}) => {
    const token = new SignJWT({ tenant_id: "org-one", scope: "aegis.analyze" }).setProtectedHeader({ alg: "RS256" }).setIssuer(issuer).setAudience("aegis-test").setSubject("user-one").setIssuedAt();
    if (expires) token.setExpirationTime("2m");
    return fetch(url, { method: "POST", headers: { origin, authorization: `Bearer ${await token.sign(privateKey)}`, "content-type": "application/json" }, body: JSON.stringify({ state }) });
  };
}

test("gateway validates the full typed provider response and forwards only the approved envelope", async (t) => {
  let data = providerData();
  const request = await fixture(t, async () => new Response(JSON.stringify(data)));
  const response = await request();
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(Object.keys(body).toSorted(), ["answers", "model", "usage"]);
  assert.deepEqual(body.usage, { input_tokens: 10 });
  assert.equal(JSON.stringify(body).includes("private"), false);
  data = { model: "jev-test", answers: {} };
  const invalid = await request();
  assert.equal(invalid.status, 502);
  assert.deepEqual(await invalid.json(), { error: "invalid_provider_response" });
});

test("gateway rejects permanent tokens and inconsistent minimized state before provider calls", async (t) => {
  let calls = 0;
  const request = await fixture(t, async () => { calls += 1; return new Response(JSON.stringify(providerData())); });
  assert.equal((await request({ expires: false })).status, 401);
  assert.equal((await request({ state: { surface: "web", link_count: 0, link_mismatch_count: 3 } })).status, 422);
  assert.equal(calls, 0);
});

test("gateway caps global upstream concurrency and frees capacity after completion", async (t) => {
  let finish;
  let started;
  const entered = new Promise((resolve) => { started = resolve; });
  let calls = 0;
  const request = await fixture(t, async () => {
    calls += 1;
    if (calls > 1) return new Response(JSON.stringify(providerData()));
    started();
    return new Promise((resolve) => { finish = resolve; });
  });
  const first = request();
  await entered;
  assert.equal((await request()).status, 503);
  finish(new Response(JSON.stringify(providerData())));
  assert.equal((await first).status, 200);
  assert.equal((await request()).status, 200);
  assert.equal(calls, 2);
});

test("gateway deadlines free capacity even if the upstream transport ignores abort", async (t) => {
  const request = await fixture(t, () => new Promise(() => undefined), { upstreamTimeoutMs: 15 });
  for (let index = 0; index < 2; index += 1) {
    const response = await request();
    assert.equal(response.status, 504);
    assert.deepEqual(await response.json(), { error: "timeout" });
  }
});
