import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { mkdir, writeFile } from "node:fs/promises";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { createGatewayServer, loadConfig } from "../gateway/server.js";
import { analyzeEmail } from "../src/email/email-analyzer.js";
import { buildJevQuestions, decodeJevResponse } from "../src/intelligence/jev-client.js";
import { makeJevState } from "../src/security/redaction.js";

if (!process.env.TYPESAFE_API_KEY) throw new Error("Supply TYPESAFE_API_KEY in the environment; never put the credential in arguments.");
const origin = `chrome-extension://${"b".repeat(32)}`;
const config = loadConfig({
  TYPESAFE_API_KEY: process.env.TYPESAFE_API_KEY,
  AEGIS_GATEWAY_ISSUER: "https://identity.example.test",
  AEGIS_GATEWAY_JWKS_URL: "https://identity.example.test/.well-known/jwks.json",
  AEGIS_GATEWAY_AUDIENCE: "aegis-gateway-synthetic-proof",
  AEGIS_GATEWAY_ALLOWED_ORIGINS: origin,
  AEGIS_GATEWAY_ALLOWED_TENANTS: "synthetic-proof-tenant",
  AEGIS_GATEWAY_MAX_CONCURRENCY: "1"
});
const { privateKey, publicKey } = await generateKeyPair("RS256");
const publicJwk = { ...await exportJWK(publicKey), kid: "ephemeral-proof", alg: "RS256", use: "sig" };
const token = await new SignJWT({ tenant_id: "synthetic-proof-tenant", scope: "aegis.analyze" })
  .setProtectedHeader({ alg: "RS256", kid: "ephemeral-proof" })
  .setIssuer(config.issuer).setAudience(config.audience).setSubject("synthetic-proof-subject")
  .setIssuedAt().setExpirationTime("2m").sign(privateKey);
const features = analyzeEmail({
  senderAddress: "notice@example.test", subject: "Verificação de acesso",
  bodyText: "Confirme sua senha no portal de verificação para atualizar o acesso.",
  links: [{ href: "https://portal.example.test/verify", visibleText: "https://microsoft.com", contextText: "Confirme sua senha no portal de verificação." }],
  qrScanStatus: "no-images"
});
const state = makeJevState(features, "STRICT");
assert.equal("body_excerpt" in state, false);
assert.equal("subject_excerpt" in state, false);
let releaseUpstream;
const waitForCapacityCheck = new Promise((resolve) => { releaseUpstream = resolve; });
let signalUpstreamEntered;
const upstreamEntered = new Promise((resolve) => { signalUpstreamEntered = resolve; });
let upstreamCalls = 0;
const server = createGatewayServer(config, {
  jwks: createLocalJWKSet({ keys: [publicJwk] }),
  fetchImpl: async (url, request) => {
    upstreamCalls += 1;
    assert.equal(upstreamCalls, 1, "This operational proof permits one actual provider request");
    assert.equal(url, "https://api.typesafe.ai/v1/systemone");
    signalUpstreamEntered();
    await waitForCapacityCheck;
    return fetch(url, request);
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const endpoint = `http://127.0.0.1:${server.address().port}/v1/systemone`;
const request = (headers = {}) => fetch(endpoint, {
  method: "POST", headers: { origin, "content-type": "application/json", ...headers },
  body: JSON.stringify({ state }), signal: AbortSignal.timeout(7500)
});
try {
  const noJwt = await request();
  assert.equal(noJwt.status, 401);
  const wrongOrigin = await request({ origin: "https://unapproved.example.test", authorization: `Bearer ${token}` });
  assert.equal(wrongOrigin.status, 403);
  assert.equal(upstreamCalls, 0, "Rejected requests cannot bypass authentication/origin gates");
  const started = performance.now();
  const approvedRequest = request({ authorization: `Bearer ${token}` });
  await Promise.race([upstreamEntered, new Promise((_resolve, reject) => setTimeout(() => reject(new Error("Authorized request did not reach gateway capacity gate")), 1800))]);
  const capacityRejected = await request({ authorization: `Bearer ${token}` });
  assert.equal(capacityRejected.status, 503);
  assert.equal((await capacityRejected.json()).error, "capacity_unavailable");
  assert.equal(upstreamCalls, 1, "The occupied capacity gate cannot be bypassed");
  releaseUpstream();
  const approved = await approvedRequest;
  assert.equal(approved.status, 200, "Authenticated gateway inference must return a validated provider answer");
  const decoded = decodeJevResponse(await approved.json());
  assert.equal(decoded.status, "connected");
  assert.deepEqual(Object.keys(decoded.answers).sort(), Object.keys(buildJevQuestions()).sort());
  const report = {
    generatedAt: new Date().toISOString(), status: decoded.status, model: decoded.model,
    dimensions: Object.keys(decoded.answers), usage: decoded.usage,
    gatewayLatencyMs: Number((performance.now() - started).toFixed(1)), actualUpstreamRequests: upstreamCalls,
    privacyMode: "STRICT", identityVerification: "ephemeral RS256 JWT with injected local JWKS resolver",
    productionOidcValidated: false,
    gates: { missingJwt: noJwt.status, wrongOrigin: wrongOrigin.status, occupiedCapacity: capacityRejected.status, upstreamCallsAfterUnauthorizedRequests: 0 },
    limits: ["Real JEV inference used only authored synthetic metadata; this is not a mailbox-accuracy measurement.", "JWT signature, issuer, audience, tenant, expiry, scope and exact origin were checked using an ephemeral identity fixture; production OIDC deployment was not tested.", "This proof permits one actual provider request and does not persist keys, tokens, state, raw provider answers or private content."]
  };
  await mkdir("release/evolution-0.3.0", { recursive: true });
  await writeFile("release/evolution-0.3.0/jev-gateway-proof.json", `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} finally {
  releaseUpstream();
  await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
}
