import test from "node:test";
import assert from "node:assert/strict";
import { findSecretIndicators } from "../scripts/audit-secrets.mjs";

const syntheticCredential = ["A1b2C3d4", "E5f6G7h8", "J9k0L1m2", "N3p4Q5r6", "S7t8U9v0"].join("");

test("secret audit detects high-entropy named credentials without returning their values", () => {
  const findings = findSecretIndicators(`TYPESAFE_API_KEY="${syntheticCredential}"`);
  assert.deepEqual(findings, ["named API credential"]);
  assert.equal(findings.join(" ").includes(syntheticCredential), false);
  assert.deepEqual(findSecretIndicators(`API_SECRET='${syntheticCredential}'`), ["named API credential"]);
});

test("secret audit detects bearer and prefixed tokens", () => {
  assert.deepEqual(findSecretIndicators(`Authorization: Bearer ${syntheticCredential}`), ["bearer credential"]);
  assert.deepEqual(findSecretIndicators(`const token = "sk_${syntheticCredential}";`), ["prefixed API token"]);
});

test("secret audit ignores empty or low-entropy example values", () => {
  assert.deepEqual(findSecretIndicators('TYPESAFE_API_KEY="not-configured"'), []);
  assert.deepEqual(findSecretIndicators("Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), []);
});
