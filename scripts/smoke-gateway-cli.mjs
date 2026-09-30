import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { once } from "node:events";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const origin = `chrome-extension://${"a".repeat(32)}`;
const reservation = createServer();
await new Promise((resolve) => reservation.listen(0, "127.0.0.1", resolve));
const port = reservation.address().port;
await new Promise((resolve) => reservation.close(resolve));
const child = spawn(process.execPath, [fileURLToPath(new URL("../gateway/server.js", import.meta.url))], {
  windowsHide: true,
  stdio: ["ignore", "pipe", "pipe"],
  env: {
    ...process.env,
    TYPESAFE_API_KEY: "test-only-key-value",
    AEGIS_GATEWAY_HOST: "127.0.0.1", AEGIS_GATEWAY_PORT: String(port),
    AEGIS_GATEWAY_ISSUER: "https://identity.example.test",
    AEGIS_GATEWAY_JWKS_URL: "https://identity.example.test/.well-known/jwks.json",
    AEGIS_GATEWAY_AUDIENCE: "aegis-cli-fixture",
    AEGIS_GATEWAY_REQUIRED_SCOPE: "aegis.analyze",
    AEGIS_GATEWAY_ALLOWED_ORIGINS: origin,
    AEGIS_GATEWAY_ALLOWED_TENANTS: "synthetic-cli-tenant",
    AEGIS_GATEWAY_RPM: "30", AEGIS_GATEWAY_MAX_CONCURRENCY: "1"
  }
});
let childError;
let startupObserved = false;
child.on("error", (error) => { childError = error.code; });
child.stdout.on("data", (data) => { startupObserved ||= String(data).includes(`AEGIS Gateway listening on 127.0.0.1:${port}`); });
child.stderr.resume();
const base = `http://127.0.0.1:${port}`;
try {
  const deadline = Date.now() + 7000;
  while (!startupObserved && Date.now() < deadline && child.exitCode === null && !childError) {
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
  assert.equal(childError, undefined, `Gateway child startup failed: ${childError ?? "none"}`);
  assert.equal(startupObserved, true, "The actual CLI entrypoint must start its owned server");
  const health = await fetch(`${base}/health`, { signal: AbortSignal.timeout(1500) });
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok", service: "aegis-gateway" });
  const missingToken = await fetch(`${base}/v1/systemone`, {
    method: "POST", headers: { origin, "content-type": "application/json" },
    body: "{}", signal: AbortSignal.timeout(1500)
  });
  assert.equal(missingToken.status, 401);
  const wrongOrigin = await fetch(`${base}/v1/systemone`, {
    method: "POST", headers: { origin: "https://unapproved.example.test", "content-type": "application/json" },
    body: "{}", signal: AbortSignal.timeout(1500)
  });
  assert.equal(wrongOrigin.status, 403);
  const report = {
    generatedAt: new Date().toISOString(), status: "passed", actualCliStartup: true,
    healthStatus: health.status, missingJwtStatus: missingToken.status, wrongOriginStatus: wrongOrigin.status,
    upstreamInferenceAttempted: false, credentials: "dummy environment only",
    limits: ["Startup and rejection gates verified with a temporary owned process; production identity and inference are outside this check."]
  };
  await mkdir("release/evolution-0.3.0", { recursive: true });
  await writeFile("release/evolution-0.3.0/gateway-cli-proof.json", `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} finally {
  if (child.pid && child.exitCode === null) {
    const exited = once(child, "exit");
    child.kill();
    await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 1500))]);
    if (child.exitCode === null) { child.kill("SIGKILL"); await exited; }
  }
}
