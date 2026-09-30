import test from "node:test";
import assert from "node:assert/strict";
import { JevScheduler } from "../src/background/jev-scheduler.js";
import { evaluateJev } from "../src/intelligence/jev-client.js";

const tick = () => new Promise((resolve) => setImmediate(resolve));
const connected = (model) => ({ status: "connected", model, signals: [] });

test("Jev queue bounds concurrency and pending work, deduplicates and applies backpressure", async () => {
  const queue = new JevScheduler({ concurrency: 2, queueLimit: 2 });
  const releases = [];
  let active = 0;
  let maximum = 0;
  const task = () => new Promise((resolve) => {
    active += 1;
    maximum = Math.max(active, maximum);
    releases.push(() => { active -= 1; resolve(connected("jev-test")); });
  });
  const first = queue.run("one", task);
  assert.strictEqual(queue.run("one", task), first);
  const second = queue.run("two", task);
  const third = queue.run("three", task);
  const fourth = queue.run("four", task);
  assert.equal((await queue.run("overflow", task)).errorCode, "BACKPRESSURE");
  await tick();
  assert.deepEqual(queue.snapshot(), { activeRequests: 2, queueLength: 2, configurationVersion: 0 });
  releases.shift()();
  releases.shift()();
  await tick();
  releases.shift()();
  releases.shift()();
  await Promise.all([first, second, third, fourth]);
  assert.equal(maximum, 2);
});

test("Jev invalidation cancels queued and active results even when transport ignores abort", async () => {
  const queue = new JevScheduler({ concurrency: 1, queueLimit: 2 });
  let finishOld;
  let queuedCalls = 0;
  const old = queue.run("same", () => new Promise((resolve) => { finishOld = resolve; }));
  const pending = queue.run("queued", async () => { queuedCalls += 1; return connected("obsolete"); });
  await tick();
  queue.invalidate();
  assert.equal((await old).errorCode, "STALE_CONFIGURATION");
  assert.equal((await pending).errorCode, "STALE_CONFIGURATION");
  assert.equal(queuedCalls, 0);
  await tick();
  assert.equal((await queue.run("same", async () => connected("replacement"))).model, "replacement");
  finishOld(connected("obsolete"));
  await tick();
  assert.equal((await queue.run("same", async () => { throw new Error("cache should be used"); })).model, "replacement");
  assert.equal(queue.cache.size, 1);
});

test("Jev enforces its deadline even when fetch ignores AbortSignal", async () => {
  const started = performance.now();
  const result = await evaluateJev({ apiKey: "test-credential-value", features: {}, timeoutMs: 15, fetchImpl: () => new Promise(() => undefined) });
  assert.equal(result.errorCode, "TIMEOUT");
  assert.ok(performance.now() - started < 1000);
});

test("Jev cancellation differs from provider timeout and prevents a pre-aborted network call", async () => {
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  const result = await evaluateJev({ apiKey: "test-credential-value", features: {}, signal: controller.signal, fetchImpl: () => { calls += 1; return new Promise(() => undefined); } });
  assert.equal(result.errorCode, "CANCELLED");
  assert.equal(calls, 0);
});
