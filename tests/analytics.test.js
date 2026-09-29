import test from "node:test";
import assert from "node:assert/strict";
import { LocalDashboard, LOCAL_DASHBOARD_RETENTION_DAYS } from "../src/analytics/local-dashboard.js";

const STORAGE_KEY = "aegis.localDashboard.v1";

function memoryStorage() {
  return {
    value: undefined,
    async get(key) { return { [key]: this.value }; },
    async set(values) { this.value = values[STORAGE_KEY]; },
    async remove() { this.value = undefined; }
  };
}

test("local dashboard counts provider invocations explicitly and keeps feedback separate", async () => {
  const storage = memoryStorage();
  const dashboard = new LocalDashboard({ storage, now: () => Date.UTC(2026, 8, 28, 12) });
  await dashboard.recordAnalyses([
    { surface: "email", state: "RED", engineStatus: { local: "active", jev: "off" }, senderDomain: "private.example", subject: "private subject" },
    { surface: "web", state: "YELLOW", engineStatus: { local: "active", jev: "connected" }, body: "private body" },
    { surface: "url", state: "UNKNOWN", engineStatus: { local: "active", jev: "off" } }
  ]);
  await dashboard.recordJevAnalysis();
  await dashboard.recordFeedback("useful");
  await dashboard.recordFeedback("falsePositive");

  assert.deepEqual(await dashboard.snapshot(), {
    periodDays: 30,
    emailsAnalyzed: 1,
    pagesAnalyzed: 2,
    warnings: 2,
    highRiskEvents: 1,
    localAnalyses: 3,
    jevAnalyses: 1,
    feedback: { useful: 1, falsePositive: 1, spam: 0, legitimate: 0, phishing: 0 }
  });
  const stored = JSON.stringify(storage.value);
  assert.equal(stored.includes("private.example"), false);
  assert.equal(stored.includes("private subject"), false);
  assert.equal(stored.includes("private body"), false);
});

test("local dashboard serializes concurrent writes and rejects unsupported feedback", async () => {
  const dashboard = new LocalDashboard({ storage: memoryStorage(), now: () => Date.UTC(2026, 8, 28) });
  await Promise.all(Array.from({ length: 40 }, () => dashboard.recordAnalyses([{ surface: "email-inbox", state: "GREEN", engineStatus: { local: "active", jev: "off" } }])));
  assert.equal((await dashboard.snapshot()).emailsAnalyzed, 40);
  await assert.rejects(dashboard.recordFeedback("include-message-body"), /Unsupported feedback/);
});

test("local dashboard drops data beyond its 90-day retention window", async () => {
  const storage = memoryStorage();
  let now = Date.UTC(2026, 5, 1);
  const dashboard = new LocalDashboard({ storage, now: () => now });
  await dashboard.recordFeedback("phishing");
  now += (LOCAL_DASHBOARD_RETENTION_DAYS + 1) * 24 * 60 * 60 * 1000;
  await dashboard.recordAnalyses([{ surface: "email", state: "GREEN", engineStatus: { local: "active", jev: "off" } }]);
  assert.equal(storage.value.days.length, 1);
  const totals = await dashboard.snapshot();
  assert.equal(totals.emailsAnalyzed, 1);
  assert.equal(totals.feedback.phishing, 0);
});
