import test from "node:test";
import assert from "node:assert/strict";
import { summarizeConnection, summarizeMonitor, connectionErrorText } from "../src/ui/operational-status.js";

const t = (key, args = []) => [key, ...args].join("|");

test("configured credentials never imply current Jev connectivity", () => {
  const config = { settings: { jevEnabled: true }, hasByok: true };
  assert.equal(summarizeConnection(config, t).text, "diagnosticUntested");
  assert.equal(summarizeConnection({ ...config, lastJevTest: { ok: true, model: "jev-test" } }, t).text, "diagnosticTestPassed|jev-test");
  assert.equal(summarizeConnection({ ...config, connectionRuntime: { status: "error", reason: "TIMEOUT" } }, t).text, "diagnosticTimeout");
  assert.equal(summarizeConnection({ ...config, settings: { jevEnabled: false } }, t).text, "diagnosticDisabled");
  assert.equal(connectionErrorText("SECRET_ERROR_TEXT", t), "diagnosticUnknown");
  const inferred = summarizeConnection({ ...config, connectionRuntime: { status: "connected", lastEvaluation: { status: "connected", at: "2026-09-30T12:00:00Z", model: "jev-test" } } }, t);
  assert.ok(inferred.text.startsWith("diagnosticInferencePassed|jev-test|"));
});

test("operational copy separates unloaded, paused and active monitoring", () => {
  assert.equal(summarizeMonitor(null, t).canPause, false);
  assert.equal(summarizeMonitor({ ok: true, monitoring: false, continuousProtection: false }, t).canPause, false);
  assert.equal(summarizeMonitor({ ok: true, manualOnly: true }, t).title, "monitorManualOnly");
  assert.equal(summarizeMonitor({ ok: true, monitoring: false }, t).title, "monitorPaused");
  const state = summarizeMonitor({ ok: true, monitoring: true, surface: "gmail", scannedItems: 20, markedItems: 1 }, t);
  assert.equal(state.title, "monitorActive");
  assert.equal(state.detail, "monitorSummary|monitorGmail|20|1");
});
