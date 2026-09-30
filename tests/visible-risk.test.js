import test from "node:test";
import assert from "node:assert/strict";
import { shouldMarkItem } from "../src/content/visible-risk.js";

test("inbox badges require evidence beyond routine or marketing keywords", () => {
  for (const category of ["financial", "credential", "social", "spam"]) {
    assert.equal(shouldMarkItem({ state: "YELLOW", findings: [{ category, severity: 2 }] }), false);
  }
  assert.equal(shouldMarkItem({ state: "YELLOW", findings: [{ category: "credential", severity: 3 }, { category: "social", severity: 2 }] }), true);
  assert.equal(shouldMarkItem({ state: "YELLOW", findings: [{ id: "ATTACHMENT_DOUBLE_EXTENSION", severity: 5 }] }), true);
  assert.equal(shouldMarkItem({ state: "YELLOW", findings: [{ category: "credential", severity: 2, source: "jev" }] }), false);
  assert.equal(shouldMarkItem({ state: "UNKNOWN", findings: [] }), false);
});
