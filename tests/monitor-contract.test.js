import assert from "node:assert/strict";
import test from "node:test";
import { selectDynamicWindow } from "../src/web/dynamic-window.js";
import { resolveSearchDestination } from "../src/web/search-results.js";
import { itemEvidenceKey } from "../src/content/item-version.js";
import { shouldMarkItem } from "../src/content/visible-risk.js";

test("search provider wrappers are decoded locally without following a destination", () => {
  assert.deepEqual(resolveSearchDestination("https://www.google.com/url?q=https%3A%2F%2Fexample.test%2Flogin", "google"), { href: "https://example.test/login", wrapperResolution: "decoded" });
  assert.deepEqual(resolveSearchDestination(`https://www.bing.com/ck/a?u=a1${btoa("https://example.test/login")}`, "bing"), { href: "https://example.test/login", wrapperResolution: "decoded" });
  assert.equal(resolveSearchDestination("https://www.google.com/aclk?adurl=javascript%3Aalert(1)", "google").wrapperResolution, "unresolved");
  assert.equal(resolveSearchDestination("https://www.bing.com/ck/a?u=a1broken", "bing").wrapperResolution, "unresolved");
  assert.equal(resolveSearchDestination("https://www.google.com/url?q=https%3A%2F%2Fuser%3Apassword%40example.test", "google").wrapperResolution, "unresolved");
  assert.equal(resolveSearchDestination("https://user:password@example.test/login", "google"), null);
});

test("a large scroll window prioritizes actual visible rows and excludes hidden rows", () => {
  const elements = Array.from({ length: 70 }, (_, index) => ({ index, closest: () => index === 41 ? {} : null, getBoundingClientRect: () => ({ height: 24, width: 500, top: index * 24 - 960, bottom: index * 24 - 936 }) }));
  const selected = selectDynamicWindow(elements, 20, 600);
  assert.equal(selected.length, 20);
  assert.ok(selected.every(({ index }) => index >= 39));
  assert.ok(!selected.some(({ index }) => index === 41));
});

test("an ignored item is bounded to its current payload, evidence and DOM identity", () => {
  const item = { payload: { bodyText: "Synthetic content", links: [] } };
  const key = itemEvidenceKey(item, "inbox", 4, [{ id: "ONE", severity: 5 }]);
  assert.notEqual(itemEvidenceKey(item, "archive", 4, [{ id: "ONE", severity: 5 }]), key);
  assert.notEqual(itemEvidenceKey(item, "inbox", 5, [{ id: "ONE", severity: 5 }]), key);
  assert.notEqual(itemEvidenceKey({ payload: { bodyText: "Changed content" } }, "inbox", 4, [{ id: "ONE", severity: 5 }]), key);
  assert.notEqual(itemEvidenceKey(item, "inbox", 4, [{ id: "TWO", severity: 5 }]), key);
});

test("visible partial evidence remains actionable while an unanalyzable result does not mark content", () => {
  assert.equal(shouldMarkItem({ state: "RED", analysisStatus: "insufficient" }), true);
  assert.equal(shouldMarkItem({ state: "RED", analysisStatus: "failure" }), false);
  assert.equal(shouldMarkItem({ state: "YELLOW", findings: [{ id: "KEYWORD", source: "local", category: "social", severity: 2 }] }), false);
});
