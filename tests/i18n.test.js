import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createI18n } from "../src/i18n.js";
import { FINDING_MESSAGE_KEYS, LOCATION_MESSAGE_KEYS, localizeFindingDetail, localizeFindingLocation } from "../src/ui/finding-copy.js";

test("localization uses text and approved attributes without parsing message markup", () => {
  const messages = {
    uiLanguage: "pt-BR",
    heading: "<img src=x onerror=alert(1)>",
    inputLabel: "Endereço para analisar",
    urlPlaceholder: "https://exemplo.com"
  };
  const heading = {
    textContent: "Original",
    getAttribute: (name) => name === "data-i18n" ? "heading" : null
  };
  const input = {
    attributes: { "data-i18n-aria-label": "inputLabel", "data-i18n-placeholder": "urlPlaceholder" },
    getAttribute(name) { return this.attributes[name] ?? null; },
    setAttribute(name, value) { this.attributes[name] = value; }
  };
  const documentRef = {
    documentElement: { lang: "" },
    querySelectorAll(selector) {
      if (selector === "[data-i18n]") return [heading];
      if (selector === "[data-i18n-aria-label]") return [input];
      if (selector === "[data-i18n-placeholder]") return [input];
      return [];
    }
  };
  const i18n = createI18n({ getMessage: (key) => messages[key] ?? "" });

  i18n.localizeDocument(documentRef);

  assert.equal(documentRef.documentElement.lang, "pt-BR");
  assert.equal(heading.textContent, "<img src=x onerror=alert(1)>");
  assert.equal(input.attributes["aria-label"], "Endereço para analisar");
  assert.equal(input.attributes.placeholder, "https://exemplo.com");
  assert.equal(i18n.t("missingMessage"), "");
});

test("extension pages contain no inline styles blocked by the MV3 CSP", async () => {
  for (const name of ["popup.html", "options.html", "sidepanel.html"]) {
    const html = await readFile(new URL(`../extension/${name}`, import.meta.url), "utf8");
    assert.equal(/\sstyle\s*=/i.test(html), false, `${name} contains an inline style attribute`);
  }
});

test("default locale contains every key referenced by the manifest, pages, and UI code", async () => {
  const [manifest, catalog, ...files] = await Promise.all([
    readFile(new URL("../extension/manifest.json", import.meta.url), "utf8"),
    readFile(new URL("../extension/_locales/pt_BR/messages.json", import.meta.url), "utf8"),
    readFile(new URL("../extension/popup.html", import.meta.url), "utf8"),
    readFile(new URL("../extension/options.html", import.meta.url), "utf8"),
    readFile(new URL("../extension/sidepanel.html", import.meta.url), "utf8"),
    readFile(new URL("../src/ui/popup.js", import.meta.url), "utf8"),
    readFile(new URL("../src/ui/options.js", import.meta.url), "utf8"),
    readFile(new URL("../src/ui/sidepanel.js", import.meta.url), "utf8"),
    readFile(new URL("../src/content/content-script.js", import.meta.url), "utf8"),
    readFile(new URL("../src/content/link-highlighter.js", import.meta.url), "utf8"),
    readFile(new URL("../src/ui/finding-copy.js", import.meta.url), "utf8"),
    readFile(new URL("../src/core/domain.js", import.meta.url), "utf8"),
    readFile(new URL("../src/core/domain-analysis.js", import.meta.url), "utf8"),
    readFile(new URL("../src/core/text-signals.js", import.meta.url), "utf8"),
    readFile(new URL("../src/email/email-analyzer.js", import.meta.url), "utf8"),
    readFile(new URL("../src/web/page-analyzer.js", import.meta.url), "utf8"),
    readFile(new URL("../src/intelligence/jev-client.js", import.meta.url), "utf8")
  ]);
  const messages = JSON.parse(catalog);
  const source = `${manifest}\n${files.join("\n")}`;
  const directCalls = [...source.matchAll(/\bt\("([A-Za-z0-9_]+)"/g)].map((match) => match[1]);
  const conditionalCalls = [...source.matchAll(/\bt\([^)]*\?\s*"([A-Za-z][A-Za-z0-9_]+)"\s*:\s*"([A-Za-z][A-Za-z0-9_]+)"\s*\)/gs)]
    .flatMap((match) => [match[1], match[2]]);
  const referenced = new Set([
    ...[...source.matchAll(/__MSG_([A-Za-z0-9_]+)__/g)].map((match) => match[1]),
    ...[...source.matchAll(/data-i18n(?:-[a-z-]+)?="([A-Za-z0-9_]+)"/g)].map((match) => match[1]),
    ...directCalls,
    ...conditionalCalls
  ]);
  const catalogKeys = [...catalog.matchAll(/^\s*"([A-Za-z0-9_]+)"\s*:/gm)].map((match) => match[1]);
  const signalSources = files.slice(9);
  const signalIds = new Set(signalSources.flatMap((file) => [
    ...[...file.matchAll(/id:\s*"([A-Z0-9_]+)"/g)].map((match) => match[1]),
    ...[...file.matchAll(/^\s*\["([A-Z0-9_]+)"/gm)].map((match) => match[1])
  ]));

  assert.ok(messages.uiLanguage);
  assert.equal(new Set(catalogKeys).size, catalogKeys.length, "locale catalog keys must be unique");
  assert.deepEqual([...referenced].filter((key) => !messages[key]).sort(), []);
  assert.deepEqual(Object.values(FINDING_MESSAGE_KEYS).filter((key) => !messages[key]).sort(), []);
  assert.deepEqual(Object.values(LOCATION_MESSAGE_KEYS).filter((key) => !messages[key]).sort(), []);
  assert.deepEqual([...files[8].matchAll(/"(signal[A-Za-z0-9_]+)"/g)].map((match) => match[1]).filter((key) => !messages[key]).sort(), []);
  assert.deepEqual([...signalIds].filter((id) => !Object.hasOwn(FINDING_MESSAGE_KEYS, id)).sort(), []);
});

test("finding copy localizes known evidence and keeps a safe fallback for unknown signals", () => {
  const calls = [];
  const t = (key, substitutions) => { calls.push({ key, substitutions }); return `${key}:${substitutions?.join("|") ?? ""}`; };

  const lookalike = localizeFindingDetail({ id: "POSSIBLE_LOOKALIKE_DOMAIN", detail: "old copy", evidence: { brand: "Example" } }, t);
  assert.equal(lookalike, "signalLookalikeDomain:Example");
  assert.equal(localizeFindingLocation({ location: "domain" }, t), "locationDomain:");
  assert.equal(localizeFindingDetail({ id: "FUTURE_SIGNAL", detail: "fallback copy" }, t), "fallback copy");
  assert.deepEqual(calls[0], { key: "signalLookalikeDomain", substitutions: ["Example"] });
});
