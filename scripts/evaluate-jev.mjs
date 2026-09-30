import { mkdir, readFile, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { analyzeEmail } from "../src/email/email-analyzer.js";
import { analyzePageSnapshot, analyzeSearchResult } from "../src/web/page-analyzer.js";
import { decideRisk } from "../src/core/decision-engine.js";
import { evaluateJev } from "../src/intelligence/jev-client.js";
import { shouldMarkItem } from "../src/content/visible-risk.js";

if (!process.env.TYPESAFE_API_KEY) throw new Error("TYPESAFE_API_KEY is required in the process environment; do not put credentials in arguments.");
const corpus = JSON.parse(await readFile(new URL("../tests/corpus/holdout-synthetic.json", import.meta.url), "utf8"));
const selectedIds = new Set(["e01", "e05", "e10", "e14", "e16", "w04", "w07", "w09", "w10", "s04", "s07", "s10"]);
const cases = corpus.cases.filter((item) => selectedIds.has(item.id));
const rows = [];
const predict = (decision, surface) => decision.state === "RED" ? "HIGH" : surface === "email" && shouldMarkItem(decision) ? "REVIEW" : "NONE";
let attempts = 0;
let inputTokens = 0;
let outputTokens = 0;
for (const privacyMode of ["STRICT", "ENHANCED"]) {
  let nextIndex = 0;
  await Promise.all(Array.from({ length: 2 }, async () => {
    while (nextIndex < cases.length) {
      const item = cases[nextIndex++];
      const local = item.surface === "email" ? analyzeEmail(item.input) : item.surface === "search" ? analyzeSearchResult(item.input) : analyzePageSnapshot(item.input, item.url);
      const start = performance.now();
      const jev = await evaluateJev({ features: local, apiKey: process.env.TYPESAFE_API_KEY, privacyMode });
      attempts += 1;
      inputTokens += jev.usage?.input_tokens ?? 0;
      outputTokens += jev.usage?.output_tokens ?? 0;
      const combined = decideRisk({ signals: [...local.signals, ...(jev.signals ?? [])], coverage: local.coverage, jev });
      rows.push({ id: item.id, surface: item.surface, expected: item.expected, privacyMode, status: jev.status, errorCode: jev.errorCode ?? null, model: jev.model ?? null, latencyMs: Number((performance.now() - start).toFixed(1)), localState: local.decision.state, combinedState: combined.state, localVisible: predict(local.decision, item.surface), combinedVisible: predict(combined, item.surface), classification: jev.answers?.classification?.choice ?? null, semanticSignalCount: jev.signals?.length ?? 0 });
    }
  }));
}
function summarize(items) {
  const valid = items.filter((item) => item.status === "connected");
  const times = valid.map((item) => item.latencyMs).sort((a, b) => a - b);
  const matrix = () => Object.fromEntries(["NONE", "REVIEW", "HIGH"].map((expected) => [expected, { NONE: 0, REVIEW: 0, HIGH: 0 }]));
  const localMatrix = matrix();
  const combinedMatrix = matrix();
  for (const row of valid) { localMatrix[row.expected][row.localVisible] += 1; combinedMatrix[row.expected][row.combinedVisible] += 1; }
  return { attempts: items.length, connected: valid.length, errors: items.length - valid.length, p50InferenceMs: times[Math.floor(times.length * 0.5)] ?? null, p95InferenceMs: times[Math.min(times.length - 1, Math.ceil(times.length * 0.95) - 1)] ?? null, localMatrix, combinedMatrix, semanticStateChanges: valid.filter((item) => item.localState !== item.combinedState).length, visibleChanges: valid.filter((item) => item.localVisible !== item.combinedVisible).length };
}
const report = { generatedAt: new Date().toISOString(), corpus: "12 selected synthetic regression cases", attempts, inputTokens, outputTokens, models: [...new Set(rows.map((row) => row.model).filter(Boolean))], byMode: Object.fromEntries(["STRICT", "ENHANCED"].map((mode) => [mode, summarize(rows.filter((row) => row.privacyMode === mode))])), limits: ["Real provider inference on synthetic inputs; not real mailbox accuracy.", "Selected regression cases were seen during development and are not an independent holdout.", "Enhanced mode shares only authored synthetic text for this experiment; no user messages or browser data were accessed.", "Only code-owned policy determines visible warnings; semantic signals cannot independently produce RED.", "No provider pricing or population-accuracy claims are made."], rows: rows.sort((a, b) => a.privacyMode.localeCompare(b.privacyMode) || a.id.localeCompare(b.id)) };
await mkdir("release/evolution-0.3.0", { recursive: true });
await writeFile("release/evolution-0.3.0/jev-ablation.json", `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({ attempts, inputTokens, outputTokens, models: report.models, byMode: report.byMode })}\n`);
