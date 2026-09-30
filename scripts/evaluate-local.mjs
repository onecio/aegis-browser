import { mkdir, readFile, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { analyzeEmail } from "../src/email/email-analyzer.js";
import { analyzePageSnapshot, analyzeSearchResult } from "../src/web/page-analyzer.js";
import { shouldMarkItem } from "../src/content/visible-risk.js";

const corpus = JSON.parse(await readFile(new URL("../tests/corpus/holdout-synthetic.json", import.meta.url), "utf8"));
const output = process.argv[2] ?? "release/evolution-0.3.0";
const labels = ["NONE", "REVIEW", "HIGH"];
function interval(successes, count) {
  if (!count) return null;
  const z = 1.96;
  const p = successes / count;
  const denominator = 1 + z * z / count;
  const center = (p + z * z / (2 * count)) / denominator;
  const margin = z * Math.sqrt(p * (1 - p) / count + z * z / (4 * count * count)) / denominator;
  return [Number((center - margin).toFixed(4)), Number((center + margin).toFixed(4))];
}
function rate(successes, count) { return { numerator: successes, denominator: count, value: count ? Number((successes / count).toFixed(4)) : null, wilson95: interval(successes, count) }; }
function summarize(rows) {
  const matrix = Object.fromEntries(labels.map((label) => [label, Object.fromEntries(labels.map((predicted) => [predicted, 0]))]));
  for (const row of rows) matrix[row.expected][row.predicted] += 1;
  const redPredictions = rows.filter((row) => row.predicted === "HIGH");
  const highLabels = rows.filter((row) => row.expected === "HIGH");
  const benign = rows.filter((row) => row.expected === "NONE");
  const times = rows.map((row) => row.localMs).sort((a, b) => a - b);
  return {
    n: rows.length, matrix,
    highPrecision: rate(redPredictions.filter((row) => row.expected === "HIGH").length, redPredictions.length),
    coveredHighRecall: rate(highLabels.filter((row) => row.predicted === "HIGH").length, highLabels.length),
    benignVisibleFpr: rate(benign.filter((row) => row.predicted !== "NONE").length, benign.length),
    unknown: rows.filter((row) => row.state === "UNKNOWN").length,
    p95LocalMs: times.length ? Number(times[Math.min(times.length - 1, Math.ceil(times.length * 0.95) - 1)].toFixed(3)) : null
  };
}

const rows = [];
for (const item of corpus.cases) {
  const start = performance.now();
  const analysis = item.surface === "email" ? analyzeEmail(item.input) : item.surface === "search" ? analyzeSearchResult(item.input) : analyzePageSnapshot(item.input, item.url);
  const localMs = performance.now() - start;
  const state = analysis.decision.state;
  // Match the product's presentation policy, not every contextual panel finding.
  const predicted = state === "RED" ? "HIGH" : item.surface === "email" && shouldMarkItem(analysis.decision) ? "REVIEW" : "NONE";
  rows.push({ id: item.id, group: item.group, surface: item.surface, category: item.category, expected: item.expected, predicted, state, analysisStatus: analysis.decision.analysisStatus, localMs: Number(localMs.toFixed(4)), signals: analysis.decision.findings.map(({ id, severity, scope }) => ({ id, severity, scope })) });
}
const report = {
  generatedAt: new Date().toISOString(), mode: "LOCAL", jev: "not-evaluated",
  corpusVersion: corpus.version, provenance: corpus.provenance,
  limits: ["Synthetic cases with a small sample; not population accuracy or certification.", "Wilson intervals describe this finite labeled sample and do not make it representative.", "Local function timing excludes extraction, browser scheduling, IPC, debounce and inference.", "This evaluation is not a blinded independent labeling study; cases have not been reviewed by a second labeler."],
  overall: summarize(rows),
  bySurface: Object.fromEntries([...new Set(rows.map((row) => row.surface))].map((surface) => [surface, summarize(rows.filter((row) => row.surface === surface))])),
  byCategory: Object.fromEntries([...new Set(rows.map((row) => row.category))].map((category) => [category, summarize(rows.filter((row) => row.category === category))])),
  mismatches: rows.filter((row) => row.expected !== row.predicted), rows
};
await mkdir(output, { recursive: true });
await writeFile(`${output}/local-evaluation.json`, `${JSON.stringify(report, null, 2)}\n`);
const lines = [
  "# Avaliação local sintética — AEGIS", "", `Casos: ${rows.length}. JEV real: não avaliado.`, "",
  "As frações abaixo se referem somente aos casos sintéticos. Não comprovam eficácia em contas reais.", "",
  "| Superfície | n | Precisão de vermelho | Recall de casos altos cobertos | Falso positivo visível em benignos | p95 local (ms) |",
  "| --- | ---: | --- | --- | --- | ---: |"
];
for (const [surface, metrics] of Object.entries(report.bySurface)) {
  const fraction = (value) => `${value.numerator}/${value.denominator}`;
  lines.push(`| ${surface} | ${metrics.n} | ${fraction(metrics.highPrecision)} | ${fraction(metrics.coveredHighRecall)} | ${fraction(metrics.benignVisibleFpr)} | ${metrics.p95LocalMs} |`);
}
lines.push("", "## Divergências", "", ...report.mismatches.map((row) => `- ${row.id}: esperado ${row.expected}, observado ${row.predicted} (${row.state}); ${row.group}.`));
if (!report.mismatches.length) lines.push("Nenhuma neste corpus.");
lines.push("", "O arquivo JSON contém matriz de confusão, denominadores, intervalos Wilson, estratos por categoria e resultados individuais. A medição exclui DOM, IPC, debounce e rede.");
await writeFile(`${output}/local-evaluation.md`, `${lines.join("\n")}\n`);
process.stdout.write(`${JSON.stringify({ cases: rows.length, mismatches: report.mismatches.map(({ id, expected, predicted }) => ({ id, expected, predicted })), metrics: report.overall })}\n`);
