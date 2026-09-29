const STORAGE_KEY = "aegis.localDashboard.v1";
const VERSION = 1;
const RETENTION_DAYS = 90;
const DASHBOARD_DAYS = 30;
const MAX_COUNTER = 1_000_000_000;
const COUNTERS = ["emailsAnalyzed", "pagesAnalyzed", "warnings", "highRiskEvents", "localAnalyses", "jevAnalyses"];
export const FEEDBACK_TYPES = Object.freeze(["useful", "falsePositive", "spam", "legitimate", "phishing"]);

function dayKey(time) {
  return new Date(time).toISOString().slice(0, 10);
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? Math.min(value, MAX_COUNTER) : 0;
}

function emptyDay(date) {
  return {
    date,
    counts: Object.fromEntries(COUNTERS.map((key) => [key, 0])),
    feedback: Object.fromEntries(FEEDBACK_TYPES.map((key) => [key, 0]))
  };
}

function validDay(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = Date.parse(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed) && dayKey(parsed) === value;
}

function normalizeStore(input, now) {
  if (!input || typeof input !== "object" || input.version !== VERSION || !Array.isArray(input.days)) return { version: VERSION, days: [] };
  const latest = dayKey(now);
  const earliest = dayKey(now - (RETENTION_DAYS - 1) * 24 * 60 * 60 * 1000);
  const normalized = input.days
    .filter((item) => item && validDay(item.date) && item.date >= earliest && item.date <= latest)
    .map((item) => {
      const day = emptyDay(item.date);
      for (const key of COUNTERS) day.counts[key] = count(item.counts?.[key]);
      for (const key of FEEDBACK_TYPES) day.feedback[key] = count(item.feedback?.[key]);
      return day;
    })
    .sort((left, right) => left.date.localeCompare(right.date));
  const unique = new Map(normalized.map((item) => [item.date, item]));
  return { version: VERSION, days: [...unique.values()].slice(-RETENTION_DAYS) };
}

function validateAnalysis(item) {
  const surface = item?.surface;
  const state = item?.state;
  if (!["email", "email-inbox", "web", "url", "search-result"].includes(surface) || !["GREEN", "YELLOW", "RED", "UNKNOWN"].includes(state)) return null;
  return {
    surface,
    state,
    localActive: item?.engineStatus?.local === "active"
  };
}

export class LocalDashboard {
  constructor({ storage, now = () => Date.now() } = {}) {
    this.storage = storage;
    this.now = now;
    this.queue = Promise.resolve();
  }

  enqueue(operation) {
    const result = this.queue.then(operation);
    this.queue = result.catch(() => undefined);
    return result;
  }

  async update(mutator) {
    if (!this.storage?.get || !this.storage?.set) return;
    return this.enqueue(async () => {
      const now = this.now();
      const date = dayKey(now);
      const stored = await this.storage.get(STORAGE_KEY);
      const metrics = normalizeStore(stored?.[STORAGE_KEY], now);
      let day = metrics.days.find((item) => item.date === date);
      if (!day) {
        day = emptyDay(date);
        metrics.days.push(day);
      }
      mutator(day);
      metrics.days.sort((left, right) => left.date.localeCompare(right.date));
      metrics.days = metrics.days.slice(-RETENTION_DAYS);
      await this.storage.set({ [STORAGE_KEY]: metrics });
    });
  }

  async recordAnalyses(items) {
    if (!Array.isArray(items) || items.length > 50) return;
    const entries = items.map(validateAnalysis).filter(Boolean);
    if (!entries.length) return;
    return this.update((day) => {
      for (const item of entries) {
        if (item.surface === "email" || item.surface === "email-inbox") day.counts.emailsAnalyzed = Math.min(MAX_COUNTER, day.counts.emailsAnalyzed + 1);
        if (["web", "url", "search-result"].includes(item.surface)) day.counts.pagesAnalyzed = Math.min(MAX_COUNTER, day.counts.pagesAnalyzed + 1);
        if (item.state === "YELLOW" || item.state === "RED") day.counts.warnings = Math.min(MAX_COUNTER, day.counts.warnings + 1);
        if (item.state === "RED") day.counts.highRiskEvents = Math.min(MAX_COUNTER, day.counts.highRiskEvents + 1);
        if (item.localActive) day.counts.localAnalyses = Math.min(MAX_COUNTER, day.counts.localAnalyses + 1);
      }
    });
  }

  async recordJevAnalysis() {
    return this.update((day) => { day.counts.jevAnalyses = Math.min(MAX_COUNTER, day.counts.jevAnalyses + 1); });
  }

  async recordFeedback(kind) {
    if (!FEEDBACK_TYPES.includes(kind)) throw new Error("Unsupported feedback type");
    return this.update((day) => { day.feedback[kind] = Math.min(MAX_COUNTER, day.feedback[kind] + 1); });
  }

  async snapshot() {
    await this.queue;
    const stored = await this.storage?.get?.(STORAGE_KEY);
    const metrics = normalizeStore(stored?.[STORAGE_KEY], this.now());
    const earliest = dayKey(this.now() - (DASHBOARD_DAYS - 1) * 24 * 60 * 60 * 1000);
    const recent = metrics.days.filter((item) => item.date >= earliest);
    const result = { periodDays: DASHBOARD_DAYS };
    for (const key of COUNTERS) result[key] = recent.reduce((sum, item) => sum + item.counts[key], 0);
    result.feedback = Object.fromEntries(FEEDBACK_TYPES.map((key) => [key, recent.reduce((sum, item) => sum + item.feedback[key], 0)]));
    return result;
  }

  async clear() {
    if (!this.storage?.remove) return;
    return this.enqueue(() => this.storage.remove(STORAGE_KEY));
  }
}

export const LOCAL_DASHBOARD_RETENTION_DAYS = RETENTION_DAYS;
