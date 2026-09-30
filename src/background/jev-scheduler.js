const stale = () => ({ status: "unavailable", errorCode: "STALE_CONFIGURATION", signals: [] });

/** Bounded, deduplicated inference queue. A configuration change cancels its effects. */
export class JevScheduler {
  constructor({ concurrency = 2, queueLimit = 8, cacheLimit = 64, cacheTtlMs = 120_000, now = Date.now } = {}) {
    this.concurrency = concurrency;
    this.queueLimit = queueLimit;
    this.cacheLimit = cacheLimit;
    this.cacheTtlMs = cacheTtlMs;
    this.now = now;
    this.version = 0;
    this.active = new Map();
    this.pending = new Map();
    this.queue = [];
    this.cache = new Map();
  }

  snapshot() { return { activeRequests: this.active.size, queueLength: this.queue.length, configurationVersion: this.version }; }

  invalidate() {
    this.version += 1;
    this.cache.clear();
    for (const entry of this.queue.splice(0)) { this.pending.delete(entry.id); entry.resolve(stale()); }
    for (const entry of this.active.values()) entry.controller.abort();
    return this.version;
  }

  run(key, task, { version = this.version, cache = true } = {}) {
    if (version !== this.version) return Promise.resolve(stale());
    const id = `${version}:${key}`;
    const previous = this.cache.get(id);
    if (cache && previous?.until > this.now()) return Promise.resolve(previous.result);
    if (previous) this.cache.delete(id);
    if (this.pending.has(id)) return this.pending.get(id).promise;
    if (this.active.size >= this.concurrency && this.queue.length >= this.queueLimit) return Promise.resolve({ status: "idle", errorCode: "BACKPRESSURE", signals: [] });
    let resolve;
    const promise = new Promise((done) => { resolve = done; });
    const entry = { id, version, task, resolve, promise, cache, controller: new AbortController() };
    this.pending.set(id, entry);
    if (this.active.size < this.concurrency) this.start(entry);
    else this.queue.push(entry);
    return promise;
  }

  start(entry) {
    this.active.set(entry.id, entry);
    let cancel;
    const cancelled = new Promise((resolve) => { cancel = resolve; });
    const abort = () => cancel(stale());
    entry.controller.signal.addEventListener("abort", abort, { once: true });
    const execution = Promise.resolve().then(() => entry.task(entry.controller.signal)).catch(() => ({ status: "unavailable", errorCode: "NETWORK_ERROR", signals: [] }));
    void Promise.race([execution, cancelled]).then((result) => {
      if (entry.version !== this.version || entry.controller.signal.aborted) result = stale();
      if (entry.cache && result.status === "connected") {
        this.cache.set(entry.id, { until: this.now() + this.cacheTtlMs, result });
        while (this.cache.size > this.cacheLimit) this.cache.delete(this.cache.keys().next().value);
      }
      entry.resolve(result);
    }).finally(() => {
      entry.controller.signal.removeEventListener("abort", abort);
      this.pending.delete(entry.id);
      this.active.delete(entry.id);
      while (this.active.size < this.concurrency && this.queue.length) this.start(this.queue.shift());
    });
  }
}
