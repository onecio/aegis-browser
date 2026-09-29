import { registrableDomain } from "../core/domain.js";

const KEY_SECRET = "aegis.patternKey";
const KEY_STATE = "aegis.patternState";
const VERSION = 2;
const RETENTION_MS = 24 * 60 * 60 * 1000;
const MAX_CAMPAIGNS = 40;
const MAX_BASELINES = 40;
const MAX_EVENTS_PER_ENTRY = 12;
const HEX_256 = /^[a-f0-9]{64}$/;

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function unhex(value) {
  return Uint8Array.from(value.match(/.{2}/g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function safeDomain(value) {
  const domain = registrableDomain(value);
  if (!domain || domain.length > 253 || !/^[a-z0-9.-]+$/i.test(domain)) return null;
  return domain.toLowerCase();
}

function uniqueDomains(values) {
  return [...new Set((values ?? []).map(safeDomain).filter(Boolean))].slice(0, 8).sort();
}

function safeState(input, now) {
  if (!input || input.version !== VERSION) return { version: VERSION, campaigns: [], baselines: [] };
  const freshEvents = (items) => (Array.isArray(items) ? items : [])
    .filter((item) => item && HEX_256.test(item.tag ?? "") && Number.isFinite(item.at) && item.at >= now - RETENTION_MS && item.at <= now + 60_000)
    .slice(-MAX_EVENTS_PER_ENTRY);
  const campaigns = (Array.isArray(input.campaigns) ? input.campaigns : [])
    .filter((item) => item && HEX_256.test(item.key ?? ""))
    .map((item) => ({ key: item.key, events: freshEvents(item.events) }))
    .filter((item) => item.events.length)
    .slice(-MAX_CAMPAIGNS);
  const baselines = (Array.isArray(input.baselines) ? input.baselines : [])
    .filter((item) => item && HEX_256.test(item.key ?? ""))
    .map((item) => ({
      key: item.key,
      events: freshEvents(item.events).map((event) => ({ ...event, targets: (Array.isArray(event.targets) ? event.targets : []).filter((target) => HEX_256.test(target)).slice(0, 8) }))
    }))
    .filter((item) => item.events.length)
    .slice(-MAX_BASELINES);
  return { version: VERSION, campaigns, baselines };
}

export class SessionPatternAnalyzer {
  constructor({ storage, crypto = globalThis.crypto, now = () => Date.now() } = {}) {
    this.storage = storage;
    this.crypto = crypto;
    this.now = now;
  }

  async clear() {
    await this.storage?.remove?.([KEY_SECRET, KEY_STATE]);
  }

  async getSessionKey() {
    if (!this.storage?.get || !this.storage?.set || !this.crypto?.subtle || !this.crypto?.getRandomValues) return null;
    const existing = await this.storage.get([KEY_SECRET]);
    if (HEX_256.test(existing?.[KEY_SECRET] ?? "")) return existing[KEY_SECRET];
    const bytes = this.crypto.getRandomValues(new Uint8Array(32));
    const key = hex(bytes);
    await this.storage.set({ [KEY_SECRET]: key });
    return key;
  }

  async fingerprint(secret, value) {
    const key = await this.crypto.subtle.importKey("raw", unhex(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return hex(new Uint8Array(await this.crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))));
  }

  async observe(analysis) {
    const secret = await this.getSessionKey();
    if (!secret) return null;
    const now = this.now();
    const sender = safeDomain(analysis?.senderDomain ?? analysis?.pageDomain);
    const targets = uniqueDomains([
      ...(analysis?.links ?? []).map((link) => link?.domain),
      ...(analysis?.forms ?? []).map((form) => form?.actionDomain)
    ]);
    if (!sender || !targets.length) return null;

    const localHighSignals = [...new Set((analysis.signals ?? [])
      .filter((signal) => signal?.source !== "jev" && Number(signal?.severity) >= 4)
      .map((signal) => String(signal.id ?? "").slice(0, 80))
      .filter(Boolean))].sort().slice(0, 12);
    const claimedBrands = [...new Set((analysis.claimedBrands ?? []).map((brand) => String(brand).normalize("NFKC").toLowerCase().slice(0, 80)))].sort().slice(0, 8);
    const eventDescriptor = {
      surface: String(analysis.surface ?? "unknown").slice(0, 32),
      senderIdentity: String(analysis.normalizedEmail?.sender?.address ?? "").normalize("NFKC").toLowerCase().slice(0, 254),
      subject: String(analysis.normalizedEmail?.subject ?? analysis.subject ?? analysis.pageTitle ?? "").normalize("NFKC").toLowerCase().slice(0, 200),
      sender,
      targets
    };
    const eventTag = await this.fingerprint(secret, `event:${JSON.stringify(eventDescriptor)}`);
    const senderKey = await this.fingerprint(secret, `sender:${sender}`);
    const targetKeys = await Promise.all(targets.map((target) => this.fingerprint(secret, `target:${target}`)));
    const campaignKeys = localHighSignals.length
      ? await Promise.all(targetKeys.map((targetKey) => this.fingerprint(secret, `campaign:${JSON.stringify({ targetKey, claimedBrands, localHighSignals })}`)))
      : [];

    const stored = await this.storage.get([KEY_STATE]);
    const state = safeState(stored?.[KEY_STATE], now);
    let campaign = { correlated: false, observations: 0 };
    for (const campaignKey of campaignKeys) {
      let entry = state.campaigns.find((item) => item.key === campaignKey);
      if (!entry) {
        entry = { key: campaignKey, events: [] };
        state.campaigns.push(entry);
      }
      if (!entry.events.some((item) => item.tag === eventTag)) entry.events.push({ tag: eventTag, at: now });
      entry.events = entry.events.slice(-MAX_EVENTS_PER_ENTRY);
      if (entry.events.length > campaign.observations) {
        campaign = { correlated: entry.events.length >= 2, observations: entry.events.length };
      } else if (entry.events.length >= 2) campaign.correlated = true;
    }

    let baseline = state.baselines.find((item) => item.key === senderKey);
    if (!baseline) {
      baseline = { key: senderKey, events: [] };
      state.baselines.push(baseline);
    }
    const priorEvents = baseline.events.filter((item) => item.tag !== eventTag);
    const priorTargets = new Set(priorEvents.flatMap((item) => item.targets));
    const novelTargets = targetKeys.filter((target) => !priorTargets.has(target));
    const anomaly = {
      detected: priorEvents.length >= 3 && priorTargets.size > 0 && novelTargets.length > 0,
      baselineObservations: Math.min(priorEvents.length, MAX_EVENTS_PER_ENTRY),
      novelTargetCount: novelTargets.length,
      totalTargetCount: targetKeys.length
    };
    if (!baseline.events.some((item) => item.tag === eventTag)) baseline.events.push({ tag: eventTag, targets: targetKeys, at: now });
    baseline.events = baseline.events.slice(-MAX_EVENTS_PER_ENTRY);

    state.campaigns = state.campaigns.slice(-MAX_CAMPAIGNS);
    state.baselines = state.baselines.slice(-MAX_BASELINES);
    await this.storage.set({ [KEY_STATE]: state });
    return { campaign, anomaly };
  }
}

export const SESSION_PATTERN_RETENTION_MS = RETENTION_MS;
