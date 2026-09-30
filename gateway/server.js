import { createServer } from "node:http";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { z } from "zod";
import { buildJevQuestions, decodeJevResponse } from "../src/intelligence/jev-client.js";

const TYPE_SAFE_ENDPOINT = "https://api.typesafe.ai/v1/systemone";
const REQUEST_LIMIT_BYTES = 12_288;
const RESPONSE_LIMIT_BYTES = 48_000;
const RATE_WINDOW_MS = 60_000;
const RATE_SUBJECT_LIMIT = 10_000;
const DOMAIN = z.string().max(253).regex(/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i);
const bodySchema = z.object({
  surface: z.enum(["email", "web", "url", "search-result"]),
  page_domain: DOMAIN.nullable().optional(),
  sender_domain: DOMAIN.nullable().optional(),
  claimed_brands: z.array(z.string().max(40)).max(12).optional(),
  link_count: z.number().int().min(0).max(100).optional(),
  link_mismatch_count: z.number().int().min(0).max(100).optional(),
  has_credential_request: z.boolean().optional(),
  has_financial_request: z.boolean().optional(),
  has_process_bypass: z.boolean().optional(),
  has_urgency_language: z.boolean().optional(),
  has_clickfix_instructions: z.boolean().optional(),
  page_has_password_form: z.boolean().optional(),
  subject_excerpt: z.string().max(120).optional(),
  body_excerpt: z.string().max(1200).optional()
}).strict().refine((state) => (state.link_mismatch_count ?? 0) <= (state.link_count ?? 0));

function loadConfig(env = process.env) {
  const issuer = new URL(env.AEGIS_GATEWAY_ISSUER ?? "");
  const jwksUrl = new URL(env.AEGIS_GATEWAY_JWKS_URL ?? "");
  if ([issuer, jwksUrl].some((url) => url.protocol !== "https:" || url.username || url.password || url.search || url.hash)) {
    throw new Error("OIDC issuer and JWKS URL must be credential-free HTTPS URLs without query or fragment");
  }
  const key = env.TYPESAFE_API_KEY ?? "";
  if (key.length < 16 || /\s/.test(key)) throw new Error("TYPESAFE_API_KEY must be supplied as a secret");
  const origins = (env.AEGIS_GATEWAY_ALLOWED_ORIGINS ?? "").split(",").map((origin) => origin.trim()).filter(Boolean);
  if (!origins.length || origins.includes("*")) throw new Error("Set exact allowed extension origins; wildcard CORS is rejected");
  const allowedTenants = new Set((env.AEGIS_GATEWAY_ALLOWED_TENANTS ?? "").split(",").map((tenant) => tenant.trim()).filter(Boolean));
  if (!allowedTenants.size || allowedTenants.has("*")) throw new Error("Set explicit allowed tenant identifiers; wildcard tenancy is rejected");
  const requestsPerMinute = Number(env.AEGIS_GATEWAY_RPM ?? 30);
  const port = Number(env.AEGIS_GATEWAY_PORT ?? 8787);
  const maxUpstreamConcurrency = Number(env.AEGIS_GATEWAY_MAX_CONCURRENCY ?? 16);
  if (!Number.isInteger(requestsPerMinute) || requestsPerMinute < 1) throw new Error("AEGIS_GATEWAY_RPM must be a positive integer");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("AEGIS_GATEWAY_PORT must be between 1 and 65535");
  if (!Number.isInteger(maxUpstreamConcurrency) || maxUpstreamConcurrency < 1 || maxUpstreamConcurrency > 64) throw new Error("AEGIS_GATEWAY_MAX_CONCURRENCY must be between 1 and 64");
  for (const origin of origins) {
    const parsed = new URL(origin);
    const exactHttps = parsed.protocol === "https:" && parsed.origin === origin;
    const exactExtension = parsed.protocol === "chrome-extension:" && /^[a-p]{32}$/.test(parsed.hostname) && origin === `chrome-extension://${parsed.hostname}`;
    if (!exactHttps && !exactExtension) throw new Error("Allowed origins must be exact HTTPS or extension origins");
  }
  return {
    issuer: issuer.href.replace(/\/$/, ""),
    jwksUrl,
    audience: env.AEGIS_GATEWAY_AUDIENCE ?? "aegis-browser",
    requiredScope: env.AEGIS_GATEWAY_REQUIRED_SCOPE ?? "aegis.analyze",
    allowedTenants,
    typesafeApiKey: key,
    typesafeModel: env.TYPESAFE_MODEL ?? "jev-latest",
    allowedOrigins: new Set(origins),
    requestsPerMinute: Math.min(600, requestsPerMinute),
    maxUpstreamConcurrency,
    host: env.AEGIS_GATEWAY_HOST ?? "127.0.0.1",
    port
  };
}

function writeJson(response, status, value, origin) {
  if (response.destroyed || response.writableEnded) return;
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store, max-age=0",
    "pragma": "no-cache",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    ...(origin ? { "access-control-allow-origin": origin, "vary": "Origin", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "POST, OPTIONS" } : {})
  });
  response.end(JSON.stringify(value));
}

function readRequestBody(request, timeoutMs) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const cleanup = () => { clearTimeout(timer); request.off("data", data); request.off("end", end); request.off("error", error); request.off("aborted", aborted); };
    const fail = (statusCode) => { cleanup(); request.resume(); reject(Object.assign(new Error("Invalid request body"), { statusCode })); };
    const data = (chunk) => {
      size += chunk.byteLength;
      if (size > REQUEST_LIMIT_BYTES) return fail(413);
      chunks.push(chunk);
    };
    const end = () => {
      cleanup();
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(Object.assign(new Error("Invalid JSON"), { statusCode: 400 })); }
    };
    const error = () => fail(400);
    const aborted = () => fail(400);
    const timer = setTimeout(() => fail(408), timeoutMs);
    request.on("data", data);
    request.once("end", end);
    request.once("error", error);
    request.once("aborted", aborted);
  });
}

async function readResponseBody(response, signal) {
  if (Number(response.headers.get("content-length")) > RESPONSE_LIMIT_BYTES) throw new Error("Provider response too large");
  const reader = response.body?.getReader();
  if (!reader) return {};
  const chunks = [];
  let size = 0;
  const cancel = () => { void reader.cancel().catch(() => undefined); };
  signal?.addEventListener("abort", cancel, { once: true });
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > RESPONSE_LIMIT_BYTES) { await reader.cancel(); throw new Error("Provider response too large"); }
      chunks.push(Buffer.from(value));
    }
  } finally { signal?.removeEventListener("abort", cancel); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new Error("Invalid provider response"); }
}

function containsSensitiveText(state) {
  const text = `${state.subject_excerpt ?? ""} ${state.body_excerpt ?? ""}`;
  return /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(text)
    || /\b(?:bearer\s+|eyJ[a-zA-Z0-9_-]{12,}\.|password\s*[:=]|senha\s*[:=])/i.test(text)
    || /https?:\/\//i.test(text);
}

export function consumeRateQuota(rateWindows, subject, at, requestsPerMinute) {
  const rate = rateWindows.get(subject);
  if (rate && at - rate.start < RATE_WINDOW_MS) {
    if (rate.count >= requestsPerMinute) return "rate_limited";
    rate.count += 1;
    return "allowed";
  }

  if (!rate && rateWindows.size >= RATE_SUBJECT_LIMIT) {
    for (const [key, value] of rateWindows) if (at - value.start >= RATE_WINDOW_MS) rateWindows.delete(key);
    if (rateWindows.size >= RATE_SUBJECT_LIMIT) return "capacity_unavailable";
  }

  rateWindows.set(subject, { start: at, count: 1 });
  return "allowed";
}

export function createGatewayServer(config, { fetchImpl = fetch, jwks = createRemoteJWKSet(config.jwksUrl), now = Date.now, upstreamTimeoutMs = 4600, bodyTimeoutMs = 5000 } = {}) {
  const rateWindows = new Map();
  let activeUpstream = 0;
  const server = createServer(async (request, response) => {
    const origin = request.headers.origin;
    if (request.method === "OPTIONS") {
      if (!origin || !config.allowedOrigins.has(origin)) return writeJson(response, 403, { error: "origin_not_allowed" });
      response.writeHead(204, { "access-control-allow-origin": origin, "vary": "Origin", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "POST, OPTIONS", "access-control-max-age": "300" });
      return response.end();
    }
    if (request.url === "/health" && request.method === "GET") return writeJson(response, 200, { status: "ok", service: "aegis-gateway" });
    if (request.method !== "POST" || request.url !== "/v1/systemone") return writeJson(response, 404, { error: "not_found" });
    if (!origin || !config.allowedOrigins.has(origin)) return writeJson(response, 403, { error: "origin_not_allowed" });
    if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] ?? "")) return writeJson(response, 415, { error: "unsupported_media_type" }, origin);

    let subject;
    try {
      const auth = String(request.headers.authorization ?? "");
      const match = auth.match(/^Bearer ([A-Za-z0-9._~-]{20,4096})$/);
      if (!match) return writeJson(response, 401, { error: "unauthorized" }, origin);
      const verified = await jwtVerify(match[1], jwks, { issuer: config.issuer, audience: config.audience, algorithms: ["RS256", "ES256"], requiredClaims: ["exp", "sub"] });
      const tenant = verified.payload.tid ?? verified.payload.tenant_id ?? verified.payload.org_id;
      subject = verified.payload.sub;
      const scopes = String(verified.payload.scope ?? verified.payload.scp ?? "").split(/\s+/);
      if (typeof subject !== "string" || subject.length < 1 || subject.length > 180 || !config.allowedTenants.has(tenant) || !scopes.includes(config.requiredScope)) {
        return writeJson(response, 403, { error: "forbidden" }, origin);
      }
      subject = JSON.stringify([tenant, subject]);
    } catch {
      return writeJson(response, 401, { error: "unauthorized" }, origin);
    }

    const quota = consumeRateQuota(rateWindows, subject, now(), config.requestsPerMinute);
    if (quota === "rate_limited") return writeJson(response, 429, { error: "rate_limited" }, origin);
    if (quota === "capacity_unavailable") return writeJson(response, 503, { error: "capacity_unavailable" }, origin);

    let body;
    try { body = await readRequestBody(request, bodyTimeoutMs); }
    catch (error) { return writeJson(response, error.statusCode ?? 400, { error: "invalid_request" }, origin); }
    const parsedState = bodySchema.safeParse(body?.state);
    if (!parsedState.success || containsSensitiveText(parsedState.data ?? {})) return writeJson(response, 422, { error: "invalid_state" }, origin);
    if (activeUpstream >= (config.maxUpstreamConcurrency ?? 16)) return writeJson(response, 503, { error: "capacity_unavailable" }, origin);
    activeUpstream += 1;

    const controller = new AbortController();
    const close = () => { if (!response.writableEnded) controller.abort(); };
    response.on("close", close);
    let rejectAbort;
    const aborted = new Promise((_resolve, reject) => { rejectAbort = reject; });
    const abort = () => rejectAbort(new DOMException("Gateway inference cancelled", "AbortError"));
    controller.signal.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(() => controller.abort(), upstreamTimeoutMs);
    let upstream;
    try {
      const payload = JSON.stringify({ state: parsedState.data, model: config.typesafeModel, questions: buildJevQuestions() });
      for (let attempt = 0; attempt < 2; attempt += 1) {
        upstream = await Promise.race([fetchImpl(TYPE_SAFE_ENDPOINT, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${config.typesafeApiKey}` },
          body: payload,
          signal: controller.signal,
          cache: "no-store",
          credentials: "omit",
          referrerPolicy: "no-referrer"
        }), aborted]);
        if (![429, 529, 502, 503, 504].includes(upstream.status) || attempt === 1 || controller.signal.aborted) break;
        await upstream.body?.cancel();
        await Promise.race([new Promise((resolve) => setTimeout(resolve, Math.min(400, 150 * (2 ** attempt)))), aborted]);
      }
      if (!upstream.ok) {
        await upstream.body?.cancel().catch(() => {});
        return writeJson(response, upstream.status === 401 || upstream.status === 403 ? 502 : 503, { error: "provider_unavailable" }, origin);
      }
      const data = await Promise.race([readResponseBody(upstream, controller.signal), aborted]);
      const decoded = decodeJevResponse(data);
      if (decoded.status !== "connected") return writeJson(response, 502, { error: "invalid_provider_response" }, origin);
      const questions = buildJevQuestions();
      const answers = Object.fromEntries(Object.entries(decoded.answers).map(([key, value]) => [key, questions[key].type === "noul" ? { type: "noul", noul: value } : { type: questions[key].type, ...value }]));
      return writeJson(response, 200, { model: decoded.model, answers, ...(decoded.usage ? { usage: decoded.usage } : {}) }, origin);
    } catch {
      return writeJson(response, controller.signal.aborted ? 504 : 502, { error: controller.signal.aborted ? "timeout" : "provider_unavailable" }, origin);
    } finally {
      clearTimeout(timeout);
      controller.signal.removeEventListener("abort", abort);
      response.off("close", close);
      activeUpstream -= 1;
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5000;
  server.maxRequestsPerSocket = 100;
  server.maxConnections = 256;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const config = loadConfig();
  createGatewayServer(config).listen(config.port, config.host, () => {
    process.stdout.write(`AEGIS Gateway listening on ${config.host}:${config.port}\n`);
  });
}

export { loadConfig };
