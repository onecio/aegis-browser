const ANALYSIS_PREFIX = "aegis.analysis.";
const LATEST_ANALYSIS_KEY = "aegis.latestTab";
const WEB_PROTOCOLS = new Set(["http:", "https:"]);

export function toSafeWebOrigin(value) {
  try {
    const url = new URL(value);
    return WEB_PROTOCOLS.has(url.protocol) ? url.origin : null;
  } catch { return null; }
}

export function originMatchesPermission(originValue, permissionPattern) {
  const safeOrigin = toSafeWebOrigin(originValue);
  if (!safeOrigin) return false;
  const origin = new URL(safeOrigin);

  const match = String(permissionPattern ?? "").match(/^(\*|https?):\/\/([^/]+)(\/.*)$/);
  if (!match || match[3] !== "/*") return false;
  const [, scheme, hostPattern] = match;
  if (scheme !== "*" && origin.protocol !== `${scheme}:`) return false;
  if (hostPattern === "*") return true;
  if (hostPattern.startsWith("*.")) {
    const suffix = hostPattern.slice(2).toLowerCase();
    return origin.hostname.toLowerCase() === suffix || origin.hostname.toLowerCase().endsWith(`.${suffix}`);
  }
  return origin.hostname.toLowerCase() === hostPattern.toLowerCase();
}

export async function clearRevokedJevCredential({ currentSettings, removedOrigins, permissions, storage, secretKeys, disableJev, resetStoredJev }) {
  if (!currentSettings || !Array.isArray(removedOrigins) || !permissions?.contains || !storage?.remove) return false;

  let providerPattern = "";
  let secretKey;
  if (currentSettings.connectionMode === "byok") {
    providerPattern = "https://api.typesafe.ai/*";
    secretKey = secretKeys?.byok;
  } else {
    try {
      const gateway = new URL(currentSettings.gatewayUrl);
      if (gateway.protocol === "https:") providerPattern = `${gateway.origin}/*`;
    } catch { /* a missing gateway origin cannot authorize Jev requests */ }
    secretKey = secretKeys?.gatewayToken;
  }
  if (!providerPattern || !secretKey) return false;

  const providerOrigin = providerPattern.replace(/\/\*$/, "");
  if (!removedOrigins.some((pattern) => originMatchesPermission(providerOrigin, pattern))) return false;

  let stillGranted = false;
  try { stillGranted = await permissions.contains({ origins: [providerPattern] }); } catch { /* fail closed after permission revocation */ }
  if (stillGranted) return false;

  if (currentSettings.jevEnabled && disableJev) {
    try { await disableJev(); } catch { /* credential cleanup must continue if settings persistence fails */ }
  }
  await storage.remove([secretKey, "aegis.jevCircuit"]);
  if (resetStoredJev) await resetStoredJev("off");
  return true;
}

export async function clearRevokedSessionAnalyses({ storage, origins }) {
  if (!storage?.get || !storage?.remove || !Array.isArray(origins) || origins.length === 0) return [];
  const session = await storage.get(null);
  const analysisKeys = Object.keys(session ?? {}).filter((key) => key.startsWith(ANALYSIS_PREFIX));
  const removedKeys = analysisKeys.filter((key) => {
    const sourceOrigin = session[key]?.sourceOrigin;
    return !sourceOrigin || origins.some((pattern) => originMatchesPermission(sourceOrigin, pattern));
  });

  const latestKey = Number.isInteger(session?.[LATEST_ANALYSIS_KEY])
    ? `${ANALYSIS_PREFIX}${session[LATEST_ANALYSIS_KEY]}`
    : "";
  if (latestKey && removedKeys.includes(latestKey)) removedKeys.push(LATEST_ANALYSIS_KEY);
  if (removedKeys.length) await storage.remove(removedKeys);
  return removedKeys;
}

export async function clearRevokedOriginState({ removedOrigins, storage, permissions, secretKeys, readSettings, clearPatterns, disableJev, resetStoredJev }) {
  if (!Array.isArray(removedOrigins) || removedOrigins.length === 0) return false;

  try {
    await clearRevokedSessionAnalyses({ storage, origins: removedOrigins });
  } catch {
    try {
      const session = await storage?.get?.(null);
      const analysisKeys = Object.keys(session ?? {}).filter((key) => key.startsWith(ANALYSIS_PREFIX));
      await storage?.remove?.([...analysisKeys, LATEST_ANALYSIS_KEY]);
    } catch { /* continue to credential revocation if analysis cleanup is unavailable */ }
  }

  try { await clearPatterns?.(); } catch { /* campaign cleanup must not prevent credential revocation */ }

  try {
    const currentSettings = await readSettings?.();
    return await clearRevokedJevCredential({
      currentSettings,
      removedOrigins,
      permissions,
      storage,
      secretKeys,
      disableJev,
      resetStoredJev
    });
  } catch { return false; }
}
