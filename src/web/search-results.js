import { selectDynamicWindow } from "./dynamic-window.js";

const ENGINES = Object.freeze({
  google: { hostPattern: /(^|\.)google\.(?:com|[a-z]{2,3})(?:\.[a-z]{2})?$/i, containers: ["#search .MjjYud", "#search .g", "#tads [data-text-ad]", "#tads .uEierd", "#bottomads [data-text-ad]", "#bottomads .uEierd"], title: "h3, [role='heading']" },
  bing: { hosts: ["bing.com", "www.bing.com"], containers: ["#b_results > li.b_algo", "#b_results .b_ad li", "#b_results > li.b_ad", "#b_top .b_ad li"], title: "h2, h3" }
});

export function detectSearchEngine(hostname = location.hostname) {
  const host = String(hostname).toLowerCase();
  for (const [id, engine] of Object.entries(ENGINES)) {
    if (engine.hostPattern?.test(host) || engine.hosts?.some((candidate) => host === candidate || host.endsWith(`.${candidate}`))) return id;
  }
  return null;
}

export function resolveSearchDestination(href, engineId, baseUrl) {
  let url;
  try { url = new URL(href, baseUrl); } catch { return null; }
  if (!/^https?:$/.test(url.protocol) || url.username || url.password) return null;
  let resolution = "direct";
  for (let depth = 0; depth < 2; depth += 1) {
    if (detectSearchEngine(url.hostname) !== engineId) break;
    let encoded = null;
    if (engineId === "google" && ["/url", "/aclk", "/pagead/aclk"].includes(url.pathname)) encoded = url.searchParams.get("adurl") || url.searchParams.get("url") || url.searchParams.get("q");
    if (engineId === "bing" && url.pathname.startsWith("/ck/")) {
      encoded = url.searchParams.get("u");
      if (encoded?.startsWith("a1")) {
        try { encoded = atob(encoded.slice(2).replace(/-/g, "+").replace(/_/g, "/")); } catch { encoded = null; }
      }
    }
    if (!encoded) return { href: url.href, wrapperResolution: "unresolved" };
    let destination;
    try { destination = new URL(encoded); } catch { return { href: url.href, wrapperResolution: "unresolved" }; }
    if (!/^https?:$/.test(destination.protocol) || destination.username || destination.password) return { href: url.href, wrapperResolution: "unresolved" };
    url = destination;
    resolution = "decoded";
  }
  return { href: url.href, wrapperResolution: detectSearchEngine(url.hostname) === engineId ? "unresolved" : resolution };
}

export function extractSearchResults(document, engineId = detectSearchEngine(document.location?.hostname)) {
  const engine = ENGINES[engineId];
  if (!engine) return [];
  const matched = [...new Set(engine.containers.flatMap((selector) => [...document.querySelectorAll(selector)]))];
  // A provider wrapper may contain multiple result cards. Analyze the smallest individual card.
  const candidateSet = new Set(matched);
  const wrappers = new Set();
  for (const element of matched) {
    for (let parent = element.parentElement; parent; parent = parent.parentElement) if (candidateSet.has(parent)) wrappers.add(parent);
  }
  const containers = matched.filter((element) => !wrappers.has(element));
  const results = [];
  const seen = new Set();
  for (const element of selectDynamicWindow(containers, 20)) {
    if (results.length >= 20) break;
    const titleNode = element.querySelector(engine.title);
    const anchor = titleNode?.closest("a[href]") ?? titleNode?.querySelector("a[href]") ?? element.querySelector("a[href]");
    if (!titleNode || !anchor?.href || seen.has(anchor)) continue;
    const destination = resolveSearchDestination(anchor.href, engineId, document.baseURI);
    if (!destination) continue;
    seen.add(anchor);
    const title = String(titleNode?.innerText ?? titleNode?.textContent ?? anchor.innerText ?? "").trim().slice(0, 180);
    const cleanElement = element.cloneNode(true);
    for (const label of cleanElement.querySelectorAll("[data-aegis-search-label], [hidden], [aria-hidden='true'], script, style")) label.remove();
    const snippet = String(cleanElement.textContent ?? "").replace(title, "").trim().slice(0, 700);
    results.push({ element, anchor, index: results.length, payload: { href: destination.href.slice(0, 2048), title, snippet, wrapperResolution: destination.wrapperResolution, sponsored: Boolean(element.closest("#tads, #bottomads, .b_ad, [data-text-ad]")) } });
  }
  return results;
}
