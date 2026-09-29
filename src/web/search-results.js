const ENGINES = Object.freeze({
  google: { hostPattern: /(^|\.)google\.(?:com|[a-z]{2,3})(?:\.[a-z]{2})?$/i, containers: ["#search .MjjYud", "#search .g"], title: "h3" },
  bing: { hosts: ["bing.com", "www.bing.com"], containers: ["#b_results > li.b_algo"], title: "h2" }
});

export function detectSearchEngine(hostname = location.hostname) {
  const host = String(hostname).toLowerCase();
  for (const [id, engine] of Object.entries(ENGINES)) {
    if (engine.hostPattern?.test(host) || engine.hosts?.some((candidate) => host === candidate || host.endsWith(`.${candidate}`))) return id;
  }
  return null;
}

export function extractSearchResults(document, engineId = detectSearchEngine(document.location?.hostname)) {
  const engine = ENGINES[engineId];
  if (!engine) return [];
  let containers = [];
  for (const selector of engine.containers) {
    containers = [...document.querySelectorAll(selector)];
    if (containers.length) break;
  }
  const results = [];
  const seen = new Set();
  for (const element of containers) {
    if (results.length >= 20) break;
    const titleNode = element.querySelector(engine.title);
    const anchor = titleNode?.closest("a[href]") ?? element.querySelector("a[href]");
    if (!anchor?.href || seen.has(anchor.href)) continue;
    let url;
    try { url = new URL(anchor.href, document.baseURI); } catch { continue; }
    if (!/^https?:$/.test(url.protocol) || url.hostname === document.location?.hostname) continue;
    seen.add(anchor.href);
    const title = String(titleNode?.innerText ?? titleNode?.textContent ?? anchor.innerText ?? "").trim().slice(0, 180);
    const snippet = String(element.innerText ?? element.textContent ?? "").replace(title, "").trim().slice(0, 700);
    results.push({ element, index: results.length, payload: { href: url.href.slice(0, 2048), title, snippet } });
  }
  return results;
}
