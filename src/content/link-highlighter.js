const originals = new WeakMap();

function clearLink(anchor) {
  const original = originals.get(anchor);
  if (original) {
    if (original.title === null) anchor.removeAttribute("title");
    else anchor.setAttribute("title", original.title);
    if (original.description === null) anchor.removeAttribute("aria-description");
    else anchor.setAttribute("aria-description", original.description);
    originals.delete(anchor);
  }
  anchor.classList.remove("aegis-risk-link");
  anchor.removeAttribute("data-aegis-risk-link");
}

function absoluteHref(value, baseUrl) {
  try { return new URL(value, baseUrl).href; }
  catch { return ""; }
}

export function highlightRiskyLinks(root, observedLinks = [], analyzedLinks = [], { limit = 8, hint = "" } = {}) {
  if (!root?.querySelectorAll) return [];
  const anchors = [...root.querySelectorAll("a[href]")];
  for (const anchor of root.querySelectorAll("[data-aegis-risk-link]")) clearLink(anchor);

  const highlighted = [];
  const maximum = Math.max(0, Math.min(20, Number.isInteger(limit) ? limit : 8));
  const baseUrl = root.ownerDocument?.baseURI ?? globalThis.location?.href ?? "";
  for (let index = 0; index < Math.min(anchors.length, observedLinks.length, analyzedLinks.length) && highlighted.length < maximum; index += 1) {
    const anchor = anchors[index];
    const observed = observedLinks[index];
    const analyzed = analyzedLinks[index];
    if (analyzed?.mismatch !== true || !observed?.href || absoluteHref(anchor.href, baseUrl) !== absoluteHref(observed.href, baseUrl)) continue;

    originals.set(anchor, {
      title: anchor.hasAttribute("title") ? anchor.getAttribute("title") : null,
      description: anchor.hasAttribute("aria-description") ? anchor.getAttribute("aria-description") : null
    });

    anchor.classList.add("aegis-risk-link");
    if (hint) {
      anchor.setAttribute("title", hint);
      anchor.setAttribute("aria-description", `AEGIS: ${hint}`);
    }
    anchor.setAttribute("data-aegis-risk-link", "mismatch");
    highlighted.push(anchor);
  }
  return highlighted;
}

