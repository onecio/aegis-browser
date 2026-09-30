export function selectDynamicWindow(elements, limit = 20, viewportHeight = globalThis.innerHeight ?? 0) {
  const capacity = Math.max(1, Math.min(40, Number(limit) || 20));
  const candidates = [...elements].filter((element) => !element.closest?.("[hidden], [aria-hidden='true'], [inert]"));
  const height = Math.max(0, Number(viewportHeight) || 0);
  const measured = candidates.map((element, index) => ({ element, index, rect: element.getBoundingClientRect?.() }));
  const visible = measured.filter(({ rect }) => rect && rect.height > 0 && rect.width > 0 && rect.bottom >= -240 && rect.top <= height + 480);
  if (visible.length) {
    // Prioritize the actual viewport before overscan; return the selected items in DOM order.
    return visible.sort((a, b) => {
      const distance = ({ rect }) => rect.bottom < 0 ? -rect.bottom : rect.top > height ? rect.top - height : 0;
      return distance(a) - distance(b) || a.index - b.index;
    }).slice(0, capacity).sort((a, b) => a.index - b.index).map(({ element }) => element);
  }
  // Detached fixture documents have no layout. A live document with no visible items has nothing to scan.
  if (candidates.some((element) => element.ownerDocument?.defaultView)) return [];
  return candidates.slice(0, capacity);
}
