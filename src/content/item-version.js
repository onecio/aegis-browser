// Bind a result to the current DOM identity, route and extracted payload.
export function isCurrentItem(item, currentItems, route, currentRoute) {
  if (route !== currentRoute || !item.element?.isConnected) return false;
  const current = currentItems.find((candidate) => candidate.element === item.element);
  return Boolean(current && JSON.stringify(current.payload) === JSON.stringify(item.payload));
}

export function itemEvidenceKey(item, route, identity, findings = []) {
  return JSON.stringify([route, identity, item.payload, findings.map(({ id, severity, evidence }) => ({ id, severity, evidence }))]);
}
