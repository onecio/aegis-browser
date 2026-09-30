// Contextual words remain available in the panel, but do not paint an inbox row.
export function shouldMarkItem(result) {
  if (["failure", "not-analyzable"].includes(result?.analysisStatus ?? result?.status)) return false;
  if (result?.state === "RED") return true;
  if (result?.state !== "YELLOW") return false;
  const local = (result.findings ?? []).filter((finding) => finding.source !== "jev" && finding.severity > 0);
  if (local.some((finding) => finding.severity >= 4)) return true;
  const categories = new Set(local.map((finding) => finding.category));
  return categories.has("credential") && categories.has("social") ||
    categories.has("spam") && categories.has("social") ||
    local.some((finding) => finding.id === "LINK_DISPLAY_DESTINATION_MISMATCH");
}
