const URL_TEXT = /^https?:\/\/(?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,}(?::\d+)?(?:\/[^\s]*)?$/iu;
const WINDOW_CONTROL = /^(?:close|dismiss|minimi[sz]e|maximi[sz]e|restore)$/i;
const WINDOW_SYMBOL = /^(?:[-–_]|□|▢|▣|×|✕|x)$/i;

function isVisible(element) {
  if (!element || element.hidden) return false;
  const rect = element.getBoundingClientRect?.();
  if (rect && (rect.width < 1 || rect.height < 1)) return false;
  const view = element.ownerDocument?.defaultView;
  const style = view?.getComputedStyle?.(element);
  return style?.display !== "none" && style?.visibility !== "hidden";
}

function hasFakeAddressBar(candidate) {
  const elements = candidate.querySelectorAll("div,span,header,nav,[role='toolbar']");
  for (const element of [...elements].slice(0, 250)) {
    if (element.querySelector("input,textarea,a[href]") || !isVisible(element)) continue;
    const text = String(element.innerText ?? element.textContent ?? "").trim();
    if (text.length <= 240 && URL_TEXT.test(text)) return true;
  }
  return false;
}

function countWindowControls(candidate) {
  const controls = candidate.querySelectorAll("button,[role='button']");
  const cues = new Set();
  for (const control of [...controls].slice(0, 80)) {
    if (!isVisible(control)) continue;
    const label = String(control.getAttribute("aria-label") ?? control.getAttribute("title") ?? control.textContent ?? "").trim();
    if (WINDOW_CONTROL.test(label) || WINDOW_SYMBOL.test(label)) cues.add(label.toLowerCase());
  }
  return cues.size;
}

function hasAuthenticationSurface(candidate) {
  if (candidate.querySelector("input[type='password'],input[type='email'],iframe")) return true;
  const text = String(candidate.innerText ?? candidate.textContent ?? "").slice(0, 1200);
  return /\b(sign[ -]?in|log[ -]?in|oauth|authorize|account)\b/i.test(text) && Boolean(candidate.querySelector("form"));
}

export function classifyBitBStructure(structure = {}) {
  return Boolean(
    structure.dialog && structure.positionedOverlay && structure.fakeAddressBar &&
    Number(structure.windowControls) >= 2 && structure.authenticationSurface
  );
}

function hasPositionedOverlay(candidate, document) {
  try {
    const style = document.defaultView?.getComputedStyle(candidate);
    const rect = candidate.getBoundingClientRect();
    return ["fixed", "absolute"].includes(style?.position) && rect.width >= 280 && rect.height >= 150;
  } catch { return false; }
}

export function inspectBitBStructure(document) {
  const selector = "[role='dialog'],[aria-modal='true'],[class*='modal' i],[class*='popup' i],[class*='dialog' i],[class*='browser-window' i],[style*='position:fixed' i],[style*='position: fixed' i]";
  const candidates = [...document.querySelectorAll(selector)].slice(0, 40);
  for (const candidate of candidates) {
    if (!isVisible(candidate)) continue;
    const positionedOverlay = hasPositionedOverlay(candidate, document);
    const fakeAddressBar = hasFakeAddressBar(candidate);
    const windowControls = countWindowControls(candidate);
    const roleDialog = candidate.getAttribute("role") === "dialog" || candidate.getAttribute("aria-modal") === "true";
    const namedDialog = /modal|popup|dialog|browser-window/i.test(`${candidate.className ?? ""} ${candidate.id ?? ""} ${candidate.getAttribute("aria-label") ?? ""}`);
    const structuralDialog = positionedOverlay && fakeAddressBar && windowControls >= 2;
    const structure = { dialog: roleDialog || namedDialog || structuralDialog, positionedOverlay, fakeAddressBar, windowControls, authenticationSurface: hasAuthenticationSurface(candidate) };
    if (classifyBitBStructure(structure)) return structure;
  }
  return { dialog: false, positionedOverlay: false, fakeAddressBar: false, windowControls: 0, authenticationSurface: false };
}
