import jsQR from "jsqr";

const MAX_IMAGES = 12;
const MAX_PIXELS_PER_IMAGE = 4_000_000;
const MAX_TOTAL_PIXELS = 12_000_000;
const MAX_DECODE_SIDE = 512;
const MAX_TOTAL_DECODE_PIXELS = 1_048_576;
const MAX_SCAN_MS = 2_000;
const MAX_URL_LENGTH = 4096;

function safeHttpUrl(value) {
  const raw = String(value ?? "").trim();
  if (!raw || raw.length > MAX_URL_LENGTH) return null;
  try {
    const url = new URL(raw);
    if (!("http:" === url.protocol || "https:" === url.protocol) || url.username || url.password || !url.hostname) return null;
    return url.href;
  } catch { return null; }
}

function drawAndDecode(image, decoder, documentRef, maxDecodePixels) {
  if (!documentRef?.createElement) throw new Error("Canvas is unavailable");
  const width = Number(image?.naturalWidth ?? image?.videoWidth ?? 0);
  const height = Number(image?.naturalHeight ?? image?.videoHeight ?? 0);
  const scale = Math.min(1, MAX_DECODE_SIDE / width, MAX_DECODE_SIDE / height, Math.sqrt(maxDecodePixels / (width * height)));
  const sampleWidth = Math.max(1, Math.floor(width * scale));
  const sampleHeight = Math.max(1, Math.floor(height * scale));
  const canvas = documentRef.createElement("canvas");
  canvas.width = sampleWidth;
  canvas.height = sampleHeight;
  try {
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("Canvas context is unavailable");
    context.drawImage(image, 0, 0, sampleWidth, sampleHeight);
    const pixels = context.getImageData(0, 0, sampleWidth, sampleHeight);
    return decoder(pixels.data, sampleWidth, sampleHeight, { inversionAttempts: "dontInvert" });
  } finally {
    canvas.width = 0;
    canvas.height = 0;
  }
}

export async function scanQrImages(images = [], Detector = globalThis.BarcodeDetector, options = {}) {
  const supplied = images && typeof images.length === "number" ? images : [...(images ?? [])];
  const suppliedCount = Math.max(0, Number(supplied.length) || 0);
  const candidates = Array.from({ length: Math.min(suppliedCount, MAX_IMAGES) }, (_, index) => supplied[index]);
  if (!candidates.length) return { status: "no-images", urls: [], scanned: 0 };

  const decoder = options.decoder ?? jsQR;
  const documentRef = options.document ?? globalThis.document;
  let detector = null;
  try {
    if (typeof Detector === "function") detector = new Detector({ formats: ["qr_code"] });
  } catch { /* use the bundled decoder when the native API is unavailable */ }
  if (!detector && !documentRef?.createElement) return { status: "unavailable", urls: [], scanned: 0 };

  const urls = new Set();
  let scanned = 0;
  let failed = suppliedCount > MAX_IMAGES;
  let pixels = 0;
  let decodePixels = 0;
  const startedAt = Date.now();
  for (const image of candidates) {
    const width = Number(image?.naturalWidth ?? image?.videoWidth ?? 0);
    const height = Number(image?.naturalHeight ?? image?.videoHeight ?? 0);
    const area = width * height;
    if (image?.complete === false || width < 1 || height < 1) { failed = true; continue; }
    if (width < 64 || height < 64) continue;
    if (area > MAX_PIXELS_PER_IMAGE) { failed = true; continue; }
    if (pixels + area > MAX_TOTAL_PIXELS || Date.now() - startedAt >= MAX_SCAN_MS) { failed = true; break; }
    pixels += area;

    let codes = null;
    if (detector) {
      scanned += 1;
      const remaining = MAX_SCAN_MS - (Date.now() - startedAt);
      if (remaining <= 0) { failed = true; break; }
      let timer;
      const timeout = new Promise((resolve) => { timer = setTimeout(() => resolve(null), remaining); });
      try {
        codes = await Promise.race([detector.detect(image), timeout]);
      } catch { /* fall back to the local decoder */ }
      finally { clearTimeout(timer); }
      if (codes === null && Date.now() - startedAt >= MAX_SCAN_MS) { failed = true; break; }
    }

    let detectedQr = false;
    const detectedCodes = Array.isArray(codes) ? codes : [];
    if (detectedCodes.length > 8) failed = true;
    for (const code of detectedCodes.slice(0, 8)) {
      if (code?.format && code.format !== "qr_code") continue;
      detectedQr = true;
      const url = safeHttpUrl(code?.rawValue);
      if (url) urls.add(url);
    }
    if (detectedQr) continue;

    const decodeArea = Math.min(MAX_DECODE_SIDE, width) * Math.min(MAX_DECODE_SIDE, height);
    if (decodePixels + decodeArea > MAX_TOTAL_DECODE_PIXELS || Date.now() - startedAt >= MAX_SCAN_MS) {
      failed = true;
      break;
    }
    decodePixels += decodeArea;
    scanned += 1;
    try {
      // The synchronous fallback cannot be preempted, so each image and the total pixel budget are capped.
      const code = drawAndDecode(image, decoder, documentRef, MAX_TOTAL_DECODE_PIXELS - (decodePixels - decodeArea));
      const url = safeHttpUrl(code?.data);
      if (url) urls.add(url);
    } catch { failed = true; }
  }

  if (Date.now() - startedAt >= MAX_SCAN_MS) failed = true;
  if (!scanned) return { status: "unavailable", urls: [], scanned: 0 };
  return { status: failed || urls.size > 8 ? "partial" : "scanned", urls: [...urls].slice(0, 8), scanned };
}
