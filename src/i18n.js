const localizedAttributes = ["aria-label", "placeholder", "title"];

export function createI18n(api) {
  if (typeof api?.getMessage !== "function") throw new TypeError("A Chrome i18n API is required.");

  const t = (key, substitutions) => api.getMessage(key, substitutions);

  function localizeDocument(documentRef) {
    if (!documentRef?.documentElement || typeof documentRef.querySelectorAll !== "function") return;
    documentRef.documentElement.lang = t("uiLanguage") || "pt-BR";

    for (const element of documentRef.querySelectorAll("[data-i18n]")) {
      const key = element.getAttribute("data-i18n");
      const value = key ? t(key) : "";
      if (value) element.textContent = value;
    }

    for (const attribute of localizedAttributes) {
      const dataAttribute = `data-i18n-${attribute}`;
      for (const element of documentRef.querySelectorAll(`[${dataAttribute}]`)) {
        const key = element.getAttribute(dataAttribute);
        const value = key ? t(key) : "";
        if (value) element.setAttribute(attribute, value);
      }
    }
  }

  return { t, localizeDocument };
}
