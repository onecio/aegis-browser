export const FINDING_MESSAGE_KEYS = Object.freeze({
  CREDENTIAL_REQUEST: "signalCredentialRequest",
  FINANCIAL_ACTION: "signalFinancialAction",
  PAYMENT_DETAILS_CHANGE: "signalPaymentDetailsChange",
  PROCESS_BYPASS_REQUEST: "signalProcessBypass",
  URGENCY_LANGUAGE: "signalUrgency",
  THREAT_OR_FEAR_LANGUAGE: "signalThreatFear",
  ATTACHMENT_DOUBLE_EXTENSION: "signalAttachmentDoubleExtension",
  SPAM_PROMOTION: "signalSpamPromotion",
  POSSIBLE_BITB: "signalPossibleBitb",
  CLICKFIX_EXECUTION_INSTRUCTIONS: "signalClickFixInstructions",
  CREDENTIAL_FORM_PRESENT: "signalCredentialFormPresent",
  CREDENTIAL_FORM_CROSS_DOMAIN: "signalCredentialFormCrossDomain",
  CREDENTIAL_FORM_INSECURE_TRANSPORT: "signalCredentialFormInsecureTransport",
  REPLY_TO_DOMAIN_MISMATCH: "signalReplyToMismatch",
  QR_CODE_URL_DECODED: "signalQrDecoded",
  QR_SCAN_INCOMPLETE: "signalQrIncomplete",
  INVALID_OR_UNSUPPORTED_LINK: "signalInvalidUnsupportedLink",
  URL_CONTAINS_CREDENTIALS: "signalUrlCredentials",
  URL_SENSITIVE_PARAMETER: "signalSensitiveUrlParameters",
  URL_REDIRECT_PARAMETER: "signalRedirectUrlParameter",
  OBSCURED_DESTINATION: "signalObscuredDestination",
  ORGANIZATION_LINK_DOMAIN_RECOGNIZED: "signalOrganizationLinkDomain",
  LINK_DISPLAY_DESTINATION_MISMATCH: "signalLinkDisplayMismatch",
  LINK_USES_HTTP: "signalHttpLink",
  IDN_PUNYCODE_DOMAIN: "signalPunycodeDomain",
  POSSIBLE_MIXED_SCRIPT_DOMAIN: "signalMixedScriptsDomain",
  POSSIBLE_LOOKALIKE_DOMAIN: "signalLookalikeDomain",
  BRAND_DOMAIN_CONFLICT: "signalBrandDomainConflict",
  ORGANIZATION_DOMAIN_RECOGNIZED: "signalOrganizationDomain",
  JEV_REVIEW_SUGGESTED: "signalJevReviewSuggested"
});

export const LOCATION_MESSAGE_KEYS = Object.freeze({
  sender: "locationSender",
  message: "locationMessage",
  domain: "locationDomain",
  link: "locationLink",
  url: "locationUrl",
  form: "locationForm",
  attachment: "locationAttachment",
  page: "locationPage",
  semantic: "locationSemantic"
});

export function localizeFindingDetail(finding, t) {
  const key = FINDING_MESSAGE_KEYS[finding?.id];
  if (!key || typeof t !== "function") return finding?.detail ?? "";
  const evidence = finding.evidence ?? {};
  let messageKey = key;
  let substitutions;

  if (finding.id === "LINK_USES_HTTP" && finding.category === "context") messageKey = "signalOrganizationHttpLink";
  if (finding.id === "POSSIBLE_LOOKALIKE_DOMAIN") substitutions = [evidence.brand ?? ""];
  if (finding.id === "BRAND_DOMAIN_CONFLICT") substitutions = [evidence.brand ?? ""];
  if (finding.id === "ORGANIZATION_DOMAIN_RECOGNIZED") substitutions = [(evidence.kinds ?? []).join(", ")];

  return t(messageKey, substitutions) || finding.detail || "";
}

export function localizeFindingLocation(finding, t) {
  const key = LOCATION_MESSAGE_KEYS[finding?.location];
  return key ? t(key) || finding.location : finding?.location ?? "";
}
