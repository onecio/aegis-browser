import test from "node:test";
import assert from "node:assert/strict";
import { isTrustedUiSender, UI_ONLY_MESSAGES } from "../src/background/message-trust.js";

test("only extension UI documents can configure credentials and permissions", () => {
  const id = "abcdefghijklmnop";
  assert.equal(isTrustedUiSender({ id, url: `chrome-extension://${id}/options.html` }, id), true);
  assert.equal(isTrustedUiSender({ id, url: "https://mail.google.com/options.html" }, id), false);
  assert.equal(isTrustedUiSender({ id, url: `chrome-extension://${id}/content.js` }, id), false);
  assert.equal(isTrustedUiSender({ id: "other", url: `chrome-extension://${id}/options.html` }, id), false);
  assert.equal(isTrustedUiSender({ id, url: "invalid" }, id), false);
  assert.ok(UI_ONLY_MESSAGES.has("AEGIS_SAVE_SECRET"));
  assert.ok(UI_ONLY_MESSAGES.has("AEGIS_SAVE_SETTINGS"));
  assert.ok(UI_ONLY_MESSAGES.has("AEGIS_GET_CURRENT_ANALYSIS"));
});
