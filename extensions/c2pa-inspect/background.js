const HOST_NAME = "dev.calvinbuild.c2pa_inspect";
const MENU_ID = "c2pa-inspect";
const STORE_PREFIX = "c2pa_result_";

function mkReqId() {
  return "req_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
}

function sourceUrlFromInfo(info) {
  if (info.srcUrl) return info.srcUrl;
  if (info.linkUrl) return info.linkUrl;
  return null;
}

function summarizeReport(report) {
  const present = report?.credentials?.present ? "yes" : "no";
  const trusted = report?.validation?.trusted ? "yes" : "no";
  const trustMode = report?.validation?.trust_mode || "off";
  const warnings = Array.isArray(report?.validation?.warnings)
    ? report.validation.warnings.join(", ")
    : "";
  return `Content Credentials present: ${present}\nTrusted: ${trusted}\nTrust mode: ${trustMode}\nWarnings: ${warnings}`;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: "Inspect Content Credentials",
    contexts: ["image", "link", "video"]
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== MENU_ID) return;
  const url = sourceUrlFromInfo(info);
  const reqId = mkReqId();
  const req = {
    id: reqId,
    v: 1,
    trust: "off",
    source: url ? { url } : { path: "" },
    caps: {
      max_download_bytes: 50000000,
      timeout_ms: 5000
    }
  };

  if (!url) {
    const payload = {
      id: reqId,
      ok: false,
      error: {
        code: "invalid_request",
        message: "No supported media URL found for this context menu action."
      }
    };
    chrome.storage.session.set({ [STORE_PREFIX + reqId]: payload }, () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("result.html") + "#id=" + reqId });
    });
    return;
  }

  chrome.runtime.sendNativeMessage(HOST_NAME, req, (resp) => {
    let payload = resp;
    if (chrome.runtime.lastError) {
      payload = {
        id: reqId,
        ok: false,
        error: {
          code: "native_host_error",
          message: chrome.runtime.lastError.message || "Native host unavailable."
        }
      };
    }
    if (payload && payload.ok && payload.report) {
      payload.summary = summarizeReport(payload.report);
    }
    chrome.storage.session.set({ [STORE_PREFIX + reqId]: payload }, () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("result.html") + "#id=" + reqId });
    });
  });
});

