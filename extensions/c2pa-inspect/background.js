const HOST_NAME = "dev.calvinbuild.c2pa_inspect";
const MENU_MEDIA = "c2pa-inspect-media";
const MENU_PAGE = "c2pa-inspect-page";
const STORE_PREFIX = "c2pa_result_";
const STORE_REQ_PREFIX = "c2pa_request_";
const STORE_LAST_REQUEST = "c2pa_last_request_id";

const DEFAULT_SETTINGS = {
  trust_mode: "default",
  max_download_bytes: 50000000,
  timeout_ms: 5000
};

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

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULT_SETTINGS, (syncVal) => {
      if (chrome.runtime.lastError) {
        chrome.storage.local.get(DEFAULT_SETTINGS, (localVal) => resolve(localVal || DEFAULT_SETTINGS));
        return;
      }
      resolve(syncVal || DEFAULT_SETTINGS);
    });
  });
}

function saveSession(items) {
  return new Promise((resolve) => chrome.storage.session.set(items, () => resolve()));
}

function getSession(keys) {
  return new Promise((resolve) => chrome.storage.session.get(keys, (items) => resolve(items || {})));
}

function trimForSession(payload) {
  try {
    const s = JSON.stringify(payload);
    if (s.length <= 900000) return payload;
  } catch (_) {
    return payload;
  }
  const clone = JSON.parse(JSON.stringify(payload));
  if (clone.report) {
    clone.report = {
      tool: clone.report.tool,
      input: clone.report.input,
      credentials: clone.report.credentials,
      validation: clone.report.validation,
      note: "response truncated in session storage"
    };
  }
  return clone;
}

function openResultTab(reqId) {
  chrome.tabs.create({ url: chrome.runtime.getURL("result.html") + "#id=" + reqId });
}

function createPending(reqId, source) {
  return {
    id: reqId,
    v: 1,
    ok: false,
    loading: true,
    source,
    error: null
  };
}

function mapNativeError(lastErrorMsg, reqId) {
  return {
    id: reqId,
    v: 1,
    ok: false,
    error: {
      code: "native_host_error",
      message: lastErrorMsg || "Native host unavailable."
    }
  };
}

async function executeNativeInspect(reqId, request, sourceInfo) {
  await saveSession({
    [STORE_REQ_PREFIX + reqId]: request,
    [STORE_LAST_REQUEST]: reqId,
    [STORE_PREFIX + reqId]: createPending(reqId, sourceInfo)
  });
  openResultTab(reqId);
  chrome.runtime.sendNativeMessage(HOST_NAME, request, async (resp) => {
    let payload = resp;
    if (chrome.runtime.lastError) {
      payload = mapNativeError(chrome.runtime.lastError.message, reqId);
    }
    if (!payload) {
      payload = mapNativeError("Empty native host response.", reqId);
    }
    payload.id = reqId;
    payload.v = 1;
    payload.loading = false;
    payload.source = sourceInfo;
    if (payload.ok && payload.report) {
      payload.summary = summarizeReport(payload.report);
    }
    await saveSession({ [STORE_PREFIX + reqId]: trimForSession(payload) });
  });
}

async function inspectUrl(url, sourceInfo, pageUrl) {
  const reqId = mkReqId();
  const s = await getSettings();
  const request = {
    id: reqId,
    v: 1,
    trust: s.trust_mode === "off" ? "off" : "default",
    source: {
      url,
      page_url: pageUrl || undefined,
      detect_reason: sourceInfo?.reason || undefined
    },
    caps: {
      max_download_bytes: clamp(Number(s.max_download_bytes || 50000000), 1000000, 200000000),
      timeout_ms: clamp(Number(s.timeout_ms || 5000), 1000, 30000)
    }
  };
  await executeNativeInspect(reqId, request, sourceInfo);
}

async function detectFromPage(tabId) {
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      files: ["media_detect.js"]
    });
    if (result === undefined) {
      // no-op
    }
    const detected = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => (typeof detectPrimaryMedia === "function" ? detectPrimaryMedia(document) : null)
    });
    return detected && detected[0] ? detected[0].result : null;
  } catch (_) {
    return null;
  }
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_MEDIA,
    title: "Inspect Content Credentials",
    contexts: ["image", "link", "video"]
  });
  chrome.contextMenus.create({
    id: MENU_PAGE,
    title: "Inspect primary media on this page",
    contexts: ["page"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === MENU_MEDIA) {
    const url = sourceUrlFromInfo(info);
    if (!url) {
      const reqId = mkReqId();
      await saveSession({
        [STORE_PREFIX + reqId]: {
          id: reqId,
          v: 1,
          ok: false,
          loading: false,
          error: {
            code: "invalid_request",
            message: "No supported media URL found for this context menu action."
          }
        }
      });
      openResultTab(reqId);
      return;
    }
    await inspectUrl(url, { kind: "direct", reason: "context_menu_media" }, tab?.url || null);
    return;
  }

  if (info.menuItemId === MENU_PAGE) {
    if (!tab || !tab.id) {
      const reqId = mkReqId();
      await saveSession({
        [STORE_PREFIX + reqId]: {
          id: reqId,
          v: 1,
          ok: false,
          loading: false,
          error: { code: "invalid_request", message: "Active tab not available." }
        }
      });
      openResultTab(reqId);
      return;
    }
    const detected = await detectFromPage(tab.id);
    if (!detected || !detected.url) {
      const reqId = mkReqId();
      await saveSession({
        [STORE_PREFIX + reqId]: {
          id: reqId,
          v: 1,
          ok: false,
          loading: false,
          error: {
            code: "no_media_detected",
            message: "No suitable primary media was detected on this page."
          }
        }
      });
      openResultTab(reqId);
      return;
    }
    await inspectUrl(detected.url, detected, tab.url || null);
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "retry_inspect") return;
  const reqId = msg.id;
  const reqKey = STORE_REQ_PREFIX + reqId;
  getSession([reqKey]).then(async (items) => {
    const oldReq = items[reqKey];
    if (!oldReq) {
      sendResponse({ ok: false, error: "No cached request for retry." });
      return;
    }
    const newReqId = mkReqId();
    const nextReq = JSON.parse(JSON.stringify(oldReq));
    nextReq.id = newReqId;
    await executeNativeInspect(newReqId, nextReq, oldReq.source || null);
    sendResponse({ ok: true, newId: newReqId });
  });
  return true;
});

