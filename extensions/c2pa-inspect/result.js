const STORE_PREFIX = "c2pa_result_";

function byId(id) {
  return document.getElementById(id);
}

function textOrDash(v) {
  return v === null || v === undefined || v === "" ? "-" : String(v);
}

function renderList(el, items, mapFn) {
  el.innerHTML = "";
  if (!Array.isArray(items) || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = "None";
    el.appendChild(li);
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = mapFn(item);
    el.appendChild(li);
  }
}

function getReqId() {
  const hash = window.location.hash || "";
  const m = hash.match(/id=([^&]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}

function mapErrorMessage(code, message) {
  switch (code) {
    case "too_large":
      return "File too large (limit exceeded).";
    case "timeout":
      return "Timed out while fetching media.";
    case "fetch_failed":
      return "Could not fetch the URL.";
    case "invalid_request":
      return "Invalid request.";
    case "inspect_failed":
      return "Inspector failed to parse this media.";
    case "no_media_detected":
      return "No media detected on this page.";
    default:
      return message || "Unknown error.";
  }
}

function showLoading(show) {
  byId("loadingSection").classList.toggle("hidden", !show);
}

function renderError(payload) {
  showLoading(false);
  byId("subtitle").textContent = "Inspection failed";
  byId("errorSection").classList.remove("hidden");
  byId("reportSection").classList.add("hidden");
  const code = textOrDash(payload?.error?.code);
  byId("errorCode").textContent = code;
  byId("errorMessage").textContent = mapErrorMessage(payload?.error?.code, payload?.error?.message);
  byId("rawJson").textContent = JSON.stringify(payload, null, 2);
}

function renderReport(payload) {
  const report = payload.report || {};
  showLoading(false);
  byId("subtitle").textContent = report?.input?.path || "Inspection result";
  byId("errorSection").classList.add("hidden");
  byId("reportSection").classList.remove("hidden");

  byId("present").textContent = report?.credentials?.present ? "Yes" : "No";
  byId("trusted").textContent = report?.validation?.trusted ? "Yes" : "No";
  byId("trustMode").textContent = textOrDash(report?.validation?.trust_mode);
  byId("state").textContent = textOrDash(report?.validation?.state);
  byId("detectReason").textContent = textOrDash(payload?.source?.reason || payload?.source?.kind);
  byId("signerIssuer").textContent = textOrDash(report?.signer?.issuer);
  byId("signerSubject").textContent = textOrDash(report?.signer?.subject);
  byId("signerOrg").textContent = textOrDash(report?.signer?.organization);

  const warnings = report?.validation?.warnings || [];
  renderList(byId("warnings"), warnings, (w) => String(w));
  renderList(byId("actions"), report?.actions, (a) => {
    const action = a?.action || "unknown";
    const when = a?.when ? ` @ ${a.when}` : "";
    const software = a?.software ? ` (${a.software})` : "";
    return `${action}${when}${software}`;
  });
  renderList(byId("ingredients"), report?.ingredients, (i) => {
    const title = i?.title || "untitled";
    const rel = i?.relationship ? ` [${i.relationship}]` : "";
    return `${title}${rel}`;
  });

  const hasLikely = warnings.some((w) => String(w).startsWith("likely_stripped"));
  const missing = report?.credentials?.present === false;
  byId("missingHint").classList.toggle("hidden", !(missing || hasLikely));
  byId("rawJson").textContent = JSON.stringify(payload, null, 2);
}

function initButtons(payloadRef, reqIdRef) {
  byId("copyJson").addEventListener("click", () => {
    copyToClipboard(JSON.stringify(payloadRef.current || {}, null, 2));
  });
  byId("copySummary").addEventListener("click", () => {
    const summary = payloadRef.current?.summary || "No summary available.";
    copyToClipboard(summary);
  });
  byId("retryBtn").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "retry_inspect", id: reqIdRef.current }, (resp) => {
      if (resp && resp.ok && resp.newId) {
        reqIdRef.current = resp.newId;
        window.location.hash = "id=" + encodeURIComponent(resp.newId);
        showLoading(true);
        byId("errorSection").classList.add("hidden");
      }
    });
  });
}

function loadPayload() {
  const payloadRef = { current: null };
  const reqIdRef = { current: getReqId() };
  initButtons(payloadRef, reqIdRef);
  if (!reqIdRef.current) {
    renderError({ error: { code: "invalid_request", message: "Missing result id." } });
    return;
  }

  const poll = () => {
    const id = reqIdRef.current;
    chrome.storage.session.get(STORE_PREFIX + id, (items) => {
      const payload = items[STORE_PREFIX + id];
      if (!payload) {
        showLoading(true);
        byId("subtitle").textContent = "Inspecting...";
        return;
      }
      payloadRef.current = payload;
      if (payload.loading) {
        showLoading(true);
        byId("subtitle").textContent = "Inspecting...";
        return;
      }
      if (payload.ok) renderReport(payload);
      else renderError(payload);
    });
  };

  showLoading(true);
  poll();
  setInterval(poll, 700);
}

loadPayload();

