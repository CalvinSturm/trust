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

function renderError(payload) {
  byId("subtitle").textContent = "Inspection failed";
  byId("errorSection").classList.remove("hidden");
  byId("reportSection").classList.add("hidden");
  byId("errorCode").textContent = textOrDash(payload?.error?.code);
  byId("errorMessage").textContent = textOrDash(payload?.error?.message);
  byId("rawJson").textContent = JSON.stringify(payload, null, 2);
}

function renderReport(payload) {
  const report = payload.report || {};
  byId("subtitle").textContent = report?.input?.path || "Inspection result";
  byId("errorSection").classList.add("hidden");
  byId("reportSection").classList.remove("hidden");

  byId("present").textContent = report?.credentials?.present ? "Yes" : "No";
  byId("trusted").textContent = report?.validation?.trusted ? "Yes" : "No";
  byId("trustMode").textContent = textOrDash(report?.validation?.trust_mode);
  byId("state").textContent = textOrDash(report?.validation?.state);
  byId("signerIssuer").textContent = textOrDash(report?.signer?.issuer);
  byId("signerSubject").textContent = textOrDash(report?.signer?.subject);
  byId("signerOrg").textContent = textOrDash(report?.signer?.organization);

  renderList(byId("warnings"), report?.validation?.warnings, (w) => String(w));
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

  byId("rawJson").textContent = JSON.stringify(payload, null, 2);
}

function initButtons(payload) {
  byId("copyJson").addEventListener("click", () => {
    copyToClipboard(JSON.stringify(payload, null, 2));
  });
  byId("copySummary").addEventListener("click", () => {
    const summary = payload?.summary || "No summary available.";
    copyToClipboard(summary);
  });
}

function loadPayload() {
  const reqId = getReqId();
  if (!reqId) {
    renderError({ error: { code: "invalid_request", message: "Missing result id." } });
    initButtons({});
    return;
  }
  chrome.storage.session.get(STORE_PREFIX + reqId, (items) => {
    const payload = items[STORE_PREFIX + reqId];
    if (!payload) {
      renderError({ error: { code: "not_found", message: "Result not found in session storage." } });
      initButtons({});
      return;
    }
    if (payload.ok) {
      renderReport(payload);
    } else {
      renderError(payload);
    }
    initButtons(payload);
  });
}

loadPayload();

