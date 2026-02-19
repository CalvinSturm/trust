const DEFAULT_SETTINGS = {
  trust_mode: "default",
  max_download_bytes: 50000000,
  timeout_ms: 5000
};

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function loadSettings(cb) {
  chrome.storage.sync.get(DEFAULT_SETTINGS, (syncVal) => {
    if (chrome.runtime.lastError) {
      chrome.storage.local.get(DEFAULT_SETTINGS, (localVal) => cb(localVal || DEFAULT_SETTINGS));
      return;
    }
    cb(syncVal || DEFAULT_SETTINGS);
  });
}

function saveSettings(settings, cb) {
  chrome.storage.sync.set(settings, () => {
    if (chrome.runtime.lastError) {
      chrome.storage.local.set(settings, () => cb());
      return;
    }
    cb();
  });
}

function fillForm(s) {
  document.getElementById("trustMode").value = s.trust_mode;
  document.getElementById("maxDownloadBytes").value = s.max_download_bytes;
  document.getElementById("timeoutMs").value = s.timeout_ms;
}

function status(msg) {
  const el = document.getElementById("status");
  el.textContent = msg;
  setTimeout(() => {
    if (el.textContent === msg) el.textContent = "";
  }, 1500);
}

document.getElementById("settingsForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const trust_mode = document.getElementById("trustMode").value === "off" ? "off" : "default";
  const max_download_bytes = clamp(
    Number(document.getElementById("maxDownloadBytes").value || DEFAULT_SETTINGS.max_download_bytes),
    1000000,
    200000000
  );
  const timeout_ms = clamp(
    Number(document.getElementById("timeoutMs").value || DEFAULT_SETTINGS.timeout_ms),
    1000,
    30000
  );
  const next = { trust_mode, max_download_bytes, timeout_ms };
  saveSettings(next, () => status("Saved."));
});

document.getElementById("resetBtn").addEventListener("click", () => {
  fillForm(DEFAULT_SETTINGS);
  saveSettings(DEFAULT_SETTINGS, () => status("Reset to defaults."));
});

loadSettings(fillForm);

