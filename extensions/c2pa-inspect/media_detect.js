(function () {
  function isHttpUrl(raw) {
    if (!raw || typeof raw !== "string") return false;
    const s = raw.trim().replace(/^['"]|['"]$/g, "");
    return /^https?:\/\//i.test(s);
  }

  function normalizeUrl(raw) {
    if (!raw || typeof raw !== "string") return null;
    const s = raw.trim().replace(/^['"]|['"]$/g, "");
    return isHttpUrl(s) ? s : null;
  }

  function visibleArea(el) {
    if (!el || typeof el.getBoundingClientRect !== "function") return 0;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return 0;
    return Math.floor(r.width * r.height);
  }

  function detectPrimaryMedia(doc) {
    const MAX_IMGS = 200;
    const MAX_VIDEOS = 50;
    const MAX_BG = 200;

    const imgs = Array.from(doc.images || []).slice(0, MAX_IMGS);
    const imgCandidates = [];
    for (let i = 0; i < imgs.length; i++) {
      const el = imgs[i];
      const url = normalizeUrl(el.currentSrc || el.src || "");
      if (!url) continue;
      const area = visibleArea(el);
      if (area <= 0) continue;
      imgCandidates.push({ url, area, idx: i, kind: "img", reason: "largest_visible_img" });
    }
    imgCandidates.sort((a, b) => (b.area - a.area) || (a.idx - b.idx));
    if (imgCandidates.length > 0) {
      const c = imgCandidates[0];
      return { url: c.url, kind: c.kind, reason: c.reason };
    }

    const videos = Array.from(doc.querySelectorAll("video")).slice(0, MAX_VIDEOS);
    for (let i = 0; i < videos.length; i++) {
      const v = videos[i];
      const poster = normalizeUrl(v.poster || "");
      if (poster) {
        return { url: poster, kind: "video_poster", reason: "video_poster" };
      }
    }

    const og = doc.querySelector('meta[property="og:image"], meta[name="og:image"]');
    const ogUrl = normalizeUrl(og ? og.getAttribute("content") || "" : "");
    if (ogUrl) {
      return { url: ogUrl, kind: "og_image", reason: "open_graph_image" };
    }

    const all = Array.from(doc.querySelectorAll("*")).slice(0, MAX_BG);
    const bgCandidates = [];
    const re = /url\(([^)]+)\)/i;
    for (let i = 0; i < all.length; i++) {
      const el = all[i];
      const style = doc.defaultView.getComputedStyle(el);
      const bg = style && style.backgroundImage ? style.backgroundImage : "";
      const m = bg.match(re);
      if (!m) continue;
      const url = normalizeUrl(m[1] || "");
      if (!url) continue;
      const area = visibleArea(el);
      if (area <= 0) continue;
      bgCandidates.push({ url, area, idx: i });
    }
    bgCandidates.sort((a, b) => (b.area - a.area) || (a.idx - b.idx));
    if (bgCandidates.length > 0) {
      return { url: bgCandidates[0].url, kind: "css_bg", reason: "largest_css_background" };
    }

    const firstVisibleImg = imgs.find((el) => normalizeUrl(el.currentSrc || el.src || "") && visibleArea(el) > 0);
    if (firstVisibleImg) {
      return {
        url: normalizeUrl(firstVisibleImg.currentSrc || firstVisibleImg.src || ""),
        kind: "img",
        reason: "first_visible_img"
      };
    }
    return null;
  }

  self.detectPrimaryMedia = detectPrimaryMedia;
})();

