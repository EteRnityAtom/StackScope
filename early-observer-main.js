(() => {
  const slot = "__stackscopeEarlyObserver_v118";
  const previous = window.__stackscopeEarlyObserver_v117;
  if (previous?.active) window.postMessage({ __stackscopeEarlyStop: "v1", channel: previous.config?.channel || null }, location.origin);
  if (window[slot]) return;
  const state = { config: null, active: false, captureEnabled: true, captured: 0, buffer: [], restores: [] };
  window[slot] = state;
  const safeUrl = (raw, transport = "http") => {
    try {
      const url = new URL(raw, location.href);
      const comparable = new URL(url.href);
      if (transport === "websocket") {
        if (comparable.protocol === "ws:") comparable.protocol = "http:";
        else if (comparable.protocol === "wss:") comparable.protocol = "https:";
      }
      if (comparable.origin !== location.origin || url.username || url.password) return null;
      url.hash = "";
      const segments = url.pathname.split("/");
      const sensitive = /^(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|session[_-]?(?:id|token)|secret|password|jwt|api[_-]?key|access[_-]?key|private[_-]?key)$/i;
      for (let index = 1; index < segments.length; index += 1) {
        let previous = "";
        let current = "";
        try { previous = decodeURIComponent(segments[index - 1]); current = decodeURIComponent(segments[index]); } catch (_) { return null; }
        if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?$/.test(current) || (sensitive.test(previous) && /^[A-Za-z0-9_-]{16,}$/.test(current))) segments[index] = "[redacted]";
      }
      url.pathname = segments.join("/");
      const queryNames = [...url.searchParams.keys()];
      if (queryNames.length) {
        url.search = "";
        for (const name of queryNames) url.searchParams.append(name, "[redacted]");
      }
      return url.href;
    } catch (_) { return null; }
  };
  const inScope = path => {
    const config = state.config;
    if (!config || location.origin !== config.origin) return false;
    if (config.mode === "site") return true;
    try {
      const rootPath = new URL(config.modulePath, config.origin).pathname;
      const root = rootPath.endsWith("/") ? rootPath.slice(0, -1) : rootPath;
      const inside = value => value === root || value.startsWith(root + "/");
      let candidate = path;
      for (let depth = 0; depth < 5; depth += 1) {
        if (candidate.includes("\\") || /[\u0000-\u001f]/.test(candidate)) return false;
        const decoded = decodeURIComponent(candidate);
        if (decoded.includes("\\") || /[\u0000-\u001f]/.test(decoded) || !inside(new URL(decoded, config.origin).pathname)) return false;
        if (decoded === candidate) return true;
        candidate = decoded;
      }
      return false;
    } catch (_) { return false; }
  };
  let recentControl = null;
  const controlSelector = 'a[href],button,[role="tab"],[role="button"],[role="menuitem"],[data-step],[data-tab],[aria-controls],[class*="steps-item"],[class*="step-item"],[class*="tab-item"],[class*="step" i][class*="item" i],[class*="step" i][class*="label" i],[class*="step" i][class*="button" i],[class*="tab" i][class*="item" i],[class*="tab" i][class*="label" i],[class*="tab" i][class*="button" i]';
  const captureControlClick = event => {
    try {
      recentControl = null;
      const target = event.target;
      if (!target?.closest || target.closest('input,textarea,select,[contenteditable="true"]')) return;
      const control = target.closest(controlSelector);
      if (!control || control.disabled || control.getAttribute("aria-disabled") === "true") return;
      const rawLabel = control.getAttribute("aria-label") || control.getAttribute("title") || control.innerText || control.textContent || "";
      const label = String(rawLabel).replace(/\s+/g, " ").trim()
        .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted]")
        .replace(/\b\+?\d[\d\s().-]{7,}\d\b/g, "[redacted]")
        .replace(/\b[A-Za-z0-9_-]{24,}\b/g, "[redacted]").slice(0, 120);
      if (!label || !/[a-z]/i.test(label)) return;
      const explicitRole = String(control.getAttribute("role") || "").toLowerCase();
      const className = String(control.className || "").toLowerCase();
      const role = ["tab", "button", "menuitem"].includes(explicitRole) ? explicitRole :
        control.hasAttribute("data-step") || className.includes("step") ? "step" :
          control.hasAttribute("data-tab") || control.hasAttribute("aria-controls") || className.includes("tab") ? "tab" :
            control.tagName === "A" ? "link" : "button";
      recentControl = { label, role, pagePath: location.pathname, at: Date.now() };
    } catch (_) { /* inaccessible or unusual page control */ }
  };
  try { document.addEventListener("click", captureControlClick, true); } catch (_) { /* document may be unavailable in a restricted page */ }
  const safeHeaders = headers => {
    const allowed = ["content-type", "content-length", "cache-control", "vary", "server", "x-powered-by", "x-aspnet-version", "x-application-context", "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "access-control-allow-origin", "access-control-allow-credentials"];
    const result = {};
    for (const name of allowed) {
      try {
        const value = headers?.get?.(name);
        if (value) result[name] = name === "content-security-policy" ? "present (" + String(value).length + " chars)" : String(value).slice(0, 500);
      } catch (_) { /* inaccessible response header */ }
    }
    return result;
  };
  const safeParameters = body => {
    const names = new Set();
    let skippedReason = null;
    const add = value => {
      const name = String(value || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100);
      if (name && !/@|\b\d{8,}\b/.test(name) && names.size < 100) names.add(name);
    };
    try {
      if (body && typeof body.keys === "function") {
        let count = 0;
        for (const name of body.keys()) { add(name); if (++count >= 100) break; }
      } else if (typeof body === "string" && body.length <= 65536) {
        if (/^\s*[\[{]/.test(body)) {
          let match;
          const pattern = /["']([^"'\\]{1,100})["']\s*:/g;
          while (names.size < 100 && (match = pattern.exec(body)) !== null) add(match[1]);
        } else if (body.includes("=")) {
          let count = 0;
          for (const name of new URLSearchParams(body).keys()) { add(name); if (++count >= 100) break; }
        } else if (body.trim()) skippedReason = "Body format is not a supported JSON or URL-encoded format.";
      } else if (typeof body === "string") {
        skippedReason = "Request body exceeded the 64 KiB parameter-name inspection limit.";
      } else if (body) {
        skippedReason = "Body format is unsupported or streaming; values were not read.";
      }
    } catch (_) { skippedReason = "Body format could not be inspected safely."; }
    return { names: [...names], skippedReason };
  };
  const publish = item => {
    if (!state.active || !state.config || !inScope(item.pagePath)) return;
    window.postMessage({ __stackscopeEarlyTraffic: "v1", channel: state.config.channel, ...item }, location.origin);
  };
  const emit = (methodValue, rawUrl, statusValue, headers, durationMs, body, transport = "http") => {
    if (!state.captureEnabled || state.captured >= 1000) return;
    const url = safeUrl(rawUrl, transport);
    if (!url) return;
    const method = String(methodValue || "GET").toUpperCase().slice(0, 20);
    if (!/^[A-Z!#$%&'*+.^_|~-]{1,20}$/.test(method)) return;
    const params = safeParameters(body);
    const control = recentControl && Date.now() - recentControl.at <= 10000 && recentControl.pagePath === location.pathname ? recentControl : null;
    const item = {
      url, method, status: Math.max(0, Math.min(599, Number(statusValue) || 0)),
      durationMs: Math.max(0, Math.min(120000, Math.round(Number(durationMs) || 0))),
      parameterNames: params.names, parameterNamesSkippedReason: params.skippedReason,
      transport, headers: safeHeaders(headers), at: Date.now(), pagePath: location.pathname,
      moduleControl: control ? { label: control.label, role: control.role, pagePath: control.pagePath } : null
    };
    state.captured += 1;
    if (state.active) publish(item);
    else {
      state.buffer.push(item);
      if (state.buffer.length > 100) state.buffer.shift();
    }
  };
  const originalFetch = window.fetch;
  if (typeof originalFetch === "function") {
    const wrapped = function(input, init) {
      let rawUrl = "";
      let method = "GET";
      let body = null;
      try {
        rawUrl = typeof input === "string" || input instanceof URL ? String(input) : String(input?.url || "");
        method = String(init?.method || input?.method || "GET");
        body = init?.body || null;
      } catch (_) { /* malformed Request-like input */ }
      const started = performance.now();
      let result;
      try { result = Reflect.apply(originalFetch, this, arguments); }
      catch (error) { emit(method, rawUrl, 0, null, performance.now() - started, body); throw error; }
      return result.then(response => {
        emit(method, rawUrl, response.status, response.headers, performance.now() - started, body);
        return response;
      }, error => {
        emit(method, rawUrl, 0, null, performance.now() - started, body);
        throw error;
      });
    };
    try { window.fetch = wrapped; if (window.fetch === wrapped) state.restores.push(() => { if (window.fetch === wrapped) window.fetch = originalFetch; }); } catch (_) { /* non-writable page API */ }
  }
  const xhr = window.XMLHttpRequest?.prototype;
  if (xhr && typeof xhr.open === "function" && typeof xhr.send === "function") {
    const originalOpen = xhr.open;
    const originalSend = xhr.send;
    const requestMeta = new WeakMap();
    const wrappedOpen = function(method, url) { requestMeta.set(this, { method: String(method || "GET"), url: String(url || "") }); return Reflect.apply(originalOpen, this, arguments); };
    const wrappedSend = function() {
      const meta = requestMeta.get(this);
      if (meta) {
        const started = performance.now();
        const body = arguments[0];
        this.addEventListener("loadend", () => {
          let headers = null;
          try { headers = { get: name => this.getResponseHeader(name) || null }; } catch (_) { /* response headers may be inaccessible */ }
          emit(meta.method, meta.url, this.status, headers, performance.now() - started, body);
        }, { once: true });
      }
      return Reflect.apply(originalSend, this, arguments);
    };
    try {
      xhr.open = wrappedOpen; xhr.send = wrappedSend;
      if (xhr.open === wrappedOpen && xhr.send === wrappedSend) state.restores.push(() => { if (xhr.open === wrappedOpen) xhr.open = originalOpen; if (xhr.send === wrappedSend) xhr.send = originalSend; });
    } catch (_) { /* XHR may be locked down */ }
  }
  const wrapConstructor = (name, transport) => {
    const original = window[name];
    if (typeof original !== "function") return;
    const wrapped = new Proxy(original, { construct(target, args, newTarget) {
      const instance = Reflect.construct(target, args, newTarget);
      emit(transport === "websocket" ? "WEBSOCKET" : "GET", args[0], 0, null, 0, null, transport);
      return instance;
    } });
    try { window[name] = wrapped; if (window[name] === wrapped) state.restores.push(() => { if (window[name] === wrapped) window[name] = original; }); } catch (_) { /* constructor may be non-writable */ }
  };
  wrapConstructor("WebSocket", "websocket");
  wrapConstructor("EventSource", "eventsource");
  const beacon = window.navigator?.sendBeacon;
  if (typeof beacon === "function") {
    const wrappedBeacon = function(url, body) {
      const started = performance.now();
      const queued = Reflect.apply(beacon, this, arguments);
      if (queued) emit("POST", url, 0, null, performance.now() - started, body, "sendBeacon");
      return queued;
    };
    try { window.navigator.sendBeacon = wrappedBeacon; if (window.navigator.sendBeacon === wrappedBeacon) state.restores.push(() => { if (window.navigator.sendBeacon === wrappedBeacon) window.navigator.sendBeacon = beacon; }); } catch (_) { /* read-only browser API */ }
  }
  const stop = channel => {
    if (channel && state.config?.channel !== channel) return;
    state.active = false;
    state.captureEnabled = false;
    state.buffer = [];
    recentControl = null;
    try { document.removeEventListener("click", captureControlClick, true); } catch (_) { /* best-effort cleanup */ }
    for (const restore of state.restores.splice(0)) { try { restore(); } catch (_) { /* best-effort restoration */ } }
  };
  window.addEventListener("message", event => {
    const data = event.data;
    if (event.source !== window || event.origin !== location.origin || !data || typeof data !== "object") return;
    if (data.__stackscopeEarlyInit === "v1" && data.config?.origin === location.origin && typeof data.config.channel === "string") {
      state.config = data.config;
      state.active = true;
      state.captureEnabled = true;
      clearTimeout(state.expiry);
      for (const item of state.buffer.splice(0)) publish(item);
    } else if (data.__stackscopeEarlyStop === "v1") stop(data.channel);
  });
  state.expiry = setTimeout(() => { if (!state.active) { state.captureEnabled = false; state.buffer = []; } }, 10000);
  window.postMessage({ __stackscopeEarlyReady: "v1" }, location.origin);
})();
