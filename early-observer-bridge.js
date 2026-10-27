(() => {
  const allowedHeaders = new Set([
    "content-type", "content-length", "cache-control", "vary", "server", "x-powered-by",
    "x-aspnet-version", "x-application-context", "content-security-policy",
    "strict-transport-security", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "access-control-allow-origin",
    "access-control-allow-credentials"
  ]);
  const sensitivePath = /(?:^|\/)(?:\.env(?:\.[^/]+)?|\.git|actuator|heapdump|credentials|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|secret|password|logout|logoff|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger|webhook|proxy)(?:\/|$)/i;
  const safeHeaders = headers => {
    const result = {};
    for (const [name, rawValue] of Object.entries(headers || {}).slice(0, 64)) {
      const key = String(name).toLowerCase();
      if (!allowedHeaders.has(key) || typeof rawValue !== "string") continue;
      const value = key === "content-security-policy"
        ? (/^present \(\d+ chars\)$/.test(rawValue) ? rawValue : `present (${rawValue.length} chars)`)
        : rawValue.replace(/'nonce-[^']+'/gi, "'nonce-[redacted]'").slice(0, 500);
      result[key] = value;
    }
    return result;
  };
  const safeNames = names => [...new Set((Array.isArray(names) ? names.slice(0, 100) : [])
    .map(name => String(name || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100))
    .filter(name => name && !/@|\b\d{8,}\b/.test(name)))].slice(0, 100);
  const redactPath = pathname => {
    const segments = String(pathname || "/").split("/");
    const credentialSegment = /^(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|session[_-]?(?:id|token)|secret|password|jwt|api[_-]?key|access[_-]?key|private[_-]?key)$/i;
    for (let index = 1; index < segments.length; index += 1) {
      let previous = "";
      let current = "";
      try { previous = decodeURIComponent(segments[index - 1]); current = decodeURIComponent(segments[index]); } catch (_) { continue; }
      if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?$/.test(current) || (credentialSegment.test(previous) && /^[A-Za-z0-9_-]{16,}$/.test(current))) segments[index] = "[redacted]";
    }
    return segments.join("/");
  };
  const isInScope = (pathname, config) => {
    if (!config || location.origin !== config.origin || !/^https?:$/.test(location.protocol)) return false;
    if (config.mode !== "module") return config.mode === "site";
    try {
      const root = new URL(String(config.modulePath || "/"), config.origin).pathname;
      const normalizedRoot = root.length > 1 && root.endsWith("/") ? root.slice(0, -1) : root;
      const inside = path => path === normalizedRoot || path.startsWith(`${normalizedRoot}/`);
      let candidate = pathname;
      for (let depth = 0; depth < 5; depth += 1) {
        if (candidate.includes("\\") || /[\u0000-\u001f]/.test(candidate)) return false;
        let decoded;
        try { decoded = decodeURIComponent(candidate); } catch (_) { return false; }
        if (decoded.includes("\\") || /[\u0000-\u001f]/.test(decoded) || !inside(new URL(decoded, config.origin).pathname)) return false;
        if (decoded === candidate) return true;
        candidate = decoded;
      }
      return false;
    } catch (_) { return false; }
  };
  const safeItem = (raw, config) => {
    if (!raw || typeof raw !== "object" || !isInScope(String(raw.pagePath || ""), config)) return null;
    if (typeof raw.url !== "string" || raw.url.length > 8192) return null;
    let url;
    try { url = new URL(String(raw.url || "")); } catch (_) { return null; }
    const transport = raw.transport || "http";
    if (!["http", "websocket", "eventsource", "sendBeacon"].includes(transport)) return null;
    const comparable = new URL(url.href);
    if (transport === "websocket") {
      if (comparable.protocol === "ws:") comparable.protocol = "http:";
      else if (comparable.protocol === "wss:") comparable.protocol = "https:";
    }
    if (comparable.origin !== config.origin || url.username || url.password) return null;
    url.hash = "";
    const queryNames = [...url.searchParams.keys()];
    if (queryNames.length > 50) return null;
    if (queryNames.length) {
      url.search = "";
      for (const name of queryNames) url.searchParams.append(name.slice(0, 100), "[redacted]");
    }
    url.pathname = redactPath(url.pathname);
    const method = String(raw.method || "GET").toUpperCase().slice(0, 20);
    if (!/^[A-Z!#$%&'*+.^_|~-]{1,20}$/.test(method)) return null;
    const status = Math.max(0, Math.min(599, Number(raw.status) || 0));
    const parameterNames = safeNames(raw.parameterNames);
    const item = {
      url: url.href,
      method,
      status,
      durationMs: Math.max(0, Math.min(120000, Math.round(Number(raw.durationMs) || 0))),
      parameterNames,
      parameterNamesSkippedReason: [
        "Body format is not a supported JSON or URL-encoded format.",
        "Request body exceeded the 64 KiB parameter-name inspection limit.",
        "Body format is unsupported or streaming; values were not read.",
        "Body format could not be inspected safely."
      ].includes(raw.parameterNamesSkippedReason) ? raw.parameterNamesSkippedReason : null,
      transport,
      headers: safeHeaders(raw.headers),
      at: Date.now(),
      moduleControl: null
    };
    const rawPagePath = String(raw.pagePath || new URL(config.origin).pathname).slice(0, 2048);
    item.pagePath = redactPath(rawPagePath);
    if (raw.moduleControl && typeof raw.moduleControl === "object" && rawPagePath === String(raw.moduleControl.pagePath || "").slice(0, 2048) && isInScope(rawPagePath, config)) {
      const label = String(raw.moduleControl.label || "").replace(/[\r\n\t]/g, " ").trim()
        .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted]")
        .replace(/\b\+?\d[\d\s().-]{7,}\d\b/g, "[redacted]")
        .replace(/\b[A-Za-z0-9_-]{24,}\b/g, "[redacted]").slice(0, 120);
      const role = String(raw.moduleControl.role || "").toLowerCase();
      if (label && ["tab", "button", "menuitem", "step", "link"].includes(role)) item.moduleControl = { label, role, pagePath: item.pagePath };
    }
    return item;
  };
  const compareWithoutCookies = async (item, config) => {
    if (!config.compareObservedGets) return null;
    if (item.method !== "GET" || item.transport !== "http") {
      return { suppressed: true, outcome: item.method !== "GET" ? "Observed only; non-GET requests are never replayed without cookies." : "Opt-in no-cookie comparison is limited to eligible HTTP GET requests." };
    }
    if (state.noCookiePaused) return { suppressed: true, outcome: "Further no-cookie comparisons were paused after the server returned a rate-limit response." };
    if (!item.status) return { suppressed: true, outcome: "The browser-session request had no readable response, so there is no baseline to compare." };
    let target;
    try { target = new URL(item.url); } catch (_) { return { suppressed: true, outcome: "Malformed URL was not compared." }; }
    if (target.search || sensitivePath.test(target.pathname.toLowerCase()) || /\b(?:logout|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger)\b/i.test(target.searchParams.get("action") || target.searchParams.get("operation") || target.searchParams.get("op") || target.searchParams.get("cmd") || "")) {
      return { suppressed: true, outcome: "Route was skipped because safe comparison would require query values or the path appears sensitive/state-changing." };
    }
    if (target.pathname.split("/").some(segment => /^\d{5,}$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment))) {
      return { suppressed: true, outcome: "Route with a numeric or UUID path identifier was skipped; no identifier was replayed." };
    }
    if (state.checkedUrls.has(target.href)) return { suppressed: true, outcome: "This URL was already checked once during this observer session; duplicate checks were skipped." };
    state.checkedUrls.add(target.href);
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), 8000);
    try {
      const started = performance.now();
      const response = await fetch(target.href, { method: "GET", credentials: "omit", redirect: "manual", cache: "no-store", signal: timeout.signal });
      const type = response.headers.get("content-type") || "unknown";
      const status = response.status || null;
      if ([429, 503].includes(status)) {
        state.noCookiePaused = true;
        const headers = {};
        for (const name of allowedHeaders) {
          try {
            const value = response.headers.get(name);
            if (value) headers[name] = name === "content-security-policy" ? `present (${value.length} chars)` : value.slice(0, 500);
          } catch (_) { /* inaccessible header */ }
        }
        try { await response.body?.cancel(); } catch (_) { /* rate-limit body is not retained */ }
        return { status, type, bytes: /^\d+$/.test(headers["content-length"] || "") ? Number(headers["content-length"]) : null, byteSource: headers["content-length"] ? "Content-Length" : null, headers, suppressed: false, outcome: `Without-cookie GET returned HTTP ${status}; further observer comparisons were paused to respect server rate limiting.` };
      }
      if (status >= 300 && status < 400 || response.type === "opaqueredirect") {
        let loginRedirect = false;
        try {
          const locationHeader = response.headers.get("location") || "";
          const destination = new URL(locationHeader, target.href);
          loginRedirect = destination.origin === config.origin && /(?:^|\/)(?:login|log-in|signin|sign-in|authenticate|auth)(?:\/|$)/i.test(destination.pathname);
        } catch (_) { /* redirect target unavailable */ }
        try { await response.body?.cancel(); } catch (_) { /* no body retained */ }
        return { suppressed: true, outcome: loginRedirect ? "Without-cookie GET redirected to a login/auth route; this suggests protection but needs manual confirmation." : "Without-cookie GET redirected; the destination was not followed." };
      }
      const headers = {};
      for (const name of allowedHeaders) {
        try {
          const value = response.headers.get(name);
          if (value) headers[name] = name === "content-security-policy" ? `present (${value.length} chars)` : value.slice(0, 500);
        } catch (_) { /* inaccessible header */ }
      }
      if (/text\/html|application\/xhtml\+xml/i.test(type)) {
        try { await response.body?.cancel(); } catch (_) { /* HTML shells are excluded */ }
        return { suppressed: true, outcome: "Without-cookie response was an HTML app/login shell and was excluded from access results." };
      }
      const declaredLength = response.headers.get("content-length");
      let bytes = /^\d+$/.test(declaredLength || "") ? Number(declaredLength) : null;
      let sizeComplete = bytes !== null;
      if (bytes === null && response.body) {
        const reader = response.body.getReader();
        bytes = 0;
        sizeComplete = false;
        try {
          while (bytes < 131072) {
            const { value, done } = await reader.read();
            if (done) { sizeComplete = true; break; }
            const remaining = 131072 - bytes;
            bytes += Math.min(value.byteLength, remaining);
            if (value.byteLength > remaining) break;
          }
        } finally { try { await reader.cancel(); } catch (_) { /* response bytes are never retained */ } }
      } else {
        try { await response.body?.cancel(); } catch (_) { /* response body is never retained */ }
      }
      const byteSource = /^\d+$/.test(declaredLength || "") ? "Content-Length" : sizeComplete ? "measured body" : "measured lower bound (128 KiB cap)";
      const sameHeaders = JSON.stringify(Object.entries(item.headers).filter(([name]) => name !== "cache-control").sort()) === JSON.stringify(Object.entries(headers).filter(([name]) => name !== "cache-control").sort());
      const sameType = type.toLowerCase() === String(item.headers["content-type"] || "unknown").toLowerCase();
      const sameSize = bytes !== null && item.headers["content-length"] !== undefined && sizeComplete && String(bytes) === String(item.headers["content-length"]);
      let outcome = "Manual review required; response metadata alone cannot prove access control.";
      if ([401, 403].includes(status)) outcome = "Without-cookie GET returned an authentication/authorization status.";
      else if (status === 200 && status === item.status && sameType && sameHeaders && sameSize) outcome = "No difference in response metadata. This does not confirm whether response data is authorized; bodies are not inspected.";
      else if (status === 200 && status === item.status && sameType && sameHeaders && !sameSize) outcome = "Both requests returned HTTP 200 with matching selected headers, but size comparison is unavailable or differs. Authorization is unconfirmed.";
      else if (status === 200) outcome = "Without-cookie GET returned HTTP 200 with metadata that differs from the app request. Authorization is unconfirmed.";
      return { status, type, bytes, byteSource, sizeComplete, headers, selectedHeadersMatch: sameHeaders, durationMs: Math.max(0, Math.round(performance.now() - started)), outcome };
    } catch (_) {
      return { suppressed: true, outcome: "Without-cookie request failed, timed out, or was blocked; no response metadata was available." };
    } finally { clearTimeout(timer); }
  };
  const state = { active: true, config: null, pending: Promise.resolve(), seen: new Set(), checkedUrls: new Set(), noCookiePaused: false };
  const receive = async () => {
    const config = await browser.runtime.sendMessage({ type: "stackscope:get-early-observer-config" });
    if (!config || config.origin !== location.origin || !isInScope(location.pathname, config)) {
      window.postMessage({ __stackscopeEarlyStop: "v1", channel: null }, location.origin);
      return;
    }
    state.config = config;
    const channel = config.channel;
    const listener = event => {
      const data = event.data;
      if (!state.active || event.source !== window || event.origin !== config.origin || !data || data.__stackscopeEarlyTraffic !== "v1" || data.channel !== channel || state.seen.size >= 1000) return;
      const item = safeItem(data, config);
      if (!item || state.seen.size >= 1000) return;
      const dedupeKey = `${item.method}|${item.url}|${item.at}`;
      if (state.seen.has(dedupeKey)) return;
      state.seen.add(dedupeKey);
      state.pending = state.pending.then(async () => {
        const anonymous = await compareWithoutCookies(item, config);
        const stored = await browser.storage.local.get(config.storageKey);
        const prior = stored[config.storageKey] || {};
        const sameScope = prior.origin === config.origin && prior.mode === config.mode && prior.modulePath === config.modulePath;
        const items = sameScope && Date.now() - Number(prior.updatedAt || 0) <= 86400000 && Array.isArray(prior.items) ? prior.items.slice(-999) : [];
        items.push({ ...item, anonymous });
        await browser.storage.local.set({
          [config.storageKey]: {
            origin: config.origin, mode: config.mode, modulePath: config.modulePath,
            tabId: config.tabId, compareObservedGets: config.compareObservedGets,
            active: true, startedAt: sameScope && prior.startedAt ? prior.startedAt : Date.now(),
            updatedAt: Date.now(), items
          }
        });
      }).catch(() => { /* storage quota does not affect the page request */ });
    };
    window.addEventListener("message", listener);
    window.postMessage({ __stackscopeEarlyInit: "v1", config: { ...config, channel } }, location.origin);
    window.addEventListener("pagehide", () => { state.active = false; window.removeEventListener("message", listener); }, { once: true });
  };
  receive().catch(() => { /* early observation is optional and best effort */ });
})();
