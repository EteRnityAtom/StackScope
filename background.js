const EARLY_CONFIG_KEY = "stackscopeEarlyObserverConfig";
const EARLY_SCRIPT_IDS = ["stackscope-early-main", "stackscope-early-bridge"];

function isInModulePath(pathname, modulePath) {
  try {
    const rootPath = new URL(modulePath, "https://scope.invalid").pathname;
    const root = rootPath.endsWith("/") ? rootPath.slice(0, -1) : rootPath;
    const inside = path => path === root || path.startsWith(root + "/");
    let candidate = pathname;
    for (let depth = 0; depth < 5; depth += 1) {
      if (candidate.includes("\\") || /[\u0000-\u001f]/.test(candidate)) return false;
      const decoded = decodeURIComponent(candidate);
      if (decoded.includes("\\") || /[\u0000-\u001f]/.test(decoded) || !inside(new URL(decoded, "https://scope.invalid").pathname)) return false;
      if (decoded === candidate) return true;
      candidate = decoded;
    }
    return false;
  } catch (_) { return false; }
}

// ---- CORS probe support ----
// The popup cannot set a forbidden request header (Origin) through fetch, so it
// marks each CORS-probe request with a header and this background script rewrites
// the Origin at the network layer and captures the ACAO/ACAC response headers.
const corsProbe = { active: false, origin: "", markedRequestIds: new Set(), results: new Map() };
const CORS_MARKER_HEADER = "x-stackscope-cors";

function isValidHttpOrigin(value) {
  try {
    const url = new URL(String(value || ""));
    return /^https?:$/.test(url.protocol) && url.origin === value && !url.username && !url.password;
  } catch (_) { return false; }
}

function onBeforeSendHeadersCors(details) {
  if (!corsProbe.active) return {};
  const headers = details.requestHeaders || [];
  const marked = headers.some(header => header.name.toLowerCase() === CORS_MARKER_HEADER);
  if (!marked) return {};
  corsProbe.markedRequestIds.add(details.requestId);
  const filtered = headers.filter(header => {
    const name = header.name.toLowerCase();
    return name !== CORS_MARKER_HEADER && name !== "origin";
  });
  filtered.push({ name: "Origin", value: corsProbe.origin });
  return { requestHeaders: filtered };
}

function onHeadersReceivedCors(details) {
  if (!corsProbe.markedRequestIds.has(details.requestId)) return {};
  corsProbe.markedRequestIds.delete(details.requestId);
  let acao = null;
  let acac = null;
  for (const header of details.responseHeaders || []) {
    const name = header.name.toLowerCase();
    if (name === "access-control-allow-origin") acao = header.value || "";
    else if (name === "access-control-allow-credentials") acac = header.value || "";
  }
  corsProbe.results.set(details.url, { acao, acac });
  return {};
}

function enableCorsProbe(origin) {
  corsProbe.active = true;
  corsProbe.origin = origin;
  corsProbe.markedRequestIds = new Set();
  corsProbe.results = new Map();
  try {
    if (!browser.webRequest.onBeforeSendHeaders.hasListener(onBeforeSendHeadersCors)) {
      browser.webRequest.onBeforeSendHeaders.addListener(onBeforeSendHeadersCors, { urls: ["http://*/*", "https://*/*"] }, ["blocking", "requestHeaders"]);
    }
    if (!browser.webRequest.onHeadersReceived.hasListener(onHeadersReceivedCors)) {
      browser.webRequest.onHeadersReceived.addListener(onHeadersReceivedCors, { urls: ["http://*/*", "https://*/*"] }, ["responseHeaders"]);
    }
    return true;
  } catch (_) { return false; }
}

function disableCorsProbe() {
  corsProbe.active = false;
  corsProbe.origin = "";
  corsProbe.markedRequestIds = new Set();
  corsProbe.results = new Map();
  try { browser.webRequest.onBeforeSendHeaders.removeListener(onBeforeSendHeadersCors); } catch (_) { /* listener may be absent */ }
  try { browser.webRequest.onHeadersReceived.removeListener(onHeadersReceivedCors); } catch (_) { /* listener may be absent */ }
}

browser.runtime.onMessage.addListener((message, sender) => {
  if (!message || typeof message !== "object") return undefined;
  if (message.type === "stackscope:cors-config") {
    if (message.active && isValidHttpOrigin(message.origin)) return Promise.resolve({ ok: enableCorsProbe(message.origin) });
    disableCorsProbe();
    return Promise.resolve({ ok: true });
  }
  if (message.type === "stackscope:cors-result") {
    const result = corsProbe.results.get(message.url) || null;
    if (result) corsProbe.results.delete(message.url);
    return Promise.resolve(result);
  }
  return undefined;
});

browser.runtime.onMessage.addListener(async (message, sender) => {
  if (message?.type !== "stackscope:get-early-observer-config") return undefined;
  const tabId = sender.tab?.id;
  if (!Number.isInteger(tabId) || sender.frameId !== 0) return null;
  try {
    const senderUrl = new URL(sender.url || "");
    if (!/^https?:$/.test(senderUrl.protocol)) return null;
    const stored = await browser.storage.local.get(EARLY_CONFIG_KEY);
    const config = stored[EARLY_CONFIG_KEY];
    if (!config?.active || config.tabId !== tabId || config.origin !== senderUrl.origin) return null;
    if (config.mode === "module") {
      if (!isInModulePath(senderUrl.pathname, config.modulePath || "/")) return null;
    } else if (config.mode !== "site") return null;
    return {
      tabId: config.tabId,
      storageKey: config.storageKey,
      channel: config.channel,
      origin: config.origin,
      mode: config.mode,
      modulePath: config.modulePath,
      compareObservedGets: Boolean(config.compareObservedGets)
    };
  } catch (_) { return null; }
});

browser.tabs.onRemoved.addListener(async tabId => {
  try {
    const stored = await browser.storage.local.get(EARLY_CONFIG_KEY);
    if (stored[EARLY_CONFIG_KEY]?.tabId !== tabId) return;
    await browser.storage.local.remove(EARLY_CONFIG_KEY);
    try { await browser.scripting.unregisterContentScripts({ ids: EARLY_SCRIPT_IDS }); } catch (_) { /* registration may already be absent */ }
  } catch (_) { /* stale configuration is harmless because lookups validate the tab id */ }
});
