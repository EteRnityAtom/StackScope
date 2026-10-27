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
