const $ = id => document.getElementById(id);

let stopRequested = false;
let lastReport = null;
let activeTabSnapshot = null;
let popupOpenedTabId = null;
let popupOpenedOrigin = null;
let activeController = null;
let activeTabReady = false;
let storageReady = false;
let pendingReportRecord = null;
let savedReports = [];
const PENDING_STORAGE_KEY = "stackscopePendingReport";
const SAVED_STORAGE_KEY = "stackscopeSavedReports";
const PENDING_TTL_MS = 24 * 60 * 60 * 1000;
const TRAFFIC_TTL_MS = 24 * 60 * 60 * 1000;
const TRAFFIC_ITEM_LIMIT = 1000;
const TRAFFIC_STORAGE_PREFIX = "stackscopeTrafficTab_";
const EARLY_OBSERVER_CONFIG_KEY = "stackscopeEarlyObserverConfig";
const EARLY_OBSERVER_SCRIPT_IDS = ["stackscope-early-main", "stackscope-early-bridge"];
let trafficRecord = null;
let activeTrafficStorageKey = null;

function collectSensitiveIndicators(text, sourceUrl, indicators, seen, limit = 1000) {
  const keywordPattern = /\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|authorization|bearer|aws_access_key_id|aws_secret_access_key)\b/gi;
  let match;
  let cursor = 0;
  let line = 1;
  while (indicators.length < limit && (match = keywordPattern.exec(text)) !== null) {
    for (; cursor < match.index; cursor += 1) if (text.charCodeAt(cursor) === 10) line += 1;
    const keyword = match[1].toLowerCase();
    const source = sourceUrl;
    const key = `${source}|${keyword}|${line}`;
    if (!seen.has(key)) {
      seen.add(key);
      indicators.push({ source, keyword, line });
    }
  }
}

// High-signal secret/credential value patterns. Unlike collectSensitiveIndicators
// (which records only a keyword name), this captures the matched value so an
// authorized tester can confirm a real leak. Values are masked before storage.
const secretValuePatterns = [
  ["AWS access key ID", /\bAKIA[0-9A-Z]{16}\b/g, 0],
  ["AWS secret access key", /\baws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+]{40})\b/gi, 1],
  ["Google API key", /\bAIza[0-9A-Za-z_\-]{35}\b/g, 0],
  ["Google OAuth client secret", /\bGOCSPX-[0-9A-Za-z_\-]{20,}\b/g, 0],
  ["Slack token", /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g, 0],
  ["Stripe secret key", /\bsk_live_[0-9A-Za-z]{16,}\b/g, 0],
  ["Stripe restricted key", /\brk_live_[0-9A-Za-z]{16,}\b/g, 0],
  ["GitHub token", /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g, 0],
  ["Twilio account SID", /\bAC[0-9a-fA-F]{32}\b/g, 0],
  ["SendGrid key", /\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b/g, 0],
  ["JSON Web Token", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, 0],
  ["Private key block", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g, 0],
  ["Basic-auth credentials in URL", /\bhttps?:\/\/[A-Za-z0-9._~%+-]+:[^\/\s:@"'`]{3,}@/g, 0],
  ["Generic secret assignment", /\b(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd)["']?\s*[:=]\s*["']([^"'`\s]{12,100})["']/gi, 1]
];

function maskSecretValue(value) {
  const raw = String(value || "");
  if (raw.length <= 8) return `${raw.slice(0, 2)}${"*".repeat(Math.max(0, raw.length - 2))}`;
  return `${raw.slice(0, 4)}…${raw.slice(-4)} (${raw.length} chars)`;
}

function extractSecretFindings(text, sourceUrl, findings, seen, limit = 500) {
  const body = String(text || "");
  for (const [label, pattern, group] of secretValuePatterns) {
    pattern.lastIndex = 0;
    let match;
    while (findings.length < limit && (match = pattern.exec(body)) !== null) {
      const captured = (group && match[group] ? match[group] : match[0]) || "";
      if (!captured) { if (match.index === pattern.lastIndex) pattern.lastIndex += 1; continue; }
      let line = 1;
      for (let i = 0; i < match.index && i < body.length; i += 1) if (body.charCodeAt(i) === 10) line += 1;
      const key = `${sourceUrl}|${label}|${captured.slice(0, 32)}|${line}`;
      if (seen.has(key)) { if (match.index === pattern.lastIndex) pattern.lastIndex += 1; continue; }
      seen.add(key);
      findings.push({ type: label, value: maskSecretValue(captured), source: sourceUrl, line });
      if (match.index === pattern.lastIndex) pattern.lastIndex += 1;
    }
  }
}

function assertActiveTargetUnchanged(tab) {
  if (!tab?.id) return;
  if (popupOpenedTabId !== null && tab.id !== popupOpenedTabId) {
    throw new Error("The active tab changed after StackScope opened. Reopen the popup on the intended target before scanning.");
  }
  if (popupOpenedOrigin && tab.url) {
    let currentOrigin = "";
    try { currentOrigin = new URL(tab.url).origin; } catch (_) { return; }
    if (currentOrigin !== popupOpenedOrigin) throw new Error("The active target origin changed after StackScope opened. Reopen the popup on the intended target before scanning.");
  }
}

const techPatterns = [
  ["Next.js", [/__NEXT_DATA__|\/_next\/|x-nextjs/i, /next(?:\.js)?/i]],
  ["Nuxt.js", [/__NUXT__|\/_nuxt\//i, /nuxt/i]],
  ["React", [/react-dom|react\.production|__react/i, /react/i]],
  ["Angular", [/ng-version=|@angular\/|angular\.js/i, /angular/i]],
  ["Vue.js", [/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|__VUE__/i, /vue/i]],
  ["jQuery", [/jquery(?:\.min)?\.js/i, /jquery/i]],
  ["Express.js", [/x-powered-by:\s*express|express\.js/i, /express/i]],
  ["Node.js", [/node\.js|x-powered-by:\s*node/i, /node/i]],
  ["Spring Boot", [/JSESSIONID|X-Application-Context|Whitelabel Error Page/i, /spring/i]],
  ["Django", [/csrftoken|csrfmiddlewaretoken|django/i, /django/i]],
  ["Laravel", [/laravel_session|XSRF-TOKEN|Whoops, looks like/i, /laravel/i]],
  ["Ruby on Rails", [/authenticity_token|X-Runtime|_session=/i, /rails/i]],
  ["ASP.NET Core", [/\.AspNetCore\.|Kestrel|__VIEWSTATE/i, /aspnet/i]],
  ["Flask/Werkzeug", [/werkzeug|flask\.app|itsdangerous/i, /flask|werkzeug/i]],
  ["FastAPI", [/\/openapi\.json|\"detail\":\s*\[/i, /fastapi|uvicorn/i]],
  ["NestJS", [/\"statusCode\"\s*:\s*\d+|@nestjs\//i, /nestjs/i]],
  ["Symfony", [/sf_redirect|X-Debug-Token/i, /symfony/i]],
  ["Go web framework", [/Server:\s*Fiber|net\/http/i, /gin-gonic|labstack\/echo|gofiber/i]],
  ["Apache Struts", [/struts\.devmode|struts\.action/i, /struts/i]],
  ["ColdFusion", [/CFID=|CFTOKEN=|ColdFusion/i, /coldfusion/i]],
  ["WordPress", [/wp-content\/|wp-includes\/|wp-json\//i, /wordpress|wp-content|wp-includes/i]],
  ["Shopify", [/cdn\.shopify\.com|Shopify\.theme|shopify-section/i, /shopify/i]],
  ["Magento / Adobe Commerce", [/mage\/cookies|Magento_|requirejs-config|static\/version\d+\//i, /magento|adobe commerce/i]],
  ["Drupal", [/drupalSettings|Drupal\.behaviors|sites\/default\/files/i, /drupal/i]],
  ["Joomla", [/option=com_|\/components\/com_|Joomla!/i, /joomla/i]],
  ["Sitecore", [/\/sitecore\/modules\/|sc_mode=|Sitecore\.XM/i, /sitecore/i]],
  ["Adobe Experience Manager", [/\/etc\.clientlibs\/|\/libs\/granite\/|CQ\.shared/i, /aem|adobe experience manager/i]],
  ["Salesforce Lightning", [/lightning\/page\/|force\.com|Aura\.initConfig/i, /salesforce|lightning/i]],
  ["Microsoft Dynamics 365", [/\.crm\.dynamics\.com|Xrm\.Page|Mscrm\.Controls/i, /dynamics 365|dynamics\.com/i]],
  ["Odoo", [/web\.assets_(?:backend|frontend)|odoo\.define/i, /odoo/i]],
  ["Strapi", [/strapi\.io|x-powered-by:\s*strapi|@strapi\//i, /strapi/i]],
  ["KeystoneJS", [/@keystone-6\//i, /keystone(?:js)?/i]],
  ["Contentful", [/cdn\.contentful\.com|contentful\.space/i, /contentful/i]],
  ["Sanity", [/cdn\.sanity\.io|sanity\.io\/images/i, /sanity/i]],
  ["Shopify Hydrogen", [/shopify-buy\/hydrogen|@shopify\/hydrogen|__HYDROGEN__/i, /hydrogen/i]],
  ["Umbraco", [/\/umbraco\/surface\/|\/umbraco\/api\/|umbracoForms/i, /umbraco/i]],
  ["Remix", [/__remixContext|@remix-run\//i, /remix/i]],
  ["SvelteKit", [/__sveltekit|_app\/immutable\/|sveltekit/i, /sveltekit|svelte/i]],
  ["Astro", [/astro-island|_astro\/|astro\.js/i, /astro/i]],
  ["Deno Fresh", [/\/_fresh\/|fresh\.runtime/i, /deno fresh|fresh framework/i]],
  ["Qwik", [/qwikloader|q:container|@builder\.io\/qwik/i, /qwik/i]],
  ["Vite", [/\/@@vite\/client|\/assets\/index-[A-Za-z0-9_-]+\.js|vite\/modulepreload/i, /vite/i]],
  ["Webpack", [/__webpack_require__|webpackChunkName|webpackJsonp/i, /webpack/i]],
  ["Apollo GraphQL", [/ApolloClient|apollo-client|@apollo\/client/i, /apollo/i]],
  ["Hasura", [/x-hasura-|hasura\.io|\/v1\/graphql/i, /hasura/i]],
  ["PostGraphile", [/postgraphile|postgraphile\.com|pg-simplify-inflector/i, /postgraphile/i]],
  ["tRPC", [/\.useQuery\(|\.useMutation\(|@trpc\/client/i, /trpc/i]],
  ["Supabase", [/supabase\.co|@supabase\/|supabase-js/i, /supabase/i]],
  ["Firebase", [/firebaseapp\.com|firebaseio\.com|@firebase\//i, /firebase/i]],
  ["PocketBase", [/\/api\/collections\/|pocketbase/i, /pocketbase/i]],
  ["Appwrite", [/\/v1\/account|appwrite\.io|X-Appwrite/i, /appwrite/i]],
  ["gRPC-Web", [/grpc-web|application\/grpc-web/i, /grpc-web/i]],
  ["Phoenix / LiveView", [/phx-\w+|phoenix\.js|Phoenix\.Socket/i, /phoenix|liveview/i]],
  ["Rust Actix / Axum", [/actix-web|axum::|X-Actix/i, /actix|axum/i]],
  ["Hono", [/x-powered-by:\s*hono|hono\/client/i, /hono/i]],
  ["Fastify", [/x-powered-by:\s*fastify|fastify\.io/i, /fastify/i]],
  ["Koa", [/x-powered-by:\s*koa|koa\.js/i, /koa/i]]
];

const frameworkIdeas = {
  "Next.js": [
    ["Authorization / IDOR / MFLAC", "Check API routes, Server Actions, and server-rendered data with authorized roles and test records. Client route guards do not replace server checks."],
    ["SSRF", "Review server-side fetches and image optimization URL allowlists. Use an assessor-controlled destination; do not probe internal networks or cloud metadata."],
    ["Data exposure", "Review hydration data, public runtime configuration, source maps, and build assets for unintended secrets or private data."],
    ["Cache isolation", "Compare authenticated and anonymous responses to ensure personalized SSR content is not shared across users."]
  ],
  "Nuxt.js": [
    ["Authorization / IDOR", "Verify server/API handlers enforce object access independently of client-side route checks."],
    ["Data exposure", "Inspect hydration payloads and public runtime configuration for sensitive values."],
    ["SSRF", "Review server-side fetch and image URL handling against a controlled allowlist."],
    ["Cache isolation", "Check whether authenticated SSR responses can be served to another user."]
  ],
  "React": [
    ["DOM XSS", "Trace untrusted values into dangerouslySetInnerHTML, innerHTML, URL sinks, and unsafe DOM libraries. Verify encoding in a controlled test account."],
    ["Authorization / IDOR / MFLAC", "Treat client routes and hidden controls as presentation only; verify server-side authorization for each sensitive operation."],
    ["Data exposure", "Review shipped bundles, source maps, and public configuration for credentials or internal-only details."]
  ],
  "Angular": [
    ["DOM XSS", "Review bypassSecurityTrust* calls and direct DOM APIs where input may be attacker-controlled."],
    ["Authorization / IDOR / MFLAC", "Treat route guards as UI controls and verify API authorization for each role and object."],
    ["CSRF", "For cookie-authenticated changes, verify the server validates its anti-CSRF token and cookie policy."]
  ],
  "Vue.js": [
    ["DOM XSS", "Review v-html, dynamic templates, and URL attributes for untrusted data flows."],
    ["Authorization / IDOR / MFLAC", "Verify server-side object and function authorization; client route checks are not sufficient."],
    ["Data exposure", "Review public runtime configuration, hydration data, and shipped bundles for sensitive values."]
  ],
  "jQuery": [
    ["DOM XSS", "Trace untrusted values into .html(), .append(), .before(), .after(), and selectors."],
    ["Dependency hygiene", "Identify the exact deployed version and compare it with vendor advisories before making a finding."]
  ],
  "Express.js": [
    ["SSTI / XSS", "If a template engine is present, review runtime template construction and unescaped output using code/config evidence."],
    ["LFI / path traversal", "Review file reads and downloads for canonical path checks and allowlisted roots."],
    ["SQLi / parameter pollution", "Review query construction and duplicate-parameter handling; verify validation and parameterized queries."],
    ["CSRF / SSRF", "Check cookie-authenticated changes for server-side CSRF validation and user-controlled outbound URL handling."],
    ["Authorization / IDOR / MFLAC", "Verify explicit per-route and per-object checks for every sensitive operation."]
  ],
  "Node.js": [
    ["SSTI / XSS", "Review template rendering and HTML output for untrusted values and unsafe runtime template construction."],
    ["LFI / path traversal", "Review fs reads and downloads for canonical path checks and allowlisted roots."],
    ["SQLi / SSRF", "Review raw query construction and server-side URL fetches for untrusted input."],
    ["Authorization / IDOR / MFLAC", "Check each route and object for explicit authorization, including alternate HTTP methods."]
  ],
  "Django": [
    ["Authorization / IDOR / MFLAC", "Test object-level permissions across authorized roles; review individual views and API permission classes."],
    ["CSRF", "Verify cookie-authenticated state changes enforce CSRF validation; review exemptions."],
    ["SQLi", "Review raw(), extra(), RawSQL, dynamic ordering, and string-built filters."],
    ["SSTI / XSS", "Review safe/mark_safe use, disabled auto-escaping, and any Jinja integration."]
  ],
  "Flask/Werkzeug": [
    ["Debug exposure", "Confirm debug tooling is disabled or access-controlled in production. Do not attempt debugger PIN bypass or command execution."],
    ["SSTI", "Review user-controlled input passed into template construction. Only use harmless arithmetic confirmation in an explicitly approved test environment."],
    ["Authorization / IDOR / MFLAC", "Verify explicit per-route and per-object permission checks."],
    ["Session security", "Review cookie flags and signing configuration without attempting forgery."]
  ],
  "Laravel": [
    ["Authorization / IDOR / MFLAC", "Review policies, gates, per-object authorization, and mass-assignment allowlists."],
    ["SQLi / XSS", "Review raw query methods and unescaped template output for untrusted input."],
    ["Debug exposure", "Check whether debug/profiling tools are publicly reachable; do not retrieve secret-bearing output or invoke execution features."],
    ["Sensitive-file exposure", "Review deployment configuration and backup exposure from authorized artifacts; do not download secrets."]
  ],
  "Ruby on Rails": [
    ["Authorization / IDOR / MFLAC", "Review controller actions and per-record authorization with separate authorized test users."],
    ["Mass assignment", "Check strong-parameter allowlists for sensitive attributes."],
    ["SQLi / SSTI", "Review raw SQL and runtime template evaluation for untrusted input."],
    ["Deserialization", "Review session and object deserialization choices from source/config evidence; avoid gadget payloads."]
  ],
  "ASP.NET Core": [
    ["Authorization / IDOR / MFLAC", "Verify authorization policies and resource-based checks are applied consistently."],
    ["LFI / path traversal", "Review user-controlled paths in file handlers for canonicalization and access checks."],
    ["SQLi", "Review raw SQL and dynamic query construction for untrusted concatenation."],
    ["CSRF / deserialization", "Check anti-forgery validation on cookie-authenticated changes and review unsafe legacy serialization paths."]
  ],
  "Spring Boot": [
    ["Access control", "Check management endpoints and API documentation are intentionally exposed and properly access-controlled."],
    ["Authorization / IDOR / MFLAC", "Verify method-level and endpoint-level authorization on mapped routes."],
    ["SQLi / SSTI", "Review raw SQL and expression evaluation using code/config evidence."],
    ["Deserialization", "Review polymorphic deserialization configuration and input trust boundaries; do not submit gadget payloads."]
  ],
  "FastAPI": [
    ["API authorization / IDOR", "Review every route's authentication and object-level authorization dependencies."],
    ["Schema exposure", "Confirm OpenAPI paths, methods, and examples are intended for public access."],
    ["CSRF", "If cookies authenticate API requests, verify server-side CSRF protection for state changes."],
    ["SQLi / SSRF", "Review raw query construction and user-controlled outbound URL flows."]
  ],
  "NestJS": [
    ["Authorization / IDOR / MFLAC", "Verify guards and role checks cover every controller action and resolver."],
    ["Mass assignment", "Review DTO validation, property whitelisting, and rejection of unexpected fields."],
    ["SQLi / SSRF", "Review raw ORM queries and webhook or URL-fetch features for untrusted input."],
    ["GraphQL access control", "If present, verify resolver-level authorization and query depth/complexity limits."]
  ],
  "Symfony": [
    ["Debug/profiler exposure", "Confirm profiler and debug routes are disabled or protected in production; do not retrieve session or query details."],
    ["Authorization / IDOR", "Review voters and per-resource authorization."],
    ["SQLi / XSS / SSTI", "Review raw Doctrine queries, Twig raw output, and runtime template construction."],
    ["Sensitive-file exposure", "Review deployment and backup exposure from authorized artifacts; redact secrets."]
  ],
  "Go web framework": [
    ["LFI / path traversal", "Review path joins and file-serving handlers for canonicalization and root-prefix enforcement."],
    ["Authorization / IDOR / MFLAC", "Verify per-resource checks on every handler."],
    ["XSS", "Confirm html/template is used for HTML and user data is not treated as trusted template source."],
    ["SSRF", "Review user-controlled URLs passed to HTTP clients."]
  ],
  "Apache Struts": [
    ["OGNL/expression injection", "Review expression evaluation, parameter binding, and deployed version from authorized source/config evidence; do not use command-execution payloads."],
    ["Authorization", "Verify route and action authorization is applied consistently."],
    ["Dependency hygiene", "Compare the exact deployed version with vendor advisories before reporting exposure."]
  ],
  "ColdFusion": [
    ["Admin/debug exposure", "Confirm administrative and diagnostic surfaces are intentionally exposed and access-controlled; do not attempt default credentials or execution."],
    ["File handling / path traversal", "Review upload, download, and template paths for canonicalization and authorization."],
    ["Dependency hygiene", "Identify the exact deployed version from authorized evidence and verify applicable advisories."]
  ],
  "WordPress": [
    ["REST API authorization / IDOR", "Review permission callbacks and object ownership for REST routes and custom post types using dedicated test records."],
    ["Plugin and theme exposure", "Identify disclosed component versions from authorized assets and compare them with vendor advisories; do not assume a version string proves vulnerability."],
    ["Access control", "Check that admin, editor, and public capabilities are enforced server-side for each action."]
  ],
  "Shopify": [
    ["Storefront and customer authorization", "Verify customer-owned orders, profiles, and files are isolated between dedicated test accounts."],
    ["App proxy and integration access", "Review proxy signature validation, tenant binding, and least-privilege scopes from authorized configuration evidence."],
    ["Theme DOM XSS", "Trace untrusted storefront values into Liquid output and client-side DOM sinks; verify encoding with harmless markers."]
  ],
  "Magento / Adobe Commerce": [
    ["REST / GraphQL authorization", "Verify ACL and object-level checks for each exposed API operation and store scope using test records."],
    ["Admin and extension exposure", "Review intended access to admin routes and extension versions without trying default credentials or retrieving configuration secrets."],
    ["Mass assignment", "Check that API input cannot change privileged customer, order, or role fields outside the caller's permissions."]
  ],
  "Drupal": [
    ["Route and entity access", "Verify route access callbacks and entity ownership checks for JSON:API and custom routes."],
    ["File access", "Check private-file downloads and media permissions with dedicated test files."],
    ["Configuration exposure", "Review public diagnostics and deployment artifacts without retrieving secret-bearing files."]
  ],
  "Adobe Experience Manager": [
    ["Repository and dispatcher access", "Review publish/author separation, dispatcher filters, and repository ACLs from approved configuration evidence."],
    ["Servlet and JSON authorization", "Verify custom Sling servlet and model endpoints enforce resource-level access checks."],
    ["Client library exposure", "Check that source maps and client libraries contain no secrets or internal-only data."]
  ],
  "Salesforce Lightning": [
    ["Apex authorization", "Verify sharing mode plus object and field-level security in Apex controllers using test users and records."],
    ["Aura / Lightning data access", "Check server-side authorization for each component action; hidden UI controls do not enforce access."],
    ["Guest and portal access", "Review guest-user and community permissions for unintended record exposure."]
  ],
  "Microsoft Dynamics 365": [
    ["Dataverse row and function access", "Verify table privileges, ownership, and role-based access through the Web API with dedicated test accounts."],
    ["OData input handling", "Review filters, expansions, and paging for server-side validation and bounded query behavior."],
    ["Custom actions", "Confirm custom APIs and workflow actions enforce caller privileges independently of client forms."]
  ],
  "Odoo": [
    ["Model ACL and record rules", "Verify RPC and portal access respects model permissions and per-record rules for test users."],
    ["Mass assignment", "Check that public or portal inputs cannot set privileged model fields."],
    ["File access", "Review attachment download authorization and tenant separation using test files."]
  ],
  "Strapi": [
    ["Content-type authorization", "Verify role permissions and policies for every REST and GraphQL content operation."],
    ["Object authorization", "Check ownership and tenant boundaries on content IDs with dedicated test records."],
    ["Input validation", "Review schema validation and unexpected writable fields without sending state-changing payloads."]
  ],
  "Apollo GraphQL": [
    ["Resolver authorization", "Check authentication and object-level permissions at resolver boundaries, including nested fields."],
    ["Query resource limits", "Review configured depth, complexity, batching, and persisted-query controls; do not submit stress queries."],
    ["Schema exposure", "Confirm schema and introspection visibility match the program's intended policy."]
  ],
  "Hasura": [
    ["Row and column permissions", "Verify role-based predicates and column allowlists for each table and relationship using test accounts."],
    ["Action and event authorization", "Check custom actions, remote schemas, and event triggers for caller and tenant checks."],
    ["Metadata exposure", "Review exposed metadata and console access without attempting administrative changes."]
  ],
  "tRPC": [
    ["Procedure authorization", "Verify protected procedures apply authentication and object-level checks, not only client-side route guards."],
    ["Input validation", "Review procedure schemas and authorization of sensitive fields using non-mutating test inputs."],
    ["Error disclosure", "Check that production errors do not expose stack traces or internal data."]
  ],
  "Supabase": [
    ["Row-level security", "Verify RLS policies for each exposed table and role using dedicated test accounts and owned records."],
    ["Storage authorization", "Check bucket policies and object ownership for test files; do not retrieve other users' objects."],
    ["Client key exposure", "Distinguish intended public keys from service-role credentials and review only authorized build artifacts."]
  ],
  "Firebase": [
    ["Security rules", "Test Firestore, Realtime Database, and Storage rules with separate authorized users and test records."],
    ["Callable functions", "Verify server-side authentication, role claims, and object ownership for each function."],
    ["Client configuration", "Treat public client configuration as identifiers; review actual data access through rules, not key visibility alone."]
  ],
  "PocketBase": [
    ["Collection rules", "Verify list, view, create, update, and delete rules for each collection with dedicated test records."],
    ["Record ownership", "Check that relation IDs cannot be changed to access another user's records."],
    ["Admin surface", "Confirm administrative routes remain access-controlled; do not attempt default credentials."]
  ],
  "Appwrite": [
    ["Document permissions", "Verify collection and document permissions across authorized roles and test users."],
    ["Function execution", "Check that server functions validate caller identity and tenant ownership."],
    ["Storage permissions", "Review bucket and file permissions using benign test files; avoid retrieving other users' data."]
  ],
  "Remix": [
    ["Loader and action authorization", "Verify each server loader and action checks authentication, role, and object ownership."],
    ["Cache isolation", "Check that user-specific loader data is not shared across sessions."],
    ["Input and redirect handling", "Review action schemas and redirect destination allowlists with non-mutating tests."]
  ],
  "SvelteKit": [
    ["Server load and action authorization", "Verify server-side loads, form actions, and API routes enforce user and record permissions."],
    ["Data serialization", "Review returned page data for private fields that should not reach the browser."],
    ["Origin and CSRF checks", "Check cookie-authenticated state changes enforce origin and CSRF protections."]
  ]
};

const commonIdeas = [
  ["XSS", "Review reflected, stored, and DOM data flows; use harmless markers and verify output encoding in an authorized test account."],
  ["LFI / path traversal", "Review file access and path normalization. Use only an approved benign canary file; avoid reading system or secret files."],
  ["SSTI", "Review whether untrusted input reaches template construction. Arithmetic-only confirmation is suitable only in an explicitly approved test environment."],
  ["CSRF", "For cookie-authenticated state changes, verify token validation, SameSite policy, and origin checks."],
  ["SQLi", "Review query construction for parameterization; use a controlled test environment and avoid destructive or blind payload spraying."],
  ["Parameter pollution", "Check how duplicate query or form keys are normalized and validated, using non-state-changing requests."],
  ["SSRF", "Review server-side URL fetches and allowlists; use only an assessor-controlled destination, never internal or metadata addresses."],
  ["IDOR / MFLAC", "Compare access to test records for insecure direct object references (IDOR), and check function access across authorized roles for missing function-level access control (MFLAC). Avoid real users' data."],
  ["Deserialization", "Review formats, libraries, and trust boundaries from authorized source/config evidence; do not submit gadget chains."],
  ["Lazy-loaded modules", "Enumerate discovered chunks and routes, then verify APIs enforce authorization independently of client-side route guards."],
  ["Configuration and diagnostic exposure", "Review discovered documentation, admin, and diagnostic routes for intended access controls; do not retrieve heap dumps, credentials, or secret files."],
  ["CORS, headers, and cookies", "Compare cross-origin policy and review CSP, HSTS, frame protections, cookie flags, and session rotation."],
  ["Open redirect", "Review redirect parameters and enforce a same-origin or explicit destination allowlist."],
  ["Business logic", "Test workflow and state transitions with dedicated test accounts and reversible actions."]
];

const genericConfigLeakPaths = [
  ["/.env", "Environment secrets (DB creds, API keys, APP_KEY)."],
  ["/.env.local", "Local environment override; often committed by mistake."],
  ["/.env.production", "Production secrets."],
  ["/.env.backup", "Backup of environment secrets."],
  ["/.git/config", "Exposed Git metadata; full source history can be dumped."],
  ["/.git/HEAD", "Exposed .git directory indicator."],
  ["/.svn/entries", "Exposed Subversion metadata."],
  ["/.DS_Store", "macOS directory listing leak."],
  ["/backup.zip", "Deployment backup archive."],
  ["/backup.sql", "Database backup."],
  ["/dump.sql", "Database dump."],
  ["/package.json", "Dependency and script inventory."],
  ["/composer.lock", "PHP dependency versions."],
  ["/Gemfile.lock", "Ruby dependency versions."],
  ["/requirements.txt", "Python dependency versions."],
  ["/Dockerfile", "Build/deploy configuration."],
  ["/docker-compose.yml", "Service topology and sometimes secrets."]
];

const genericDangerousEndpoints = [
  ["/admin/", "Generic admin panel; version disclosure on login."],
  ["/administrator/", "Admin panel (Joomla and others)."],
  ["/phpmyadmin/", "Database admin console; version-specific RCEs."],
  ["/adminer.php", "Single-file DB admin console."],
  ["/.well-known/security.txt", "Disclosure contact and policy."],
  ["/graphql", "GraphQL endpoint; test introspection and resolver authorization."],
  ["/graphiql", "GraphQL IDE; introspection surface."],
  ["/metrics", "Prometheus metrics; may leak internal URLs/hostnames."],
  ["/healthz", "Health endpoint; may leak build/version info."],
  ["/webhook/", "Generic SSRF/state-change surface."],
  ["/proxy/", "Generic SSRF surface."]
];

// Framework-specific recon endpoints, template engine (for SSTI leads), and
// deserialization markers from the TBHM cheat sheet. All are manual-review
// leads only: StackScope never fetches these, sends payloads, or reads values.
const frameworkRecon = {
  "Spring Boot": {
    recon: [
      ["/actuator/env", "Environment variables; credential goldmine."],
      ["/actuator/heapdump", "Full JVM heap dump (passwords, tokens)."],
      ["/actuator/configprops", "Resolved configuration properties."],
      ["/actuator/mappings", "All request mappings (route map)."],
      ["/actuator/jolokia/list", "JMX over HTTP; MBean manipulation can reach RCE."],
      ["/h2-console", "Exposed H2 console can reach RCE."],
      ["/swagger-ui.html", "API explorer."],
      ["/v3/api-docs", "OpenAPI schema."],
      ["/error?trace=true", "Stack-trace disclosure."]
    ],
    engine: { name: "FreeMarker / Thymeleaf / SpEL", test: "${7*7}", confirm: "Returns 49 (Java expression context).", note: "Spring4Shell (CVE-2022-22965) and SpEL injection live here." },
    deser: "Java ObjectOutputStream — Base64 rO0AB / hex AC ED 00 05 in cookies, session, or ViewState-like values."
  },
  "Ruby on Rails": {
    recon: [
      ["/rails/info/routes", "Full route list (development)."],
      ["/rails/info/properties", "Runtime properties (development)."],
      ["/assets/*.js.map", "Source maps for original source reconstruction."],
      ["/packs/*.js.map", "Webpacker source maps."]
    ],
    engine: { name: "ERB", test: "<%= 7*7 %>", confirm: "Returns 49 (Ruby).", note: "ERB.new(input).result and render inline: are the classic sinks." },
    deser: "Ruby Marshal — Base64 BAg / magic \\x04\\x08; also YAML !ruby/object in legacy session cookies (CVE-2022-32224)."
  },
  "Django": {
    recon: [
      ["/admin/", "Admin login leaks Django version."],
      ["/admin/login/?next=/", "Admin login."],
      ["/__debug__/", "django-debug-toolbar (SQL, settings, templates)."],
      ["/silk/", "django-silk profiler."],
      ["/api/schema/swagger-ui/", "DRF + drf-spectacular schema."],
      ["/static/admin/", "Admin static assets confirm Django."]
    ],
    engine: { name: "Jinja2 (if integrated)", test: "{{7*7}}", confirm: "Returns 49 only where Jinja2 is used; Django templates are restricted.", note: "SSTI appears when Jinja2 is added alongside Django." },
    deser: "Python pickle — Base64 gAR / gAN; pickle session backend + SECRET_KEY leak = RCE."
  },
  "Laravel": {
    recon: [
      ["/.env", "Laravel secrets incl. APP_KEY (session forgery / RCE)."],
      ["/storage/logs/laravel.log", "Application log; frequent info leak."],
      ["/telescope", "Telescope debug UI; massive info leak in prod."],
      ["/horizon", "Queue dashboard."],
      ["/_ignition/execute-solution", "Ignition RCE (CVE-2021-3129)."],
      ["/debugbar/open", "Laravel Debugbar."],
      ["/api/documentation", "L5-Swagger docs."]
    ],
    engine: { name: "Blade", test: "{{ 7*7 }}", confirm: "Blade escapes by default; {!! !!} is the raw sink.", note: "SSTI is low-likelihood; focus on {!! !!} raw output." },
    deser: "PHP serialize() — O:{len}:\"...\" / a:{len}: in cookies/session; APP_KEY leak + unserialize = RCE (CVE-2018-15133)."
  },
  "Next.js": {
    recon: [
      ["/_next/static/chunks/", "Chunk bundles; often contain API routes and env vars."],
      ["/_next/image?url=", "Image optimizer; SSRF if domain allowlist is weak."],
      ["/api/auth/", "NextAuth endpoints."],
      ["/_next/data/", "getServerSideProps/getStaticProps JSON data."]
    ],
    engine: null,
    deser: "NEXT_PUBLIC_* env vars leak to the client; review middleware auth bypass (CVE-2025-29927) and Server Actions SSRF (CVE-2024-34351)."
  },
  "ASP.NET Core": {
    recon: [
      ["/swagger", "Swagger UI."],
      ["/swagger/v1/swagger.json", "OpenAPI schema."],
      ["/healthchecks-ui", "Health dashboard."],
      ["/hangfire", "Background-job dashboard; often unauth by default."],
      ["/appsettings.Production.json", "Production configuration if served."]
    ],
    engine: { name: "Razor", test: "@(7*7)", confirm: "Returns 49 only with runtime compilation (rare).", note: "Classic runtime SSTI is effectively absent unless RazorLight-style runtime compilation is used." },
    deser: ".NET BinaryFormatter — Base64 AAEAAAD///// in __VIEWSTATE/cookies; LosFormatter/ObjectStateFormatter variants."
  },
  "Flask/Werkzeug": {
    recon: [
      ["/console", "Werkzeug debugger (DEBUG=True) — direct RCE if PIN guessed."],
      ["/admin/", "Flask-Admin."],
      ["/api/docs", "Flask-RESTX docs."]
    ],
    engine: { name: "Jinja2", test: "{{7*7}}", confirm: "Returns 49; {{7*'7'}} returns 7777777.", note: "render_template_string(user_input) is a well-known RCE primitive." },
    deser: "Python pickle — gAR / gAN in pickle-based sessions; SECRET_KEY leak = session forgery."
  },
  "FastAPI": {
    recon: [
      ["/docs", "Swagger UI."],
      ["/redoc", "ReDoc."],
      ["/openapi.json", "Schema — check even when /docs is disabled."],
      ["/health", "Health endpoint."],
      ["/metrics", "Prometheus metrics."]
    ],
    engine: { name: "Jinja2 (if templating used)", test: "{{7*7}}", confirm: "Only where fastapi.templating/Jinja2 is used.", note: "Most FastAPI apps are JSON APIs with no templating." },
    deser: "No built-in CSRF for cookie auth; review JWT (alg:none / weak secret) and raw SQLAlchemy text()."
  },
  "NestJS": {
    recon: [
      ["/api", "Common global prefix."],
      ["/api-docs", "SwaggerModule docs."],
      ["/graphql", "GraphQLModule; test introspection."],
      ["/health", "Terminus health module."]
    ],
    engine: null,
    deser: "node-serialize marker _$$ND_FUNC$$_ if that library is used; ValidationPipe without whitelist:true enables mass assignment."
  },
  "Nuxt.js": {
    recon: [
      ["/_nuxt/", "Static assets; check for source maps."],
      ["/api/_content/", "@nuxt/content query endpoint."],
      ["/__nuxt_devtools__/", "Dev tools, sometimes leaked in prod."],
      ["/server/api/", "Server route surface to enumerate."]
    ],
    engine: null,
    deser: "runtimeConfig.public leaks; SSR __NUXT__ hydration data often leaks API responses and user data."
  },
  "Go web framework": {
    recon: [
      ["/debug/pprof/", "Go profiler; goroutine/heap/CPU dumps leak memory."],
      ["/debug/pprof/heap", "Heap profile."],
      ["/metrics", "Prometheus metrics."],
      ["/swagger/index.html", "swaggo docs."]
    ],
    engine: { name: "text/template vs html/template", test: "{{7*7}}", confirm: "Returns 49 when template string is user-controlled.", note: "Importing text/template instead of html/template causes XSS/SSTI." },
    deser: "encoding/xml XXE and json.Unmarshal type confusion; no deserialization magic bytes on the wire."
  },
  "Symfony": {
    recon: [
      ["/_profiler/", "Profiler — full request/response/SQL/session access."],
      ["/_profiler/phpinfo", "phpinfo via profiler."],
      ["/app_dev.php", "Legacy dev front controller."],
      ["/_fragment", "ESI fragment; RCE via _controller if unsigned."]
    ],
    engine: { name: "Twig", test: "{{7*7}}", confirm: "Returns 49; {{7*'7'}} returns 49 (vs 7777777 for Jinja2).", note: "Twig SSTI via user input in template strings." },
    deser: "PHP serialize() — O:/a: markers; CVE-2019-10912 PhpBridgeSessionStorage deserialization."
  },
  "Apache Struts": {
    recon: [
      ["/index.action", "Struts action endpoint; test OGNL vectors manually."],
      ["/struts/webconsole.html", "Struts console if enabled."]
    ],
    engine: { name: "OGNL", test: "${7*7} / %{7*7}", confirm: "OGNL evaluation in parameter names, Content-Type, or namespace.", note: "Signature RCE class: CVE-2017-5638, CVE-2018-11776, CVE-2020-17530." },
    deser: "Java XStream (REST plugin, CVE-2017-9805) and ObjectOutputStream rO0AB values."
  },
  "ColdFusion": {
    recon: [
      ["/CFIDE/administrator/", "Admin panel; multiple unauth RCEs."],
      ["/CFIDE/administrator/enter.cfm", "Admin login."],
      ["/CFIDE/adminapi/", "Admin API."],
      ["/CFIDE/componentutils/", "Component utilities."],
      ["/cf_scripts/", "CF script assets confirm ColdFusion."]
    ],
    engine: { name: "CFML", test: "#7*7#", confirm: "CFML tag/expression evaluation on user input.", note: "SSRF via <cfhttp>, LFI via <cffile>/<cfinclude>." },
    deser: "Java deserialization in CF runtime; CVE-2023-26360 access-control bypass + RCE."
  },
  "Express.js": {
    recon: [
      ["/api-docs", "swagger-jsdoc/OpenAPI docs if mounted."]
    ],
    engine: { name: "EJS / Handlebars / Pug", test: "{{7*7}} or <%= 7*7 %> or #{7*7}", confirm: "Depends on the view engine in use.", note: "Handlebars/EJS SSTI when a template engine renders unsanitized input." },
    deser: "node-serialize marker _$$ND_FUNC$$_ if that library is used."
  },
  "Node.js": {
    recon: [],
    engine: { name: "EJS / Pug / Handlebars", test: "<%= 7*7 %> / #{7*7} / {{7*7}}", confirm: "Depends on the template engine.", note: "Dynamic template rendering on user input is the sink." },
    deser: "node-serialize marker _$$ND_FUNC$$_ if that library is used."
  }
};

// Frameworks that imply a specific config/leak path worth adding to the hunt list.
const frameworkConfigLeaks = {
  "Ruby on Rails": [["/config/master.key", "Decrypts credentials.yml.enc = full compromise."], ["/config/database.yml", "Database credentials."]],
  "Django": [["/settings.py", "Django settings incl. SECRET_KEY if served."], ["/local_settings.py", "Local settings override."]],
  "Laravel": [["/.env.backup", "Backup of Laravel secrets."], ["/composer.json", "Dependency inventory."]],
  "WordPress": [["/wp-config.php", "WordPress DB creds and keys."], ["/wp-config.php.bak", "Backup of wp-config."]],
  "Drupal": [["/sites/default/settings.php", "Drupal DB creds."]],
  "Joomla": [["/configuration.php", "Joomla configuration."]],
  "Spring Boot": [["/application.properties", "Spring configuration."], ["/application-prod.yml", "Production profile config."]],
  "ASP.NET Core": [["/web.config", "IIS configuration."], ["/appsettings.json", "Application configuration."]]
};

function buildReconChecklist(fingerprints) {
  const names = (fingerprints || []).map(item => item.name);
  const reconSeen = new Set();
  const reconEndpoints = [];
  const engineHints = [];
  const engineSeen = new Set();
  const deserHints = [];
  const deserSeen = new Set();
  const configSeen = new Set();
  const configLeaks = [];
  const dangerousEndpoints = genericDangerousEndpoints.map(([path, why]) => ({ path, why }));
  for (const [path, why] of genericConfigLeakPaths) {
    if (configSeen.has(path)) continue;
    configSeen.add(path);
    configLeaks.push({ path, why, framework: "General" });
  }
  for (const name of names) {
    const entry = frameworkRecon[name];
    if (entry) {
      for (const [path, why] of entry.recon || []) {
        const key = `${path}|${why}`;
        if (reconSeen.has(key)) continue;
        reconSeen.add(key);
        reconEndpoints.push({ framework: name, path, why });
      }
      if (entry.engine && !engineSeen.has(entry.engine.name)) {
        engineSeen.add(entry.engine.name);
        engineHints.push({ framework: name, ...entry.engine });
      }
      if (entry.deser && !deserSeen.has(entry.deser)) {
        deserSeen.add(entry.deser);
        deserHints.push({ framework: name, note: entry.deser });
      }
    }
    for (const [path, why] of frameworkConfigLeaks[name] || []) {
      if (configSeen.has(path)) continue;
      configSeen.add(path);
      configLeaks.push({ path, why, framework: name });
    }
  }
  return { reconEndpoints, configLeaks, dangerousEndpoints, engineHints, deserHints };
}

function normalizeModulePath(value) {
  const raw = String(value || "").trim();
  if (!raw.startsWith("/") || raw.startsWith("//") || /[?#\\\u0000-\u001f]/.test(raw)) {
    throw new Error("Module path must be an origin-relative path such as /portal/; query strings and fragments are not allowed.");
  }
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch (_) { throw new Error("Module path contains invalid percent encoding."); }
  if (decoded.split("/").some(part => part === "." || part === "..")) {
    throw new Error("Module path cannot contain dot segments.");
  }
  const normalized = new URL(raw, "https://scope.invalid").pathname;
  if (normalized === "/") throw new Error("Use Whole current origin mode to scan the entire origin.");
  return normalized.endsWith("/") ? normalized : `${normalized}/`;
}

function parseAuthorizedAssetOrigins(value, appOrigin) {
  const entries = String(value || "").split(/[\s,;]+/).map(item => item.trim()).filter(Boolean);
  if (entries.length > 20) throw new Error("Enter no more than 20 explicitly authorized asset origins.");
  const origins = new Set();
  for (const entry of entries) {
    let url;
    try { url = new URL(entry); } catch (_) { throw new Error(`Invalid asset origin: ${entry}`); }
    if (!/^https?:$/.test(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
      throw new Error(`Use an exact origin only, such as https://assets.example.com: ${entry}`);
    }
    if (url.origin !== appOrigin) origins.add(url.origin);
  }
  return [...origins];
}

function parseImportAliases(value, appOrigin) {
  const aliases = [];
  const entries = String(value || "").split(/[;\n]+/).map(entry => entry.trim()).filter(Boolean);
  if (entries.length > 50) throw new Error("Enter no more than 50 JavaScript import aliases.");
  for (const entry of entries) {
    const separator = entry.indexOf("=");
    if (separator < 1) throw new Error(`Use alias mappings such as @/=/src/: ${entry}`);
    const alias = entry.slice(0, separator).trim();
    const target = entry.slice(separator + 1).trim();
    if (!/^[A-Za-z0-9_@~./-]+\/$/.test(alias) || !target.startsWith("/") || target.startsWith("//") || /[?#\\\u0000-\u001f]/.test(target)) {
      throw new Error(`Use a slash-terminated import prefix and an origin-relative target: ${entry}`);
    }
    const normalizedTarget = new URL(target, appOrigin).pathname;
    aliases.push({ alias, target: normalizedTarget.endsWith("/") ? normalizedTarget : `${normalizedTarget}/` });
  }
  return [...new Map(aliases.map(item => [item.alias, item])).values()].sort((a, b) => b.alias.length - a.alias.length);
}

function parseApiPrefixes(value) {
  const entries = String(value || "").split(/[\s,;]+/).map(item => item.trim()).filter(Boolean);
  if (entries.length > 100) throw new Error("Enter no more than 100 API path prefixes.");
  const prefixes = [];
  for (const entry of entries) {
    if (entry.startsWith("//") || /[?#\\\u0000-\u001f]/.test(entry)) throw new Error(`Use an origin-relative API prefix such as /portal/data/: ${entry}`);
    const path = entry.startsWith("/") ? entry : `/${entry}`;
    const normalized = new URL(path, "https://scope.invalid").pathname;
    if (normalized === "/" || normalized.split("/").some(part => part === "." || part === "..")) throw new Error(`API prefix must identify a path below /: ${entry}`);
    prefixes.push(normalized.endsWith("/") ? normalized : `${normalized}/`);
  }
  return [...new Set(prefixes)];
}

function resolveImportSpecifier(specifier, sourceUrl, importMaps, importAliases, appOrigin = null) {
  const value = String(specifier || "").trim();
  if (/^(?:https?:)?\/\//i.test(value) || value.startsWith("/") || value.startsWith("./") || value.startsWith("../")) return cleanUrl(value, sourceUrl);
  for (const map of importMaps || []) {
    const imports = map.imports || {};
    if (Object.hasOwn(imports, value)) return cleanUrl(imports[value], map.base || sourceUrl);
    const prefix = Object.keys(imports).filter(key => key.endsWith("/") && value.startsWith(key)).sort((a, b) => b.length - a.length)[0];
    if (prefix) return cleanUrl(`${imports[prefix]}${value.slice(prefix.length)}`, map.base || sourceUrl);
  }
  const alias = (importAliases || []).find(item => value.startsWith(item.alias));
  if (alias) return cleanUrl(`${alias.target}${value.slice(alias.alias.length)}`, appOrigin || sourceUrl);
  return null;
}

function importMapCandidatesFromDocument(doc, baseUrl) {
  return [...doc.querySelectorAll('script[type="importmap"]')].slice(0, 10).map(element => ({ base: baseUrl, source: String(element.textContent || "").slice(0, 100_000) }));
}

function cleanUrl(raw, base) {
  try {
    const url = new URL(raw, base);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) return null;
    url.hash = "";
    return url.href;
  } catch (_) {
    return null;
  }
}

function isOpaqueCredentialValue(value) {
  return /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?$/.test(value) || /^[A-Za-z0-9_-]{16,}$/.test(value);
}

function reportUrl(raw) {
  try {
    const url = new URL(raw);
    url.username = "";
    url.password = "";
    url.hash = "";
    const pathParts = url.pathname.split("/");
    const credentialSegment = /^(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|session[_-]?(?:id|token)|secret|password|jwt|api[_-]?key|access[_-]?key|private[_-]?key)$/i;
    for (let index = 1; index < pathParts.length; index += 1) {
      let previous;
      let current;
      try { previous = decodeURIComponent(pathParts[index - 1]); } catch (_) { continue; }
      try { current = decodeURIComponent(pathParts[index]); } catch (_) { continue; }
      if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?$/.test(current) || (credentialSegment.test(previous) && isOpaqueCredentialValue(current))) pathParts[index] = "[redacted]";
    }
    url.pathname = pathParts.join("/");
    const names = [...url.searchParams.keys()];
    if (names.length) {
      url.search = "";
      for (const name of names) url.searchParams.append(name, "[redacted]");
    }
    return url.href;
  } catch (_) {
    return String(raw);
  }
}

function redactedPathname(rawPath, origin) {
  try {
    const url = new URL(String(rawPath || "/"), origin);
    return new URL(reportUrl(url.href)).pathname;
  } catch (_) { return "/"; }
}

function mergeObservedTraffic(reportItems, activeItems) {
  const merged = new Map();
  const lists = [reportItems, activeItems];
  for (const items of lists) {
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      if (!item || typeof item !== "object" || typeof item.url !== "string") continue;
      const url = reportUrl(item.url);
      const method = String(item.method || "GET").toUpperCase();
      const transport = String(item.transport || "http");
      let pagePath = "";
      try { pagePath = redactedPathname(item.pagePath || item.moduleControl?.pagePath || new URL(url).pathname, new URL(url).origin); } catch (_) { /* invalid metadata is filtered by the report sanitizer */ }
      const key = JSON.stringify([
        method, transport, url, Number(item.at) || 0, Number(item.status) || 0,
        Array.isArray(item.parameterNames) ? item.parameterNames : [],
        pagePath,
        String(item.moduleControl?.label || "")
      ]);
      // Prefer the live record when it matches a record captured in the report.
      const safeItem = { ...item, url };
      if (pagePath) safeItem.pagePath = pagePath;
      if (item.moduleControl && typeof item.moduleControl === "object") safeItem.moduleControl = { ...item.moduleControl, pagePath };
      merged.set(key, safeItem);
    }
  }
  return [...merged.values()].slice(-TRAFFIC_ITEM_LIMIT);
}

function blockedRequestReason(rawUrl) {
  let url;
  try { url = new URL(rawUrl); } catch (_) { return "Invalid URL"; }
  let path;
  try { path = decodeURIComponent(url.pathname).toLowerCase(); } catch (_) { return "Ambiguous encoded path"; }
  if (path.split("/").some(segment => /^\d{5,}$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment))) {
    return "Concrete numeric or UUID path identifier; use an approved test record for manual review instead of fetching an embedded identifier.";
  }
  if (/(?:^|\/)(?:\.env(?:\.[^/]+)?|\.git(?:\/|$)|id_rsa(?:\.pub)?|authorized_keys|\.npmrc|\.pypirc|credentials|dump\.sql|db\.sql|database\.sql|backup\.(?:zip|sql|tar\.gz)|[^/]+\.(?:pem|key))(?:\/|$)/i.test(path)) {
    return "Potential credential, source, key, or database backup file";
  }
  if (/^\/actuator\/(?:env|heapdump|configprops|jolokia)(?:\/|$)/i.test(path) ||
      /^\/debug\/pprof(?:\/|$)/i.test(path) ||
      /(?:^|\/)(?:_profiler|telescope|debugbar|__debug__)(?:\/|$)/i.test(path) ||
      /^\/cfide\/administrator(?:\/|$)/i.test(path) ||
      /^\/manager\/html(?:\/|$)/i.test(path)) {
    return "Sensitive management or diagnostic endpoint; inspect manually";
  }
  if (/^\/_next\/image\/?$/i.test(path) && url.searchParams.has("url")) {
    return "Image optimizer URL can trigger server-side fetching; inspect manually";
  }
  if (/(?:^|\/)(?:proxy|webhook)(?:\/|$)/i.test(path)) {
    return "Proxy or webhook route can trigger outbound or stateful behavior; inspect manually";
  }
  if (/(?:^|\/)(?:logout|logoff|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger)(?:\/|$)/i.test(path)) {
    return "Potentially state-changing GET endpoint; inspect manually";
  }
  for (const key of ["action", "operation", "op", "cmd", "command"]) {
    const value = url.searchParams.get(key) || "";
    if (/^(?:logout|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger)$/i.test(value)) {
      return "Potentially state-changing GET action; inspect manually";
    }
  }
  if (hasCredentialQuery(url.href)) return "Credential-like URL parameter or path; inspect manually without automatic fetching";
  return null;
}

function hasCredentialQuery(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const sensitiveParam = [...url.searchParams.keys()].some(name => /(?:token|secret|password|passwd|authorization|session|jwt|signature|\bsig\b|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|credential|^auth$|^key$|^code$)/i.test(name));
    let sensitivePath = false;
    try {
      const pathParts = decodeURIComponent(url.pathname).split("/");
      const credentialSegment = /^(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|session[_-]?(?:id|token)|secret|password|jwt|api[_-]?key|access[_-]?key|private[_-]?key)$/i;
      sensitivePath = pathParts.some((segment, index) => credentialSegment.test(segment) && isOpaqueCredentialValue(pathParts[index + 1] || ""));
    } catch (_) { return true; }
    return sensitiveParam || sensitivePath;
  } catch (_) {
    return true;
  }
}

function isInScope(rawUrl, origin, mode, modulePath) {
  try {
    const url = new URL(rawUrl);
    if (url.origin !== origin || !["http:", "https:"].includes(url.protocol) || url.username || url.password) return false;
    if (mode === "site") return true;
    const rootPath = new URL(normalizeModulePath(modulePath), origin).pathname;
    const root = rootPath.endsWith("/") ? rootPath.slice(0, -1) : rootPath;
    const inside = path => path === root || path.startsWith(`${root}/`);
    let candidate = url.pathname;
    for (let depth = 0; depth < 5; depth += 1) {
      if (candidate.includes("\\") || /[\u0000-\u001f]/.test(candidate)) return false;
      let decoded;
      try { decoded = decodeURIComponent(candidate); } catch (_) { return false; }
      if (decoded.includes("\\") || /[\u0000-\u001f]/.test(decoded)) return false;
      const canonical = new URL(decoded, origin).pathname;
      if (!inside(canonical)) return false;
      if (decoded === candidate) return true;
      candidate = decoded;
    }
    return false;
  } catch (_) {
    return false;
  }
}

function earlyObserverMatchPatterns(origin, mode, modulePath) {
  const parsed = new URL(origin);
  // Firefox match patterns ignore ports. The background bridge validates the
  // exact tab origin before enabling collection.
  const authority = parsed.hostname;
  if (mode !== "module") return [`${parsed.protocol}//${authority}/*`];
  const root = normalizeModulePath(modulePath || "/");
  const prefix = root === "/" ? "/" : root.slice(0, -1);
  return [`${parsed.protocol}//${authority}${prefix}*`];
}

async function registerEarlyObserverScripts(tab, config) {
  const earlyConfig = { ...config, active: true };
  await browser.storage.local.set({ [EARLY_OBSERVER_CONFIG_KEY]: earlyConfig });
  if (!browser.scripting?.registerContentScripts || !browser.scripting?.unregisterContentScripts) return false;
  try {
    try { await browser.scripting.unregisterContentScripts({ ids: EARLY_OBSERVER_SCRIPT_IDS }); } catch (_) { /* no prior registration */ }
    const matches = earlyObserverMatchPatterns(config.origin, config.mode, config.modulePath);
    await browser.scripting.registerContentScripts([
      {
        id: EARLY_OBSERVER_SCRIPT_IDS[0], matches, js: ["early-observer-main.js"],
        runAt: "document_start", world: "MAIN", allFrames: false, persistAcrossSessions: false
      },
      {
        id: EARLY_OBSERVER_SCRIPT_IDS[1], matches, js: ["early-observer-bridge.js"],
        runAt: "document_start", world: "ISOLATED", allFrames: false, persistAcrossSessions: false
      }
    ]);
    return true;
  } catch (_) {
    await browser.storage.local.remove(EARLY_OBSERVER_CONFIG_KEY).catch(() => {});
    return false;
  }
}

async function unregisterEarlyObserverScripts(tabId) {
  let shouldUnregister = false;
  try {
    const stored = await browser.storage.local.get(EARLY_OBSERVER_CONFIG_KEY);
    const config = stored[EARLY_OBSERVER_CONFIG_KEY];
    if (!config || config.tabId === tabId) {
      if (config?.tabId === tabId) await browser.storage.local.remove(EARLY_OBSERVER_CONFIG_KEY);
      shouldUnregister = true;
    }
  } catch (_) { /* still attempt to remove dynamic scripts */ }
  if (shouldUnregister) {
    try { await browser.scripting.unregisterContentScripts({ ids: EARLY_OBSERVER_SCRIPT_IDS }); } catch (_) { /* registrations may be absent */ }
  }
}

function stopEarlyObserverInPage(channel) {
  window.postMessage({ __stackscopeEarlyStop: "v1", channel }, location.origin);
  const previous = window.__stackscopeEarlyObserver_v117;
  if (previous?.active) window.postMessage({ __stackscopeEarlyStop: "v1", channel: previous.config?.channel || null }, location.origin);
}

function isSameOriginUrl(rawUrl, origin) {
  try {
    const url = new URL(rawUrl);
    return url.origin === origin && ["http:", "https:"].includes(url.protocol) && !url.username && !url.password;
  } catch (_) {
    return false;
  }
}

function isInOriginList(rawUrl, origins) {
  try {
    const url = new URL(rawUrl);
    return origins.includes(url.origin) && ["http:", "https:"].includes(url.protocol) && !url.username && !url.password;
  } catch (_) { return false; }
}

function getQueryParameterNames(rawUrl) {
  try { return [...new Set([...new URL(rawUrl).searchParams.keys()].map(name => String(name).slice(0, 80)))].slice(0, 100); }
  catch (_) { return []; }
}

function parameterReviewIdea(name) {
  const key = String(name || "").toLowerCase().replace(/[^a-z0-9_]/g, "");
  if (/(?:^|_)(?:id|uid|user|account|client|insurer|order|lead|record|owner)(?:_|$)|^(?:id|uid)$|(?:user|account|client|insurer|order|lead|record|owner)(?:id|code|number)$/.test(key)) return "Authorization / IDOR: verify object access with two dedicated test accounts and owned test records.";
  if (/(?:redirect|return|next|continue|callback|target|url|uri)/.test(key)) return "Redirect / SSRF review: check server-side allowlists and redirect destinations with a controlled test target.";
  if (/(?:file|path|folder|document|upload|filename)/.test(key)) return "File handling review: verify type, size, storage path, and download authorization using harmless test files.";
  if (/(?:search|query|filter|sort|field|page|limit|skip|offset)/.test(key)) return "Input validation review: check bounds, duplicate keys, and server-side query handling without sending exploit payloads.";
  if (/(?:role|permission|scope|status|type|enabled|admin)/.test(key)) return "Function authorization / mass assignment review: confirm the server controls privileged fields and state transitions.";
  return "Validate server-side type, length, allowed values, and authorization with an approved test account; no value was submitted.";
}

function isLikelyApiEndpoint(rawUrl) {
  try {
    const path = decodeURIComponent(new URL(rawUrl).pathname).toLowerCase();
    return /(?:^|\/)(?:api|graphql|rest|rpc)(?:\/|$)/.test(path) || /(?:^|\/)[^/]*-api(?:\/|$)/.test(path) || /(?:^|\/)v\d+(?:\/|$)/.test(path);
  } catch (_) {
    return false;
  }
}

function matchesApiPrefix(rawUrl, prefixes) {
  try {
    const path = new URL(rawUrl).pathname;
    return (prefixes || []).some(prefix => path === prefix.slice(0, -1) || path.startsWith(prefix));
  } catch (_) { return false; }
}

function normalizedMediaType(contentType) {
  return String(contentType || "unknown").split(";", 1)[0].trim().toLowerCase() || "unknown";
}

function isHtmlDocument(contentType) {
  return /(?:^|\s|;)text\/html(?:\s|;|$)|application\/xhtml\+xml/i.test(String(contentType || ""));
}

function isActionableAnonymousComparison(item) {
  if (!item || typeof item !== "object") return false;
  const sessionStatus = Number(item.sessionStatus);
  const anonymousStatus = Number(item.anonymousStatus);
  const successfulSession = Number.isFinite(sessionStatus) && sessionStatus >= 200 && sessionStatus < 300;
  if (successfulSession && /without-cookie(?: GET| request)? redirected to (?:a )?(?:same-origin )?login\/auth route/i.test(String(item.outcome || ""))) return true;
  if (successfulSession && [401, 403].includes(anonymousStatus)) return true;
  if (!successfulSession || anonymousStatus !== 200) return false;
  if (isHtmlDocument(item.sessionType) || isHtmlDocument(item.anonymousType) || /HTML.*(?:shell|app\/login)|app\/login shell/i.test(String(item.outcome || ""))) return false;
  const sessionType = normalizedMediaType(item.sessionType);
  const anonymousType = normalizedMediaType(item.anonymousType);
  const typeDiffers = sessionType !== anonymousType;
  const sessionBytes = Number(item.sessionBytes);
  const anonymousBytes = Number(item.anonymousBytes);
  const sizeDiffers = Number.isFinite(sessionBytes) && Number.isFinite(anonymousBytes) && sessionBytes !== anonymousBytes;
  return item.selectedHeadersMatch === false || typeDiffers || sizeDiffers;
}

function looksLikeHtmlDocument(bodyText) {
  const prefix = String(bodyText || "").slice(0, 4096).replace(/^\uFEFF/, "").replace(/^(?:\s|<!--[\s\S]*?-->)+/, "");
  return /^(?:<!doctype\s+html\b|<html\b|<head\b|<body\b|<main\b|<div\b|<form\b)/i.test(prefix);
}

function isUsefulEndpoint(url, contentType, kind) {
  const type = String(contentType || "").toLowerCase();
  if (isHtmlDocument(type) || /^(?:image|font|audio|video)\//.test(type) || /^(?:text\/css|application\/javascript|text\/javascript)/.test(type)) return false;
  try {
    if (/\.(?:css|m?js|cjs|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|eot|pdf|zip|mp4|webm)(?:$|[?#])/i.test(new URL(url).href)) return false;
  } catch (_) { return false; }
  return kind === "endpoint" || isLikelyApiEndpoint(url) || /(?:application|text)\/(?:[^;]+\+)?json|graphql/i.test(type);
}

function extractUrls(text, base) {
  const found = new Set();
  const quoted = /["'`]((?:https?:)?\/\/[^"'`\s<>\\]+|\/[A-Za-z0-9_~!$&'()*+,;=:@%./?-]+)["'`]/g;
  const relativeRoute = /["'`]((?!\.\.?\/)(?:[A-Za-z0-9_~.-]+\/){1,8}[A-Za-z0-9_~!$&'()*+,;=:@%.-]*(?:\?[A-Za-z0-9_~!$&'()*+,;=:@%./?%-]*)?)["'`]/g;
  for (const re of [quoted, relativeRoute]) {
    let match;
    while ((match = re.exec(text)) !== null) {
      if (/\$\{|\{\{/.test(match[1])) continue;
      const preceding = text.slice(Math.max(0, match.index - 100), match.index);
      if (/(?:const|let|var)\s+[A-Za-z_$][\w$]*(?:BASE|HOST|ORIGIN|PREFIX|ROOT)[\w$]*\s*=\s*$/i.test(preceding)) continue;
      const url = cleanUrl(match[1], base);
      if (url) found.add(url);
    }
  }
  return [...found];
}

function extractSitemapLocations(text, base) {
  const found = new Set();
  for (const match of String(text || "").matchAll(/<loc\b[^>]*>([\s\S]*?)<\/loc\s*>/gi)) {
    const value = match[1].trim().replace(/^<!\[CDATA\[([\s\S]*?)\]\]>$/i, "$1").trim()
      .replace(/&amp;/gi, "&").replace(/&quot;/gi, "\"").replace(/&#39;|&apos;/gi, "'");
    const url = cleanUrl(value, base);
    if (url) found.add(url);
  }
  return [...found];
}

function extractRobotsSitemaps(text, base) {
  const found = new Set();
  for (const match of String(text || "").matchAll(/^\s*Sitemap\s*:\s*(\S+)/gim)) {
    const url = cleanUrl(match[1], base);
    if (url) found.add(url);
  }
  return [...found];
}

function splitTopLevel(expression, delimiter) {
  const parts = [];
  let start = 0;
  let quote = "";
  let escaped = false;
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = 0; index < expression.length; index += 1) {
    const char = expression[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = "";
      continue;
    }
    if (char === "\"" || char === "'" || char === "`") { quote = char; continue; }
    if (char === "(") round += 1;
    else if (char === ")") round = Math.max(0, round - 1);
    else if (char === "[") square += 1;
    else if (char === "]") square = Math.max(0, square - 1);
    else if (char === "{") curly += 1;
    else if (char === "}") curly = Math.max(0, curly - 1);
    else if (char === delimiter && round === 0 && square === 0 && curly === 0) {
      parts.push(expression.slice(start, index).trim());
      start = index + 1;
    }
  }
  parts.push(expression.slice(start).trim());
  return parts;
}

function readCallArguments(text, openIndex) {
  const args = [];
  let start = openIndex + 1;
  let quote = "";
  let escaped = false;
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = openIndex + 1; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = "";
      continue;
    }
    if (char === "\"" || char === "'" || char === "`") { quote = char; continue; }
    if (char === "(") round += 1;
    else if (char === ")") {
      if (round === 0 && square === 0 && curly === 0) {
        const last = text.slice(start, index).trim();
        if (last || args.length) args.push(last);
        return args;
      }
      round = Math.max(0, round - 1);
    } else if (char === "[") square += 1;
    else if (char === "]") square = Math.max(0, square - 1);
    else if (char === "{") curly += 1;
    else if (char === "}") curly = Math.max(0, curly - 1);
    else if (char === "," && round === 0 && square === 0 && curly === 0) {
      args.push(text.slice(start, index).trim());
      start = index + 1;
    }
  }
  return [];
}

function readBalancedBlock(text, openIndex, maxLength = 20_000) {
  const open = text[openIndex];
  const close = open === "{" ? "}" : open === "[" ? "]" : null;
  if (!close) return null;
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = openIndex; index < Math.min(text.length, openIndex + maxLength); index += 1) {
    const char = text[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === quote) quote = "";
      continue;
    }
    if (char === "\"" || char === "'" || char.charCodeAt(0) === 96) { quote = char; continue; }
    if (char === open) depth += 1;
    else if (char === close) {
      depth -= 1;
      if (depth === 0) return text.slice(openIndex, index + 1);
    }
  }
  return null;
}

function staticObjectProperties(source) {
  const properties = new Map();
  const body = String(source || "").trim().replace(/^\{/, "").replace(/\}$/, "");
  for (const property of splitTopLevel(body, ",")) {
    const match = property.match(/^(?:["']([^"']+)["']|([A-Za-z_$][\w$]*))\s*:\s*([\s\S]+)$/);
    if (match) properties.set(match[1] || match[2], match[3].trim());
  }
  return properties;
}

function decodeJsStringLiteral(expression) {
  const quote = expression[0];
  const body = expression.slice(1, -1);
  if (quote === "\"") {
    try { return JSON.parse(expression); } catch (_) { return body.replace(/\\([\\"/bfnrt])/g, "$1"); }
  }
  return body.replace(/\\([\\'`])/g, "$1").replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t");
}

function collectStaticJsSymbols(text, baseUrl) {
  const aliases = new Map();
  const functions = new Map();
  const objects = new Map();
  const literalPattern = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)/g;
  let match;
  while ((match = literalPattern.exec(text)) !== null) aliases.set(match[1], match[2]);
  const simpleFunctionPattern = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)?\s*\)\s*\{[^{}]{0,5000}?\breturn\s+([^;{}]+);?[^{}]*\}/g;
  while ((match = simpleFunctionPattern.exec(text)) !== null) functions.set(match[1], { parameter: match[2] || "", expression: match[3].trim() });
  const objectPattern = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{/g;
  while ((match = objectPattern.exec(text)) !== null) {
    const block = readBalancedBlock(text, text.indexOf("{", match.index), 20_000);
    if (block) objects.set(match[1], staticObjectProperties(block));
  }
  const symbols = { aliases, functions, objects };
  const expressionPattern = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,500})/g;
  for (let pass = 0; pass < 5; pass += 1) {
    let changed = false;
    expressionPattern.lastIndex = 0;
    while ((match = expressionPattern.exec(text)) !== null) {
      if (match[2].includes("=>") || /\b(?:function|await|yield|new\s+Promise)\b/.test(match[2])) continue;
      const resolved = resolveStaticJsExpression(match[2].trim().replace(/,$/, ""), symbols, baseUrl);
      if (resolved.value !== null && !resolved.dynamic && aliases.get(match[1]) !== JSON.stringify(resolved.value)) {
        aliases.set(match[1], JSON.stringify(resolved.value));
        changed = true;
      }
    }
    if (!changed) break;
  }
  return symbols;
}

function resolveStaticJsExpression(expression, symbols, baseUrl, depth = 0) {
  if (depth > 8) return { value: null, dynamic: false };
  let source = String(expression || "").trim();
  if (!source) return { value: null, dynamic: false };
  const literal = source.match(/^("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)$/);
  if (literal) {
    const raw = decodeJsStringLiteral(literal[0]);
    if (literal[0][0] !== "`") return { value: raw, dynamic: false };
    let dynamic = false;
    const value = raw.replace(/\$\{([^}]{1,200})\}/g, (_all, inner) => {
      const resolved = resolveStaticJsExpression(inner, symbols, baseUrl, depth + 1);
      if (resolved.value !== null && !resolved.dynamic) return resolved.value;
      dynamic = true;
      return `STACKSCOPE_PARAM_${String(inner).replace(/[^A-Za-z0-9_]/g, "_")}`;
    });
    return { value, dynamic };
  }
  const urlCall = source.match(/^new\s+URL\s*\(([\s\S]*)\)$/);
  if (urlCall) {
    const args = splitTopLevel(urlCall[1], ",");
    if (args.length >= 2) {
      const path = resolveStaticJsExpression(args[0], symbols, baseUrl, depth + 1);
      const base = resolveStaticJsExpression(args[1], symbols, baseUrl, depth + 1);
      if (path.value !== null && base.value !== null) {
        try { return { value: new URL(path.value, base.value).href, dynamic: path.dynamic || base.dynamic }; } catch (_) { return { value: null, dynamic: false }; }
      }
    }
    return { value: null, dynamic: false };
  }
  const call = source.match(/^([A-Za-z_$][\w$]*)\s*\(([\s\S]*)\)$/);
  if (call && symbols.functions.has(call[1])) {
    const fn = symbols.functions.get(call[1]);
    const args = splitTopLevel(call[2], ",");
    const alias = new Map(symbols.aliases);
    if (fn.parameter && args[0]) alias.set(fn.parameter, args[0]);
    return resolveStaticJsExpression(fn.expression, { ...symbols, aliases: alias }, baseUrl, depth + 1);
  }
  if (symbols.aliases.has(source)) return resolveStaticJsExpression(symbols.aliases.get(source), symbols, baseUrl, depth + 1);
  const objectProperty = source.match(/^([A-Za-z_$][\w$]*)\.(url|uri|endpoint|baseURL|baseUrl|method)$/);
  if (objectProperty) {
    const property = symbols.objects?.get(objectProperty[1])?.get(objectProperty[2]);
    if (property) return resolveStaticJsExpression(property, symbols, baseUrl, depth + 1);
  }
  const concat = splitTopLevel(source, "+");
  if (concat.length > 1) {
    let value = "";
    let dynamic = false;
    for (const part of concat) {
      const resolved = resolveStaticJsExpression(part, symbols, baseUrl, depth + 1);
      if (resolved.value === null) return { value: null, dynamic: false };
      value += resolved.value;
      dynamic ||= resolved.dynamic;
    }
    return { value, dynamic };
  }
  return { value: null, dynamic: false };
}

function extractApiCallTargets(text, base) {
  const symbols = collectStaticJsSymbols(text, base);
  const targets = new Map();
  const add = (method, expression) => {
    const resolved = resolveStaticJsExpression(expression, symbols, base);
    if (!resolved.value) return;
    const url = cleanUrl(resolved.value, base);
    if (url) targets.set(url, { url, method: String(method || "UNKNOWN").toUpperCase(), dynamic: resolved.dynamic, expression: resolved.value });
  };
  const fetchPattern = /\bfetch\s*\(/gi;
  let match;
  while ((match = fetchPattern.exec(text)) !== null) {
    const open = text.indexOf("(", match.index);
    const args = readCallArguments(text, open);
    if (!args[0]) continue;
    let method = "GET";
    if (args[1]) {
      if (!args[1].trim().startsWith("{")) method = "UNKNOWN";
      else method = args[1].match(/\bmethod\s*:\s*["'`]([A-Za-z]+)["'`]/i)?.[1] || "GET";
    }
    if (args[1] && !args[1].trim().startsWith("{")) {
      const initName = args[1].trim().match(/^([A-Za-z_$][\w$]*)$/)?.[1];
      const methodExpression = symbols.objects.get(initName)?.get("method");
      if (methodExpression) method = resolveStaticJsExpression(methodExpression, symbols, base).value || "UNKNOWN";
    }
    add(method, args[0]);
  }
  const axiosPattern = /\baxios\.(get|post|put|patch|delete|head|options)\s*\(/gi;
  while ((match = axiosPattern.exec(text)) !== null) {
    const args = readCallArguments(text, text.indexOf("(", match.index));
    if (args[0]) add(match[1], args[0]);
  }
  const xhrPattern = /\.open\s*\(/gi;
  while ((match = xhrPattern.exec(text)) !== null) {
    const args = readCallArguments(text, text.indexOf("(", match.index));
    if (args.length > 1) add(resolveStaticJsExpression(args[0], symbols, base).value || "UNKNOWN", args[1]);
  }
  const configPattern = /\b(?:axios|request)\s*\(/gi;
  while ((match = configPattern.exec(text)) !== null) {
    const args = readCallArguments(text, text.indexOf("(", match.index));
    if (!args[0]?.trim().startsWith("{")) continue;
    const properties = args[0];
    const url = properties.match(/\b(?:url|uri|endpoint)\s*:\s*([^,\n}]+)/i);
    if (url) {
      const method = properties.match(/\bmethod\s*:\s*["'`]([A-Za-z]+)["'`]/i);
      add(method?.[1] || "GET", url[1]);
    }
  }
  const variableConfigPattern = /\b(?:axios|request)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/gi;
  while ((match = variableConfigPattern.exec(text)) !== null) {
    const properties = symbols.objects.get(match[1]);
    if (!properties) continue;
    const url = properties.get("url") || properties.get("uri") || properties.get("endpoint");
    if (!url) continue;
    const methodExpression = properties.get("method");
    const method = methodExpression ? resolveStaticJsExpression(methodExpression, symbols, base).value : "GET";
    add(method || "UNKNOWN", url);
  }
  return [...targets.values()];
}

function extractBundlerChunkUrls(text, base) {
  const urls = new Set();
  const directPath = /["'`]((?:https?:\/\/[^"'`\s]+|\/)[^"'`\s]*(?:_next\/static\/chunks|static\/chunks|\/chunks\/)[^"'`\s]*\.(?:m?js)(?:\?[^"'`]*)?)["'`]/gi;
  let match;
  while ((match = directPath.exec(text)) !== null) {
    const url = cleanUrl(match[1], base);
    if (url && /\.(?:m?js)(?:\?|$)/i.test(url)) urls.add(url);
  }
  const runtimeMarker = /(?:__webpack_require__|[A-Za-z_$][\w$]*)\.u\s*=|webpackChunkName|webpackChunkFiles/gi;
  const markers = [...text.matchAll(runtimeMarker)].map(item => item.index);
  const hashTable = /\{([^{}]{1,100000})\}/g;
  while ((match = hashTable.exec(text)) !== null) {
    const pairs = [...match[1].matchAll(/["']?([A-Za-z0-9_-]{1,80})["']?\s*:\s*["']([A-Fa-f0-9]{5,64})["']/g)];
    if (!pairs.length) continue;
    const recentMarker = markers.filter(index => index <= match.index && match.index - index < 20_000).at(-1);
    if (recentMarker === undefined) continue;
    const contextStart = Math.max(recentMarker, match.index - 4000);
    const before = text.slice(contextStart, match.index);
    const prefixMatch = [...before.matchAll(/["'`]([^"'`]*(?:_next\/static\/chunks|static\/chunks|chunks)\/)["'`]/gi)].at(-1);
    if (!prefixMatch) continue;
    const after = text.slice(match.index + match[0].length, Math.min(text.length, match.index + match[0].length + 500));
    const suffix = after.match(/\+\s*["'`]([^"'`]{1,30}\.(?:m?js))["'`]/i)?.[1] || ".js";
    const separator = before.match(/\+\s*[A-Za-z_$][\w$]*\s*\+\s*["'`]([._-])["'`]\s*\+\s*$/)?.[1] || ".";
    for (const [, id, hash] of pairs.slice(0, 500)) {
      const url = cleanUrl(`${prefixMatch[1]}${id}${separator}${hash}${suffix}`, base);
      if (url) urls.add(url);
    }
  }
  return [...urls];
}

function extractDynamicScriptUrls(text, base) {
  const symbols = collectStaticJsSymbols(text, base);
  const urls = new Set();
  const creationPattern = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:window\.)?document\.createElement\(\s*["']script["']\s*\)/gi;
  let match;
  while ((match = creationPattern.exec(text)) !== null) {
    const name = match[1].replace(/[$]/g, "\\$");
    const tail = text.slice(creationPattern.lastIndex, creationPattern.lastIndex + 4000);
    if (!(new RegExp(`(?:appendChild|append)\\s*\\(\\s*${name}\\s*\\)`)).test(tail)) continue;
    const assignment = new RegExp(`\\b${name}\\.src\\s*=\\s*([^;,}\\n]+)|\\b${name}\\.setAttribute\\(\\s*["']src["']\\s*,\\s*([^)]{1,1000})\\)`, "i").exec(tail);
    const expression = assignment?.[1] || assignment?.[2];
    if (!expression) continue;
    const resolved = resolveStaticJsExpression(expression, symbols, base);
    if (resolved.value && !resolved.dynamic) {
      const url = cleanUrl(resolved.value, base);
      if (url) urls.add(url);
    }
  }
  return [...urls];
}

function extractTransportEndpoints(text, base, appOrigin) {
  const symbols = collectStaticJsSymbols(text, base);
  const candidates = [];
  const patterns = [
    { type: "WebSocket", regex: /\bnew\s+WebSocket\s*\(/gi },
    { type: "Server-Sent Events", regex: /\bnew\s+EventSource\s*\(/gi },
    { type: "SignalR", regex: /\b(?:\.withUrl|hubConnection)\s*\(/gi }
  ];
  for (const { type, regex } of patterns) {
    let match;
    while ((match = regex.exec(text)) !== null) {
      const args = readCallArguments(text, text.indexOf("(", match.index));
      if (!args[0]) continue;
      const resolved = resolveStaticJsExpression(args[0], symbols, base);
      if (!resolved.value || resolved.dynamic) continue;
      try {
        const url = new URL(resolved.value, base);
        const comparisonUrl = new URL(url.href);
        if (type === "WebSocket" && comparisonUrl.protocol === "wss:") comparisonUrl.protocol = "https:";
        else if (type === "WebSocket" && comparisonUrl.protocol === "ws:") comparisonUrl.protocol = "http:";
        if ((type === "WebSocket" ? !["ws:", "wss:"].includes(url.protocol) : !["http:", "https:"].includes(url.protocol)) || comparisonUrl.origin !== appOrigin || url.username || url.password) continue;
        candidates.push({ type, url: reportUrl(url.href) });
      } catch (_) { /* unresolved or malformed transport address */ }
    }
  }
  return [...new Map(candidates.map(item => [`${item.type}|${item.url}`, item])).values()];
}

function extractGraphqlMetadata(text, base) {
  const records = [];
  const seen = new Set();
  const operationPattern = /\b(query|mutation|subscription)\s*([A-Za-z_][\w]*)?\s*(?:\([^)]{0,2000}\))?\s*\{/g;
  let match;
  while ((match = operationPattern.exec(text)) !== null && records.length < 300) {
    const start = match.index;
    const fragment = text.slice(start, Math.min(text.length, start + 12000));
    const bodyStart = match[0].lastIndexOf("{") + 1;
    let selection = fragment.slice(bodyStart);
    for (let pass = 0; pass < 5; pass += 1) selection = selection.replace(/\([^()]*\)/g, " ");
    const fieldMatches = [...selection.matchAll(/(?:^|[,\{\s])([_A-Za-z][_0-9A-Za-z]*)\b/g)];
    const fields = [...new Set(fieldMatches.map(item => item[1])
      .filter(name => !["query", "mutation", "subscription", "fragment", "on", "true", "false", "null"].includes(name)))].slice(0, 100);
    const key = `${match[1]}|${match[2] || "anonymous"}|${fields.join(",")}`;
    if (seen.has(key)) continue;
    seen.add(key);
    records.push({ operationType: match[1], operationName: match[2] || null, fieldNames: fields, source: reportUrl(base) });
  }
  const hashes = [...new Set([...text.matchAll(/(?:sha256Hash|persistedQueryHash)\s*[:=]\s*["'`]([a-f0-9]{32,128})["'`]/gi)].map(item => item[1].toLowerCase()))].slice(0, 100);
  return { operations: records, persistedQueryHashes: hashes };
}

function extractTechnologyVersions(text, scriptUrls) {
  const versions = [];
  const add = (technology, version, source) => {
    if (!version || versions.some(item => item.technology === technology && item.version === version)) return;
    versions.push({ technology, version: String(version).slice(0, 100), source: String(source || "page content").slice(0, 500) });
  };
  for (const rawUrl of scriptUrls || []) {
    let url;
    try { url = new URL(rawUrl); } catch (_) { continue; }
    const path = `${url.pathname}${url.search}`;
    const jquery = path.match(/jquery(?:[-.]|%2d)(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i) || path.match(/[?&](?:ver|v)=(\d+\.\d+(?:\.\d+)?)(?:&|$)/i);
    if (jquery && /jquery/i.test(path)) add("jQuery", jquery[1], reportUrl(rawUrl));
    const wordpress = path.match(/(?:wp-includes|wp-content)[^?]*[?&](?:ver|v)=(\d+\.\d+(?:\.\d+)?)/i);
    if (wordpress) add("WordPress asset version", wordpress[1], reportUrl(rawUrl));
  }
  const nextData = String(text || "").match(/<script[^>]+id=["']__NEXT_DATA__["'][^>]*>([\s\S]{0,200000}?)<\/script>/i);
  if (nextData) {
    try {
      const parsed = JSON.parse(nextData[1]);
      if (parsed.buildId) add("Next.js build ID", parsed.buildId, "__NEXT_DATA__");
      if (parsed.version) add("Next.js", parsed.version, "__NEXT_DATA__");
    } catch (_) { /* malformed hydration data is not interpreted */ }
  }
  for (const match of String(text || "").matchAll(/(?:React|Angular|Vue|Nuxt|Next\.js|jQuery)[^\n]{0,80}?\bversion\s*[:=]\s*["']?(\d+\.\d+(?:\.\d+)?)/gi)) add(match[0].split(/\s/)[0], match[1], "page content");
  return versions.slice(0, 200);
}

function nextBuildManifestUrl(text, baseUrl) {
  const match = String(text || "").match(/<script[^>]+id=["']__NEXT_DATA__["'][^>]*>([\s\S]{0,200000}?)<\/script>/i);
  if (!match) return null;
  try {
    const parsed = JSON.parse(match[1]);
    if (typeof parsed.buildId !== "string" || !/^[A-Za-z0-9_-]{1,200}$/.test(parsed.buildId)) return null;
    return new URL(`/_next/static/${parsed.buildId}/_buildManifest.js`, baseUrl).href;
  } catch (_) { return null; }
}

function extractManifestScriptUrls(text, baseUrl) {
  let parsed;
  try { parsed = JSON.parse(String(text || "")); } catch (_) { return []; }
  const found = new Set();
  const walk = (value, key = "") => {
    if (typeof value === "string" && /^(?:file|imports?|dynamicImports?)$/i.test(key) && /\.(?:m?js|cjs)(?:[?#]|$)/i.test(value)) {
      const url = cleanUrl(value, baseUrl);
      if (url) found.add(url);
    } else if (Array.isArray(value)) {
      for (const child of value.slice(0, 1000)) walk(child, key);
    } else if (value && typeof value === "object") {
      for (const [childKey, child] of Object.entries(value).slice(0, 2000)) walk(child, childKey);
    }
  };
  walk(parsed);
  return [...found].slice(0, 1000);
}

function routeTestIdeas(routes, technologies = []) {
  const techNames = technologies.map(item => item.name);
  const ideas = [];
  const seen = new Set();
  const routesWithIdeas = new Set();
  const add = (route, category, tbhmCategory, details) => {
    const method = String(route.method || "GET").toUpperCase();
    const key = `${method}|${route.url}|${category}`;
    if (seen.has(key) || ideas.length >= 10_000) return;
    seen.add(key);
    routesWithIdeas.add(route.url);
    ideas.push({ key, url: route.url, method, category, tbhmCategory, details, framework: techNames.join(", ") || "Unidentified" });
  };
  for (const route of routes.slice(0, 5000)) {
    const path = String(route.url || "").toLowerCase();
    const method = String(route.method || "GET").toUpperCase();
    if (/\b(?:users?|accounts?|orders?|leads?|records?|insurers?|clients?)\b|\{[^}]*id/i.test(path)) add(route, "Object authorization", "IDOR / MFLAC", "With two authorized test accounts and owned test records, verify the server checks ownership for this route and function. Do not use real user records.");
    if (/\b(?:admin|role|permission|configuration|settings|management)\b/i.test(path)) add(route, "Function authorization", "MFLAC", "Verify this sensitive function is enforced server-side for each role; hidden UI controls or client route guards are not authorization.");
    if (/\b(?:upload|download|file|document|attachment)\b/i.test(path)) add(route, "File handling", "LFI / Path Traversal", "Review file type, canonical path, storage root, and object authorization with harmless test files.");
    if (/\b(?:search|query|filter|sort|page|limit|skip|offset)\b/i.test(path)) add(route, "Input handling", "SQLi / Parameter Pollution", "Review validation, bounds, duplicate parameter handling, and query construction using non-destructive test inputs.");
    if (/graphql/i.test(path)) add(route, "GraphQL authorization", "IDOR / MFLAC / Lazy Load", "Review resolver-level object and function authorization, plus query depth and complexity limits; do not submit introspection or stress queries automatically.");
    if (method !== "GET" || /\b(?:create|update|delete|remove|save|submit|action)\b/i.test(path)) add(route, "State change", "CSRF / Business Logic", "Review CSRF/origin validation for cookie-authenticated state changes and verify transitions with reversible test records.");
    if (!routesWithIdeas.has(route.url)) add(route, "Route authorization", "IDOR / MFLAC", "Confirm authentication, object ownership, role checks, and response minimization for this route with approved test accounts.");
  }
  return ideas;
}

function chooseNextQueueIndex(queue, familyCounts = new Map()) {
  if (queue.length < 2) return 0;
  let selected = 0;
  let best = Infinity;
  for (let index = 0; index < queue.length; index += 1) {
    const item = queue[index];
    let pathname = "";
    try { pathname = new URL(item.url).pathname; } catch (_) { /* no path */ }
    const family = `/${pathname.split("/").filter(Boolean)[0] || ""}/`;
    const familyPenalty = Math.min(40, familyCounts.get(family) || 0) * 0.18;
    const kindPenalty = item.kind === "page" ? 0 : item.kind === "endpoint" ? 2 : 5;
    const score = item.depth * 2.5 + kindPenalty + familyPenalty;
    if (score < best) { best = score; selected = index; }
  }
  return selected;
}

function seedManifestCandidates(origin, mode, modulePath) {
  const paths = [
    ["/.well-known/security.txt", "endpoint"], ["/robots.txt", "endpoint"], ["/sitemap.xml", "endpoint"],
    ["/openapi.json", "endpoint"], ["/openapi.yaml", "endpoint"], ["/swagger.json", "endpoint"],
    ["/swagger", "page"], ["/swagger-ui.html", "page"], ["/docs", "page"], ["/redoc", "page"],
    ["/api/swagger", "endpoint"], ["/api/documentation", "endpoint"],
    ["/v3/api-docs", "endpoint"], ["/manifest.json", "endpoint"], ["/api-docs", "endpoint"],
    ["/@vite/manifest.json", "endpoint"]
  ];
  return paths.map(([path, kind]) => ({ url: new URL(path, origin).href, depth: 0, kind }))
    .filter(item => mode === "site" ? isSameOriginUrl(item.url, origin) : isInScope(item.url, origin, mode, modulePath));
}

function retryAfterDelayMs(value, now = Date.now()) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  if (/^\d+(?:\.\d+)?$/.test(raw)) return Math.max(0, Math.min(120_000, Number(raw) * 1000));
  const timestamp = Date.parse(raw);
  return Number.isFinite(timestamp) ? Math.max(0, Math.min(120_000, timestamp - now)) : null;
}

function classifyFetchFailure(error, signalAborted = false) {
  if (signalAborted || error?.name === "AbortError") return "Request timed out or was stopped.";
  if (/redirect/i.test(String(error?.message || ""))) return "Redirect could not be followed safely; destination was not requested.";
  return "Network, CORS, DNS, or browser permission failure; response details were unavailable.";
}

function isStaticNonScriptAsset(rawUrl) {
  try { return /\.(?:css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|eot|pdf|zip|mp4|webm)(?:$|[?#])/i.test(new URL(rawUrl).href); }
  catch (_) { return true; }
}

function detectTechnologies(text, scriptUrls, headers, pageData) {
  const combined = [text, scriptUrls.join("\n"), JSON.stringify(headers), JSON.stringify(pageData)].join("\n");
  const detected = [];
  for (const [name, patterns] of techPatterns) {
    let score = 0;
    if (patterns[0].test(combined)) score += 2;
    if (patterns[1].test(combined)) score += 1;
    if (pageData.htmlHints.includes(name)) score += 2;
    if (scriptUrls.some(url => patterns[1].test(url))) score += 1;
    if (score) detected.push({ name, confidence: score >= 3 ? "Likely" : "Possible", score });
  }
  return detected.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
}

async function readTextLimited(response, maxBytes = 1_500_000) {
  if (!response.body) return { text: "", bytesRead: 0, complete: true };
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let result = "";
  let complete = false;
  try {
    while (bytes < maxBytes) {
      const { value, done } = await reader.read();
      if (done) { complete = true; break; }
      const remaining = maxBytes - bytes;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      bytes += chunk.byteLength;
      result += decoder.decode(chunk, { stream: true });
      if (chunk.byteLength < value.byteLength) break;
    }
    result += decoder.decode();
  } finally {
    try { await reader.cancel(); } catch (_) { /* response may already be closed */ }
  }
  return { text: result, bytesRead: bytes, complete };
}

async function measureBodyWithoutRetaining(response, maxBytes = 128 * 1024) {
  if (!response.body) return { bytesRead: 0, complete: true };
  const reader = response.body.getReader();
  let bytesRead = 0;
  let complete = false;
  try {
    while (bytesRead < maxBytes) {
      const { value, done } = await reader.read();
      if (done) { complete = true; break; }
      const remaining = maxBytes - bytesRead;
      bytesRead += Math.min(value.byteLength, remaining);
      if (value.byteLength > remaining) break;
    }
  } finally {
    try { await reader.cancel(); } catch (_) { /* response may already be closed */ }
  }
  return { bytesRead, complete };
}

function makeTestIdeas(technologies) {
  const categoryMap = [
    [/xss|dom/i, "XSS"], [/lfi|traversal|file/i, "LFI / Path Traversal"], [/ssti|template/i, "SSTI"],
    [/csrf/i, "CSRF"], [/sql/i, "SQLi"], [/parameter|pollution/i, "Parameter Pollution"], [/ssrf/i, "SSRF"],
    [/idor|authorization|access control|permissions?|ownership|row-level|record access/i, "IDOR / MFLAC"], [/mass assignment/i, "Mass Assignment"],
    [/deserial/i, "Deserialization"], [/lazy/i, "Lazy Load"], [/debug|configuration|data exposure|schema exposure|sensitive/i, "Config Leak / Information Disclosure"],
    [/cors|header|cookie/i, "CORS / Security Headers"], [/redirect/i, "Open Redirect"], [/business/i, "Business Logic"]
  ];
  const mapCategory = category => categoryMap.find(([pattern]) => pattern.test(category))?.[1] || "General manual review";
  const byKey = new Map();
  for (const technology of technologies) {
    for (const [category, details] of frameworkIdeas[technology.name] || []) {
      const key = `${category}|${details}`;
      if (!byKey.has(key)) byKey.set(key, { category, tbhmCategory: mapCategory(category), details, relevance: technology.name });
    }
  }
  for (const [category, details] of commonIdeas) {
    const key = `${category}|${details}`;
    if (!byKey.has(key)) byKey.set(key, { category, tbhmCategory: mapCategory(category), details, relevance: "General" });
  }
  return [...byKey.values()];
}

function uiModuleCandidatesFromDocument(doc, baseUrl) {
  const selector = '[role="tab"],[role="menuitem"],nav a[href],nav button,[role="navigation"] a[href],[role="navigation"] button,[role="tablist"] [role="tab"],[data-step],[data-tab],[class~="step"],[class~="tab"],[class*="step"][class*="item"],[class*="Step"][class*="Item"],[class*="tab"][class*="item"],[class*="Tab"][class*="Item"],[class*="Step"][class*="Button"],[class*="steps"] [class*="item"]';
  return [...new Set(doc.querySelectorAll(selector))].slice(0, 200).map(element => {
    const role = element.getAttribute("role") || "";
    const classes = typeof element.className === "string" ? element.className : "";
    const isStep = element.hasAttribute("data-step") || /(?:^|[-_\s])steps?(?:[-_\s]|$)/i.test(classes);
    const isTab = role === "tab" || element.hasAttribute("data-tab") || /(?:^|[-_\s])tabs?(?:[-_\s]|$)/i.test(classes);
    const isNavigation = role === "menuitem" || Boolean(element.closest?.('nav,[role="navigation"]'));
    const group = isTab ? "Tab" : isStep ? "Step" : isNavigation ? "Navigation" : "";
    if (!group || role === "presentation") return null;
    const text = String(element.getAttribute("aria-label") || element.getAttribute("title") || element.innerText || element.textContent || "").replace(/\s+/g, " ").trim();
    let href = "";
    try {
      const target = new URL(element.href || element.getAttribute("href") || "", baseUrl);
      if (target.origin === new URL(baseUrl).origin && element.matches("a[href]")) href = target.href;
    } catch (_) { /* no route attached to this control */ }
    return { label: text.slice(0, 80), group, control: role || element.tagName.toLowerCase(), selected: element.getAttribute("aria-selected") === "true" || Boolean(element.getAttribute("aria-current")) || /(?:^|[-_\s])(?:active|current|selected)(?:$|[-_\s])/i.test(classes), href };
  }).filter(item => item && item.label.length >= 2 && /[a-z]/i.test(item.label) && !/@|\b\d{8,}\b/.test(item.label));
}

function inputFieldCandidatesFromDocument(doc, baseUrl) {
  return [...doc.querySelectorAll("input,textarea,select")].slice(0, 500).map(element => {
    const tag = element.tagName.toLowerCase();
    const type = tag === "input" ? String(element.getAttribute("type") || "text").toLowerCase() : tag;
    if (["button", "submit", "reset", "image"].includes(type)) return null;
    const name = String(element.getAttribute("name") || element.getAttribute("id") || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100);
    if (!name) return null;
    const labelText = [...(element.labels || [])].map(label => label.innerText || label.textContent || "").join(" ") || element.getAttribute("aria-label") || element.getAttribute("title") || name;
    const normalizedLabel = String(labelText).replace(/\s+/g, " ").trim().slice(0, 100);
    const label = /@|\b\d{8,}\b/.test(normalizedLabel) ? name : normalizedLabel;
    const form = element.form || element.closest("form");
    const method = String(form?.getAttribute("method") || "GET").toUpperCase();
    let action = "";
    try {
      const target = new URL(form?.getAttribute("action") || baseUrl, baseUrl);
      if (target.origin === new URL(baseUrl).origin && !target.username && !target.password) action = target.href;
    } catch (_) { /* invalid or external form action is not included */ }
    return { name, type, label, required: Boolean(element.required || element.getAttribute("required") !== null), method, action, page: reportUrl(baseUrl) };
  }).filter(Boolean);
}

function formActionCandidatesFromDocument(doc, baseUrl) {
  const base = new URL(baseUrl);
  return [...doc.querySelectorAll("form")].slice(0, 300).map(form => {
    const method = String(form.getAttribute("method") || "GET").trim().toUpperCase().slice(0, 12);
    const rawAction = form.getAttribute("action") || base.href;
    try {
      const url = new URL(rawAction, base.href);
      if (url.origin !== base.origin || url.username || url.password || !/^https?:$/.test(url.protocol)) return null;
      return { url: reportUrl(url.href), method, page: reportUrl(base.href), requested: false };
    } catch (_) { return null; }
  }).filter(Boolean);
}

function pageSnapshotCode() {
  return () => {
    const html = (document.documentElement?.outerHTML || "").slice(0, 500_000)
      .replace(/(<input\b[^>]*?)\svalue\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "$1")
      .replace(/(<textarea\b[^>]*>)[\s\S]*?(<\/textarea>)/gi, "$1$2");
    const inlineScripts = [];
    let inlineChars = 0;
    for (const script of [...document.querySelectorAll("script:not([src])")].slice(0, 200)) {
      const remaining = 1_000_000 - inlineChars;
      if (remaining <= 0) break;
      const code = (script.textContent || "").slice(0, Math.min(100_000, remaining));
      if (code) inlineScripts.push(code);
      inlineChars += code.length;
    }
    const moduleSelector = '[role="tab"],[role="menuitem"],nav a[href],nav button,[role="navigation"] a[href],[role="navigation"] button,[role="tablist"] [role="tab"],[data-step],[data-tab],[class~="step"],[class~="tab"],[class*="step"][class*="item"],[class*="Step"][class*="Item"],[class*="tab"][class*="item"],[class*="Tab"][class*="Item"],[class*="Step"][class*="Button"],[class*="steps"] [class*="item"]';
    const uiModules = [...new Set(document.querySelectorAll(moduleSelector))].slice(0, 200).map(element => {
      const text = String(element.getAttribute("aria-label") || element.getAttribute("title") || element.innerText || element.textContent || "").replace(/\s+/g, " ").trim();
      const label = text.slice(0, 80);
      let href = "";
      try {
        const target = new URL(element.href || element.getAttribute("href") || "", location.href);
        if (target.origin === location.origin && element.matches("a[href]")) href = target.href;
      } catch (_) { /* no route attached to this control */ }
      const classes = typeof element.className === "string" ? element.className : "";
      const role = element.getAttribute("role") || "";
      const isStep = element.hasAttribute("data-step") || /(?:^|[-_\s])steps?(?:[-_\s]|$)/i.test(classes);
      const isTab = role === "tab" || element.hasAttribute("data-tab") || /(?:^|[-_\s])tabs?(?:[-_\s]|$)/i.test(classes);
      const isNavigation = role === "menuitem" || Boolean(element.closest?.('nav,[role="navigation"]'));
      const group = role === "presentation" ? "" : isTab ? "Tab" : isStep ? "Step" : isNavigation ? "Navigation" : "";
      return {
        label,
        group,
        control: role || element.tagName.toLowerCase(),
        selected: element.getAttribute("aria-selected") === "true" || Boolean(element.getAttribute("aria-current")) || /(?:^|[-_\s])(?:active|current|selected)(?:$|[-_\s])/i.test(classes),
        href
      };
    }).filter(item => item.group && item.label.length >= 2 && !/@|\b\d{8,}\b/.test(item.label) && /[a-z]/i.test(item.label));
    const inputFields = [...document.querySelectorAll("input,textarea,select")].slice(0, 500).map(element => {
      const tag = element.tagName.toLowerCase();
      const type = tag === "input" ? String(element.getAttribute("type") || "text").toLowerCase() : tag;
      if (["button", "submit", "reset", "image"].includes(type)) return null;
      const name = String(element.getAttribute("name") || element.getAttribute("id") || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100);
      if (!name) return null;
      const labelText = [...(element.labels || [])].map(label => label.innerText || label.textContent || "").join(" ") || element.getAttribute("aria-label") || element.getAttribute("title") || name;
      const form = element.form || element.closest("form");
      let action = "";
      try {
        const target = new URL(form?.getAttribute("action") || location.href, location.href);
        if (target.origin === location.origin && !target.username && !target.password) action = target.href;
      } catch (_) { /* invalid or external form action is not included */ }
      const normalizedLabel = String(labelText).replace(/\s+/g, " ").trim().slice(0, 100);
      const label = /@|\b\d{8,}\b/.test(normalizedLabel) ? name : normalizedLabel;
      return { name, type, label, required: Boolean(element.required || element.getAttribute("required") !== null), method: String(form?.getAttribute("method") || "GET").toUpperCase(), action, page: location.href };
    }).filter(Boolean);
    const formActions = [...document.querySelectorAll("form")].slice(0, 300).map(form => {
      const method = String(form.getAttribute("method") || "GET").trim().toUpperCase().slice(0, 12);
      try {
        const target = new URL(form.getAttribute("action") || location.href, location.href);
        if (target.origin !== location.origin || target.username || target.password || !/^https?:$/.test(target.protocol)) return null;
        return { url: target.href, method, page: location.href };
      } catch (_) { return null; }
    }).filter(Boolean);
    return {
      html,
      inlineScripts,
      importMaps: [...document.querySelectorAll('script[type="importmap"]')].slice(0, 10).map(element => ({ base: location.href, source: String(element.textContent || "").slice(0, 100_000) })),
      uiModules,
      inputFields,
      formActions,
      links: [...document.querySelectorAll("a[href],area[href],form[action],iframe[src]")]
        .filter(el => el.tagName !== "FORM" || (el.getAttribute("method") || "get").toUpperCase() === "GET")
        .slice(0, 1000).map(el => el.href || el.action || el.src).filter(Boolean),
      scripts: [...new Set([
        ...[...document.scripts].map(el => el.src),
        ...[...document.querySelectorAll("link[rel=modulepreload][href],link[rel=preload][as=script][href]")].map(el => el.href)
      ])].filter(Boolean).slice(0, 1000),
      resources: performance.getEntriesByType("resource").slice(0, 1000).map(entry => ({ url: entry.name, type: entry.initiatorType || "" })).filter(entry => entry.url),
      htmlHints: [
        ["Next.js", /__NEXT_DATA__|\/_next\//i], ["Nuxt.js", /__NUXT__|\/_nuxt\//i],
        ["Angular", /ng-version=|ng-app/i], ["React", /__REACT|data-reactroot|react-dom/i],
        ["Vue.js", /__VUE__|data-v-[a-f0-9]+/i], ["jQuery", /jquery(?:\.min)?\.js/i],
        ["Django", /csrfmiddlewaretoken|csrftoken/i], ["Laravel", /laravel_session|XSRF-TOKEN/i],
        ["Ruby on Rails", /authenticity_token|_session=/i], ["Spring Boot", /JSESSIONID|Whitelabel Error Page/i],
        ["Flask/Werkzeug", /werkzeug|flask/i], ["FastAPI", /\/openapi\.json|\/docs\b/i]
      ].filter(([, pattern]) => pattern.test(html)).map(([name]) => name)
    };
  };
}

function responseHeaders(headers) {
  const allowed = new Set([
    "content-type", "content-length", "cache-control", "vary",
    "server", "x-powered-by", "x-aspnet-version", "x-application-context",
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "access-control-allow-origin", "access-control-allow-credentials"
  ]);
  const result = {};
  for (const [name, value] of headers.entries()) {
    const key = name.toLowerCase();
    if (allowed.has(key)) result[key] = key === "content-security-policy" ? `present (${value.length} chars)` : value;
  }
  return result;
}

function headersForComparison(headers) {
  const volatileOrNonAuthorizationHeaders = new Set(["cache-control", "content-length", "server", "vary", "x-powered-by", "x-aspnet-version", "x-application-context"]);
  return Object.entries(headers || {})
    .filter(([name]) => !volatileOrNonAuthorizationHeaders.has(name.toLowerCase()))
    .map(([name, value]) => [name.toLowerCase(), name.toLowerCase() === "content-type" ? normalizedMediaType(value) : value])
    .sort(([a], [b]) => a.localeCompare(b));
}

function sizesComparable(first, second) {
  return Boolean(first?.complete && second?.complete && Number.isFinite(Number(first.bytes)) && Number.isFinite(Number(second.bytes)));
}

function mainWorldRequestObserver(config) {
  const slot = "__stackscopePassiveObserver_v118";
  const previous = window.__stackscopePassiveObserver_v114;
  if (previous && typeof previous.stop === "function") { try { previous.stop(); } catch (_) { /* stop older observer version */ } }
  const existing = window[slot];
  if (config.active === false) {
    if (existing && typeof existing.stop === "function") existing.stop();
    return { active: false };
  }
  const state = existing && typeof existing === "object" ? existing : {};
  if (state.installed && state.channel === config.channel) {
    state.config = config;
    state.active = true;
    return { active: true, installed: true };
  }
  if (state.installed && typeof state.stop === "function") state.stop();
  state.config = config;
  state.channel = config.channel;
  state.active = true;

  const validPagePath = () => {
    if (location.origin !== config.origin) return false;
    if (config.mode === "site") return true;
    try {
      const rootPath = new URL(config.modulePath, config.origin).pathname;
      const root = rootPath.endsWith("/") ? rootPath.slice(0, -1) : rootPath;
      const inside = path => path === root || path.startsWith(`${root}/`);
      let candidate = location.pathname;
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
  const safeUrl = (raw, transport = "http") => {
    try {
      const url = new URL(raw, location.href);
      const comparable = new URL(url.href);
      if (transport === "websocket") {
        if (comparable.protocol === "ws:") comparable.protocol = "http:";
        else if (comparable.protocol === "wss:") comparable.protocol = "https:";
      }
      if (comparable.origin !== config.origin || url.username || url.password) return null;
      url.hash = "";
      const segments = url.pathname.split("/");
      const sensitive = /^(?:token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|session[_-]?(?:id|token)|secret|password|jwt|api[_-]?key|access[_-]?key|private[_-]?key)$/i;
      for (let i = 1; i < segments.length; i += 1) {
        let previous = "";
        let current = "";
        try { previous = decodeURIComponent(segments[i - 1]); current = decodeURIComponent(segments[i]); } catch (_) { return null; }
        if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?$/.test(current) || (sensitive.test(previous) && /^[A-Za-z0-9_-]{16,}$/.test(current))) segments[i] = "[redacted]";
      }
      url.pathname = segments.join("/");
      const names = [...url.searchParams.keys()];
      if (names.length) {
        url.search = "";
        for (const name of names) url.searchParams.append(name, "[redacted]");
      }
      return url.href;
    } catch (_) { return null; }
  };
  const safeHeaderSnapshot = headers => {
    const names = ["content-type", "content-length", "cache-control", "vary", "server", "x-powered-by", "x-aspnet-version", "x-application-context", "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "access-control-allow-origin", "access-control-allow-credentials"];
    const result = {};
    for (const name of names) {
      try {
        const value = headers?.get(name);
        if (value) result[name] = name === "content-security-policy" ? `present (${String(value).length} chars)` : String(value).slice(0, 500);
      } catch (_) { /* inaccessible response header */ }
    }
    return result;
  };
  const safeAnonymousCandidate = raw => {
    if (!config.compareObservedGets) return { url: null, reason: "Without-cookie comparison was not enabled." };
    try {
      const url = new URL(raw, location.href);
      const sensitiveName = /(?:token|secret|password|passwd|authorization|session|jwt|signature|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|credential|^auth$|^key$|^code$)/i;
      const sensitivePath = /(?:^|\/)(?:\.env(?:\.[^/]+)?|\.git|actuator|heapdump|credentials|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|secret|password|logout|logoff|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger|webhook|proxy)(?:\/|$)/i;
      const action = url.searchParams.get("action") || url.searchParams.get("operation") || url.searchParams.get("op") || url.searchParams.get("cmd") || "";
      let decodedPath = "";
      try { decodedPath = decodeURIComponent(url.pathname); } catch (_) { return { url: null, reason: "Path encoding could not be validated." }; }
      const jwtPath = decodedPath.split("/").some(segment => /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?$/.test(segment));
      const numericOrUuidPath = decodedPath.split("/").some(segment => /^\d{5,}$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment));
      if (url.origin !== config.origin || url.username || url.password) return { url: null, reason: "Cross-origin or credential-bearing URL was excluded." };
      if ([...url.searchParams.keys()].some(name => sensitiveName.test(name))) return { url: null, reason: "Credential-like query parameter was excluded." };
      if (sensitivePath.test(decodedPath.toLowerCase()) || jwtPath) return { url: null, reason: "Credential-like or sensitive path was excluded." };
      if (/^(?:logout|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger)$/i.test(action) || /(?:^|\/)(?:logout|logoff|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger)(?:\/|$)/i.test(decodedPath)) return { url: null, reason: "Potentially state-changing route was excluded from automatic GET comparison." };
      if (numericOrUuidPath) return { url: null, reason: "Numeric or UUID path identifier was excluded from automatic GET comparison." };
      if ([...url.searchParams.keys()].length) return { url: null, reason: "Query parameters were excluded from automatic GET comparison." };
      url.hash = "";
      return { url: url.href, reason: null };
    } catch (_) { return { url: null, reason: "URL could not be validated." }; }
  };
  const safeParameterNames = body => {
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
          const keyPattern = /["']([^"'\\]{1,100})["']\s*:/g;
          let match;
          while (names.size < 100 && (match = keyPattern.exec(body)) !== null) add(match[1]);
        } else if (body.includes("=")) {
          let count = 0;
          for (const name of new URLSearchParams(body).keys()) { add(name); if (++count >= 100) break; }
        } else if (body.trim()) skippedReason = "Body format is not a supported JSON or URL-encoded format.";
      } else if (typeof body === "string") {
        skippedReason = "Request body exceeded the 64 KiB parameter-name inspection limit.";
      } else if (body) {
        skippedReason = "Body format is unsupported or streaming; values were not read.";
      }
    } catch (_) { /* unknown or streaming bodies are not inspected */ }
    return { names: [...names], skippedReason };
  };
  const emit = (methodValue, rawUrl, statusValue, headers, durationValue, body, transport = "http") => {
    if (!state.active || !validPagePath() || state.captured >= 1000) return;
    const url = safeUrl(rawUrl, transport);
    if (!url) return;
    const method = String(methodValue || "GET").toUpperCase().slice(0, 20);
    if (!/^[A-Z!#$%&'*+.^_`|~-]{1,20}$/.test(method)) return;
    const status = Number.isInteger(Number(statusValue)) ? Math.max(0, Math.min(599, Number(statusValue))) : 0;
    const anonymous = method !== "GET" ? { url: null, reason: "Non-GET requests are observed only and never replayed." }
      : transport !== "http" ? { url: null, reason: "Non-HTTP transports are observed only and are never replayed." }
        : safeAnonymousCandidate(rawUrl);
    const parameterResult = safeParameterNames(body);
    const control = recentControl && Date.now() - recentControl.at <= 10000 && recentControl.pagePath === location.pathname ? recentControl : null;
    state.captured += 1;
    window.postMessage({
      __stackscopeObserver: "traffic-v1",
      channel: config.channel,
      url,
      method,
      status,
      anonymousCandidate: anonymous.url,
      anonymousFilterReason: anonymous.reason,
      parameterNames: parameterResult.names,
      parameterNamesSkippedReason: parameterResult.skippedReason,
      moduleControl: control ? { label: control.label, role: control.role, pagePath: control.pagePath } : null,
      transport,
      headers: safeHeaderSnapshot(headers),
      durationMs: Math.max(0, Math.min(120000, Math.round(Number(durationValue) || 0))),
      at: Date.now()
    }, location.origin);
  };

  const install = () => {
    let patchCount = 0;
    try {
      document.addEventListener("click", captureControlClick, true);
      state.controlRestore = () => document.removeEventListener("click", captureControlClick, true);
      patchCount += 1;
    } catch (_) { /* document may be unavailable in a restricted page */ }
    const originalFetch = window.fetch;
    if (typeof originalFetch === "function") {
      const wrappedFetch = function(input, init) {
        let rawUrl = "";
        let method = "GET";
        try {
          rawUrl = typeof input === "string" || input instanceof URL ? String(input) : String(input?.url || "");
          method = String(init?.method || input?.method || "GET");
        } catch (_) { /* ignore malformed Request-like objects */ }
        const started = performance.now();
        let result;
        try { result = Reflect.apply(originalFetch, this, arguments); }
        catch (error) { emit(method, rawUrl, 0, null, performance.now() - started, init?.body); throw error; }
        return result.then(response => {
          emit(method, rawUrl, response.status, response.headers, performance.now() - started, init?.body);
          return response;
        }, error => {
          emit(method, rawUrl, 0, null, performance.now() - started, init?.body);
          throw error;
        });
      };
      try {
        window.fetch = wrappedFetch;
        if (window.fetch === wrappedFetch) {
          patchCount += 1;
          state.fetchRestore = () => { if (window.fetch === wrappedFetch) window.fetch = originalFetch; };
        }
      } catch (_) { /* page may expose a non-writable fetch */ }
    }

    const prototype = window.XMLHttpRequest?.prototype;
    if (prototype && typeof prototype.open === "function" && typeof prototype.send === "function") {
      const originalOpen = prototype.open;
      const originalSend = prototype.send;
      const requestMeta = new WeakMap();
      const wrappedOpen = function(method, url) {
        requestMeta.set(this, { method: String(method || "GET"), url: String(url || "") });
        return Reflect.apply(originalOpen, this, arguments);
      };
      const wrappedSend = function() {
        const meta = requestMeta.get(this);
        if (meta) {
          const started = performance.now();
          this.addEventListener("loadend", () => {
            let headers = null;
            try {
              headers = { get: name => {
                const value = this.getResponseHeader(name);
                return value || null;
              } };
            } catch (_) { /* response headers may be inaccessible */ }
            emit(meta.method, meta.url, this.status, headers, performance.now() - started, arguments[0]);
          }, { once: true });
        }
        return Reflect.apply(originalSend, this, arguments);
      };
      try {
        prototype.open = wrappedOpen;
        prototype.send = wrappedSend;
        if (prototype.open === wrappedOpen && prototype.send === wrappedSend) {
          patchCount += 1;
          state.xhrRestore = () => {
            if (prototype.open === wrappedOpen) prototype.open = originalOpen;
            if (prototype.send === wrappedSend) prototype.send = originalSend;
          };
        }
      } catch (_) { /* XHR may be locked down by the page */ }
    }
    const wrapPassiveConstructor = (name, transport) => {
      const original = window[name];
      if (typeof original !== "function") return;
      const wrapped = new Proxy(original, {
        construct(target, args, newTarget) {
          const instance = Reflect.construct(target, args, newTarget);
          emit(transport === "websocket" ? "WEBSOCKET" : "GET", args[0], 0, null, 0, null, transport);
          return instance;
        }
      });
      try {
        window[name] = wrapped;
        if (window[name] === wrapped) {
          patchCount += 1;
          const restoreName = transport === "websocket" ? "webSocketRestore" : "eventSourceRestore";
          state[restoreName] = () => { if (window[name] === wrapped) window[name] = original; };
        }
      } catch (_) { /* constructor may be non-writable */ }
    };
    wrapPassiveConstructor("WebSocket", "websocket");
    wrapPassiveConstructor("EventSource", "eventsource");
    const beacon = window.navigator?.sendBeacon;
    if (typeof beacon === "function") {
      const wrappedBeacon = function(url, body) {
        const started = performance.now();
        const queued = Reflect.apply(beacon, this, arguments);
        if (queued) emit("POST", url, 0, null, performance.now() - started, body, "sendBeacon");
        return queued;
      };
      try {
        window.navigator.sendBeacon = wrappedBeacon;
        if (window.navigator.sendBeacon === wrappedBeacon) {
          patchCount += 1;
          state.beaconRestore = () => { if (window.navigator.sendBeacon === wrappedBeacon) window.navigator.sendBeacon = beacon; };
        }
      } catch (_) { /* browser may expose a non-writable method */ }
    }
    return patchCount;
  };
  state.stop = () => {
    state.active = false;
    try { state.fetchRestore?.(); } catch (_) { /* ignore restore failure */ }
    try { state.xhrRestore?.(); } catch (_) { /* ignore restore failure */ }
    try { state.beaconRestore?.(); } catch (_) { /* ignore restore failure */ }
    try { state.webSocketRestore?.(); } catch (_) { /* ignore restore failure */ }
    try { state.eventSourceRestore?.(); } catch (_) { /* ignore restore failure */ }
    try { state.controlRestore?.(); } catch (_) { /* ignore restore failure */ }
    state.fetchRestore = null;
    state.xhrRestore = null;
    state.beaconRestore = null;
    state.webSocketRestore = null;
    state.eventSourceRestore = null;
    state.controlRestore = null;
    recentControl = null;
    state.installed = false;
  };
  state.captured = 0;
  window[slot] = state;
  const patchCount = install();
  state.installed = patchCount > 0;
  if (!state.installed) state.active = false;
  return { active: state.active, installed: state.installed, patchCount };
}

function isolatedTrafficBridge(config) {
  const slot = "__stackscopeTrafficBridge_v118";
  const previous = globalThis.__stackscopeTrafficBridge_v114;
  if (previous) {
    previous.active = false;
    try { if (previous.listener) window.removeEventListener("message", previous.listener); } catch (_) { /* remove older bridge listener */ }
  }
  const comparableHeaders = headers => Object.entries(headers || {}).filter(([name]) => name.toLowerCase() !== "cache-control").sort(([a], [b]) => a.localeCompare(b));
  const isHtmlType = value => /(?:^|\s|;)text\/html(?:\s|;|$)|application\/xhtml\+xml/i.test(String(value || ""));
  const safeTrafficHeaders = new Set([
    "content-type", "content-length", "cache-control", "vary", "server", "x-powered-by",
    "x-aspnet-version", "x-application-context", "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
    "access-control-allow-origin", "access-control-allow-credentials"
  ]);
  const compactHeaders = headers => {
    const result = {};
    if (!headers || typeof headers !== "object" || Array.isArray(headers)) return result;
    for (const [name, rawValue] of Object.entries(headers).slice(0, 64)) {
      const key = String(name).toLowerCase();
      if (!safeTrafficHeaders.has(key) || typeof rawValue !== "string") continue;
      result[key] = key === "content-security-policy"
        ? (/^present \(\d+ chars\)$/.test(rawValue) ? rawValue : `present (${rawValue.length} chars)`)
        : rawValue.replace(/'nonce-[^']+'/gi, "'nonce-[redacted]'").slice(0, 500);
    }
    return result;
  };
  const safeStoredUrl = (rawUrl, transport) => {
    try {
      const url = new URL(String(rawUrl || ""));
      const comparable = new URL(url.href);
      if (transport === "websocket") {
        if (comparable.protocol === "ws:") comparable.protocol = "http:";
        else if (comparable.protocol === "wss:") comparable.protocol = "https:";
      }
      if (comparable.origin !== config.origin || url.username || url.password) return null;
      url.hash = "";
      const names = [...url.searchParams.keys()];
      if (names.length > 50) return null;
      if (names.length) {
        url.search = "";
        for (const name of names) url.searchParams.append(name.slice(0, 100), "[redacted]");
      }
      return url.href;
    } catch (_) { return null; }
  };
  const redactStoredPath = pathname => {
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
  const inScopePagePath = pathname => {
    if (config.mode !== "module") return config.mode === "site";
    try {
      const rawRoot = new URL(config.modulePath, config.origin).pathname;
      const root = rawRoot.endsWith("/") ? rawRoot.slice(0, -1) : rawRoot;
      const inside = path => path === root || path.startsWith(`${root}/`);
      let candidate = pathname;
      for (let depth = 0; depth < 5; depth += 1) {
        if (candidate.includes("\\") || /[\u0000-\u001f]/.test(candidate)) return false;
        const decoded = decodeURIComponent(candidate);
        if (decoded.includes("\\") || /[\u0000-\u001f]/.test(decoded) || !inside(new URL(decoded, config.origin).pathname)) return false;
        if (decoded === candidate) return true;
        candidate = decoded;
      }
    } catch (_) { return false; }
    return false;
  };
  const safeParameterNames = values => [...new Set((Array.isArray(values) ? values.slice(0, 100) : [])
    .map(value => String(value || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100))
    .filter(value => value && !/@|\b\d{8,}\b/.test(value)))];
  const cleanItems = items => (Array.isArray(items) ? items : []).slice(-1000).filter(item => item && typeof item === "object" && !Array.isArray(item)).flatMap(raw => {
    const transport = ["http", "websocket", "eventsource", "sendBeacon"].includes(raw.transport) ? raw.transport : "http";
    const url = safeStoredUrl(raw.url, transport);
    if (!url) return [];
    let pagePath = typeof raw.pagePath === "string" ? raw.pagePath : raw.moduleControl?.pagePath;
    if (typeof pagePath !== "string" || !pagePath) return [];
    let page;
    try { page = new URL(pagePath, config.origin); } catch (_) { return []; }
    if (page.origin !== config.origin || page.search || page.hash || !inScopePagePath(page.pathname)) return [];
    const method = String(raw.method || "GET").toUpperCase().slice(0, 20);
    if (!/^[A-Z!#$%&'*+.^_`|~-]{1,20}$/.test(method)) return [];
    const statusValue = Number(raw.status);
    const safeItem = {
      url, pagePath: page.pathname, method,
      status: Number.isInteger(statusValue) && statusValue >= 0 && statusValue <= 599 ? statusValue : 0,
      durationMs: Math.max(0, Math.min(120000, Math.round(Number(raw.durationMs) || 0))),
      parameterNames: safeParameterNames(raw.parameterNames),
      parameterNamesSkippedReason: [
        "Body format is not a supported JSON or URL-encoded format.",
        "Request body exceeded the 64 KiB parameter-name inspection limit.",
        "Body format is unsupported or streaming; values were not read.",
        "Body format could not be inspected safely."
      ].includes(raw.parameterNamesSkippedReason) ? raw.parameterNamesSkippedReason : null,
      transport, headers: compactHeaders(raw.headers), at: Number.isFinite(Number(raw.at)) ? Number(raw.at) : Date.now()
    };
    const control = raw.moduleControl && typeof raw.moduleControl === "object" && raw.moduleControl.pagePath === page.pathname ? raw.moduleControl : null;
    if (control) {
      const label = String(control.label || "").replace(/[\r\n\t]/g, " ").trim()
        .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted]")
        .replace(/\b\+?\d[\d\s().-]{7,}\d\b/g, "[redacted]")
        .replace(/\b[A-Za-z0-9_-]{24,}\b/g, "[redacted]").slice(0, 120);
      const role = String(control.role || "").toLowerCase();
      if (label && ["tab", "button", "menuitem", "step", "link"].includes(role)) safeItem.moduleControl = { label, role, pagePath: page.pathname };
    }
    if (Number.isFinite(Number(raw.bytes)) && Number(raw.bytes) >= 0) safeItem.bytes = Math.min(Number(raw.bytes), Number.MAX_SAFE_INTEGER);
    if (typeof raw.byteSource === "string") safeItem.byteSource = raw.byteSource.slice(0, 40);
    if (raw.anonymous && typeof raw.anonymous === "object" && !Array.isArray(raw.anonymous)) {
      const anonymousStatus = Number(raw.anonymous.status);
      if (raw.anonymous.suppressed || !Number.isInteger(anonymousStatus) || anonymousStatus < 100 || anonymousStatus > 599 || isHtmlType(raw.anonymous.type)) {
        safeItem.anonymous = { suppressed: true, outcome: String(raw.anonymous.outcome || "Without-cookie response was unavailable or an HTML app/login shell; it was excluded from access results.").slice(0, 500) };
      } else {
        safeItem.anonymous = {
          status: anonymousStatus, type: typeof raw.anonymous.type === "string" ? raw.anonymous.type.slice(0, 120) : "unknown",
          bytes: Number.isFinite(Number(raw.anonymous.bytes)) && Number(raw.anonymous.bytes) >= 0 ? Math.min(Number(raw.anonymous.bytes), Number.MAX_SAFE_INTEGER) : null,
          byteSource: typeof raw.anonymous.byteSource === "string" ? raw.anonymous.byteSource.slice(0, 40) : null,
          sizeComplete: raw.anonymous.sizeComplete !== false, headers: compactHeaders(raw.anonymous.headers),
          selectedHeadersMatch: typeof raw.anonymous.selectedHeadersMatch === "boolean" ? raw.anonymous.selectedHeadersMatch : null,
          outcome: typeof raw.anonymous.outcome === "string" ? raw.anonymous.outcome.slice(0, 500) : ""
        };
      }
    }
    safeItem.url = (() => { try { const parsed = new URL(safeItem.url); parsed.pathname = redactStoredPath(parsed.pathname); return parsed.href; } catch (_) { return safeItem.url; } })();
    safeItem.pagePath = redactStoredPath(page.pathname);
    if (safeItem.moduleControl) safeItem.moduleControl.pagePath = safeItem.pagePath;
    return [safeItem];
  });
  let state = globalThis[slot];
  if (!state || typeof state !== "object") {
    state = { listener: null, active: false, pending: Promise.resolve(), config: null, checkedUrls: new Set(), rateLimitPaused: false, accepted: 0 };
    globalThis[slot] = state;
  }
  if (state.config?.channel !== config.channel) { state.checkedUrls = new Set(); state.rateLimitPaused = false; state.accepted = 0; }
  if (!Number.isInteger(state.accepted) || state.accepted < 0) state.accepted = 0;
  state.config = config;
  state.active = true;
  if (!state.listener) {
    state.listener = event => {
      const current = state.config;
      const data = event.data;
      if (!state.active || !current || event.source !== window || event.origin !== current.origin || state.accepted >= 1000 ||
          !data || data.__stackscopeObserver !== "traffic-v1" || data.channel !== current.channel) return;
      try {
        if (location.origin !== current.origin) return;
        if (current.mode === "module") {
          const rootPath = new URL(current.modulePath, current.origin).pathname;
          const root = rootPath.endsWith("/") ? rootPath.slice(0, -1) : rootPath;
          const inside = path => path === root || path.startsWith(`${root}/`);
          let candidate = location.pathname;
          let inScope = false;
          for (let depth = 0; depth < 5; depth += 1) {
            if (candidate.includes("\\") || /[\u0000-\u001f]/.test(candidate)) return;
            const decoded = decodeURIComponent(candidate);
            if (decoded.includes("\\") || /[\u0000-\u001f]/.test(decoded) || !inside(new URL(decoded, current.origin).pathname)) return;
            if (decoded === candidate) { inScope = true; break; }
            candidate = decoded;
          }
          if (!inScope) return;
        }
        if (typeof data.url !== "string" || data.url.length > 8192) return;
        const parsed = new URL(data.url);
        const transport = data.transport || "http";
        if (!["http", "websocket", "eventsource", "sendBeacon"].includes(transport)) return;
        const comparableOrigin = new URL(parsed.href);
        if (transport === "websocket") {
          if (comparableOrigin.protocol === "ws:") comparableOrigin.protocol = "http:";
          else if (comparableOrigin.protocol === "wss:") comparableOrigin.protocol = "https:";
        }
        if (comparableOrigin.origin !== current.origin || parsed.username || parsed.password) return;
        parsed.hash = "";
        const queryNames = [...parsed.searchParams.keys()];
        if (queryNames.length) {
          parsed.search = "";
          for (const name of queryNames) parsed.searchParams.append(name, "[redacted]");
        }
        const method = String(data.method || "GET").toUpperCase();
        if (!/^[A-Z!#$%&'*+.^_`|~-]{1,20}$/.test(method)) return;
        const parameterNames = [...new Set((Array.isArray(data.parameterNames) ? data.parameterNames.slice(0, 1000) : []).map(name => String(name || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100)).filter(name => name && !/@|\b\d{8,}\b/.test(name)))].slice(0, 100);
        const allowed = new Set(["content-type", "content-length", "cache-control", "vary", "server", "x-powered-by", "x-aspnet-version", "x-application-context", "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "access-control-allow-origin", "access-control-allow-credentials"]);
        const headers = {};
        if (data.headers && typeof data.headers === "object") {
          for (const [name, value] of Object.entries(data.headers).slice(0, 64)) {
            const key = name.toLowerCase();
            if (allowed.has(key) && typeof value === "string") headers[key] = key === "content-security-policy" ? value.replace(/'nonce-[^']+'/gi, "'nonce-[redacted]'").slice(0, 500) : value.slice(0, 500);
          }
        }
        let moduleControl = null;
        if (data.moduleControl && typeof data.moduleControl === "object" && String(data.moduleControl.pagePath || "") === location.pathname) {
          const label = String(data.moduleControl.label || "").replace(/[\r\n\t]/g, " ").trim()
            .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted]")
            .replace(/\b\+?\d[\d\s().-]{7,}\d\b/g, "[redacted]")
            .replace(/\b[A-Za-z0-9_-]{24,}\b/g, "[redacted]").slice(0, 120);
          const role = String(data.moduleControl.role || "").toLowerCase();
          if (label && ["tab", "button", "menuitem", "step", "link"].includes(role)) moduleControl = { label, role, pagePath: location.pathname };
        }
        const item = {
          url: parsed.href,
          pagePath: location.pathname,
          method,
          status: Math.max(0, Math.min(599, Number(data.status) || 0)),
          durationMs: Math.max(0, Math.min(120000, Number(data.durationMs) || 0)),
          parameterNames,
          parameterNamesSkippedReason: [
            "Body format is not a supported JSON or URL-encoded format.",
            "Request body exceeded the 64 KiB parameter-name inspection limit.",
            "Body format is unsupported or streaming; values were not read."
          ].includes(data.parameterNamesSkippedReason) ? data.parameterNamesSkippedReason : null,
          transport,
          moduleControl,
          headers,
          at: Number.isFinite(Number(data.at)) ? Number(data.at) : Date.now()
        };
        state.accepted += 1;
        state.pending = state.pending.then(async () => {
          let anonymous = null;
          const candidate = current.compareObservedGets && method === "GET" ? String(data.anonymousCandidate || "") : "";
          if (current.compareObservedGets && method !== "GET") {
            anonymous = { suppressed: true, reason: "non-get", outcome: "Observed only; non-GET requests are never replayed without cookies." };
          } else if (current.compareObservedGets && transport !== "http") {
            anonymous = { suppressed: true, reason: "transport", outcome: "Non-HTTP transports are observed only and are never replayed without cookies." };
          } else if (current.compareObservedGets && state.rateLimitPaused) {
            anonymous = { suppressed: true, reason: "rate-limit", outcome: "Further no-cookie comparisons were paused after the server returned HTTP 429 or 503." };
          } else if (current.compareObservedGets && method === "GET" && !candidate) {
            const reasons = new Set([
              "Without-cookie comparison was not enabled.", "Path encoding could not be validated.",
              "Cross-origin or credential-bearing URL was excluded.", "Credential-like query parameter was excluded.",
              "Credential-like or sensitive path was excluded.", "Potentially state-changing route was excluded from automatic GET comparison.",
              "Query parameters were excluded from automatic GET comparison.", "Numeric or UUID path identifier was excluded from automatic GET comparison.",
              "URL could not be validated."
            ]);
            anonymous = { suppressed: true, reason: "filtered", outcome: reasons.has(data.anonymousFilterReason) ? data.anonymousFilterReason : "This route was filtered from automatic no-cookie comparison." };
          } else if (candidate && candidate.length < 8000 && state.checkedUrls.has(candidate)) {
            anonymous = { suppressed: true, reason: "duplicate", outcome: "This URL was already checked once in the current observer session; duplicate checks were skipped." };
          } else if (candidate.length >= 8000) {
            anonymous = { suppressed: true, reason: "too-long", outcome: "URL exceeded the observer comparison length limit and was filtered." };
          } else if (candidate && candidate.length < 8000) {
            let candidateUrl = null;
            try { candidateUrl = new URL(candidate); } catch (_) { candidateUrl = null; }
            const sensitiveName = /(?:token|secret|password|passwd|authorization|session|jwt|signature|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|credential|^auth$|^key$|^code$)/i;
            const sensitivePath = /(?:^|\/)(?:\.env(?:\.[^/]+)?|\.git|actuator|heapdump|credentials|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session|secret|password|logout|logoff|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger|webhook|proxy)(?:\/|$)/i;
            const action = candidateUrl ? candidateUrl.searchParams.get("action") || candidateUrl.searchParams.get("operation") || candidateUrl.searchParams.get("op") || candidateUrl.searchParams.get("cmd") || "" : "";
            const sensitiveQuery = candidateUrl && [...candidateUrl.searchParams.keys()].some(name => sensitiveName.test(name));
            const hasQuery = candidateUrl && [...candidateUrl.searchParams.keys()].length > 0;
            let decodedPath = "";
            try { decodedPath = candidateUrl ? decodeURIComponent(candidateUrl.pathname) : ""; } catch (_) { decodedPath = "!invalid!"; }
            const jwtPath = decodedPath.split("/").some(segment => /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?$/.test(segment));
            const numericOrUuidPath = decodedPath.split("/").some(segment => /^\d{5,}$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment));
            if (candidateUrl && candidateUrl.origin === current.origin && !candidateUrl.username && !candidateUrl.password && candidateUrl.href === item.url &&
                !sensitiveQuery && !hasQuery && !numericOrUuidPath && decodedPath !== "!invalid!" && !sensitivePath.test(decodedPath.toLowerCase()) && !jwtPath &&
                !/^(?:logout|delete|remove|destroy|checkout|purchase|payment|transfer|reset|execute|run|trigger)$/i.test(action)) {
              state.checkedUrls.add(candidate);
              const controller = new AbortController();
              const timeout = setTimeout(() => controller.abort(), 10000);
              try {
                const response = await fetch(candidateUrl.href, { method: "GET", credentials: "omit", redirect: "manual", cache: "no-store", signal: controller.signal });
                if ([429, 503].includes(response.status)) {
                  state.rateLimitPaused = true;
                  const limitedHeaders = {};
                  const allowed = new Set(["content-type", "content-length", "cache-control", "vary", "server", "x-powered-by", "x-aspnet-version", "x-application-context", "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "access-control-allow-origin", "access-control-allow-credentials"]);
                  for (const name of allowed) {
                    try {
                      const value = response.headers.get(name);
                      if (value) limitedHeaders[name] = name === "content-security-policy" ? `present (${value.length} chars)` : value.slice(0, 500);
                    } catch (_) { /* inaccessible header */ }
                  }
                  const rawLength = response.headers.get("content-length");
                  anonymous = { status: response.status, type: response.headers.get("content-type") || "unknown", bytes: /^\d+$/.test(rawLength || "") ? Number(rawLength) : null, byteSource: /^\d+$/.test(rawLength || "") ? "Content-Length" : null, headers: compactHeaders(limitedHeaders), suppressed: false, outcome: `Without-cookie GET returned HTTP ${response.status}; further observer comparisons were paused to respect server rate limiting.` };
                  try { await response.body?.cancel(); } catch (_) { /* rate-limit body is not retained */ }
                } else if (response.status >= 300 && response.status < 400 || response.type === "opaqueredirect") {
                  const redirectTarget = response.headers?.get?.("location") || "";
                  let loginRedirect = false;
                  try { loginRedirect = new URL(redirectTarget, candidateUrl.href).origin === current.origin && /(?:^|\/)(?:login|log-in|signin|sign-in|authenticate|auth)(?:\/|$)/i.test(new URL(redirectTarget, candidateUrl.href).pathname); } catch (_) { /* hidden redirect */ }
                  anonymous = { status: response.status || null, type: response.headers?.get?.("content-type") || "unknown", headers: {}, suppressed: false, outcome: loginRedirect ? "Without-cookie GET redirected to a login/auth route; this suggests protection but needs manual confirmation." : "Without-cookie GET redirected; the destination was not followed." };
                  try { await response.body?.cancel(); } catch (_) { /* no redirect body retained */ }
                } else {
                const anonHeaders = {};
                const allowed = new Set(["content-type", "content-length", "cache-control", "vary", "server", "x-powered-by", "x-aspnet-version", "x-application-context", "content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "access-control-allow-origin", "access-control-allow-credentials"]);
                for (const name of allowed) {
                  try {
                    const value = response.headers.get(name);
                    if (value) anonHeaders[name] = name === "content-security-policy" ? `present (${value.length} chars)` : value.slice(0, 500);
                  } catch (_) { /* ignore inaccessible header */ }
                }
                const anonType = (response.headers.get("content-type") || "unknown").toLowerCase();
                if (isHtmlType(anonType)) {
                  try { await response.body?.cancel(); } catch (_) { /* HTML login/app shells are excluded from access results */ }
                  anonymous = { suppressed: true, outcome: "Without-cookie response was an HTML app/login shell and was excluded from access results." };
                } else {
                const rawLength = response.headers.get("content-length");
                let anonBytes = /^\d+$/.test(rawLength || "") ? Number(rawLength) : null;
                let sizeComplete = anonBytes !== null;
                if (anonBytes === null && response.body) {
                  const reader = response.body.getReader();
                  anonBytes = 0;
                  sizeComplete = false;
                  try {
                    while (anonBytes < 131072) {
                      const { value, done } = await reader.read();
                      if (done) { sizeComplete = true; break; }
                      const remaining = 131072 - anonBytes;
                      anonBytes += Math.min(value.byteLength, remaining);
                      if (value.byteLength > remaining) break;
                    }
                  } finally { try { await reader.cancel(); } catch (_) { /* response body is not retained */ } }
                } else {
                  try { await response.body?.cancel(); } catch (_) { /* response body is not retained */ }
                }
                const anonSizeSource = /^\d+$/.test(rawLength || "") ? "Content-Length" : sizeComplete ? "measured body" : "measured lower bound (128 KiB cap)";
                const sameHeaders = JSON.stringify(headersForComparison(item.headers)) === JSON.stringify(headersForComparison(anonHeaders));
                const sessionDeclared = item.headers["content-length"];
                const comparableSize = anonBytes !== null && sessionDeclared !== undefined;
                const sameSize = comparableSize && String(anonBytes) === String(sessionDeclared);
                const sameType = anonType === String(item.headers["content-type"] || "unknown").toLowerCase();
                let outcome = "Manual review required; response metadata alone cannot prove access control.";
                if ([401, 403].includes(response.status)) outcome = "Without-cookie GET returned an authentication/authorization status.";
                else if (response.status === 200 && response.status === item.status && sameType && sameHeaders && sameSize) outcome = "No difference in measured response metadata. This does not confirm whether response data is authorized; bodies are not inspected.";
                else if (response.status === 200 && response.status === item.status && sameType && sameHeaders && !comparableSize) outcome = "Both requests returned HTTP 200 with matching selected headers, but size comparison is unavailable. Authorization is unconfirmed.";
                else if (response.status === 200) outcome = "Without-cookie GET returned HTTP 200 with metadata that differs from the app request. Authorization is unconfirmed.";
                anonymous = { status: response.status, type: anonType, bytes: anonBytes, byteSource: anonSizeSource, sizeComplete, headers: compactHeaders(anonHeaders), selectedHeadersMatch: sameHeaders, outcome };
                }
              }
              } catch (_) {
                anonymous = { suppressed: true, reason: "request-failed", outcome: "Without-cookie request failed, timed out, or was blocked by the browser; no response metadata was available." };
              } finally { clearTimeout(timeout); }
            } else {
              const filteredOutcome = !candidateUrl
                ? "URL could not be validated."
                : candidateUrl.origin !== current.origin || candidateUrl.username || candidateUrl.password
                  ? "Cross-origin or credential-bearing URL was excluded."
                  : sensitiveQuery
                    ? "Credential-like query parameter was excluded."
                    : decodedPath === "!invalid!"
                      ? "Path encoding could not be validated."
                      : sensitivePath.test(decodedPath.toLowerCase()) || jwtPath
                        ? "Credential-like or sensitive path was excluded."
                        : numericOrUuidPath
                          ? "Numeric or UUID path identifier was excluded from automatic GET comparison."
                          : hasQuery
                            ? "Query parameters were excluded from automatic GET comparison."
                              : candidateUrl.href !== item.url
                                ? "Candidate URL did not match the observed request and was rejected."
                            : "Potentially state-changing route was excluded from automatic GET comparison.";
              anonymous = { suppressed: true, reason: "bridge-filter", outcome: filteredOutcome };
            }
          }
          const stored = await browser.storage.local.get(current.storageKey);
          const prior = stored[current.storageKey] || {};
          const items = cleanItems(prior.items).slice(-999);
          items.push({ ...item, anonymous });
          await browser.storage.local.set({ [current.storageKey]: {
            origin: current.origin,
            mode: current.mode,
            modulePath: current.modulePath,
            tabId: current.tabId,
            compareObservedGets: current.compareObservedGets,
            active: state.active,
            startedAt: prior.startedAt || Date.now(),
            updatedAt: Date.now(),
            items
          } });
        }).catch(() => { /* quota or storage errors do not affect the site request */ });
      } catch (_) { /* reject malformed page messages */ }
    };
    window.addEventListener("message", state.listener);
  }
  browser.storage.local.get(config.storageKey).then(result => {
    const prior = result[config.storageKey] || {};
    const sameScope = prior.origin === config.origin && prior.mode === config.mode && prior.modulePath === config.modulePath;
    const items = sameScope && Date.now() - Number(prior.updatedAt || 0) <= 86400000
      ? cleanItems(prior.items).slice(-1000) : [];
    return browser.storage.local.set({ [config.storageKey]: {
      origin: config.origin, mode: config.mode, modulePath: config.modulePath, tabId: config.tabId, compareObservedGets: config.compareObservedGets,
      active: true, startedAt: sameScope && prior.startedAt ? prior.startedAt : Date.now(),
      updatedAt: Date.now(), items
    } });
  }).catch(() => { /* observer can still run if local storage is unavailable */ });
  return { active: true };
}

function isolatedTrafficStop(storageKey) {
  const state = globalThis.__stackscopeTrafficBridge_v118;
  if (state?.config?.storageKey === storageKey) state.active = false;
  const previous = globalThis.__stackscopeTrafficBridge_v114;
  if (previous?.config?.storageKey === storageKey) {
    previous.active = false;
    try { if (previous.listener) window.removeEventListener("message", previous.listener); } catch (_) { /* remove older bridge listener */ }
  }
  return browser.storage.local.get(storageKey).then(result => {
    const prior = result[storageKey];
    if (!prior) return false;
    return browser.storage.local.set({ [storageKey]: { ...prior, active: false, updatedAt: Date.now() } }).then(() => true);
  });
}

function isMainWorldObserverActive() {
  return Boolean(window.__stackscopePassiveObserver_v118?.active || window.__stackscopeEarlyObserver_v118?.active);
}

function findTokenInObject(value, depth = 0) {
  if (!value || typeof value !== "object" || depth > 4) return null;
  const jwt = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
  const tokenKey = /(?:access|id|auth|refresh)?[._-]?token$|^authorization$|^jwt$|^bearer$|^accesstoken$|^idtoken$/i;
  for (const [key, child] of Object.entries(value)) {
    if (typeof child === "string" && child && (jwt.test(child.trim()) || (tokenKey.test(key) && child.trim().length >= 20))) return child.trim();
  }
  for (const child of Object.values(value)) {
    if (child && typeof child === "object") { const found = findTokenInObject(child, depth + 1); if (found) return found; }
  }
  return null;
}

function pickAuthToken(entries) {
  if (!Array.isArray(entries)) return null;
  const jwt = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
  const tokenKey = /(?:^|[._-])(?:access[._-]?token|id[._-]?token|auth[._-]?token|authorization|jwt|bearer|token|session[._-]?token)(?:$|[._-])/i;
  const opaque = /^[A-Za-z0-9._\-]{20,}$/;
  const candidates = [];
  for (const entry of entries) {
    const key = String(entry?.key || "");
    const value = String(entry?.value || "").trim();
    if (!value) continue;
    if (jwt.test(value)) { candidates.push({ token: value, source: `${entry.store}.${key}`, kind: "jwt" }); continue; }
    if (/^[\[{]/.test(value)) {
      try {
        const found = findTokenInObject(JSON.parse(value));
        if (found) { candidates.push({ token: found, source: `${entry.store}.${key} (json)`, kind: jwt.test(found) ? "jwt" : "opaque" }); continue; }
      } catch (_) { /* value is not JSON */ }
    }
    if (tokenKey.test(key) && opaque.test(value)) candidates.push({ token: value, source: `${entry.store}.${key}`, kind: "opaque" });
  }
  const best = candidates.find(item => item.kind === "jwt") || candidates[0];
  if (!best) return null;
  return { headerName: "Authorization", headerValue: `Bearer ${best.token}`, source: best.source, kind: best.kind };
}

async function captureAuthTokenFromPage(tabId) {
  if (!tabId || !browser.scripting?.executeScript) return null;
  try {
    const results = await browser.scripting.executeScript({
      target: { tabId },
      func: () => {
        const out = [];
        const read = (store, name) => {
          try {
            for (let index = 0; index < store.length && out.length < 500; index += 1) {
              const key = store.key(index);
              let value = "";
              try { value = store.getItem(key) || ""; } catch (_) { continue; }
              if (value) out.push({ store: name, key, value: value.slice(0, 8192) });
            }
          } catch (_) { /* storage access blocked */ }
        };
        try { read(window.localStorage, "localStorage"); } catch (_) { /* unavailable */ }
        try { read(window.sessionStorage, "sessionStorage"); } catch (_) { /* unavailable */ }
        return out;
      }
    });
    return pickAuthToken(results?.[0]?.result || []);
  } catch (_) { return null; }
}

function buildScanPermissionOrigins() {
  const snapshot = activeTabSnapshot;
  if (!snapshot?.url || !/^https?:/i.test(snapshot.url)) throw new Error("Open an HTTP/HTTPS target tab first.");
  const current = new URL(snapshot.url);
  const assetOrigins = parseAuthorizedAssetOrigins($("assetOrigins").value, current.origin);
  const permissionOrigin = `${current.protocol}//${current.hostname}/*`;
  return [permissionOrigin, ...assetOrigins.map(assetOrigin => `${new URL(assetOrigin).protocol}//${new URL(assetOrigin).hostname}/*`)];
}

async function scan(permissionRequest) {
  stopRequested = false;
  lastReport = null;
  $("start").disabled = true;
  $("stop").disabled = false;
  $("results").hidden = true;
  $("reportDecision").hidden = true;
  $("status").textContent = "Preparing the scoped scan…";

  try {
    const [refreshedTab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!refreshedTab) throw new Error("Could not confirm the active tab. Reopen StackScope on the intended target before scanning.");
    assertActiveTargetUnchanged(refreshedTab);
    const tab = refreshedTab;
    activeTabSnapshot = tab || null;
    if (!tab?.url || !/^https?:/i.test(tab.url)) throw new Error("Open an HTTP/HTTPS target tab first.");

    const current = new URL(tab.url);
    current.hash = "";
    const origin = current.origin;
    const mode = $("scopeMode").value;
    const modulePath = mode === "module" ? normalizeModulePath($("modulePath").value) : null;
    const assetOrigins = parseAuthorizedAssetOrigins($("assetOrigins").value, origin);
    const importAliases = parseImportAliases($("importAliases").value, origin);
    const apiPrefixes = parseApiPrefixes($("apiPrefixes").value);
    const permissionOrigin = `${current.protocol}//${current.hostname}/*`;
    const requestedOrigins = [permissionOrigin, ...assetOrigins.map(assetOrigin => `${new URL(assetOrigin).protocol}//${new URL(assetOrigin).hostname}/*`)];
    // permissions.request must be invoked from the user gesture, so the click
    // handler starts it and passes the pending promise here. Fall back to a
    // direct request only when the scan was started programmatically.
    const granted = permissionRequest ? await permissionRequest : await browser.permissions.request({ origins: requestedOrigins });
    if (!granted) throw new Error("Site access was not granted, so no crawl requests were made.");

    const useStoredToken = $("useStoredToken")?.checked || false;
    const capturedToken = useStoredToken ? await captureAuthTokenFromPage(tab.id) : null;
    const crawlHeaders = capturedToken ? { [capturedToken.headerName]: capturedToken.headerValue } : {};
    if (useStoredToken) $("status").textContent = capturedToken ? `Using bearer token from ${capturedToken.source} for the authenticated crawl…` : "No bearer token found in page storage; crawling with cookies only…";

    const scope = url => isInScope(url, origin, mode, modulePath);
    const sameOrigin = url => isSameOriginUrl(url, origin);
    const scriptOrigin = url => sameOrigin(url) || isInOriginList(url, assetOrigins);
    const maxPages = Math.max(10, Math.min(5000, Number($("maxPages").value) || 1000));
    const crawlJs = $("crawlJs").checked;
    const only200 = $("only200").checked;
    const checkAnonymous = $("checkAnonymous").checked;
    const anonymousLimit = Math.max(1, Math.min(2000, Number($("anonymousLimit").value) || 250));
    const seeds = [];
    if (scope(current.href)) seeds.push({ url: current.href, depth: 0, kind: "page" });
    if (mode === "module") {
      const moduleRoot = new URL(modulePath, origin).href;
      if (scope(moduleRoot)) seeds.push({ url: moduleRoot, depth: 0, kind: "page" });
    }
    seeds.push(...seedManifestCandidates(origin, mode, modulePath));

    const queue = [];
    const queued = new Set();
    const visited = new Set();
    const withheld = new Map();
    const endpoints = [];
    const authBaselines = [];
    const pageBaselines = [];
    const pages = [];
    const routeCandidates = [];
    const routeCandidateKeys = new Set();
    const requestIssues = [];
    const formActions = [];
    const formActionKeys = new Set();
    const nonGetCallSites = [];
    const nonGetCallSiteKeys = new Set();
    const graphqlOperations = [];
    const graphqlOperationKeys = new Set();
    const transportEndpoints = [];
    const transportKeys = new Set();
    const importMaps = [];
    const unresolvedImports = [];
    const unresolvedImportKeys = new Set();
    const uiModules = [];
    const uiModuleKeys = new Set();
    const inputFields = [];
    const inputFieldKeys = new Set();
    const scriptUrls = new Set();
    const externalScriptHosts = new Set();
    let externalScriptReferences = 0;
    const textCorpus = [];
    const headersBag = {};
    let corpusChars = 0;
    let requestCount = 0;
    const scanDeadline = Date.now() + Math.max(60_000, Math.min(30 * 60_000, (Number($("scanDeadlineMinutes")?.value) || 10) * 60_000));
    let scanDeadlineReached = false;
    let rateLimitBackoffUntil = 0;
    let tooLongRetryAfter = false;
    const familyRequestCounts = new Map();
    let anonymousBackoffUntil = 0;
    let requestLimitReached = false;
    let htmlRouteResponsesSuppressed = 0;
    let anonymousHtmlResponsesSuppressed = 0;
    let anonymousUnavailableSuppressed = 0;
    let anonymousCredentialQuerySkipped = 0;
    let live = { html: "", inlineScripts: [], importMaps: [], links: [], scripts: [], resources: [], htmlHints: [], uiModules: [], inputFields: [], formActions: [] };
    const scriptIndicators = [];
    const scriptIndicatorKeys = new Set();
    const secretFindings = [];
    const secretFindingKeys = new Set();
    const addScriptUrl = url => {
      if (scriptUrls.size < maxPages) scriptUrls.add(url);
    };
    const rememberImportMaps = (candidates, baseUrl) => {
      for (const candidate of candidates || []) {
        try {
          const parsed = JSON.parse(String(candidate.source || ""));
          if (!parsed || typeof parsed !== "object" || !parsed.imports || typeof parsed.imports !== "object") continue;
          const imports = {};
          for (const [specifier, target] of Object.entries(parsed.imports).slice(0, 200)) {
            if (typeof target !== "string") continue;
            const resolved = cleanUrl(target, candidate.base || baseUrl);
            if (resolved) imports[String(specifier).slice(0, 200)] = resolved;
          }
          if (Object.keys(imports).length) importMaps.push({ base: candidate.base || baseUrl, imports });
        } catch (_) { /* malformed import maps are reported as unresolved imports only */ }
      }
    };
    const rememberRouteCandidate = (rawUrl, source, kind, reason = "Dynamic path value could not be resolved safely; review with an approved test account.") => {
      const displayInput = String(rawUrl || "").replace(/\$\{([^}]{1,200})\}/g, "STACKSCOPE_PARAM_$1").replace(/\{\{([^}]{1,200})\}\}/g, "STACKSCOPE_PARAM_$1");
      const parsed = cleanUrl(displayInput, source || current.href);
      if (!parsed || !sameOrigin(parsed)) return;
      const display = reportUrl(parsed).replace(/STACKSCOPE_PARAM_([A-Za-z0-9_$.-]+)/g, "{$1}");
      const key = `${kind}|${display}`;
      if (routeCandidateKeys.has(key) || routeCandidates.length >= 1000) return;
      routeCandidateKeys.add(key);
      routeCandidates.push({ url: display, source: reportUrl(source || current.href), kind, requested: false, reason });
    };
    const rememberUnresolvedImport = (specifier, sourceUrl) => {
      const key = `${sourceUrl}|${specifier}`;
      if (unresolvedImportKeys.has(key) || unresolvedImports.length >= 500) return;
      unresolvedImportKeys.add(key);
      unresolvedImports.push({ specifier: String(specifier).slice(0, 300), source: reportUrl(sourceUrl), reason: "No relative path, import-map entry, or configured alias resolved this specifier." });
    };
    const rememberUiModules = (candidates, baseUrl) => {
      for (const candidate of candidates || []) {
        const label = String(candidate?.label || "").replace(/\s+/g, " ").trim().slice(0, 80);
        if (label.length < 2 || /@|\b\d{8,}\b/.test(label) || !/[a-z]/i.test(label)) continue;
        const resolved = candidate.href ? cleanUrl(candidate.href, baseUrl) : null;
        const href = resolved && scope(resolved) ? reportUrl(resolved) : null;
        const path = href || reportUrl(baseUrl);
        const group = ["Navigation", "Tab", "Step"].includes(candidate.group) ? candidate.group : "Module";
        const control = String(candidate.control || "control").slice(0, 24);
        const key = `${group}|${label.toLowerCase()}|${path}`;
        if (uiModuleKeys.has(key) || uiModules.length >= 200) continue;
        uiModuleKeys.add(key);
        uiModules.push({ label, group, control, selected: Boolean(candidate.selected), path, href });
      }
    };
    const rememberInputFields = (candidates, baseUrl) => {
      for (const candidate of candidates || []) {
        const name = String(candidate?.name || "").replace(/[\r\n\t]/g, " ").trim().slice(0, 100);
        if (!name || inputFields.length >= 1000) continue;
        const page = reportUrl(baseUrl);
        const actionUrl = candidate.action ? cleanUrl(candidate.action, baseUrl) : null;
        const action = actionUrl && sameOrigin(actionUrl) ? reportUrl(actionUrl) : null;
        const field = {
          name,
          type: String(candidate.type || "text").slice(0, 32),
          label: String(candidate.label || name).replace(/\s+/g, " ").trim().slice(0, 100),
          required: Boolean(candidate.required),
          method: String(candidate.method || "GET").toUpperCase().slice(0, 12),
          action,
          page
        };
        const key = `${page}|${field.name}|${field.type}|${field.action || ""}`;
        if (inputFieldKeys.has(key)) continue;
        inputFieldKeys.add(key);
        inputFields.push(field);
      }
    };
    const rememberFormActions = (candidates, baseUrl) => {
      for (const candidate of candidates || []) {
        const url = cleanUrl(candidate?.url, baseUrl);
        const method = String(candidate?.method || "GET").toUpperCase().slice(0, 12);
        if (!url || !sameOrigin(url) || !/^[A-Z]{3,12}$/.test(method)) continue;
        const record = { url: reportUrl(url), method, page: reportUrl(candidate.page || baseUrl), requested: false };
        const key = `${record.method}|${record.url}|${record.page}`;
        if (formActionKeys.has(key) || formActions.length >= 500) continue;
        formActionKeys.add(key);
        formActions.push(record);
      }
    };
    const rememberNonGetCallSite = (target, sourceUrl) => {
      if (!target?.url || !sameOrigin(target.url)) return;
      const record = { url: reportUrl(target.url), method: String(target.method || "UNKNOWN").toUpperCase(), source: reportUrl(sourceUrl), requested: false, reason: "The extension does not send non-GET requests." };
      const key = `${record.method}|${record.url}|${record.source}`;
      if (nonGetCallSiteKeys.has(key) || nonGetCallSites.length >= 1000) return;
      nonGetCallSiteKeys.add(key);
      nonGetCallSites.push(record);
    };
    const rememberRequestIssue = (rawUrl, type, reason, status = null, redirectTarget = null) => {
      if (requestIssues.length >= 1000) return;
      const url = cleanUrl(rawUrl, current.href);
      if (!url) return;
      requestIssues.push({ url: reportUrl(url), type, reason, status, redirectTarget: redirectTarget ? reportUrl(redirectTarget) : null });
    };
    const noteExternalScript = rawUrl => {
      const url = cleanUrl(rawUrl, current.href);
      if (!url || scriptOrigin(url)) return;
      externalScriptReferences += 1;
      try { if (externalScriptHosts.size < 50) externalScriptHosts.add(new URL(url).host); } catch (_) { /* skip malformed asset references */ }
    };

    // Read the current page only when it is inside the selected boundary.
    if (scope(current.href)) {
      try {
        const injected = await browser.scripting.executeScript({ target: { tabId: tab.id }, func: pageSnapshotCode() });
        if (injected?.[0]?.result) live = { ...live, ...injected[0].result };
      } catch (_) {
        // Browser-internal/restricted pages can deny injection; the HTTP crawl can still continue.
      }
    }
    rememberUiModules(live.uiModules, current.href);
    rememberInputFields(live.inputFields, current.href);
    rememberFormActions(live.formActions, current.href);
    rememberImportMaps(live.importMaps, current.href);

    const enqueue = (rawUrl, depth, kind, base = current.href, allowOutOfModuleApi = false, discoveryBase = current.href) => {
      if (queued.size >= maxPages) {
        requestLimitReached = true;
        return;
      }
      const url = cleanUrl(rawUrl, base);
      if (!url || queued.has(url)) return;
      const normalizedKind = kind === "js" || /\.(?:m?js|cjs)(?:[?#]|$)/i.test(url) ? "js" : kind;
      const allowed = normalizedKind === "page" ? scope(url) : normalizedKind === "js" ? scriptOrigin(url) :
        (scope(url) || (sameOrigin(url) && (allowOutOfModuleApi || isLikelyApiEndpoint(url))));
      if (!allowed) return;
      const blockReason = blockedRequestReason(url);
      if (blockReason) {
        if (!withheld.has(url) && withheld.size < maxPages) withheld.set(url, blockReason);
        return;
      }
      if (normalizedKind === "js") addScriptUrl(url);
      queued.add(url);
      queue.push({ url, depth, kind: normalizedKind, discoveryBase: cleanUrl(discoveryBase, current.href) || current.href });
    };
    const enqueueDiscoveredUrl = (rawUrl, depth, base) => {
      const url = cleanUrl(rawUrl, base);
      if (!url || !sameOrigin(url) || isStaticNonScriptAsset(url)) return;
      if (isLikelyApiEndpoint(url) || matchesApiPrefix(url, apiPrefixes)) enqueue(url, depth, "endpoint", base, true);
      else if (scope(url)) enqueue(url, depth, "page", base);
    };
    const initialNextManifest = nextBuildManifestUrl(live.html, current.href);
    if (crawlJs && initialNextManifest && scriptOrigin(initialNextManifest)) enqueue(initialNextManifest, 1, "js", current.href, false, current.href);
    const analyzeScriptText = (text, sourceUrl, depth, discoveryBase = current.href) => {
      if (!crawlJs || !text) return;
      collectSensitiveIndicators(text, sourceUrl, scriptIndicators, scriptIndicatorKeys);
      extractSecretFindings(text, sourceUrl, secretFindings, secretFindingKeys);
      const importPattern = /(?:import\s*(?:[^"'`]*?from\s*)?|import\s*\(|export\s+[^"'`]*?from\s*|require\s*\()\s*["'`]([^"'`]+)["'`]/g;
      let match;
      while ((match = importPattern.exec(text)) !== null) {
        const specifier = match[1];
        const url = resolveImportSpecifier(specifier, sourceUrl, importMaps, importAliases, origin);
        if (!url) { rememberUnresolvedImport(specifier, sourceUrl); continue; }
        if (!scriptOrigin(url)) { noteExternalScript(url); continue; }
        addScriptUrl(url);
        enqueue(url, depth + 1, "js", sourceUrl, false, discoveryBase);
      }
      const sourceMapPattern = /[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/g;
      while ((match = sourceMapPattern.exec(text)) !== null) {
        const mapUrl = cleanUrl(match[1], sourceUrl);
        if (mapUrl && scriptOrigin(mapUrl) && /\.map(?:[?#]|$)/i.test(mapUrl)) enqueue(mapUrl, depth + 1, "js", sourceUrl, false, discoveryBase);
      }
      for (const chunkUrl of extractBundlerChunkUrls(text, sourceUrl)) {
        if (!scriptOrigin(chunkUrl)) { noteExternalScript(chunkUrl); continue; }
        addScriptUrl(chunkUrl);
        enqueue(chunkUrl, depth + 1, "js", sourceUrl, false, discoveryBase);
      }
      for (const scriptUrl of extractDynamicScriptUrls(text, discoveryBase)) {
        if (!scriptOrigin(scriptUrl)) { noteExternalScript(scriptUrl); continue; }
        addScriptUrl(scriptUrl);
        enqueue(scriptUrl, depth + 1, "js", discoveryBase, false, discoveryBase);
      }
      for (const transport of extractTransportEndpoints(text, discoveryBase, origin)) {
        const key = `${transport.type}|${transport.url}`;
        if (!transportKeys.has(key) && transportEndpoints.length < 500) {
          transportKeys.add(key);
          transportEndpoints.push({ ...transport, source: reportUrl(sourceUrl), requested: false });
        }
      }
      const graphql = extractGraphqlMetadata(text, sourceUrl);
      for (const operation of graphql.operations) {
        const key = `${operation.operationType}|${operation.operationName || ""}|${operation.source}|${operation.fieldNames.join(",")}`;
        if (!graphqlOperationKeys.has(key) && graphqlOperations.length < 500) {
          graphqlOperationKeys.add(key);
          graphqlOperations.push(operation);
        }
      }
      for (const hash of graphql.persistedQueryHashes) {
        const key = `persisted|${hash}|${reportUrl(sourceUrl)}`;
        if (!graphqlOperationKeys.has(key) && graphqlOperations.length < 500) {
          graphqlOperationKeys.add(key);
          graphqlOperations.push({ operationType: "persisted-query", operationName: null, fieldNames: [], persistedQueryHash: hash, source: reportUrl(sourceUrl) });
        }
      }
      const apiTargets = extractApiCallTargets(text, discoveryBase);
      const nonGetTargets = new Set();
      for (const target of apiTargets) {
        if (target.dynamic) {
          rememberRouteCandidate(target.expression, discoveryBase, `Dynamic ${target.method} API`);
          nonGetTargets.add(target.url);
        } else if (target.method === "GET") enqueue(target.url, depth + 1, "endpoint", discoveryBase, true, discoveryBase);
        else {
          nonGetTargets.add(target.url);
          rememberNonGetCallSite(target, sourceUrl);
        }
      }
      const dynamicRoutePattern = /["'`]([^"'`\r\n]{1,500}\$\{[^}]{1,200}\}[^"'`\r\n]{0,300})["'`]/g;
      while ((match = dynamicRoutePattern.exec(text)) !== null) {
        if (/^(?:https?:\/\/|\/|[A-Za-z0-9_.~-]+\/)/i.test(match[1])) rememberRouteCandidate(match[1], discoveryBase, "Dynamic URL template");
      }
      for (const url of extractUrls(text, discoveryBase)) {
        if (!nonGetTargets.has(url)) enqueueDiscoveredUrl(url, depth + 1, discoveryBase);
      }
    };
    for (const seed of seeds) enqueue(seed.url, seed.depth, seed.kind);
    for (const rawUrl of [...live.links, ...live.scripts]) {
      const url = cleanUrl(rawUrl, current.href);
      const scriptAsset = live.scripts.includes(rawUrl) || /\.(?:m?js|cjs)(?:[?#]|$)/i.test(url || "");
      if (!url || (scriptAsset ? !scriptOrigin(url) : !scope(url))) {
        if (scriptAsset) noteExternalScript(url);
        continue;
      }
      if (scriptAsset) {
        addScriptUrl(url);
        if (crawlJs) enqueue(url, 1, "js", current.href, false, current.href);
      } else {
        enqueue(url, 1, "page", current.href, false, current.href);
      }
    }
    for (const resource of live.resources) {
      const rawUrl = typeof resource === "string" ? resource : resource.url;
      const kind = typeof resource === "string" ? "" : String(resource.type || "").toLowerCase();
      const url = cleanUrl(rawUrl, current.href);
      if (!url) continue;
      if (kind === "script" || /\.(?:m?js|cjs)(?:[?#]|$)/i.test(url)) {
        if (!scriptOrigin(url)) { noteExternalScript(url); continue; }
        addScriptUrl(url);
        if (crawlJs) enqueue(url, 1, "js", current.href, false, current.href);
      } else if (["fetch", "xmlhttprequest"].includes(kind) && sameOrigin(url)) {
        rememberRouteCandidate(url, current.href, `Observed ${kind} resource (HTTP method unknown)`, "The browser resource entry does not expose the HTTP method; it was listed but not requested as a guessed GET.");
      }
    }
    (live.inlineScripts || []).forEach((code, index) => {
      analyzeScriptText(code, `${reportUrl(current.href)}#inline-script-${index + 1}`, 0, current.href);
    });

    if (live.html) {
      const initialHtml = live.html.slice(0, 500_000);
      textCorpus.push(initialHtml);
      corpusChars += initialHtml.length;
    }

    const updateStatus = () => {
      const responseCount = endpoints.length;
      $("status").textContent = `Requested ${visited.size}/${maxPages} URLs · ${responseCount} endpoint responses recorded · ${queue.length} queued${stopRequested ? " · stopping" : ""}`;
    };

    while (queue.length && visited.size < maxPages && !stopRequested && corpusChars < 8_000_000 && Date.now() < scanDeadline) {
      while (rateLimitBackoffUntil > Date.now() && !stopRequested && Date.now() < scanDeadline) {
        const pause = Math.min(500, rateLimitBackoffUntil - Date.now(), scanDeadline - Date.now());
        if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
      }
      if (stopRequested || Date.now() >= scanDeadline) break;
      const item = queue.splice(chooseNextQueueIndex(queue, familyRequestCounts), 1)[0];
      const itemAllowed = item.kind === "page" ? scope(item.url) : item.kind === "js" ? scriptOrigin(item.url) : sameOrigin(item.url);
      if (visited.has(item.url) || !itemAllowed) continue;
      const blockReason = blockedRequestReason(item.url);
      if (blockReason) {
        if (!withheld.has(item.url) && withheld.size < maxPages) withheld.set(item.url, blockReason);
        continue;
      }
      visited.add(item.url);
      requestCount += 1;
      updateStatus();

      const requestController = new AbortController();
      activeController = requestController;
      const requestTimeout = setTimeout(() => requestController.abort(), 15_000);
      try {
        // GET only. Redirects are inspected manually so only an in-scope target can be queued.
        const response = await fetch(item.url, { method: "GET", credentials: "include", headers: crawlHeaders, redirect: "manual", cache: "no-store", signal: requestController.signal });
        if (response.status >= 300 && response.status < 400 || response.type === "opaqueredirect") {
          const location = response.headers?.get?.("location") || "";
          const redirectTarget = location ? cleanUrl(location, item.url) : null;
          const targetAllowed = redirectTarget && (item.kind === "page" ? scope(redirectTarget) : item.kind === "js" ? scriptOrigin(redirectTarget) : sameOrigin(redirectTarget));
          rememberRequestIssue(item.url, "redirect", targetAllowed ? "Redirect target was found and queued within scope." : redirectTarget ? "Redirect target is outside the authorized origin or selected module path; it was not requested." : "Redirect target is hidden or unavailable; it was not followed.", response.status || null, redirectTarget);
          if (targetAllowed) enqueue(redirectTarget, item.depth + 1, item.kind, item.url, item.kind === "endpoint", item.discoveryBase || current.href);
          try { await response.body?.cancel(); } catch (_) { /* no redirect response body retained */ }
          await new Promise(resolve => setTimeout(resolve, 120));
          continue;
        }
        if ([429, 503].includes(response.status)) {
          const retryDelay = retryAfterDelayMs(response.headers.get("retry-after"));
          rememberRequestIssue(item.url, "rate-limit", retryDelay === null ? `Server returned HTTP ${response.status}; no valid Retry-After was provided, so the scan paused.` : `Server returned HTTP ${response.status}; Retry-After was ${Math.ceil(retryDelay / 1000)} seconds.`, response.status);
          try { await response.body?.cancel(); } catch (_) { /* no error body retained */ }
          if (retryDelay === null || retryDelay > 30_000) {
            tooLongRetryAfter = true;
            break;
          }
          rateLimitBackoffUntil = Math.max(rateLimitBackoffUntil, Date.now() + retryDelay);
          continue;
        }
        const finalUrl = cleanUrl(response.url || item.url, item.url);
        if (!finalUrl || (item.kind === "page" ? !scope(finalUrl) : item.kind === "js" ? !scriptOrigin(finalUrl) : !sameOrigin(finalUrl))) continue;
        const contentType = (response.headers.get("content-type") || "").toLowerCase();
        let isHtml = isHtmlDocument(contentType);
        const isScript = item.kind === "js" || /(?:javascript|ecmascript)/i.test(contentType) || /\.(?:m?js|cjs)(?:[?#]|$)/i.test(finalUrl);
        const isSourceMap = /\.map(?:[?#]|$)/i.test(finalUrl);
        const headers = responseHeaders(response.headers);
        const rawLength = response.headers.get("content-length");
        const declaredBytes = /^\d+$/.test(rawLength || "") ? Number(rawLength) : null;
        if (item.depth === 0) Object.assign(headersBag, headers);
        const readable = contentType.includes("text/html") || contentType.includes("javascript") || contentType.includes("ecmascript") || contentType.includes("json") || contentType.startsWith("text/") || isScript;
        const sniffUnknownType = !contentType && !isScript;
        let body = "";
        let bodyMetrics = { bytesRead: 0, complete: true };
        if ((readable || sniffUnknownType) && corpusChars < 8_000_000) {
          const bodyLimit = readable ? Math.min(1_500_000, 8_000_000 - corpusChars) : 128 * 1024;
          const readResult = await readTextLimited(response, bodyLimit);
          body = readResult.text;
          bodyMetrics = { bytesRead: readResult.bytesRead, complete: readResult.complete };
          if (readable) {
            corpusChars += body.length;
            if (body) textCorpus.push(body.slice(0, 500_000));
          }
        } else {
          bodyMetrics = await measureBodyWithoutRetaining(response);
        }
        if (!isHtml && looksLikeHtmlDocument(body)) isHtml = true;
        const effectiveBytes = declaredBytes ?? bodyMetrics.bytesRead;
        const sizeComplete = declaredBytes !== null || bodyMetrics.complete;
        const byteSource = declaredBytes !== null ? "Content-Length" : bodyMetrics.complete ? "measured body" : "measured lower bound (128 KiB cap)";
        const usefulEndpoint = !isHtml && isUsefulEndpoint(finalUrl, contentType, item.kind);
        let authBaseline = null;
        if (checkAnonymous && !isScript && item.kind !== "js" && usefulEndpoint) {
          authBaseline = {
            url: finalUrl, status: response.status, type: contentType || "unknown", headers, kind: "api",
            bytes: effectiveBytes, byteSource, sizeComplete
          };
          authBaselines.push(authBaseline);
        }
        let endpointRecord = null;
        if (item.kind !== "js" && usefulEndpoint && (!only200 || response.status === 200)) {
          endpointRecord = {
            url: finalUrl, status: response.status, type: contentType || "unknown", kind: item.kind, depth: item.depth,
            bytes: effectiveBytes, byteSource, sizeComplete, parameters: getQueryParameterNames(finalUrl), headers
          };
          endpoints.push(endpointRecord);
        }
        if (isHtml) htmlRouteResponsesSuppressed += 1;
        if (authBaseline) Object.assign(authBaseline, { bytes: effectiveBytes, byteSource, sizeComplete });
        if (endpointRecord) Object.assign(endpointRecord, { bytes: effectiveBytes, byteSource, sizeComplete });

        if (isHtml && item.kind === "page") {
          const pageType = contentType || "text/html (body detected)";
          const pageRecord = { url: reportUrl(finalUrl), status: response.status, type: pageType, depth: item.depth, bytes: effectiveBytes, byteSource, sizeComplete, parameters: getQueryParameterNames(finalUrl), headers };
          pages.push(pageRecord);
          if (checkAnonymous) pageBaselines.push({ url: finalUrl, status: response.status, type: pageType, depth: item.depth, bytes: effectiveBytes, byteSource, sizeComplete, headers, kind: "page" });
        }
        if (isHtml && body) {
          const parser = new DOMParser();
          const dom = parser.parseFromString(body, "text/html");
          rememberImportMaps(importMapCandidatesFromDocument(dom, finalUrl), finalUrl);
          rememberUiModules(uiModuleCandidatesFromDocument(dom, finalUrl), finalUrl);
          rememberInputFields(inputFieldCandidatesFromDocument(dom, finalUrl), finalUrl);
          rememberFormActions(formActionCandidatesFromDocument(dom, finalUrl), finalUrl);
          const buildManifest = nextBuildManifestUrl(body, finalUrl);
          if (crawlJs && buildManifest && scriptOrigin(buildManifest)) enqueue(buildManifest, item.depth + 1, "js", finalUrl, false, finalUrl);
          for (const element of dom.querySelectorAll("a[href],area[href],form[action],script[src],iframe[src],link[href]")) {
            if (element.tagName === "FORM" && (element.getAttribute("method") || "get").toUpperCase() !== "GET") continue;
            const rawUrl = element.getAttribute("href") || element.getAttribute("action") || element.getAttribute("src");
            const url = cleanUrl(rawUrl, finalUrl);
            const linkRel = (element.getAttribute("rel") || "").toLowerCase();
            const scriptAsset = element.tagName === "SCRIPT" || (element.tagName === "LINK" && (linkRel === "modulepreload" || (linkRel === "preload" && (element.getAttribute("as") || "").toLowerCase() === "script")));
            if (!url || (!scriptAsset && isStaticNonScriptAsset(url)) || (scriptAsset ? !scriptOrigin(url) : !scope(url))) {
              if (scriptAsset) noteExternalScript(url);
              continue;
            }
            if (scriptAsset) {
              addScriptUrl(url);
              if (crawlJs) enqueue(url, item.depth + 1, "js", finalUrl, false, finalUrl);
            } else if (["A", "AREA", "FORM", "IFRAME"].includes(element.tagName)) {
              enqueue(url, item.depth + 1, "page", finalUrl, false, finalUrl);
            }
          }
          let inlineIndex = 0;
          let inlineBudget = 1_000_000;
          for (const inlineScript of dom.querySelectorAll("script:not([src])")) {
            if (inlineBudget <= 0 || inlineIndex >= 200) break;
            const code = (inlineScript.textContent || "").slice(0, Math.min(100_000, inlineBudget));
            inlineBudget -= code.length;
            if (!code) continue;
            inlineIndex += 1;
            analyzeScriptText(code, `${reportUrl(finalUrl)}#inline-script-${inlineIndex}`, item.depth, finalUrl);
          }
        } else if (isSourceMap && body) {
          addScriptUrl(finalUrl);
          try {
            const sourceMap = JSON.parse(body);
            if (Array.isArray(sourceMap.sourcesContent)) {
              sourceMap.sourcesContent.slice(0, 100).forEach((sourceText, index) => {
                if (typeof sourceText === "string") analyzeScriptText(sourceText, `${reportUrl(finalUrl)}#source-${index + 1}`, item.depth, item.discoveryBase || current.href);
              });
            } else if (Array.isArray(sourceMap.sources)) {
              const sourceBase = sourceMap.sourceRoot ? cleanUrl(sourceMap.sourceRoot, finalUrl) || finalUrl : finalUrl;
              for (const source of sourceMap.sources.slice(0, 200)) {
                const sourceUrl = cleanUrl(source, sourceBase);
                if (sourceUrl && scriptOrigin(sourceUrl) && /\.(?:m?js|cjs)(?:[?#]|$)/i.test(sourceUrl)) {
                  addScriptUrl(sourceUrl);
                  if (crawlJs) enqueue(sourceUrl, item.depth + 1, "js", sourceBase, false, item.discoveryBase || current.href);
                }
              }
            }
          } catch (_) {
            // Malformed source maps remain ordinary text and are not interpreted.
          }
        } else if (isScript && body) {
          addScriptUrl(finalUrl);
          analyzeScriptText(body, reportUrl(finalUrl), item.depth, item.discoveryBase || current.href);
        } else if (body && (contentType.includes("json") || contentType.startsWith("text/"))) {
          if (crawlJs && (contentType.includes("json") || /manifest/i.test(finalUrl))) {
            for (const manifestScript of extractManifestScriptUrls(body, finalUrl)) {
              if (scriptOrigin(manifestScript)) enqueue(manifestScript, item.depth + 1, "js", finalUrl, false, item.discoveryBase || current.href);
              else noteExternalScript(manifestScript);
            }
          }
          for (const url of extractUrls(body, finalUrl)) enqueueDiscoveredUrl(url, item.depth + 1, finalUrl);
          if (/<loc\b/i.test(body)) {
            for (const url of extractSitemapLocations(body, finalUrl)) enqueueDiscoveredUrl(url, item.depth + 1, finalUrl);
          }
          if (/\/robots\.txt$/i.test(new URL(finalUrl).pathname)) {
            for (const url of extractRobotsSitemaps(body, finalUrl)) enqueueDiscoveredUrl(url, item.depth + 1, finalUrl);
          }
        }
      } catch (error) {
        rememberRequestIssue(item.url, "fetch-failure", classifyFetchFailure(error, requestController.signal.aborted));
      } finally {
        clearTimeout(requestTimeout);
        if (activeController === requestController) activeController = null;
      }
      try {
        const requestPath = new URL(item.url).pathname;
        const family = `/${requestPath.split("/").filter(Boolean)[0] || ""}/`;
        familyRequestCounts.set(family, (familyRequestCounts.get(family) || 0) + 1);
      } catch (_) { /* malformed paths do not affect scheduling fairness */ }
      updateStatus();
      await new Promise(resolve => setTimeout(resolve, 120));
    }
    if (Date.now() >= scanDeadline && queue.length) scanDeadlineReached = true;
    if (visited.size >= maxPages && queue.length) requestLimitReached = true;

    const anonymousChecks = [];
    const anonymousPageChecks = [];
    let anonymousRequestsAttempted = 0;
    let anonymousPageShellResponses = 0;
    let anonymousPageUnavailable = 0;
    if (checkAnonymous && !stopRequested) {
      const targets = [];
      const targetCount = Math.max(authBaselines.length, pageBaselines.length);
      for (let index = 0; index < targetCount; index += 1) {
        if (authBaselines[index]) targets.push(authBaselines[index]);
        if (pageBaselines[index]) targets.push(pageBaselines[index]);
      }
      const boundedTargets = targets.slice(0, anonymousLimit);
      for (const baseline of boundedTargets) {
        if (stopRequested || Date.now() >= scanDeadline) { if (Date.now() >= scanDeadline) scanDeadlineReached = true; break; }
        while (anonymousBackoffUntil > Date.now() && !stopRequested && Date.now() < scanDeadline) {
          const pause = Math.min(500, anonymousBackoffUntil - Date.now(), scanDeadline - Date.now());
          if (pause > 0) await new Promise(resolve => setTimeout(resolve, pause));
        }
        if (stopRequested || Date.now() >= scanDeadline) { if (Date.now() >= scanDeadline) scanDeadlineReached = true; break; }
        const pageTarget = baseline.kind === "page";
        if (!sameOrigin(baseline.url)) continue;
        const blockedReason = blockedRequestReason(baseline.url);
        if (blockedReason) {
          if (pageTarget) anonymousPageChecks.push({ url: reportUrl(baseline.url), sessionStatus: baseline.status, anonymousStatus: null, sessionType: baseline.type, anonymousType: null, sessionBytes: baseline.bytes, anonymousBytes: null, outcome: `Not requested: ${blockedReason}` });
          continue;
        }
        if (hasCredentialQuery(baseline.url)) {
          anonymousCredentialQuerySkipped += 1;
          if (pageTarget) anonymousPageChecks.push({ url: reportUrl(baseline.url), sessionStatus: baseline.status, anonymousStatus: null, sessionType: baseline.type, anonymousType: null, sessionBytes: baseline.bytes, anonymousBytes: null, outcome: "Skipped because the route has a credential-like query parameter." });
          continue;
        }
        const requestController = new AbortController();
        activeController = requestController;
        const requestTimeout = setTimeout(() => requestController.abort(), 15_000);
        anonymousRequestsAttempted += 1;
        $("status").textContent = "Checking without cookies " + anonymousRequestsAttempted + "/" + boundedTargets.length + " · " + reportUrl(baseline.url);
        try {
          const response = await fetch(baseline.url, { method: "GET", credentials: "omit", redirect: "manual", cache: "no-store", signal: requestController.signal });
          if (response.status >= 300 && response.status < 400 || response.type === "opaqueredirect") {
            const location = response.headers?.get?.("location") || "";
            const redirectTarget = location ? cleanUrl(location, baseline.url) : null;
            const sameOriginTarget = redirectTarget && sameOrigin(redirectTarget);
            const loginRedirect = sameOriginTarget && /(?:^|\/)(?:login|log-in|signin|sign-in|authenticate|auth)(?:\/|$)/i.test(new URL(redirectTarget).pathname);
            const redirectDescription = loginRedirect
              ? "Without-cookie request redirected to a same-origin login/auth route; this is evidence the route may be protected, but verify the flow manually."
              : sameOriginTarget
                ? "Without-cookie request redirected within the origin; the target was not followed. Review the route behavior manually."
                : redirectTarget
                  ? "Without-cookie request redirected outside the origin; the destination was not followed."
                  : "Without-cookie redirect target was hidden by the browser; authorization is inconclusive.";
            const redirectHeaders = responseHeaders(response.headers || new Headers());
            const rawRedirectLength = response.headers?.get?.("content-length");
            const redirectBytes = /^\d+$/.test(rawRedirectLength || "") ? Number(rawRedirectLength) : null;
            if (pageTarget) {
              anonymousPageChecks.push({
                url: reportUrl(baseline.url), sessionStatus: baseline.status, anonymousStatus: response.status || null,
                sessionType: baseline.type, anonymousType: response.headers?.get?.("content-type") || null,
                sessionBytes: baseline.bytes, anonymousBytes: redirectBytes, sessionByteSource: baseline.byteSource,
                anonymousByteSource: redirectBytes === null ? null : "Content-Length", sessionHeaders: baseline.headers,
                anonymousHeaders: redirectHeaders, anonymousRedirectTarget: sameOriginTarget ? reportUrl(redirectTarget) : null,
                selectedHeadersMatch: JSON.stringify(headersForComparison(baseline.headers)) === JSON.stringify(headersForComparison(redirectHeaders)),
                outcome: redirectDescription
              });
            } else {
              anonymousChecks.push({
                url: reportUrl(baseline.url), sessionStatus: baseline.status, anonymousStatus: response.status || null,
                sessionType: baseline.type, anonymousType: response.headers?.get?.("content-type") || "unknown",
                sessionBytes: baseline.bytes, anonymousBytes: redirectBytes, sessionByteSource: baseline.byteSource,
                anonymousByteSource: redirectBytes === null ? null : "Content-Length", sessionHeaders: baseline.headers,
                anonymousHeaders: redirectHeaders, anonymousRedirectTarget: sameOriginTarget ? reportUrl(redirectTarget) : null,
                selectedHeadersMatch: JSON.stringify(headersForComparison(baseline.headers)) === JSON.stringify(headersForComparison(redirectHeaders)),
                outcome: redirectDescription
              });
            }
            try { await response.body?.cancel(); } catch (_) { /* no redirect body is retained */ }
            continue;
          }
          if ([429, 503].includes(response.status)) {
            const retryDelay = retryAfterDelayMs(response.headers.get("retry-after"));
            rememberRequestIssue(baseline.url, "anonymous-rate-limit", retryDelay === null ? `No-cookie comparison received HTTP ${response.status}; further checks paused.` : `No-cookie comparison received HTTP ${response.status}; Retry-After was ${Math.ceil(retryDelay / 1000)} seconds.`, response.status);
            try { await response.body?.cancel(); } catch (_) { /* no rate-limit body retained */ }
            if (retryDelay === null || retryDelay > 30_000) { tooLongRetryAfter = true; break; }
            anonymousBackoffUntil = Math.max(anonymousBackoffUntil, Date.now() + retryDelay);
            continue;
          }
          const finalUrl = cleanUrl(response.url || baseline.url, baseline.url);
          if (!finalUrl || !sameOrigin(finalUrl)) {
            try { await response.body?.cancel(); } catch (_) { /* ignore a closed stream */ }
            if (pageTarget) {
              anonymousPageUnavailable += 1;
              anonymousPageChecks.push({ url: reportUrl(baseline.url), sessionStatus: baseline.status, anonymousStatus: null, sessionType: baseline.type, anonymousType: null, sessionBytes: baseline.bytes, anonymousBytes: null, outcome: "No in-scope response; redirect or cross-origin destination was rejected. Authorization is inconclusive." });
            } else anonymousUnavailableSuppressed += 1;
            continue;
          }
          const anonymousType = (response.headers.get("content-type") || "unknown").toLowerCase();
          const anonymousHeaders = responseHeaders(response.headers);
          const rawLength = response.headers.get("content-length");
          const declaredAnonymousBytes = /^\d+$/.test(rawLength || "") ? Number(rawLength) : null;
          const anonymousRead = await readTextLimited(response, 128 * 1024);
          const anonymousMeasure = { bytesRead: anonymousRead.bytesRead, complete: anonymousRead.complete };
          const anonymousBytes = declaredAnonymousBytes ?? anonymousMeasure.bytesRead;
          const anonymousByteSource = declaredAnonymousBytes !== null
            ? "Content-Length"
            : anonymousMeasure.complete ? "measured body" : "measured lower bound (128 KiB cap)";
          const anonymousHtml = isHtmlDocument(anonymousType) || looksLikeHtmlDocument(anonymousRead.text);
          const sameHeaders = JSON.stringify(headersForComparison(baseline.headers)) === JSON.stringify(headersForComparison(anonymousHeaders));
          const comparableSize = sizesComparable({ bytes: baseline.bytes, complete: baseline.sizeComplete }, { bytes: anonymousBytes, complete: declaredAnonymousBytes !== null || anonymousMeasure.complete });
          const sameSize = comparableSize && baseline.bytes === anonymousBytes;
          const sameType = normalizedMediaType(baseline.type) === normalizedMediaType(anonymousType);
          if (pageTarget) {
            if (anonymousHtml) anonymousPageShellResponses += 1;
            let outcome;
            if (anonymousHtml) outcome = "Without-cookie request returned HTML. This may be a shared app/login shell; HTTP status, size, and headers do not determine app-level authorization.";
            else if ([401, 403].includes(response.status)) outcome = "Without-cookie GET returned an authentication/authorization status for this page route.";
            else if (response.status === 200 && sameHeaders && sameSize && sameType) outcome = "Page response metadata matches. This does not show whether the client application redirects to login or protects its API data.";
            else if (response.status === 200) outcome = "Page response metadata differs or could not be fully compared. The route's app-level authorization remains unconfirmed.";
            else outcome = "Page route returned a response; status alone does not confirm application-level access.";
            anonymousPageChecks.push({
              url: reportUrl(baseline.url), sessionStatus: baseline.status, anonymousStatus: response.status,
              sessionType: baseline.type, anonymousType, sessionBytes: baseline.bytes, anonymousBytes,
              sessionByteSource: baseline.byteSource, anonymousByteSource, selectedHeadersMatch: sameHeaders,
              sessionHeaders: baseline.headers, anonymousHeaders,
              sizeComplete: baseline.sizeComplete && (declaredAnonymousBytes !== null || anonymousMeasure.complete),
              outcome
            });
            continue;
          }
          if (anonymousHtml) {
            anonymousHtmlResponsesSuppressed += 1;
            continue;
          }
          let outcome = "Review manually; status alone cannot confirm access";
          let selectedHeadersMatch = sameHeaders;
          if ([401, 403].includes(response.status)) outcome = baseline.status === 200 ? "Anonymous status changed from authenticated HTTP 200 to an authentication/authorization status" : "Server returned an authentication/authorization status";
          else if (response.status === 200 && baseline.status !== 200) outcome = "Anonymous HTTP 200 differs from the authenticated status; verify manually";
          else if (response.status === 200 && baseline.status === 200) {
            outcome = sameHeaders && sameSize && sameType
              ? "No difference in measured response metadata. This does not confirm whether response data is authorized; bodies are not inspected."
              : sameHeaders && sameType && !comparableSize
                ? "Both responses are HTTP 200 with matching selected headers, but byte sizes could not be compared. Authorization is unconfirmed."
                : "Both responses are HTTP 200, but measured response metadata differs. Authorization is unconfirmed.";
          }
          anonymousChecks.push({
            url: reportUrl(baseline.url),
            sessionStatus: baseline.status,
            anonymousStatus: response.status,
            sessionType: baseline.type,
            anonymousType,
            sessionBytes: baseline.bytes,
            anonymousBytes,
            sessionByteSource: baseline.byteSource,
            anonymousByteSource,
            sessionHeaders: baseline.headers,
            anonymousHeaders,
            selectedHeadersMatch,
            outcome,
            sizeComplete: baseline.sizeComplete && (declaredAnonymousBytes !== null || anonymousMeasure.complete)
          });
        } catch (error) {
          if (pageTarget) {
            anonymousPageUnavailable += 1;
            anonymousPageChecks.push({ url: reportUrl(baseline.url), sessionStatus: baseline.status, anonymousStatus: null, sessionType: baseline.type, anonymousType: null, sessionBytes: baseline.bytes, anonymousBytes: null, outcome: `No readable response. ${classifyFetchFailure(error, requestController.signal.aborted)} Authorization is inconclusive.` });
          } else anonymousUnavailableSuppressed += 1;
        } finally {
          clearTimeout(requestTimeout);
          if (activeController === requestController) activeController = null;
        }
        await new Promise(resolve => setTimeout(resolve, 120));
      }
    }

    const uniqueEndpoints = [...new Map(endpoints.map(entry => [reportUrl(entry.url), { ...entry, url: reportUrl(entry.url) }])).values()]
      .sort((a, b) => a.url.localeCompare(b.url));
    const uniquePages = [...new Map(pages.map(entry => [entry.url, entry])).values()].sort((a, b) => a.url.localeCompare(b.url));
    const uniqueAnonymousPageChecks = [...new Map(anonymousPageChecks.map(entry => [entry.url, entry])).values()].sort((a, b) => a.url.localeCompare(b.url));
    const parameterReviews = [];
    const parameterReviewKeys = new Set();
    const addParameterReview = (name, source, kind, method = "") => {
      const key = `${kind}|${source}|${name.toLowerCase()}`;
      if (!name || parameterReviewKeys.has(key)) return;
      parameterReviewKeys.add(key);
      parameterReviews.push({ name, source, kind, method, idea: parameterReviewIdea(name) });
    };
    for (const endpoint of uniqueEndpoints) for (const name of endpoint.parameters || []) addParameterReview(name, endpoint.url, "API query");
    for (const page of uniquePages) for (const name of page.parameters || []) addParameterReview(name, page.url, "Page query");
    for (const field of inputFields) addParameterReview(field.name, field.action || field.page, `Form ${field.method} field`);
    const observedTraffic = trafficRecord?.origin === origin && trafficRecord?.mode === mode && trafficRecord?.modulePath === modulePath
      ? (trafficRecord.items || []).slice(-TRAFFIC_ITEM_LIMIT).map(item => ({
        url: reportUrl(item.url), method: String(item.method || "GET").toUpperCase(), status: Number(item.status) || 0,
        parameterNames: Array.isArray(item.parameterNames) ? item.parameterNames.slice(0, 100) : [],
        parameterNamesSkippedReason: item.parameterNamesSkippedReason || null,
        transport: item.transport || "http", at: item.at,
        pagePath: String(item.pagePath || item.moduleControl?.pagePath || "").slice(0, 2048),
        moduleControl: item.moduleControl ? {
          label: String(item.moduleControl.label || "").slice(0, 120),
          role: String(item.moduleControl.role || "").slice(0, 20),
          pagePath: String(item.moduleControl.pagePath || "").slice(0, 2048)
        } : null
      })) : [];
    for (const item of observedTraffic) for (const name of item.parameterNames) addParameterReview(name, item.url, "Observed request", item.method);
    const routesForIdeas = [
      ...uniquePages.map(item => ({ url: item.url, method: "GET" })),
      ...uniqueEndpoints.map(item => ({ url: item.url, method: "GET" })),
      ...formActions.map(item => ({ url: item.url, method: item.method })),
      ...nonGetCallSites.map(item => ({ url: item.url, method: item.method })),
      ...observedTraffic.map(item => ({ url: item.url, method: item.method }))
    ];
    const fingerprints = detectTechnologies(textCorpus.join("\n"), [...scriptUrls], headersBag, {
      htmlHints: live.htmlHints || []
    });
    const technologyVersions = extractTechnologyVersions(textCorpus.join("\n"), [...scriptUrls]);
    const graphqlTargets = nonGetCallSites.filter(item => /graphql/i.test(item.url));
    for (const operation of graphqlOperations) {
      const target = graphqlTargets.find(item => item.source === operation.source) || graphqlTargets[0];
      if (target && !operation.endpoint) operation.endpoint = target.url;
    }
    lastReport = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt: new Date().toISOString(),
      origin,
      scope: { mode, modulePath, assetOrigins, importAliases, apiPrefixes, strictSameOrigin: true, only200, crawlJs, maxPages, checkAnonymous, anonymousLimit },
      stats: {
        requestsAttempted: requestCount,
        urlsVisited: visited.size,
        htmlPagesParsed: uniquePages.length,
        pageRoutesDiscovered: uniquePages.length,
        htmlRouteResponsesSuppressed,
        anonymousHtmlResponsesSuppressed,
        anonymousPageShellResponses,
        anonymousPageUnavailable,
        uiModuleCandidates: uiModules.length,
        inputFieldsDiscovered: inputFields.length,
        jsFilesDiscovered: scriptUrls.size,
        unresolvedImports: unresolvedImports.length,
        dynamicRouteCandidates: routeCandidates.length,
        transportEndpoints: transportEndpoints.length,
        formActions: formActions.length,
        nonGetCallSites: nonGetCallSites.length,
        graphqlOperations: graphqlOperations.length,
        requestIssues: requestIssues.length,
        externalScriptReferences,
        externalScriptHostsExcluded: externalScriptHosts.size,
        endpointResponses: uniqueEndpoints.length,
        http200Endpoints: uniqueEndpoints.filter(entry => entry.status === 200).length,
        withheldRequests: withheld.size,
        queueRemaining: queue.length,
        requestLimitReached,
        responseTextLimitReached: corpusChars >= 8_000_000,
        scanDeadlineReached,
        rateLimitPaused: tooLongRetryAfter,
        anonymousRequestsAttempted,
        anonymousUnavailableSuppressed,
        anonymousCredentialQuerySkipped,
        anonymousPageChecks: uniqueAnonymousPageChecks.length,
        responseTextLimitBytes: 1_500_000,
        analysisTextLimitChars: 8_000_000,
        stopped: stopRequested
      },
      fingerprints,
      headers: headersBag,
      pages: uniquePages,
      routeCandidates,
      transportEndpoints,
      formActions,
      nonGetCallSites,
      graphqlOperations,
      technologyVersions,
      requestIssues,
      unresolvedImports,
      uiModules,
      inputFields,
      parameterReviews,
      routeTestIdeas: routeTestIdeas(routesForIdeas, fingerprints),
      reconChecklist: buildReconChecklist(fingerprints),
      observedTraffic,
      externalScriptHosts: [...externalScriptHosts].sort(),
      jsFiles: [...new Set([...scriptUrls].map(reportUrl))].sort(),
      scriptIndicators,
      secretFindings,
      auth: { tokenUsed: Boolean(capturedToken), tokenSource: capturedToken?.source || null, tokenKind: capturedToken?.kind || null, headerName: capturedToken?.headerName || null },
      endpoints: uniqueEndpoints,
      anonymousChecks,
      anonymousPageChecks: uniqueAnonymousPageChecks,
      withheldRequests: [...withheld].map(([url, reason]) => ({ url: reportUrl(url), reason })),
      testIdeas: makeTestIdeas(fingerprints),
      limitations: [
        "Static parsing cannot discover every runtime-generated route or authenticated workflow.",
        "HTML route responses are excluded from access comparisons because login redirects and client-side shells can make protected routes look like HTTP 200 pages.",
        "Authenticated-versus-anonymous comparison is GET-only. It measures metadata and at most 128 KiB of streamed bytes when Content-Length is absent; it never retains response bodies.",
        "The passive observer records page-initiated methods and routes and extracts parameter names only from supported request body formats. It never stores parameter values or response bodies, reads cookies or authorization headers, or replays requests.",
        "Only discovered same-origin URLs are requested; redirects and cross-origin resources are excluded.",
        "The passive request observer cannot see service-worker-owned fetches or API calls completed before observer installation; cross-origin traffic is excluded.",
        "JavaScript extraction is heuristic and may miss obfuscated or dynamically assembled paths.",
        "GET requests can still have application-specific side effects; inspect the target and authorization before scanning."
      ]
    };
    pendingReportRecord = { id: lastReport.id, savedAt: Date.now(), inProgress: false, report: lastReport };
    let persisted = true;
    try {
      await browser.storage.local.set({ [PENDING_STORAGE_KEY]: pendingReportRecord });
    } catch (_) {
      persisted = false;
    }
    $("reportDecision").hidden = false;
    render("summary");
    $("results").hidden = false;
    $("status").textContent = `Scan ${stopRequested ? "stopped" : "complete"} · ${visited.size} URLs requested · ${uniqueEndpoints.filter(entry => entry.status === 200).length} HTTP 200 endpoints recorded. ${persisted ? "Save or discard this temporary report." : "Temporary storage failed; export the report before closing."}`;
  } finally {
    updateStartButton();
    $("stop").disabled = true;
  }
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[character]);
}

function trafficStorageKey(tabId) {
  return `${TRAFFIC_STORAGE_PREFIX}${tabId}`;
}

function renderTrafficRecord() {
  const section = $("trafficResults");
  if (!trafficRecord) {
    section.hidden = true;
    $("startObserver").disabled = false;
    $("stopObserver").disabled = true;
    return;
  }
  section.hidden = false;
  const count = Array.isArray(trafficRecord.items) ? trafficRecord.items.length : 0;
  $("startObserver").disabled = Boolean(trafficRecord.active);
  $("stopObserver").disabled = !trafficRecord.active;
  const actionableAnonymous = (trafficRecord.items || []).filter(item => item.anonymous && !item.anonymous.suppressed && isActionableAnonymousComparison({
    sessionStatus: item.status, anonymousStatus: item.anonymous.status,
    sessionType: item.headers?.["content-type"], anonymousType: item.anonymous.type,
    sessionBytes: item.headers?.["content-length"], anonymousBytes: item.anonymous.bytes,
    selectedHeadersMatch: item.anonymous.selectedHeadersMatch, outcome: item.anonymous.outcome
  })).length;
  const hiddenAnonymous = (trafficRecord.items || []).filter(item => item.anonymous && !item.anonymous.suppressed).length - actionableAnonymous;
  $("trafficStatus").textContent = `${trafficRecord.active ? "Observing" : "Stopped"} · ${trafficRecord.mode === "module" ? `module ${trafficRecord.modulePath}` : "whole origin"} · ${count}/${TRAFFIC_ITEM_LIMIT} requests · ${actionableAnonymous} no-cookie differences · ${hiddenAnonymous} inconclusive comparisons hidden · metadata expires after 24 hours`;
  const items = (trafficRecord.items || []).slice(-100).reverse();
  $("trafficList").innerHTML = items.length ? items.map(item => {
    const hasContentLength = item.headers?.["content-length"] !== undefined;
    const size = hasContentLength ? `${escapeHtml(item.headers["content-length"])} bytes (Content-Length)` : "size unavailable from response headers";
    const headers = Object.keys(item.headers || {}).join(", ");
    const parameterSummary = item.parameterNames?.length ? `<p class="muted">Observed parameter names only: ${item.parameterNames.map(escapeHtml).join(", ")}</p>` : "";
    const skippedParameterNote = item.parameterNamesSkippedReason ? `<p class="muted">Parameter names not fully inspected: ${escapeHtml(item.parameterNamesSkippedReason)}</p>` : "";
    const moduleControl = item.moduleControl?.label ? `<p class="muted">Triggered by ${escapeHtml(item.moduleControl.role)}: ${escapeHtml(item.moduleControl.label)} · page ${escapeHtml(item.moduleControl.pagePath)}</p>` : "";
    const statusSummary = item.status ? `<span class="pill ${item.status >= 200 && item.status < 300 ? "good" : "warn"}">HTTP ${item.status}</span>` : `<span class="pill warn">metadata only</span>`;
    const actionableAnonymousResult = item.anonymous && !item.anonymous.suppressed && isActionableAnonymousComparison({
      sessionStatus: item.status, anonymousStatus: item.anonymous.status,
      sessionType: item.headers?.["content-type"], anonymousType: item.anonymous.type,
      sessionBytes: item.headers?.["content-length"], anonymousBytes: item.anonymous.bytes,
      selectedHeadersMatch: item.anonymous.selectedHeadersMatch, outcome: item.anonymous.outcome
    });
    const anonymous = item.anonymous?.suppressed
      ? `<p class="muted">${escapeHtml(item.anonymous.outcome)}</p>`
      : actionableAnonymousResult ? `<p class="muted">Without cookies: ${item.anonymous.status === null ? "no response" : `HTTP ${item.anonymous.status}`} · ${escapeHtml(item.anonymous.type || "unknown")} · ${sizeLabel(item.anonymous.bytes, item.anonymous.byteSource)} · selected headers ${item.anonymous.selectedHeadersMatch === true ? "match" : item.anonymous.selectedHeadersMatch === false ? "differ" : "not compared"}</p><p class="muted">${escapeHtml(item.anonymous.outcome)}</p>` : "";
    const noReplayNote = !item.anonymous && item.method !== "GET" ? "Observed only; non-GET requests are never replayed without cookies." :
      !item.anonymous && trafficRecord.compareObservedGets && item.method === "GET" ? "No no-cookie result (the route may have been filtered or the check may have failed)." : "";
    return `<div class="card"><div class="endpoint">${escapeHtml(item.url)}</div><p><span class="pill">${escapeHtml(item.method)}</span>${statusSummary}<span class="pill">${escapeHtml(item.transport || "http")}</span><span class="muted">${item.durationMs} ms · ${size}</span></p>${moduleControl}${parameterSummary}${skippedParameterNote}<div class="traffic-headers">Safe response header names: ${escapeHtml(headers || "none")}</div>${noReplayNote ? `<p class="muted">${escapeHtml(noReplayNote)}</p>` : ""}${anonymous}</div>`;
  }).join("") : "<p class=\"muted\">No observed requests yet. Close this popup and click through the selected module in the page.</p>";
}

function reportObservedTraffic(report) {
  const scope = report?.scope || {};
  const liveMatches = trafficRecord?.origin === report?.origin && trafficRecord?.mode === scope.mode && trafficRecord?.modulePath === (scope.modulePath || null);
  if (liveMatches && Array.isArray(trafficRecord.items)) return trafficRecord.items;
  return Array.isArray(report?.observedTraffic) ? report.observedTraffic : [];
}

function sizeLabel(bytes, source) {
  if (bytes === null || bytes === undefined) return "size unknown";
  return `${Number(bytes).toLocaleString()} bytes${source ? ` (${escapeHtml(source)})` : ""}`;
}

function compactStoredHeaders(headers) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) return {};
  const allowed = new Set([
    "content-type", "content-length", "cache-control", "vary", "server", "x-powered-by", "x-aspnet-version",
    "x-application-context", "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy", "access-control-allow-origin",
    "access-control-allow-credentials"
  ]);
  const result = {};
  for (const [name, value] of Object.entries(headers)) {
    const key = String(name).toLowerCase();
    if (!allowed.has(key) || typeof value !== "string") continue;
    result[key] = key === "content-security-policy"
      ? (/^present \(\d+ chars\)$/.test(value) ? value : `present (${value.length} chars)`)
      : value.slice(0, 500);
  }
  const csp = result["content-security-policy"];
  if (typeof csp === "string" && !/^present \(\d+ chars\)$/.test(csp)) result["content-security-policy"] = `present (${csp.length} chars)`;
  return result;
}

function compactModuleControl(value, origin, mode, modulePath) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const label = String(value.label || "").replace(/[\r\n\t]/g, " ").trim()
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted]")
    .replace(/\b\+?\d[\d\s().-]{7,}\d\b/g, "[redacted]")
    .replace(/\b[A-Za-z0-9_-]{24,}\b/g, "[redacted]").slice(0, 120);
  const role = String(value.role || "").toLowerCase();
  let pagePath = "";
  try {
    const page = new URL(String(value.pagePath || ""), origin);
    if (page.search || page.hash || !isInScope(page.href, origin, mode, modulePath)) return null;
    pagePath = redactedPathname(page.pathname, origin).slice(0, 2048);
  } catch (_) { return null; }
  if (!label || !["tab", "button", "menuitem", "step", "link"].includes(role)) return null;
  return { label, role, pagePath };
}

function sanitizeStoredReport(rawReport) {
  const isRecord = value => Boolean(value && typeof value === "object" && !Array.isArray(value));
  const objectList = value => Array.isArray(value) ? value.filter(isRecord).slice(0, 5000) : [];
  const stringList = value => Array.isArray(value) ? value.filter(item => typeof item === "string").slice(0, 5000) : [];
  const text = (value, limit = 2048) => typeof value === "string" ? value.slice(0, limit) : "";
  const count = value => Number.isFinite(Number(value)) && Number(value) >= 0 ? Math.min(1_000_000_000, Math.floor(Number(value))) : 0;
  const bytes = value => Number.isFinite(Number(value)) && Number(value) >= 0 ? Math.min(Number.MAX_SAFE_INTEGER, Number(value)) : null;
  const status = value => Number.isInteger(value) && value >= 100 && value <= 599 ? value : null;
  const safeUrl = value => {
    if (typeof value !== "string") return null;
    try {
      if (!/^https?:\/\//i.test(value) && !value.startsWith("/") && !value.startsWith("./") && !value.startsWith("../")) return null;
      const parsedInput = new URL(value, report.origin);
      if (!/^https?:$/.test(parsedInput.protocol) || parsedInput.username || parsedInput.password) return null;
      const cleaned = reportUrl(parsedInput.href);
      return cleaned.slice(0, 4096);
    } catch (_) { return null; }
  };
  if (!isRecord(rawReport)) return null;
  let report;
  try { report = JSON.parse(JSON.stringify(rawReport)); } catch (_) { return null; }
  if (!isRecord(report)) return null;
  const allowedFields = [
    "id", "createdAt", "origin", "scope", "stats", "fingerprints", "headers", "pages", "routeCandidates",
    "transportEndpoints", "formActions", "nonGetCallSites", "graphqlOperations", "technologyVersions", "requestIssues",
    "unresolvedImports", "uiModules", "inputFields", "parameterReviews", "routeTestIdeas", "reconChecklist", "observedTraffic",
    "externalScriptHosts", "jsFiles", "scriptIndicators", "secretFindings", "auth", "endpoints", "anonymousChecks", "anonymousPageChecks",
    "withheldRequests", "testIdeas", "limitations"
  ];
  report = Object.fromEntries(allowedFields.filter(key => Object.prototype.hasOwnProperty.call(report, key)).map(key => [key, report[key]]));
  report.origin = text(report.origin, 2048);
  try {
    const parsedOrigin = new URL(report.origin);
    if (!/^https?:$/.test(parsedOrigin.protocol) || parsedOrigin.origin !== report.origin) return null;
  } catch (_) { return null; }
  report.id = text(report.id, 128);
  report.createdAt = text(report.createdAt, 40);
  report.limitations = stringList(report.limitations).slice(0, 20).map(value => value.slice(0, 500));
  const rawStats = isRecord(report.stats) ? report.stats : {};
  const numericStats = ["urlsVisited", "requestsAttempted", "pageRoutesDiscovered", "htmlPagesParsed", "endpointResponses", "anonymousPageChecks", "anonymousPageUnavailable", "anonymousRequestsAttempted", "anonymousPageShellResponses", "anonymousHtmlResponsesSuppressed", "anonymousUnavailableSuppressed", "anonymousCredentialQuerySkipped", "uiModuleCandidates", "inputFieldsDiscovered", "jsFilesDiscovered", "unresolvedImports", "dynamicRouteCandidates", "transportEndpoints", "formActions", "nonGetCallSites", "graphqlOperations", "requestIssues", "externalScriptReferences", "externalScriptHostsExcluded", "http200Endpoints", "withheldRequests", "queueRemaining", "htmlRouteResponsesSuppressed", "nonEndpointResponsesSuppressed", "responseTextLimitBytes", "analysisTextLimitChars"];
  const booleanStats = ["requestLimitReached", "responseTextLimitReached", "scanDeadlineReached", "rateLimitPaused", "stopped"];
  report.stats = Object.fromEntries(numericStats.map(key => [key, count(rawStats[key])]));
  for (const key of booleanStats) report.stats[key] = Boolean(rawStats[key]);
  const rawScope = isRecord(report.scope) ? report.scope : {};
  report.scope = {
    mode: rawScope.mode === "module" ? "module" : "site",
    modulePath: null,
    checkAnonymous: Boolean(rawScope.checkAnonymous),
    assetOrigins: stringList(rawScope.assetOrigins).filter(value => {
      try { const parsed = new URL(value); return /^https?:$/.test(parsed.protocol) && parsed.origin === value; } catch (_) { return false; }
    }).slice(0, 20),
    importAliases: stringList(rawScope.importAliases).slice(0, 200),
    apiPrefixes: stringList(rawScope.apiPrefixes).slice(0, 200)
  };
  report.scope.only200 = Boolean(rawScope.only200);
  report.scope.crawlJs = rawScope.crawlJs !== false;
  report.scope.maxPages = count(rawScope.maxPages);
  report.scope.anonymousLimit = count(rawScope.anonymousLimit);
  if (typeof rawScope.mode === "string" && !["site", "module"].includes(rawScope.mode)) return null;
  if (report.scope.mode === "module") {
    try { report.scope.modulePath = normalizeModulePath(rawScope.modulePath); }
    catch (_) { return null; }
  }
  const sameOriginUrl = value => {
    const safe = safeUrl(value);
    if (!safe) return null;
    try { return new URL(safe).origin === report.origin ? safe : null; } catch (_) { return null; }
  };
  const sameOriginTransportUrl = (value, transport) => {
    if (transport !== "websocket") return sameOriginUrl(value);
    try {
      const parsed = new URL(String(value || ""), report.origin);
      if (!["ws:", "wss:"].includes(parsed.protocol) || parsed.username || parsed.password) return null;
      const comparable = new URL(parsed.href);
      comparable.protocol = parsed.protocol === "wss:" ? "https:" : "http:";
      return comparable.origin === report.origin ? reportUrl(parsed.href).slice(0, 4096) : null;
    } catch (_) { return null; }
  };
  const inPageScopeUrl = value => {
    const safe = sameOriginUrl(value);
    return safe && isInScope(safe, report.origin, report.scope.mode, report.scope.modulePath) ? safe : null;
  };
  const authorizedAssetUrl = value => {
    const safe = safeUrl(value);
    if (!safe) return null;
    try {
      const urlOrigin = new URL(safe).origin;
      return urlOrigin === report.origin || report.scope.assetOrigins.includes(urlOrigin) ? safe : null;
    } catch (_) { return null; }
  };
  const sameOriginOrText = value => {
    const safe = sameOriginUrl(value);
    if (safe) return safe;
    const raw = text(value, 4096);
    return /^https?:\/\//i.test(raw) ? "" : raw;
  };
  const authorizedAssetOrText = value => {
    const safe = authorizedAssetUrl(value);
    if (safe) return safe;
    const raw = text(value, 4096);
    return /^https?:\/\//i.test(raw) ? "" : raw;
  };
  const endpoints = objectList(report.endpoints).map(entry => ({
    url: sameOriginUrl(entry.url),
    kind: text(entry.kind, 64),
    type: text(entry.type, 160),
    status: status(entry.status),
    depth: count(entry.depth),
    bytes: bytes(entry.bytes),
    sizeComplete: entry.sizeComplete !== false,
    byteSource: text(entry.byteSource, 40),
    parameters: stringList(entry.parameters).slice(0, 100).map(value => value.slice(0, 100)),
    headers: compactStoredHeaders(entry.headers) || {}
  })).filter(entry => entry.url);
  const htmlEndpoints = endpoints.filter(entry => isHtmlDocument(entry.type));
  const isUseful = entry => typeof entry.url === "string" && isUsefulEndpoint(entry.url, entry.type, entry.kind);
  const excludedEndpoints = endpoints.filter(entry => !isUseful(entry));
  report.endpoints = endpoints.filter(isUseful);
  const checks = objectList(report.anonymousChecks).map(item => ({
    ...item,
    url: sameOriginUrl(item.url),
    sessionStatus: status(item.sessionStatus),
    anonymousStatus: status(item.anonymousStatus),
    sessionType: text(item.sessionType, 160),
    anonymousType: text(item.anonymousType, 160),
    sessionBytes: bytes(item.sessionBytes),
    anonymousBytes: bytes(item.anonymousBytes),
    sessionByteSource: text(item.sessionByteSource, 40),
    anonymousByteSource: text(item.anonymousByteSource, 40),
    outcome: text(item.outcome, 500),
    selectedHeadersMatch: typeof item.selectedHeadersMatch === "boolean" ? item.selectedHeadersMatch : null,
    sizeComplete: item.sizeComplete !== false,
    anonymousRedirectTarget: sameOriginUrl(item.anonymousRedirectTarget),
    sessionHeaders: compactStoredHeaders(item.sessionHeaders) || {},
    anonymousHeaders: compactStoredHeaders(item.anonymousHeaders) || {}
  })).filter(item => item.url);
  const isLoginRedirect = item => Number(item.anonymousStatus) >= 300 && Number(item.anonymousStatus) < 400 && /redirected to a same-origin login\/auth route/i.test(String(item.outcome || ""));
  const htmlChecks = checks.filter(item => (isHtmlDocument(item.sessionType) || isHtmlDocument(item.anonymousType)) && !isLoginRedirect(item));
  const credentialChecks = checks.filter(item => /credential-like query/i.test(String(item.outcome || "")));
  const unavailableChecks = checks.filter(item => !isHtmlDocument(item.sessionType) && !isHtmlDocument(item.anonymousType) && !credentialChecks.includes(item) && (item.anonymousStatus === null || item.anonymousStatus === undefined || item.anonymousStatus === 0));
  report.anonymousChecks = checks.filter(item => (!isHtmlDocument(item.sessionType) && !isHtmlDocument(item.anonymousType) || isLoginRedirect(item)) && item.anonymousStatus !== null && item.anonymousStatus !== undefined && item.anonymousStatus !== 0).map(item => ({
    url: item.url,
    sessionStatus: item.sessionStatus,
    anonymousStatus: item.anonymousStatus,
    sessionType: item.sessionType,
    anonymousType: item.anonymousType,
    sessionBytes: item.sessionBytes,
    anonymousBytes: item.anonymousBytes,
    sessionByteSource: item.sessionByteSource,
    anonymousByteSource: item.anonymousByteSource,
    outcome: item.outcome,
    selectedHeadersMatch: item.selectedHeadersMatch,
    sizeComplete: item.sizeComplete,
    anonymousRedirectTarget: item.anonymousRedirectTarget,
    sessionHeaders: compactStoredHeaders(item.sessionHeaders) || {},
    anonymousHeaders: compactStoredHeaders(item.anonymousHeaders) || {}
  }));
  report.stats.htmlRouteResponsesSuppressed = Math.max(Number(report.stats.htmlRouteResponsesSuppressed) || 0, htmlEndpoints.length);
  report.stats.nonEndpointResponsesSuppressed = Math.max(Number(report.stats.nonEndpointResponsesSuppressed) || 0, excludedEndpoints.length - htmlEndpoints.length);
  report.stats.anonymousHtmlResponsesSuppressed = Math.max(Number(report.stats.anonymousHtmlResponsesSuppressed) || 0, htmlChecks.length);
  report.stats.anonymousUnavailableSuppressed = Math.max(Number(report.stats.anonymousUnavailableSuppressed) || 0, unavailableChecks.length);
  report.stats.anonymousCredentialQuerySkipped = Math.max(Number(report.stats.anonymousCredentialQuerySkipped) || 0, credentialChecks.length);
  report.stats.endpointResponses = report.endpoints.length;
  report.stats.http200Endpoints = report.endpoints.filter(entry => entry.status === 200).length;
  report.pages = objectList(report.pages).map(page => ({
    url: inPageScopeUrl(page.url),
    status: status(page.status),
    depth: count(page.depth),
    type: text(page.type, 160),
    bytes: bytes(page.bytes),
    byteSource: text(page.byteSource, 40),
    sizeComplete: page.sizeComplete !== false,
    parameters: stringList(page.parameters).slice(0, 100).map(value => value.slice(0, 100)),
    headers: compactStoredHeaders(page.headers) || {}
  })).filter(page => page.url);
  report.routeCandidates = objectList(report.routeCandidates).map(item => ({
    url: sameOriginUrl(item.url) || "", kind: text(item.kind, 64), reason: text(item.reason, 500), source: authorizedAssetOrText(item.source)
  }));
  report.unresolvedImports = objectList(report.unresolvedImports).map(item => ({
    specifier: text(item.specifier, 1000), source: authorizedAssetOrText(item.source), reason: text(item.reason, 500)
  }));
  report.transportEndpoints = objectList(report.transportEndpoints).map(item => ({
    url: sameOriginTransportUrl(item.url, text(item.transport, 64)) || "", transport: text(item.transport, 64), source: authorizedAssetOrText(item.source)
  }));
  report.formActions = objectList(report.formActions).map(item => ({
    url: sameOriginUrl(item.url) || "", method: text(item.method, 16), page: inPageScopeUrl(item.page) || ""
  }));
  report.nonGetCallSites = objectList(report.nonGetCallSites).map(item => ({
    url: sameOriginUrl(item.url) || "", method: text(item.method, 16), source: authorizedAssetOrText(item.source)
  }));
  report.graphqlOperations = objectList(report.graphqlOperations).map(item => ({
    operationType: text(item.operationType, 32), operationName: text(item.operationName, 200),
    persistedQueryHash: text(item.persistedQueryHash, 200), endpoint: sameOriginUrl(item.endpoint) || "",
    source: authorizedAssetOrText(item.source), fieldNames: stringList(item.fieldNames).slice(0, 200).map(value => value.slice(0, 200))
  }));
  report.technologyVersions = objectList(report.technologyVersions).map(item => ({ technology: text(item.technology, 200), version: text(item.version, 200), source: authorizedAssetOrText(item.source) }));
  report.requestIssues = objectList(report.requestIssues).map(item => ({
    type: text(item.type, 80), status: status(item.status), url: sameOriginUrl(item.url) || "",
    reason: text(item.reason, 500), redirectTarget: sameOriginUrl(item.redirectTarget) || ""
  }));
  report.routeTestIdeas = objectList(report.routeTestIdeas).map(item => ({
    method: text(item.method, 16), tbhmCategory: text(item.tbhmCategory, 120), category: text(item.category, 200),
    url: sameOriginUrl(item.url) || "", details: text(item.details, 1000), framework: text(item.framework, 200)
  }));
  report.observedTraffic = objectList(report.observedTraffic).flatMap(item => {
    const transport = text(item.transport, 24);
    const url = sameOriginTransportUrl(item.url, transport);
    if (!url) return [];
    let pagePath = typeof item.pagePath === "string" ? item.pagePath.slice(0, 2048) : item.moduleControl?.pagePath;
    if (!pagePath) { try { pagePath = new URL(url).pathname; } catch (_) { return []; } }
    try { if (!isInScope(new URL(pagePath, report.origin).href, report.origin, report.scope.mode, report.scope.modulePath)) return []; } catch (_) { return []; }
    const method = text(item.method, 16).toUpperCase();
    const safeItem = {
      url, pagePath: redactedPathname(new URL(pagePath, report.origin).pathname, report.origin), method: /^[A-Z]{1,16}$/.test(method) ? method : "OTHER",
      status: status(item.status), durationMs: count(item.durationMs), at: count(item.at),
      transport: /^[a-z-]{1,24}$/i.test(transport) ? transport : "http",
      headers: compactStoredHeaders(item.headers) || {},
      parameterNames: stringList(item.parameterNames).slice(0, 100).map(value => value.slice(0, 100)),
      parameterNamesSkippedReason: text(item.parameterNamesSkippedReason, 120),
      moduleControl: compactModuleControl(item.moduleControl, report.origin, report.scope.mode, report.scope.modulePath)
    };
    const observedBytes = bytes(item.bytes);
    if (observedBytes !== null) safeItem.bytes = observedBytes;
    if (typeof item.byteSource === "string") safeItem.byteSource = text(item.byteSource, 40);
    if (isRecord(item.anonymous)) {
      const anonymousStatus = status(item.anonymous.status);
      if (anonymousStatus !== null && !isHtmlDocument(item.anonymous.type) && !item.anonymous.suppressed) {
        safeItem.anonymous = {
          status: anonymousStatus, type: text(item.anonymous.type, 120),
          headers: compactStoredHeaders(item.anonymous.headers) || {}, outcome: text(item.anonymous.outcome, 500)
        };
        const anonymousBytes = bytes(item.anonymous.bytes);
        if (anonymousBytes !== null) safeItem.anonymous.bytes = anonymousBytes;
        if (typeof item.anonymous.byteSource === "string") safeItem.anonymous.byteSource = text(item.anonymous.byteSource, 40);
      } else {
        safeItem.anonymous = { suppressed: true, outcome: "Without-cookie response was unavailable or an HTML app/login shell; it was excluded from access results." };
      }
    }
    return [safeItem];
  });
  report.stats.pageRoutesDiscovered = Math.max(Number(report.stats.pageRoutesDiscovered) || 0, report.pages.length);
  report.uiModules = objectList(report.uiModules).map(item => ({
    label: text(item.label, 300), href: inPageScopeUrl(item.href) || "",
    group: ["Navigation", "Tab", "Step"].includes(item.group) ? item.group : "Module",
    path: inPageScopeUrl(item.path) || inPageScopeUrl(item.href) || `${report.origin}${report.scope?.modulePath || "/"}`,
    selected: Boolean(item.selected)
  }));
  report.inputFields = objectList(report.inputFields).map(item => ({
    name: text(item.name, 200), label: text(item.label, 300), type: text(item.type, 80), method: text(item.method, 16),
    action: sameOriginOrText(item.action), page: inPageScopeUrl(item.page) || "", required: Boolean(item.required)
  }));
  report.parameterReviews = objectList(report.parameterReviews).map(item => ({
    name: text(item.name, 200), source: authorizedAssetOrText(item.source), kind: text(item.kind, 100), method: text(item.method, 16), idea: text(item.idea, 1000)
  }));
  report.testIdeas = objectList(report.testIdeas).map(item => ({ relevance: text(item.relevance, 100), category: text(item.category, 200), details: text(item.details, 1000) }));
  const reconIn = isRecord(report.reconChecklist) ? report.reconChecklist : {};
  const originRelativePath = value => {
    const raw = text(value, 512);
    if (!raw || !raw.startsWith("/") || raw.startsWith("//") || /[\u0000-\u001f\\]/.test(raw)) return "";
    return raw;
  };
  report.reconChecklist = {
    reconEndpoints: objectList(reconIn.reconEndpoints).map(item => ({ framework: text(item.framework, 80), path: originRelativePath(item.path), why: text(item.why, 300) })).filter(item => item.path).slice(0, 400),
    configLeaks: objectList(reconIn.configLeaks).map(item => ({ framework: text(item.framework, 80), path: originRelativePath(item.path), why: text(item.why, 300) })).filter(item => item.path).slice(0, 400),
    dangerousEndpoints: objectList(reconIn.dangerousEndpoints).map(item => ({ path: originRelativePath(item.path), why: text(item.why, 300) })).filter(item => item.path).slice(0, 200),
    engineHints: objectList(reconIn.engineHints).map(item => ({ framework: text(item.framework, 80), name: text(item.name, 120), test: text(item.test, 120), confirm: text(item.confirm, 300), note: text(item.note, 300) })).slice(0, 50),
    deserHints: objectList(reconIn.deserHints).map(item => ({ framework: text(item.framework, 80), note: text(item.note, 400) })).slice(0, 50)
  };
  report.fingerprints = objectList(report.fingerprints).map(item => ({
    name: text(item.name, 200), confidence: text(item.confidence, 80), score: count(item.score)
  }));
  report.scriptIndicators = objectList(report.scriptIndicators).map(item => ({
    keyword: text(item.keyword, 100), source: authorizedAssetOrText(item.source), line: count(item.line)
  }));
  report.secretFindings = objectList(report.secretFindings).map(item => ({
    type: text(item.type, 100), value: text(item.value, 120), source: authorizedAssetOrText(item.source), line: count(item.line)
  })).slice(0, 500);
  const rawAuth = isRecord(report.auth) ? report.auth : {};
  report.auth = {
    tokenUsed: Boolean(rawAuth.tokenUsed),
    tokenSource: text(rawAuth.tokenSource, 200),
    tokenKind: ["jwt", "opaque"].includes(rawAuth.tokenKind) ? rawAuth.tokenKind : "",
    headerName: text(rawAuth.headerName, 60)
  };
  report.jsFiles = stringList(report.jsFiles).map(authorizedAssetUrl).filter(Boolean);
  report.withheldRequests = objectList(report.withheldRequests).map(item => ({ url: sameOriginOrText(item.url), reason: text(item.reason, 500) }));
  report.externalScriptHosts = stringList(report.externalScriptHosts).filter(value => {
    try { const parsed = new URL(value); return /^https?:$/.test(parsed.protocol) && parsed.origin === value; } catch (_) { return false; }
  }).slice(0, 100);
  report.anonymousPageChecks = objectList(report.anonymousPageChecks).map(item => ({
    url: inPageScopeUrl(item.url), sessionStatus: status(item.sessionStatus), anonymousStatus: status(item.anonymousStatus),
    sessionType: text(item.sessionType, 160), anonymousType: text(item.anonymousType, 160),
    sessionBytes: bytes(item.sessionBytes), anonymousBytes: bytes(item.anonymousBytes),
    sessionByteSource: text(item.sessionByteSource, 40), anonymousByteSource: text(item.anonymousByteSource, 40),
    outcome: text(item.outcome, 500), selectedHeadersMatch: typeof item.selectedHeadersMatch === "boolean" ? item.selectedHeadersMatch : null,
    anonymousRedirectTarget: sameOriginUrl(item.anonymousRedirectTarget),
    sessionHeaders: compactStoredHeaders(item.sessionHeaders) || {}, anonymousHeaders: compactStoredHeaders(item.anonymousHeaders) || {}
  })).filter(item => item.url);
  report.headers = compactStoredHeaders(report.headers) || {};
  return report;
}

function sanitizeStoredTraffic(rawRecord) {
  const isRecord = value => Boolean(value && typeof value === "object" && !Array.isArray(value));
  if (!isRecord(rawRecord)) return null;
  let record;
  try { record = JSON.parse(JSON.stringify(rawRecord)); } catch (_) { return null; }
  if (!isRecord(record)) return null;
  record.origin = typeof record.origin === "string" ? record.origin.slice(0, 2048) : "";
  try {
    const origin = new URL(record.origin);
    if (!/^https?:$/.test(origin.protocol) || origin.origin !== record.origin) return null;
  } catch (_) { return null; }
  record.mode = record.mode === "module" ? "module" : "site";
  if (record.mode === "module") {
    try { record.modulePath = normalizeModulePath(record.modulePath); } catch (_) { return null; }
  } else {
    record.modulePath = null;
  }
  record.compareObservedGets = Boolean(record.compareObservedGets);
  record.active = Boolean(record.active);
  record.updatedAt = Number.isFinite(Number(record.updatedAt)) ? Number(record.updatedAt) : 0;
  record.items = (Array.isArray(record.items) ? record.items : []).filter(isRecord).slice(-TRAFFIC_ITEM_LIMIT).flatMap(item => {
    if (typeof item.url !== "string") return [];
    let parsed;
    try { parsed = new URL(reportUrl(item.url)); } catch (_) { return []; }
    const transport = typeof item.transport === "string" && /^[a-z-]{1,24}$/i.test(item.transport) ? item.transport : "http";
    const comparable = new URL(parsed.href);
    if (transport === "websocket") {
      if (comparable.protocol === "ws:") comparable.protocol = "http:";
      else if (comparable.protocol === "wss:") comparable.protocol = "https:";
    }
    if (parsed.username || parsed.password || comparable.origin !== record.origin) return [];
    let sourcePath = typeof item.pagePath === "string" ? item.pagePath.slice(0, 2048) : item.moduleControl?.pagePath;
    if (!sourcePath) sourcePath = parsed.pathname;
    let page;
    try { page = new URL(sourcePath, record.origin); } catch (_) { return []; }
    if (page.origin !== record.origin || page.search || page.hash || !isInScope(page.href, record.origin, record.mode, record.modulePath)) return [];
    const safeUrl = reportUrl(parsed.href);
    const method = typeof item.method === "string" ? item.method.toUpperCase().slice(0, 16) : "GET";
    const safeItem = {
      url: safeUrl,
      pagePath: redactedPathname(page.pathname, record.origin),
      method: /^[A-Z]{1,16}$/.test(method) ? method : "OTHER",
      status: Number.isInteger(item.status) && item.status >= 100 && item.status <= 599 ? item.status : null,
      durationMs: Number.isFinite(Number(item.durationMs)) ? Math.max(0, Math.min(3_600_000, Number(item.durationMs))) : 0,
      at: Number.isFinite(Number(item.at)) && Number(item.at) >= 0 ? Math.min(Number(item.at), Number.MAX_SAFE_INTEGER) : 0,
      transport,
      headers: compactStoredHeaders(item.headers) || {},
      parameterNames: Array.isArray(item.parameterNames) ? item.parameterNames.filter(value => typeof value === "string").slice(0, 100).map(value => value.slice(0, 100)) : [],
      parameterNamesSkippedReason: typeof item.parameterNamesSkippedReason === "string" ? item.parameterNamesSkippedReason.slice(0, 120) : null,
      moduleControl: compactModuleControl(item.moduleControl, record.origin, record.mode, record.modulePath)
    };
    if (Number.isFinite(Number(item.bytes)) && Number(item.bytes) >= 0) safeItem.bytes = Math.min(Number(item.bytes), Number.MAX_SAFE_INTEGER);
    if (typeof item.byteSource === "string") safeItem.byteSource = item.byteSource.slice(0, 40);
    if (isRecord(item.anonymous)) {
      const anonymousStatus = Number.isInteger(item.anonymous.status) && item.anonymous.status >= 100 && item.anonymous.status <= 599 ? item.anonymous.status : null;
      if (item.anonymous.suppressed || anonymousStatus === null || isHtmlDocument(item.anonymous.type)) {
        safeItem.anonymous = { suppressed: true, outcome: "Without-cookie response was redirected, unavailable, or an HTML app/login shell; it was excluded from access results." };
      } else {
        safeItem.anonymous = {
          status: anonymousStatus,
          type: typeof item.anonymous.type === "string" ? item.anonymous.type.slice(0, 120) : null,
          headers: compactStoredHeaders(item.anonymous.headers) || {},
          outcome: typeof item.anonymous.outcome === "string" ? item.anonymous.outcome.slice(0, 500) : "",
          selectedHeadersMatch: typeof item.anonymous.selectedHeadersMatch === "boolean" ? item.anonymous.selectedHeadersMatch : null
        };
        if (Number.isFinite(Number(item.anonymous.bytes)) && Number(item.anonymous.bytes) >= 0) safeItem.anonymous.bytes = Math.min(Number(item.anonymous.bytes), Number.MAX_SAFE_INTEGER);
        if (typeof item.anonymous.byteSource === "string") safeItem.anonymous.byteSource = item.anonymous.byteSource.slice(0, 40);
      }
    }
    return [safeItem];
  });
  return record;
}

async function restoreTrafficForActiveTab() {
  const tab = activeTabSnapshot;
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) return;
  const key = trafficStorageKey(tab.id);
  const stored = await browser.storage.local.get(key);
  let record = sanitizeStoredTraffic(stored[key] || null);
  if (!record) return;
  if (JSON.stringify(record) !== JSON.stringify(stored[key])) await browser.storage.local.set({ [key]: record });
  if (Date.now() - Number(record.updatedAt || 0) > TRAFFIC_TTL_MS) {
    await browser.storage.local.remove(key);
    return;
  }
  if (record.origin !== new URL(tab.url).origin) return;
  if (record.mode === "module" && record.modulePath) {
    $("scopeMode").value = "module";
    $("modulePath").value = record.modulePath;
    $("modulePath").disabled = false;
  } else if (record.mode === "site") {
    $("scopeMode").value = "site";
    $("modulePath").disabled = true;
  }
  $("compareObservedGets").checked = Boolean(record.compareObservedGets);
  if (record.active) {
    let active = false;
    try {
      const state = await browser.scripting.executeScript({
        target: { tabId: tab.id },
        world: "MAIN",
        func: isMainWorldObserverActive
      });
      active = Boolean(state?.[0]?.result);
    } catch (_) {
      active = false;
    }
    if (!active && browser.scripting?.getRegisteredContentScripts) {
      try {
        const [early, registrations] = await Promise.all([
          browser.storage.local.get(EARLY_OBSERVER_CONFIG_KEY),
          browser.scripting.getRegisteredContentScripts({ ids: EARLY_OBSERVER_SCRIPT_IDS })
        ]);
        const config = early[EARLY_OBSERVER_CONFIG_KEY];
        const matchesScope = config?.active && config.tabId === tab.id && config.origin === new URL(tab.url).origin &&
          isInScope(tab.url, config.origin, config.mode, config.modulePath);
        active = Boolean(matchesScope && registrations?.length === EARLY_OBSERVER_SCRIPT_IDS.length);
      } catch (_) { active = false; }
    }
    if (!active) {
      record = { ...record, active: false, updatedAt: Date.now() };
      await browser.storage.local.set({ [key]: record });
      await unregisterEarlyObserverScripts(tab.id);
    }
  }
  activeTrafficStorageKey = key;
  trafficRecord = record;
  renderTrafficRecord();
}

function buildObserverPermissionOrigins() {
  const snapshot = activeTabSnapshot;
  if (!snapshot?.url || !/^https?:/i.test(snapshot.url)) throw new Error("Open the module in an HTTP/HTTPS tab first.");
  const current = new URL(snapshot.url);
  return [`${current.protocol}//${current.hostname}/*`];
}

async function startTrafficObserver(permissionRequest) {
  const [freshTab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!freshTab) throw new Error("Could not confirm the active tab. Reopen StackScope on the intended target before starting the observer.");
  assertActiveTargetUnchanged(freshTab);
  const tab = freshTab;
  activeTabSnapshot = tab || null;
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) throw new Error("Open the module in an HTTP/HTTPS tab first.");
  const current = new URL(tab.url);
  const mode = $("scopeMode").value;
  const modulePath = mode === "module" ? normalizeModulePath($("modulePath").value) : null;
  if (!isInScope(current.href, current.origin, mode, modulePath)) throw new Error("The current page is outside the selected module or origin scope.");
  const permissionOrigin = `${current.protocol}//${current.hostname}/*`;
  const granted = permissionRequest ? await permissionRequest : await browser.permissions.request({ origins: [permissionOrigin] });
  if (!granted) throw new Error("Site access was not granted, so the click observer was not started.");

  const key = trafficStorageKey(tab.id);
  const channel = [...crypto.getRandomValues(new Uint8Array(24))].map(value => value.toString(16).padStart(2, "0")).join("");
  const compareObservedGets = $("compareObservedGets").checked;
  const config = { tabId: tab.id, storageKey: key, channel, origin: current.origin, mode, modulePath, compareObservedGets, active: true };
  const earlyCaptureEnabled = await registerEarlyObserverScripts(tab, config);
  await browser.scripting.executeScript({
    target: { tabId: tab.id }, world: "ISOLATED", func: isolatedTrafficBridge, args: [config]
  });
  const result = await browser.scripting.executeScript({
    target: { tabId: tab.id }, world: "MAIN", func: mainWorldRequestObserver, args: [config]
  });
  if (!result?.[0]?.result?.installed) {
    try { await browser.scripting.executeScript({ target: { tabId: tab.id }, world: "ISOLATED", func: isolatedTrafficStop, args: [key] }); } catch (_) { /* no observer record to retain */ }
    await unregisterEarlyObserverScripts(tab.id);
    throw new Error("Firefox could not install the page request observer.");
  }
  activeTrafficStorageKey = key;
  const stored = await browser.storage.local.get(key);
  const prior = sanitizeStoredTraffic(stored[key]);
  const sameScope = prior?.origin === config.origin && prior?.mode === config.mode && prior?.modulePath === config.modulePath;
  trafficRecord = {
    ...config,
    active: true,
    startedAt: sameScope && prior.startedAt ? prior.startedAt : Date.now(),
    updatedAt: Date.now(),
    items: sameScope && Array.isArray(prior.items) ? prior.items.slice(-TRAFFIC_ITEM_LIMIT) : []
  };
  renderTrafficRecord();
  $("status").textContent = "Click observer is active for this page" + (earlyCaptureEnabled ? " and will also capture requests from the start of the next page load" : "; early page-load capture is unavailable in this Firefox session") + ". Close the popup and use the selected module; reopen it to review observed API traffic.";
}

async function stopTrafficObserver() {
  const tab = activeTabSnapshot;
  const key = activeTrafficStorageKey || (tab?.id ? trafficStorageKey(tab.id) : null);
  if (!tab?.id || !key) return;
  let earlyConfig = null;
  try { earlyConfig = (await browser.storage.local.get(EARLY_OBSERVER_CONFIG_KEY))[EARLY_OBSERVER_CONFIG_KEY] || null; } catch (_) { /* best effort */ }
  try {
    await browser.scripting.executeScript({
      target: { tabId: tab.id }, world: "MAIN", func: stopEarlyObserverInPage,
      args: [earlyConfig?.tabId === tab.id ? earlyConfig.channel : null]
    });
  } catch (_) { /* page may have navigated or early capture may not be installed */ }
  try {
    await browser.scripting.executeScript({
      target: { tabId: tab.id }, world: "MAIN", func: mainWorldRequestObserver,
      args: [{ active: false }]
    });
  } catch (_) { /* page may have navigated since the observer started */ }
  await unregisterEarlyObserverScripts(tab.id);
  try {
    await browser.scripting.executeScript({
      target: { tabId: tab.id }, world: "ISOLATED", func: isolatedTrafficStop, args: [key]
    });
  } catch (_) { /* the observer record can still be stopped locally */ }
  const stored = await browser.storage.local.get(key);
  trafficRecord = stored[key] ? { ...stored[key], active: false, updatedAt: Date.now() } : null;
  if (trafficRecord) await browser.storage.local.set({ [key]: trafficRecord });
  renderTrafficRecord();
  $("status").textContent = "Click observer stopped. Recorded metadata remains on this device until cleared or it expires.";
}

function render(tabName) {
  if (!lastReport) return;
  document.querySelectorAll(".tab").forEach(button => button.classList.toggle("active", button.dataset.tab === tabName));
  const panel = $("panel");
  const report = lastReport;
  const stats = report.stats || {};
  const observedItems = reportObservedTraffic(report);
  if (tabName === "summary") {
    panel.innerHTML = `<div class="card"><h3>Scan summary</h3><p><span class="pill">${escapeHtml(report.scope.mode === "module" ? "Module scoped" : "Whole origin")}</span><span class="pill">GET requests only</span></p><div>${escapeHtml(report.origin)}${report.scope.modulePath ? `<br>Module path: <b>${escapeHtml(report.scope.modulePath)}</b>` : ""}</div><ul><li>${stats.urlsVisited || 0} URLs requested</li><li>${stats.pageRoutesDiscovered ?? stats.htmlPagesParsed ?? 0} page routes discovered</li><li>${report.endpoints.length} API endpoint responses recorded</li><li>${stats.anonymousPageChecks || 0} page routes checked without cookies</li><li>${stats.uiModuleCandidates || 0} navigation, tab, or step controls detected</li><li>${stats.inputFieldsDiscovered || 0} form fields inventoried (values not collected)</li><li>${stats.jsFilesDiscovered || 0} JavaScript files fetched</li><li>${stats.formActions || 0} form actions listed without submission</li><li>${stats.nonGetCallSites || 0} non-GET callsites listed without replay</li><li>${stats.graphqlOperations || 0} GraphQL operations or persisted-query hashes found</li><li>${stats.requestIssues || 0} redirect, rate-limit, or network issues recorded</li><li>${stats.http200Endpoints || 0} HTTP 200 API responses</li><li>${stats.queueRemaining || 0} discovered URLs still queued</li></ul><p class="muted">Authenticated crawl: ${report.auth?.tokenUsed ? `cookies + bearer token from ${escapeHtml(report.auth.tokenSource || "page storage")} (${escapeHtml(report.auth.tokenKind || "token")})` : "browser cookies only (no page-storage token attached)"}. No-cookie comparison, when enabled, sends neither cookies nor token.</p><p class="muted">Page routes are listed separately from API responses. An HTML 200 means the page shell responded; it does not prove the app-level route is public. Anonymous comparisons use GET only. ${stats.requestLimitReached ? "URL request cap reached. " : ""}${stats.responseTextLimitReached ? "Response text analysis cap reached. " : ""}${stats.scanDeadlineReached ? "Total scan deadline reached. " : ""}${stats.rateLimitPaused ? "Scan paused because the server rate limit requested a long or unspecified delay. " : ""}</p></div><div class="card"><h3>Scope</h3>Page routes stay within the selected module path. Scripts can be fetched from the active origin and exact additional asset origins you entered. API checks stay on the active origin. ${report.scope.assetOrigins?.length ? `Authorized asset origins: ${report.scope.assetOrigins.map(escapeHtml).join(", ")}.` : "No additional asset origins were authorized."} Cross-origin API hosts are not requested.${report.scope.apiPrefixes?.length ? ` App-specific API prefixes: ${report.scope.apiPrefixes.map(escapeHtml).join(", ")}.` : ""}</div>`;
  } else if (tabName === "pages") {
    const checks = new Map((report.anonymousPageChecks || []).map(item => [item.url, item]));
    const rows = (report.pages || []).map(page => {
      const anon = checks.get(page.url);
      const params = (page.parameters || []).map(name => `<span class="pill">${escapeHtml(name)}</span>`).join("");
      const anonSummary = isActionableAnonymousComparison(anon) ? `<p class="muted">Without cookies: ${anon.anonymousStatus === null ? "no readable response" : `HTTP ${anon.anonymousStatus}`} · ${escapeHtml(anon.outcome)}</p>` : "";
      return `<div class="card"><div class="endpoint">${escapeHtml(page.url)}</div><span class="pill ${page.status === 200 ? "good" : "warn"}">Browser HTTP ${page.status}</span><span class="muted">${escapeHtml(page.type || "HTML page")} · depth ${page.depth ?? "?"} · ${sizeLabel(page.bytes, page.byteSource)}</span>${params ? `<div>Query names: ${params}</div>` : ""}${anonSummary}</div>`;
    }).join("");
    panel.innerHTML = `<div class="card"><h3>Page routes / URLs</h3><p class="muted">These are in-scope page URLs the crawler requested. HTML shell responses are shown as routes, not findings. The no-cookie note describes the response only; client-side redirects and API authorization need separate verification.</p><p>${(report.pages || []).length} page routes · ${(report.anonymousPageChecks || []).length} no-cookie route checks</p></div>${rows || "<p>No HTML page routes were discovered in the selected scope.</p>"}`;
  } else if (tabName === "endpoints") {
    const responses = report.endpoints.length ? report.endpoints.map(entry => `<div class="card"><div class="endpoint">${escapeHtml(entry.url)}</div><span class="pill ${entry.status === 200 ? "good" : "warn"}">HTTP ${entry.status}</span><span class="pill">${escapeHtml(entry.kind)}</span><span class="muted">${escapeHtml(entry.type)} · depth ${entry.depth} · ${sizeLabel(entry.bytes, entry.byteSource)}${entry.sizeComplete ? "" : " (partial)"}</span>${entry.parameters?.length ? `<p class="muted">Query names: ${entry.parameters.map(name => escapeHtml(name)).join(", ")}</p>` : ""}</div>`).join("") : "<p>No non-HTML API endpoint responses recorded. Page routes are listed in URLs.</p>";
    const withheld = report.withheldRequests.length ? `<div class="card"><h3>Not requested</h3><p class="muted">Sensitive or potentially state-changing routes are listed for manual review and were not fetched.</p>${report.withheldRequests.map(entry => `<div class="idea"><div class="endpoint">${escapeHtml(entry.url)}</div><p class="muted">${escapeHtml(entry.reason)}</p></div>`).join("")}</div>` : "";
    const templates = report.routeCandidates?.length ? `<div class="card"><h3>Dynamic route templates not requested</h3><p class="muted">These routes contain unresolved runtime values. They are shown for manual review and were not fetched with guessed identifiers.</p>${report.routeCandidates.map(entry => `<div class="idea"><span class="pill">${escapeHtml(entry.kind)}</span><div class="endpoint">${escapeHtml(entry.url)}</div><p>${escapeHtml(entry.reason)}</p><small>Source: ${escapeHtml(entry.source)}</small></div>`).join("")}</div>` : "";
    const forms = report.formActions?.length ? `<div class="card"><h3>Form actions (not submitted)</h3><p class="muted">Actions and methods came from page markup. Non-GET forms are listed for review and were never requested.</p>${report.formActions.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.method)}</span><div class="endpoint">${escapeHtml(item.url)}</div><small>Page: ${escapeHtml(item.page)}</small></div>`).join("")}</div>` : "";
    const callSites = report.nonGetCallSites?.length ? `<div class="card"><h3>Non-GET API callsites (not sent)</h3><p class="muted">Methods and URLs were statically identified in JavaScript. No request body was created or replayed.</p>${report.nonGetCallSites.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.method)}</span><div class="endpoint">${escapeHtml(item.url)}</div><small>Source: ${escapeHtml(item.source)}</small></div>`).join("")}</div>` : "";
    const graphql = report.graphqlOperations?.length ? `<div class="card"><h3>GraphQL operation metadata</h3><p class="muted">Operation and field names are source-code metadata. No GraphQL requests or introspection queries were sent.</p>${report.graphqlOperations.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.operationType)}</span><b>${escapeHtml(item.operationName || item.persistedQueryHash || "unnamed")}</b>${item.endpoint ? `<div class="endpoint">${escapeHtml(item.endpoint)}</div>` : ""}${item.fieldNames?.length ? `<p>Fields: ${item.fieldNames.map(escapeHtml).join(", ")}</p>` : ""}<small>Source: ${escapeHtml(item.source)}</small></div>`).join("")}</div>` : "";
    const issues = report.requestIssues?.length ? `<div class="card"><h3>Request issues</h3>${report.requestIssues.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.type)}</span>${item.status ? `<span class="pill">HTTP ${item.status}</span>` : ""}<div class="endpoint">${escapeHtml(item.url)}</div><p>${escapeHtml(item.reason)}</p>${item.redirectTarget ? `<small>Redirect target: ${escapeHtml(item.redirectTarget)}</small>` : ""}</div>`).join("")}</div>` : "";
    panel.innerHTML = responses + withheld + templates + forms + callSites + graphql + issues;
  } else if (tabName === "modules") {
    const modules = [...(report.uiModules || [])];
    const seenModules = new Set(modules.map(item => `${String(item.label || "").toLowerCase()}|${String(item.path || item.href || "")}`));
    for (const item of observedItems) {
      const control = item.moduleControl;
      if (!control?.label) continue;
      const path = `${report.origin}${control.pagePath || report.scope?.modulePath || "/"}`;
      const key = `${control.label.toLowerCase()}|${path}`;
      if (seenModules.has(key)) continue;
      seenModules.add(key);
      modules.push({ label: control.label, group: control.role === "step" ? "Step" : control.role === "tab" ? "Tab" : "Navigation", path, observed: true, selected: false });
    }
    panel.innerHTML = `<div class="card"><h3>Module names and routes</h3><p class="muted">Each row shows the visible control name and its full page path. Clicked tabs and steps can share one URL; the observer links their API requests to the clicked label. The crawler does not click arbitrary controls or submit forms.</p>${modules.length ? modules.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.group || "Module")}</span><b>${escapeHtml(item.label)}</b>${item.selected ? `<span class="pill good">selected</span>` : ""}${item.observed ? `<span class="pill">observed</span>` : ""}<div class="endpoint">${escapeHtml(item.path || item.href || "")}</div></div>`).join("") : "No navigation, tab, or step controls were detected in the page snapshot or observer history."}</div>`;
  } else if (tabName === "inputs") {
    const fields = report.inputFields || [];
    const observed = observedItems.flatMap(item => (item.parameterNames || []).map(name => ({ name, source: item.url, method: item.method, control: item.moduleControl?.label || "" })));
    const reviews = [...(report.parameterReviews || [])];
    const reviewKeys = new Set(reviews.map(item => `${item.kind}|${item.source}|${String(item.name).toLowerCase()}`));
    for (const item of observed) {
      const key = `Observed request|${item.source}|${String(item.name).toLowerCase()}`;
      if (!reviewKeys.has(key)) { reviews.push({ name: item.name, source: item.source, kind: "Observed request", method: item.method, idea: parameterReviewIdea(item.name) }); reviewKeys.add(key); }
    }
    panel.innerHTML = `<div class="card"><h3>Input fields</h3><p class="muted">Only field names, labels, types, required flags, form methods, and same-origin actions are collected. Input values are never read or submitted.</p>${fields.length ? fields.map(field => `<div class="idea"><b>${escapeHtml(field.label || field.name)}</b><span class="pill">${escapeHtml(field.type)}</span>${field.required ? `<span class="pill warn">required</span>` : ""}<div>Parameter: <code>${escapeHtml(field.name)}</code> · Form ${escapeHtml(field.method)}</div>${field.action ? `<div class="endpoint">Action: ${escapeHtml(field.action)}</div>` : ""}<div class="endpoint">Page: ${escapeHtml(field.page)}</div></div>`).join("") : "No named input, select, or textarea fields were found in crawled page markup."}</div>${observed.length ? `<div class="card"><h3>Observed request parameters</h3><p class="muted">Names captured from user-triggered requests; values were not retained.</p>${observed.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.method)}</span><b>${escapeHtml(item.name)}</b>${item.control ? `<p class="muted">Triggered by ${escapeHtml(item.control)}</p>` : ""}<div class="endpoint">${escapeHtml(item.source)}</div></div>`).join("")}</div>` : ""}<div class="card"><h3>Parameter review ideas</h3><p class="muted">These are TBHM-aligned manual checks based on parameter names. They are suggestions only; the extension sends no test values.</p>${reviews.length ? reviews.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.kind)}</span><b>${escapeHtml(item.name)}</b>${item.method ? `<span class="pill">${escapeHtml(item.method)}</span>` : ""}<div class="endpoint">${escapeHtml(item.source)}</div><p>${escapeHtml(item.idea)}</p></div>`).join("") : "No named query, form, or observed request parameters were found."}${observedItems.some(item => item.parameterNamesSkippedReason) ? `<p class="muted">Some request body parameter names were skipped: ${observedItems.filter(item => item.parameterNamesSkippedReason).map(item => escapeHtml(item.parameterNamesSkippedReason)).join("; ")}</p>` : ""}</div>`;
  } else if (tabName === "tech") {
    panel.innerHTML = `<div class="card"><h3>Technology fingerprints</h3>${report.fingerprints.length ? report.fingerprints.map(technology => `<p><b>${escapeHtml(technology.name)}</b> <span class="pill">${escapeHtml(technology.confidence)}</span><span class="muted"> score ${technology.score}</span></p>`).join("") : "No framework fingerprint detected from the observed page and assets."}<p class="muted">Fingerprints are heuristic; confirm exact products and versions using authorized evidence. A build ID is not a framework version.</p>${report.technologyVersions?.length ? `<h4>Version/build metadata</h4>${report.technologyVersions.map(item => `<div class="idea"><b>${escapeHtml(item.technology)}</b>: ${escapeHtml(item.version)}<small>Source: ${escapeHtml(item.source)}</small></div>`).join("")}` : "No exact version or build identifier was extracted from public asset names or page metadata."}</div><div class="card"><h3>Observed response headers</h3>${Object.keys(report.headers).length ? Object.entries(report.headers).map(([name, value]) => `<div><b>${escapeHtml(name)}:</b> ${escapeHtml(value)}</div>`).join("") : "No selected fingerprint/security headers were readable."}</div><div class="card"><h3>Discovered JavaScript files</h3><p>${report.jsFiles.length} fetched JS/source-map files.</p>${report.jsFiles.map(url => `<div class="endpoint">${escapeHtml(url)}</div>`).join("") || "None"}${report.externalScriptHosts?.length ? `<p class="muted">External script hosts were not fetched because they were not explicitly authorized: ${report.externalScriptHosts.map(escapeHtml).join(", ")}. Add exact authorized origins above and rescan if your program scope includes them.</p>` : ""}</div>`;
  } else if (tabName === "js") {
    const indicators = report.scriptIndicators || [];
    const unresolved = report.unresolvedImports || [];
    const secrets = report.secretFindings || [];
    const secretsCard = `<div class="card"><h3>Possible secrets in JavaScript</h3><p class="muted">High-signal credential patterns found in analyzed JavaScript. Values are masked (first/last characters only); open the source at the given line to confirm. A match is a lead, not proof — verify before reporting.</p>${secrets.length ? secrets.map(item => `<div class="idea"><span class="pill warn">${escapeHtml(item.type)}</span><code>${escapeHtml(item.value)}</code><p class="endpoint">${escapeHtml(item.source)} · line ${item.line}</p></div>`).join("") : "No high-signal secret patterns were found in analyzed script text."}</div>`;
    panel.innerHTML = `<div class="card"><h3>Recursive JavaScript crawl</h3><p>${report.stats.jsFilesDiscovered || 0} JavaScript/source-map files fetched within the request cap.</p><p class="muted">The crawler follows inline scripts, authorized scripts, import maps, configured aliases, dynamic script references, and recursive imports. API/page requests remain on the active origin.</p>${report.jsFiles.map(url => `<div class="endpoint">${escapeHtml(url)}</div>`).join("") || "No authorized JavaScript files were fetched."}${report.externalScriptHosts?.length ? `<p class="muted">Unapproved external script hosts excluded: ${report.externalScriptHosts.map(escapeHtml).join(", ")}</p>` : ""}${unresolved.length ? `<h4>Unresolved import specifiers</h4>${unresolved.map(item => `<div class="idea"><code>${escapeHtml(item.specifier)}</code><div class="endpoint">${escapeHtml(item.source)}</div><small>${escapeHtml(item.reason)}</small></div>`).join("")}` : ""}</div>${secretsCard}<div class="card"><h3>Sensitive keyword indicators</h3><p class="muted">Only keyword names, source locations, and line numbers are kept. Matched values are never shown or saved; a keyword is not proof of a secret.</p>${indicators.length ? indicators.map(item => `<div class="idea"><b>${escapeHtml(item.keyword)}</b><p class="endpoint">${escapeHtml(item.source)} · line ${item.line}</p></div>`).join("") : "No configured keyword indicators found in analyzed script text."}</div>`;
  } else if (tabName === "anonymous") {
    const checks = report.anonymousChecks || [];
    const pageChecks = report.anonymousPageChecks || [];
    const usefulApiChecks = checks.filter(isActionableAnonymousComparison);
    const usefulPageChecks = pageChecks.filter(isActionableAnonymousComparison);
    const emptyMessage = !report.scope.checkAnonymous
      ? "<div class=\"card\"><h3>Anonymous comparison not run</h3><p>Enable the opt-in before a scan to compare discovered same-origin routes without browser credentials.</p></div>"
      : report.stats.stopped && checks.length === 0 && pageChecks.length === 0
        ? "<div class=\"card\"><h3>Anonymous comparison stopped</h3><p>The scan was stopped before no-cookie checks began.</p></div>"
        : "";
    const apiRows = usefulApiChecks.map(item => `<div class="card"><div class="endpoint">${escapeHtml(item.url)}</div><p>Browser session: HTTP ${item.sessionStatus} · Without cookies: HTTP ${item.anonymousStatus}</p><p class="muted">${escapeHtml(item.outcome)}</p>${item.anonymousRedirectTarget ? `<p class="muted">Same-origin redirect target: ${escapeHtml(item.anonymousRedirectTarget)}</p>` : ""}<p class="muted">${escapeHtml(item.sessionType || "unknown")} → ${escapeHtml(item.anonymousType || "unknown")} · ${sizeLabel(item.sessionBytes, item.sessionByteSource)} → ${sizeLabel(item.anonymousBytes, item.anonymousByteSource)}${item.sizeComplete === false ? " · size may be partial" : ""} · selected headers ${item.selectedHeadersMatch === true ? "match" : item.selectedHeadersMatch === false ? "differ" : "not compared"}</p></div>`).join("");
    const pageRows = usefulPageChecks.map(item => `<div class="card"><div class="endpoint">${escapeHtml(item.url)}</div><p>Page: HTTP ${item.sessionStatus} · Without cookies: ${item.anonymousStatus === null ? "no readable response" : `HTTP ${item.anonymousStatus}`}</p><p class="muted">${escapeHtml(item.outcome)}</p>${item.anonymousRedirectTarget ? `<p class="muted">Same-origin redirect target: ${escapeHtml(item.anonymousRedirectTarget)}</p>` : ""}<p class="muted">${escapeHtml(item.sessionType || "unknown")} → ${escapeHtml(item.anonymousType || "unknown")} · ${sizeLabel(item.sessionBytes, item.sessionByteSource)} → ${sizeLabel(item.anonymousBytes, item.anonymousByteSource)} · selected headers ${item.selectedHeadersMatch === true ? "match" : item.selectedHeadersMatch === false ? "differ" : "not compared"}</p></div>`).join("");
    panel.innerHTML = !report.scope.checkAnonymous || (report.stats.stopped && checks.length === 0 && pageChecks.length === 0)
      ? emptyMessage
       : `<div class="card"><h3>Without-cookie checks</h3><p class="muted">GET requests use credentials omitted. Only a login redirect, an authentication status after a successful browser-session response, or a non-HTML 200 response with different metadata is shown. Identical responses, HTML shells, unavailable checks, and comparisons without a successful browser-session baseline are hidden as inconclusive. Raw header values and response bodies are not shown.</p><p>${stats.anonymousRequestsAttempted || 0} requests sent · ${pageChecks.length} page routes checked · ${checks.length} API responses checked · ${usefulPageChecks.length} page-route leads shown · ${usefulApiChecks.length} API leads shown · ${Math.max(0, pageChecks.length - usefulPageChecks.length)} page results hidden · ${Math.max(0, checks.length - usefulApiChecks.length)} API results hidden${report.stats.stopped ? " · stopped early" : ""}</p></div><div class="card"><h3>Page route results</h3>${pageRows || "No actionable page-route result. HTML shells and ambiguous or unavailable checks were hidden."}</div><div class="card"><h3>API endpoint checks</h3>${apiRows || "No actionable API access-control difference. Ambiguous or unavailable checks were hidden."}</div>`;
  } else {
    const baseRouteIdeas = report.routeTestIdeas || [];
    const liveRoutes = observedItems.map(item => ({ url: reportUrl(item.url), method: item.method }));
    const routeIdeas = [...baseRouteIdeas, ...routeTestIdeas(liveRoutes, report.fingerprints || [])];
    const recon = report.reconChecklist || { reconEndpoints: [], configLeaks: [], dangerousEndpoints: [], engineHints: [], deserHints: [] };
    const reconRow = item => `<div class="idea"><span class="pill">${escapeHtml(item.framework || "General")}</span><div class="endpoint">${escapeHtml(report.origin + item.path)}</div><p>${escapeHtml(item.why)}</p></div>`;
    const reconCard = recon.reconEndpoints?.length ? `<div class="card"><h3>Fingerprint-based recon endpoints</h3><p class="muted">Suggested from detected frameworks. StackScope did not request these; check them manually within authorized scope. Presence of a path is not a finding.</p>${recon.reconEndpoints.map(reconRow).join("")}</div>` : "";
    const leakCard = recon.configLeaks?.length ? `<div class="card"><h3>Config / secret leak paths to review</h3><p class="muted">Common configuration and secret paths. StackScope does not fetch these; review manually only where your authorization allows.</p>${recon.configLeaks.map(reconRow).join("")}</div>` : "";
    const dangerCard = recon.dangerousEndpoints?.length ? `<div class="card"><h3>Default dangerous endpoints to review</h3><p class="muted">Generic high-value paths. Manual review leads only; not requested by the extension.</p>${recon.dangerousEndpoints.map(item => `<div class="idea"><div class="endpoint">${escapeHtml(report.origin + item.path)}</div><p>${escapeHtml(item.why)}</p></div>`).join("")}</div>` : "";
    const engineCard = recon.engineHints?.length ? `<div class="card"><h3>Template-engine SSTI leads</h3><p class="muted">Inferred from fingerprints. Confirmation payloads are shown for manual testing only; StackScope never sends them.</p>${recon.engineHints.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.framework)}</span><b>${escapeHtml(item.name)}</b><div>Probe (manual): <code>${escapeHtml(item.test)}</code></div><p>${escapeHtml(item.confirm)}</p>${item.note ? `<small>${escapeHtml(item.note)}</small>` : ""}</div>`).join("")}</div>` : "";
    const deserCard = recon.deserHints?.length ? `<div class="card"><h3>Deserialization / token review</h3><p class="muted">What to look for in cookies, tokens, and bodies during manual review. StackScope stores no values, so inspect these yourself.</p>${recon.deserHints.map(item => `<div class="idea"><span class="pill">${escapeHtml(item.framework)}</span><p>${escapeHtml(item.note)}</p></div>`).join("")}</div>` : "";
    panel.innerHTML = `${routeIdeas.length ? `<div class="card"><h3>Route-specific TBHM review ideas</h3><p class="muted">Each item points to a discovered route or observed method. These are manual review prompts; no attack payloads are sent.</p>${routeIdeas.map(idea => `<div class="idea"><span class="pill">${escapeHtml(idea.method)}</span><span class="pill">TBHM: ${escapeHtml(idea.tbhmCategory)}</span><b>${escapeHtml(idea.category)}</b><div class="endpoint">${escapeHtml(idea.url)}</div><p>${escapeHtml(idea.details)}</p><small>Fingerprint context: ${escapeHtml(idea.framework)}</small></div>`).join("")}</div>` : ""}${reconCard}${leakCard}${dangerCard}${engineCard}${deserCard}<div class="card"><h3>TBHM-aligned manual test ideas</h3><p class="muted">Framework-specific ideas are shown first, followed by general bug classes from TBHM. These are review leads, not confirmed vulnerabilities. No payloads are sent by this extension.</p>${report.testIdeas.map(idea => `<div class="idea"><span class="pill">${escapeHtml(idea.relevance)}</span><b>${escapeHtml(idea.category)}</b><p>${escapeHtml(idea.details)}</p></div>`).join("")}</div><div class="card"><h3>Safe use notes</h3>Use written authorization, dedicated test accounts, and reversible checks. Do not retrieve exposed secrets, heap dumps, or other users' data.</div>`;
  }
}

function updateStartButton() {
  $("start").disabled = !activeTabReady || !storageReady || Boolean(pendingReportRecord) || Boolean(activeController);
}

function refreshSavedReportList() {
  const select = $("historySelect");
  select.replaceChildren();
  for (const record of savedReports) {
    const option = document.createElement("option");
    option.value = record.id;
    const when = new Date(record.report.createdAt).toLocaleString();
    const scope = record.report.scope || {};
    const mode = scope.mode === "module" ? "module " + (scope.modulePath || "") : "whole origin";
    const count = record.report.stats?.urlsVisited ?? record.report.stats?.requestsAttempted ?? 0;
    option.textContent = record.report.origin + " · " + mode + " · " + count + " requests · " + when;
    select.append(option);
  }
  $("reportHistory").hidden = savedReports.length === 0;
}

async function restoreStoredReports() {
  const stored = await browser.storage.local.get([PENDING_STORAGE_KEY, SAVED_STORAGE_KEY]);
  const isRecord = value => Boolean(value && typeof value === "object" && !Array.isArray(value));
  const validOrigin = value => {
    try {
      const parsed = new URL(String(value || ""));
      return /^https?:$/.test(parsed.protocol) && parsed.origin === value;
    } catch (_) { return false; }
  };
  const rawSavedReports = Array.isArray(stored[SAVED_STORAGE_KEY]) ? stored[SAVED_STORAGE_KEY].filter(record => isRecord(record) && record.id && isRecord(record.report)) : [];
  savedReports = rawSavedReports.flatMap(record => {
    const report = sanitizeStoredReport(record.report);
    if (!report || !validOrigin(report.origin)) return [];
    return [{
      id: String(record.id).slice(0, 128),
      savedAt: Number.isFinite(Number(record.savedAt)) ? Number(record.savedAt) : 0,
      inProgress: false,
      report
    }];
  }).slice(0, 20);
  if (JSON.stringify(savedReports) !== JSON.stringify(rawSavedReports)) await browser.storage.local.set({ [SAVED_STORAGE_KEY]: savedReports });
  const storedPending = isRecord(stored[PENDING_STORAGE_KEY]) ? stored[PENDING_STORAGE_KEY] : null;
  const pendingReport = storedPending && isRecord(storedPending.report) ? sanitizeStoredReport(storedPending.report) : null;
  pendingReportRecord = pendingReport && validOrigin(pendingReport.origin) ? {
    id: String(storedPending.id || "recovered").slice(0, 128),
    savedAt: Number.isFinite(Number(storedPending.savedAt)) ? Number(storedPending.savedAt) : 0,
    inProgress: Boolean(storedPending.inProgress),
    report: pendingReport
  } : null;
  if (pendingReportRecord && Date.now() - Number(pendingReportRecord.savedAt || 0) > PENDING_TTL_MS) {
    await browser.storage.local.remove(PENDING_STORAGE_KEY);
    pendingReportRecord = null;
  } else if (JSON.stringify(pendingReportRecord) !== JSON.stringify(storedPending)) {
    if (pendingReportRecord) await browser.storage.local.set({ [PENDING_STORAGE_KEY]: pendingReportRecord });
    else await browser.storage.local.remove(PENDING_STORAGE_KEY);
  }
  refreshSavedReportList();
  if (pendingReportRecord?.report) {
    lastReport = pendingReportRecord.report;
    $("reportDecision").hidden = false;
    $("results").hidden = false;
    render("summary");
    $("status").textContent = `Recovered an unsaved ${pendingReportRecord.inProgress ? "partial" : "completed"} recon report. Save or discard it before starting another scan.`;
  }
  storageReady = true;
  updateStartButton();
}

async function savePendingReport() {
  if (!pendingReportRecord) return;
  const record = { ...pendingReportRecord, inProgress: false };
  savedReports = [record, ...savedReports.filter(existing => existing.id !== record.id)].slice(0, 20);
  await browser.storage.local.set({ [SAVED_STORAGE_KEY]: savedReports });
  await browser.storage.local.remove(PENDING_STORAGE_KEY);
  pendingReportRecord = null;
  $("reportDecision").hidden = true;
  refreshSavedReportList();
  updateStartButton();
  $("status").textContent = "Report saved in this Firefox profile. You can reopen it from Saved reports.";
}

async function discardPendingReport() {
  if (pendingReportRecord) await browser.storage.local.remove(PENDING_STORAGE_KEY);
  pendingReportRecord = null;
  lastReport = null;
  $("reportDecision").hidden = true;
  $("results").hidden = true;
  updateStartButton();
  $("status").textContent = "Temporary report discarded.";
}

$("start").addEventListener("click", () => {
  // Firefox requires permissions.request to be called synchronously from the
  // user gesture, before any await. Start it here and hand the promise to scan.
  let permissionRequest;
  try {
    permissionRequest = browser.permissions.request({ origins: buildScanPermissionOrigins() });
  } catch (error) {
    $("status").textContent = `Error: ${error?.message || "Scan could not start."}`;
    return;
  }
  scan(permissionRequest).catch(error => {
    $("status").textContent = `Error: ${error?.message || "Scan could not start."}`;
    updateStartButton();
    $("stop").disabled = true;
  });
});
$("stop").addEventListener("click", () => {
  stopRequested = true;
  activeController?.abort();
  $("status").textContent = "Stopping the current request…";
});
document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => render(button.dataset.tab)));
$("scopeMode").addEventListener("change", () => {
  $("modulePath").disabled = $("scopeMode").value !== "module";
});
$("checkAnonymous").addEventListener("change", () => {
  $("anonymousLimit").disabled = !$("checkAnonymous").checked;
});
$("startObserver").addEventListener("click", () => {
  let permissionRequest;
  try {
    permissionRequest = browser.permissions.request({ origins: buildObserverPermissionOrigins() });
  } catch (error) {
    $("status").textContent = `Observer error: ${error?.message || "Could not start the observer."}`;
    return;
  }
  startTrafficObserver(permissionRequest).catch(error => { $("status").textContent = `Observer error: ${error?.message || "Could not start the observer."}`; });
});
$("stopObserver").addEventListener("click", () => {
  stopTrafficObserver().catch(error => { $("status").textContent = `Could not stop observer: ${error?.message || "unknown error"}`; });
});
$("clearTraffic").addEventListener("click", async () => {
  if (!activeTrafficStorageKey) return;
  const stored = await browser.storage.local.get(activeTrafficStorageKey);
  const existing = stored[activeTrafficStorageKey];
  if (!existing) return;
  trafficRecord = { ...existing, items: [], updatedAt: Date.now() };
  await browser.storage.local.set({ [activeTrafficStorageKey]: trafficRecord });
  renderTrafficRecord();
  $("status").textContent = "Observed request metadata cleared from this device.";
});
$("saveReport").addEventListener("click", () => {
  savePendingReport().catch(error => { $("status").textContent = `Could not save report: ${error?.message || "storage error"}`; });
});
$("discardReport").addEventListener("click", () => {
  discardPendingReport().catch(error => { $("status").textContent = `Could not discard report: ${error?.message || "storage error"}`; });
});
$("openSaved").addEventListener("click", () => {
  if (pendingReportRecord) {
    $("status").textContent = "Save or discard the temporary report before opening a saved report.";
    return;
  }
  const record = savedReports.find(item => item.id === $("historySelect").value);
  if (!record) return;
  lastReport = record.report;
  $("results").hidden = false;
  $("reportDecision").hidden = true;
  render("summary");
  $("status").textContent = `Opened saved report for ${record.report.origin}.`;
});
$("deleteSaved").addEventListener("click", async () => {
  const selectedId = $("historySelect").value;
  if (!selectedId) return;
  savedReports = savedReports.filter(item => item.id !== selectedId);
  try {
    await browser.storage.local.set({ [SAVED_STORAGE_KEY]: savedReports });
    refreshSavedReportList();
    $("status").textContent = "Saved report deleted from this Firefox profile.";
  } catch (error) {
    $("status").textContent = `Could not delete saved report: ${error?.message || "storage error"}`;
  }
});
$("export").addEventListener("click", () => {
  if (!lastReport) return;
  const sameScopeTraffic = trafficRecord?.origin === lastReport.origin && trafficRecord?.mode === lastReport.scope?.mode && trafficRecord?.modulePath === lastReport.scope?.modulePath
    ? (trafficRecord.items || []).slice(-TRAFFIC_ITEM_LIMIT) : [];
  const combinedTraffic = mergeObservedTraffic(lastReport.observedTraffic, sameScopeTraffic);
  const exportData = sanitizeStoredReport({ ...lastReport, observedTraffic: combinedTraffic, exportedAt: new Date().toISOString() });
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  let slug = "site";
  try { slug = new URL(lastReport.origin).hostname.toLowerCase().replace(/[^a-z0-9.-]+/g, "-"); } catch (_) { /* use generic name */ }
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  anchor.download = "stackscope-" + slug + "-" + timestamp + ".json";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
});

$("importReport").addEventListener("change", async event => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    if (file.size > 5_000_000) throw new Error("Choose a JSON report smaller than 5 MB.");
    const parsed = JSON.parse(await file.text());
    const report = parsed?.report || parsed;
    const originUrl = new URL(String(report?.origin || ""));
    if (!/^https?:$/.test(originUrl.protocol) || originUrl.origin !== report.origin) throw new Error("The JSON file does not contain a valid StackScope origin report.");
    const sanitized = sanitizeStoredReport(report);
    if (!sanitized.scope || !Array.isArray(sanitized.endpoints)) throw new Error("The JSON file is not a compatible StackScope report.");
    const record = { id: String(Date.now()) + "-" + Math.random().toString(36).slice(2, 8), savedAt: Date.now(), inProgress: false, report: sanitized };
    savedReports = [record, ...savedReports.filter(item => item.id !== record.id)].slice(0, 20);
    await browser.storage.local.set({ [SAVED_STORAGE_KEY]: savedReports });
    refreshSavedReportList();
    $("status").textContent = "Imported report for " + originUrl.origin + " into this Firefox profile.";
  } catch (error) {
    $("status").textContent = "Could not import report: " + (error?.message || "invalid JSON");
  } finally {
    event.target.value = "";
  }
});

// Capture the tab while the action popup is open. Requiring an explicit module
// path avoids silently treating `/` as a narrow module selection.
$("start").disabled = true;
$("startObserver").disabled = true;
$("status").textContent = "Reading the active tab…";
browser.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  activeTabSnapshot = tab || null;
  popupOpenedTabId = tab?.id ?? null;
  try { popupOpenedOrigin = tab?.url ? new URL(tab.url).origin : null; } catch (_) { popupOpenedOrigin = null; }
  activeTabReady = true;
  updateStartButton();
  $("startObserver").disabled = !tab?.id || !tab?.url || !/^https?:/i.test(tab.url);
  if (tab?.url && /^https?:/i.test(tab.url)) {
    const pathname = new URL(tab.url).pathname;
    $("modulePath").placeholder = `Enter module path (current page: ${pathname})`;
    $("status").textContent = "Choose a module path or whole origin, then start the scan.";
  } else {
    $("status").textContent = "Open an HTTP/HTTPS target page to start.";
  }
  restoreTrafficForActiveTab().catch(error => { $("status").textContent = `Could not restore observed traffic: ${error?.message || "storage error"}`; });
}).catch(() => {
  activeTabReady = true;
  updateStartButton();
  $("startObserver").disabled = true;
  $("status").textContent = "Could not read the active tab. Reopen this popup and try again.";
});
restoreStoredReports().catch(error => {
  storageReady = true;
  updateStartButton();
  $("status").textContent = `Could not read local report storage: ${error?.message || "storage error"}`;
});
