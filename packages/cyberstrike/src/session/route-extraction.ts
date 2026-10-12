import { Server } from "../server/server"
import { Log } from "../util/log"

// ============================================================
// ROUTE EXTRACTION — plan_A2.md §9 "Phương án A"
//
// Closes the discovery→test gap in the proxy pipeline. hackbrowser is a
// UI-driven crawler: it only reaches endpoints that have a clickable element,
// so hidden routes (Angular hash routes' backing APIs, /ftp, /metrics, backup
// files) are never captured and therefore never get a test orchestration.
//
// This module runs ONCE, right after a crawl completes (hooked from
// hackbrowser-launcher's success branch). It mines the app's own JS bundles +
// robots.txt + a small curated wordlist for candidate HTTP paths, probes each,
// and re-feeds every live one through the SAME /session/ingest path the crawler
// uses. From there each hidden endpoint is deduped, persisted to RequestTable,
// bridged into the Methodology Engine, and handed its own proxy-agent
// orchestration — identical to any crawled capture, no special-casing.
//
// Loopback ingest skips server auth (server.ts) so no credential is needed.
// ============================================================

export namespace RouteExtraction {
  const log = Log.create({ service: "route-extraction" })

  // Safety caps so a hostile/huge target can't turn this into a runaway.
  const MAX_BUNDLES = 20
  const MAX_CANDIDATES = 300
  const MAX_LIVE_FEEDS = 200
  const FETCH_TIMEOUT_MS = 10_000

  // Curated, app-agnostic paths that dir-fuzz wordlists and UI crawls commonly
  // miss but that carry high signal on real targets (matches the concrete A2
  // cases in plan_A2.md §1: /ftp listing, /metrics, backup/config files).
  const WORDLIST = [
    "/ftp",
    "/metrics",
    "/robots.txt",
    "/sitemap.xml",
    "/.git/config",
    "/.env",
    "/.well-known/security.txt",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/actuator",
    "/actuator/health",
    "/server-status",
  ]

  /** Fetch with a timeout and (for https) relaxed TLS — lab targets are often
   *  self-signed. Returns null on any failure instead of throwing. */
  async function safeFetch(
    url: string,
    method: string = "GET",
    extra?: { headers?: Record<string, string>; body?: string },
  ): Promise<{ status: number; body: string; contentType: string } | null> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
    try {
      // Bun's fetch accepts a `tls` option that the DOM RequestInit type omits.
      const opts: RequestInit = { method, signal: controller.signal, redirect: "manual" }
      if (extra?.headers) opts.headers = extra.headers
      if (extra?.body !== undefined) opts.body = extra.body
      if (url.startsWith("https:")) (opts as { tls?: unknown }).tls = { rejectUnauthorized: false }
      const res = await fetch(url, opts)
      const contentType = res.headers.get("content-type") ?? ""
      // Cap body read so a giant asset doesn't blow memory. 8 MB covers real SPA bundles — the
      // old 512 KB cap TRUNCATED main.js (often 700 KB–3 MB), dropping every API path declared past
      // that offset (e.g. /api/Cards, /rest/wallet/balance), which is exactly why the write +
      // authenticated surface came back short. (bug fix 16-9-2026)
      const body = (await res.text().catch(() => "")).slice(0, 8 * 1024 * 1024)
      return { status: res.status, body, contentType }
    } catch {
      return null
    } finally {
      clearTimeout(timer)
    }
  }

  /** Pull candidate absolute HTTP paths out of a JS bundle's source text.
   *  Only real server paths (leading "/"), never client-side hash routes
   *  (#/...) — a hash route isn't a distinct HTTP request, its backing REST
   *  path is, and those appear here as quoted "/rest/..." / "/api/..." strings. */
  function extractPathsFromJs(js: string): Set<string> {
    const found = new Set<string>()
    // Quoted absolute paths: "'/rest/admin/application-configuration'", etc.
    // Lookahead terminator (not just a closing quote) also captures the path portion of a
    // query-suffixed literal like "/redirect?to=" → /redirect (a server route the SPA links to
    // but that the strict-quote form drops).
    // Optional leading "./" captures relative links too (e.g. "./redirect?to=" → /redirect).
    const quoted = /["'`]\.?(\/[A-Za-z0-9._\-/]{2,80})(?=["'`?&#])/g
    for (const m of js.matchAll(quoted)) {
      const p = m[1]
      // Skip static assets and obvious non-endpoints.
      if (/\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webmanifest|mp4|webp)$/i.test(p)) continue
      if (p.includes("//")) continue
      found.add(p)
    }
    return found
  }

  /** Cải thiện ① (16-9-2026.md): pull (METHOD, path) PAIRS from HTTP call sites in a JS bundle.
   *  This is how the WRITE surface (POST/PUT/DELETE) is discovered — an anonymous crawl only
   *  navigates (GET), but the SPA's own code declares every call it makes WITH its verb. General
   *  to any Angular/React/Vue app; deterministic; static-parse (fast, black-box safe). Path
   *  templates ({id} / ${var}) → concrete "1" so they are probeable. */
  function extractMethodPathsFromJs(js: string): Array<{ method: string; path: string }> {
    const out: Array<{ method: string; path: string }> = []
    const seen = new Set<string>()
    const norm = (p: string) => p.replace(/\$\{[^}]*\}/g, "1").replace(/\{[^}]+\}/g, "1")
    const push = (method: string, raw: string) => {
      const p = norm(raw)
      if (/\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webmanifest|mp4|webp)$/i.test(p)) return
      if (p.includes("//")) return
      const key = method.toUpperCase() + " " + p
      if (seen.has(key)) return
      seen.add(key)
      out.push({ method: method.toUpperCase(), path: p })
    }
    // Angular HttpClient / axios / $http / superagent: .get('/x') .post('/x') .put/.delete/.patch
    const call = /\.(get|post|put|delete|patch)\s*\(\s*["'`](\/[A-Za-z0-9._\-/{}$]{2,80})/gi
    for (const m of js.matchAll(call)) push(m[1], m[2])
    // fetch('/x', { method: 'POST' })  and  request('POST', '/x')
    const fetchCall =
      /fetch\s*\(\s*["'`](\/[A-Za-z0-9._\-/{}$]{2,80})["'`]\s*,\s*\{[^}]*method\s*:\s*["'`](GET|POST|PUT|DELETE|PATCH)/gi
    for (const m of js.matchAll(fetchCall)) push(m[2], m[1])
    const reqCall = /\brequest\s*\(\s*["'`](GET|POST|PUT|DELETE|PATCH)["'`]\s*,\s*["'`](\/[A-Za-z0-9._\-/{}$]{2,80})/gi
    for (const m of js.matchAll(reqCall)) push(m[1], m[2])
    return out
  }

  /** Cải thiện (16-9-2026.md): high-signal API paths mined WITHOUT requiring surrounding quotes.
   *  Minified SPAs concatenate the base URL (`this.hostServer+"/api/Cards"`, or split across
   *  tokens) so the quoted-literal miner above misses many endpoints. `/api/`, `/rest/`, `/b2b/`
   *  are distinctive enough to grab anywhere in the source — this is what surfaces the full API
   *  surface (e.g. /api/Cards, /rest/wallet/balance, /rest/order-history) that the quoted miner drops. */
  function extractApiPathsFromJs(js: string): Set<string> {
    const found = new Set<string>()
    for (const m of js.matchAll(/\/(?:api|rest|b2b)\/[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*/g)) {
      const p = m[0].replace(/[.\-_/]+$/, "") // trim trailing punctuation from a truncated match
      if (p.length < 4 || p.includes("//")) continue
      found.add(p)
    }
    return found
  }

  /** SPA client-route table. Angular/React/Vue declare page routes as `path:"profile"` —
   *  RELATIVE (no leading slash), so neither the quoted-path miner (requires "/") nor the
   *  api/rest miner catches them. Yet these backing page routes (/profile, /redirect,
   *  /administration, ...) are real server-reachable GET paths carrying SSRF/SSTi/redirect/XSS
   *  surface. `path:` is a framework API key preserved through minification, so this is general
   *  to any SPA router config; static-parse, black-box. */
  function extractSpaRoutesFromJs(js: string): Set<string> {
    const found = new Set<string>()
    for (const m of js.matchAll(/\bpath\s*:\s*["'`]([A-Za-z0-9][A-Za-z0-9._\-/]{0,60})["'`]/g)) {
      let r = m[1]
      if (!r || r === "**" || r.includes(":") || r.includes("*")) continue // skip wildcard / param-only routes
      // take the concrete leading segments only (drop a trailing /:param handled above)
      r = r.replace(/\/+$/, "")
      if (!r) continue
      const p = "/" + r
      if (/\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webmanifest|mp4|webp)$/i.test(p)) continue
      if (p.includes("//")) continue
      found.add(p)
      // also register the first path segment as a base route (e.g. /administration)
      const first = "/" + r.split("/")[0]
      if (first.length > 1) found.add(first)
    }
    return found
  }

  /** robots.txt Disallow entries are high-signal hidden paths (that's how /ftp
   *  is found on Juice Shop). */
  function extractPathsFromRobots(robots: string): Set<string> {
    const found = new Set<string>()
    for (const line of robots.split(/\r?\n/)) {
      const m = /^\s*Disallow:\s*(\/\S*)/i.exec(line)
      if (m && m[1] !== "/") found.add(m[1])
    }
    return found
  }

  /** OpenAPI/Swagger `paths` keys — routes the app itself declares. Finds endpoints
   *  with NO UI and NO JS reference (e.g. a deprecated B2B interface documented only
   *  in the spec — the plan_A2.md XXE case). Path templates ({id}) → a concrete "1". */
  function extractPathsFromOpenApi(json: string): Set<string> {
    return extractFromOpenApi(json).paths
  }

  export interface OpenApiOperation {
    method: string
    path: string
    params: Array<{ name: string; type: string; in: string }>
  }

  function extractFromOpenApi(json: string): { paths: Set<string>; operations: OpenApiOperation[] } {
    const paths = new Set<string>()
    const operations: OpenApiOperation[] = []
    try {
      const doc = JSON.parse(json) as Record<string, unknown>
      const docPaths = (doc as { paths?: Record<string, unknown> }).paths
      if (!docPaths || typeof docPaths !== "object") return { paths, operations }

      // OpenAPI 3.x base path from servers[0].url
      const servers = doc.servers as Array<{ url?: string }> | undefined
      const basePath = (servers?.[0]?.url ?? "").replace(/^https?:\/\/[^/]+/, "").replace(/\/$/, "")
      // Swagger 2.x base path
      const swaggerBase = ((doc.basePath as string) ?? "").replace(/\/$/, "")
      const prefix = basePath || swaggerBase

      // Resolve $ref to component schemas for body param extraction
      const components = doc.components as Record<string, unknown> | undefined
      const definitions = doc.definitions as Record<string, unknown> | undefined
      const schemasMap = (components?.schemas ?? definitions ?? {}) as Record<string, Record<string, unknown>>

      function resolveSchema(schema: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
        if (!schema) return undefined
        const ref = schema["$ref"] as string | undefined
        if (ref) {
          const name = ref.split("/").pop()
          if (name && schemasMap[name]) return schemasMap[name]
        }
        return schema
      }

      for (const [rawPath, methodsObj] of Object.entries(docPaths)) {
        if (!rawPath.startsWith("/")) continue
        const fullPath = (prefix + rawPath).replace(/\{[^}]+\}/g, "1")
        paths.add(fullPath)
        if (!methodsObj || typeof methodsObj !== "object") continue
        for (const [method, opObj] of Object.entries(methodsObj as Record<string, unknown>)) {
          if (!["get", "post", "put", "delete", "patch"].includes(method)) continue
          const op = opObj as Record<string, unknown>
          const params: OpenApiOperation["params"] = []
          if (Array.isArray(op?.parameters)) {
            for (const pm of op.parameters as Array<Record<string, unknown>>) {
              if (pm?.name && typeof pm.name === "string") {
                const schema = pm.schema as Record<string, unknown> | undefined
                params.push({
                  name: pm.name,
                  type: (schema?.type as string) ?? (pm.type as string) ?? "string",
                  in: (pm.in as string) ?? "query",
                })
                const resolved = resolveSchema(schema)
                if (pm.in === "body" && resolved?.properties && typeof resolved.properties === "object") {
                  for (const [propName, propVal] of Object.entries(resolved.properties as Record<string, unknown>)) {
                    params.push({ name: propName, type: ((propVal as Record<string, unknown>)?.type as string) ?? "string", in: "body" })
                  }
                }
              }
            }
          }
          // OpenAPI 3.x requestBody with $ref resolution
          const reqBody = op?.requestBody as Record<string, unknown> | undefined
          const content = reqBody?.content as Record<string, unknown> | undefined
          const jsonContent = content?.["application/json"] as Record<string, unknown> | undefined
          let bodySchema = resolveSchema(jsonContent?.schema as Record<string, unknown> | undefined)
          if (bodySchema?.properties && typeof bodySchema.properties === "object") {
            for (const [propName, propVal] of Object.entries(bodySchema.properties as Record<string, unknown>)) {
              params.push({ name: propName, type: ((propVal as Record<string, unknown>)?.type as string) ?? "string", in: "body" })
            }
          }
          operations.push({ method: method.toUpperCase(), path: fullPath, params })
        }
      }
    } catch {}
    return { paths, operations }
  }

  /** Extract OpenAPI/Swagger spec from Swagger-UI's inline JS initializer.
   *  The spec is embedded as `"swaggerDoc": { ... }` in swagger-ui-init.js. */
  function extractSwaggerDocFromJs(js: string): string | null {
    const m = js.match(/"swaggerDoc"\s*:\s*(\{)/)
    if (!m || m.index === undefined) return null
    const start = m.index + m[0].length - 1
    let depth = 0
    for (let i = start; i < js.length; i++) {
      if (js[i] === "{") depth++
      else if (js[i] === "}") depth--
      if (depth === 0) return js.slice(start, i + 1)
    }
    return null
  }

  const SENSITIVE_FILE_RE = /["'`]([A-Za-z0-9][A-Za-z0-9._-]{1,60}\.(?:stl|bak|kdbx|key|pem|sql|csv|log|conf|config|yml|yaml|pdf|doc|docx|xls|xlsx|sqlite|db|dump|asc|gpg|crt|p12|jks|properties|htpasswd|htaccess|old|orig|save|swp|bkp))["'`]/gi

  function extractFilenames(js: string): Set<string> {
    const found = new Set<string>()
    for (const m of js.matchAll(SENSITIVE_FILE_RE)) {
      const f = m[1]
      if (f.length < 3) continue
      if (/^(main|vendor|polyfills|runtime|styles|scripts|chunk|es2015|es5)\./i.test(f)) continue
      found.add(f)
    }
    return found
  }

  const FILE_PATH_PREFIXES = [
    "/assets/public/images/products/",
    "/assets/public/images/uploads/",
    "/assets/public/",
    "/public/images/",
    "/public/",
    "/assets/",
    "/images/",
    "/static/",
    "/downloads/",
    "/files/",
    "/ftp/",
    "/",
  ]

  /** sitemap.xml <loc> entries — declared, crawlable URLs. */
  function extractPathsFromSitemap(xml: string): Set<string> {
    const found = new Set<string>()
    for (const m of xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) {
      try {
        const u = new URL(m[1].trim())
        if (u.pathname && u.pathname !== "/") found.add(u.pathname)
      } catch {
        // relative or malformed <loc> — ignore
      }
    }
    return found
  }

  /** Build a minimal raw HTTP request (request line + Host header) for the given method/path,
   *  as the ingest normalizer expects. Cải thiện ①: method is no longer hard-coded to GET. */
  function rawRequest(method: string, host: string, path: string): string {
    return `${method} ${path} HTTP/1.1\r\nHost: ${host}\r\n\r\n`
  }

  /** POST one synthetic capture through the normal ingest path (loopback → no
   *  auth). Dedup, persistence, methodology bridge and orchestration all happen
   *  downstream exactly as for a crawled capture. */
  async function feedCapture(
    ingestUrl: string,
    sessionID: string,
    host: string,
    scheme: "http" | "https",
    path: string,
    probe: { status: number; body: string; contentType: string },
    method: string = "GET",
  ): Promise<void> {
    const payload = {
      text: rawRequest(method, host, path),
      sessionID,
      scheme,
      response: {
        status: probe.status,
        headers: probe.contentType ? { "content-type": probe.contentType } : {},
        body: probe.body.slice(0, 64 * 1024),
      },
    }
    try {
      await fetch(ingestUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
    } catch (err) {
      log.warn("synthetic capture feed failed", { sessionID, path, error: String(err) })
    }
  }

  /** Recon-ONLY (16-9-2026.md): mine + probe the endpoint surface and RETURN the inventory WITHOUT
   *  feeding the test pipeline. Backs the `discover_endpoints` tool so an operator can prompt
   *  "recon this target, list endpoints" and STOP at recon — seconds, deterministic, no LLM
   *  testing, no state mutation (writes probed with OPTIONS only). */
  export async function discover(input: {
    target: string
    // Cải thiện ② (16-9-2026.md): authenticated recon WITHOUT hackbrowser/testing. Provide a
    // Bearer token directly, OR email+password+loginPath to log in by code (HTTP only). Each
    // endpoint is then probed both anonymously AND with the token, so 401-anon→200-auth reveals
    // the authenticated-only surface (the "login flow") — no browser, no orchestration, no test.
    token?: string
    email?: string
    password?: string
    loginPath?: string
  }): Promise<{
    origin: string
    authenticated: boolean
    gets: Array<{ path: string; statusAnon: number; statusAuth?: number; authOnly?: boolean }>
    writes: Array<{ method: string; path: string; status: number }>
    openApiOps: OpenApiOperation[]
    filenames: string[]
    token?: string
  } | null> {
    let base: URL
    try {
      base = new URL(input.target)
    } catch {
      return null
    }
    const host = base.host
    const scheme = base.protocol === "https:" ? "https" : "http"
    const origin = `${scheme}://${host}`

    // Obtain a Bearer token: use one given directly, else log in by code with credentials.
    let token = input.token
    if (!token && input.email && input.password && input.loginPath) {
      const loginRes = await safeFetch(origin + input.loginPath, "POST", {
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: input.email, password: input.password }),
      })
      if (loginRes && loginRes.status < 400) {
        try {
          const j = JSON.parse(loginRes.body) as Record<string, unknown>
          // Common token shapes: {token}, {access_token}, {jwt}, {authentication:{token}}
          const auth = j.authentication as Record<string, unknown> | undefined
          token =
            (j.token as string) ??
            (j.access_token as string) ??
            (j.jwt as string) ??
            (auth?.token as string) ??
            undefined
        } catch {
          // non-JSON login response — leave token undefined
        }
      }
    }
    const authHeaders = token ? { Authorization: `Bearer ${token}` } : undefined

    const candidates = new Set<string>()
    const writeCandidates = new Map<string, string>()
    const allFilenames = new Set<string>()
    let openApiOps: OpenApiOperation[] = []

    const rootHtml = await safeFetch(origin + "/")
    if (rootHtml) {
      const srcs = [...rootHtml.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1])
      let n = 0
      for (const src of srcs) {
        if (n >= MAX_BUNDLES) break
        if (!/\.js(\?|$)/i.test(src)) continue
        const url = src.startsWith("http") ? src : origin + (src.startsWith("/") ? src : "/" + src)
        try {
          if (new URL(url).host !== host) continue
        } catch {
          continue
        }
        const js = await safeFetch(url)
        n++
        if (!js) continue
        for (const p of extractPathsFromJs(js.body)) candidates.add(p)
        for (const p of extractApiPathsFromJs(js.body)) candidates.add(p)
        for (const p of extractSpaRoutesFromJs(js.body)) candidates.add(p)
        for (const mp of extractMethodPathsFromJs(js.body)) {
          if (mp.method === "GET") candidates.add(mp.path)
          else writeCandidates.set(`${mp.method} ${mp.path}`, mp.path)
        }
        for (const f of extractFilenames(js.body)) allFilenames.add(f)
      }
    }
    const robots = await safeFetch(origin + "/robots.txt")
    if (robots && robots.status === 200) for (const p of extractPathsFromRobots(robots.body)) candidates.add(p)
    for (const p of WORDLIST) candidates.add(p)
    const specPaths = ["/swagger.json", "/openapi.json", "/api-docs", "/sitemap.xml", "/api-docs/swagger-ui-init.js"]
    for (const specPath of specPaths) {
      const spec = await safeFetch(origin + specPath)
      if (!spec || spec.status !== 200) continue
      if (specPath.endsWith(".xml")) {
        for (const p of extractPathsFromSitemap(spec.body)) candidates.add(p)
      } else {
        // Try direct JSON parse; if it fails (HTML/JS), try extracting inline swaggerDoc
        let specJson = spec.body
        try { JSON.parse(specJson) } catch {
          const inline = extractSwaggerDocFromJs(specJson)
          if (inline) specJson = inline; else continue
        }
        const result = extractFromOpenApi(specJson)
        for (const p of result.paths) candidates.add(p)
        for (const op of result.operations) {
          if (op.method !== "GET") writeCandidates.set(`${op.method} ${op.path}`, op.path)
        }
        if (result.operations.length > 0) openApiOps = result.operations
      }
    }
    for (const p of candidates) {
      if (!/^\/api\/[A-Za-z][A-Za-z0-9]*\/?$/.test(p)) continue
      const b = p.replace(/\/$/, "")
      writeCandidates.set(`POST ${b}`, b)
      writeCandidates.set(`PUT ${b}/1`, `${b}/1`)
      writeCandidates.set(`DELETE ${b}/1`, `${b}/1`)
    }
    for (const filename of allFilenames) {
      for (const prefix of FILE_PATH_PREFIXES) candidates.add(prefix + filename)
    }

    const gets: Array<{ path: string; statusAnon: number; statusAuth?: number; authOnly?: boolean }> = []
    for (const path of [...candidates].slice(0, MAX_CANDIDATES)) {
      const anon = await safeFetch(origin + path)
      if (!anon) continue
      // Anonymous existence: keep anything not 404/5xx. With a token, also probe authenticated so
      // an endpoint that is 401/403 anon but 200 authed surfaces as the login-flow surface.
      const auth = authHeaders ? await safeFetch(origin + path, "GET", { headers: authHeaders }) : undefined
      const anonLive = anon.status !== 404 && anon.status < 500
      const authLive = auth ? auth.status !== 404 && auth.status < 500 : false
      if (!anonLive && !authLive) continue
      const authOnly = auth ? (anon.status === 401 || anon.status === 403) && auth.status < 400 : undefined
      gets.push({
        path,
        statusAnon: anon.status,
        ...(auth ? { statusAuth: auth.status } : {}),
        ...(authOnly ? { authOnly: true } : {}),
      })
    }
    const writes: Array<{ method: string; path: string; status: number }> = []
    for (const [key, path] of writeCandidates) {
      const method = key.slice(0, key.indexOf(" "))
      const probe = await safeFetch(origin + path, "OPTIONS", authHeaders ? { headers: authHeaders } : undefined)
      if (!probe || probe.status === 404) continue
      writes.push({ method, path, status: probe.status })
    }
    return { origin, authenticated: Boolean(token), gets, writes, openApiOps, filenames: [...allFilenames], token }
  }

  export async function run(input: { sessionID: string; target: string; token?: string }): Promise<void> {
    const { sessionID, target, token } = input
    let base: URL
    try {
      base = new URL(target)
    } catch {
      log.warn("route-extraction: invalid target url", { target })
      return
    }
    const host = base.host
    const scheme = base.protocol === "https:" ? "https" : "http"
    const origin = `${scheme}://${host}`
    const ingestUrl = `${Server.url().toString().replace(/\/$/, "")}/session/ingest`
    // Optional authenticated probing: when a session token is supplied (e.g. the
    // auto-bootstrap lab credential), an anon 401/403 endpoint is re-probed WITH the
    // token so the login-gated business surface (baskets/orders/cards/wallet — where
    // most IDOR/business-logic challenges live) is discovered with its REAL response,
    // not fed as a 401 shell the analyzer can't extract object values from.
    const authHeaders = token ? { Authorization: `Bearer ${token}` } : undefined

    log.info("route-extraction started", { sessionID, target: origin })

    const candidates = new Set<string>()
    // Cải thiện ①: write-surface candidates (POST/PUT/DELETE/PATCH) mined from JS call sites.
    // Kept separate from GET `candidates` so we can probe them SAFELY (OPTIONS) — a live crawl
    // never issues these verbs, so this is the only way the write surface is discovered.
    const writeCandidates = new Map<string, string>() // key "METHOD PATH" → dedup

    // 1. Root HTML → <script src> bundles → grep each for API paths.
    const rootHtml = await safeFetch(origin + "/")
    if (rootHtml) {
      const srcs = [...rootHtml.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1])
      let bundleCount = 0
      for (const src of srcs) {
        if (bundleCount >= MAX_BUNDLES) break
        if (!/\.js(\?|$)/i.test(src)) continue
        const url = src.startsWith("http") ? src : origin + (src.startsWith("/") ? src : "/" + src)
        // Same-origin bundles only — don't crawl third-party CDNs.
        try {
          if (new URL(url).host !== host) continue
        } catch {
          continue
        }
        const js = await safeFetch(url)
        bundleCount++
        if (!js) continue
        for (const p of extractPathsFromJs(js.body)) candidates.add(p)
        for (const p of extractApiPathsFromJs(js.body)) candidates.add(p)
        for (const p of extractSpaRoutesFromJs(js.body)) candidates.add(p)
        // Cải thiện ①: (method, path) pairs. GET → normal candidate; write verbs → writeCandidates.
        for (const mp of extractMethodPathsFromJs(js.body)) {
          if (mp.method === "GET") candidates.add(mp.path)
          else writeCandidates.set(`${mp.method} ${mp.path}`, mp.path)
        }
      }
    }

    // 2. robots.txt Disallow entries.
    const robots = await safeFetch(origin + "/robots.txt")
    if (robots && robots.status === 200) for (const p of extractPathsFromRobots(robots.body)) candidates.add(p)

    // 3. Curated wordlist.
    for (const p of WORDLIST) candidates.add(p)

    // 3b. Parse API specs / sitemap CONTENT for declared paths — catches routes with no UI
    //     element and no JS reference (e.g. a deprecated B2B endpoint documented only in the
    //     OpenAPI spec — the exact plan_A2.md XXE miss). Distinct from step 3, which only probes
    //     the spec URLs as endpoints; here we read their bodies to enumerate what they declare.
    const runSpecPaths = ["/swagger.json", "/openapi.json", "/api-docs", "/sitemap.xml", "/api-docs/swagger-ui-init.js"]
    for (const specPath of runSpecPaths) {
      const spec = await safeFetch(origin + specPath)
      if (!spec || spec.status !== 200) continue
      if (specPath.endsWith(".xml")) {
        for (const p of extractPathsFromSitemap(spec.body)) candidates.add(p)
      } else {
        let specJson = spec.body
        try { JSON.parse(specJson) } catch {
          const inline = extractSwaggerDocFromJs(specJson)
          if (inline) specJson = inline; else continue
        }
        const result = extractFromOpenApi(specJson)
        for (const p of result.paths) candidates.add(p)
        for (const op of result.operations) {
          if (op.method !== "GET") writeCandidates.set(`${op.method} ${op.path}`, op.path)
        }
      }
    }

    // 3c. Cải thiện ④ — CRUD method-completion. Method-from-JS (①) is unreliable on MINIFIED SPAs:
    //     Angular declares the resource path as a class field (`host = server + "/api/Model"`) and
    //     the verb elsewhere (`this.http.post(this.host, …)`), so path & verb are decoupled. Instead
    //     we INFER the write surface from the resource path: any `/api/<Model>` collection found by
    //     the string-miner exposes, by the finale/Sequelize auto-REST convention, POST (create) on
    //     the collection and PUT/DELETE on `/{id}`. Deterministic, general to any RESTful backend —
    //     this is what turns "0 write endpoints" into the real write surface.
    for (const p of candidates) {
      if (!/^\/api\/[A-Za-z][A-Za-z0-9]*\/?$/.test(p)) continue
      const base = p.replace(/\/$/, "")
      writeCandidates.set(`POST ${base}`, base)
      writeCandidates.set(`PUT ${base}/1`, `${base}/1`)
      writeCandidates.set(`DELETE ${base}/1`, `${base}/1`)
    }

    // Cap the candidate set (bundles on a huge SPA can yield thousands).
    const capped = [...candidates].slice(0, MAX_CANDIDATES)
    log.info("route-extraction candidates", { sessionID, count: capped.length })

    // 4. Probe each; feed the live ones (non-404/5xx) back through ingest. The
    //    ingest handler dedups against already-captured requests, so routes the
    //    crawler already found here are no-ops — only genuinely new hidden
    //    endpoints spawn a test orchestration.
    let fed = 0
    for (const path of capped) {
      if (fed >= MAX_LIVE_FEEDS) break
      let probe = await safeFetch(origin + path)
      if (!probe) continue
      // 404 = doesn't exist; 5xx = server error, low signal. Everything else
      // (200/301/302/401/403) means the endpoint IS there and worth testing —
      // a 401/403 is itself an access-control test surface.
      if (probe.status === 404 || probe.status >= 500) continue
      // Authenticated re-probe: feed the REAL authenticated response for endpoints
      // gated behind login, so the analyzer extracts live object values (the IDOR /
      // business-logic substrate) instead of a 401 shell.
      if (authHeaders && (probe.status === 401 || probe.status === 403)) {
        const authProbe = await safeFetch(origin + path, "GET", { headers: authHeaders })
        if (authProbe && authProbe.status < 400) probe = authProbe
      }
      await feedCapture(ingestUrl, sessionID, host, scheme, path, probe)
      fed++
    }

    // 5. Cải thiện ① — probe the WRITE surface (POST/PUT/DELETE/PATCH mined from JS). Use OPTIONS
    //    (never mutates state) as a SAFE existence check; if the path is live, feed a synthetic
    //    capture with the REAL verb so the pipeline gives it a VRT checklist + its own orchestration
    //    (the per-class testers then exercise it under their non-destructive discipline). This is
    //    the single change that turns "0 write endpoints" into real write-surface coverage.
    let fedWrite = 0
    for (const [key, path] of writeCandidates) {
      if (fedWrite >= MAX_LIVE_FEEDS) break
      const method = key.slice(0, key.indexOf(" "))
      const probe = await safeFetch(origin + path, "OPTIONS")
      if (!probe || probe.status === 404) continue
      await feedCapture(ingestUrl, sessionID, host, scheme, path, probe, method)
      fedWrite++
    }

    log.info("route-extraction complete", {
      sessionID,
      target: origin,
      candidates: capped.length,
      fed,
      writeCandidates: writeCandidates.size,
      fedWrite,
    })
  }
}
