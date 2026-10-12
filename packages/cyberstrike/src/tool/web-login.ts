import z from "zod"
import { Tool } from "./tool"
import { WebCredential } from "../session/web/web-credential"
import { WebRole } from "../session/web/web-role"
import { WebRetest } from "../session/web/web-retest"
import { Intel } from "../methodology/intel"
import { Session } from "../session"

const description = `Authenticate to the target with known credentials and register the resulting session as a reusable web credential.

Use this to establish a REAL authenticated session once, so every proxy-tester and the retest queue can reuse the same live token/cookies for authenticated + cross-user (BOLA/IDOR) testing — instead of each lane logging in again.

Typical flow:
1. web_login({ login_url, body, token_path, label, role_name }) — logs in, extracts the token, stores it as a credential.
2. Register a second identity (e.g. a customer) the same way to enable cross-user comparisons.
3. Testers automatically receive these credentials (via session context + retest triggers).

Notes:
- Extracts a bearer token from the JSON response via token_path (dot notation, e.g. "authentication.token"), and/or captures Set-Cookie headers.
- Only for AUTHORIZED lab targets where the operator has supplied the credentials in the rules of engagement.
- Re-run when the token expires to refresh the stored credential (pass the same label to replace guidance is manual — a new credential row is created).`

function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc && typeof acc === "object" && key in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[key]
    }
    return undefined
  }, obj)
}

export const WebLoginTool = Tool.define("web_login", {
  description,
  parameters: z.object({
    login_url: z.string().describe("Absolute URL of the login endpoint, e.g. http://host:port/rest/user/login"),
    method: z.string().optional().describe("HTTP method (default POST)"),
    body: z
      .record(z.string(), z.any())
      .optional()
      .describe('JSON body sent to the login endpoint, e.g. {"email":"admin@x","password":"admin123"}'),
    headers: z.record(z.string(), z.string()).optional().describe("Extra request headers for the login call"),
    token_path: z
      .string()
      .optional()
      .describe('Dot path to the token in the JSON response, e.g. "authentication.token" or "token"'),
    auth_header: z.string().optional().describe("Header name to carry the token (default Authorization)"),
    auth_format: z.string().optional().describe('Token header format, {token} placeholder (default "Bearer {token}")'),
    capture_cookies: z.boolean().optional().describe("Capture Set-Cookie into a Cookie header (default true)"),
    label: z.string().describe("Label for the stored credential, e.g. admin / customer-demo"),
    role_name: z.string().optional().describe("Role to link this credential to (e.g. admin, customer)"),
    role_level: z.number().optional().describe("Role hierarchy level (higher = more privileged)"),
  }),
  async execute(params, ctx): Promise<{ title: string; output: string; metadata: { ok: boolean; status: number; credential_id?: string } }> {
    const sessionID = Session.root(ctx.sessionID)

    const url = params.login_url
    if (!/^https?:\/\//i.test(url)) {
      return { title: "Error: invalid login_url", output: "login_url must be an absolute http(s) URL", metadata: { ok: false, status: 0 } }
    }

    const method = (params.method ?? "POST").toUpperCase()
    const reqHeaders: Record<string, string> = { "content-type": "application/json", ...(params.headers ?? {}) }

    let res: Response
    try {
      res = await fetch(url, {
        method,
        headers: reqHeaders,
        body: method === "GET" || method === "HEAD" ? undefined : JSON.stringify(params.body ?? {}),
      })
    } catch (e) {
      return { title: "Error: login request failed", output: String(e), metadata: { ok: false, status: 0 } }
    }

    const rawText = await res.text()
    let json: unknown = undefined
    try {
      json = JSON.parse(rawText)
    } catch {
      /* non-JSON response */
    }

    const credHeaders: Record<string, string> = {}

    // 1) token from JSON
    let token: string | undefined
    if (params.token_path && json !== undefined) {
      const v = getPath(json, params.token_path)
      if (typeof v === "string") token = v
    }
    if (token) {
      const headerName = params.auth_header ?? "Authorization"
      const fmt = params.auth_format ?? "Bearer {token}"
      credHeaders[headerName] = fmt.replace("{token}", token)
    }

    // 2) cookies from Set-Cookie
    if (params.capture_cookies !== false) {
      let setCookies: string[] = []
      const anyHeaders = res.headers as unknown as { getSetCookie?: () => string[] }
      if (typeof anyHeaders.getSetCookie === "function") setCookies = anyHeaders.getSetCookie()
      else {
        const sc = res.headers.get("set-cookie")
        if (sc) setCookies = [sc]
      }
      const cookiePairs = setCookies.map((c) => c.split(";")[0].trim()).filter(Boolean)
      if (cookiePairs.length > 0) credHeaders["Cookie"] = cookiePairs.join("; ")
    }

    if (Object.keys(credHeaders).length === 0) {
      return {
        title: "Login produced no usable credential",
        output: `HTTP ${res.status}. No token found at token_path "${params.token_path ?? "(none)"}" and no Set-Cookie captured.\nResponse (first 400 chars):\n${rawText.slice(0, 400)}`,
        metadata: { ok: false, status: res.status },
      }
    }

    // Optional role
    let roleID: string | undefined
    if (params.role_name) {
      const role = WebRole.add({
        sessionID,
        name: params.role_name,
        level: params.role_level,
        discoveredFrom: "web_login",
      })
      roleID = role.id
    }

    // Durable session slot: if a credential with this label already exists, REFRESH it
    // in place (replace the stale/expired token) instead of piling up duplicate rows.
    // This makes web_login idempotent — call it again on a 401/expired token and the same
    // shared session is renewed for the whole pipeline (no churn of dead credentials).
    const prior = WebCredential.get(sessionID).find((c) => c.label === params.label)
    let cred
    let refreshed = false
    if (prior) {
      cred =
        WebCredential.update({ id: prior.id, sessionID, headers: credHeaders, roleID }) ??
        WebCredential.add({ sessionID, label: params.label, headers: credHeaders, roleID })
      refreshed = true
    } else {
      cred = WebCredential.add({ sessionID, label: params.label, headers: credHeaders, roleID })
    }

    // Chain logic — an authenticated session is now live. Drive it like a human would:
    // 1) fire the new_credential retest so every relevant endpoint is re-run WITH this session
    //    (this is the "logged in → now everything is authenticated" step; capped by MAX_RETEST_DEPTH).
    let retestsQueued = 0
    try {
      const retests = WebRetest.checkTriggers({
        sessionID,
        triggerType: "new_credential",
        triggerSource: cred.id,
      })
      retestsQueued = retests.length
    } catch {
      /* retest fan-out best-effort */
    }
    // 2) feed the chain engine so credential + authenticated endpoints = ATO / BOLA chains are detected.
    let asset = params.login_url
    try {
      asset = new URL(params.login_url).origin
    } catch {
      /* keep raw url */
    }
    try {
      Intel.add({
        sessionID,
        data: {
          type: "credential",
          severity: "high",
          title: `Authenticated session: ${params.label}${params.role_name ? ` (role ${params.role_name})` : ""}`,
          detail: `Live session established via web_login against ${params.login_url}. Reuse for authenticated + cross-user (BOLA/IDOR/privilege-escalation) testing.`,
          asset,
          source: "web_login",
          confidenceLevel: "confirmed",
          tags: ["credential", "authenticated-session", params.role_name ?? "user"],
          chainPotential:
            "Use this session to enumerate own objects, then chain: BOLA (swap to other users' IDs), BOPLA/mass-assignment (extra/role fields), and authenticated business-logic flows.",
        },
      })
    } catch {
      /* intel best-effort */
    }

    const out = {
      credential_id: cred.id,
      label: cred.label,
      login_status: res.status,
      headers_set: Object.keys(credHeaders),
      token_captured: !!token,
      cookies_captured: !!credHeaders["Cookie"],
      role: params.role_name ?? null,
      role_id: roleID ?? null,
      refreshed_existing: refreshed,
      retests_queued: retestsQueued,
    }
    return {
      title: `${refreshed ? "Refreshed" : "Logged in and registered"} credential "${cred.label}" (HTTP ${res.status}) — ${retestsQueued} authenticated retests queued`,
      output: JSON.stringify(out, null, 2),
      metadata: { ok: true, status: res.status, credential_id: cred.id },
    }
  },
})
