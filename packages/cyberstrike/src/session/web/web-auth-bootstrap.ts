import path from "path"
import os from "os"
import { WebCredential } from "./web-credential"
import { WebRole } from "./web-role"
import { WebRetest } from "./web-retest"
import { RouteExtraction } from "../route-extraction"
import { Intel } from "../../methodology/intel"
import { Log } from "../../util/log"

/**
 * Deterministic authenticated-session bootstrap.
 *
 * The orchestrator is reactive (it processes captured requests one at a time) and does not
 * reliably call `web_login` on its own, so authenticated sessions never get established and
 * idor/authz lanes get skipped for lack of credentials. This module fixes that at the code
 * level: as soon as the first request for a target origin is ingested, it logs in with the
 * lab credentials from a config file and registers the resulting credential(s) — no dependence
 * on the agent choosing to log in.
 *
 * Config source (NOT the prompt): a JSON file of entries, resolved in this order:
 *   1. $CYBERSTRIKE_LAB_AUTH  (path)
 *   2. ~/.config/cyberstrike/lab-auth.json
 * Each entry:
 *   { "match": "192.168.5.144:3000", "login_url": "http://192.168.5.144:3000/rest/user/login",
 *     "body": {"email":"admin@juice-sh.op","password":"admin123"},
 *     "token_path": "authentication.token", "auth_header": "Authorization",
 *     "auth_format": "Bearer {token}", "label": "admin", "role": "admin" }
 */
export namespace WebAuthBootstrap {
  const log = Log.create({ service: "web-auth-bootstrap" })

  type Entry = {
    match?: string
    login_url: string
    method?: string
    body?: Record<string, unknown>
    headers?: Record<string, string>
    token_path?: string
    auth_header?: string
    auth_format?: string
    capture_cookies?: boolean
    label: string
    role?: string
    role_level?: number
  }

  // per-process guard so bootstrap runs once per (session, origin)
  const done = new Set<string>()

  function configPaths(): string[] {
    const out: string[] = []
    if (process.env.CYBERSTRIKE_LAB_AUTH) out.push(process.env.CYBERSTRIKE_LAB_AUTH)
    out.push(path.join(os.homedir(), ".config", "cyberstrike", "lab-auth.json"))
    return out
  }

  async function loadEntries(): Promise<Entry[]> {
    for (const p of configPaths()) {
      try {
        const f = Bun.file(p)
        if (!(await f.exists())) continue
        const data = JSON.parse(await f.text())
        if (Array.isArray(data)) return data as Entry[]
      } catch (e) {
        log.warn("failed to read lab-auth config", { path: p, error: String(e) })
      }
    }
    return []
  }

  function getPath(obj: unknown, dotted: string): unknown {
    return dotted.split(".").reduce<unknown>((acc, k) => {
      if (acc && typeof acc === "object" && k in (acc as Record<string, unknown>)) return (acc as Record<string, unknown>)[k]
      return undefined
    }, obj)
  }

  function originMatches(origin: string, match?: string): boolean {
    if (!match) return true
    const o = origin.toLowerCase()
    const m = match.toLowerCase()
    return o.includes(m) || m.includes(o.replace(/^https?:\/\//, ""))
  }

  async function performLogin(entry: Entry): Promise<Record<string, string> | undefined> {
    const method = (entry.method ?? "POST").toUpperCase()
    const reqHeaders: Record<string, string> = { "content-type": "application/json", ...(entry.headers ?? {}) }
    let res: Response
    try {
      res = await fetch(entry.login_url, {
        method,
        headers: reqHeaders,
        body: method === "GET" || method === "HEAD" ? undefined : JSON.stringify(entry.body ?? {}),
      })
    } catch (e) {
      log.warn("bootstrap login request failed", { url: entry.login_url, error: String(e) })
      return undefined
    }
    const text = await res.text()
    let json: unknown
    try {
      json = JSON.parse(text)
    } catch {
      /* non-JSON */
    }
    const headers: Record<string, string> = {}
    if (entry.token_path && json !== undefined) {
      const v = getPath(json, entry.token_path)
      if (typeof v === "string") {
        headers[entry.auth_header ?? "Authorization"] = (entry.auth_format ?? "Bearer {token}").replace("{token}", v)
      }
    }
    if (entry.capture_cookies !== false) {
      const anyHeaders = res.headers as unknown as { getSetCookie?: () => string[] }
      let cookies: string[] = typeof anyHeaders.getSetCookie === "function" ? anyHeaders.getSetCookie() : []
      if (cookies.length === 0) {
        const sc = res.headers.get("set-cookie")
        if (sc) cookies = [sc]
      }
      const pairs = cookies.map((c) => c.split(";")[0].trim()).filter(Boolean)
      if (pairs.length) headers["Cookie"] = pairs.join("; ")
    }
    if (Object.keys(headers).length === 0) {
      log.info("bootstrap login produced no credential (likely MFA/2FA or wrong creds)", {
        url: entry.login_url,
        label: entry.label,
        status: res.status,
      })
      return undefined
    }
    return headers
  }

  /** Run once per (session, origin): establish authenticated credentials from config. */
  export async function ensureBootstrap(sessionID: string, origin: string): Promise<void> {
    if (!sessionID || !origin) return
    const key = `${sessionID}|${origin}`
    if (done.has(key)) return
    done.add(key) // mark before await so concurrent ingests don't double-run

    const entries = (await loadEntries()).filter((e) => originMatches(origin, e.match))
    if (entries.length === 0) return

    // First established Bearer token → drives an authenticated route-extraction sweep
    // below (mines the login-gated surface the anon crawl never reaches).
    let bootstrapToken: string | undefined

    for (const entry of entries) {
      try {
        // skip if a credential with this label already exists for the session
        if (WebCredential.get(sessionID).some((c) => c.label === entry.label)) continue
        const headers = await performLogin(entry)
        if (!headers) continue

        if (!bootstrapToken) {
          const authv = headers[entry.auth_header ?? "Authorization"]
          if (typeof authv === "string") bootstrapToken = authv.replace(/^Bearer\s+/i, "").trim() || undefined
        }

        let roleID: string | undefined
        if (entry.role) {
          roleID = WebRole.add({ sessionID, name: entry.role, level: entry.role_level, discoveredFrom: "auto-bootstrap" }).id
        }
        const cred = WebCredential.add({ sessionID, label: entry.label, headers, roleID })

        try {
          WebRetest.checkTriggers({ sessionID, triggerType: "new_credential", triggerSource: cred.id })
        } catch {
          /* best-effort */
        }
        try {
          Intel.add({
            sessionID,
            data: {
              type: "credential",
              severity: "high",
              title: `Authenticated session (auto-bootstrap): ${entry.label}${entry.role ? ` (role ${entry.role})` : ""}`,
              detail: `Live session established at ${origin} from lab-auth config. Reuse for authenticated + cross-user (BOLA/IDOR/privilege-escalation) testing.`,
              asset: origin,
              source: "auto-bootstrap",
              confidenceLevel: "confirmed",
              tags: ["credential", "authenticated-session", entry.role ?? "user"],
              chainPotential:
                "Use this session to enumerate own objects, then chain BOLA / BOPLA / mass-assignment / business-logic.",
            },
          })
        } catch {
          /* best-effort */
        }
        log.info("auto-bootstrap credential established", { sessionID, label: entry.label, origin })
      } catch (e) {
        log.warn("auto-bootstrap entry failed", { label: entry.label, error: String(e) })
      }
    }

    // Deterministic surface discovery (TRẦN 1): mine JS bundles / OpenAPI / robots /
    // CRUD-inference and feed every live route into the SAME ingest pipeline — driven by
    // code, not by the agent choosing to crawl or call discover_endpoints. Runs with the
    // bootstrapped token so the login-gated business surface (baskets/orders/cards/wallet)
    // is discovered authenticated. Ingest dedups, so overlap with the post-crawl sweep is
    // a no-op. Fire-and-forget: never block or break ingest.
    try {
      void RouteExtraction.run({ sessionID, target: origin, token: bootstrapToken }).catch((err) =>
        log.warn("auto-bootstrap route-extraction failed", { sessionID, origin, error: String(err) }),
      )
    } catch (e) {
      log.warn("auto-bootstrap route-extraction dispatch failed", { sessionID, origin, error: String(e) })
    }
  }
}
