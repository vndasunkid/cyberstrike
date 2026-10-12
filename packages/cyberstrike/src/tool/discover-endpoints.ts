import z from "zod"
import { Tool } from "./tool"
import { RouteExtraction } from "../session/route-extraction"
import { Intel } from "../methodology/intel"
import { Session } from "../session"
import { AutoDispatch } from "../session/auto-dispatch"
import { AutoScanner } from "../session/auto-scanner"

// Cap on how many discovered endpoints are registered as coverage-tracked intel
// entries. Each endpoint entry auto-generates a VRT checklist, so this bounds the
// total check count (and thus run length) while still forcing the agent to work the
// real surface instead of a small self-selected set.
const MAX_REGISTER = 60

// Recon-ONLY endpoint enumeration (16-9-2026.md). Lets an operator prompt "recon this target and
// list the endpoints" and STOP at recon — no exploitation, no multi-hour test pipeline. Mines the
// app's own JS bundles (paths + verbs), OpenAPI/sitemap/robots, and infers the REST CRUD write
// surface, then probes each (GET + a SAFE OPTIONS for writes — never mutates state). Deterministic,
// seconds, zero LLM. Cải thiện ②: optionally AUTHENTICATED — pass a Bearer token, or email+password
// +login_path to log in by code (HTTP only, no browser) so the login-flow surface is enumerated too.
// Distinct from the automatic post-crawl route-extraction which FEEDS the test pipeline; this
// returns the inventory to the caller and does nothing else.
export const DiscoverEndpointsTool = Tool.define("discover_endpoints", {
  description:
    "Endpoint discovery + surface coverage registration. Enumerates a web target's endpoint surface — GET routes plus the WRITE surface (POST/PUT/DELETE) — by mining JS bundles, OpenAPI/Swagger, sitemap and robots, and inferring REST CRUD endpoints, then probing each (writes checked with a safe OPTIONS request that never mutates state). Does NOT run exploitation. It REGISTERS each discovered live endpoint as a coverage-tracked item, so the assessment's completion gate measures tested-vs-discovered surface and will not pass while real endpoints remain untested (an endpoint with nothing to find is closed cheaply with a coverage note). Optionally AUTHENTICATED: pass `token` (a Bearer JWT), or `email`+`password`+`login_path` to log in by code (plain HTTP, no browser) — each endpoint is then probed both anonymously and with the token, so endpoints that are 401 anonymously but reachable when authenticated are flagged as the login-flow surface. Call this EARLY to seed the full surface, then test it. Fast (seconds), deterministic.",
  parameters: z.object({
    target: z.string().describe("Target base URL, e.g. http://192.168.5.144:3000"),
    token: z.string().optional().describe("Optional Bearer JWT to probe the authenticated surface (no browser needed)"),
    email: z
      .string()
      .optional()
      .describe("Optional login email — with password+login_path, logs in by code to get a token"),
    password: z.string().optional().describe("Optional login password (used with email + login_path)"),
    login_path: z
      .string()
      .optional()
      .describe("Optional login endpoint path, e.g. /rest/user/login — POSTed {email,password} to obtain a token"),
  }),
  async execute(params, ctx) {
    const r = await RouteExtraction.discover({
      target: params.target,
      token: params.token,
      email: params.email,
      password: params.password,
      loginPath: params.login_path,
    })
    if (!r) {
      return {
        title: `discover_endpoints: invalid URL`,
        output: `Invalid target URL: ${params.target}`,
        metadata: { gets: 0, writes: 0, authOnly: 0, authenticated: false, registered: 0 },
      }
    }
    const authOnly = r.gets.filter((g) => g.authOnly)

    // Register the discovered surface for COVERAGE TRACKING. Each endpoint becomes an
    // `endpoint` intel entry (auto-generating its VRT checklist), so the completion gate
    // measures tested-vs-discovered SURFACE — not a small self-selected checklist. This
    // is what stops the agent declaring "done" while real endpoints remain untested
    // (the per-asset coverage gate cannot pass until the discovered surface is worked;
    // an endpoint with nothing to find is closed cheaply with a coverage note). Priority:
    // write surface + authenticated-only first (highest value), then the rest of the GETs.
    let registered = 0
    try {
      const sessionID = Session.root(ctx.sessionID)
      const seen = new Set<string>()
      const toRegister: Array<{ method: string; path: string; status: number; note: string }> = [
        ...r.writes.map((w) => ({ method: w.method, path: w.path, status: w.status, note: "write surface" })),
        ...authOnly.map((g) => ({
          method: "GET",
          path: g.path,
          status: g.statusAuth ?? g.statusAnon,
          note: `authenticated-only (anon ${g.statusAnon} → auth ${g.statusAuth})`,
        })),
        ...r.gets
          .filter((g) => !g.authOnly)
          .map((g) => ({ method: "GET", path: g.path, status: g.statusAnon, note: "GET surface" })),
      ]
      for (const e of toRegister) {
        if (registered >= MAX_REGISTER) break
        const key = `${e.method} ${e.path}`
        if (seen.has(key)) continue
        seen.add(key)
        const res = Intel.add({
          sessionID,
          data: {
            type: "endpoint",
            severity: "info",
            title: `Endpoint ${key}`,
            detail: `Discovered live endpoint (${e.note}) [status ${e.status}] on ${r.origin}. Test this endpoint for its applicable vulnerability classes; if nothing is found, close its checks with a coverage note.`,
            asset: r.origin,
            source: "discover_endpoints",
            confidenceLevel: "confirmed",
            tags: ["endpoint", "surface", e.method.toLowerCase()],
          },
        })
        if (!res.duplicate) registered++
      }
    } catch (err) {
      // best-effort: surface registration must never break recon output
      void err
    }

    // Auto-dispatch proxy-tester subagents for the discovered surface. Runs once
    // per root session (guarded). Fire-and-forget: the subagents run in background,
    // report_vulnerability and update_vrt_check feed coverage back to the root.
    try {
      const rootID = Session.root(ctx.sessionID)
      const parentSession = await Session.get(rootID).catch(() => null)
      const isRoot = !parentSession?.parentID
      if (isRoot && registered > 0) {
        const endpoints = [
          ...r.writes.map((w) => ({ method: w.method, path: w.path })),
          ...r.gets.map((g) => ({ method: "GET", path: g.path })),
        ]
        void AutoDispatch.run({ sessionID: rootID, target: r.origin, endpoints }).catch(() => {})
        void AutoScanner.run({
          sessionID: rootID,
          target: r.origin,
          endpoints,
          openApiOps: r.openApiOps,
          filenames: r.filenames,
          token: r.token,
        }).catch(() => {})
      }
    } catch {
      // best-effort
    }

    const lines: string[] = [
      `# Recon — ${r.origin}${r.authenticated ? " (authenticated)" : " (anonymous)"}`,
      "",
      `**${r.gets.length} GET + ${r.writes.length} write = ${r.gets.length + r.writes.length} live endpoints**` +
        (r.authenticated ? ` · ${authOnly.length} authenticated-only (login-flow)` : ""),
    ]
    if (!r.authenticated) {
      lines.push(
        "",
        "_No token — anonymous only. Pass `token`, or `email`+`password`+`login_path`, to also map the authenticated surface._",
      )
    }
    lines.push("", `## WRITE surface (POST/PUT/DELETE) — ${r.writes.length}`)
    if (r.writes.length === 0) lines.push("_(none discovered)_")
    for (const w of [...r.writes].sort((a, b) => a.path.localeCompare(b.path))) {
      lines.push(`- \`${w.method} ${w.path}\` [${w.status}]`)
    }
    if (authOnly.length > 0) {
      lines.push("", `## AUTHENTICATED-ONLY surface (401 anon → reachable authed) — ${authOnly.length}`)
      for (const g of [...authOnly].sort((a, b) => a.path.localeCompare(b.path))) {
        lines.push(`- \`GET ${g.path}\` [anon ${g.statusAnon} → auth ${g.statusAuth}]`)
      }
    }
    lines.push("", `## GET surface — ${r.gets.length}`)
    for (const g of [...r.gets].sort((a, b) => a.path.localeCompare(b.path))) {
      const auth = g.statusAuth !== undefined ? ` / auth ${g.statusAuth}` : ""
      lines.push(`- \`GET ${g.path}\` [anon ${g.statusAnon}${auth}]`)
    }
    lines.push(
      "",
      `_Registered ${registered} endpoint(s) for coverage tracking — the assessment is not complete until the discovered surface is tested (or closed with a coverage note)._`,
    )
    return {
      title: `Recon ${r.origin}: ${r.gets.length + r.writes.length} endpoints (${r.writes.length} write${r.authenticated ? `, ${authOnly.length} auth-only` : ""}) · ${registered} tracked`,
      output: lines.join("\n"),
      metadata: {
        gets: r.gets.length,
        writes: r.writes.length,
        authOnly: authOnly.length,
        authenticated: r.authenticated,
        registered,
      },
    }
  },
})
