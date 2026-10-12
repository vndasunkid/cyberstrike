import { Database, eq, and, asc } from "../storage/db"
import { IntelEntryTable, VrtCheckTable } from "./methodology.sql"
import { Identifier } from "../id/id"
import { Phase } from "./phase"
import { Bus } from "../bus"
import { BusEvent } from "../bus/bus-event"
import z from "zod"

// ============================================================
// INTELLIGENCE SYSTEM — CRUD, VRT checklists, coverage,
// red flag detection, prompt formatting
// ============================================================

export namespace Intel {
  export const Type = z.enum([
    "endpoint",
    "subdomain",
    "technology",
    "credential",
    "parameter",
    "vulnerability_hint",
    "configuration",
    "api_schema",
    "authentication_flow",
    "business_rule",
    "sensitive_data",
    "infrastructure",
  ])
  export type Type = z.infer<typeof Type>

  export const Confidence = z.enum(["confirmed", "high", "medium", "low"])
  export type Confidence = z.infer<typeof Confidence>

  export const Severity = z.enum(["critical", "high", "medium", "low", "info"])
  export type Severity = z.infer<typeof Severity>

  export const EntryStatus = z.enum(["new", "investigating", "tested", "exploited", "reported"])
  export type EntryStatus = z.infer<typeof EntryStatus>

  export interface Entry {
    id: string
    sessionID: string
    type: Type
    severity?: string
    title: string
    detail?: string
    source?: string
    asset: string
    confidenceLevel?: Confidence
    tags: string[]
    chainPotential?: string
    relatedEntries: string[]
    status: EntryStatus
    position: number
    timeCreated: number
    timeUpdated: number
  }

  export const CONFIDENCE_WEIGHTS: Record<string, number> = {
    confirmed: 1.0,
    high: 0.8,
    medium: 0.5,
    low: 0.2,
  }

  export const Event = {
    Updated: BusEvent.define(
      "intel.updated",
      z.object({
        sessionID: z.string(),
        entryCount: z.number(),
      }),
    ),
  }

  // --- CRUD ---

  export function add(input: {
    sessionID: string
    data: {
      type: Type
      severity?: string
      title: string
      detail?: string
      source?: string
      asset: string
      confidenceLevel?: Confidence
      tags?: string[]
      chainPotential?: string
      relatedEntries?: string[]
      status?: EntryStatus
    }
  }): Entry & { duplicate: boolean; vrtChecksCreated: number } {
    // Dedup check
    const existing = findDuplicate(input.sessionID, input.data.title, input.data.asset)
    if (existing) return { ...existing, duplicate: true, vrtChecksCreated: 0 }

    const id = Identifier.ascending("intel_entry")
    const now = Date.now()
    const tags = input.data.tags ?? []
    const relatedEntries = input.data.relatedEntries ?? []

    const position = Database.use((db) => {
      const rows = db
        .select({ position: IntelEntryTable.position })
        .from(IntelEntryTable)
        .where(eq(IntelEntryTable.session_id, input.sessionID))
        .all()
      return rows.length === 0 ? 0 : Math.max(...rows.map((r) => r.position)) + 1
    })

    Database.use((db) => {
      db.insert(IntelEntryTable)
        .values({
          id,
          session_id: input.sessionID,
          type: input.data.type,
          severity: input.data.severity ?? null,
          title: input.data.title,
          detail: input.data.detail ?? null,
          source: input.data.source ?? null,
          asset: input.data.asset,
          confidence_level: input.data.confidenceLevel ?? "low",
          tags: tags as any,
          chain_potential: input.data.chainPotential ?? null,
          related_entries: relatedEntries as any,
          status: input.data.status ?? "new",
          position,
          time_created: now,
          time_updated: now,
        })
        .run()
    })

    // Auto-generate VRT checklist (applicability-filtered by asset — Bước 4)
    const vrtChecks = generateVrtChecklist(input.data.type, input.data.asset)
    for (const check of vrtChecks) {
      Database.use((db) => {
        db.insert(VrtCheckTable)
          .values({
            id: Identifier.ascending("vrt_check"),
            session_id: input.sessionID,
            intel_entry_id: id,
            vrt_category: check.category,
            vrt_path: check.path,
            status: "pending",
            time_created: now,
            time_updated: now,
          })
          .run()
      })
    }

    const entry: Entry = {
      id,
      sessionID: input.sessionID,
      type: input.data.type,
      severity: input.data.severity,
      title: input.data.title,
      detail: input.data.detail,
      source: input.data.source,
      asset: input.data.asset,
      confidenceLevel: input.data.confidenceLevel ?? "low",
      tags,
      chainPotential: input.data.chainPotential,
      relatedEntries,
      status: input.data.status ?? "new",
      position,
      timeCreated: now,
      timeUpdated: now,
    }

    Database.effect(() => {
      const count = get(input.sessionID).length
      Bus.publish(Event.Updated, { sessionID: input.sessionID, entryCount: count })
    })

    return { ...entry, duplicate: false, vrtChecksCreated: vrtChecks.length }
  }

  export function update(
    sessionID: string,
    entryID: string,
    updates: Partial<{
      severity: string
      title: string
      detail: string
      confidenceLevel: Confidence
      tags: string[]
      chainPotential: string
      relatedEntries: string[]
      status: EntryStatus
    }>,
  ): void {
    Database.use((db) => {
      const values: Record<string, any> = { time_updated: Date.now() }
      if (updates.severity !== undefined) values.severity = updates.severity
      if (updates.title !== undefined) values.title = updates.title
      if (updates.detail !== undefined) values.detail = updates.detail
      if (updates.confidenceLevel !== undefined) values.confidence_level = updates.confidenceLevel
      if (updates.tags !== undefined) values.tags = updates.tags
      if (updates.chainPotential !== undefined) values.chain_potential = updates.chainPotential
      if (updates.relatedEntries !== undefined) values.related_entries = updates.relatedEntries
      if (updates.status !== undefined) values.status = updates.status

      db.update(IntelEntryTable)
        .set(values)
        .where(and(eq(IntelEntryTable.id, entryID), eq(IntelEntryTable.session_id, sessionID)))
        .run()
    })
  }

  export function get(sessionID: string): Entry[] {
    const rows = Database.use((db) =>
      db
        .select()
        .from(IntelEntryTable)
        .where(eq(IntelEntryTable.session_id, sessionID))
        .orderBy(asc(IntelEntryTable.position))
        .all(),
    )
    return rows.map(rowToEntry)
  }

  export function getByAsset(sessionID: string, asset: string): Entry[] {
    const normalized = asset.toLowerCase().trim()
    return get(sessionID).filter((e) => e.asset.toLowerCase().trim() === normalized)
  }

  function findDuplicate(sessionID: string, title: string, asset: string): Entry | undefined {
    const normalized = title.toLowerCase().trim()
    const normalizedAsset = asset.toLowerCase().trim()
    return get(sessionID).find(
      (e) => e.title.toLowerCase().trim() === normalized && e.asset.toLowerCase().trim() === normalizedAsset,
    )
  }

  function rowToEntry(row: typeof IntelEntryTable.$inferSelect): Entry {
    return {
      id: row.id,
      sessionID: row.session_id,
      type: row.type as Type,
      severity: row.severity ?? undefined,
      title: row.title,
      detail: row.detail ?? undefined,
      source: row.source ?? undefined,
      asset: row.asset,
      confidenceLevel: (row.confidence_level as Confidence) ?? undefined,
      tags: (row.tags as string[]) ?? [],
      chainPotential: row.chain_potential ?? undefined,
      relatedEntries: (row.related_entries as string[]) ?? [],
      status: (row.status as EntryStatus) ?? "new",
      position: row.position,
      timeCreated: row.time_created,
      timeUpdated: row.time_updated,
    }
  }

  // --- VRT Checklist ---

  // Bước 4 (plan_fix.md): applicability filter. A static asset (.js/.css/.png/...) serves a fixed
  // file — it cannot carry a server-side injection in its response, so generating SQLi/XSS/SSTI/
  // cmd/SSRF/XXE checks for it is wasted testing + coverage noise (a proxy-tester runs a full
  // payload matrix only to close each as not_applicable). Access-control / info-disclosure checks
  // still apply (a static file can leak data or be mis-scoped), so those are kept.
  const INJECTION_CATEGORIES = new Set(["SQLi", "XSS", "SSTI", "Command Injection", "SSRF", "XXE", "NoSQLi"])
  const STATIC_ASSET_RE = /\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webmanifest|mp4|webp)(\?|#|$)/i

  // Gói 0 (ke_hoach_70.md): suy attack-class TỔNG QUÁT từ HÌNH DẠNG path (không phải tên target).
  // Một endpoint mang dấu hiệu shape dưới đây được cấp THÊM lớp lỗi tương ứng, để tester bị CỬ đi
  // đúng chỗ thay vì improvise/bỏ sót. Chỉ dùng category đã được taxonomy + dispatch công nhận.
  const SHAPE_RULES: Array<{ re: RegExp; cats: Array<{ category: string; path: string }> }> = [
    {
      re: /(search|query|filter|lookup|[?&]q=)/i,
      cats: [
        { category: "SQLi", path: "Injection > SQL Injection > Search Parameter" },
        { category: "NoSQLi", path: "Injection > NoSQL Injection > Search Operator" },
        { category: "XSS", path: "Cross-Site Scripting > Reflected > Search Parameter" },
      ],
    },
    {
      re: /(login|signin|sign-in|auth|token|session|reset|password|passwd|2fa|otp|verify)/i,
      cats: [
        { category: "Auth Bypass", path: "Authentication > Authentication Bypass > Credential Field" },
        { category: "SQLi", path: "Injection > SQL Injection > Login Field" },
        { category: "NoSQLi", path: "Injection > NoSQL Injection > Auth Operator" },
      ],
    },
    {
      re: /(admin|manage|internal|metrics|debug|actuator|console|dashboard)/i,
      cats: [
        { category: "Privilege Escalation", path: "Broken Access Control > Privilege Escalation > Admin Function" },
        { category: "Auth Bypass", path: "Authentication > Forced Browsing > Restricted Path" },
      ],
    },
    {
      re: /(file|upload|download|attachment|ftp|report|export|backup|blueprint|document|image|photo|avatar|profile)/i,
      cats: [
        { category: "File Attacks", path: "File Attacks > Path Traversal > Restricted File Read" },
        { category: "Info Disclosure", path: "Information Disclosure > Sensitive File Exposure" },
      ],
    },
    {
      re: /(redirect|url=|returnto|return_to|next=|callback|continue|dest=|target=)/i,
      cats: [
        { category: "Open Redirect", path: "Broken Access Control > Open Redirect > URL Parameter" },
        { category: "SSRF", path: "Server-Side Request Forgery > URL Parameter" },
      ],
    },
    {
      re: /\/(\d+|\{?id\}?|:id|[0-9a-f]{8}-[0-9a-f]{4})(\/|$|\?)/i,
      cats: [
        { category: "IDOR", path: "Broken Access Control > IDOR > Object Reference" },
        { category: "NoSQLi", path: "Injection > NoSQL Injection > ID Operator" },
      ],
    },
  ]

  function shapeCategories(asset?: string): Array<{ category: string; path: string }> {
    if (!asset) return []
    const out: Array<{ category: string; path: string }> = []
    for (const rule of SHAPE_RULES) if (rule.re.test(asset)) out.push(...rule.cats)
    return out
  }

  export function generateVrtChecklist(entryType: Type, asset?: string): Array<{ category: string; path: string }> {
    const base = Phase.VRT_CATEGORIES_BY_TYPE[entryType] ?? []
    // Merge base + shape-derived, dedupe by category (first path wins) to avoid check explosion.
    const merged: Array<{ category: string; path: string }> = []
    const seen = new Set<string>()
    for (const c of [...base, ...shapeCategories(asset)]) {
      if (seen.has(c.category)) continue
      seen.add(c.category)
      merged.push(c)
    }
    if (asset && STATIC_ASSET_RE.test(asset)) return merged.filter((c) => !INJECTION_CATEGORIES.has(c.category))
    return merged
  }

  export function getVrtChecks(
    sessionID: string,
    entryID?: string,
  ): Array<{
    id: string
    entryID: string
    category: string
    path?: string
    status: string
    technique?: string
    techniquesAttempted: string[]
    justification?: string
    testedBy?: string
    evidence?: Record<string, unknown>
  }> {
    const rows = Database.use((db) => {
      const query = entryID
        ? db
            .select()
            .from(VrtCheckTable)
            .where(and(eq(VrtCheckTable.session_id, sessionID), eq(VrtCheckTable.intel_entry_id, entryID)))
        : db.select().from(VrtCheckTable).where(eq(VrtCheckTable.session_id, sessionID))
      return query.all()
    })
    return rows.map((r) => ({
      id: r.id,
      entryID: r.intel_entry_id,
      category: r.vrt_category,
      path: r.vrt_path ?? undefined,
      status: r.status,
      technique: r.technique ?? undefined,
      techniquesAttempted: (r.techniques_attempted as string[] | null) ?? [],
      justification: r.single_technique_justification ?? undefined,
      testedBy: r.tested_by ?? undefined,
      evidence: (r.evidence as Record<string, unknown>) ?? undefined,
    }))
  }

  /** Single-row lookup used by Gate 1 (vrt-check.ts) to read the accumulated
   *  technique list before deciding whether a close is allowed. */
  export function getVrtCheck(sessionID: string, entryID: string, category: string) {
    return getVrtChecks(sessionID, entryID).find((c) => c.category === category)
  }

  export function updateVrtCheck(
    sessionID: string,
    entryID: string,
    category: string,
    update: {
      status: "pending" | "tested_vulnerable" | "tested_not_vulnerable" | "not_applicable"
      technique?: string
      techniquesAttempted?: string[]
      justification?: string
      testedBy?: string
      evidence?: Record<string, unknown>
    },
  ): void {
    Database.use((db) => {
      const existing = db
        .select()
        .from(VrtCheckTable)
        .where(
          and(
            eq(VrtCheckTable.session_id, sessionID),
            eq(VrtCheckTable.intel_entry_id, entryID),
            eq(VrtCheckTable.vrt_category, category),
          ),
        )
        .get()

      const now = Date.now()
      if (existing) {
        db.update(VrtCheckTable)
          .set({
            status: update.status,
            technique: update.technique ?? existing.technique,
            techniques_attempted: update.techniquesAttempted ?? (existing.techniques_attempted as string[] | null),
            single_technique_justification: update.justification ?? existing.single_technique_justification,
            tested_by: update.testedBy ?? existing.tested_by,
            tested_at: now,
            evidence: (update.evidence as any) ?? existing.evidence,
            time_updated: now,
          })
          .where(eq(VrtCheckTable.id, existing.id))
          .run()
      } else {
        db.insert(VrtCheckTable)
          .values({
            id: Identifier.ascending("vrt_check"),
            session_id: sessionID,
            intel_entry_id: entryID,
            vrt_category: category,
            status: update.status,
            technique: update.technique ?? null,
            techniques_attempted: update.techniquesAttempted ?? null,
            single_technique_justification: update.justification ?? null,
            tested_by: update.testedBy ?? null,
            tested_at: now,
            evidence: (update.evidence as any) ?? null,
            time_created: now,
            time_updated: now,
          })
          .run()
      }
    })
  }

  // --- Coverage ---

  export interface CoverageReport {
    totalEntries: number
    entriesWithChecklist: number
    totalChecks: number
    completedChecks: number
    pendingChecks: number
    vulnerableChecks: number
    coveragePercent: number
    weightedCoveragePercent: number
    redFlags: RedFlag[]
    untestedItems: UntestedItem[]
  }

  export interface RedFlag {
    type: string
    severity: "critical" | "warning"
    message: string
    affectedEntries: string[]
  }

  export interface UntestedItem {
    entryID: string
    entryTitle: string
    vrtCategory: string
    asset: string
    // Distinct techniques already logged for this check (Gate 1, plan_A1.md
    // §4.3). 0 = never touched; >=1 = Gate 1 is holding it open pending a
    // second distinct technique (or a justification) — cheaper to finish
    // than to start a fresh untested item, so directives should prioritize it.
    techniquesAttempted: number
  }

  export function computeCoverage(sessionID: string): CoverageReport {
    const entries = get(sessionID)
    const allChecks = getVrtChecks(sessionID)

    const entriesWithChecklist = new Set(allChecks.map((c) => c.entryID)).size
    const completed = allChecks.filter((c) => c.status !== "pending")
    const pending = allChecks.filter((c) => c.status === "pending")
    const vulnerable = allChecks.filter((c) => c.status === "tested_vulnerable")
    const coveragePercent = allChecks.length > 0 ? Math.round((completed.length / allChecks.length) * 100) : 0

    // Weighted coverage
    const entryMap = new Map(entries.map((e) => [e.id, e]))
    let totalWeight = 0
    let weightedComplete = 0
    for (const check of allChecks) {
      const entry = entryMap.get(check.entryID)
      const weight = CONFIDENCE_WEIGHTS[entry?.confidenceLevel ?? "low"] ?? 0.2
      totalWeight += weight
      if (check.status !== "pending") weightedComplete += weight
    }
    const weightedCoveragePercent = totalWeight > 0 ? Math.round((weightedComplete / totalWeight) * 100) : 0

    const redFlags = detectRedFlags(entries, allChecks)
    const untestedItems = pending
      .map((c) => {
        const entry = entryMap.get(c.entryID)
        return {
          entryID: c.entryID,
          entryTitle: entry?.title ?? "unknown",
          vrtCategory: c.category,
          asset: entry?.asset ?? "unknown",
          techniquesAttempted: c.techniquesAttempted.length,
        }
      })
      // Items Gate 1 is holding open (1 technique already logged) surface
      // first — one more technique closes them, cheaper than starting fresh.
      .sort((a, b) => b.techniquesAttempted - a.techniquesAttempted)

    return {
      totalEntries: entries.length,
      entriesWithChecklist,
      totalChecks: allChecks.length,
      completedChecks: completed.length,
      pendingChecks: pending.length,
      vulnerableChecks: vulnerable.length,
      coveragePercent,
      weightedCoveragePercent,
      redFlags,
      untestedItems,
    }
  }

  function detectRedFlags(entries: Entry[], checks: ReturnType<typeof getVrtChecks>): RedFlag[] {
    const flags: RedFlag[] = []
    const entryCheckMap = new Map<string, typeof checks>()
    for (const check of checks) {
      if (!entryCheckMap.has(check.entryID)) entryCheckMap.set(check.entryID, [])
      entryCheckMap.get(check.entryID)!.push(check)
    }

    // 1. no_evidence: tested_not_vulnerable without evidence
    const noEvidence: string[] = []
    for (const [entryID, entryChecks] of entryCheckMap) {
      for (const check of entryChecks) {
        if (check.status === "tested_not_vulnerable" && (!check.evidence || !Object.keys(check.evidence).length)) {
          noEvidence.push(entryID)
          break
        }
      }
    }
    if (noEvidence.length > 0) {
      flags.push({
        type: "no_evidence",
        severity: "critical",
        message: `${noEvidence.length} entries marked "tested_not_vulnerable" without evidence`,
        affectedEntries: noEvidence,
      })
    }

    // 2. bulk_copy_paste: identical reasoning across 5+ checks
    const reasonings = new Map<string, string[]>()
    for (const check of checks) {
      const reasoning = (check.evidence as any)?.reasoning
      if (!reasoning) continue
      const key = String(reasoning).trim().toLowerCase()
      if (!reasonings.has(key)) reasonings.set(key, [])
      reasonings.get(key)!.push(check.entryID)
    }
    for (const [, entryIds] of reasonings) {
      const unique = [...new Set(entryIds)]
      if (unique.length >= 5) {
        flags.push({
          type: "bulk_copy_paste",
          severity: "warning",
          message: `${unique.length} entries have identical reasoning text — possible copy-paste`,
          affectedEntries: unique,
        })
        break
      }
    }

    // 3. too_fast: many checks but very few HTTP requests
    let totalRequests = 0
    let totalCompleted = 0
    for (const check of checks) {
      if (check.status !== "pending") {
        totalCompleted++
        totalRequests += Number((check.evidence as any)?.requestCount ?? 0)
      }
    }
    if (totalCompleted >= 10 && totalRequests < 5) {
      flags.push({
        type: "too_fast",
        severity: "warning",
        message: `${totalCompleted} checks completed but only ${totalRequests} total HTTP requests — suspicious`,
        affectedEntries: entries.map((e) => e.id),
      })
    }

    // 4. all_not_applicable: >60% checks are N/A
    const naCount = checks.filter((c) => c.status === "not_applicable").length
    if (checks.length > 0 && naCount / checks.length > 0.6) {
      flags.push({
        type: "all_not_applicable",
        severity: "warning",
        message: `${Math.round((naCount / checks.length) * 100)}% of checks marked "not_applicable" — agent may be avoiding work`,
        affectedEntries: entries.map((e) => e.id),
      })
    }

    return flags
  }

  // --- Per-Asset Coverage ---

  export interface AssetCoverage {
    asset: string
    totalEntries: number
    totalChecks: number
    completedChecks: number
    pendingChecks: number
    vulnerableChecks: number
    coveragePercent: number
  }

  export function computePerAssetCoverage(sessionID: string): AssetCoverage[] {
    const entries = get(sessionID)
    const allChecks = getVrtChecks(sessionID)

    const assetMap = new Map<string, { entries: Entry[]; checks: ReturnType<typeof getVrtChecks> }>()
    for (const entry of entries) {
      const asset = entry.asset.toLowerCase().trim()
      if (!assetMap.has(asset)) assetMap.set(asset, { entries: [], checks: [] })
      assetMap.get(asset)!.entries.push(entry)
    }

    const entryToAsset = new Map<string, string>()
    for (const entry of entries) {
      entryToAsset.set(entry.id, entry.asset.toLowerCase().trim())
    }
    for (const check of allChecks) {
      const asset = entryToAsset.get(check.entryID)
      if (asset && assetMap.has(asset)) assetMap.get(asset)!.checks.push(check)
    }

    const results: AssetCoverage[] = []
    for (const [asset, data] of assetMap) {
      const completed = data.checks.filter((c) => c.status !== "pending")
      const pending = data.checks.filter((c) => c.status === "pending")
      const vulnerable = data.checks.filter((c) => c.status === "tested_vulnerable")
      results.push({
        asset,
        totalEntries: data.entries.length,
        totalChecks: data.checks.length,
        completedChecks: completed.length,
        pendingChecks: pending.length,
        vulnerableChecks: vulnerable.length,
        coveragePercent: data.checks.length > 0 ? Math.round((completed.length / data.checks.length) * 100) : 0,
      })
    }

    return results.sort((a, b) => a.coveragePercent - b.coveragePercent)
  }

  // --- Prompt Formatting ---

  export function formatCoverageForPrompt(coverage: CoverageReport): string {
    const lines: string[] = [
      "## Intelligence Coverage Report",
      `- Total entries: ${coverage.totalEntries} (${coverage.entriesWithChecklist} with VRT checklists)`,
      `- VRT checks: ${coverage.totalChecks} total, ${coverage.completedChecks} completed, ${coverage.pendingChecks} pending`,
      `- Vulnerable: ${coverage.vulnerableChecks}`,
      `- Coverage: ${coverage.coveragePercent}%`,
      `- Weighted Coverage: ${coverage.weightedCoveragePercent}% (confidence-adjusted)`,
    ]

    if (coverage.redFlags.length > 0) {
      lines.push("")
      lines.push("### RED FLAGS:")
      for (const flag of coverage.redFlags) {
        lines.push(`- [${flag.severity.toUpperCase()}] ${flag.message}`)
      }
    }

    if (coverage.untestedItems.length > 0) {
      lines.push("")
      lines.push("### Untested (top 10):")
      for (const item of coverage.untestedItems.slice(0, 10)) {
        const note = item.techniquesAttempted >= 1 ? ` [1 technique tried — needs 1 more to close]` : ""
        lines.push(`- ${item.entryID}: ${item.entryTitle} -> ${item.vrtCategory} (${item.asset})${note}`)
      }
    }

    return lines.join("\n")
  }
}
