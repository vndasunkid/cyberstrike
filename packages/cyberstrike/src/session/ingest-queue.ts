import { Instance } from "@/project/instance"
import { Log } from "@/util/log"
import { SessionQueueStatus } from "./queue-status"

const log = Log.create({ service: "ingest-queue" })

export namespace IngestQueue {
  // Priority (plan_fix.md "nhanh → ra rộng → sâu"): the queue drains highest-value work FIRST so a
  // session that is cut short has already covered the important surface, and only goes deep once
  // breadth is done. Lower number = sooner. Fresh high-signal captures (0) beat plain page GETs
  // (1); deep re-tests (2) run only after all fresh work is drained. Within one priority: FIFO.
  export const Priority = { HIGH: 0, NORMAL: 1, DEEP: 2 } as const
  type Job = { task: () => Promise<unknown>; priority: number; seq: number }
  type State = {
    jobs: Job[] // pending, not yet started — drained by priority then FIFO
    running: boolean // a worker loop is currently draining this session
    paused: boolean
    pending: number
    seq: number // monotonic tiebreaker to keep same-priority jobs FIFO
    resumeSignal: Promise<void> | null
    resumeResolve: (() => void) | null
  }

  const state = Instance.state(() => {
    const data: Record<string, State> = {}
    return data
  })

  function getOrInit(sessionID: string): State {
    let s = state()[sessionID]
    if (!s) {
      s = {
        jobs: [],
        running: false,
        paused: false,
        pending: 0,
        seq: 0,
        resumeSignal: null,
        resumeResolve: null,
      }
      state()[sessionID] = s
    }
    return s
  }

  function publish(sessionID: string) {
    const s = state()[sessionID]
    SessionQueueStatus.set(sessionID, {
      paused: s?.paused ?? false,
      pending: s?.pending ?? 0,
    })
  }

  function maybeCleanup(sessionID: string) {
    const s = state()[sessionID]
    if (!s) return
    if (s.pending === 0 && !s.paused && !s.running && s.jobs.length === 0) {
      delete state()[sessionID]
    }
  }

  function waitIfPaused(sessionID: string): Promise<void> {
    const s = state()[sessionID]
    if (!s || !s.paused) return Promise.resolve()
    if (!s.resumeSignal) {
      s.resumeSignal = new Promise<void>((resolve) => {
        s.resumeResolve = resolve
      })
    }
    return s.resumeSignal
  }

  export function enqueue(sessionID: string, task: () => Promise<unknown>, priority: number = Priority.NORMAL) {
    const s = getOrInit(sessionID)
    s.pending++
    s.jobs.push({ task, priority, seq: s.seq++ })
    publish(sessionID)
    // Single serial worker per session (preserves the per-session serialization SessionPrompt
    // requires); idempotent — a second enqueue while draining just adds to the pending set.
    void drain(sessionID)
  }

  async function drain(sessionID: string) {
    const s = getOrInit(sessionID)
    if (s.running) return
    s.running = true
    try {
      while (true) {
        await waitIfPaused(sessionID)
        const cur = state()[sessionID]
        if (!cur || cur.jobs.length === 0) break
        // Highest priority first; FIFO within the same priority (stable via seq).
        cur.jobs.sort((a, b) => a.priority - b.priority || a.seq - b.seq)
        const job = cur.jobs.shift()!
        try {
          await job.task()
        } catch (err) {
          log.error("ingest prompt failed", { sessionID, error: err })
        }
        const after = state()[sessionID]
        if (after) after.pending = Math.max(0, after.pending - 1)
        publish(sessionID)
      }
    } finally {
      const cur = state()[sessionID]
      if (cur) cur.running = false
      publish(sessionID)
      maybeCleanup(sessionID)
    }
  }

  export function pause(sessionID: string) {
    const s = getOrInit(sessionID)
    if (s.paused) return
    s.paused = true
    publish(sessionID)
  }

  export function resume(sessionID: string) {
    const s = state()[sessionID]
    if (!s || !s.paused) return
    s.paused = false
    const resolve = s.resumeResolve
    s.resumeResolve = null
    s.resumeSignal = null
    if (resolve) resolve()
    publish(sessionID)
    maybeCleanup(sessionID)
  }

  export function pendingCount(sessionID: string): number {
    return state()[sessionID]?.pending ?? 0
  }

  export function isPaused(sessionID: string): boolean {
    return state()[sessionID]?.paused ?? false
  }
}
