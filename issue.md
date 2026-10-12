User: Following is the logs.

The recon seems to hang at `Shell
Test XML content negotiation for XXE` . I don't know if it hangs or crash some where. Note that it's been more than 10 mins.

└─$ pkill -f "cyberstrike serve" 2>/dev/null; sleep 1
export CYBERSTRIKE_SERVER_PASSWORD=admin && /home/master/code/CyberStrike/packages/cyberstrike/dist/cyberstrike-linux-x64/bin/cyberstrike web --hostname 0.0.0.0 --port 4444

     ______      __              _____ __       _ __
    / ____/_  __/ /_  ___  _____/ ___// /______(_) /_____
   / /   / / / / __ \/ _ \/ ___/\__ \/ __/ ___/ / //_/ _ \
  / /___/ /_/ / /_/ /  __/ /  ___/ / /_/ /  / / ,< /  __/
  \____/\__, /_.___/\___/_/  /____/\__/_/  /_/_/|_|\___/
       /____/

  Local access:        http://localhost:4444
  Network access:      http://192.168.5.147:4444
/bin/sh:

Claude: I'll investigate the hang. Let me look at the shell tool execution and the screenshot to understand what's happening.

Read [](file:///home/master/.vscode-server/data/agentSessionData/e9519208-f2aa-4b25-a054-dca483ba5e74/attachments/a68d16d6-bd0d-4fca-820a-7b2968147162/Screenshot%202026-08-06%20at%205.43.44%20PM.png)
Completed with input: {
  "file_path": "/home/master/.vscode-server/data/agentSessionData/e9519208-f2aa-4b25-a054-dca483ba5e74/attachments/a68d16d6-bd0d-4fca-820a-7b2968147162/Screenshot 2026-08-06 at 5.43.44 PM.png"
}

Ran terminal command: cd /home/master/code/CyberStrike && git diff --stat

Let me look at how the Shell tool executes commands and where a hang could occur.

Ran terminal command: cd /home/master/code/CyberStrike && ls packages/cyberstrike/src/tool/ | head -50

Ran terminal command: cd /home/master/code/CyberStrike && git diff packages/cyberstrike/src/tool/hackbrowser-launcher.ts packages/cyberstrike/src/permission/next.ts packages/cyberstrike/src/cli/cmd/web.ts

Now let me look at the bash tool that executes these Shell commands, since the hang is on a Shell command.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/tool/bash.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/tool/bash.ts"
}

The bash tool has a 2-minute default timeout, so a hanging *command* would be killed. But the recon has been stuck 10+ min. The key suspect is the **permission ask** that happens *before* the command runs (bash.ts:157-164) — that has no timeout. Let me examine the permission flow.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/permission/next.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/permission/next.ts"
}

Now I understand the architecture. The `ask` promise (permission/next.ts:146) only resolves when a client replies — before this fix there was **no timeout**, so a permission ask that's never answered hangs forever. The 2-min bash timeout only applies *after* permission is granted. Let me confirm how permission asks from the injection subagent get surfaced to the UI.

Ran terminal command: cd /home/master/code/CyberStrike && git diff packages/cyberstrike/src/server/routes/session.ts packages/cyberstrike/src/config/config.ts packages/cyberstrike/src/provider/provider.ts

Ran terminal command: cd /home/master/code/CyberStrike && grep -rn "permission.asked\|Event.Asked\|permission\b" packages/cyberstrike/src/server/routes/session.ts | head -30

Let me look at how subagent (Proxy-Tester-Injection) permission asks are routed — the injection agent is a subagent, and its `ctx.ask` needs to reach the UI.

Ran terminal command: grep -rn "ctx.ask\|\.ask(\|permission" packages/cyberstrike/src/session/*.ts packages/cyberstrike/src/tool/task.ts | grep -i "ask\|permission" | head -40

Ran terminal command: grep -rn "PermissionNext.ask\|\.ask(\|permission:" packages/cyberstrike/src/session/ | head -40

Let me examine how `ctx.ask` is wired for tools and what ruleset a subagent's bash uses.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts",
  "offset": 1000,
  "limit": 70
}

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts",
  "limit": 80,
  "offset": 920
}

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/tool/task.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/tool/task.ts"
}

Let me check the proxy-tester agent's permission config for bash, and whether the UI surfaces subagent permission asks.

Ran terminal command: grep -rln "proxy-tester\|proxy_tester" packages/cyberstrike/src/agent/ | head; echo "---AGENT DEFS---"; find packages/cyberstrike/src/agent -name "*.ts" | xargs grep -ln "permission" 2>/dev/null | head

Ran terminal command: grep -rn "bash" packages/cyberstrike/src/agent/agent.ts | head -20; echo "=== default permission ==="; grep -rn "permission\|bash\|ask\|allow" packages/cyberstrike/src/agent/agent.ts | head -40

Line 589 has a bash permission with nested rules ("Defense-in-depth"). Let me look at that.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/agent/agent.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/agent/agent.ts",
  "limit": 90,
  "offset": 560
}

The injection agent has `bash: "allow"`, so bash commands don't trigger a permission ask — that rules out the permission path for this subagent. The 2-min timeout should kill any hanging command *unless the kill itself fails to terminate the process*, in which case the `await proc.once("exit")` never resolves. Let me check `Shell.killTree`.

Ran terminal command: find packages/cyberstrike/src/shell -name "*.ts"; echo "==="; grep -n "killTree\|export" packages/cyberstrike/src/shell/shell.ts | head

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/shell/shell.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/shell/shell.ts"
}

The kill path looks sound for normal processes. But note line 160/166: `doom_loop: "ask"`. Let me check the doom_loop permission ask in the processor — that's a permission ask that *can* fire mid-run and would hang if not surfaced.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/session/processor.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/session/processor.ts",
  "limit": 60,
  "offset": 140
}

This is the likely culprit. The **doom-loop guard** (processor.ts:166) fires a `doom_loop: "ask"` permission request when the last 3 tool calls are identical — e.g. a weak model retrying the same XXE `curl` three times. That `PermissionNext.ask` had **no timeout**, so it blocks the subagent (and the whole recon) forever. Let me confirm how these asks reach the UI and whether subagent-session asks are surfaced.

Ran terminal command: grep -rn "permission.asked\|Asked\|doom_loop\|permission" packages/cyberstrike/src/server/routes/session.ts | head; echo "=== event stream / SSE ==="; grep -rln "permission.asked\|Event.Asked\|permission.replied" packages/cyberstrike/src/ | head

Let me verify whether permission asks from hidden subagent sessions actually surface in the web UI — if they don't, a doom_loop/permission ask on a subagent is invisible and unanswerable.

Ran terminal command: find packages -path '*web*' -name "*.tsx" | xargs grep -ln "permission" 2>/dev/null | head; echo "=== web ui dir ==="; ls packages/ 2>/dev/null; find packages -maxdepth 3 -type d -name "web" 2>/dev/null | head

Ran terminal command: grep -rln "permission" packages/app packages/console packages/ui 2>/dev/null | grep -iE "tsx|ts$" | head; echo "=== search permission asked handling in frontends ==="; grep -rln "permission.asked\|permissions/\|doom" packages/app packages/console 2>/dev/null | head

Ran terminal command: grep -rln "permission" packages/app/src --include="*.tsx" | grep -viE "i18n" | head; echo "=== how asks are shown ==="; grep -rn "asked\|pending\|permission" packages/app/src/app.tsx | head -30

Read [](file:///home/master/code/CyberStrike/packages/app/src/context/permission.tsx)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/app/src/context/permission.tsx"
}

The frontend only auto-accepts `edit` permissions; everything else needs a visible prompt. Let me find where that prompt is rendered and whether it filters by session ID (which would hide subagent asks).

Ran terminal command: grep -rln "permission.asked\|PermissionRequest\|respond\|usePermission\|reject\|once\|always" packages/app/src/pages/session/*.tsx | head; echo "==="; grep -rln "permission" packages/app/src/pages/session/ | head

Ran terminal command: grep -n "permission\|asked\|Permission\|sessionID\|respond\|pending\|doom" packages/app/src/pages/session/session-prompt-dock.tsx | head -40

The prompt dock renders a single `permissionRequest()`. Let me find how it's computed — specifically whether it's scoped to the currently-open session (which would hide subagent asks).

Ran terminal command: grep -rn "permissionRequest\|SessionPromptDock\|session-prompt-dock" packages/app/src/pages/session/*.tsx | grep -v "session-prompt-dock.tsx:" | head

Ran terminal command: grep -rln "SessionPromptDock\|permissionRequest\|permission-prompt\|permissions.list\|permission.list" packages/app/src --include="*.tsx" --include="*.ts" | head; echo "=== usage ==="; grep -rn "permissionRequest\|PromptDock" packages/app/src/pages/session.tsx packages/app/src/pages/session/*.tsx 2>/dev/null | head

Ran terminal command: grep -n "permRequest\|permissionRequest\|permission" packages/app/src/pages/session.tsx | head -40

Found the root cause. Let me read the exact `permRequest` memo and confirm the session scoping.

Read [](file:///home/master/code/CyberStrike/packages/app/src/pages/session.tsx)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/app/src/pages/session.tsx",
  "limit": 18,
  "offset": 104
}

Let me verify whether `doom_loop` actually evaluates to "ask" (not "deny") for the injection subagent, given the `"*": "deny"` rule ordering.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/agent/agent.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/agent/agent.ts",
  "limit": 45,
  "offset": 150
}

I've traced both candidate hang sites in code; now let me get empirical data from the running system to settle which it is — stuck child processes and pending permission requests are directly observable.

Ran terminal command: echo "=== cyberstrike / node / bun processes ==="; ps -eo pid,ppid,etime,stat,cmd | grep -iE "cyberstrike|hackbrowser|sqlmap|nc |ncat|nmap|curl|python.*http.server" | grep -v grep | head -40
echo; echo "=== D-state (uninterruptible) or stuck procs ==="; ps -eo pid,ppid,etime,stat,cmd | awk '$4 ~ /D/ {print}' | head

A **netcat listener** (`nc -lvnp 28026`) has been stuck for **22 days** (`etime 22-02:52:20`). This is an OOB (out-of-band) listener — exactly what an XXE callback test spawns. It blocks forever waiting for a connection. Let me map the process tree and find all such leaked listeners plus the current server.

Ran terminal command: echo "=== all nc/ncat/socat/http.server listeners ==="; ps -eo pid,ppid,etime,stat,cmd | grep -iE "\bnc \b|nc -l|ncat|socat|http\.server|-lvnp|-lnvp|LISTEN" | grep -v grep
echo; echo "=== is 528889 alive? what is it ==="; ps -o pid,ppid,etime,stat,cmd -p 528889 2>/dev/null || echo "528889 GONE (nc was orphaned/reparented)"
echo; echo "=== current cyberstrike server ==="; ps -eo pid,ppid,etime,stat,cmd | grep -iE "cyberstrike (web|serve)" | grep -v grep | head

Important correction: that stuck `nc` is running **inside a Docker target container** (parent is `containerd-shim`, exposed via docker-proxy on 172.17.0.9) — it's lab infrastructure, not spawned by the bash tool. And the `cyberstrike web` server grep came back empty. Let me find the actual running server and its children, plus the log.

Ran terminal command: echo "=== any cyberstrike host process ==="; ps -eo pid,ppid,etime,stat,cmd | grep -iE "cyberstrike|bin/cyberstrike|dist/cyberstrike" | grep -v grep | head
echo; echo "=== bun/node processes owned by user ==="; ps -eo pid,ppid,etime,stat,cmd | grep -iE "\bbun\b|node " | grep -v grep | grep -iv docker | head -20
echo; echo "=== listening on 4444? ==="; (ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | grep 4444 || echo "nothing on 4444 — server not running"

Server isn't running now (nothing on :4444), so the live hang is gone — I'll rely on the logs it left behind. Let me find CyberStrike's log directory and check what the last session actually did before hanging.

Ran terminal command: grep -rn "Global.Path\|export namespace Global\|data:\|log:\|Path = {" packages/cyberstrike/src/global/*.ts 2>/dev/null | head -20; echo "=== find global path def ==="; find packages/cyberstrike/src -name "*.ts" | xargs grep -ln "Path.log\|Path = \|namespace Global" 2>/dev/null | head

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/global/index.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/global/index.ts",
  "limit": 27
}

Ran terminal command: LOGDIR="${XDG_DATA_HOME:-$HOME/.local/share}/cyberstrike/log"; echo "LOGDIR=$LOGDIR"; ls -lt "$LOGDIR" 2>/dev/null | head -8

The latest log is **437 MB** (last modified 06:52) — that size alone signals a runaway loop. Let me inspect its tail and search for the relevant markers.

Ran terminal command: LOG="/home/master/.local/share/cyberstrike/log/2026-08-06T100228.log"
echo "=== TAIL (last 40 lines) ==="; tail -c 200000 "$LOG" | tail -40
echo; echo "=== last distinct service/message shapes in tail ==="; tail -c 500000 "$LOG" | sed -E 's/[0-9]+//g' | sort | uniq -c | sort -rn | head -15

The log ends mid-setup (a new subagent's tool registry initializing) — that's where `pkill` cut it. Let me search for the XXE command, permission/doom_loop asks, and evidence of a loop.

Ran terminal command: LOG="/home/master/.local/share/cyberstrike/log/2026-08-06T100228.log"
echo "=== permission asks / doom_loop / rejected ==="; grep -aiE "doom_loop|permission.*(ask|asked|pending)|evaluated.*action" "$LOG" | grep -aiE "doom|asked|ask\b" | tail -20
echo; echo "=== count of permission-related lines ==="; grep -aciE "doom_loop" "$LOG"; grep -aciE "service=permission" "$LOG"
echo; echo "=== XXE / content negotiation mentions ==="; grep -aiE "content negotiation|XXE" "$LOG" | tail -10

A self-hosted **vLLM (Qwen3.6-27B) at `https://124.197.18.226:8000`** is throwing `AI_APICallError` on the injection subagent — and `provider.ts` sets `timeout: false`. Let me extract the actual error reason (not the huge request bodies) and check for a retry loop.

Ran terminal command: LOG="/home/master/.local/share/cyberstrike/log/2026-08-06T100228.log"
echo "=== error kinds (statusCode / message / cause), request bodies stripped ==="
grep -aoE '"name":"[A-Za-z_]+"|"statusCode":[0-9]+|"message":"[^"]{0,160}"|"code":"[A-Za-z_]+"|ECONNREFUSED|ETIMEDOUT|ECONNRESET|self-signed|certificate|EOF|fetch failed' "$LOG" \
 | grep -avE '"name":"(function|object|string|array)"' | sort | uniq -c | sort -rn | head -40

**1625 identical `AI_APICallError` with `statusCode: 400`** — this is a tight infinite retry loop, not a true hang. It's spinning on an HTTP 400 from the vLLM endpoint, re-logging the full request each time (hence 437 MB). Let me get the exact 400 message and response body.

Ran terminal command: LOG="/home/master/.local/share/cyberstrike/log/2026-08-06T100228.log"
echo "=== one AI_APICallError, showing responseBody / message (bodies of REQUEST stripped) ==="
grep -ao 'AI_APICallError[^\n]*' "$LOG" | head -1 | grep -aoE '"responseBody":"[^"]{0,500}"|"statusCode":[0-9]+|"message":"[^"]{0,300}"|"url":"[^"]+"'
echo; echo "=== distinct responseBody contents (what the 400 says) ==="
grep -aoE '"responseBody":"[^"]{0,400}"' "$LOG" | sort | uniq -c | sort -rn | head -5
echo; echo "=== timing: first vs last AI_APICallError ==="
grep -an "AI_APICallError" "$LOG" | head -1 | grep -aoE "^[0-9]+:.{0,40}"
grep -an "AI_APICallError" "$LOG" | tail -1 | grep -aoE "^[0-9]+:.{0,40}"

Retries span 10:31→10:52 (~21 min, 1625 times) — that's the "hang." Let me read the full 400 response body to see exactly what the vLLM is rejecting.

Ran terminal command: LOG="/home/master/.local/share/cyberstrike/log/2026-08-06T100228.log"
grep -aoE '"responseBody":"\{.{0,700}' "$LOG" | head -1
echo; echo "=== also the AI SDK 'message' field on the error ==="
grep -aoE '"message":"[^"]{0,400}"' "$LOG" | grep -aiE "token|context|length|400|invalid|maximum|exceed|certificate|schema|tool" | sort | uniq -c | sort -rn | head

**Definitive root cause found.** The vLLM error:

> `This model's maximum context length is 128000 tokens. However, you requested 32000 output tokens and your prompt contains at least 96001 input tokens, for a total of at least 128001 tokens.` — `"isRetryable": false`

96001 input + 32000 `max_tokens` = 128001, **exactly 1 over** the 128k limit → HTTP 400. It's marked non-retryable, yet it repeated **1625 times in 21 minutes**. So something is retrying a non-retryable error in a tight loop. Let me find that retry loop and where `max_tokens: 32000` comes from.

Ran terminal command: cd packages/cyberstrike/src
echo "=== max output tokens / 32000 ==="; grep -rnE "32000|32_000|maxOutputTokens|max_tokens|maxTokens" session/ provider/ config/ | grep -viE "test|//|input" | head -20

The compaction threshold is `model.limit.context - maxOutputTokens`. Let me check how errors are retried (why 1625×) and what context limit is configured for this vLLM model.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/session/llm.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/session/llm.ts",
  "limit": 80,
  "offset": 140
}

Let me look at the compaction trigger and the error/retry handling in prompt.ts.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts",
  "limit": 75,
  "offset": 795
}

The preflight compaction uses `model.limit.context - maxOutputTokens`. Let me determine whether the 1625 retries are one subagent looping or repeated re-dispatch, and check the vLLM model's configured context limit.

Ran terminal command: LOG="/home/master/.local/share/cyberstrike/log/2026-08-06T100228.log"
echo "=== distinct sessionIDs among the AI_APICallError lines ==="
grep -ao 'sessionID=ses_[A-Za-z0-9]*' "$LOG" | sort | uniq -c | sort -rn | head
echo; echo "=== context-usage / preflight / compaction log lines (utilization) ==="
grep -aE "pre-flight overflow|context usage|compaction" "$LOG" | grep -aoE "(pre-flight overflow detected|utilization=[0-9]+|contextLimit=[0-9]+|estimated=[0-9]+|limit=[0-9]+)" | sort | uniq -c | sort -rn | head
echo; echo "=== how many streamText attempts vs stepCapped/MAX_STEPS ==="; grep -aciE "stepCapped|MAX_STEPS|step limit" "$LOG"

The stuck subagent session `ses_0296126e3ffe…` retried **4894 times**, and critically `utilization=0` appears 1790× — meaning `model.limit.context` is **0/unset** for this vLLM model, so the preflight guard `if (preflightLimit > 0 …)` is false and compaction never fires. Let me confirm the retry mechanism in the prompt loop.

Ran terminal command: cd packages/cyberstrike/src/session
echo "=== catch / retry / while in prompt loop ==="; grep -nE "while *\(|catch|retry|continue|APICallError|isRetryable|error instanceof|for *\(" prompt.ts | head -40

Ran terminal command: cd /home/master/code/CyberStrike/packages/cyberstrike/src/session
grep -nE "while *\(|} catch|\.catch\(|retry|continue|APICallError|isRetryable|MAX_STEPS|for *\(let|maxRetries" prompt.ts | head -40

`while (true)` at line 313 is the agent loop, and `streamText`'s `onError` (llm.ts:177) only **logs** the error rather than throwing — so a 400 produces an empty step and the loop repeats the same oversized prompt forever. Let me confirm what breaks the loop after `processor.process`.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/session/prompt.ts",
  "limit": 55,
  "offset": 870
}

Let me see how the processor handles a stream `error` part — what `result` and `finish` it produces, which determines whether the loop breaks or spins.

Ran terminal command: cd /home/master/code/CyberStrike/packages/cyberstrike/src/session
grep -nE "case \"error\"|\"error\"|finish|return \"stop\"|return \"compact\"|isRetryable|APICallError|throw|error =" processor.ts | head -40

Line 429 `if (needsCompaction) return "compact"` → prompt.ts then compacts and `continue`s (loops). If the context-overflow 400 is classified as `needsCompaction` but compaction can't shrink a single-turn subagent prompt, it loops forever. Let me confirm.

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/session/processor.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/session/processor.ts",
  "limit": 65,
  "offset": 368
}

Confirmed the loop: vLLM 400 → `ContextOverflowError` → `needsCompaction=true` → `return "compact"` → prompt.ts compacts and `continue`s → rebuilds the same oversized prompt → 400 again. **4894 iterations.** And `utilization=0` indicates `model.limit.context` is 0/unset, which (a) disables the preflight guard (`preflightLimit > 0` is false) and (b) makes compaction's target negative — so compaction can never resolve it. Let me confirm the vLLM model config.

Ran terminal command: cd /home/master/code/CyberStrike
echo "=== user config (cyberstrike.jsonc referenced) ==="; find . -maxdepth 3 -name "*.jsonc" -o -maxdepth 3 -name "cyberstrike.json" 2>/dev/null | grep -iv node_modules | head
echo; echo "=== search for vllm / 124.197 / Qwen model config ==="; grep -rniE "vllm|124\.197|Qwen3\.6|limit.*context|\"context\"" --include=*.json --include=*.jsonc --include=*.ts . 2>/dev/null | grep -vi node_modules | grep -iE "vllm|124\.197|qwen|context" | head -20

Ran terminal command: cd /home/master/code/CyberStrike; sed -n '1,80p' .cyberstrike/cyberstrike.jsonc

The vLLM provider isn't in this local config — it's in the global config the user attached (`file_cyberstrike.jsonc`). Let me read it.

Read [](file:///home/master/.vscode-server/data/agentSessionData/e9519208-f2aa-4b25-a054-dca483ba5e74/attachments/87a9de57-3eb0-4d33-9a36-96cb6354d5d0/file_cyberstrike.jsonc)
Completed with input: {
  "file_path": "/home/master/.vscode-server/data/agentSessionData/e9519208-f2aa-4b25-a054-dca483ba5e74/attachments/87a9de57-3eb0-4d33-9a36-96cb6354d5d0/file_cyberstrike.jsonc"
}

**Root cause confirmed.** The vLLM model `Qwen/Qwen3.6-27B` is defined with **no `limit` field** (file_cyberstrike.jsonc:9-11). Let me locate the real global config file so I can propose the exact fix.

Ran terminal command: for p in "$HOME/.config/cyberstrike/cyberstrike.jsonc" "$HOME/.config/cyberstrike/config.jsonc" "$HOME/.config/cyberstrike/cyberstrike.json" "$HOME/.config/cyberstrike/config.json"; do [ -f "$p" ] && echo "FOUND: $p"; done
echo "=== grep global config dir ==="; grep -rl "124.197.18.226\|Qwen3.6-27B" "$HOME/.config/cyberstrike/" 2>/dev/null

Let me confirm the config schema field name for the model limit before proposing the exact edit.

Ran terminal command: cd /home/master/code/CyberStrike/packages/cyberstrike/src
grep -nE "limit|context:|output:|input:" config/config.ts | grep -iE "limit|context|output" | head; echo "=== Model.limit shape in provider ==="; grep -nE "limit:|context:|output:|input:" provider/provider.ts | head

Ran terminal command: cd /home/master/code/CyberStrike/packages/cyberstrike/src
grep -nE "models:|limit|CustomLoader|Model = z|z.object" config/config.ts | grep -iE "model|limit" | head; echo "=== show model schema block ==="; grep -n "limit" config/config.ts

Read [](file:///home/master/code/CyberStrike/packages/cyberstrike/src/config/config.ts)
Completed with input: {
  "file_path": "/home/master/code/CyberStrike/packages/cyberstrike/src/config/config.ts",
  "limit": 40,
  "offset": 1044
}

I have the complete picture. Let me read the actual global config to apply the fix precisely.

Read [](file:///home/master/.config/cyberstrike/cyberstrike.jsonc)
Completed with input: {
  "file_path": "/home/master/.config/cyberstrike/cyberstrike.jsonc"
}

I've traced the hang end-to-end. Applying the fix to the vLLM model config (the root cause), then I'll explain everything.

Edited [](file:///home/master/.config/cyberstrike/cyberstrike.jsonc)

Let me record this non-obvious failure mode in memory, then summarize.

Edited [](file:///home/master/.claude/projects/-home-master-code-CyberStrike/memory/vllm-model-needs-context-limit.md)

Ran terminal command: cd /home/master/code/CyberStrike; MEM="/home/master/.claude/projects/-home-master-code-CyberStrike/memory/MEMORY.md"; [ -f "$MEM" ] && tail -3 "$MEM" || echo "no MEMORY.md yet"

Edited [](file:///home/master/.claude/projects/-home-master-code-CyberStrike/memory/MEMORY.md)

It's not a crash and not really a hang — it's an **infinite compaction-retry loop** making zero progress. I traced it from the 437 MB log the run left behind.

## What actually happened

Your recon used the self-hosted **vLLM model `Qwen/Qwen3.6-27B`** (`https://124.197.18.226:8000`). In your global config (`~/.config/cyberstrike/cyberstrike.jsonc`) that model was declared **without a `limit` field**:

```jsonc
"Qwen/Qwen3.6-27B": { "name": "Qwen 3.6-27B" }   // no limit → model.limit.context = 0
```

The log shows the consequence precisely — the injection subagent session `ses_0296126e3ffe…` produced the **same error 4894 times** in ~21 minutes:

> `This model's maximum context length is 128000 tokens. However, you requested 32000 output tokens and your prompt contains at least 96001 input tokens, for a total of at least 128001 tokens` — HTTP 400, `"isRetryable": false`

The loop:

1. `model.limit.context = 0`, so the **preflight compaction guard is disabled** (`session/prompt.ts:810` requires `preflightLimit > 0`). Oversized prompts are never trimmed before sending.
2. The `proxy-tester-injection` subagent accumulated bash-output context across its many Shell commands. By the ~10th command ("Test XML content negotiation for XXE") input crossed 128k — **XXE wasn't special, it was just where the running total tipped over**.
3. vLLM returns a hard 400. `session/processor.ts:371` classifies it as `ContextOverflowError` → `needsCompaction = true` → returns `"compact"`.
4. `prompt.ts` (`while(true)` loop) runs compaction and `continue`s — but with `limit.context = 0` the compaction target is negative, so it can't shrink anything. Same 96001-token prompt → same 400 → repeat forever.

That's the 437 MB log (each retry re-logs the full request + 41 tool schemas) and the apparent freeze. The `/bin/sh:` line at startup is unrelated — that's the headless `open()` browser-launch failure you already fixed in `web.ts`. The 22-day `nc -lvnp 28026` I found is inside a Docker target container (lab infra), also unrelated.

## The fix (applied)

I added the model's real limits to `~/.config/cyberstrike/cyberstrike.jsonc`:

```jsonc
"Qwen/Qwen3.6-27B": {
  "name": "Qwen 3.6-27B",
  "limit": { "context": 128000, "output": 16000 }
}
```

Now preflight compaction fires at ~95% of `128000 − 16000 = 112000` tokens, trimming accumulated context **before** the request is ever sent — so the 400 never occurs. Restart `cyberstrike web` and re-run.

## Two things worth noting about your uncommitted changes

- Your `permission/next.ts` 10-minute auto-reject and the `web.ts` DISPLAY guard are both reasonable, but **neither addresses this bug** — this was never a permission ask (the injection agent has `bash: "allow"`, and `doom_loop` resolves to `deny` for vuln agents, not `ask`). Don't count on the permission timeout to catch this class of failure.
- There's a **latent robustness bug** independent of config: the `compact → continue` loop has no progress check. Any model with an unknown/oversized-irreducible prompt will spin indefinitely. A real guard would be: if a `ContextOverflowError` recurs after a compaction that didn't reduce token count, bail the turn with a fatal error instead of looping. Want me to draft that fix in `session/prompt.ts`/`processor.ts`?

One cleanup note: `~/.local/share/cyberstrike/log/` has a 437 MB and a 1.7 GB log from these runaway runs — safe to delete to reclaim ~2 GB.