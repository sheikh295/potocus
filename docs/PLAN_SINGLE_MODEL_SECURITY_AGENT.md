# Potocus Enhancement Plan — Single-Model Security Agent

**Repo:** `/Users/mamoor/Documents/work/products/potocus`
**Branch base:** `main` @ `9d02e59`
**Target model:** `hf.co/mradermacher/Cyber-Ornith-1.5-9B-OBLITERATED-GGUF:Q3_K_S` (Ollama, local)
**Context cap:** `64000` tokens — set from `config.yaml` (`agent.context_token_limit`) and enforced forcefully at the application level by Potocus (not relying on the model's native window).
**Mode:** Plan + Act (implementation proceeds; no pytest/mocks — verified live against Ollama).


## A. Goals & Non-Goals

**Goals:**
1. Replace dual-model (orchestrator Qwen3 + specialist Dolphin3-Cyber) with **one model**: Cyber-Ornith, which is itself the security expert.
2. **Context compaction by threshold only (64k from config):** when token estimate >= `agent.context_token_limit`, summarize once, clear all prior messages, keep the summary as the first message (right after the system prompt). Never compact every turn; no rolling `keep_recent_messages` window.
3. **Fixed terminal UI:** fixed thinking box + fixed chat box + fixed live terminal box (no scrolling print-out).
4. **Live sub-terminal:** commands run in a spawned sub-pty streaming output live; `sudo su` → `sudo -i`.
5. **Model switch command:** `potocus config model list|show|set <name>` to test other local Ollama models.
6. No pytest/mocking; realtime verification against live Ollama.

**Non-goals (this sprint):** pytest, multi-model routing, remote providers beyond Ollama.

## B. Confirmed Facts (from exploration)

| Item | Value |
|------|-------|
| Repo root | `/Users/mamoor/Documents/work/products/potocus` |
| Python env | `.venv` (Python 3.14), package installed editable |
| Entry | `main.py` → typer CLI (`potocus`), subcommands under `src/cli/` |
| Global config | `config.yaml` (`ollama.*`, `models.*`, `agent.*`) |
| Models source | `src/models.py` `get_model_endpoints()` / `ModelEndpoints` |
| Graph engine | `src/graph.py`: `START → compact → agent → (tools ↔ agent)* → END` |
| Specialist tool | `src/tools/expert.py`: `consult_security_expert`, `SpecialistBudget` |
| Terminal tool | `src/tools/terminal.py`: `execute_kali_command` → `subprocess.run(capture_output=True)` |
| UI | `src/cli/chat_ui.py`: `ActivityDisplay` (Live spinner + scrolling panels) |
| Chat REPL | `src/cli/chat.py`: `potocus chat` ReAct loop, HITL, `/status`, `/phase` |
| Config CLI | `src/cli/config_cmd.py`: `show`, `test-ollama`, `classify`, `consult` |
| Ollama (local) | 3 models; **Cyber-Ornith** = qwen35, 8.95B, Q3_K_S, ctx **262144**, capabilities `tools,thinking,completion` ✓ tool calling supported |

> **Context-window note:** Ollama advertises 262144 for Cyber-Ornith, but Potocus will enforce its own **64000** application-level cap from `config.yaml`. This is tunable in one place.

**Resume artifact:** This document + commit `9d02e59` (main). If resuming in another session, re-read this plan and `src/graph.py`, `src/models.py`, `src/cli/chat.py`, `src/cli/chat_ui.py`, `src/tools/terminal.py`, `config.yaml`.


## C. Phase-by-Phase Implementation Plan

### Phase 0 — Pre-flight verification (no code changes)
1. Confirm Ollama reachable: `curl http://127.0.0.1:11434/api/tags` ✓ (done)
2. Confirm Cyber-Ornith pulled and supports `tools` ✓ (done)
3. Create git branch `feature/single-model-security-ui` before editing.
4. Quick smoke chat to Cyber-Ornith to confirm tool-calling end-to-end.

### Phase 1 — Configuration: single primary model + 64k cap
**Files:** `config.yaml`, `README.md`

Changes to `config.yaml`:
```yaml
ollama:
  base_url: http://127.0.0.1:11434/v1
  native_url: http://127.0.0.1:11434
  timeout_seconds: 120

models:
  primary: hf.co/mradermacher/Cyber-Ornith-1.5-9B-OBLITERATED-GGUF:Q3_K_S
  temperature: 0.2
  # REMOVED: orchestrator, specialist, specialist_calls_per_turn

agent:
  # Application-level context token cap (enforced by Potocus compaction).
  # Tunable here; model's native window (262144) is larger but we cap at 64k.
  context_token_limit: 64000
  # REMOVED: keep_recent_messages (no rolling window)
  command_timeout_seconds: 120

defaults:
  pacing: normal
  output_dir: ./reports

active:
  workspace: null
  session: null
```
Update `README.md` brain line: "Ollama on macOS (Cyber-Ornith single security-expert model)". Remove dual-model references.

### Phase 2 — LLM layer: single model client
**File:** `src/models.py`

- `ModelEndpoints`: drop `specialist`, `specialist_calls_per_turn`; rename `orchestrator` → `primary`; keep `base_url`, `native_url`, `temperature`, `timeout_seconds`. Add `context_window` (read from Ollama `/api/tags` details, fallback config).
- `get_model_endpoints()`: read `models.primary` from config; default to Cyber-Ornith.
- `get_openai_client()`: unchanged (points at Ollama OpenAI-compatible API).
- `list_local_models()`: unchanged (used by model switch command).
- `test_ollama_connection()`: check only `primary` model present + chat probe; drop `specialist_present`. Add `context_window` to result. Keep `chat_ok`, `chat_preview`.

### Phase 3 — Graph: single LLM, remove specialist
**File:** `src/graph.py`

- `AgentState`: drop `specialist_calls_this_turn`; keep `messages`, `phase`, `context_tokens_approx`, `workspace_root`, `session_id`, `seen_targets`, `tier2_confirmed`.
- `GraphRuntime`: drop `specialist_model`, `budget` (`SpecialistBudget`); keep single `model` (= primary).
- `build_tools(runtime)`: remove `consult_security_expert_tool`; keep `execute_kali_command_tool`, `search_kali_tools_tool`, `search_past_engagements_tool`, filesystem/web tools. The single model handles security reasoning itself.
- `compact_node`: **rewrite** per threshold-only design (Section D). Cap = `runtime.context_token_limit` (64k from config).
- `agent_node`: single `_make_llm(runtime.model, ...).bind_tools(tools)`; no specialist retry; emit thinking events.
- `_build_system_prompt`: single security-expert system prompt; remove `consult_security_expert` from available-tools list.
- `create_agent`: resolve single `model` from workspace.yaml `models.primary` then global `models.primary`; remove `specialist_model`.
- `PotocusAgent`: drop specialist-related status; keep `invoke_turn`, `resume`, `latest_ai_text`, `tool_messages`, `close`.

**File:** `src/tools/expert.py`
- Keep `consult_security_expert` function (standalone, usable via `potocus config consult`) but remove from the graph tool set.

**File:** `src/prompts.py`
- Replace `ORCHESTRATOR_SYSTEM_PROMPT` + `SPECIALIST_SYSTEM_PROMPT` with one `SYSTEM_PROMPT` (security expert, tool-using, offensive security, scope/HITL deferred to code).

### Phase 4 — Context compaction by threshold (64k, one-time, not per-turn)
**File:** `src/graph.py` `compact_node`

Design:
- Compute `tokens = estimate_tokens(messages)` at graph start (compact node).
- If `tokens < context_token_limit`: emit "within budget", return unchanged (no compaction this turn).
- If `tokens >= context_token_limit`:
  - Split off the last `HumanMessage` (this turn's input, kept verbatim).
  - `older` = all messages before it.
  - Summarize `older` into one summary using the single model (system: "Summarize prior engagement context... Keep facts, hosts, findings, decisions. Drop fluff.").
  - New message list = `[SystemMessage(prompt), HumanMessage("[context_compacted]\n"+summary, name="potocus_compactor"), current_user_msg]`.
  - Emit `context_compacted` event; set `context_tokens_approx`.
  - Return `RemoveMessage(id=REMOVE_ALL_MESSAGES)` + new messages so LangGraph replaces the whole history.
- After compaction the window is tiny → won't re-compact until new turns accumulate past 64k.
- No `keep_recent_messages` rolling window. All prior context collapses into the single summary first message.


## D. Exact compaction pseudocode (Phase 4)

```python
def compact_node(state):
    runtime.emit({"type": "node", "node": "compact"})
    messages = list(state.get("messages") or [])
    tokens = estimate_tokens(messages)
    limit = runtime.context_token_limit   # 64000 from config, enforced at app level
    if tokens < limit:
        return {"context_tokens_approx": tokens}  # no-op this turn

    runtime.emit({"type": "status", "text": "context threshold reached — summarizing once"})

    # Keep current user turn verbatim; summarize everything older.
    current_user = None
    older = list(messages)
    for i in range(len(older) - 1, -1, -1):
        if getattr(older[i], "type", "") == "human":
            current_user = older.pop(i)
            break

    digest = []
    for msg in older:
        role = getattr(msg, "type", msg.__class__.__name__)
        content = getattr(msg, "content", "") or ""
        if isinstance(content, str) and content.strip():
            digest.append(f"{role}: {content[:800]}")
    digest_blob = "\n".join(digest)[:6000] or "(empty)"

    summarizer = _make_llm(runtime.model, endpoints.temperature, think=False)
    summary = summarizer.invoke([
        SystemMessage(content="Summarize prior engagement context ... facts, hosts, findings, decisions. Drop fluff."),
        HumanMessage(content=digest_blob),
    ])
    summary_text = summary.content if isinstance(summary.content, str) else str(summary.content)

    compacted = [
        SystemMessage(content=_build_system_prompt(runtime, runtime.phase)),
        HumanMessage(content=f"[context_compacted]\n{summary_text}", name="potocus_compactor"),
    ]
    if current_user is not None:
        compacted.append(current_user)

    new_tokens = estimate_tokens(compacted)
    return {
        "messages": [RemoveMessage(id=REMOVE_ALL_MESSAGES), *compacted],
        "context_tokens_approx": new_tokens,
    }
```

## E. File-change map

| File | Change |
|------|--------|
| `config.yaml` | single `models.primary`, `context_token_limit: 64000`, drop specialist/keep_recent |
| `src/models.py` | `ModelEndpoints.primary`, drop specialist; single-model `test_ollama_connection`; add `context_window` |
| `src/graph.py` | single LLM, remove consult tool & budget, rewrite `compact_node` threshold-only @64k, update prompt |
| `src/tools/expert.py` | keep standalone, remove from graph tools |
| `src/prompts.py` | single `SYSTEM_PROMPT` |
| `src/tools/terminal.py` | pty streaming + live output, `sudo su`→`sudo -i` |
| `src/cli/chat_ui.py` | fixed Layout (thinking/chat/terminal boxes), no scrolling |
| `src/cli/chat.py` | wire fixed UI, single-model banner, `/status` |
| `src/cli/config_cmd.py` | `model list|show|set`, update `show`/`test-ollama` |
| `src/workspace/manager.py` | workspace.yaml `models.primary` single key |
| `README.md`, `docs/master_doc_potocus.md` | single-model docs |

## F. Verification (realtime, no pytest)
1. `potocus config test-ollama` → Cyber-Ornith present + chat ok.
2. `potocus config model list` → shows local models.
3. `potocus workspace init ./lab --mode unscoped && potocus session new --name t1 && potocus chat`
   - Reasoning question → fixed thinking box + chat box.
   - `uname -a` → live streaming terminal sub-window.
   - `sudo su` → runs as `sudo -i`.
   - Send many messages to cross 64k → one `[context_compacted]` first message, then no more compaction until threshold recrossed.
4. `potocus config model set <other> && potocus config model set Cyber-Ornith...` → switch back and forth.
5. `potocus status` → confirms single model, tokens, 64k budget.
