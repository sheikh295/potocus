# 🛡️ Potocus: Master Architecture & Requirements Document

**Version:** 2.0.0 (Production Release)
**Target Environment:** Kali Linux VM (Harness) + macOS Host (Ollama API)
**Architecture:** Hybrid Multi-Agent System (LangGraph), CLI-native, Workspace/Session model

## 1. Executive Summary & Vision

Potocus is a local-first, hybrid AI agent harness designed for autonomous offensive security operations, penetration testing, bug bounty hunting, and security research/learning.

Unlike basic wrapper scripts, Potocus is a **production-grade multi-agent framework**. It decouples the AI "brain" (running GPU-accelerated on the macOS host via Ollama) from the "hands" (running inside an isolated Kali Linux VM). It utilizes a dual-model architecture to combine the reasoning and tool-calling stability of **Qwen3** with the deep, uncensored offensive cybersecurity expertise of **Dolphin3-Cyber-8B**.

Potocus is built CLI-first and organized around **workspaces** (one per engagement, client, program, or lab) and **sessions** (one per line of work inside a workspace). The harness's offensive capabilities — the full 600+ tool surface of Kali, exploitation frameworks, post-exploitation tooling — are never artificially limited. Control is applied through **scope enforcement** and **human-in-the-loop (HITL) gating**, both implemented as code, not as instructions the model is trusted to follow. The agent is as capable as a skilled human operator; the harness is what keeps that capability pointed only where it's authorized to go.

## 2. Core Architecture

### 2.1 The "Brain + Hands" Topology

- **The Brain (Mac Host):** Runs Ollama, exposing an OpenAI-compatible API on the local network (e.g., `http://192.168.x.x:11434/v1`). Hosts the LLMs and utilizes Metal GPU acceleration.
- **The Hands (Kali VM):** Runs the Potocus Python harness. It acts as the orchestrator, executing CLI tools, managing state, and parsing tool outputs.

### 2.2 Multi-Model Ensemble Routing

The harness does not use a single model for everything. It implements a **Supervisor/Worker** pattern:

- **The Orchestrator (Default: Qwen3 8B/9B):** The primary driver. It manages the ReAct (Reasoning + Acting) loop, decides which tools to use, and formats JSON outputs. It is optimized for instruction following and tool calling.
- **The Specialist (Default: Dolphin3-Cyber-8B, confirmed available via `ollama pull dolphin3-cyber:8b`):** Exposed to the Orchestrator as a tool named `consult_security_expert` (use this exact name everywhere — the tool/phase naming mismatch in v1 is fixed here). Invoked only when deep CVE analysis, exploit payload generation, or specialized offensive security reasoning is required. Because it is uncensored, it provides actionable red-team intelligence without refusal friction.
- **Configurability:** `config.yaml` allows swapping these models, changing temperature, and pointing to different API providers (e.g., vLLM, LM Studio) without touching core code.
- **Model-call budgeting:** The Orchestrator must not round-trip to the Specialist more than once per reasoning step (no ping-pong loops). The graph should cap `consult_security_expert` calls per tool-call turn and log when the cap is hit so you can see it happening instead of silently burning context.

## 3. Framework Selection

- **Primary Framework:** **LangGraph** (part of LangChain).
  - *Why:* LangGraph is specifically designed for stateful, multi-agent workflows with cyclic graphs (loops), which is perfect for a ReAct agent. It handles state persistence, error recovery, and human-in-the-loop approvals natively. LlamaIndex is better for RAG (document Q&A), which is not the primary use case here.
- **API Client:** `openai` Python SDK (pointed to the local Ollama base URL).
- **CLI Interface:** `Typer` for commands/subcommands, `Rich` for terminal output (tables, panels, progress spinners, live-updating phase/status display), `prompt_toolkit` for the interactive chat REPL (history, multi-line input, autocomplete over tool/session names).

## 4. CLI & Interaction Model

Potocus is a CLI-native tool, not a chat-script-with-flags tool. It should feel like `git` or `docker` in structure: a persistent working context (current workspace + current session) plus explicit subcommands for everything else.

### 4.1 Top-level command groups

```text
potocus workspace   # create, list, switch, configure workspaces
potocus scope       # define/list/edit scope for a scoped workspace
potocus session     # create, list, resume, rename, close sessions
potocus chat         # enter the interactive agent REPL for the active session
potocus report       # generate/export reports from a workspace's findings
potocus status       # show current workspace, session, phase, scope mode at a glance
potocus config       # view/edit global (non-secret) settings
```

### 4.2 Example flows

```bash
# Start a real, authorized engagement
potocus workspace init ./clientX-pentest --mode scoped --output-dir ./clientX-pentest/reports
potocus scope add 10.10.20.0/24 --note "corp-vlan per ROE v2"
potocus scope add *.clientx-staging.com
potocus session new --name "external-recon"
potocus chat
# ... agent works, HITL prompts appear inline in the REPL ...
potocus report generate --format pdf

# Start a personal lab / learning session — no scope friction
potocus workspace init ./htb-boxes --mode unscoped
potocus session new --name "htb-forest"
potocus chat
```

### 4.3 Non-negotiables

- Every destructive/HITL prompt, scope rejection, and phase transition is rendered clearly in the CLI (Rich panels), not buried in scrollback.
- `potocus status` must always be able to answer "what workspace, what mode, what scope, what session, what phase am I in right now" in one call — this matters when you're context-switching between a learning session and a live client engagement.
- All commands are scriptable (JSON output mode via `--json`) so the CLI itself can be driven by other tooling later if needed.

## 5. Workspace / Project Model

A **workspace** is the top-level unit of work: one client engagement, one bug bounty program, one personal lab, one piece of research. It is bound to a directory on disk chosen at creation time — that directory is where reports, raw tool output, and anything you ask the agent to write get saved. Nothing workspace-scoped leaks into another workspace.

### 5.1 Workspace layout

```text
<workspace-root>/                 # the directory you chose at `workspace init`
├── .potocus/
│   ├── workspace.yaml            # mode, output dir, model overrides, pacing profile
│   ├── scope.yaml                # present only if mode: scoped — target allowlist + notes
│   ├── findings.db                # SQLite — structured findings, hosts, services, vulns
│   ├── vectorstore/                # ChromaDB — tool manuals + past-engagement memory, scoped to this workspace
│   ├── sessions/
│   │   ├── <session-id>/
│   │   │   ├── session.yaml       # name, created_at, phase, target focus
│   │   │   ├── checkpoints/        # LangGraph state checkpoints (resumability)
│   │   │   └── raw_output/         # full, unsummarized tool stdout/stderr for this session
│   │   └── ...
│   └── potocus.log                 # full audit log for the workspace
└── reports/                       # (or wherever --output-dir points) generated deliverables
```

### 5.2 `workspace.yaml`

```yaml
name: clientX-pentest
mode: scoped              # scoped | unscoped
output_dir: ./reports
pacing: normal            # stealth | normal | aggressive — see §13
created_at: 2026-10-25
models:
  orchestrator: qwen3:9b
  specialist: dolphin3-cyber:8b
```

### 5.3 Why workspace-scoped, not global

Long-term memory (past engagements, successful attack vectors, target notes — §11) and the tool-discovery vector DB are scoped **per workspace**, not global. A client engagement's findings shouldn't surface as "relevant past context" in an unrelated lab session, and a lab session's sloppy learning experiments shouldn't contaminate the memory you rely on for real client work. Cross-workspace search can be a deliberate, explicit opt-in command later (`potocus workspace link`), never the default.

## 6. Session / Thread Model

Inside a workspace, you can have multiple **sessions** — separate lines of work, each with its own conversation history, agent state, and phase, but all sharing the workspace's scope config, findings DB, and output directory. Think: one session per subdomain of recon, one per vuln you're chasing, one per day of work — whatever split makes sense to you.

- Each session is a LangGraph thread with its own checkpointed state (`sessions/<id>/checkpoints/`), so `potocus session resume <id>` picks up exactly where you left off — mid-phase, mid-tool-call, with full message history.
- Sessions within a workspace share:
  - the scope config (a session in a scoped workspace cannot touch out-of-scope targets regardless of what it's doing)
  - the findings DB (a host discovered in session A is visible to session B)
  - the tool-discovery vector store
- Sessions do **not** share raw LLM message history with each other — that stays per-session to keep context windows clean and focused.
- `potocus session list` shows name, phase, target focus, and last-active time for every session in the current workspace.

## 7. Scope & Mode Enforcement

This is the control layer that lets the rest of the system stay maximally capable. Every workspace is created in one of two modes, chosen explicitly at `workspace init` and visible everywhere (`potocus status`, REPL prompt, report headers):

### 7.1 Scoped mode — real engagements

- Used when you're operating under an authorized program, contract, or rules-of-engagement document.
- Requires a non-empty `scope.yaml`: an explicit allowlist of targets (CIDR ranges, domains, wildcard domains), with optional notes per entry (e.g., "per ROE v2, excludes prod DB tier").
- A `ScopeGuard` component sits between the agent's tool-call decision and `execute_kali_command`/any network-touching tool. It parses the target(s) implied by the command and checks them against `scope.yaml` **in code** — this is a hard gate, not a prompt instruction, and the LLM has no path to override or "mark safe" a rejection.
- Any out-of-scope attempt is logged, blocked, and surfaced to you in the CLI immediately — this is a signal worth seeing, not just suppressing.
- Scope can be edited mid-engagement (`potocus scope add/remove`) as the ROE changes, but every change is logged with a timestamp for audit purposes.

### 7.2 Unscoped mode — labs, learning, personal research

- Used for HTB/THM boxes, your own lab VMs, local CTFs, skill-building — anywhere you're not bound by a third party's authorization boundaries.
- No `scope.yaml` required; the ScopeGuard is a no-op pass-through.
- Still fully logged — unscoped doesn't mean unaudited, it means un-gated.
- The CLI makes the mode impossible to miss: a persistent banner/prompt-color difference between scoped and unscoped sessions so you never mistake which one you're in.

### 7.3 Mode is a workspace property, not a per-command toggle

You pick the mode once, when you create the workspace, matching how you'd actually use this: a real client workspace is scoped for its whole lifetime; a lab workspace stays unscoped. Changing a workspace's mode after creation is a deliberate, confirmed action (`potocus workspace set-mode`), not a casual flag — this prevents a scoped engagement from accidentally losing its guardrail mid-session.

## 8. Tooling System (The "600+ Tools" Requirement)

Kali Linux has over 600 tools. The harness must use a dynamic tool registration system — and the full breadth stays available in every mode; scope/HITL control *where* and *when* a tool fires, never *which* tools exist.

### 8.1 Terminal Execution Engine

- **`execute_kali_command`:** A robust wrapper around Python's `subprocess`.
- **Capabilities:** Standard `stdout`/`stderr` capture, timeouts (to prevent hanging commands), and background execution for long-running scans.
- **Routing:** Every call passes through the ScopeGuard (§7) and the Risk Classifier (§9) before execution. Neither of these reduces what the tool *can* do — they decide whether it fires immediately, fires after confirmation, or is blocked.

### 8.2 Tool Discovery (Dynamic Tooling)

- The agent cannot memorize 600 tools. Implement a **Tool Discovery Mechanism**:
  - **`search_kali_tools(query)`:** Queries the workspace's local vector database (ChromaDB) containing the `--help` manuals of all installed Kali tools.
  - *Workflow:* The agent thinks "I need to scan a network" → calls `search_kali_tools("network scanner")` → DB returns `nmap` and its usage → the agent formats the `nmap` command and calls `execute_kali_command`.
- **Custom Tool Wrappers:** For high-frequency tools, write explicit LangChain `@tool` decorators (e.g., `run_nmap`, `run_gobuster`, `run_sqlmap`, `run_metasploit_module`) to give the LLM strict parameter validation and structured (not raw-text) results.
- **Post-exploitation & pivoting tool wrappers:** credential-harvesting tool wrappers, session/pivot management (e.g., wrapping Metasploit sessions, SSH pivoting), and persistence-check tooling belong in this same layer — these are exploitation-phase tools, gated by phase (§12) and risk tier (§9), not excluded from the harness.

### 8.3 Web & OSINT Operations

- **`web_search`:** Integration with DuckDuckGo Search or a self-hosted SearXNG instance to avoid API rate limits.
- **`fetch_url`:** Scrapes and reads raw text from a URL (`BeautifulSoup`/`trafilatura`) so the agent can read CVE databases or blog posts directly.
- **`get_cve_details`:** NIST NVD API integration to pull exact CVE data instead of relying on model hallucination.

## 9. HITL & Command Risk Classification

Human-in-the-loop is implemented as a **static, code-level risk classifier**, not a judgment call the LLM makes about its own command. The model proposes a command; the classifier decides the tier; the tier decides what happens next. This keeps the agent's actual capability unconstrained while keeping a human in the loop exactly where it matters.

| Tier | Examples | Behavior |
|---|---|---|
| **Tier 1 — Passive/Recon** | `nmap -sn`, `whois`, `dig`, `search_kali_tools`, `fetch_url` | Auto-runs, no prompt |
| **Tier 2 — Active/Intrusive** | service/version scans, directory brute-forcing, vuln scanning | Auto-runs in scoped mode with a visible log line; one-time session confirmation in unscoped mode on first use |
| **Tier 3 — Exploitation/Destructive** | Metasploit exploit execution, credential spraying, any write/delete, payload delivery | Always requires explicit `[Y/n]` HITL confirmation, every time, in both modes |

- Tier is determined by a maintained table of command patterns/tool metadata (`tools/risk_classification.py`), checked in code — never inferred by the LLM at call time.
- **Any scope boundary change** (agent wants to touch a host not previously acted on, even if in-scope) triggers a Tier-escalated confirmation regardless of the command's normal tier — new targets deserve a second look.
- HITL prompts render the full command, target, and tier reasoning in the CLI (Rich panel) so the decision is informed, not a blind `[Y/n]`.

## 10. Context & Output Management

Raw tool output (a `-A` nmap scan, a large gobuster run) can run thousands of lines — enough to blow an 8B model's context window in one tool call. A processing layer sits between tool execution and what the LLM sees:

- **Structured extraction over raw text:** prefer machine-readable tool output where available (`nmap -oX`, JSON output modes) and parse it into structured findings (open ports, service versions, discovered paths, flagged vulns) rather than handing the LLM raw stdout.
- **Raw output is never discarded** — it's always written in full to `sessions/<id>/raw_output/` for audit and later deep-dives; only the *summarized/structured* version goes into the LLM's context.
- **Findings get written to `findings.db` immediately** as they're extracted, independent of whether the current session later gets summarized/compacted — this is what makes cross-session findings-sharing (§6) and reporting (§14) reliable even if conversation history gets pruned.
- **Per-session context budget:** LangGraph's state should track approximate token usage and proactively summarize/compact older tool-call turns before hitting the model's context ceiling, rather than failing or silently truncating.

## 11. State Management & Memory

- **Short-Term Memory (Context Window):** LangGraph manages per-session message history with the summarization/compaction policy from §10.
- **Long-Term Memory (RAG), workspace-scoped:** Past successful attack vectors, scan results, and target notes stored in the workspace's `findings.db`/`vectorstore/`. The agent can query this (`search_past_engagements`) to remember what worked before, scoped to the current workspace only (see §5.3).
- **Workspace Isolation:** All scan outputs, downloaded files, and logs stay inside the workspace directory you chose at `init`. The agent never writes outside the active workspace's root or the global `~/.potocus/` config dir.

## 12. Engagement Phase State Machine

A real engagement isn't a flat tool-call loop — it moves through phases, and each phase implies a different tool set and risk posture. Track this explicitly in session state rather than leaving it implicit in the conversation:

```text
RECON → ENUMERATION → VULN_IDENTIFICATION → EXPLOITATION → POST_EXPLOITATION → REPORTING
```

- `session.yaml` tracks `current_phase`. The LangGraph graph uses it to decide which tool subset is even offered to the Orchestrator at a given step — not as a hard block (you can manually advance/rewind phase via `potocus session set-phase`), but as the default framing so the agent isn't reaching for exploitation tooling during passive recon without you choosing to let it.
- Tier-2/3 risk classification (§9) can be phase-aware: the same command might warrant a lighter-touch confirmation during EXPLOITATION (where you've already accepted you're in an active phase) than if it showed up unexpectedly during RECON.
- Phase transitions are logged and shown in the CLI — part of what `potocus status` reports.

## 13. Reporting Module

The commercial/practical output of an engagement is the report, not the log file. Section 6 (logging) captures everything that happened; this module turns it into a deliverable.

- **`potocus report generate --format md|pdf|docx`** compiles the workspace's `findings.db`, session summaries, and selected evidence (screenshots, command output excerpts) into a structured report, written to the workspace's configured `output_dir`.
- **Templates per engagement type** (pentest report, bug bounty submission, internal research writeup) — a `templates/` directory the user can edit, not hardcoded formatting.
- **Severity/CVSS scoring** attached to findings as they're written to `findings.db`, either agent-proposed (via `consult_security_expert`) with human confirmation, or set manually.
- Reports pull from the *structured* findings DB, not raw session transcripts — keeps output clean and consistent regardless of how messy the actual working session was.

## 14. Pacing & Stealth Controls

- `workspace.yaml` sets a default `pacing` profile: `stealth` (slow timing templates, low concurrency — e.g., `nmap -T2`, throttled brute-forcing), `normal` (default), `aggressive` (max speed, for labs/internal engagements where noise doesn't matter).
- Tool wrappers (§8.2) read the active pacing profile and apply it automatically to timing-sensitive flags, rather than relying on the LLM to remember to add `-T2` every time.
- Pacing can be overridden per-session (`potocus session set-pacing`) without changing the workspace default — useful when one session needs to stay quiet while another doesn't.
- This matters most for bug bounty work, where aggressive unthrottled scanning gets you rate-limited or banned from programs.

## 15. Production-Grade Features

- **Human-in-the-Loop (HITL):** LangGraph's `interrupt` feature, driven by the risk classifier in §9 — never bypassable by the model.
- **Comprehensive Logging:** Every prompt, model response, tool call, and execution result logged to `potocus.log` per workspace. Crucial for debugging, audit, and post-engagement reporting.
- **Error Handling:** If a tool fails (e.g., `nmap` throws a syntax error), the harness catches `stderr`, feeds it back to the LLM, and allows self-correction.
- **Session Management:** `potocus session resume <id>` restores full LangGraph checkpoint state — message history, phase, findings context — so you can stop mid-engagement and pick up later, per-session, inside the right workspace.

## 16. Configuration & Secrets

- API keys/tokens (Ollama endpoint if auth'd, NVD API key, any third-party service keys) live in environment variables or a `.env` file — **never** committed to `config.yaml` or `workspace.yaml`, and `.env` is gitignored by default in the generated project.
- `config.yaml` (global) and `workspace.yaml` (per-workspace) hold only non-secret settings: model names/endpoints, temperature, pacing defaults, output directories.
- If a workspace or session file ever ends up with a secret accidentally written into it (e.g., an API key pasted into a chat message gets logged), that's a real risk for a tool that's meant to produce shareable reports — worth a basic secret-pattern scrubber on anything written to `findings.db` or report output.

## 17. Directory Structure

```text
potocus/
├── config.yaml                 # global, non-secret settings — model endpoints, defaults
├── .env.example                 # template for secrets (API keys) — never committed with real values
├── main.py                      # CLI entry point (Typer), command groups from §4.1
├── requirements.txt              # dependencies (langgraph, openai, rich, typer, prompt_toolkit, etc.)
├── README.md
├── src/
│   ├── __init__.py
│   ├── cli/
│   │   ├── workspace.py          # `potocus workspace ...`
│   │   ├── scope.py               # `potocus scope ...`
│   │   ├── session.py             # `potocus session ...`
│   │   ├── chat.py                # `potocus chat` REPL
│   │   ├── report.py              # `potocus report ...`
│   │   └── status.py              # `potocus status`
│   ├── graph.py                   # LangGraph state machine: ReAct loop + phase state (§12)
│   ├── models.py                  # Ollama/OpenAI client initialization
│   ├── prompts.py                 # System prompts for Qwen3 and Dolphin3-Cyber
│   ├── workspace/
│   │   ├── __init__.py
│   │   ├── manager.py              # workspace init/load, directory layout enforcement
│   │   └── scope_guard.py          # ScopeGuard — code-level scope enforcement (§7)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── terminal.py             # subprocess wrappers, routed through scope_guard + risk_classification
│   │   ├── web.py                  # search and fetch tools
│   │   ├── discovery.py            # tool search via vector DB
│   │   ├── expert.py               # bridge to Dolphin3-Cyber (`consult_security_expert`)
│   │   ├── post_exploit.py          # pivoting, persistence-check, credential-harvest wrappers
│   │   └── risk_classification.py   # Tier 1/2/3 command classification table (§9)
│   ├── memory/
│   │   ├── __init__.py
│   │   ├── vectorstore.py           # ChromaDB, workspace-scoped
│   │   └── findings_db.py           # SQLite findings store, workspace-scoped
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── generator.py             # compiles findings_db → report
│   │   └── templates/                # per-engagement-type report templates
│   └── utils/
│       ├── __init__.py
│       ├── logger.py                 # per-workspace logging setup
│       └── output_parser.py          # structured extraction from tool stdout (§10)
└── tests/                             # Pytest for tool execution, scope guard, risk classifier, graph logic
```

## 18. Implementation Phases (For the Coding Agent)

> Note: scope enforcement and HITL-as-code are foundational, not later polish — they're pulled earlier in the sequence than a typical "add safety at the end" build order.

1. **Phase 1: Core, CLI & Workspace Scaffolding** — folder structure, `config.yaml`, Typer CLI skeleton (all command groups stubbed), workspace init/load with the full directory layout from §17, `workspace.yaml` read/write. Ollama API connection test.
2. **Phase 2: Scope Guard & Risk Classification** — `scope_guard.py` and `risk_classification.py` built and unit-tested *before* any tool can execute against a real target. This is the control layer the rest of the system runs inside.
3. **Phase 3: The Bridge** — `consult_security_expert` tool (Dolphin3-Cyber) with the model-call budgeting from §2.2; test dual-model communication.
4. **Phase 4: LangGraph Engine** — ReAct loop in `graph.py`, state schema including phase tracking (§12) and context budget tracking (§10).
5. **Phase 5: Terminal Tools & HITL** — `execute_kali_command`, routed through scope_guard + risk_classification, with the `interrupt`-based HITL confirmation UI in the CLI.
6. **Phase 6: Tool Discovery** — scrape `--help` for installed Kali tools, embed into workspace-scoped ChromaDB, expose `search_kali_tools`.
7. **Phase 7: Output Management & Findings DB** — structured output parsing (§10), `findings_db.py`, raw-output archival.
8. **Phase 8: Session Management** — multi-session support within a workspace, checkpointed resume (§6).
9. **Phase 9: Reporting** — `reporting/generator.py` and initial templates (§13).
10. **Phase 10: Polish** — pacing profiles (§14), secret scrubbing (§16), logging/error-recovery hardening.

## 19. Strict Rules for the Coding Agent

- Do not hardcode IP addresses. Use `config.yaml`/`workspace.yaml` or environment variables for the Ollama base URL.
- Do not use `os.system()`. Always use `subprocess.run()` with `shell=False` or strict list-based arguments to prevent shell injection vulnerabilities.
- **Scope and risk-tier checks happen in Python, never in the system prompt.** The LLM must have no code path that lets it mark a command as "safe to skip" scope or HITL checks.
- Type hinting is mandatory. Use Python type hints for all functions and classes.
- Docstrings are mandatory. Every tool must have a clear docstring, as the LLM relies on the docstring to understand what the tool does.
- Keep models separate. The Qwen3 prompt focuses on tool usage, planning, and phase management. The Dolphin3-Cyber prompt focuses strictly on offensive cybersecurity analysis and payload generation. Do not mix their histories in the LLM context.
- Secrets never land in `config.yaml`, `workspace.yaml`, `findings.db`, or generated reports — environment/`.env` only, scrubbed on write where relevant (§16).
- Tool naming must stay consistent across code, prompts, and docs (`consult_security_expert`, `execute_kali_command`, `search_kali_tools`, etc.) — no renamed duplicates.

---

### 🚀 Pro-Tip for Dolphin3-Cyber

When you pull this model in Ollama (`ollama pull dolphin3-cyber:8b`), check its specific system prompt requirements. Some Dolphin models perform best with a system prompt like:

> "You are an expert cybersecurity researcher specializing in offensive security, red teaming, and penetration testing. You provide technical, actionable, and direct answers without unnecessary warnings."
