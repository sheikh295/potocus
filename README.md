# Potocus

Local-first hybrid AI agent harness for authorized offensive security operations.

- **Brain:** Ollama on macOS (Qwen3 orchestrator + Dolphin3-Cyber specialist)
- **Hands:** Python harness (built on Mac, **runtime target = Kali Linux**)
- **Control:** code-level scope enforcement + HITL risk tiers (not prompt trust)

Full architecture: [`docs/master_doc_potocus.md`](docs/master_doc_potocus.md)

## Mac build → Kali test

Development happens on macOS. Full offensive-tool fidelity is validated later on Kali.

| Environment | What works today | What to do |
|---|---|---|
| **macOS (now)** | CLI, workspaces, ScopeGuard, risk HITL, LangGraph, Ollama dual-model, tool search via **seed manuals** + any local binaries | `potocus tools index` then develop/test |
| **Kali (later)** | Live `--help` from the real 600+ tool install | `pip install …` then `potocus tools index --reset --live-only` |

Seed manuals live in `data/kali_tools/` so `search_kali_tools` is usable before Kali is available. They are **not** mocks of the search stack — they are real documents. On Kali, live capture replaces them.

## How you will use this (install, not “clone forever”)

Potocus is a normal Python package (`pyproject.toml` + `potocus` console script).

| Mode | Command | When |
|---|---|---|
| Dev (this machine) | `pip install -e .` | Day-to-day building |
| From git URL | `pip install git+https://github.com/<you>/potocus.git` | Install on Kali without manual copy |
| Published package | `pip install potocus` | After we publish to PyPI (or a private index) |
| Wheel / artifact | `pip install ./dist/potocus-*.whl` | Air-gapped / pinned releases |

Typical production layout:

1. **Mac host** — Ollama + both models; API reachable on the LAN (`http://<mac-ip>:11434`).
2. **Kali VM** — `pip install potocus`, point `POTOCUS_OLLAMA_*` at the Mac, `potocus tools index --reset --live-only`, then run engagements.

## Setup (dev)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # optional
```

```bash
ollama list
# qwen3:8b
# hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M
```

## Quick start

```bash
potocus config test-ollama
potocus workspace init ./lab --mode unscoped
potocus tools index
potocus tools search "network port scanner"
potocus session new --name "first-run"
potocus status
potocus chat
```

Scoped engagement:

```bash
potocus workspace init ./clientX-pentest --mode scoped
potocus scope add 10.10.20.0/24 --note "corp-vlan per ROE"
potocus tools index
potocus session new --name "external-recon"
potocus chat
```

## CLI

| Command | Purpose |
|---|---|
| `potocus workspace` | init / switch / show / set-mode |
| `potocus scope` | add / remove / list / check |
| `potocus session` | new / list / resume / rename / close / set-phase |
| `potocus tools` | index / search / status (Kali manuals → ChromaDB) |
| `potocus chat` | LangGraph ReAct REPL + HITL panels |
| `potocus status` | workspace / session / phase / mode |
| `potocus config` | show / test-ollama / classify / consult |

## Tests

Real filesystem, classifiers, Ollama, and ChromaDB — no mocks:

```bash
pytest -q
```
