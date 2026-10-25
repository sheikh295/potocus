# Potocus

Local-first hybrid AI agent harness for authorized offensive security operations.

- **Brain:** Ollama on macOS (Qwen3 orchestrator + Dolphin3-Cyber specialist)
- **Hands:** Python harness (intended to run on Kali Linux)
- **Control:** code-level scope enforcement + HITL risk tiers (not prompt trust)

Full architecture: [`docs/master_doc_potocus.md`](docs/master_doc_potocus.md)

## How you will use this (install, not “clone forever”)

You do **not** need to keep a git clone as the runtime. Potocus is a normal Python package (`pyproject.toml` + `potocus` console script).

| Mode | Command | When |
|---|---|---|
| Dev (this machine) | `pip install -e .` | Day-to-day building |
| From git URL | `pip install git+https://github.com/<you>/potocus.git` | Install on Kali without manual copy |
| Published package | `pip install potocus` | After we publish to PyPI (or a private index) |
| Wheel / artifact | `pip install ./dist/potocus-*.whl` | Air-gapped / pinned releases |

Typical production layout:

1. **Mac host** — Ollama + both models; API reachable on the LAN (`http://<mac-ip>:11434`).
2. **Kali VM** — `pip install potocus` (or install from git/wheel), set `POTOCUS_OLLAMA_BASE_URL` / `POTOCUS_OLLAMA_NATIVE_URL` to the Mac, then run `potocus …`.

Secrets stay in `.env` / environment variables. Engagement data stays in the workspace directory you choose at `workspace init`.

## Setup (dev)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # optional
```

Require both models in Ollama:

```bash
ollama list
# qwen3:8b
# hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M
```

## Quick start

```bash
potocus config test-ollama
potocus workspace init ./lab --mode unscoped
potocus session new --name "first-run"
potocus status
potocus chat
```

Scoped engagement:

```bash
potocus workspace init ./clientX-pentest --mode scoped
potocus scope add 10.10.20.0/24 --note "corp-vlan per ROE"
potocus scope check -- nmap -sn 10.10.20.5
potocus config classify -- nmap -sV 10.10.20.5
potocus session new --name "external-recon"
potocus chat
```

## CLI

| Command | Purpose |
|---|---|
| `potocus workspace` | init / switch / show / set-mode |
| `potocus scope` | add / remove / list / check |
| `potocus session` | new / list / resume / rename / close / set-phase |
| `potocus chat` | live orchestrator REPL (Ollama) |
| `potocus status` | workspace / session / phase / mode |
| `potocus config` | show / test-ollama / classify |

## Tests

Real filesystem + real classifiers — no mocks:

```bash
pytest -q
```
