# Titan.Log — agent rules

## Mission
Build Titan.Log: an AUTONOMOUS L1/L2 incident triage & investigation agent (correlate, investigate, decide severity, recommend/take a gated action) that cannot be manipulated by attacker-written logs. Main demo on REAL OTRF logs; injections are a labeled SIMULATED overlay. Robust ingest (skip+count+quarantine; unknown → human "insufficient evidence"). Structured claims + deterministic Oracle. Three arms for AFCR: naive (CONTROL only), hardened_prompt (quarantine tags + do-not-obey, NO Oracle), titan (quarantine + Oracle). AFCR = adversarial false-close rate. temperature=0; prefer 3 runs × 12 variants × 3 arms (cache); else 1 run/variant. P0: 2 OTRF files (comsvcs, psexec), 6 verifiers, simple JSONL audit (no hash chain). Public Railway demo READ-ONLY on run_cache.json (no live LLM buttons). UI Streamlit optional / FastAPI+Jinja OK. All user-facing text, docs and pitch in English; code in English.

## Stack (do not change without asking)
- Python 3.12, Streamlit, pandas, pydantic v2, openai SDK (OpenAI-compatible), python-dotenv, orjson, pytest
- Runtime LLM: provider-agnostic via LLM_BASE_URL, LLM_API_KEY, LLM_MODEL (local .env + Railway Variables)
- Default: LLM_BASE_URL=https://api.deepseek.com, LLM_MODEL=deepseek-flash, thinking disabled for AFCR when supported
- Fallback: Nebius Token Factory (OpenAI-compatible). Copy base URL / key / model ID from the Token Factory console — NEVER hardcode a Nebius URL or model ID
- Keys: create at scaffold; .env chmod 600; spending limit / low balance; never commit; revoke after event
- Deploy ONLY if P0 done by 14:45; URL https://titan-log.focampo.com must be READ-ONLY (serve run_cache.json, no live LLM). Else skip deploy, demo laptop + cache
- Path: ~/Proyectos/titan-log (repo git@github.com:focampok/titanlog.git) ; copy only comsvcs + psexec JSON into data/otrf/ for P0 (schtask/mimikatz = P1)
- Data: local JSONL under data/otrf/ (OTRF Security-Datasets, MIT). Do not re-download in prompts unless missing.

## Plug-in layer rules (adoption)
- Titan.Log is a LAYER, not a platform: sits between AI triage agents and the action; feeds the human analyst via gate + audit.
- All input goes through `Adapter.to_events()` → common event schema with ECS-like names (process.command_line, process.executable, process.parent.executable, host.name, user.name, event.code, winlog.channel, service.name, file.path, @timestamp, row_id, raw).
- Adapters: OtrfSysmonAdapter + GenericJsonlAdapter(field_map YAML at config/field_map.yaml). New log source = edit YAML, not code.
- Public API (src/titanlog/__init__.py): `triage(events) -> Incident` and `verify(claims, events) -> list[Verdict]`, JSON-serializable (`.model_dump_json()`), so any agent framework can call it.
- Keep LLM provider-agnostic (LLM_BASE_URL / LLM_API_KEY / LLM_MODEL).
- P1 only if time: FastAPI `/verify` + Dockerfile. Post-event: OCSF mapping, Splunk/Elastic/Sentinel connectors.

## Hard rules
1. NEVER read, print, log, or commit secrets. .env is gitignored. Use os.environ["LLM_API_KEY"] (and LLM_BASE_URL / LLM_MODEL). Never hardcode provider URLs beyond the DeepSeek default.
2. All user-facing text, docs and pitch in English (WRITEUP.md, README, AI usage, dataset citations, UI labels, pitch, Q&A). Planning notes for Francisco may stay Spanish.
3. NEVER invent metrics. All numbers come from code over real files or results/run_cache.json.
4. Label every synthetic injection with simulated=true. Show a SIMULATED badge in UI for injection views.
5. Do not scan or attack external systems. Containment is a local mock writing JSONL.
6. Prefer small files: src/ingest.py, detectors.py, correlate.py, claims.py, oracle.py, inject.py, agents.py, gate.py, metrics.py, app.py
7. After each task: add/adjust pytest for the pure functions touched; keep green.
8. Commits: small, conventional messages (feat:, fix:, docs:).
9. If behind: drop Railway first, then Nebius AFCR, then FastAPI/Docker, then P1 datasets/verifiers/hash-chain; never drop Oracle or AFCR cache. Prefer 1 AFCR run/variant over skipping arms.

## Claim contract
P0 ClaimTypes (6): process_executed, lsass_access, service_installed, encoded_powershell, authorization (deliberate stub→REJECTED; prod would query ServiceNow/Jira), attack_technique. Declare I10/I11 split-context as known limitation.

## Definition of done for demo
Three tabs from run_cache offline; AFCR table shows 3 arms; I01: naive vs hardened_prompt vs Titan.Log; gate DENY on rejected evidence; audit JSONL simple; pitch mentions authorization stub + I10/I11 (+ optional Nebius cross-model if ran); docs+AI usage; public site READ-ONLY if deployed.
