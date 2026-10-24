# Titan.Log

A trust layer between an AI SOC verdict and the action.

Live demo (read-only, cached results, no live model): https://titan-log.focampo.com

Write-up: [WRITEUP.md](WRITEUP.md)

## Quickstart

```bash
uv venv
source .venv/bin/activate
uv sync
cp .env.example .env
streamlit run app.py
```

The sidebar checkbox **Use cache (offline demo)** is on by default. That path reads `results/run_cache.json` and does not call a model. For a public-style run with no key:

```bash
DEMO_READONLY=1 LLM_API_KEY=
streamlit run app.py
```

## What it is

Titan.Log sits between an AI security-operations verdict and the action a human or a playbook would take. Detectors and a correlator group real log rows into one incident. The model proposes claims. The Oracle checks each claim against the cited row. A gate then recommends `disable_account`, asks a human, or denies the action, and writes a local audit line.

## Demo data

| Path | What it is |
| --- | --- |
| `results/run_cache.json` | Cached live triage of the real OTRF files: event counts, claims, Oracle verdicts, and the gate. |
| `results/afcr_summary.json` | SIMULATED injection results for three arms and two models. Counts are `x of n`. |
| `demo/forged_incident.jsonl` | Real OTRF rows plus two SIMULATED injection lines, two malformed lines, and one ambiguous line. See [demo/README.md](demo/README.md). |

REAL means a row copied from OTRF Security-Datasets. SIMULATED means an injection inserted by this project and labeled `_titan_label` `SIMULATED_INJECTION`. The public demo serves the cache. It does not call a model.

## Repo layout

- `app.py` — Streamlit analyst console
- `src/` — ingest, detectors, correlator, Oracle, gate, cache, metrics
- `src/titanlog/` — public `triage` and `verify` API and log adapters
- `config/field_map.yaml` — source-field map for a new log format
- `tests/` — pytest
- `data/otrf/` — the two P0 OTRF JSON files
- `demo/forged_incident.jsonl` — the forged-incident file
- `results/run_cache.json`, `results/afcr_summary.json` — committed demo results
- `pitch/` — pitch assets

## OTRF dataset citations

The JSON files under `data/otrf/` come from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT). SHA-256 values are the original zip archives from that project's `SHA256SUMS`, as recorded in `data/otrf/SOURCE.md`.

| JSON file | Original zip | SHA-256 |
| --- | --- | --- |
| `psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json` | `psh_lsass_memory_dump_comsvcs.zip` | `0af9e920220d746432f0972be83ad057629695540aecd68c15869d190786e1ae` |
| `empire_psexec_dcerpc_tcp_svcctl_2020-09-20121608.json` | `empire_psexec_dcerpc_tcp_svcctl.zip` | `8f40e7fc86bbbf31ebd50b3ba537cf0f4378392ae3e74de84bee00aeb0de1fa5` |

## AI usage

- Runtime: OpenAI-compatible via `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` (default DeepSeek `deepseek-flash`; Nebius Token Factory fallback, `LLM_BASE_URL=https://api.tokenfactory.nebius.com/v1/`; second-model eval with `Qwen/Qwen3-30B-A3B-Instruct-2507`). Never hardcode keys.
- Authoring: AI coding agents (Claude Code / Roo Code / Cursor), reviewed by the author.
- Deterministic code: ingest/quarantine, detectors, correlator, Oracle, gate, AFCR math.

Copy `.env.example` to `.env` and fill the key locally. `.env` and `.env.nebius` are gitignored.

## Public demo on Railway

https://titan-log.focampo.com serves this repo read-only.

- Set `DEMO_READONLY=1`.
- Do not set `LLM_BASE_URL`, `LLM_API_KEY`, or `LLM_MODEL` on the public service.
- The app reads `results/run_cache.json`. It does not call a model.
