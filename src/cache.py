"""Offline run cache. The public demo reads this file and does not call a model.

P09 fills incident fields through save_run(). The AFCR summary is always copied
in from results/afcr_summary.json when that file exists.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[1]
SUMMARY_PATH = _REPO / "results" / "afcr_summary.json"
CACHE_PATH = _REPO / "results" / "run_cache.json"


def load_afcr_summary(path: str | Path | None = None) -> dict[str, Any] | None:
    """Return the saved summary, or None when the file is absent."""
    summary = Path(path) if path is not None else SUMMARY_PATH
    if not summary.exists():
        return None
    data = json.loads(summary.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return None
    return data


def save_run(
    payload: dict[str, Any],
    *,
    cache_path: str | Path | None = None,
    summary_path: str | Path | None = None,
) -> Path:
    """Write results/run_cache.json, including afcr_summary when the summary file exists."""
    target = Path(cache_path) if cache_path is not None else CACHE_PATH
    body = dict(payload)
    summary = load_afcr_summary(summary_path)
    if summary is not None:
        body["afcr_summary"] = summary
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return target


def load_run(path: str | Path | None = None) -> dict[str, Any]:
    """Read the offline cache."""
    target = Path(path) if path is not None else CACHE_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("run cache must be a JSON object")
    return data
