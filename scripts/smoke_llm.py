"""Check the configured OpenAI-compatible endpoint. Never prints the API key."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI


def main() -> int:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    api_key = os.environ.get("LLM_API_KEY", "").strip()
    if not api_key:
        print("LLM_API_KEY missing")
        return 1

    base_url = os.environ.get("LLM_BASE_URL", "").strip()
    model = os.environ.get("LLM_MODEL", "").strip()
    request: dict = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: PONG"}],
        "max_tokens": 8,
        "temperature": 0,
    }
    if "deepseek" in model.lower():
        request["extra_body"] = {"thinking": {"type": "disabled"}}

    client = OpenAI(api_key=api_key, base_url=base_url)
    try:
        response = client.chat.completions.create(**request)
    except Exception as exc:  # noqa: BLE001 - provider errors vary; the key is redacted below.
        print(str(exc).replace(api_key, "[redacted]"))
        return 1

    reply = response.choices[0].message.content or ""
    print("api_ok")
    print(reply)
    print(model)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
