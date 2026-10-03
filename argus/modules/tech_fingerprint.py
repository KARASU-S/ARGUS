"""Tech fingerprint по YAML-сигнатурам.

v0.3: путь к сигнатурам абсолютный (старый ронял модуль при запуске из другой
директории), TLS-верификация через core.net, fallback на http:// если https
не поднимается.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import yaml

from core.finding import Finding
from core.net import make_client

SIGNATURES_PATH = Path(__file__).resolve().parent.parent / "data" / "tech_signatures.yaml"


def _load_signatures() -> dict:
    try:
        with open(SIGNATURES_PATH, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


async def _probe(client, url: str, signatures: dict) -> list[str] | None:
    try:
        resp = await client.get(url)
    except Exception:
        return None
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    html_text = resp.text
    found: list[str] = []
    for tech_name, sigs in signatures.items():
        if not isinstance(sigs, dict):
            continue
        hit = False
        for hdr_key, hdr_regex in (sigs.get("headers") or {}).items():
            val = headers_lower.get(hdr_key.lower(), "")
            if val and re.search(str(hdr_regex), str(val), re.I):
                hit = True
                break
        if not hit:
            for html_regex in (sigs.get("html") or []):
                if re.search(str(html_regex), html_text, re.I):
                    hit = True
                    break
        if hit:
            found.append(tech_name)
    return sorted(found)


async def _run_async(target: str) -> list[Finding]:
    signatures = _load_signatures()
    base = target if target.startswith(("http://", "https://")) else f"https://{target}"
    urls = [base]
    if base.startswith("https://"):
        urls.append("http://" + base[len("https://"):])

    async with make_client(timeout=15) as client:
        for url in urls:
            techs = await _probe(client, url, signatures)
            if techs is not None:
                return [Finding(
                    module="tech_fingerprint", target=url, category="web",
                    data={"technologies": techs, "count": len(techs)},
                )]
    return [Finding(
        module="tech_fingerprint", target=target, category="web",
        data={"error": "цель недоступна по HTTP/HTTPS"},
    )]


def run(target: str) -> list[Finding]:
    return asyncio.run(_run_async(target))
