"""crt.sh — поиск субдоменов по прозрачности сертификатов.

v0.3: ответ парсится как JSON с лимитом размера, TLS-верификация через core.net,
явная обработка пустого/битого ответа (раньше 502 от crt.sh молча терялся).
"""
from __future__ import annotations

import asyncio

import httpx

from core.finding import Finding
from core.net import make_client

MAX_JSON_BYTES = 10 * 1024 * 1024  # защита от memory-exhaustion


async def _run_async(domain: str) -> list[Finding]:
    try:
        async with make_client(timeout=40) as client:
            resp = await client.get(
                "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}
            )
            if len(resp.content) > MAX_JSON_BYTES:
                return [Finding(module="crtsh", target=domain, category="osint",
                                data={"error": "ответ crt.sh слишком большой"})]
            try:
                data = resp.json()
            except ValueError:
                return [Finding(module="crtsh", target=domain, category="osint",
                                data={"error": f"crt.sh вернул не JSON (HTTP {resp.status_code})"})]
            if not isinstance(data, list):
                return [Finding(module="crtsh", target=domain, category="osint",
                                data={"subdomains": [], "count": 0})]

            subdomains: set[str] = set()
            for item in data:
                for name in str(item.get("name_value", "")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and domain.lower() in name:
                        subdomains.add(name)

            subs = sorted(subdomains)
            return [Finding(
                module="crtsh", target=domain, category="osint",
                data={"subdomains": subs, "count": len(subs)},
            )]
    except httpx.HTTPError as e:
        return [Finding(module="crtsh", target=domain, category="osint",
                        data={"error": f"{type(e).__name__}: {e}"})]


def run(domain: str) -> list[Finding]:
    return asyncio.run(_run_async(domain))
