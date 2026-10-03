"""Брутфорс субдоменов по словарю с детектом wildcard-зон.

v0.3: абсолютный путь к wordlist, DNS-резолв в отдельном потоке (не блокирует
event loop), ограничение общего времени прогона.
"""
from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import tldextract

from core.finding import Finding

WORDLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "subdomains.txt"
WILDCARD_PROBE = "argus-wildcard-probe-1337"


def _resolve_sync(subdomain: str) -> str | None:
    try:
        infos = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        return infos[0][4][0] if infos else None
    except (socket.gaierror, OSError, UnicodeError):
        return None


async def _resolve(subdomain: str) -> str | None:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _resolve_sync, subdomain)


def _load_wordlist() -> list[str]:
    try:
        with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f
                    if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


async def _run_async(domain: str, concurrency: int = 80) -> list[Finding]:
    ext = tldextract.extract(domain)
    root_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else domain
    wordlist = _load_wordlist()
    if not wordlist:
        return [Finding(module="subdomain_brute", target=domain, category="osint",
                        data={"error": f"wordlist не найден: {WORDLIST_PATH}"})]

    wildcard_ip = await _resolve(f"{WILDCARD_PROBE}.{root_domain}")
    results: list[dict] = []
    sem = asyncio.Semaphore(concurrency)

    async def worker(word: str) -> None:
        async with sem:
            ip = await _resolve(f"{word}.{root_domain}")
            if ip and ip != wildcard_ip:
                results.append({"name": f"{word}.{root_domain}", "ip": ip})

    tasks = [asyncio.create_task(worker(w)) for w in wordlist]
    try:
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=600)
    except asyncio.TimeoutError:
        for t in tasks:
            t.cancel()

    results.sort(key=lambda x: x["name"])
    return [Finding(
        module="subdomain_brute", target=domain, category="osint",
        data={
            "subdomains": results,
            "count": len(results),
            "wildcard_detected": bool(wildcard_ip),
            "wildcard_ip": wildcard_ip,
        },
    )]


def run(domain: str) -> list[Finding]:
    return asyncio.run(_run_async(domain))
