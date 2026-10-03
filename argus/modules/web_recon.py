"""Web-разведка: заголовки безопасности, banner-grab, robots.txt.

v0.3: TLS-верификация включена (core.net), лимит на размер robots.txt,
понятные ошибки вместо проглатывания исключений.
"""
from __future__ import annotations

import asyncio
import re

from core.finding import Finding
from core.net import make_client

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:120] if m else ""


async def _run_async(target: str) -> list[Finding]:
    findings: list[Finding] = []
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    try:
        async with make_client(timeout=15) as client:
            resp = await client.get(target)
            headers = resp.headers
            missing = [h for h in SEC_HEADERS if h not in headers]

            findings.append(Finding(
                module="web", target=str(resp.url), category="web",
                severity="low" if missing else "info",
                data={
                    "status": resp.status_code,
                    "server": headers.get("server"),
                    "powered_by": headers.get("x-powered-by"),
                    "missing_security_headers": missing,
                    "title": _title(resp.text),
                },
            ))

            robots_url = f"{str(resp.url).rstrip('/')}/robots.txt"
            try:
                r_resp = await client.get(robots_url, timeout=8)
                if r_resp.status_code == 200:
                    findings.append(Finding(
                        module="web", target=robots_url, category="web",
                        data={"robots": r_resp.text[:2000]},
                    ))
            except Exception:
                pass  # robots часто отсутствует — не ошибка разведки
    except Exception as e:
        findings.append(Finding(
            module="web", target=target, category="web",
            data={"error": f"{type(e).__name__}: {e}"},
        ))
    return findings


def run(target: str) -> list[Finding]:
    return asyncio.run(_run_async(target))
