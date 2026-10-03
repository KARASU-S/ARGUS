"""WHOIS-разведка.

v0.3: данные нормализуются (даты/списки), поле error не теряется, таймаут
процесса резолвера ограничивается самой библиотекой; вывод — максимум полезного.
"""
from __future__ import annotations

import whois
from core.finding import Finding


def run(domain: str) -> list[Finding]:
    try:
        w = whois.whois(domain)
        raw = dict(w)
        data = {}
        for k, v in raw.items():
            if not v:
                continue
            if isinstance(v, (list, tuple)):
                data[k] = [str(x)[:200] for x in v][:20]
            else:
                data[k] = str(v)[:500]
        if not data:
            return [Finding(module="whois", target=domain, category="osint",
                            data={"note": "пустой ответ регистратора"})]
        return [Finding(module="whois", target=domain, category="osint", data=data)]
    except Exception as e:
        return [Finding(module="whois", target=domain, category="osint",
                        data={"error": f"{type(e).__name__}: {e}"})]
