"""DNS-разведка: базовые записи + DMARC/SPF.

v0.3: различаем NXDOMAIN/NOERROR (раньше всё глоталось в except pass),
собираем SPF/DMARC отдельными находками с оценкой риска.
"""
from __future__ import annotations

import dns.resolver
import dns.exception

from core.finding import Finding

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]


def _query(domain: str, rtype: str) -> tuple[list[str], str | None]:
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        return [str(rdata) for rdata in answers], None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NOERROR (записи нет)"
    except dns.resolver.NoNameservers:
        return [], "NoNameservers"
    except (dns.exception.DNSException, OSError) as e:
        return [], f"{type(e).__name__}: {e}"


def run(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    nxdomain = False
    for rt in RECORD_TYPES:
        values, err = _query(domain, rt)
        if err == "NXDOMAIN":
            nxdomain = True
        if values:
            findings.append(Finding(
                module="dns", target=domain, category="dns",
                data={"type": rt, "values": values},
            ))

    if nxdomain:
        findings.append(Finding(
            module="dns", target=domain, category="dns", severity="info",
            data={"error": "NXDOMAIN — домен не зарегистрирован"},
        ))
        return findings

    # почтовая безопасность
    for label, sev_missing in (("_dmarc", "medium"), ):
        d = f"{label}.{domain}"
        values, _ = _query(d, "TXT")
        if values:
            findings.append(Finding(
                module="dns", target=d, category="dns",
                data={"type": "TXT", "values": values, "role": label.upper()},
            ))
        else:
            findings.append(Finding(
                module="dns", target=d, category="dns", severity=sev_missing,
                data={"issue": f"Отсутствует {label.upper()} — спуфинг почты не ограничен"},
            ))

    spf, _ = _query(domain, "TXT")
    has_spf = any(v.lower().startswith(("v=spf1", '"v=spf1')) for v in spf)
    if not has_spf:
        findings.append(Finding(
            module="dns", target=domain, category="dns", severity="medium",
            data={"issue": "Отсутствует SPF-запись"},
        ))
    elif any("+all" in v for v in spf):
        findings.append(Finding(
            module="dns", target=domain, category="dns", severity="high",
            data={"issue": "SPF содержит +all — любой сервер может отправлять почту от домена"},
        ))

    return findings
