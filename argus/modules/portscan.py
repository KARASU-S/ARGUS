"""Высокоскоростной TCP-сканер портов с фнгерпринтингом сервисов.

Что исправлено по сравнению со старой версией:
  • TOP_PORTS расширен до ~110 реально значимых портов (было 30 — «только 80 порт»).
  • Конкурентность stealth-режима поднята с 50 до 800 соединений, убраны
    искусственные sleep-задержки — полный скан 65535 портов занимает минуты.
  • Баннер читается корректно (без «\\r\\n»-провкации, которая ломала молчаливые
    сервисы вроде RDP/VNC).
  • TLS/HTTP-фнгерпринт собирается для ВСЕХ потенциально-TLS/веб портов,
    включая нестандартные (https на 80/8080 больше не теряется).
  • Добавлены service / product / version / os_hint — максимальный вывод.
  • Валидация спецификации портов, ограниченные таймауты, гарантированное
    закрытие сокетов.
"""
from __future__ import annotations

import asyncio
import re
import ssl

from core.finding import Finding
from core.services import service_name, service_category

# ---------------------------------------------------------------------------
# Списки портов
# ---------------------------------------------------------------------------
TOP_PORTS: list[int] = sorted({
    21, 22, 23, 25, 43, 53, 69, 79, 80, 81, 88, 110, 111, 113, 123,
    135, 137, 139, 143, 161, 162, 179, 389, 427, 443, 444, 445, 465,
    512, 513, 514, 515, 548, 554, 587, 631, 636, 873, 902, 903, 990,
    992, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 1883, 2049,
    2121, 2375, 2376, 2379, 2380, 3000, 3128, 3268, 3269, 3306, 3372,
    3389, 3690, 4444, 4848, 4899, 5000, 5001, 5432, 5555, 5601, 5631,
    5672, 5679, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443,
    7001, 8000, 8001, 8008, 8009, 8080, 8081, 8082, 8083, 8086, 8088,
    8090, 8443, 8500, 8765, 8888, 9000, 9001, 9043, 9090, 9091, 9093,
    9100, 9200, 9300, 9418, 9999, 10000, 10250, 10255, 11211, 11434,
    15672, 27017, 27018, 28017, 31337, 33060, 34573, 49152, 50000,
    54328, 61532,
})

FULL_PORTS: list[int] = list(range(1, 65536))

# режим: (метка, список портов, aggressive, fingerprint, concurrency, timeout)
MODES: dict[str, tuple[str, list[int], bool, bool, int, float]] = {
    "1": ("Full scan + fingerprint (fast)", FULL_PORTS, False, True, 800, 1.0),
    "2": ("Top-110 + fingerprint", TOP_PORTS, False, True, 500, 1.5),
    "3": ("Full scan (all ports, no fingerprint)", FULL_PORTS, False, False, 1500, 0.6),
    "4": ("Aggressive full + fingerprint", FULL_PORTS, True, True, 2000, 0.7),
    "5": ("Aggressive top ports", TOP_PORTS, True, True, 1000, 1.0),
}

TLS_PORTS = {443, 465, 587, 636, 990, 992, 993, 995, 8443, 8883, 9093,
             5671, 2376, 6443, 5986, 11434, 27017}
HTTP_PORTS = {80, 81, 3000, 5000, 4444, 8000, 8008, 8080, 8081, 8082, 8083,
              8086, 8088, 8090, 8888, 9000, 9080, 9090, 9418, 8443, 9093}

MAX_BANNER_LEN = 300


def ports_range(arg: str) -> list[int]:
    """Разбор спецификации портов: '20-25,80,443'. Валидация против инъекций диапазона."""
    result: set[int] = set()
    for part in arg.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Некорректный диапазон портов: {part}")
            result.update(range(start, end + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"Порт вне диапазона: {p}")
            result.add(p)
    return sorted(result)


# ---------------------------------------------------------------------------
# Фнгерпринтинг по баннеру
# ---------------------------------------------------------------------------
_VERSION_RES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"SSH-\d\.\d-(OpenSSH)[_ ]([\w.~+-]+)", re.I), "{p} {v}"),
    (re.compile(r"SSH-\d\.\d-(libssh|Dropbox SSH)[_ ]?([\w.]*)", re.I), "{p} {v}"),
    (re.compile(r"(ProFTPD)\s*([\d.]+)", re.I), "{p} {v}"),
    (re.compile(r"(vsFTPd)\s*([\w.]+)", re.I), "{p} {v}"),
    (re.compile(r"(FileZilla Server)(?: version ([\w.]+))?", re.I), "{p} {v}"),
    (re.compile(r"(Microsoft FTP Service)(?: Version ([\w.]+))?", re.I), "{p} {v}"),
    (re.compile(r"(Postfix)\s*\([^)]*\)\s*([\w.]+)", re.I), "{p} {v}"),
    (re.compile(r"(Exim)\s+(\d[\w.-]+)", re.I), "{p} {v}"),
    (re.compile(r"(Sendmail)/([\w.]+)", re.I), "{p} {v}"),
    (re.compile(r"(Dovecot)(?:[^\n]{0,60})?", re.I), "{p}{v}"),
    (re.compile(r"(MongoDB)", re.I), "{p}{v}"),
    (re.compile(r"(Redis)", re.I), "{p}{v}"),
    (re.compile(r"(Jetty)(?:[/ ]([\d.]+))?", re.I), "{p} {v}"),
    (re.compile(r"(Apache)[-/]([\d.]+)", re.I), "{p} {v}"),
    (re.compile(r"(nginx)[/ ]?([\d.]*)", re.I), "{p} {v}"),
    (re.compile(r"(Microsoft-IIS)[/ ]?([\d.]*)", re.I), "{p} {v}"),
]

_OS_BY_SIG = {
    "microsoft-iis": "Windows", "ms ftp": "Windows", "winapi": "Windows",
    "exchange": "Windows", "iis": "Windows",
    "nginx": "Linux/Unix", "apache": "Linux/Unix", "openssh": "Linux/Unix",
    "glibc": "Linux/Unix", "dovecot": "Linux/Unix", "postfix": "Linux/Unix",
    "exim": "Linux/Unix", "cisco": "Cisco IOS", "juniper": "Juniper Junos",
    "mikrotik": "MikroTik RouterOS", "synology": "Synology DSM (Linux)",
    "qnap": "QNAP QTS (Linux)", "ubiquiti": "UniFi (Linux)",
}

_WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}


def _extract_version(banner: str) -> tuple[str | None, str | None]:
    """Вернуть (version, product) из баннера."""
    for rx, tmpl in _VERSION_RES:
        m = rx.search(banner)
        if m:
            groups = m.groups()
            prod = groups[0] if groups else ""
            ver = groups[1] if len(groups) > 1 else None
            product = tmpl.replace("{p}", prod or "").replace("{v}", ver or "").strip()
            return ver, product
    return None, None


def _os_hint(port: int, text: str) -> str | None:
    low = text.lower()
    for key, os_name in _OS_BY_SIG.items():
        if key in low:
            return os_name
    if port in _WINDOWS_PORTS:
        return "Windows (вероятно)"
    if port == 22 and "openssh" in low:
        return "Linux/Unix (вероятно)"
    return None


async def _read_banner(reader: asyncio.StreamReader, timeout: float) -> str:
    """Прочитать баннер, ничего не отправляя (безопасно для молчаливых сервисов)."""
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
    except Exception:
        data = b""
    return data.decode(errors="ignore").strip()[:MAX_BANNER_LEN]


async def _http_probe(host: str, port: int, timeout: float) -> dict:
    """Мини-фнгерпринт HTTP(S)-сервера: HEAD-запрос сначала по TLS, затем plain."""
    out: dict = {}
    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ARGUS/0.3\r\nConnection: close\r\n\r\n"
    for use_tls in (True, False):
        writer = None
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # только заголовок Server:, данных нет
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx if use_tls else None,
                                        server_hostname=host if use_tls else None),
                timeout=timeout,
            )
            writer.write(req.encode())
            await writer.drain()
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
            text = raw.decode(errors="ignore")
            m_srv = re.search(r"^Server:\s*(.+)$", text, re.M | re.I)
            m_code = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text)
            if m_srv or m_code:
                if m_srv:
                    out["http_server"] = m_srv.group(1).strip()[:120]
                if m_code:
                    out["http_status"] = m_code.group(1)
                out["https"] = use_tls
                break
        except Exception:
            continue
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
    return out


async def _tls_info(host: str, port: int, timeout: float) -> dict:
    writer = None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # цель — собрать метаданные сертификата цели
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
        cipher = writer.get_extra_info("cipher")
        info: dict = {"present": True}
        if cipher:
            info["protocol"] = cipher[1] if len(cipher) > 2 else ""
            info["cipher"] = cipher[0]
        try:
            cert = writer.get_extra_info("ssl_object").getpeercert()
        except Exception:
            cert = None
        if cert:
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            info["cn"] = subject.get("commonName", "")
            info["org"] = issuer.get("organizationName", "")
            info["not_after"] = cert.get("notAfter", "")
            sans = [d[1] for d in cert.get("subjectAltName", ()) if d[0] == "DNS"]
            if sans:
                info["san"] = sans[:20]
        return info
    except Exception:
        return {}
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def scan_port(host: str, port: int, timeout: float = 1.5,
                    fingerprint: bool = True) -> dict | None:
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        result: dict = {"port": port, "state": "open"}

        banner = ""
        if fingerprint:
            banner = await _read_banner(reader, timeout=min(timeout, 1.2))
        result["banner"] = banner

        result["service"] = service_name(port)
        result["category"] = service_category(port)
        if banner:
            ver, product = _extract_version(banner)
            if product:
                result["product"] = product
            if ver:
                result["version"] = ver

        if fingerprint:
            tls = {}
            if port in TLS_PORTS or port in HTTP_PORTS:
                tls = await _tls_info(host, port, timeout=min(timeout, 2.5))
            if tls.get("present"):
                result["tls"] = tls
                if port in (80, 8080, 8000, 8008) and result["service"] == "http":
                    result["service"] = "https"
            else:
                if port in HTTP_PORTS:
                    http = await _http_probe(host, port, timeout=min(timeout, 2.5))
                    if http:
                        result["http"] = http
                        srv = http.get("http_server", "")
                        sv, sp = _extract_version(srv)
                        if sp:
                            result.setdefault("product", sp)
                        if sv:
                            result.setdefault("version", sv)

        hint = _os_hint(port, f"{banner} {result.get('product', '')} "
                              f"{result.get('tls', {}).get('cn', '')} "
                              f"{result.get('http', {}).get('http_server', '')}")
        if hint:
            result["os_hint"] = hint

        return result
    except Exception:
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def run_scan(host: str, ports: list[int], concurrency: int = 800,
                   aggressive: bool = False, fingerprint: bool = True,
                   timeout: float | None = None) -> list[Finding]:
    if timeout is None:
        timeout = 0.7 if aggressive else 1.5
    sem = asyncio.Semaphore(concurrency)
    findings: list[Finding] = []
    total = len(ports)
    done = 0
    step = max(1, total // 20)

    async def worker(p: int):
        nonlocal done
        async with sem:
            res = await scan_port(host, p, timeout=timeout, fingerprint=fingerprint)
            if res:
                findings.append(Finding(
                    module="portscan",
                    target=f"{host}:{p}",
                    category="port",
                    data=res,
                ))
            done += 1
            if total > 1000 and done % step == 0:
                print(f"\r  прогресс: {done}/{total} портов, открыто: {len(findings)}",
                      end="", flush=True)

    await asyncio.gather(*(worker(p) for p in ports))
    if total > 1000:
        print("\r" + " " * 60 + "\r", end="")

    findings.sort(key=lambda x: x.data["port"])
    return findings
