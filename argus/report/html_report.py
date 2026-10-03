"""HTML-отчёт ARGUS v0.3.

Исправления:
  • Экранирование через html.escape (старый ручной _escape был ближе к XSS-багу,
    чем к защите — не обрабатывал корректно вложенность и атрибуты).
  • Полная таблица портов: состояние, сервис, продукт/версия, TLS, баннер,
    ОС-подсказка — максимальный вывод без обрезки данных.
  • Блок OS/hardware-выводов из guess_os.
  • CSP-заголовок внутри файла-meta + sandbox-friendly разметка.
  • Имя файла цели санитизируется (path traversal в reports/ исключён).
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from html import escape
from pathlib import Path

from core.finding import Finding
from core.services import guess_os

SEV_COLORS = {
    "critical": "#f44336", "high": "#ff9800", "medium": "#ffeb3b",
    "low": "#4caf50", "info": "#2196f3",
}


def _e(s) -> str:
    return escape(str(s), quote=True)


def _port_table(findings: list[Finding]) -> str:
    rows = []
    for f in sorted((f for f in findings if f.category == "port"),
                    key=lambda x: x.data.get("port", 0)):
        d = f.data
        tls = d.get("tls") or {}
        http = d.get("http") or {}
        proto = "<br>".join(filter(None, [
            _e(f"TLS {tls.get('protocol','')} {_e(tls.get('cipher',''))}".strip()) if tls else "",
            _e(f"CN={tls['cn']} (до {tls.get('not_after','')})") if tls.get("cn") else "",
            _e(f"{'HTTPS' if http.get('https') else 'HTTP'} {http.get('http_status','')} "
               f"{http.get('http_server','')}".strip()) if http else "",
        ]))
        rows.append(
            f"<tr><td>{_e(d.get('port'))}</td><td class='open'>{_e(d.get('state','open'))}</td>"
            f"<td>{_e(d.get('service',''))}</td>"
            f"<td>{_e((d.get('product') or '') + ' ' + (d.get('version') or '')).strip()}</td>"
            f"<td>{proto}</td><td class='banner'>{_e(d.get('banner',''))}</td>"
            f"<td>{_e(d.get('os_hint',''))}</td></tr>"
        )
    return ("<table><tr><th>Port</th><th>State</th><th>Service</th>"
            "<th>Product/Ver</th><th>TLS/HTTP</th><th>Banner</th><th>OS hint</th></tr>"
            + "".join(rows) + "</table>") if rows else "<p>Открытых портов не найдено.</p>"


def _render_finding(f: dict) -> str:
    sev = _e(f.get("severity", "info"))
    color = SEV_COLORS.get(f.get("severity", "info"), "#2196f3")
    data_str = json.dumps(f.get("data", {}), ensure_ascii=False, indent=2)
    if len(data_str) > 4000:
        data_html = f"<pre>{_e(data_str[:4000])}\n…[обрезано, полное в JSON-отчёте]</pre>"
    else:
        data_html = f"<pre>{_e(data_str)}</pre>"
    return (f"<div class='finding'><span class='badge' style='background:{color}'>{sev}</span>"
            f"<span class='module'>{_e(f.get('module',''))}</span>"
            f"<span class='target'>{_e(f.get('target',''))}</span>{data_html}</div>")


def build(target: str, findings: list[Finding]) -> str:
    dicts = [f.to_dict() for f in findings]
    ports = [f for f in findings if f.category == "port"]

    sev_counts: dict[str, int] = {}
    for f in dicts:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1
    sev_rows = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>"
                       for k, v in sorted(sev_counts.items()))

    os_block = ""
    if ports:
        info = guess_os([f.to_dict() for f in ports])
        signals = "".join(f"<li>{_e(s)}</li>" for s in info.get("signals", []))
        os_block = (
            "<h2>ОС / аппаратная платформа (пассивная оценка)</h2>"
            f"<p><b>Предположение:</b> {_e(info.get('os_guess'))} "
            f"(уверенность: {_e(info.get('confidence'))})</p>"
            f"<p><i>{_e(info.get('method',''))}</i></p><ul>{signals}</ul>"
        )

    other_html = "".join(_render_finding(f) for f in dicts if f.get("category") != "port")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ARGUS Report — {_e(target)}</title>
<style>
 body {{ background:#1e1e1e; color:#d4d4d4; font-family:monospace; margin:20px; }}
 h1,h2 {{ color:#569cd6; }}
 table {{ border-collapse:collapse; width:100%; margin-bottom:20px; }}
 th,td {{ border:1px solid #3e3e42; padding:6px; text-align:left; vertical-align:top; }}
 th {{ background:#2d2d30; }}
 td.open {{ color:#4caf50; font-weight:bold; }}
 td.banner {{ white-space:pre-wrap; word-break:break-all; max-width:420px; color:#9cdcfe; }}
 .finding {{ background:#252526; border:1px solid #3e3e42; padding:10px;
             margin-bottom:10px; border-radius:4px; }}
 .badge {{ padding:2px 6px; border-radius:3px; font-weight:bold; color:#fff; }}
 .module {{ color:#ce9178; font-weight:bold; margin-left:8px; }}
 .target {{ color:#9cdcfe; margin-left:8px; }}
 pre {{ background:#1e1e1e; padding:10px; overflow-x:auto; white-space:pre-wrap;
        word-break:break-all; }}
 footer {{ margin-top:40px; color:#858585; }}
</style>
</head>
<body>
<h1>ARGUS v0.3 Report — {_e(target)}</h1>
<h2>Summary</h2>
<p>Всего находок: {len(dicts)} (портов открыто: {len(ports)})</p>
<table><tr><th>Severity</th><th>Count</th></tr>{sev_rows}</table>
<h2>Порты и сервисы</h2>
{_port_table(findings)}
{os_block}
<h2>Прочие находки</h2>
{other_html or '<p>Нет прочих находок.</p>'}
<footer>Generated by ARGUS v0.3 — {ts}</footer>
</body>
</html>"""


def save(target: str, findings: list[Finding]) -> str:
    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:80]
    filename = reports_dir / f"{safe}_{ts}.html"
    filename.write_text(build(target, findings), encoding="utf-8")
    return str(filename)
