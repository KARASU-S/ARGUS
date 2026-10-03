"""ARGUS v0.3 — оркестратор разведки.

Что изменено в v0.3:
  • Удалён GitHub-модуль (требовал токен / давал 403 без него) — никакого кода,
    где нужен токен, в инструменте не осталось.
  • Убраны ~250 строк копипасты: режимы и модули описаны декларативно,
    общий раннер _run_module / _run_all.
  • Дедупликация находок через Finding.dedup_key (sha256 от payload).
  • Максимальный консольный вывод: порты с состоянием, сервисом, продуктом,
    версией, баннером, TLS, подсказкой ОС + сводка по ОС/аппаратной платформе.
  • Исправлен mode=q: при пустом кэше теперь запускает полную разведку, а не
    молча завершается.
  • Пути к data/, reports/, ai/ — абсолютные относительно файла модуля
    (работа из любой директории).
  • Все внешние запросы идут через core.net с честной проверкой TLS
    (убран verify=False), SSL-зонды portscan используют отдельную политику.
"""
from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.finding import Finding
from core.menu import banner, show_menu
from core.ai_engine import AIEngine
from core.cache import Cache
from core.services import guess_os
import modules.portscan as portscan
import modules.dns_recon as dns_recon
import modules.whois_recon as whois_recon
import modules.crtsh as crtsh
import modules.web_recon as web_recon
from modules import subdomain_brute, tech_fingerprint
from report import html_report

app = typer.Typer(add_completion=False)
console = Console()

# допустимые символы цели: hostname/IP/URL без инъекций пути и спецсимволов
TARGET_RX = re.compile(r"^[A-Za-z0-9._~:/#@%\[\]-]{1,253}$")

# ---------------------------------------------------------------------------
# Декларативное описание немодульных режимов и модулей (устранение копипасты)
# ---------------------------------------------------------------------------
MODULES: dict[str, dict] = {
    "6": {"name": "dns", "func": dns_recon.run, "label": "DNS recon"},
    "7": {"name": "whois", "func": whois_recon.run, "label": "WHOIS recon"},
    "8": {"name": "crtsh", "func": crtsh.run, "label": "crt.sh subdomains"},
    "10": {"name": "web", "func": web_recon.run, "label": "Web recon"},
    "s": {"name": "subdomain_brute", "func": subdomain_brute.run, "label": "Subdomain brute"},
    "t": {"name": "tech_fingerprint", "func": tech_fingerprint.run, "label": "Tech fingerprint"},
}


def valid_target(target: str) -> str:
    target = target.strip().strip("/")
    if not TARGET_RX.match(target):
        raise ValueError(f"Некорректная цель: {target!r}")
    return target


def dedup(findings: list[Finding]) -> list[Finding]:
    """Удалить дубликаты находок (кэш + повторные запуски дают их десятками)."""
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        key = f.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def save_report(target: str, findings: list[Finding]) -> Path:
    reports_dir = Path(__file__).resolve().parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:80]
    filename = reports_dir / f"{safe}_{ts}.json"
    filename.write_text(
        json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    console.print(f"[green]Отчёт сохранён: {filename}[/green]")
    return filename


# ---------------------------------------------------------------------------
# Максимальный консольный вывод
# ---------------------------------------------------------------------------
def show_full_results(findings: list[Finding]) -> None:
    ports = [f for f in findings if f.category == "port"]
    if ports:
        table = Table(title=f"Порты — {len(ports)} открытых (ВСЕ, без обрезки)",
                      expand=True)
        table.add_column("Порт", justify="right", style="cyan", no_wrap=True)
        table.add_column("State", style="green", no_wrap=True)
        table.add_column("Сервис", style="magenta", no_wrap=True)
        table.add_column("Продукт / версия", style="yellow")
        table.add_column("TLS / HTTP", overflow="fold")
        table.add_column("Баннер", style="dim", overflow="fold")
        table.add_column("ОС-подсказка", style="blue", no_wrap=True)
        for f in ports:
            d = f.data
            tls = d.get("tls") or {}
            http = d.get("http") or {}
            proto = []
            if tls:
                proto.append(f"TLS {tls.get('protocol','')} {tls.get('cipher','')}".strip())
                if tls.get("cn"):
                    proto.append(f"CN={tls['cn']}")
                if tls.get("not_after"):
                    proto.append(f"до {tls['not_after']}")
            if http:
                proto.append(("HTTPS " if http.get("https") else "HTTP ")
                             + f"{http.get('http_status','')} {http.get('http_server','')}".strip())
            table.add_row(
                str(d["port"]),
                d.get("state", "open"),
                d.get("service", ""),
                " ".join(x for x in (d.get("product", ""), d.get("version", "")) if x),
                "\n".join(proto),
                (d.get("banner") or "")[:120],
                d.get("os_hint", ""),
            )
        console.print(table)

        osinfo = guess_os([f.to_dict() for f in ports])
        t2 = Table(title="Предположение об ОС / аппаратной платформе", show_lines=False)
        t2.add_column("Параметр", style="cyan")
        t2.add_column("Значение", overflow="fold")
        t2.add_row("ОС", str(osinfo.get("os_guess")))
        t2.add_row("Уверенность", str(osinfo.get("confidence")))
        t2.add_row("Метод", str(osinfo.get("method", "")))
        t2.add_row("Сигналы", "\n".join(osinfo.get("signals", [])))
        console.print(t2)

    other = [f for f in findings if f.category != "port"]
    if other:
        by_mod: dict[str, int] = {}
        for f in other:
            by_mod[f.module] = by_mod.get(f.module, 0) + 1
        t3 = Table(title="Прочие находки по модулям")
        t3.add_column("Модуль", style="magenta")
        t3.add_column("Количество", justify="right", style="cyan")
        for m, c in sorted(by_mod.items()):
            t3.add_row(m, str(c))
        console.print(t3)


# ---------------------------------------------------------------------------
# Общие исполнители (замена 250 строк копипасты)
# ---------------------------------------------------------------------------
def _load_cached(cached: list[dict]) -> list[Finding]:
    return [Finding(**{k: v for k, v in c.items() if k != "ts"}) for c in cached]


def _run_portscan_mode(target: str, m: str, cache: Cache, no_cache: bool) -> list[Finding]:
    cache_key = f"portscan:{target}:{m}"
    if not no_cache and (cached := cache.get(cache_key)):
        console.print(f"[dim]Из кэша: {cache_key} ({len(cached)} записей)[/dim]")
        return _load_cached(cached)
    label, ports, aggressive, fingerprint, concurrency, timeout = portscan.MODES[m]
    console.print(f"[yellow]Запуск: {label} ({len(ports)} портов)…[/yellow]")
    res = asyncio.run(portscan.run_scan(
        target, ports, concurrency=concurrency,
        aggressive=aggressive, fingerprint=fingerprint, timeout=timeout,
    ))
    cache.set(cache_key, [f.to_dict() for f in res])
    return res


def _run_module(target: str, mid: str, cache: Cache, no_cache: bool) -> list[Finding]:
    mod = MODULES[mid]
    cache_key = f"{mod['name']}:{target}:default"
    if not no_cache and (cached := cache.get(cache_key)):
        console.print(f"[dim]Из кэша: {cache_key}[/dim]")
        return _load_cached(cached)
    res = mod["func"](target)
    cache.set(cache_key, [f.to_dict() for f in res])
    console.print(f"[green]{mod['label']} завершён. Найдено: {len(res)}[/green]")
    return res


ALL_CACHE_KEYS = (
    [f"portscan:{{t}}:{m}" for m in portscan.MODES]
    + [f"{mod['name']}:{{t}}:default" for mod in MODULES.values()]
)


def _run_all(target: str, cache: Cache, no_cache: bool) -> list[Finding]:
    findings: list[Finding] = []
    findings += _run_portscan_mode(target, "2", cache, no_cache)
    for mid in MODULES:
        try:
            findings += _run_module(target, mid, cache, no_cache)
        except Exception as e:
            console.print(f"[red]{MODULES[mid]['label']}: {e}[/red]")
    return findings


def _analyze_with_ai(findings: list[Finding]) -> None:
    ai = AIEngine()
    ai.analyze([f.to_dict() for f in findings])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
@app.command()
def main(
    target: str = typer.Option(None, "--target", "-t", help="Цель (domain/ip)"),
    mode: str = typer.Option(None, "--mode", "-m",
                             help="1-5 портскан, 6 DNS, 7 WHOIS, 8 crt.sh, 10 Web, "
                                  "s субдомены, t технологии, a всё, q полный цикл + AI"),
    ports: str = typer.Option(None, "--ports", "-p",
                              help="Свой диапазон портов, напр. '20-100,443,3389' (вместо mode)"),
    output: bool = typer.Option(False, "--html", help="Сохранить HTML-отчёт"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Не запускать AI"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Игнорировать кэш"),
) -> None:
    cache = Cache()

    # ---------- интерактивный режим ----------
    if not target:
        console.print(banner())
        raw = Prompt.ask("Укажи цель")
        try:
            target = valid_target(raw)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1)

        findings: list[Finding] = []
        while True:
            show_menu()
            choice = Prompt.ask("Выбор").strip().lower()
            if choice == "0":
                break
            try:
                if choice in portscan.MODES:
                    findings += _run_portscan_mode(target, choice, cache, no_cache)
                elif choice in MODULES:
                    findings += _run_module(target, choice, cache, no_cache)
                elif choice == "h":
                    path = html_report.save(target, dedup(findings))
                    console.print(f"[green]HTML: {path}[/green]")
                elif choice == "a":
                    console.print("[yellow]Запуск ALL recon…[/yellow]")
                    findings += _run_all(target, cache, no_cache)
                    show_full_results(dedup(findings))
                elif choice == "q":
                    if not findings:
                        console.print("[yellow]Нет данных — запускаю полную разведку…[/yellow]")
                        findings += _run_all(target, cache, no_cache)
                    uniq = dedup(findings)
                    show_full_results(uniq)
                    save_report(target, uniq)
                    _analyze_with_ai(uniq)
                else:
                    console.print("[red]Неизвестный пункт[/red]")
            except Exception as e:
                console.print(f"[red]Ошибка в модуле: {e}[/red]")
        return

    # ---------- неинтерактивный (CLI) режим ----------
    try:
        target = valid_target(target)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    findings: list[Finding] = []
    try:
        if ports:
            plist = portscan.ports_range(ports)
            console.print(f"[yellow]Скан {len(plist)} заданных портов…[/yellow]")
            findings += asyncio.run(portscan.run_scan(target, plist, concurrency=500))
        else:
            m = (mode or "a").lower()
            if m in portscan.MODES:
                findings += _run_portscan_mode(target, m, cache, no_cache)
            elif m in MODULES:
                findings += _run_module(target, m, cache, no_cache)
            elif m == "a":
                findings += _run_all(target, cache, no_cache)
            elif m == "q":
                # сначала пробуем кэш, если пусто — полная разведка (исправлено!)
                for ck in ALL_CACHE_KEYS:
                    cached = cache.get(ck.format(t=target))
                    if cached:
                        findings += _load_cached(cached)
                if not findings:
                    console.print("[yellow]Кэш пуст — выполняю полную разведку…[/yellow]")
                    findings += _run_all(target, cache, no_cache)
            else:
                console.print(f"[red]Неизвестный режим: {m}[/red]")
                raise typer.Exit(2)

        findings = dedup(findings)
        show_full_results(findings)
        save_report(target, findings)
        if output:
            path = html_report.save(target, findings)
            console.print(f"[green]HTML: {path}[/green]")
        if (mode or "a").lower() == "q" and not no_ai and findings:
            _analyze_with_ai(findings)
    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Ошибка: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
