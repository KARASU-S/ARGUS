"""AI-анализ через локальную Ollama (без токенов и внешних API-ключей).

Исправления v0.3:
  • Никаких секретов: только локальный http://localhost:11434, host можно
    переопределить переменной окружения ARGUS_OLLAMA_HOST.
  • Хост валидируется на localhost/приватный адрес — SSRF через конфиг исключён.
  • Ошибка подключения даёт понятную рекомендацию, а не тихий fallback.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx
import ollama
from rich.console import Console

PROMPT_PATH = Path(__file__).resolve().parent.parent / "ai" / "prompts" / "system_pentest.md"


def _host_is_safe(host: str) -> bool:
    """Разрешаем только loopback/приватные сети — AI-движок локальный."""
    try:
        parsed = urlparse(host)
        addr = parsed.hostname or ""
        if addr in ("localhost", "127.0.0.1", "::1"):
            return True
        ip = ipaddress.ip_address(addr)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


class AIEngine:
    def __init__(self, model: str | None = None, host: str | None = None):
        self.host = host or os.environ.get("ARGUS_OLLAMA_HOST", "http://localhost:11434")
        if not _host_is_safe(self.host):
            raise ValueError(
                f"ARGUS AI работает только с локальной Ollama; хост {self.host} запрещён."
            )
        self.model = model or os.environ.get("ARGUS_OLLAMA_MODEL", "qwen2.5:3b")
        self.client = ollama.Client(host=self.host)
        self.system_prompt = PROMPT_PATH.read_text(encoding="utf-8")

    def _check_ollama(self) -> bool:
        try:
            resp = httpx.get(f"{self.host}/api/tags", timeout=3)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def _format_findings(self, findings: list[dict]) -> str:
        if not findings:
            return "нет данных"

        if len(findings) <= 60:
            lines = [f"[{f['category']}] {f['module']} @ {f['target']}: {f['data']}"
                     for f in findings]
        else:
            from collections import defaultdict
            grouped: dict[str, list[dict]] = defaultdict(list)
            for f in findings:
                grouped[f["module"]].append(f)
            lines = []
            for mod, items in grouped.items():
                examples = [f["target"] for f in items[:8]]
                lines.append(f"[{mod}] count={len(items)}, примеры: {', '.join(examples)}")

        result = "\n".join(lines)
        if len(result) > 12000:
            result = result[:12000]
            last_nl = result.rfind("\n")
            if last_nl != -1:
                result = result[:last_nl]
        return result

    def analyze(self, findings: list[dict]) -> str:
        console = Console()
        if not self._check_ollama():
            console.print("[red]Ollama не запущена. Выполни: "
                          "ollama serve && ollama pull qwen2.5:3b[/red]")
            return ""

        ctx = self._format_findings(findings)
        console.print(f"[cyan]ARGUS AI ({self.model}) — анализ…[/cyan]")
        try:
            resp = self.client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user",
                     "content": f"РЕЗУЛЬТАТЫ СКАНА:\n{ctx}\n\n"
                                "ЗАДАЧА:\nПроанализируй и выдай структурированный отчёт."},
                ],
                options={"temperature": 0.2, "num_ctx": 4096, "num_predict": 1024},
                stream=True,
            )
            full_text = ""
            for chunk in resp:
                piece = chunk["message"]["content"]
                print(piece, end="", flush=True)
                full_text += piece
            print()
            return full_text
        except Exception as e:
            console.print(f"[red]Ошибка AI: {e}[/red]")
            return ""
