"""Безопасный HTTP-клиент для всех сетевых модулей ARGUS.

Ключевое исправление безопасности: старая версия использовала verify=False,
что открывало MITM-атаку на результаты разведки. Здесь TLS-верификация
включена по умолчанию; при ошибке верификации возвращается понятная ошибка.
"""
from __future__ import annotations

import httpx

DEFAULT_HEADERS = {"User-Agent": "ARGUS/0.3 (recon)"}


def make_client(timeout: float = 20.0, follow_redirects: bool = True) -> httpx.AsyncClient:
    """Async-клиент с честной проверкой сертификатов."""
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers=DEFAULT_HEADERS,
        verify=True,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )


def sync_get(url: str, timeout: float = 30.0) -> httpx.Response:
    resp = httpx.get(url, timeout=timeout, headers=DEFAULT_HEADERS,
                     follow_redirects=True, verify=True)
    resp.raise_for_status()
    return resp
