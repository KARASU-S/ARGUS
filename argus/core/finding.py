"""Единая модель находок ARGUS.

Исправления: datetime.utcnow() (deprecated) -> aware UTC; стабильный хеш для
дедупликации; валидация severity.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class Finding:
    module: str
    target: str
    category: str
    severity: str = "info"
    data: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            self.severity = "info"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ts"] = datetime.now(timezone.utc).isoformat()
        return d

    def dedup_key(self) -> str:
        """Стабильный ключ без временной метки — для дедупликации."""
        payload = json.dumps(
            [self.module, self.target, self.category, self.severity, self.data],
            sort_keys=True, ensure_ascii=False, default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()
