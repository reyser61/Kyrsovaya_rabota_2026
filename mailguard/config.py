"""Загрузка и доступ к конфигурации MailGuard."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml

# Путь к config.yaml по умолчанию — корень проекта.
DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yaml"
)


@dataclass
class Config:
    """Обёртка над словарём конфигурации с удобными помощниками."""

    raw: dict[str, Any] = field(default_factory=dict)

    # --- быстрые доступы к часто используемым секциям ---
    @property
    def internal_domains(self) -> list[str]:
        return [d.lower() for d in self.raw.get("internal_domains", [])]

    @property
    def free_mail_domains(self) -> list[str]:
        return [d.lower() for d in self.raw.get("free_mail_domains", [])]

    @property
    def phishing(self) -> dict[str, Any]:
        return self.raw.get("phishing", {})

    @property
    def dlp(self) -> dict[str, Any]:
        return self.raw.get("dlp", {})

    @property
    def account(self) -> dict[str, Any]:
        return self.raw.get("account", {})

    @property
    def body(self) -> dict[str, Any]:
        return self.raw.get("body", {})

    @property
    def attachments(self) -> dict[str, Any]:
        return self.raw.get("attachments", {})

    @property
    def severity_thresholds(self) -> dict[str, int]:
        return self.raw.get("severity_thresholds", {})

    def severity_for_score(self, score: int) -> str:
        """Преобразует числовой балл риска в текстовый уровень серьёзности."""
        thresholds = self.severity_thresholds or {
            "low": 0,
            "medium": 30,
            "high": 50,
            "critical": 75,
        }
        # сортируем по возрастанию порога и берём наибольший подходящий
        level = "low"
        for name, threshold in sorted(thresholds.items(), key=lambda kv: kv[1]):
            if score >= threshold:
                level = name
        return level

    def is_internal_domain(self, domain: str | None) -> bool:
        if not domain:
            return False
        return domain.lower() in self.internal_domains

    def is_free_domain(self, domain: str | None) -> bool:
        if not domain:
            return False
        return domain.lower() in self.free_mail_domains


def load_config(path: str | None = None) -> Config:
    """Читает YAML-конфигурацию. Если файл не найден — возбуждает ошибку."""
    path = path or DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"Файл конфигурации не найден: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Config(raw=data)
