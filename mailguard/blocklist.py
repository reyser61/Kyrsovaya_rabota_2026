"""Блок-лист известных вредоносных индикаторов (IoC).

Файл CSV (`type,value,source,added`) — человекочитаемый, его можно вести
вручную, импортировать из TI-отчётов или пополнять «промоутом» собранных
системой IoC. На этапе анализа индикаторы письма сверяются с блок-листом;
совпадение — сильный сигнал угрозы (правила `ioc.match_*`).

Типы: ip, domain, email, file_sha256, subject. Тип `domain` сопоставляется как
с доменом отправителя, так и с доменами из ссылок (с учётом поддоменов).
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from datetime import datetime

DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "ioc_blocklist.csv")

VALID_TYPES = {"ip", "domain", "email", "file_sha256", "subject"}


@dataclass
class BlocklistEntry:
    type: str
    value: str
    source: str = "manual"
    added: str = ""


class Blocklist:
    def __init__(self, path: str | None = None):
        self.path = path or DEFAULT_PATH
        # индекс: type -> { value(lower) -> entry }
        self._by_type: dict[str, dict[str, BlocklistEntry]] = {}
        self.load()

    # ---- загрузка / сохранение ---------------------------------------- #

    def load(self) -> None:
        self._by_type = {t: {} for t in VALID_TYPES}
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                t = (row.get("type") or "").strip().lower()
                v = (row.get("value") or "").strip()
                if t in VALID_TYPES and v:
                    self._by_type[t][v.lower()] = BlocklistEntry(
                        type=t, value=v,
                        source=(row.get("source") or "manual").strip(),
                        added=(row.get("added") or "").strip())

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["type", "value", "source", "added"])
            for entries in self._by_type.values():
                for e in entries.values():
                    writer.writerow([e.type, e.value, e.source, e.added])

    # ---- доступ -------------------------------------------------------- #

    def all(self) -> list[BlocklistEntry]:
        out: list[BlocklistEntry] = []
        for entries in self._by_type.values():
            out.extend(entries.values())
        return sorted(out, key=lambda e: (e.type, e.value))

    def count(self) -> int:
        return sum(len(v) for v in self._by_type.values())

    def match(self, type_: str, value: str | None) -> BlocklistEntry | None:
        """Точное совпадение по значению (регистронезависимо)."""
        if not value:
            return None
        return self._by_type.get(type_, {}).get(value.lower())

    def match_domain(self, domain: str | None) -> BlocklistEntry | None:
        """Совпадение домена с учётом поддоменов (sub.evil.ru ⊂ evil.ru)."""
        if not domain:
            return None
        d = domain.lower()
        table = self._by_type.get("domain", {})
        if d in table:
            return table[d]
        for value, entry in table.items():
            if d.endswith("." + value):
                return entry
        return None

    def match_subject(self, subject: str | None) -> BlocklistEntry | None:
        """Совпадение, если занесённая тема входит в тему письма."""
        if not subject:
            return None
        s = subject.strip().lower()
        for value, entry in self._by_type.get("subject", {}).items():
            if value in s:
                return entry
        return None

    # ---- изменение ----------------------------------------------------- #

    def add(self, type_: str, value: str, source: str = "manual") -> bool:
        type_ = (type_ or "").strip().lower()
        value = (value or "").strip()
        if type_ not in VALID_TYPES or not value:
            return False
        table = self._by_type.setdefault(type_, {})
        if value.lower() in table:
            return False
        table[value.lower()] = BlocklistEntry(
            type=type_, value=value, source=source,
            added=datetime.now().strftime("%Y-%m-%d"))
        return True

    def add_many(self, entries: list[tuple[str, str, str]]) -> int:
        added = sum(self.add(t, v, s) for t, v, s in entries)
        if added:
            self.save()
        return added
