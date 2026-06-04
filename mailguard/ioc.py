"""Сбор индикаторов компрометации (IoC) из подтверждённых инцидентов.

По решению заносим IoC только из инцидентов высокой/критической серьёзности —
это снижает шум и даёт «чистую» базу подтверждённых индикаторов. IoC затем
можно использовать для новых правил, обогащения и сверки с TI (этапы D–F).

Типы: IP отправителя, e-mail и домен отправителя, домен из ссылки,
SHA-256 вложения, тема письма (как индикатор кампании).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .config import Config
from .models import Incident, MessageRecord, domain_of
from .detectors.util import domain_from_url

_SEV_ORDER = ["low", "medium", "high", "critical"]


def _sev_ge(a: str, b: str) -> bool:
    try:
        return _SEV_ORDER.index(a) >= _SEV_ORDER.index(b)
    except ValueError:
        return False


def _norm_subject(subject: str | None) -> str | None:
    if not subject:
        return None
    s = subject.strip().lower()
    for pref in ("re:", "fw:", "fwd:"):
        while s.startswith(pref):
            s = s[len(pref):].strip()
    return s or None


@dataclass
class Ioc:
    type: str
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 0
    max_severity: str = "low"
    categories: set[str] = field(default_factory=set)
    labels: set[str] = field(default_factory=set)   # доп. контекст (имя файла и т.п.)
    context: set[str] = field(default_factory=set)   # из каких писем/инцидентов

    def to_row(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "count": self.count,
            "max_severity": self.max_severity,
            "categories": ", ".join(sorted(self.categories)),
            "labels": ", ".join(sorted(self.labels)),
            "context": " | ".join(sorted(self.context)),
        }


class IocCollector:
    """Накапливает и дедуплицирует индикаторы из инцидентов."""

    def __init__(self, config: Config):
        self.config = config
        cfg = config.raw.get("ioc", {})
        self.min_severity = cfg.get("min_severity", "high")
        self.types = set(cfg.get("types", [
            "ip", "sender_email", "sender_domain", "url_domain",
            "file_sha256", "subject"]))
        # свои/доверенные домены не заносим как IoC (нельзя блокировать своё)
        self._known = set(config.internal_domains) | {
            d.lower() for d in config.raw.get("trusted_domains", [])}
        self._items: dict[tuple[str, str], Ioc] = {}

    def _is_own_domain(self, domain: str | None) -> bool:
        if not domain:
            return False
        return any(domain == d or domain.endswith("." + d) for d in self._known)

    @staticmethod
    def _is_private_ip(ip: str | None) -> bool:
        if not ip or ":" in ip:
            return False
        p = ip.split(".")
        if len(p) != 4 or not p[0].isdigit():
            return False
        a, b = int(p[0]), int(p[1]) if p[1].isdigit() else 0
        return a in (10, 127) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)

    def qualifies(self, incident: Incident) -> bool:
        return _sev_ge(incident.severity, self.min_severity)

    def consider(self, incident: Incident, record: MessageRecord | None) -> None:
        if not self.qualifies(incident):
            return
        ts, sev, cat = incident.timestamp, incident.severity, incident.category
        ctx = self._context(incident, record)

        if record is not None:
            self._add("ip", record.client_ip, ts, sev, cat, context=ctx)
            self._add("sender_email", record.from_addr, ts, sev, cat, context=ctx)
            self._add("sender_domain", record.from_domain, ts, sev, cat, context=ctx)
            for att in record.attachments:
                self._add("file_sha256", att.sha256, ts, sev, cat,
                          label=att.filename, context=ctx)
            for url in record.urls:
                self._add("url_domain", domain_from_url(url), ts, sev, cat, context=ctx)
            if cat == "phishing":
                self._add("subject", _norm_subject(record.subject), ts, sev, cat,
                          context=ctx)
        else:
            ev = incident.evidence or {}
            self._add("ip", ev.get("ip"), ts, sev, cat, context=ctx)
            if ev.get("recipient"):
                self._add("sender_domain", domain_of(ev["recipient"]), ts, sev, cat,
                          context=ctx)

    @staticmethod
    def _context(incident: Incident, record: MessageRecord | None) -> str:
        """Короткая пометка, откуда/почему заведён индикатор."""
        cat = {"phishing": "фишинг", "dlp": "утечка",
               "account": "аккаунт"}.get(incident.category, incident.category)
        if record is not None:
            who = record.from_addr or record.client_ip or "?"
            subj = (record.subject or "").strip()
            if len(subj) > 40:
                subj = subj[:40] + "…"
            return f"{cat}: {who}" + (f" — «{subj}»" if subj else "")
        return f"{cat}: {incident.source or incident.title}"

    def _add(self, type_: str, value: str | None, ts, sev: str, cat: str,
             label: str | None = None, context: str | None = None) -> None:
        if type_ not in self.types or not value:
            return
        # отфильтровываем «свои» сущности и приватные IP — они не IoC
        if type_ == "ip" and self._is_private_ip(value):
            return
        if type_ == "sender_email" and self._is_own_domain(domain_of(value)):
            return
        if type_ in ("sender_domain", "url_domain") and self._is_own_domain(value):
            return
        key = (type_, value)
        item = self._items.get(key)
        if item is None:
            item = Ioc(type=type_, value=value, first_seen=ts, last_seen=ts)
            self._items[key] = item
        item.count += 1
        if ts:
            if item.first_seen is None or ts < item.first_seen:
                item.first_seen = ts
            if item.last_seen is None or ts > item.last_seen:
                item.last_seen = ts
        if _sev_ge(sev, item.max_severity):
            item.max_severity = sev
        item.categories.add(cat)
        if label:
            item.labels.add(label)
        if context and len(item.context) < 5:
            item.context.add(context)

    def result(self) -> list[Ioc]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(self._items.values(),
                      key=lambda i: (order.get(i.max_severity, 9), -i.count))


# соответствие типов собранных IoC и типов блок-листа
_IOC_TO_BLOCKLIST = {
    "ip": "ip",
    "sender_email": "email",
    "sender_domain": "domain",
    "url_domain": "domain",
    "file_sha256": "file_sha256",
    "subject": "subject",
}


def iocs_to_blocklist_entries(iocs: list[Ioc],
                              source: str = "promoted") -> list[tuple[str, str, str]]:
    """Преобразует собранные IoC в записи блок-листа (type, value, source)."""
    out: list[tuple[str, str, str]] = []
    for i in iocs:
        bt = _IOC_TO_BLOCKLIST.get(i.type)
        if bt:
            out.append((bt, i.value, source))
    return out
