"""Движок анализа: парсинг -> единые записи -> признаки -> агрегированные
инциденты (модель достоверности) -> IoC + статистика."""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from .blocklist import Blocklist
from .config import Config, load_config
from .detectors import (
    AccountDetector,
    AttachmentDetector,
    ContentDetector,
    DlpDetector,
    IocMatchDetector,
    LinkDetector,
    PhishingDetector,
)
from .ioc import Ioc, IocCollector
from .models import (
    EmailMessage,
    ImapEvent,
    Incident,
    MailMessage,
    MessageRecord,
    normalize_message_id,
)
from .narrative import build_description, build_summary
from .parsers import DovecotParser, EmlParser, PostfixParser
from .rules import RuleRegistry
from .scoring import Finding, assess
from .storage import Storage

_TITLE = {
    "phishing": "Подозрение на фишинг",
    "dlp": "Возможная утечка данных",
}


def _as_list(value) -> list:
    """Нормализует аргумент в список путей: None -> [], str -> [str], list -> list."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [v for v in value if v]
    return [value]


@dataclass
class AnalysisResult:
    records: list[MessageRecord] = field(default_factory=list)
    imap_events: list[ImapEvent] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    iocs: list[Ioc] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


class Engine:
    def __init__(self, config: Config | None = None,
                 registry: RuleRegistry | None = None,
                 blocklist: Blocklist | None = None):
        self.config = config or load_config()
        self.registry = registry or RuleRegistry(self.config)
        bl_path = self.config.raw.get("ioc", {}).get("blocklist_file")
        if bl_path and not os.path.isabs(bl_path):
            bl_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), bl_path)
        self.blocklist = blocklist or Blocklist(bl_path)
        self.postfix = PostfixParser(self.config)
        self.dovecot = DovecotParser()
        self.eml = EmlParser(self.config)
        self.dlp = DlpDetector(self.config, self.registry)
        # детекторы-«поставщики признаков» (per-record)
        self.signal_detectors = [
            PhishingDetector(self.config, self.registry),
            ContentDetector(self.config, self.registry),
            LinkDetector(self.config, self.registry),
            AttachmentDetector(self.config, self.registry),
            self.dlp,
            IocMatchDetector(self.config, self.registry, self.blocklist),
        ]
        self.account = AccountDetector(self.config, self.registry)

    def run(self, postfix_log=None, dovecot_log=None, emails_dir=None,
            storage: Storage | None = None) -> AnalysisResult:
        # Каждый аргумент принимает как одиночный путь (str), так и список путей —
        # это позволяет анализировать несколько источников вместе (напр. образцы
        # + загруженные пользователем файлы).
        mail_messages: list[MailMessage] = []
        for path in _as_list(postfix_log):
            mail_messages += self.postfix.parse_file(path)
        imap_events: list[ImapEvent] = []
        for path in _as_list(dovecot_log):
            imap_events += self.dovecot.parse_file(path)
        emails: list[EmailMessage] = []
        for path in _as_list(emails_dir):
            emails += self.eml.parse_dir(path)

        records = self._build_records(mail_messages, emails)

        # (incident, record|None) — запоминаем запись для извлечения IoC
        pairs: list[tuple[Incident, MessageRecord | None]] = []

        # признаки по каждому письму -> агрегированные инциденты по категориям
        for rec in records:
            findings: list[Finding] = []
            for det in self.signal_detectors:
                findings += det.findings(rec)
            by_cat: dict[str, list[Finding]] = defaultdict(list)
            for f in findings:
                by_cat[f.category].append(f)
            for category, cat_findings in by_cat.items():
                incident = self._make_incident(rec, category, cat_findings)
                if incident:
                    pairs.append((incident, rec))

        # кросс-письмовые и логовые инциденты (без привязки к одной записи)
        for inc in self.dlp.exfiltration(records):
            pairs.append((inc, None))
        for inc in self.account.analyze(imap_events):
            pairs.append((inc, None))

        pairs.sort(key=lambda p: p[0].score, reverse=True)
        incidents = [inc for inc, _ in pairs]

        # сбор IoC из подтверждённых (high/critical) инцидентов
        collector = IocCollector(self.config)
        for inc, rec in pairs:
            collector.consider(inc, rec)
        iocs = collector.result()

        stats = self._build_stats(records, imap_events, incidents, iocs)

        if storage is not None:
            storage.clear()
            storage.save_incidents(incidents)
            storage.save_iocs(iocs)
            storage.save_run(stats)

        return AnalysisResult(records=records, imap_events=imap_events,
                              incidents=incidents, iocs=iocs, stats=stats)

    # ------------------------------------------------------------------ #

    def _make_incident(self, rec: MessageRecord, category: str,
                       findings: list[Finding]) -> Incident | None:
        a = assess(findings, self.registry, self.config, rec)
        if a is None:
            return None
        evidence = {
            "from": rec.from_addr,
            "to": rec.to_addrs,
            "client_ip": rec.client_ip,
            "subject": rec.subject,
            "direction": rec.direction,
            "sources": rec.sources,
            "triggered_rules": a.triggered_rules,
            "reasons": a.reasons,
        }
        if rec.attachments:
            evidence["attachments"] = {a.filename: a.sha256 for a in rec.attachments}
        if rec.urls:
            evidence["urls"] = rec.urls
        evidence.update(a.evidence)
        title = _TITLE.get(category, "Инцидент")
        return Incident(
            timestamp=rec.timestamp,
            category=category,
            rule_id=f"{category}.composite",
            title=f"{title} — {rec.from_addr or rec.client_ip or 'неизвестно'}",
            description=build_description(rec, category, a),
            summary=build_summary(rec, category, a),
            origin=self._origin(rec.sources),
            score=a.score,
            severity=a.severity,
            confidence=a.confidence,
            source=rec.from_addr or rec.client_ip,
            evidence=evidence,
        )

    @staticmethod
    def _origin(sources: list[str]) -> str:
        has_log = "postfix" in sources
        has_eml = "eml" in sources
        if has_log and has_eml:
            return "SMTP+EML"
        if has_eml:
            return "EML"
        return "SMTP"

    @staticmethod
    def _build_records(mail_messages: list[MailMessage],
                       emails: list[EmailMessage]) -> list[MessageRecord]:
        records: list[MessageRecord] = []
        by_mid: dict[str, MessageRecord] = {}
        for m in mail_messages:
            rec = MessageRecord.from_mail(m)
            records.append(rec)
            if rec.message_id:
                by_mid[rec.message_id] = rec
        for e in emails:
            mid = normalize_message_id(e.message_id)
            if mid and mid in by_mid:
                by_mid[mid].merge_email(e)
            else:
                records.append(MessageRecord.from_email(e))
        return records

    def _build_stats(self, records, imap_events, incidents, iocs) -> dict[str, Any]:
        by_category = Counter(i.category for i in incidents)
        by_severity = Counter(i.severity for i in incidents)
        by_confidence = Counter(i.confidence for i in incidents)
        direction = Counter(r.direction for r in records)
        top_sources = Counter(i.source for i in incidents if i.source)
        hours = Counter(i.timestamp.hour for i in incidents if i.timestamp is not None)
        all_rules = self.registry.all()

        return {
            "total_messages": len(records),
            "total_imap_events": len(imap_events),
            "total_emails": sum(1 for r in records if "eml" in r.sources),
            "total_attachments": sum(len(r.attachments) for r in records),
            "correlated": sum(1 for r in records if len(r.sources) > 1),
            "total_incidents": len(incidents),
            "total_iocs": len(iocs),
            "blocklist_size": self.blocklist.count(),
            "inbound": direction.get("inbound", 0),
            "outbound": direction.get("outbound", 0),
            "rules_total": len(all_rules),
            "rules_enabled": sum(1 for r in all_rules if r.enabled),
            "by_category": {
                "phishing": by_category.get("phishing", 0),
                "dlp": by_category.get("dlp", 0),
                "account": by_category.get("account", 0),
            },
            "by_severity": {s: by_severity.get(s, 0)
                            for s in ("low", "medium", "high", "critical")},
            "by_confidence": {c: by_confidence.get(c, 0)
                              for c in ("low", "medium", "high")},
            "top_sources": top_sources.most_common(10),
            "hourly": {str(h): hours.get(h, 0) for h in range(24)},
        }
