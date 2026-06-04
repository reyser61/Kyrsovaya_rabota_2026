"""Признаки утечек по МЕТАДАННЫМ исходящих писем (Finding) + эксфильтрация.

Метаданные (free-mail, крупное письмо, нерабочее время) — слабые сигналы,
алертят только в сочетании. Эксфильтрация (много писем одному адресату) — это
кросс-письмовый признак, поэтому считается отдельно и сразу как инцидент.
"""

from __future__ import annotations

from collections import defaultdict

from ..config import Config
from ..models import Incident, MessageRecord, domain_of
from ..rules import RuleRegistry
from ..scoring import Finding


class DlpDetector:
    category = "dlp"

    def __init__(self, config: Config, registry: RuleRegistry):
        self.config = config
        self.registry = registry
        self.cfg = config.dlp

    def findings(self, rec: MessageRecord) -> list[Finding]:
        if rec.direction != "outbound":
            return []
        external = self._external(rec)
        if not external:
            return []
        out: list[Finding] = []

        free = [r for r in external if self.config.is_free_domain(domain_of(r))]
        if free:
            out.append(Finding("dlp.free_mail_recipient", "dlp",
                               "получатель — личная/бесплатная почта: " + ", ".join(free),
                               {"free_recipients": free}))

        limit = self.cfg.get("large_message_bytes", 5_000_000)
        if rec.size and rec.size >= limit:
            out.append(Finding("dlp.large_external", "dlp",
                               f"крупное письмо наружу ({rec.size} байт)"))

        if rec.timestamp and self._off_hours(rec.timestamp.hour):
            out.append(Finding("dlp.off_hours", "dlp",
                               f"отправка в нерабочее время ({rec.timestamp.hour}:00)"))
        return out

    def exfiltration(self, records: list[MessageRecord]) -> list[Incident]:
        """Кросс-письмовый признак: много писем одному внешнему получателю."""
        if not self.registry.enabled("dlp.exfiltration"):
            return []
        counter: dict[tuple[str, str], int] = defaultdict(int)
        last_ts: dict[tuple[str, str], object] = {}
        for rec in records:
            if rec.direction != "outbound":
                continue
            for rcpt in rec.to_addrs:
                rdom = domain_of(rcpt)
                if rdom and not self.config.is_internal_domain(rdom):
                    key = (rec.from_addr or "?", rcpt)
                    counter[key] += 1
                    last_ts[key] = rec.timestamp

        threshold = self.cfg.get("exfil_recipient_threshold", 10)
        weight = self.registry.weight("dlp.exfiltration")
        out: list[Incident] = []
        for (sender, rcpt), count in counter.items():
            if count >= threshold:
                score = weight + min(count - threshold, 20)
                out.append(Incident(
                    timestamp=last_ts.get((sender, rcpt)),
                    category="dlp",
                    rule_id="dlp.exfiltration",
                    title=f"Аномальный объём писем: {sender} → {rcpt}",
                    description=(
                        f"С адреса {sender} внешнему получателю {rcpt} отправлено "
                        f"{count} писем (порог {threshold}). Такая концентрация "
                        f"характерна для постепенного вывода данных (эксфильтрации). "
                        f"Рекомендация: проверить содержимое переписки и "
                        f"правомерность передачи; при необходимости заблокировать канал."),
                    score=score,
                    severity=self.config.severity_for_score(score),
                    confidence="high",
                    origin="SMTP",
                    summary=(f"Эксфильтрация: {sender} → {rcpt} "
                             f"({count} писем) · достоверность высокая."),
                    source=sender,
                    evidence={"sender": sender, "recipient": rcpt, "count": count,
                              "triggered_rules": ["dlp.exfiltration"]},
                ))
        return out

    def _external(self, rec: MessageRecord) -> list[str]:
        return [r for r in rec.to_addrs
                if (d := domain_of(r)) and not self.config.is_internal_domain(d)]

    def _off_hours(self, hour: int) -> bool:
        start = self.cfg.get("business_hours_start", 8)
        end = self.cfg.get("business_hours_end", 20)
        return hour < start or hour >= end
