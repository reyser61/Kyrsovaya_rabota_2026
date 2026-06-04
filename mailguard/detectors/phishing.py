"""Признаки фишинга по МЕТАДАННЫМ письма (подлинность отправителя).

Возвращает список Finding (без оценки серьёзности — агрегацией и расчётом риска
занимается scoring.assess в движке).
"""

from __future__ import annotations

from ..config import Config
from ..models import MessageRecord, domain_of
from ..rules import RuleRegistry
from ..scoring import Finding
from .util import is_punycode, levenshtein


class PhishingDetector:
    category = "phishing"

    def __init__(self, config: Config, registry: RuleRegistry):
        self.config = config
        self.registry = registry
        self.cfg = config.phishing

    def findings(self, rec: MessageRecord) -> list[Finding]:
        if rec.direction == "outbound":
            return []
        out: list[Finding] = []

        def add(rule_id: str, reason: str, ev: dict | None = None) -> None:
            out.append(Finding(rule_id, "phishing", reason, ev or {}))

        if rec.dmarc == "fail":
            add("phishing.dmarc_fail", "отправитель не прошёл проверку подлинности DMARC")
        if rec.spf in {"fail", "softfail"}:
            add("phishing.spf_fail", f"SPF-проверка не пройдена ({rec.spf})")
        if rec.dkim == "fail":
            add("phishing.dkim_fail", "цифровая подпись DKIM недействительна")

        if self.config.is_internal_domain(rec.from_domain) and rec.direction == "inbound":
            add("phishing.spoofed_internal",
                f"внешний отправитель выдаёт себя за внутренний домен {rec.from_domain}",
                {"spoofed_domain": rec.from_domain})

        look = self._lookalike(rec.from_domain)
        if look:
            add("phishing.lookalike_sender",
                f"домен отправителя имитирует внутренний «{look}»",
                {"lookalike_of": look})

        if is_punycode(rec.from_domain):
            add("phishing.punycode_sender",
                f"домен отправителя записан в punycode ({rec.from_domain})")

        if rec.reply_to and rec.from_addr and \
                domain_of(rec.reply_to) != domain_of(rec.from_addr):
            add("phishing.replyto_mismatch",
                f"адрес для ответа (Reply-To: {rec.reply_to}) ведёт на другой домен")

        threshold = self.cfg.get("mass_mail_recipients", 15)
        if rec.nrcpt >= threshold:
            add("phishing.mass_recipients", f"массовая рассылка ({rec.nrcpt} получателей)")

        if rec.helo and rec.from_domain and self._helo_mismatch(rec):
            add("phishing.helo_mismatch",
                f"имя сервера HELO «{rec.helo}» не соответствует домену отправителя")

        return out

    def _lookalike(self, domain: str | None) -> str | None:
        if not domain or self.config.is_internal_domain(domain):
            return None
        max_dist = self.cfg.get("lookalike_max_distance", 2)
        for internal in self.config.internal_domains:
            if 0 < levenshtein(domain, internal) <= max_dist:
                return internal
        return None

    @staticmethod
    def _helo_mismatch(rec: MessageRecord) -> bool:
        helo = (rec.helo or "").lower().strip("[]")
        fdom = (rec.from_domain or "").lower()
        if not helo or not fdom:
            return False
        if helo.replace(".", "").isdigit():
            return True
        return fdom not in helo and helo not in fdom
