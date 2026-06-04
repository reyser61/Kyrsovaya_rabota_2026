"""Признаки в ТЕМЕ и ТЕЛЕ письма (контентный анализ) + декларативные правила.

Контентные правила работают по `subject + body` как единому тексту — значит
срабатывают и в теме, и в теле. Возвращает Finding обеих категорий
(phishing — манипуляции/выманивание; dlp — ПДн/секреты/конфиденц. слова).
"""

from __future__ import annotations

import re

from ..config import Config
from ..models import MessageRecord
from ..rules import Rule, RuleRegistry
from ..scoring import Finding
from .util import contains_any, find_pii, manipulation_categories

_SECRET_TYPES = {"private_key", "aws_key", "generic_secret", "jwt"}
_PII_RU = {
    "credit_card": "номер банковской карты", "snils": "СНИЛС", "inn": "ИНН",
    "passport_ru": "паспортные данные", "bank_account": "номер счёта",
    "email_list": "список e-mail адресов", "phone_bulk": "набор телефонов",
}


class ContentDetector:
    category = "content"

    def __init__(self, config: Config, registry: RuleRegistry):
        self.config = config
        self.registry = registry
        self.content_cfg = config.raw.get("content", {})

    def findings(self, rec: MessageRecord) -> list[Finding]:
        text = rec.content_text
        if not text.strip():
            return []
        out: list[Finding] = []
        is_inbound = rec.direction != "outbound"
        is_outbound_ext = rec.direction == "outbound" and bool(self._external(rec))

        # ---- фишинговый контент (входящие) ----
        if is_inbound:
            cats = manipulation_categories(text)
            min_cats = self.content_cfg.get("manipulation_min_categories", 2)
            if len(cats) >= min_cats:
                out.append(Finding(
                    "phishing.manipulative_content", "phishing",
                    "в тексте сочетаются приёмы соц. инженерии (" + ", ".join(cats) + ")",
                    {"manipulation_categories": cats}))

            cred = contains_any(text, self.config.body.get("credential_keywords", []))
            if cred:
                out.append(Finding(
                    "phishing.credential_request", "phishing",
                    "текст требует ввести учётные данные (" + ", ".join(cred) + ")",
                    {"credential_keywords": cred}))

        # ---- утечки в контенте (исходящие наружу) ----
        if is_outbound_ext:
            conf = contains_any(text, self.config.dlp.get("confidential_keywords", []))
            if conf:
                out.append(Finding(
                    "dlp.confidential_keyword", "dlp",
                    "в тексте есть отметки о конфиденциальности (" + ", ".join(conf) + ")",
                    {"keywords": conf}))

            found = find_pii(text)
            pii = [t for t in found if t not in _SECRET_TYPES]
            secrets = [t for t in found if t in _SECRET_TYPES]
            if pii:
                human = ", ".join(_PII_RU.get(t, t) for t in pii)
                out.append(Finding("dlp.pii", "dlp",
                                   f"обнаружены персональные данные: {human}",
                                   {"pii": pii}))
            if secrets:
                out.append(Finding("dlp.secret_exposure", "dlp",
                                   "обнаружены секреты/ключи: " + ", ".join(secrets),
                                   {"secrets": secrets}))

        # ---- декларативные правила ----
        for rule in self.registry.declarative():
            if rule.category == "phishing" and not is_inbound:
                continue
            if rule.category == "dlp" and not is_outbound_ext:
                continue
            hit = self._match_declarative(rule, rec)
            if hit:
                out.append(Finding(rule.id, rule.category,
                                   f"пользовательское правило «{rule.name}»: {hit}"))
        return out

    def _external(self, rec: MessageRecord) -> list[str]:
        return [d for d in rec.recipient_domains
                if not self.config.is_internal_domain(d)]

    @staticmethod
    def _match_declarative(rule: Rule, rec: MessageRecord) -> str | None:
        scope = rule.field_scope or "both"
        text = {"subject": rec.subject or "", "body": rec.body_text or ""}.get(
            scope, rec.content_text)
        if not text:
            return None
        if rule.rtype == "regex":
            for pat in rule.patterns:
                try:
                    if re.search(pat, text, re.IGNORECASE):
                        return f"совпадение по шаблону {pat}"
                except re.error:
                    continue
            return None
        hits = contains_any(text, rule.patterns)
        return ("найдены слова: " + ", ".join(hits)) if hits else None
