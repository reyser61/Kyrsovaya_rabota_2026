"""Признаки во ВЛОЖЕНИЯХ (возвращает Finding обеих категорий).

Фишинг/ВПО (входящие): исполняемые, двойные расширения, реальные макросы,
опасный файл внутри архива, запароленный архив, HTML-вложения. Обычный архив —
слабый сигнал (легитимен сам по себе).

DLP (исходящие наружу): высокорисковые форматы (.sql/.pst…) — средний сигнал;
обычные офисные документы — слабый (нужен контекст); крупный объём.
"""

from __future__ import annotations

from ..config import Config
from ..models import Attachment, MessageRecord
from ..rules import RuleRegistry
from ..scoring import Finding


class AttachmentDetector:
    def __init__(self, config: Config, registry: RuleRegistry):
        self.config = config
        self.registry = registry
        self.cfg = config.attachments

    def findings(self, rec: MessageRecord) -> list[Finding]:
        if not rec.attachments:
            return []
        if rec.direction == "outbound":
            return self._dlp(rec)
        return self._malware(rec)

    # ------------------------------------------------------------------ #

    def _malware(self, rec: MessageRecord) -> list[Finding]:
        dangerous = set(self.cfg.get("dangerous_extensions", []))
        macro = set(self.cfg.get("macro_extensions", []))
        archive = set(self.cfg.get("archive_extensions", []))
        html = set(self.cfg.get("html_extensions", []))
        out: list[Finding] = []

        def add(rule_id: str, reason: str, fname: str) -> None:
            out.append(Finding(rule_id, "phishing", reason, {"attachment": fname}))

        for att in rec.attachments:
            ext, exts = att.ext, att.extensions
            if ext in dangerous:
                add("phishing.attachment_dangerous",
                    f"исполняемое вложение «{att.filename}»", att.filename)
            elif att.has_macro:
                add("phishing.attachment_real_macro",
                    f"в документе «{att.filename}» есть исполняемый макрос", att.filename)
            elif ext in macro:
                add("phishing.attachment_macro",
                    f"документ «{att.filename}» допускает макросы", att.filename)
            elif ext in html:
                add("phishing.attachment_html",
                    f"HTML/скрипт-вложение «{att.filename}»", att.filename)
            elif ext in archive:
                add("phishing.attachment_archive",
                    f"архив-вложение «{att.filename}»", att.filename)

            if len(exts) >= 2 and exts[-1] in dangerous and exts[-2] not in dangerous:
                add("phishing.attachment_double_ext",
                    f"двойное расширение-маскировка «{att.filename}»", att.filename)

            if att.encrypted_archive:
                add("phishing.attachment_encrypted",
                    f"запароленный архив «{att.filename}» (обход антивируса)", att.filename)
            inner = self._inner_dangerous(att, dangerous)
            if inner:
                add("phishing.attachment_archive_inner",
                    f"внутри архива «{att.filename}» опасный файл: " + ", ".join(inner),
                    att.filename)
        return out

    def _dlp(self, rec: MessageRecord) -> list[Finding]:
        external = [d for d in rec.recipient_domains
                    if not self.config.is_internal_domain(d)]
        if not external:
            return []
        highrisk = set(self.cfg.get("highrisk_extensions", []))
        office = set(self.cfg.get("office_extensions", []))
        limit = self.cfg.get("max_attachment_bytes", 5_000_000)
        out: list[Finding] = []

        hr = [a.filename for a in rec.attachments if a.ext in highrisk]
        of = [a.filename for a in rec.attachments if a.ext in office]
        if hr:
            out.append(Finding("dlp.attachment_highrisk", "dlp",
                               "наружу уходят высокорисковые файлы: " + ", ".join(hr),
                               {"attachments": hr}))
        if of:
            out.append(Finding("dlp.attachment_office", "dlp",
                               "наружу уходят документы: " + ", ".join(of),
                               {"attachments": of}))
        total = sum(a.size for a in rec.attachments)
        if total >= limit:
            out.append(Finding("dlp.attachment_large", "dlp",
                               f"крупный объём вложений ({total} байт)",
                               {"total_size": total}))
        return out

    @staticmethod
    def _inner_dangerous(att: Attachment, dangerous: set[str]) -> list[str]:
        out: list[str] = []
        for name in att.inner_files:
            parts = name.lower().split(".")
            exts = ["." + p for p in parts[1:]]
            if exts and exts[-1] in dangerous:
                out.append(name)
        return out
