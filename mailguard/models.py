"""Модели данных MailGuard.

Исходные данные приводятся к сущностям:
  * MailMessage   — собранное из строк лога Postfix SMTP-письмо (метаданные);
  * EmailMessage  — письмо, разобранное из .eml (тело, ссылки, вложения);
  * MessageRecord — ЕДИНАЯ запись о письме: метаданные из лога + содержимое из
                    .eml, объединённые по Message-ID. Над ней работают детекторы;
  * ImapEvent     — событие входа/аутентификации IMAP;
  * Incident      — выявленный детектором инцидент безопасности.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def domain_of(address: str | None) -> str | None:
    """Возвращает доменную часть e-mail адреса в нижнем регистре."""
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].strip().lower()


def normalize_message_id(mid: str | None) -> str | None:
    """Нормализует Message-ID для корреляции (убирает <>, регистр, пробелы)."""
    if not mid:
        return None
    return mid.strip().strip("<>").strip().lower() or None


@dataclass
class MailMessage:
    """Одно SMTP-письмо, собранное из строк лога Postfix по queue_id."""

    queue_id: str
    timestamp: datetime | None = None
    client_ip: str | None = None
    client_host: str | None = None
    helo: str | None = None
    from_addr: str | None = None
    to_addrs: list[str] = field(default_factory=list)
    message_id: str | None = None
    subject: str | None = None
    size: int | None = None
    nrcpt: int = 0
    status: str | None = None          # sent / bounced / deferred / reject
    spf: str | None = None             # pass / fail / softfail / none
    dkim: str | None = None
    dmarc: str | None = None
    sasl_username: str | None = None   # аутентифицированный отправитель (исходящее)
    direction: str = "unknown"         # inbound / outbound / unknown

    @property
    def from_domain(self) -> str | None:
        return domain_of(self.from_addr)

    @property
    def recipient_domains(self) -> list[str]:
        seen: list[str] = []
        for addr in self.to_addrs:
            d = domain_of(addr)
            if d and d not in seen:
                seen.append(d)
        return seen


@dataclass
class ImapEvent:
    """Событие IMAP-сессии (Dovecot)."""

    timestamp: datetime | None
    user: str
    rip: str | None = None             # remote IP (источник входа)
    lip: str | None = None             # local IP сервера
    method: str | None = None          # PLAIN / LOGIN / ...
    tls: bool = False
    result: str = "login"              # login / auth_failed
    attempts: int = 1


@dataclass
class Attachment:
    """Вложение письма (из .eml)."""

    filename: str
    content_type: str = "application/octet-stream"
    size: int = 0
    sha256: str | None = None          # хэш содержимого (IoC, сверка с TI)
    inner_files: list[str] = field(default_factory=list)  # содержимое архива
    encrypted_archive: bool = False    # архив защищён паролем
    has_macro: bool = False            # внутри Office-документа найден макрос

    @property
    def ext(self) -> str:
        """Последнее расширение файла в нижнем регистре, включая точку."""
        name = (self.filename or "").strip().lower()
        if "." not in name:
            return ""
        return "." + name.rsplit(".", 1)[1]

    @property
    def extensions(self) -> list[str]:
        """Все расширения (для выявления двойных, напр. invoice.pdf.exe)."""
        name = (self.filename or "").strip().lower()
        parts = name.split(".")
        return ["." + p for p in parts[1:]] if len(parts) > 1 else []


@dataclass
class EmailMessage:
    """Полное письмо, разобранное из .eml: заголовки, тело, ссылки, вложения."""

    message_id: str | None = None
    timestamp: datetime | None = None
    from_addr: str | None = None
    to_addrs: list[str] = field(default_factory=list)
    subject: str | None = None
    body_text: str = ""
    urls: list[str] = field(default_factory=list)
    # пары (видимый текст ссылки, реальный href) для выявления подмены
    anchors: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    reply_to: str | None = None
    direction: str = "unknown"          # inbound / outbound / unknown
    source_file: str | None = None

    @property
    def from_domain(self) -> str | None:
        return domain_of(self.from_addr)

    @property
    def recipient_domains(self) -> list[str]:
        seen: list[str] = []
        for addr in self.to_addrs:
            d = domain_of(addr)
            if d and d not in seen:
                seen.append(d)
        return seen


@dataclass
class MessageRecord:
    """Единая запись о письме для детекторов: метаданные (из лога) + содержимое
    (из .eml). Собирается движком; при совпадении Message-ID источники
    объединяются, что даёт детекторам максимум контекста."""

    message_id: str | None = None
    timestamp: datetime | None = None
    # --- метаданные (преимущественно из логов Postfix) ---
    client_ip: str | None = None
    client_host: str | None = None
    helo: str | None = None
    from_addr: str | None = None
    to_addrs: list[str] = field(default_factory=list)
    size: int | None = None
    nrcpt: int = 0
    status: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    sasl_username: str | None = None
    direction: str = "unknown"
    # --- содержимое (из .eml) ---
    subject: str | None = None
    body_text: str = ""
    urls: list[str] = field(default_factory=list)
    anchors: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    reply_to: str | None = None
    # --- происхождение ---
    sources: list[str] = field(default_factory=list)   # ['postfix', 'eml']
    source_file: str | None = None

    @property
    def from_domain(self) -> str | None:
        return domain_of(self.from_addr)

    @property
    def recipient_domains(self) -> list[str]:
        seen: list[str] = []
        for addr in self.to_addrs:
            d = domain_of(addr)
            if d and d not in seen:
                seen.append(d)
        return seen

    @property
    def content_text(self) -> str:
        """Тема + тело как единый текст — для контентных правил (тема И тело)."""
        return ((self.subject or "") + "\n" + (self.body_text or "")).strip()

    @property
    def external_recipients(self) -> list[str]:
        # домены определяются как внешние вызывающей стороной; здесь — все адреса
        return list(self.to_addrs)

    # ---- построение из источников --------------------------------------- #

    @classmethod
    def from_mail(cls, m: "MailMessage") -> "MessageRecord":
        return cls(
            message_id=normalize_message_id(m.message_id),
            timestamp=m.timestamp,
            client_ip=m.client_ip,
            client_host=m.client_host,
            helo=m.helo,
            from_addr=m.from_addr,
            to_addrs=list(m.to_addrs),
            size=m.size,
            nrcpt=m.nrcpt,
            status=m.status,
            spf=m.spf,
            dkim=m.dkim,
            dmarc=m.dmarc,
            sasl_username=m.sasl_username,
            direction=m.direction,
            subject=m.subject,
            sources=["postfix"],
        )

    @classmethod
    def from_email(cls, e: "EmailMessage") -> "MessageRecord":
        return cls(
            message_id=normalize_message_id(e.message_id),
            timestamp=e.timestamp,
            from_addr=e.from_addr,
            to_addrs=list(e.to_addrs),
            direction=e.direction,
            subject=e.subject,
            body_text=e.body_text,
            urls=list(e.urls),
            anchors=list(e.anchors),
            attachments=list(e.attachments),
            reply_to=e.reply_to,
            source_file=e.source_file,
            sources=["eml"],
        )

    def merge_email(self, e: "EmailMessage") -> None:
        """Дополняет запись (из лога) содержимым письма .eml с тем же Message-ID."""
        self.subject = self.subject or e.subject
        self.body_text = e.body_text or self.body_text
        self.urls = e.urls or self.urls
        self.anchors = e.anchors or self.anchors
        self.attachments = e.attachments or self.attachments
        self.reply_to = e.reply_to or self.reply_to
        self.source_file = e.source_file
        if not self.from_addr:
            self.from_addr = e.from_addr
        if not self.to_addrs:
            self.to_addrs = list(e.to_addrs)
        if self.timestamp is None:
            self.timestamp = e.timestamp
        if "eml" not in self.sources:
            self.sources.append("eml")


@dataclass
class Incident:
    """Инцидент безопасности, сформированный детектором."""

    timestamp: datetime | None
    category: str                      # phishing / dlp / account
    rule_id: str
    title: str
    description: str
    score: int
    severity: str = "low"
    confidence: str = "medium"         # high / medium / low — достоверность
    source: str | None = None          # ключевая сущность: отправитель/IP/пользователь
    summary: str = ""                  # короткое человекочитаемое описание
    origin: str = ""                   # источник: SMTP / IMAP / EML / SMTP+EML
    evidence: dict[str, Any] = field(default_factory=dict)
    id: int | None = None

    def to_row(self) -> dict[str, Any]:
        """Представление для записи в БД."""
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "category": self.category,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "score": self.score,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
            "summary": self.summary,
            "origin": self.origin,
            "evidence": json.dumps(self.evidence, ensure_ascii=False),
        }
