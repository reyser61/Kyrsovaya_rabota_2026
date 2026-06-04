"""Парсер исходных писем в формате .eml (RFC 822 / MIME).

Логи Postfix/Dovecot содержат только метаданные, поэтому для анализа ТЕЛА
письма и ВЛОЖЕНИЙ нужны сами письма. Многие почтовые системы хранят их копии
(Maildir, журналирование, карантин), и каждое письмо — это .eml-файл.

Парсер использует стандартный модуль email и приводит письмо к EmailMessage:
тема, отправитель, получатели, текст тела, список ссылок (включая пары
«видимый текст → реальный href» для выявления подмены) и вложения.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import zipfile
from email import message_from_binary_file, policy
from email.utils import getaddresses, parsedate_to_datetime

from ..config import Config
from ..models import Attachment, EmailMessage
from ..detectors.util import extract_urls

# Извлечение пар (текст, href) из HTML-тела письма.
_ANCHOR_RE = re.compile(
    r"<a\b[^>]*?href=[\"'](?P<href>[^\"']+)[\"'][^>]*>(?P<text>.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    """Грубое удаление HTML-тегов для получения читаемого текста."""
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = _TAG_RE.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


class EmlParser:
    """Преобразует .eml-файлы в объекты EmailMessage."""

    def __init__(self, config: Config):
        self.config = config

    def parse_dir(self, directory: str) -> list[EmailMessage]:
        """Разбирает все .eml-файлы в каталоге."""
        if not directory or not os.path.isdir(directory):
            return []
        result: list[EmailMessage] = []
        for name in sorted(os.listdir(directory)):
            if name.lower().endswith(".eml"):
                msg = self.parse_file(os.path.join(directory, name))
                if msg:
                    result.append(msg)
        return result

    def parse_file(self, path: str) -> EmailMessage | None:
        with open(path, "rb") as fh:
            msg = message_from_binary_file(fh, policy=policy.default)
        parsed = self._parse_message(msg)
        parsed.source_file = os.path.basename(path)
        return parsed

    # ------------------------------------------------------------------ #

    def _parse_message(self, msg) -> EmailMessage:
        from_addr = self._first_addr(msg.get("From"))
        to_addrs = self._all_addrs(msg.get_all("To", []) + msg.get_all("Cc", []))

        out = EmailMessage(
            message_id=(msg.get("Message-ID") or "").strip("<> ") or None,
            timestamp=self._date(msg.get("Date")),
            from_addr=from_addr,
            to_addrs=to_addrs,
            subject=msg.get("Subject"),
            reply_to=self._first_addr(msg.get("Reply-To")),
        )

        text_parts: list[str] = []
        html_parts: list[str] = []
        self._walk(msg, out, text_parts, html_parts)

        # Тело: берём plain text и добавляем текст из HTML, чтобы детекторы
        # (ключевые слова, ПДн) видели содержимое обеих версий письма.
        body = "\n".join(text_parts).strip()
        if html_parts:
            html_text = _strip_html("\n".join(html_parts))
            if html_text and html_text not in body:
                body = (body + "\n" + html_text).strip()
        out.body_text = body

        # Ссылки: из текста и из HTML (с парами текст→href).
        urls: list[str] = list(extract_urls(body))
        for html in html_parts:
            for m in _ANCHOR_RE.finditer(html):
                href = m.group("href").strip()
                anchor_text = _strip_html(m.group("text"))
                if href.lower().startswith(("http://", "https://")):
                    out.anchors.append((anchor_text, href))
                    urls.append(href)
        # уникализируем, сохраняя порядок
        seen: set[str] = set()
        out.urls = [u for u in urls if not (u in seen or seen.add(u))]

        out.direction = (
            "outbound" if self.config.is_internal_domain(out.from_domain) else "inbound"
        )
        return out

    def _walk(self, msg, out: EmailMessage, text_parts, html_parts) -> None:
        """Рекурсивно обходит части письма, собирая тело и вложения."""
        if msg.is_multipart():
            for part in msg.iter_parts():
                self._walk(part, out, text_parts, html_parts)
            return

        filename = msg.get_filename()
        disposition = (msg.get_content_disposition() or "").lower()
        ctype = msg.get_content_type()

        # Вложение определяется именем файла или disposition=attachment.
        if filename or disposition == "attachment":
            payload = msg.get_payload(decode=True) or b""
            att = Attachment(
                filename=filename or "(без имени)",
                content_type=ctype,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest() if payload else None,
            )
            self._inspect_archive(att, payload)
            out.attachments.append(att)
            return

        # Иначе это часть тела.
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if not isinstance(content, str):
            return
        if ctype == "text/plain":
            text_parts.append(content)
        elif ctype == "text/html":
            html_parts.append(content)

    # Office-форматы — это zip-контейнеры; ищем в них реальный макрос.
    _OFFICE_ZIP = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".dotm"}

    def _inspect_archive(self, att: Attachment, payload: bytes) -> None:
        """Заглядывает внутрь zip-контейнера штатным zipfile:
          * для .zip — список файлов и признак шифрования (ВПО в архиве);
          * для Office-документов — наличие vbaProject.bin (реальный макрос)."""
        if not payload:
            return
        if att.ext != ".zip" and att.ext not in self._OFFICE_ZIP:
            return
        limit = self.config.attachments.get("max_inspect_archive_bytes", 20_000_000)
        if len(payload) > limit:
            return
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename
                    if att.ext == ".zip":
                        att.inner_files.append(name)
                        if info.flag_bits & 0x1:   # бит 0 = файл зашифрован
                            att.encrypted_archive = True
                    elif name.lower().endswith("vbaproject.bin"):
                        att.has_macro = True
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return

    # ------------------------------------------------------------------ #

    @staticmethod
    def _first_addr(value) -> str | None:
        if not value:
            return None
        addrs = getaddresses([str(value)])
        return addrs[0][1].lower() if addrs and addrs[0][1] else None

    @staticmethod
    def _all_addrs(values) -> list[str]:
        out: list[str] = []
        for _, addr in getaddresses([str(v) for v in values]):
            if addr:
                low = addr.lower()
                if low not in out:
                    out.append(low)
        return out

    @staticmethod
    def _date(value):
        if not value:
            return None
        try:
            dt = parsedate_to_datetime(str(value))
            # приводим к наивному времени (без tz) для единообразия с логами
            return dt.replace(tzinfo=None) if dt and dt.tzinfo else dt
        except (TypeError, ValueError):
            return None
