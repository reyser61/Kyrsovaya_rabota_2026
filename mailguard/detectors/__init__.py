"""Детекторы угроз MailGuard.

  * PhishingDetector   — фишинг по метаданным (аутентификация, спуфинг, HELO…);
  * ContentDetector    — контент по ТЕМЕ+ТЕЛУ (манипуляции, ПДн, секреты,
                         выманивание данных) + декларативные правила;
  * LinkDetector       — фишинговые ссылки в теле;
  * AttachmentDetector — анализ вложений (ВПО + DLP);
  * DlpDetector        — утечки по метаданным (личная почта, объём, эксфильтрация);
  * AccountDetector    — компрометация аккаунтов по логам IMAP.
"""

from .phishing import PhishingDetector
from .content import ContentDetector
from .links import LinkDetector
from .attachment import AttachmentDetector
from .dlp import DlpDetector
from .account import AccountDetector
from .ioc_match import IocMatchDetector

__all__ = [
    "PhishingDetector",
    "ContentDetector",
    "LinkDetector",
    "AttachmentDetector",
    "DlpDetector",
    "AccountDetector",
    "IocMatchDetector",
]
