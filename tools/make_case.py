"""Генератор тестовых сценариев («кейсов») под конкретный вердикт или правила.

Позволяет создать лог/письмо, которое ДОЛЖНО (или НЕ должно) детектироваться, и
проверить работу конкретных правил. Удобно на защите: «покажите, что система
ловит фишинг с высокой достоверностью» или «что это письмо НЕ сработает».

Примеры:
  # Готовые пресеты (вердикт + достоверность):
  py tools/make_case.py --preset phishing-high
  py tools/make_case.py --preset dlp-medium
  py tools/make_case.py --preset clean
  py tools/make_case.py --preset imap-bruteforce

  # Под конкретные правила (через запятую):
  py tools/make_case.py --type eml  --rules phishing.attachment_double_ext,phishing.url_text_mismatch
  py tools/make_case.py --type smtp --rules phishing.spoofed_internal,phishing.dmarc_fail

  # Справка по поддерживаемым правилам:
  py tools/make_case.py --list-rules

После генерации запустите анализ на полученном файле, напр.:
  py run.py analyze --emails data/cases --save
  py run.py analyze --postfix data/cases/case.log --save
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import sys
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASE_DIR = os.path.join(ROOT, "data", "cases")

INTERNAL = "corp-mail.ru"
VICTIM = f"buhgalter@{INTERNAL}"
INSIDER = f"sidorov@{INTERNAL}"
EXT_GMAIL = "drop2026@gmail.com"
VALID_CARD = "4111 1111 1111 1111"   # проходит алгоритм Луна

_MON = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _syslog_ts(dt: datetime) -> str:
    return f"{_MON[dt.month]} {dt.day:2d} {dt:%H:%M:%S}"


@dataclass
class Spec:
    """Описание письма; правила-рецепты модифицируют поля, рендер собирает файл."""
    direction: str = "inbound"          # inbound (фишинг) / outbound (DLP)
    from_addr: str = "attacker@unknown-sender.example"
    to_addrs: list[str] = field(default_factory=lambda: [VICTIM])
    subject: str = "Рабочее письмо"
    body: list[str] = field(default_factory=lambda: ["Здравствуйте. Текст письма."])
    anchors: list[tuple[str, str]] = field(default_factory=list)   # (текст, href)
    attachments: list[dict] = field(default_factory=list)
    reply_to: str | None = None
    # SMTP-метаданные
    client_ip: str = "203.0.113.55"
    helo: str = "mail.unknown-sender.example"
    spf: str | None = "pass"
    dkim: str | None = "pass"
    dmarc: str | None = "pass"
    size: int = 24000


# --------------------------------------------------------------------------- #
#  Рецепты правил: как смодифицировать Spec, чтобы сработало конкретное правило
# --------------------------------------------------------------------------- #
def _macro_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/vbaProject.bin", b"\x00fake macro project")
    return buf.getvalue()


def _zip_with(name: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, b"MZ payload")
    return buf.getvalue()


def att(filename, data=b"data", **kw):
    return {"filename": filename, "data": data, **kw}


RECIPES = {
    # --- метаданные (лучше с --type smtp) ---
    "phishing.spoofed_internal": lambda s: (
        setattr(s, "from_addr", f"ceo@{INTERNAL}"), setattr(s, "client_ip", "91.214.124.77")),
    "phishing.dmarc_fail": lambda s: setattr(s, "dmarc", "fail"),
    "phishing.spf_fail": lambda s: setattr(s, "spf", "fail"),
    "phishing.dkim_fail": lambda s: setattr(s, "dkim", "fail"),
    "phishing.lookalike_sender": lambda s: setattr(s, "from_addr", "support@corp-maill.ru"),
    "phishing.helo_mismatch": lambda s: setattr(s, "helo", "[91.214.124.77]"),
    "phishing.mass_recipients": lambda s: setattr(
        s, "to_addrs", [f"staff{i}@{INTERNAL}" for i in range(20)]),
    "phishing.punycode_sender": lambda s: setattr(s, "from_addr", "info@xn--80ak6aa92e.com"),
    "phishing.replyto_mismatch": lambda s: setattr(s, "reply_to", "collector@evil-drop.top"),
    # --- контент (тема/тело) ---
    "phishing.manipulative_content": lambda s: setattr(
        s, "subject", "Срочно подтвердите, иначе аккаунт будет заблокирован"),
    "phishing.credential_request": lambda s: s.body.append(
        "Перейдите по ссылке и введите пароль для подтверждения."),
    "dlp.confidential_keyword": lambda s: s.body.append(
        "Конфиденциально. Содержит реквизиты и коммерческую тайну."),
    "dlp.pii": lambda s: s.body.append(f"Данные карты: {VALID_CARD}, паспорт 45 11 223344."),
    "dlp.secret_exposure": lambda s: s.body.append("api_key=AKIAIOSFODNN7EXAMPLE12345"),
    # --- ссылки (только --type eml) ---
    "phishing.url_ip_literal": lambda s: s.anchors.append(
        ("перейти", "http://93.184.216.34/login")),
    "phishing.url_text_mismatch": lambda s: s.anchors.append(
        (f"online.{INTERNAL}", "http://malicious-login.ru/verify")),
    "phishing.url_lookalike": lambda s: s.anchors.append(("вход", "http://corp-maill.ru/")),
    "phishing.url_suspicious_tld": lambda s: s.anchors.append(("акция", "http://promo.top/win")),
    "phishing.url_punycode": lambda s: s.anchors.append(("банк", "https://xn--80ak6aa92e.com/")),
    # --- вложения (только --type eml) ---
    "phishing.attachment_dangerous": lambda s: s.attachments.append(att("update.exe")),
    "phishing.attachment_double_ext": lambda s: s.attachments.append(att("Счет.pdf.exe")),
    "phishing.attachment_real_macro": lambda s: s.attachments.append(
        att("Договор.docx", _macro_docx())),
    "phishing.attachment_macro": lambda s: s.attachments.append(att("Отчет.docm")),
    "phishing.attachment_archive": lambda s: s.attachments.append(att("photos.zip", _zip_with("a.jpg"))),
    "phishing.attachment_archive_inner": lambda s: s.attachments.append(
        att("Документ.zip", _zip_with("invoice.exe"))),
    "phishing.attachment_html": lambda s: s.attachments.append(att("form.html", b"<html></html>")),
    "dlp.attachment_highrisk": lambda s: s.attachments.append(att("dump.sql", b"-- sql")),
    "dlp.attachment_office": lambda s: s.attachments.append(att("report.xlsx", b"xl")),
    "dlp.attachment_large": lambda s: s.attachments.append(att("big.bin", b"x" * 6_000_000)),
    # --- DLP метаданные ---
    "dlp.free_mail_recipient": lambda s: setattr(s, "to_addrs", [EXT_GMAIL]),
    "dlp.large_external": lambda s: setattr(s, "size", 9_000_000),
    # --- совпадение с блок-листом IoC ---
    "ioc.match_domain": lambda s: s.anchors.append(("вход", "http://malicious-login.ru/")),
    "ioc.match_ip": lambda s: setattr(s, "client_ip", "91.214.124.77"),
}

DLP_RULES = {r for r in RECIPES if r.startswith("dlp.")}

PRESETS = {
    "phishing-high": ("smtp", ["phishing.spoofed_internal", "phishing.dmarc_fail",
                               "phishing.spf_fail", "phishing.manipulative_content"]),
    "phishing-medium": ("smtp", ["phishing.dmarc_fail", "phishing.manipulative_content"]),
    "phishing-low": ("smtp", ["phishing.spf_fail", "phishing.helo_mismatch"]),
    # DLP-контент живёт в теле письма -> генерируем .eml (в логе тела нет)
    "dlp-high": ("eml", ["dlp.pii", "dlp.confidential_keyword", "dlp.free_mail_recipient"]),
    "dlp-medium": ("eml", ["dlp.confidential_keyword", "dlp.free_mail_recipient"]),
    "dlp-low": ("eml", ["dlp.attachment_office", "dlp.free_mail_recipient"]),
    "clean": ("smtp", []),
    # коррелированная пара лог+письмо: метаданные из SMTP + содержимое из EML
    "phishing-correlated": ("smtp+eml", [
        "phishing.spoofed_internal", "phishing.dmarc_fail",
        "phishing.manipulative_content", "phishing.credential_request",
        "phishing.attachment_double_ext"]),
    "imap-bruteforce": ("imap", ["account.bruteforce"]),
    "imap-takeover": ("imap", ["account.takeover"]),
    "imap-travel": ("imap", ["account.impossible_travel"]),
    "imap-plaintext": ("imap", ["account.plaintext_login"]),
}


def apply_rules(rules: list[str]) -> Spec:
    s = Spec()
    if any(r in DLP_RULES for r in rules):
        # DLP-сценарий: исходящее от инсайдера наружу
        s.direction = "outbound"
        s.from_addr = INSIDER
        s.to_addrs = [EXT_GMAIL]
        s.client_ip = "10.0.5.51"
        s.helo = f"workstation.{INTERNAL}"
        s.subject = "Материалы"
    for r in rules:
        recipe = RECIPES.get(r)
        if recipe:
            recipe(s)
        else:
            print(f"  ! правило не поддерживается генератором: {r}")
    return s


# --------------------------------------------------------------------------- #
#  Рендер
# --------------------------------------------------------------------------- #
def render_eml(spec: Spec, path: str, message_id: str | None = None) -> None:
    msg = EmailMessage()
    msg["Subject"] = spec.subject
    msg["From"] = spec.from_addr
    msg["To"] = ", ".join(spec.to_addrs)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = f"<{message_id}>" if message_id else make_msgid(domain="case.local")
    if spec.reply_to:
        msg["Reply-To"] = spec.reply_to
    msg.set_content("\n".join(spec.body))
    if spec.anchors:
        links = "".join(f'<p><a href="{h}">{t}</a></p>' for t, h in spec.anchors)
        msg.add_alternative(f"<html><body>{''.join('<p>'+b+'</p>' for b in spec.body)}"
                            f"{links}</body></html>", subtype="html")
    for a in spec.attachments:
        msg.add_attachment(a["data"], maintype="application",
                           subtype="octet-stream", filename=a["filename"])
    with open(path, "wb") as fh:
        fh.write(msg.as_bytes())


def render_smtp(spec: Spec, path: str, message_id: str | None = None) -> None:
    t = datetime.now().replace(microsecond=0)
    qid = hashlib.md5(spec.subject.encode()).hexdigest()[:10].upper()
    mid = message_id or f"{qid.lower()}@case.local"
    host, pid = "mail", 4242
    sasl = f", sasl_username={spec.from_addr}" if spec.direction == "outbound" else ""
    L = []
    L.append(f"{_syslog_ts(t)} {host} postfix/smtpd[{pid}]: connect from "
             f"{spec.helo}[{spec.client_ip}]")
    L.append(f"{_syslog_ts(t)} {host} postfix/smtpd[{pid}]: {qid}: "
             f"client={spec.helo}[{spec.client_ip}], helo=<{spec.helo}>{sasl}")
    L.append(f"{_syslog_ts(t)} {host} postfix/cleanup[{pid+1}]: {qid}: "
             f"message-id=<{mid}>")
    L.append(f"{_syslog_ts(t)} {host} postfix/cleanup[{pid+1}]: {qid}: "
             f"warning: header Subject: {spec.subject} from {spec.helo}[{spec.client_ip}]")
    for tag, val in (("SPF(mailfrom)", spec.spf), ("DKIM", spec.dkim), ("DMARC", spec.dmarc)):
        if val is not None:
            L.append(f"{_syslog_ts(t)} {host} opendmarc[{pid+2}]: {qid}: {tag}: {val}")
    L.append(f"{_syslog_ts(t)} {host} postfix/qmgr[{pid+3}]: {qid}: "
             f"from=<{spec.from_addr}>, size={spec.size}, nrcpt={len(spec.to_addrs)} (queue active)")
    for rcpt in spec.to_addrs:
        L.append(f"{_syslog_ts(t)} {host} postfix/smtp[{pid+4}]: {qid}: to=<{rcpt}>, "
                 f"relay=mx[10.0.0.9]:25, delay=0.5, status=sent (250 OK)")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def render_both(spec: Spec, log_path: str, eml_path: str) -> None:
    """Коррелированная пара: лог Postfix + письмо .eml с ОДНИМ Message-ID.
    Движок объединит их в одну запись с источником SMTP+EML
    (метаданные из лога + содержимое из письма)."""
    mid = "case-correlated@case.local"
    render_smtp(spec, log_path, message_id=mid)
    render_eml(spec, eml_path, message_id=mid)


def render_imap(rules: list[str], path: str) -> None:
    host = "mail"
    base = datetime.now().replace(microsecond=0)
    L = []

    def login(dt, user, rip, tls=True):
        sec = " TLS," if tls else ""
        L.append(f"{_syslog_ts(dt)} {host} dovecot: imap-login: Login: user=<{user}>, "
                 f"method=PLAIN, rip={rip}, lip=10.0.0.5, mpid=1,{sec} session=<x>")

    def fail(dt, user, rip, n):
        L.append(f"{_syslog_ts(dt)} {host} dovecot: imap-login: Disconnected "
                 f"(auth failed, {n} attempts in 2 secs): user=<{user}>, method=PLAIN, "
                 f"rip={rip}, lip=10.0.0.5")

    if "account.bruteforce" in rules or "account.takeover" in rules:
        ip = "185.220.101.45"
        for i in range(7):
            fail(base + timedelta(seconds=40 * i), VICTIM, ip, i + 1)
        if "account.takeover" in rules:
            login(base + timedelta(minutes=6), VICTIM, ip)
    if "account.impossible_travel" in rules:
        login(base, f"ivanov@{INTERNAL}", "192.0.2.10")
        login(base + timedelta(minutes=15), f"ivanov@{INTERNAL}", "198.51.100.77")
    if "account.plaintext_login" in rules:
        login(base, f"petrov@{INTERNAL}", "10.0.5.99", tls=False)
    if not L:   # clean
        for i in range(5):
            login(base + timedelta(minutes=5 * i), f"user{i}@{INTERNAL}", f"10.0.5.{30+i}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def main() -> None:
    p = argparse.ArgumentParser(description="Генератор тестовых сценариев MailGuard")
    p.add_argument("--preset", choices=sorted(PRESETS), help="готовый сценарий")
    p.add_argument("--type", choices=["smtp", "eml", "imap", "smtp+eml"],
                   help="тип лога/файла (smtp+eml — коррелированная пара)")
    p.add_argument("--rules", help="список rule id через запятую")
    p.add_argument("--clean", action="store_true", help="заведомо безопасный кейс")
    p.add_argument("--out", help="путь к выходному файлу")
    p.add_argument("--list-rules", action="store_true", help="показать поддерживаемые правила")
    args = p.parse_args()

    if args.list_rules:
        print("Поддерживаемые правила (для --rules):")
        for r in sorted(RECIPES):
            print(f"  {r}")
        print("  account.bruteforce / takeover / impossible_travel / plaintext_login (--type imap)")
        print("\nПресеты (--preset):", ", ".join(sorted(PRESETS)))
        return

    if args.preset:
        ftype, rules = PRESETS[args.preset]
    else:
        ftype = args.type or "eml"
        rules = [] if args.clean else [r.strip() for r in (args.rules or "").split(",") if r.strip()]
        if not rules and not args.clean:
            p.error("укажите --preset, либо --rules, либо --clean")

    res = generate_case(ftype, rules)
    print(f"Создан кейс: {res['out']}")
    print(f"Тип: {ftype}; правил заложено: {len(rules)}"
          + (f" ({', '.join(rules)})" if rules else " (чистый)"))
    print(f"Проверить: {res['run_hint']}")


def generate_case(ftype: str, rules: list[str]) -> dict:
    """Создаёт файл(ы) кейса и возвращает пути для анализа.

    Возвращает словарь с ключами postfix / dovecot / emails_dir (None если не
    применимо), а также out (что создано) и run_hint (команда проверки).
    Используется и из CLI (main), и из интерактивного меню."""
    os.makedirs(CASE_DIR, exist_ok=True)
    res = {"postfix": None, "dovecot": None, "emails_dir": None,
           "out": "", "run_hint": ""}
    if ftype == "imap":
        out = os.path.join(CASE_DIR, "case_dovecot.log")
        render_imap(rules, out)
        res["dovecot"] = out
        res["out"] = out
        res["run_hint"] = f"py run.py analyze --dovecot {os.path.relpath(out, ROOT)} --save"
    elif ftype == "smtp":
        out = os.path.join(CASE_DIR, "case.log")
        render_smtp(apply_rules(rules), out)
        res["postfix"] = out
        res["out"] = out
        res["run_hint"] = f"py run.py analyze --postfix {os.path.relpath(out, ROOT)} --save"
    elif ftype == "smtp+eml":
        log_out = os.path.join(CASE_DIR, "case.log")
        eml_out = os.path.join(CASE_DIR, "case.eml")
        render_both(apply_rules(rules), log_out, eml_out)
        res["postfix"] = log_out
        res["emails_dir"] = CASE_DIR
        res["out"] = f"{log_out} + {eml_out}"
        res["run_hint"] = (f"py run.py analyze --postfix {os.path.relpath(log_out, ROOT)} "
                           f"--emails {os.path.relpath(CASE_DIR, ROOT)} --save")
    else:
        out = os.path.join(CASE_DIR, "case.eml")
        render_eml(apply_rules(rules), out)
        res["emails_dir"] = CASE_DIR
        res["out"] = out
        res["run_hint"] = f"py run.py analyze --emails {os.path.relpath(CASE_DIR, ROOT)} --save"
    return res


if __name__ == "__main__":
    main()
