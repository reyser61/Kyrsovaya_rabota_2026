"""Генератор тестовых писем .eml для демонстрации анализа тела и вложений.

Создаёт набор писем со встроенными угрозами (фишинговые ссылки, опасные
вложения, утечки конфиденциальных данных) и одно легитимное письмо.

Запуск:  python tools/generate_sample_emails.py
Каталог: data/sample_emails/*.eml
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "data", "sample_emails")


def _save(name: str, msg: EmailMessage) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    with open(path, "wb") as fh:
        fh.write(msg.as_bytes())
    print(f"  {name}")


def _base(subject: str, sender: str, to: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="mail.example")
    return msg


# ---------------------------------------------------------------------------
# 1) ФИШИНГ: выманивание учётных данных + подменённые/опасные ссылки
# ---------------------------------------------------------------------------
def phishing_credentials() -> None:
    msg = _base(
        "Подтвердите учетную запись — срочно",
        "security@sberbank-secure.top",
        "ivanov@corp-mail.ru",
    )
    # Reply-To ведёт на чужой домен (сбор ответов жертв) — признак фишинга.
    msg["Reply-To"] = "collector@evil-drop.top"
    msg.set_content(
        "Ваша учетная запись будет заблокирована.\n"
        "Перейдите по ссылке и введите пароль, чтобы подтвердить личность."
    )
    # видимый текст ссылки выглядит как наш домен, href ведёт на чужой сайт;
    # ссылка на IP-адрес, punycode-домен (IDN-омоглиф) и просьба ввести карту.
    msg.add_alternative(
        """<html><body>
        <p>Уважаемый клиент! Ваша учетная запись будет <b>заблокирована</b>.</p>
        <p>Срочно <a href="http://malicious-login.ru/verify">https://online.corp-mail.ru/login</a>
           войдите в систему и введите пароль.</p>
        <p>Резервный вход: <a href="http://93.184.216.34/secure">резервный сервер</a></p>
        <p>Банк-онлайн: <a href="https://xn--80ak6aa92e.com/login">безопасный вход</a></p>
        <p>Также подтвердите <b>номер карты</b> и <b>CVV</b>.</p>
        </body></html>""",
        subtype="html",
    )
    _save("01_phishing_credentials.eml", msg)


# ---------------------------------------------------------------------------
# 2) ФИШИНГ: исполняемое вложение с двойным расширением
# ---------------------------------------------------------------------------
def phishing_exe_attachment() -> None:
    msg = _base(
        "Счет на оплату",
        "buh@postavshik-deals.xyz",
        "buhgalter@corp-mail.ru",
    )
    msg.set_content("Здравствуйте! Счет на оплату во вложении. С уважением.")
    msg.add_attachment(
        b"MZ\x90\x00 fake executable payload",
        maintype="application",
        subtype="x-msdownload",
        filename="Счет_на_оплату.pdf.exe",
    )
    _save("02_phishing_exe.eml", msg)


# ---------------------------------------------------------------------------
# 3) ФИШИНГ: документ с макросами
# ---------------------------------------------------------------------------
def phishing_macro_attachment() -> None:
    msg = _base(
        "Договор на согласование",
        "partner@unknown-corp.click",
        "ivanov@corp-mail.ru",
    )
    msg.set_content("Договор во вложении, включите макросы для просмотра.")
    msg.add_attachment(
        b"PK\x03\x04 fake docm with macros",
        maintype="application",
        subtype="vnd.ms-word.document.macroEnabled.12",
        filename="Договор_2026.docm",
    )
    _save("03_phishing_macro.eml", msg)


# ---------------------------------------------------------------------------
# 3b) ФИШИНГ: исполняемый файл, спрятанный внутри ZIP-архива
# ---------------------------------------------------------------------------
def phishing_zip_exe() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Платежное_поручение.exe", b"MZ\x90\x00 fake payload inside zip")
    msg = _base(
        "Платёжное поручение",
        "billing@account-verify.xyz",
        "buhgalter@corp-mail.ru",
    )
    msg.set_content("Документ во вложении (архив). Откройте файл внутри.")
    msg.add_attachment(
        buf.getvalue(), maintype="application", subtype="zip",
        filename="Платежное_поручение.zip",
    )
    _save("07_phishing_zip_exe.eml", msg)


# ---------------------------------------------------------------------------
# 4) DLP: конфиденциальные данные в теле + чувствительное вложение наружу
# ---------------------------------------------------------------------------
def dlp_client_base() -> None:
    msg = _base(
        "Материалы",
        "sidorov@corp-mail.ru",
        "sidorov.personal@gmail.com",
    )
    msg.set_content(
        "Конфиденциально. Высылаю базу клиентов и реквизиты.\n"
        "Тестовая карта: 4111 1111 1111 1111, паспорт 45 11 223344.\n"
        "Доступ к API: api_key=AKIAIOSFODNN7EXAMPLE12345\n"
        "Пароль от архива: 1234."
    )
    msg.add_attachment(
        b"id;name;phone\n1;client;+700000000\n" * 100,
        maintype="application",
        subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename="База_клиентов.xlsx",
    )
    _save("04_dlp_client_base.eml", msg)


# ---------------------------------------------------------------------------
# 5) DLP: крупный дамп базы данных уходит внешнему адресату
# ---------------------------------------------------------------------------
def dlp_db_dump() -> None:
    msg = _base(
        "Архив",
        "analytik@corp-mail.ru",
        "external@partner.com",
    )
    msg.set_content("Выгрузка во вложении.")
    msg.add_attachment(
        b"-- SQL dump\n" + b"INSERT INTO users VALUES (1);\n" * 250000,
        maintype="application",
        subtype="sql",
        filename="dump.sql",
    )
    _save("05_dlp_db_dump.eml", msg)


# ---------------------------------------------------------------------------
# 6) Легитимное письмо (контроль — не должно порождать инцидентов)
# ---------------------------------------------------------------------------
def legitimate() -> None:
    msg = _base(
        "Договор на согласование",
        "manager@partner.com",
        "ivanov@corp-mail.ru",
    )
    msg.set_content(
        "Здравствуйте! Договор во вложении. Подробности на нашем сайте."
    )
    msg.add_alternative(
        """<html><body><p>Здравствуйте!</p>
        <p>Подробности на <a href="https://partner.com/contract">partner.com</a></p>
        </body></html>""",
        subtype="html",
    )
    msg.add_attachment(
        b"%PDF-1.4 fake pdf content",
        maintype="application",
        subtype="pdf",
        filename="Договор.pdf",
    )
    _save("06_legitimate.eml", msg)


def main() -> None:
    print("Создаю тестовые письма .eml:")
    phishing_credentials()
    phishing_exe_attachment()
    phishing_macro_attachment()
    phishing_zip_exe()
    dlp_client_base()
    dlp_db_dump()
    legitimate()
    print(f"Готово. Каталог: {OUT_DIR}")


if __name__ == "__main__":
    main()
