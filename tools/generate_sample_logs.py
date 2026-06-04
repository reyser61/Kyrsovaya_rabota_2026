"""Генератор тестовых почтовых логов (Postfix + Dovecot).

Создаёт реалистичные логи со смесью легитимного трафика и заложенных угроз,
чтобы продемонстрировать работу детекторов фишинга, DLP и компрометации.

Запуск:  python tools/generate_sample_logs.py
Файлы:   data/sample_logs/postfix.log
         data/sample_logs/dovecot.log
"""

from __future__ import annotations

import os
import random
import sys
from datetime import datetime, timedelta

# На Windows консоль по умолчанию cp1252 — переключаем вывод на UTF-8,
# чтобы корректно печатать кириллицу.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

random.seed(42)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "data", "sample_logs")
HOST = "mail"

BASE = datetime.now().replace(hour=9, minute=0, second=0, microsecond=0)


_MON = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def ts(dt: datetime) -> str:
    """Форматирует время в стиле syslog: 'Jun  2 09:00:00'.

    Месяц всегда по-английски (как в реальном syslog), день дополняется
    пробелом до двух знаков. Не зависит от локали ОС.
    """
    return f"{_MON[dt.month]} {dt.day:2d} {dt:%H:%M:%S}"


def _qid() -> str:
    return "".join(random.choice("0123456789ABCDEF") for _ in range(10))


# ============================================================================
#  Postfix (SMTP)
# ============================================================================
postfix_lines: list[str] = []


def smtp_message(
    dt: datetime,
    *,
    client_host: str,
    client_ip: str,
    helo: str,
    mail_from: str,
    rcpts: list[str],
    subject: str | None,
    size: int,
    status: str = "sent",
    spf: str | None = None,
    dkim: str | None = None,
    dmarc: str | None = None,
    sasl_user: str | None = None,
    pid: int | None = None,
) -> None:
    """Добавляет полный набор строк жизненного цикла одного письма."""
    pid = pid or random.randint(1000, 9999)
    qid = _qid()
    nrcpt = len(rcpts)

    postfix_lines.append(
        f"{ts(dt)} {HOST} postfix/smtpd[{pid}]: connect from {client_host}[{client_ip}]"
    )
    sasl = f", sasl_username={sasl_user}" if sasl_user else ""
    postfix_lines.append(
        f"{ts(dt)} {HOST} postfix/smtpd[{pid}]: {qid}: "
        f"client={client_host}[{client_ip}], helo=<{helo}>{sasl}"
    )
    postfix_lines.append(
        f"{ts(dt)} {HOST} postfix/cleanup[{pid+1}]: {qid}: "
        f"message-id=<{qid.lower()}@{helo}>"
    )
    if subject:
        postfix_lines.append(
            f"{ts(dt)} {HOST} postfix/cleanup[{pid+1}]: {qid}: "
            f"warning: header Subject: {subject} from {client_host}[{client_ip}]"
        )
    if spf is not None:
        postfix_lines.append(
            f"{ts(dt)} {HOST} opendmarc[{pid+2}]: {qid}: SPF(mailfrom): {spf}"
        )
    if dkim is not None:
        postfix_lines.append(
            f"{ts(dt)} {HOST} opendmarc[{pid+2}]: {qid}: DKIM: {dkim}"
        )
    if dmarc is not None:
        postfix_lines.append(
            f"{ts(dt)} {HOST} opendmarc[{pid+2}]: {qid}: DMARC: {dmarc}"
        )
    postfix_lines.append(
        f"{ts(dt)} {HOST} postfix/qmgr[{pid+3}]: {qid}: "
        f"from=<{mail_from}>, size={size}, nrcpt={nrcpt} (queue active)"
    )
    for rcpt in rcpts:
        postfix_lines.append(
            f"{ts(dt)} {HOST} postfix/smtp[{pid+4}]: {qid}: to=<{rcpt}>, "
            f"relay=mx.dest[10.0.0.9]:25, delay=0.8, status={status} (250 2.0.0 OK)"
        )


# Темы и домены для генерации разнообразного легитимного трафика.
_LEGIT_SUBJECTS = [
    "Договор на согласование", "Счёт-фактура за май", "Протокол совещания",
    "Коммерческое предложение", "Акт выполненных работ", "Отчёт за квартал",
    "Приглашение на вебинар", "Обновление прайс-листа", "Ответ на ваш запрос",
    "Уточнение по поставке", "График отгрузок", "Согласование сметы",
]
_PARTNER_DOMAINS = ["partner.com", "gov-client.ru", "supplier.example",
                    "logistics.example", "audit-firm.example"]


def build_postfix() -> None:
    t = BASE

    # --- много легитимного входящего трафика (от партнёров, проходит проверки) ---
    for i in range(40):
        t += timedelta(minutes=2)
        dom = random.choice(_PARTNER_DOMAINS)
        smtp_message(
            t,
            client_host=f"mx{i % 4}.{dom}",
            client_ip=f"203.0.113.{20 + (i % 60)}",
            helo=f"mx{i % 4}.{dom}",
            mail_from=f"manager{i % 7}@{dom}",
            rcpts=[f"user{i % 8}@corp-mail.ru"],
            subject=random.choice(_LEGIT_SUBJECTS),
            size=random.randint(8000, 250000),
            spf="pass", dkim="pass", dmarc="pass",
        )

    # --- легитимная внутренняя переписка (исходящие, без внешних адресатов) ---
    for i in range(15):
        t += timedelta(minutes=2)
        smtp_message(
            t,
            client_host="workstation", client_ip=f"10.0.5.{20 + i}",
            helo="workstation.corp-mail.ru",
            mail_from=f"employee{i % 6}@corp-mail.ru",
            rcpts=[f"colleague{i % 5}@corp-mail.ru"],
            subject=random.choice(_LEGIT_SUBJECTS),
            size=random.randint(5000, 60000),
            sasl_user=f"employee{i % 6}@corp-mail.ru",
        )

    # --- легитимные исходящие доверенным партнёрам (не должны тревожить) ---
    for i in range(8):
        t += timedelta(minutes=2)
        smtp_message(
            t,
            client_host="workstation", client_ip=f"10.0.6.{30 + i}",
            helo="workstation.corp-mail.ru",
            mail_from=f"sales{i % 3}@corp-mail.ru",
            rcpts=[f"buyer{i % 4}@partner.com"],
            subject=random.choice(_LEGIT_SUBJECTS),
            size=random.randint(10000, 120000),
            sasl_user=f"sales{i % 3}@corp-mail.ru",
        )

    # --- (демонстрация прежней внутренней переписки) ---
    for i in range(4):
        t += timedelta(minutes=3)
        smtp_message(
            t,
            client_host="workstation", client_ip="10.0.5.21",
            helo="workstation.corp-mail.ru",
            mail_from=f"ivanov@corp-mail.ru",
            rcpts=[f"petrov{i}@corp-mail.ru"],
            subject="Совещание в 15:00",
            size=12000, sasl_user="ivanov@corp-mail.ru",
        )

    # === ФИШИНГ 1: спуфинг руководителя (внешний IP выдаёт себя за наш домен) ===
    t += timedelta(minutes=5)
    smtp_message(
        t,
        client_host="unknown", client_ip="91.214.124.77",
        helo="[91.214.124.77]",
        mail_from="ceo@corp-mail.ru",
        rcpts=["buhgalter@corp-mail.ru"],
        subject="Срочно подтвердите перевод средств контрагенту",
        size=4200, spf="fail", dkim="fail", dmarc="fail",
    )

    # === ФИШИНГ 2: домен-двойник (typosquatting) ===
    t += timedelta(minutes=6)
    smtp_message(
        t,
        client_host="mail.corp-maill.ru", client_ip="45.137.21.9",
        helo="mail.corp-maill.ru",
        mail_from="support@corp-maill.ru",
        rcpts=["ivanov@corp-mail.ru"],
        subject="Обновите пароль, иначе аккаунт будет заблокирован",
        size=5300, spf="softfail", dkim="fail", dmarc="fail",
    )

    # === ФИШИНГ 3: провал DMARC + манипулятивная тема ===
    t += timedelta(minutes=7)
    smtp_message(
        t,
        client_host="srv.promo-deals.top", client_ip="193.43.146.12",
        helo="srv.promo-deals.top",
        mail_from="win@promo-deals.top",
        rcpts=["user1@corp-mail.ru"],
        subject="Вы выиграли приз! Подтвердите учетную запись",
        size=8800, spf="fail", dkim="none", dmarc="fail",
    )

    # === ФИШИНГ 4: массовая рассылка ===
    t += timedelta(minutes=8)
    smtp_message(
        t,
        client_host="bulk.spam-net.ru", client_ip="178.62.99.4",
        helo="bulk.spam-net.ru",
        mail_from="noreply@spam-net.ru",
        rcpts=[f"staff{i}@corp-mail.ru" for i in range(20)],
        subject="Срочно: проверьте вашу почту",
        size=15000, spf="fail", dkim="fail", dmarc="fail",
    )

    # === DLP 1: конфиденциальные данные на личную почту ===
    t += timedelta(minutes=10)
    smtp_message(
        t,
        client_host="workstation", client_ip="10.0.5.33",
        helo="workstation.corp-mail.ru",
        mail_from="sidorov@corp-mail.ru",
        rcpts=["sidorov.personal@gmail.com"],
        subject="Конфиденциально: база клиентов и реквизиты",
        size=2400000, sasl_user="sidorov@corp-mail.ru",
    )

    # === DLP 2: крупное вложение наружу вне рабочего времени ===
    t_night = BASE.replace(hour=23, minute=15)
    smtp_message(
        t_night,
        client_host="workstation", client_ip="10.0.5.40",
        helo="workstation.corp-mail.ru",
        mail_from="kadrov@corp-mail.ru",
        rcpts=["external@partner.com"],
        subject="Архив документов",
        size=9_500_000, sasl_user="kadrov@corp-mail.ru",
    )

    # === DLP 3: персональные данные (номер карты) в теме ===
    t += timedelta(minutes=12)
    smtp_message(
        t,
        client_host="workstation", client_ip="10.0.5.51",
        helo="workstation.corp-mail.ru",
        mail_from="finotdel@corp-mail.ru",
        rcpts=["partner.pay@yandex.ru"],
        subject="Оплата по карте 4276 3801 2345 6789 паспорт 45 11 223344",
        size=30000, sasl_user="finotdel@corp-mail.ru",
    )

    # === DLP 4: эксфильтрация — много писем одному внешнему адресу ===
    for i in range(12):
        t += timedelta(minutes=2)
        smtp_message(
            t,
            client_host="workstation", client_ip="10.0.5.60",
            helo="workstation.corp-mail.ru",
            mail_from="analytik@corp-mail.ru",
            rcpts=["collector2024@gmail.com"],
            subject=f"Выгрузка отчёта часть {i+1}",
            size=480000, sasl_user="analytik@corp-mail.ru",
        )


# ============================================================================
#  Dovecot (IMAP)
# ============================================================================
dovecot_lines: list[str] = []


def imap_login(dt, user, rip, *, tls=True, method="PLAIN"):
    sec = " TLS," if tls else ""
    dovecot_lines.append(
        f"{ts(dt)} {HOST} dovecot: imap-login: Login: user=<{user}>, "
        f"method={method}, rip={rip}, lip=10.0.0.5, mpid={random.randint(2000,9000)},"
        f"{sec} session=<{_qid()}>"
    )


def imap_fail(dt, user, rip, attempts=1, method="PLAIN"):
    dovecot_lines.append(
        f"{ts(dt)} {HOST} dovecot: imap-login: Disconnected (auth failed, "
        f"{attempts} attempts in 2 secs): user=<{user}>, method={method}, "
        f"rip={rip}, lip=10.0.0.5"
    )


def build_dovecot() -> None:
    t = BASE

    # --- много нормальных входов с TLS (штатная работа сотрудников) ---
    for i in range(30):
        t += timedelta(minutes=3)
        imap_login(t, f"user{i % 8}@corp-mail.ru", f"10.0.5.{30 + (i % 40)}")

    # === АККАУНТ 1: брутфорс с одного IP + последующий захват ящика ===
    bf_ip = "185.220.101.45"
    bt = BASE.replace(hour=2, minute=0)
    for i in range(7):
        bt += timedelta(seconds=40)
        imap_fail(bt, "buhgalter@corp-mail.ru", bf_ip, attempts=i + 1)
    bt += timedelta(seconds=30)
    imap_login(bt, "buhgalter@corp-mail.ru", bf_ip)  # успешный вход = захват

    # === АККАУНТ 2: «невозможное перемещение» — два входа из разных сетей ===
    it = BASE.replace(hour=14, minute=0)
    imap_login(it, "ivanov@corp-mail.ru", "192.0.2.10")
    imap_login(it + timedelta(minutes=18), "ivanov@corp-mail.ru", "198.51.100.77")

    # === АККАУНТ 3: вход без TLS (пароль в открытом виде) ===
    imap_login(BASE.replace(hour=11, minute=30), "petrov@corp-mail.ru",
               "10.0.5.99", tls=False)


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    build_postfix()
    build_dovecot()

    pf = os.path.join(OUT_DIR, "postfix.log")
    dc = os.path.join(OUT_DIR, "dovecot.log")
    with open(pf, "w", encoding="utf-8") as fh:
        fh.write("\n".join(postfix_lines) + "\n")
    with open(dc, "w", encoding="utf-8") as fh:
        fh.write("\n".join(dovecot_lines) + "\n")

    print(f"Готово:\n  {pf} ({len(postfix_lines)} строк)\n  {dc} ({len(dovecot_lines)} строк)")


if __name__ == "__main__":
    main()
