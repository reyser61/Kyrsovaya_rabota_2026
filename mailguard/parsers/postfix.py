"""Парсер логов Postfix (SMTP).

Postfix пишет жизненный цикл одного письма несколькими строками, связанными
общим идентификатором очереди (queue id), например:

    Jun  2 10:15:32 mail postfix/smtpd[111]: connect from mx.bad.tld[203.0.113.45]
    Jun  2 10:15:33 mail postfix/smtpd[111]: D1A2B[..]: client=mx.bad.tld[203.0.113.45]
    Jun  2 10:15:33 mail postfix/cleanup[112]: D1A2B[..]: message-id=<...>
    Jun  2 10:15:33 mail postfix/cleanup[112]: D1A2B[..]: warning: header Subject: Срочно ...
    Jun  2 10:15:33 mail postfix/qmgr[113]: D1A2B[..]: from=<a@bad.tld>, size=2456, nrcpt=1
    Jun  2 10:15:34 mail postfix/smtp[114]: D1A2B[..]: to=<b@corp.ru>, status=sent (250 OK)

Результаты проверок SPF/DKIM/DMARC добавляют милтеры (opendkim/opendmarc):

    Jun  2 10:15:33 mail opendmarc[120]: D1A2B[..]: SPF(mailfrom): fail
    Jun  2 10:15:33 mail opendmarc[120]: D1A2B[..]: DKIM: fail
    Jun  2 10:15:33 mail opendmarc[120]: D1A2B[..]: DMARC: fail

Парсер группирует строки по queue id и возвращает список MailMessage.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..config import Config
from ..models import MailMessage
from .timeutil import parse_syslog_time

# Идентификатор очереди стоит сразу после имени процесса: "...: ABCD1234: ..."
_QID = r"(?P<qid>[0-9A-F]{6,16})"

_RE_CLIENT = re.compile(rf"{_QID}: client=(?P<host>[^\[]+)\[(?P<ip>[0-9a-fA-F:.]+)\]")
_RE_MSGID = re.compile(rf"{_QID}: message-id=<(?P<mid>[^>]*)>")
_RE_SUBJECT = re.compile(rf"{_QID}: warning: header Subject:\s*(?P<subject>.*?)\s+from\s")
_RE_FROM = re.compile(
    rf"{_QID}: from=<(?P<from>[^>]*)>,\s*size=(?P<size>\d+),\s*nrcpt=(?P<nrcpt>\d+)"
)
_RE_TO = re.compile(rf"{_QID}: to=<(?P<to>[^>]*)>.*?status=(?P<status>\w+)")
_RE_SASL = re.compile(rf"{_QID}: client=.*?sasl_username=(?P<user>[^,\s]+)")
_RE_HELO = re.compile(rf"{_QID}: .*?helo=<(?P<helo>[^>]*)>")
_RE_SPF = re.compile(rf"{_QID}: SPF(?:\([^)]*\))?:\s*(?P<spf>\w+)")
_RE_DKIM = re.compile(rf"{_QID}: DKIM:\s*(?P<dkim>\w+)")
_RE_DMARC = re.compile(rf"{_QID}: DMARC:\s*(?P<dmarc>\w+)")

# Строка connect без queue id — запоминаем IP по pid, чтобы привязать к письму.
_RE_CONNECT = re.compile(
    r"postfix/smtpd\[(?P<pid>\d+)\]: connect from (?P<host>[^\[]+)\[(?P<ip>[0-9a-fA-F:.]+)\]"
)


class PostfixParser:
    """Преобразует строки лога Postfix в список объектов MailMessage."""

    def __init__(self, config: Config):
        self.config = config

    def parse_file(self, path: str) -> list[MailMessage]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return self.parse_lines(fh)

    def parse_lines(self, lines: Iterable[str]) -> list[MailMessage]:
        messages: dict[str, MailMessage] = {}
        # запоминаем последний connect по pid процесса smtpd для привязки helo/ip
        pid_ip: dict[str, tuple[str, str]] = {}

        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            ts = parse_syslog_time(line)

            mconn = _RE_CONNECT.search(line)
            if mconn:
                pid_ip[mconn.group("pid")] = (mconn.group("host"), mconn.group("ip"))
                continue

            # Любая строка с queue id пополняет соответствующее письмо.
            self._h_client(line, ts, messages)
            self._h_msgid(line, ts, messages)
            self._h_subject(line, ts, messages)
            self._h_from(line, ts, messages)
            self._h_to(line, ts, messages)
            self._h_helo(line, ts, messages)
            self._h_auth(line, ts, messages)

        result = list(messages.values())
        for msg in result:
            self._finalize(msg)
        # сортируем по времени для воспроизводимости
        result.sort(key=lambda m: (m.timestamp or _MIN_DT))
        return result

    # --- отдельные обработчики строк ---------------------------------------

    def _get(self, messages: dict[str, MailMessage], qid: str, ts) -> MailMessage:
        msg = messages.get(qid)
        if msg is None:
            msg = MailMessage(queue_id=qid)
            messages[qid] = msg
        if ts and msg.timestamp is None:
            msg.timestamp = ts
        return msg

    def _h_client(self, line, ts, messages):
        m = _RE_CLIENT.search(line)
        if m:
            msg = self._get(messages, m.group("qid"), ts)
            msg.client_host = m.group("host")
            msg.client_ip = m.group("ip")
        ms = _RE_SASL.search(line)
        if ms:
            msg = self._get(messages, ms.group("qid"), ts)
            msg.sasl_username = ms.group("user")

    def _h_msgid(self, line, ts, messages):
        m = _RE_MSGID.search(line)
        if m:
            self._get(messages, m.group("qid"), ts).message_id = m.group("mid")

    def _h_subject(self, line, ts, messages):
        m = _RE_SUBJECT.search(line)
        if m:
            self._get(messages, m.group("qid"), ts).subject = m.group("subject").strip()

    def _h_from(self, line, ts, messages):
        m = _RE_FROM.search(line)
        if m:
            msg = self._get(messages, m.group("qid"), ts)
            msg.from_addr = m.group("from") or None
            msg.size = int(m.group("size"))
            msg.nrcpt = int(m.group("nrcpt"))

    def _h_to(self, line, ts, messages):
        m = _RE_TO.search(line)
        if m:
            msg = self._get(messages, m.group("qid"), ts)
            to = m.group("to")
            if to and to not in msg.to_addrs:
                msg.to_addrs.append(to)
            msg.status = m.group("status")

    def _h_helo(self, line, ts, messages):
        m = _RE_HELO.search(line)
        if m:
            self._get(messages, m.group("qid"), ts).helo = m.group("helo")

    def _h_auth(self, line, ts, messages):
        for rx, attr in ((_RE_SPF, "spf"), (_RE_DKIM, "dkim"), (_RE_DMARC, "dmarc")):
            m = rx.search(line)
            if m:
                setattr(self._get(messages, m.group("qid"), ts), attr, m.group(attr).lower())

    # --- постобработка ------------------------------------------------------

    def _finalize(self, msg: MailMessage) -> None:
        """Определяет направление письма (входящее/исходящее).

        Исходящим считаем письмо, отправленное аутентифицированным
        пользователем (есть sasl_username) или с внутреннего (приватного) IP.
        Если же письмо приходит с внешнего адреса, но в поле From стоит наш
        домен — это не исходящее письмо, а спуфинг (входящее).
        """
        if msg.sasl_username or _is_private_ip(msg.client_ip):
            msg.direction = "outbound"
        elif msg.from_domain:
            msg.direction = "inbound"
        else:
            msg.direction = "unknown"


from datetime import datetime as _dt

_MIN_DT = _dt.min


def _is_private_ip(ip: str | None) -> bool:
    """Проверяет, относится ли IPv4 к приватным диапазонам (RFC 1918) или loopback."""
    if not ip or ":" in ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or a == 127
        or (a == 192 and b == 168)
        or (a == 172 and 16 <= b <= 31)
    )
