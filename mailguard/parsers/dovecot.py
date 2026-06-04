"""Парсер логов Dovecot (IMAP).

Примеры строк:

    Jun  2 10:20:01 mail dovecot: imap-login: Login: user=<alice@corp.ru>, \
        method=PLAIN, rip=192.0.2.10, lip=10.0.0.5, mpid=2345, TLS, session=<..>
    Jun  2 10:20:05 mail dovecot: imap-login: Disconnected (auth failed, 1 attempts \
        in 0 secs): user=<bob@corp.ru>, method=PLAIN, rip=198.51.100.7, lip=10.0.0.5
    Jun  2 10:20:07 mail dovecot: auth: passwd-file(bob,198.51.100.7): unknown user
"""

from __future__ import annotations

import re
from typing import Iterable

from ..models import ImapEvent
from .timeutil import parse_syslog_time

_RE_LOGIN = re.compile(
    r"imap-login: Login: user=<(?P<user>[^>]*)>"
    r".*?method=(?P<method>[^,]+)"
    r".*?rip=(?P<rip>[0-9a-fA-F:.]+)"
    r".*?lip=(?P<lip>[0-9a-fA-F:.]+)"
)

_RE_FAIL = re.compile(
    r"imap-login: (?:Disconnected|Aborted login) \(auth failed, (?P<attempts>\d+) attempts"
    r".*?\): user=<(?P<user>[^>]*)>"
    r".*?(?:method=(?P<method>[^,]+))?"
    r".*?rip=(?P<rip>[0-9a-fA-F:.]+)"
    r".*?lip=(?P<lip>[0-9a-fA-F:.]+)"
)


class DovecotParser:
    """Преобразует строки лога Dovecot в список ImapEvent."""

    def parse_file(self, path: str) -> list[ImapEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return self.parse_lines(fh)

    def parse_lines(self, lines: Iterable[str]) -> list[ImapEvent]:
        events: list[ImapEvent] = []
        for line in lines:
            line = line.rstrip("\n")
            if "imap-login" not in line:
                continue
            ts = parse_syslog_time(line)
            tls = (" TLS" in line) or ("TLS," in line) or ("secured" in line)

            m = _RE_LOGIN.search(line)
            if m:
                events.append(
                    ImapEvent(
                        timestamp=ts,
                        user=m.group("user"),
                        rip=m.group("rip"),
                        lip=m.group("lip"),
                        method=m.group("method"),
                        tls=tls,
                        result="login",
                        attempts=1,
                    )
                )
                continue

            mf = _RE_FAIL.search(line)
            if mf:
                events.append(
                    ImapEvent(
                        timestamp=ts,
                        user=mf.group("user"),
                        rip=mf.group("rip"),
                        lip=mf.group("lip"),
                        method=(mf.group("method") or "").strip() or None,
                        tls=tls,
                        result="auth_failed",
                        attempts=int(mf.group("attempts")),
                    )
                )
        return events
