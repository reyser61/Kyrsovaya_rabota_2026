"""Разбор временных меток syslog (в них отсутствует год)."""

from __future__ import annotations

from datetime import datetime

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog_time(prefix: str, default_year: int | None = None) -> datetime | None:
    """Парсит начало строки syslog вида 'Jun  2 10:15:32 ...'.

    Год в syslog не пишется, поэтому подставляем текущий (или переданный).
    """
    parts = prefix.split()
    if len(parts) < 3:
        return None
    mon, day, clock = parts[0], parts[1], parts[2]
    if mon not in _MONTHS:
        return None
    try:
        hh, mm, ss = (int(x) for x in clock.split(":"))
        year = default_year or datetime.now().year
        return datetime(year, _MONTHS[mon], int(day), hh, mm, ss)
    except (ValueError, IndexError):
        return None
