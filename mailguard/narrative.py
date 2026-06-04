"""Формирование человекочитаемых описаний инцидентов.

Вместо сухого «DMARC: fail; SPF: fail» — связный текст с контекстом письма,
перечислением признаков и рекомендацией аналитику.
"""

from __future__ import annotations

from .models import MessageRecord
from .scoring import Assessment

_CONF_RU = {"high": "высокая", "medium": "средняя", "low": "низкая"}

_LEAD = {
    "phishing": {
        "high": "Письмо с высокой вероятностью является фишинговым",
        "medium": "Письмо имеет признаки фишинга",
        "low": "Письмо содержит отдельные признаки, возможно, фишинга",
    },
    "dlp": {
        "high": "Письмо с высокой вероятностью содержит утечку данных наружу",
        "medium": "Письмо имеет признаки утечки данных",
        "low": "Письмо содержит отдельные признаки возможной утечки данных",
    },
    "account": {
        "high": "Зафиксированы убедительные признаки компрометации учётной записи",
        "medium": "Зафиксированы признаки подозрительной активности учётной записи",
        "low": "Зафиксирована потенциально подозрительная активность",
    },
}

_RECOMMENDATION = {
    "phishing": ("Рекомендация: не переходить по ссылкам и не открывать вложения; "
                 "проверить отправителя по доверенному каналу; при подтверждении — "
                 "заблокировать отправителя/домен/IP и предупредить получателей."),
    "dlp": ("Рекомендация: проверить правомерность отправки этих данных наружу; "
            "при необходимости отозвать письмо и уведомить ответственного за ИБ; "
            "рассмотреть блокировку канала передачи."),
    "account": ("Рекомендация: сбросить пароль и завершить активные сессии "
                "пользователя; проверить правила пересылки и недавнюю активность; "
                "при подтверждении компрометации — изолировать учётную запись."),
}

_MONTHS = ["", "января", "февраля", "марта", "апреля", "мая", "июня",
           "июля", "августа", "сентября", "октября", "ноября", "декабря"]


def _when(record: MessageRecord) -> str:
    ts = record.timestamp
    if not ts:
        return ""
    return f"{ts.day} {_MONTHS[ts.month]} в {ts.hour:02d}:{ts.minute:02d}"


def _context(record: MessageRecord) -> str:
    """Контекстное предложение: кто, куда, когда, в какую сторону."""
    parts: list[str] = []
    direction = {
        "inbound": "входящее", "outbound": "исходящее"
    }.get(record.direction, "")
    src = record.from_addr or "неизвестного отправителя"
    lead = f"Письмо от {src}"
    if record.client_ip:
        lead += f" (IP {record.client_ip})"
    if direction:
        lead += f", {direction}"
    parts.append(lead)
    if record.to_addrs:
        rcpts = ", ".join(record.to_addrs[:3])
        if len(record.to_addrs) > 3:
            rcpts += f" и ещё {len(record.to_addrs) - 3}"
        parts.append(f"получатель: {rcpts}")
    when = _when(record)
    if when:
        parts.append(when)
    if record.subject:
        parts.append(f"тема: «{record.subject}»")
    return "; ".join(parts) + "."


_LEAD_SHORT = {
    "phishing": {"high": "Вероятный фишинг", "medium": "Признаки фишинга",
                 "low": "Слабые признаки фишинга"},
    "dlp": {"high": "Вероятная утечка данных", "medium": "Признаки утечки данных",
            "low": "Слабые признаки утечки"},
    "account": {"high": "Компрометация учётной записи",
                "medium": "Подозрительная активность УЗ",
                "low": "Потенциально подозрительная активность"},
}


def recommendation(category: str) -> str:
    """Текст рекомендации аналитику по категории инцидента."""
    return _RECOMMENDATION.get(category, "")


def build_summary(record: MessageRecord, category: str,
                  assessment: Assessment) -> str:
    """Короткое человекочитаемое описание для списка инцидентов (одна строка)."""
    conf = _CONF_RU.get(assessment.confidence, assessment.confidence)
    lead = _LEAD_SHORT.get(category, {}).get(assessment.confidence, "Признаки угрозы")
    who = record.from_addr or record.client_ip or "неизвестный отправитель"
    n = len(assessment.reasons)
    return f"{lead} от {who} · признаков: {n} · достоверность {conf}."


def build_description(record: MessageRecord, category: str,
                      assessment: Assessment) -> str:
    """Развёрнутое описание (для отчётов и CLI). Делится на смысловые части."""
    conf = _CONF_RU.get(assessment.confidence, assessment.confidence)
    lead = _LEAD.get(category, {}).get(assessment.confidence, "Обнаружены признаки угрозы")

    parts = [
        f"{lead} (достоверность: {conf}).",
        _context(record),
    ]
    if assessment.reasons:
        parts.append("Сработавшие признаки:")
        parts.extend(f"  • {r}." for r in assessment.reasons)
    rec = _RECOMMENDATION.get(category, "")
    if rec:
        parts.append(rec)
    return "\n".join(parts)


def build_account_summary(detail_short: str, confidence: str) -> str:
    conf = _CONF_RU.get(confidence, confidence)
    return f"{detail_short} · достоверность {conf}."


def build_account_description(title: str, detail: str, recommendation: bool = True) -> str:
    """Описание для инцидентов уровня учётной записи (логи IMAP)."""
    text = detail.rstrip(".") + "."
    if recommendation:
        text += "\n" + _RECOMMENDATION["account"]
    return text
