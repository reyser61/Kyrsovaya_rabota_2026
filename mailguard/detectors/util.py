"""Вспомогательные функции для детекторов: метрики, валидация ПДн,
манипулятивные паттерны, поиск секретов и работа с URL."""

from __future__ import annotations

import re


def levenshtein(a: str, b: str) -> int:
    """Расстояние редактирования между строками (для поиска lookalike-доменов)."""
    a, b = a.lower(), b.lower()
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def contains_any(text: str | None, keywords: list[str]) -> list[str]:
    """Возвращает список ключевых слов, найденных в тексте (без учёта регистра)."""
    if not text:
        return []
    low = text.lower()
    return [kw for kw in keywords if kw.lower() in low]


# ===========================================================================
#  ВАЛИДАЦИЯ ПЕРСОНАЛЬНЫХ ДАННЫХ (ПДн)
#  Валидация контрольных сумм резко снижает ложные срабатывания по сравнению
#  с «голым» regex — это и есть «углублённое» детектирование.
# ===========================================================================

def luhn_valid(digits: str) -> bool:
    """Проверка номера по алгоритму Луна (ISO/IEC 7812) — банковские карты."""
    digits = re.sub(r"\D", "", digits)
    if not (13 <= len(digits) <= 19):
        return False
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def snils_valid(value: str) -> bool:
    """Проверка контрольной суммы СНИЛС (11 цифр)."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11:
        return False
    body, control = digits[:9], int(digits[9:])
    s = sum(int(body[i]) * (9 - i) for i in range(9))
    s %= 101
    if s == 100:
        s = 0
    return s == control


def inn_valid(value: str) -> bool:
    """Проверка контрольных цифр ИНН (10 или 12 знаков)."""
    digits = re.sub(r"\D", "", value)

    def csum(d, coeffs):
        return (sum(int(d[i]) * c for i, c in enumerate(coeffs)) % 11) % 10

    if len(digits) == 10:
        return csum(digits, [2, 4, 10, 3, 5, 9, 4, 6, 8]) == int(digits[9])
    if len(digits) == 12:
        c11 = csum(digits, [7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
        c12 = csum(digits, [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8])
        return c11 == int(digits[10]) and c12 == int(digits[11])
    return False


# Кандидаты под валидацию (с допустимыми разделителями).
_CARD_CAND = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SNILS_CAND = re.compile(r"\b\d{3}[- ]\d{3}[- ]\d{3}[ -]?\d{2}\b")
_INN_CAND = re.compile(r"\b\d{10}\b|\b\d{12}\b")
_PASSPORT_RU = re.compile(r"\b\d{2}\s?\d{2}\s?\d{6}\b")
_ACCOUNT_RU = re.compile(r"\b\d{20}\b")
_EMAIL_LIST = re.compile(r"(?:[\w.+-]+@[\w-]+\.[\w.-]+[,;]\s*){5,}")
_PHONE_RU = re.compile(r"(?:\+7|8)[\s(-]?\d{3}[\s)-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}")

# Секреты и учётные данные.
_SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|пароль)\b\s*[:=]\s*\S{6,}"
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}


def find_pii(text: str | None) -> list[str]:
    """Возвращает список найденных и провалидированных типов ПДн/секретов."""
    if not text:
        return []
    hits: list[str] = []

    if any(luhn_valid(m.group()) for m in _CARD_CAND.finditer(text)):
        hits.append("credit_card")
    if any(snils_valid(m.group()) for m in _SNILS_CAND.finditer(text)):
        hits.append("snils")
    if any(inn_valid(m.group()) for m in _INN_CAND.finditer(text)):
        hits.append("inn")
    if _PASSPORT_RU.search(text):
        hits.append("passport_ru")
    if _ACCOUNT_RU.search(text):
        hits.append("bank_account")
    if _EMAIL_LIST.search(text):
        hits.append("email_list")
    if len(_PHONE_RU.findall(text)) >= 3:
        hits.append("phone_bulk")
    for name, rx in _SECRET_PATTERNS.items():
        if rx.search(text):
            hits.append(name)
    return hits


# ===========================================================================
#  МАНИПУЛЯТИВНЫЕ ПАТТЕРНЫ (социальная инженерия)
#  Категории по принципам влияния Чалдини / методикам анти-фишинга.
# ===========================================================================

_MANIPULATION = {
    "urgency": re.compile(
        r"срочн|немедленн|в течени|истека|сегодня же|как можно скорее|"
        r"urgent|asap|immediately|right now|expires?", re.IGNORECASE),
    "threat": re.compile(
        r"заблокир|блокировк|удал|штраф|приостановлен|закрыт|санкци|"
        r"suspend|terminat|deactivat|penalty|legal action", re.IGNORECASE),
    "authority": re.compile(
        r"служба безопасност|руководител|директор|администрац|налогов|"
        r"банк|госуслуг|it[\s-]?отдел|техподдержк|"
        r"security team|administrator|ceo|it department|support team", re.IGNORECASE),
    "reward": re.compile(
        r"выигр|приз|бонус|вознагражд|бесплатн|подарок|"
        r"won|prize|bonus|reward|gift|free money|cash", re.IGNORECASE),
    "secrecy": re.compile(
        r"конфиденциальн|никому не сообщ|только для вас|строго между|"
        r"do not share|keep this confidential|between us", re.IGNORECASE),
    "action": re.compile(
        r"подтверд|перейдите по|нажмите|войдите|введите|обновите данные|"
        r"click here|verify (?:your|now)|log ?in|update your|confirm your", re.IGNORECASE),
}


def manipulation_categories(text: str | None) -> list[str]:
    """Возвращает категории манипулятивных приёмов, найденные в тексте."""
    if not text:
        return []
    return [name for name, rx in _MANIPULATION.items() if rx.search(text)]


# ===========================================================================
#  Работа с URL и доменами
# ===========================================================================

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def extract_urls(text: str | None) -> list[str]:
    """Извлекает все http(s)-ссылки из текста."""
    if not text:
        return []
    return URL_RE.findall(text)


def domain_from_url(url: str | None) -> str | None:
    """Возвращает доменную часть (host) URL в нижнем регистре."""
    if not url:
        return None
    u = url.strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in u:
        u = u.rsplit("@", 1)[1]
    u = u.split(":", 1)[0]
    return u.lower() or None


def is_ip_literal_url(url: str | None) -> bool:
    """True, если ссылка ведёт на IP-адрес, а не на доменное имя."""
    host = domain_from_url(url)
    return bool(host and _IPV4_RE.match(host))


def is_punycode(domain: str | None) -> bool:
    """True, если домен содержит punycode-метку (xn--) — возможна IDN-омоглиф атака."""
    if not domain:
        return False
    return any(label.startswith("xn--") for label in domain.lower().split("."))
