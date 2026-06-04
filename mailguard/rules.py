"""Реестр правил MailGuard.

Делает правила объектами первого класса: у каждого есть идентификатор,
описание, категория, вес (берётся из config.yaml), привязка к MITRE ATT&CK и
RFC, флаг включения. Это даёт:
  * единый источник метаданных для веб-панели правил;
  * управление весами и включением/выключением без правки кода;
  * декларативные пользовательские правила (ключевые слова / regex), которые
    создаются через интерфейс и загружаются движком на лету.

Встроенные правила (`builtin`) описывают логику, реализованную в коде детекторов.
Декларативные (`declarative`) — это правила-данные, исполняемые ContentDetector.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any

import yaml

from .config import Config

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DECLARATIVE_PATH = os.path.join(DATA_DIR, "rules.yaml")
STATE_PATH = os.path.join(DATA_DIR, "rules_state.json")


@dataclass
class Rule:
    """Метаданные одного правила детектирования."""

    id: str
    name: str
    description: str
    category: str                     # phishing / dlp / account
    default_weight: int
    confidence: str = "medium"        # strong / medium / weak — достоверность
    mitre: list[str] = field(default_factory=list)
    rfc: list[str] = field(default_factory=list)
    enabled: bool = True
    source: str = "builtin"           # builtin / declarative
    # привязка веса к секции config.yaml: (секция, ключ в weights)
    config_section: str | None = None
    config_key: str | None = None
    # поля декларативных правил
    rtype: str | None = None          # keyword / regex
    field_scope: str | None = None    # subject / body / both
    patterns: list[str] = field(default_factory=list)
    weight: int | None = None         # явный вес для декларативного правила


# ===========================================================================
#  Каталог встроенных правил
# ===========================================================================
def _builtin_rules() -> list[Rule]:
    def R(rid, name, desc, category, weight, confidence, *,
          section, key, mitre=None, rfc=None):
        return Rule(rid, name, desc, category, weight, confidence,
                    mitre=mitre or [], rfc=rfc or [],
                    config_section=section, config_key=key)

    return [
        # --- Фишинг: подлинность отправителя (метаданные) ---
        # Каждый провал аутентификации по отдельности — лишь СРЕДНИЙ/СЛАБЫЙ
        # сигнал (легитимные отправители тоже иногда «спотыкаются»); сила — в
        # их совокупности (модель достоверности это учитывает).
        R("phishing.dmarc_fail", "Провал DMARC",
          "Письмо не прошло проверку политики DMARC домена отправителя.",
          "phishing", 35, "medium", section="phishing", key="dmarc_fail",
          mitre=["T1566", "T1656"], rfc=["RFC 7489"]),
        R("phishing.spf_fail", "Провал SPF",
          "IP отправителя не авторизован SPF-записью домена.",
          "phishing", 30, "weak", section="phishing", key="auth_fail",
          mitre=["T1566"], rfc=["RFC 7208"]),
        R("phishing.dkim_fail", "Провал DKIM",
          "Цифровая подпись DKIM недействительна или отсутствует.",
          "phishing", 30, "weak", section="phishing", key="auth_fail",
          mitre=["T1566"], rfc=["RFC 6376"]),
        R("phishing.spoofed_internal", "Спуфинг внутреннего домена",
          "Внешний источник выдаёт себя за внутренний домен организации.",
          "phishing", 40, "strong", section="phishing", key="spoofed_internal",
          mitre=["T1656"], rfc=["RFC 7489"]),
        R("phishing.lookalike_sender", "Домен-двойник отправителя",
          "Домен отправителя похож на внутренний (typosquatting).",
          "phishing", 35, "strong", section="phishing", key="lookalike_domain",
          mitre=["T1566.002"]),
        R("phishing.mass_recipients", "Массовая рассылка",
          "Одно письмо адресовано большому числу получателей.",
          "phishing", 15, "weak", section="phishing", key="mass_recipients",
          mitre=["T1566"]),
        R("phishing.helo_mismatch", "Несоответствие HELO",
          "HELO/EHLO не соответствует домену отправителя или является IP.",
          "phishing", 15, "weak", section="phishing", key="helo_mismatch",
          rfc=["RFC 5321"]),
        R("phishing.punycode_sender", "Punycode в домене отправителя",
          "Домен отправителя содержит метку xn-- (возможна IDN-омоглиф атака).",
          "phishing", 25, "medium", section="phishing", key="punycode",
          mitre=["T1566.002"], rfc=["RFC 3492"]),
        R("phishing.replyto_mismatch", "Reply-To не совпадает с From",
          "Адрес для ответа отличается от отправителя — частый признак фишинга.",
          "phishing", 20, "weak", section="phishing", key="replyto_mismatch",
          mitre=["T1566"]),

        # --- Контент: тема + тело ---
        R("phishing.manipulative_content", "Манипулятивные паттерны",
          "В теме/теле присутствуют приёмы соц. инженерии (срочность, угроза…).",
          "phishing", 20, "medium", section="content", key="manipulation",
          mitre=["T1566"]),
        R("phishing.credential_request", "Запрос учётных данных",
          "Текст призывает ввести пароль/реквизиты — выманивание данных.",
          "phishing", 25, "medium", section="content", key="credential_request",
          mitre=["T1566.002"]),
        R("dlp.confidential_keyword", "Конфиденциальные ключевые слова",
          "В теме/теле исходящего письма — слова о конфиденциальных данных.",
          "dlp", 35, "medium", section="content", key="confidential_keyword",
          rfc=["ФЗ-152"]),
        R("dlp.pii", "Персональные данные (ПДн)",
          "Найдены провалидированные ПДн: карта, СНИЛС, ИНН, паспорт и т.п.",
          "dlp", 35, "strong", section="content", key="pii",
          rfc=["ФЗ-152", "ISO/IEC 7812"]),
        R("dlp.secret_exposure", "Утечка секретов/ключей",
          "В письме обнаружены пароли, токены, API-ключи или приватные ключи.",
          "dlp", 40, "strong", section="content", key="secret", mitre=["T1552"]),

        # --- Ссылки в теле ---
        R("phishing.url_ip_literal", "Ссылка на IP-адрес",
          "Ссылка ведёт на IP вместо доменного имени.",
          "phishing", 30, "medium", section="body", key="url_ip_literal",
          mitre=["T1566.002"]),
        R("phishing.url_shortener", "Сокращённая ссылка",
          "Ссылка через сервис сокращения URL скрывает реальный адрес.",
          "phishing", 20, "weak", section="body", key="url_shortener",
          mitre=["T1566.002"]),
        R("phishing.url_text_mismatch", "Подмена ссылки",
          "Видимый текст ссылки не соответствует реальному href.",
          "phishing", 35, "strong", section="body", key="url_text_mismatch",
          mitre=["T1566.002"]),
        R("phishing.url_lookalike", "Домен-двойник в ссылке",
          "Домен в ссылке похож на внутренний домен организации.",
          "phishing", 35, "strong", section="body", key="url_lookalike",
          mitre=["T1566.002"]),
        R("phishing.url_suspicious_tld", "Подозрительная зона ссылки",
          "Домен ссылки в зоне с высокой долей злоупотреблений (.top/.xyz…).",
          "phishing", 15, "weak", section="body", key="suspicious_tld",
          mitre=["T1566.002"]),
        R("phishing.url_punycode", "Punycode в ссылке",
          "Домен ссылки содержит метку xn-- (IDN-омоглиф).",
          "phishing", 25, "medium", section="body", key="url_punycode",
          mitre=["T1566.002"], rfc=["RFC 3492"]),

        # --- Вложения ---
        R("phishing.attachment_dangerous", "Исполняемое вложение",
          "Вложение имеет опасное исполняемое/скриптовое расширение.",
          "phishing", 45, "strong", section="attachments", key="dangerous_ext",
          mitre=["T1566.001", "T1204.002"]),
        R("phishing.attachment_double_ext", "Двойное расширение",
          "Маскировка исполняемого файла под документ (invoice.pdf.exe).",
          "phishing", 40, "strong", section="attachments", key="double_extension",
          mitre=["T1036.007"]),
        R("phishing.attachment_real_macro", "Документ с реальным макросом",
          "Внутри Office-документа найден vbaProject.bin — есть исполняемый макрос.",
          "phishing", 40, "strong", section="attachments", key="real_macro",
          mitre=["T1566.001", "T1204.002"]),
        R("phishing.attachment_macro", "Документ с поддержкой макросов",
          "Расширение допускает макросы (.docm/.xlsm) — макрос лишь возможен.",
          "phishing", 25, "medium", section="attachments", key="macro_document",
          mitre=["T1566.001"]),
        R("phishing.attachment_archive", "Архив-вложение",
          "Архив может скрывать файлы; сам по себе — легитимен.",
          "phishing", 8, "weak", section="attachments", key="archive",
          mitre=["T1566.001"]),
        R("phishing.attachment_archive_inner", "Опасный файл внутри архива",
          "Внутри архива найден исполняемый/двойной-расширения файл.",
          "phishing", 40, "strong", section="attachments",
          key="archive_inner_dangerous", mitre=["T1566.001", "T1027.002"]),
        R("phishing.attachment_encrypted", "Запароленный архив",
          "Архив зашифрован — обход антивирусной проверки шлюза.",
          "phishing", 25, "medium", section="attachments", key="encrypted_archive",
          mitre=["T1027.002"]),
        R("phishing.attachment_html", "HTML/скрипт-вложение",
          "Вложение HTML/скрипт может содержать фишинговую форму.",
          "phishing", 30, "medium", section="attachments", key="html_attachment",
          mitre=["T1566.001"]),
        R("dlp.attachment_highrisk", "Высокорисковый файл наружу",
          "Дамп БД / архив почты (.sql/.db/.pst…) уходит внешнему адресату.",
          "dlp", 35, "medium", section="attachments", key="highrisk_external",
          mitre=["T1048"], rfc=["ФЗ-152"]),
        R("dlp.attachment_office", "Документ наружу",
          "Обычный офисный документ внешнему адресату — слабый признак (нужен контекст).",
          "dlp", 12, "weak", section="attachments", key="office_external",
          mitre=["T1048"]),
        R("dlp.attachment_large", "Крупный объём вложений",
          "Суммарный размер вложений превышает порог при отправке наружу.",
          "dlp", 20, "weak", section="attachments", key="large_attachment",
          mitre=["T1048"]),

        # --- DLP по метаданным ---
        R("dlp.free_mail_recipient", "Отправка на личную почту",
          "Исходящее письмо адресовано бесплатному/личному почтовому сервису.",
          "dlp", 25, "weak", section="dlp", key="free_mail_recipient",
          mitre=["T1048"]),
        R("dlp.large_external", "Крупное письмо наружу",
          "Размер исходящего письма внешнему адресату превышает порог.",
          "dlp", 25, "weak", section="dlp", key="large_external", mitre=["T1048"]),
        R("dlp.off_hours", "Отправка вне рабочего времени",
          "Исходящее письмо наружу отправлено в нерабочие часы.",
          "dlp", 15, "weak", section="dlp", key="off_hours"),
        R("dlp.exfiltration", "Аномальный объём писем (эксфильтрация)",
          "Много писем одному внешнему получателю за период анализа.",
          "dlp", 40, "strong", section="dlp", key="exfiltration_volume",
          mitre=["T1048", "T1567"]),

        # --- Совпадение с блок-листом IoC (этап D) ---
        R("ioc.match_ip", "IP в блок-листе IoC",
          "IP отправителя присутствует в списке известных вредоносных IoC.",
          "phishing", 45, "strong", section="ioc", key="match_ip",
          mitre=["T1566"]),
        R("ioc.match_email", "Отправитель в блок-листе IoC",
          "Адрес отправителя присутствует в списке известных вредоносных IoC.",
          "phishing", 45, "strong", section="ioc", key="match_email",
          mitre=["T1566"]),
        R("ioc.match_domain", "Домен в блок-листе IoC",
          "Домен отправителя или ссылки есть в списке известных вредоносных IoC.",
          "phishing", 45, "strong", section="ioc", key="match_domain",
          mitre=["T1566"]),
        R("ioc.match_file_hash", "Хэш вложения в блок-листе IoC",
          "SHA-256 вложения совпадает с известным вредоносным образцом.",
          "phishing", 50, "strong", section="ioc", key="match_file_hash",
          mitre=["T1566.001"]),
        R("ioc.match_subject", "Тема в блок-листе IoC",
          "Тема письма совпадает с известной фишинговой кампанией.",
          "phishing", 25, "medium", section="ioc", key="match_subject",
          mitre=["T1566"]),

        # --- Компрометация аккаунта (IMAP) ---
        R("account.bruteforce", "Брутфорс IMAP",
          "Серия неудачных входов с одного IP за короткое окно.",
          "account", 30, "strong", section="account", key="bruteforce",
          mitre=["T1110"]),
        R("account.takeover", "Захват ящика",
          "Успешный вход сразу после серии неудачных попыток.",
          "account", 45, "strong", section="account", key="login_after_bruteforce",
          mitre=["T1078"]),
        R("account.impossible_travel", "Невозможное перемещение",
          "Входы одного пользователя из разных сетей за короткое время.",
          "account", 35, "medium", section="account", key="impossible_travel",
          mitre=["T1078"]),
        R("account.plaintext_login", "Вход без TLS",
          "Вход выполнен без шифрования — пароль мог уйти открытым текстом.",
          "account", 15, "weak", section="account", key="plaintext_login",
          rfc=["RFC 3207"]),
    ]


class RuleRegistry:
    """Хранит каталог правил, их веса, состояние и декларативные правила."""

    def __init__(self, config: Config,
                 declarative_path: str | None = None,
                 state_path: str | None = None):
        self.config = config
        self.declarative_path = declarative_path or DECLARATIVE_PATH
        self.state_path = state_path or STATE_PATH
        self._rules: dict[str, Rule] = {}
        self.reload()

    # ---- загрузка ------------------------------------------------------- #

    def reload(self) -> None:
        self._rules = {r.id: r for r in _builtin_rules()}
        self._apply_weights()
        self._apply_state()
        self._load_declarative()

    def _apply_weights(self) -> None:
        """Берёт вес каждого правила из config.yaml (секция.weights.ключ)."""
        for r in self._rules.values():
            if not (r.config_section and r.config_key):
                r.weight = r.default_weight
                continue
            section = self.config.raw.get(r.config_section, {}) or {}
            weights = section.get("weights", {}) if isinstance(section, dict) else {}
            r.weight = int(weights.get(r.config_key, r.default_weight))

    def _apply_state(self) -> None:
        state = self._read_json(self.state_path)
        for rid, enabled in state.items():
            if rid in self._rules:
                self._rules[rid].enabled = bool(enabled)

    def _load_declarative(self) -> None:
        data = self._read_yaml(self.declarative_path)
        for item in data.get("rules", []) if isinstance(data, dict) else []:
            try:
                rule = Rule(
                    id=item["id"],
                    name=item.get("name", item["id"]),
                    description=item.get("description", ""),
                    category=item.get("category", "phishing"),
                    default_weight=int(item.get("weight", 20)),
                    weight=int(item.get("weight", 20)),
                    confidence=item.get("confidence", "medium"),
                    enabled=bool(item.get("enabled", True)),
                    source="declarative",
                    rtype=item.get("rtype", "keyword"),
                    field_scope=item.get("field_scope", "both"),
                    patterns=list(item.get("patterns", [])),
                    mitre=list(item.get("mitre", [])),
                )
                self._rules[rule.id] = rule
            except (KeyError, TypeError, ValueError):
                continue

    # ---- доступ --------------------------------------------------------- #

    def all(self) -> list[Rule]:
        return sorted(self._rules.values(), key=lambda r: (r.category, r.id))

    def by_category(self, category: str) -> list[Rule]:
        return [r for r in self.all() if r.category == category]

    def declarative(self) -> list[Rule]:
        return [r for r in self.all() if r.source == "declarative" and r.enabled]

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def enabled(self, rule_id: str) -> bool:
        r = self._rules.get(rule_id)
        return bool(r and r.enabled)

    def weight(self, rule_id: str) -> int:
        """Вес правила (0, если правило выключено)."""
        r = self._rules.get(rule_id)
        if not r or not r.enabled:
            return 0
        return int(r.weight if r.weight is not None else r.default_weight)

    def confidence(self, rule_id: str) -> str:
        """Уровень достоверности правила: strong / medium / weak."""
        r = self._rules.get(rule_id)
        return r.confidence if r else "weak"

    # ---- изменение (для веб-интерфейса) -------------------------------- #

    def set_enabled(self, rule_id: str, enabled: bool) -> bool:
        r = self._rules.get(rule_id)
        if not r:
            return False
        r.enabled = enabled
        if r.source == "declarative":
            self._save_declarative()
        else:
            state = self._read_json(self.state_path)
            state[rule_id] = enabled
            self._write_json(self.state_path, state)
        return True

    def add_declarative(self, rule: Rule) -> None:
        rule.source = "declarative"
        if rule.weight is None:
            rule.weight = rule.default_weight
        self._rules[rule.id] = rule
        self._save_declarative()

    def _save_declarative(self) -> None:
        rules = []
        for r in self._rules.values():
            if r.source != "declarative":
                continue
            rules.append({
                "id": r.id, "name": r.name, "description": r.description,
                "category": r.category, "weight": r.weight,
                "confidence": r.confidence, "enabled": r.enabled,
                "rtype": r.rtype, "field_scope": r.field_scope,
                "patterns": r.patterns, "mitre": r.mitre,
            })
        os.makedirs(os.path.dirname(self.declarative_path), exist_ok=True)
        with open(self.declarative_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump({"rules": rules}, fh, allow_unicode=True, sort_keys=False)

    # ---- утилиты файлов ------------------------------------------------- #

    @staticmethod
    def _read_yaml(path: str) -> dict[str, Any]:
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            return {}

    @staticmethod
    def _read_json(path: str) -> dict[str, Any]:
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _write_json(path: str, data: dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
