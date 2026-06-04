"""Интерактивное меню генератора сценариев MailGuard.

Запуск без флагов: выбираешь пункт цифрой — система создаёт тестовый кейс,
сразу прогоняет анализ и показывает, что сработало (или что инцидентов нет).
Удобно для защиты: не нужно помнить команды и параметры.

Запуск:  py tools/make_case_menu.py   (или двойной клик по Генератор.bat)
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))          # tools/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # корень

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stdin, "reconfigure"):
    # utf-8-sig: корректно читает ввод и автоматически срезает ведущий BOM
    sys.stdin.reconfigure(encoding="utf-8-sig")

import make_case  # noqa: E402
from mailguard.engine import Engine  # noqa: E402

# Пункты меню: (подпись, имя пресета).
MENU = [
    ("Фишинг — высокая достоверность",        "phishing-high"),
    ("Фишинг — средняя достоверность",        "phishing-medium"),
    ("Фишинг — низкая достоверность",         "phishing-low"),
    ("Утечка данных (DLP) — высокая",         "dlp-high"),
    ("Утечка данных (DLP) — средняя",         "dlp-medium"),
    ("Чистое письмо (НЕ должно детектиться)", "clean"),
    ("Коррелированная пара SMTP+EML",         "phishing-correlated"),
    ("Брутфорс IMAP",                          "imap-bruteforce"),
    ("Захват ящика IMAP",                      "imap-takeover"),
    ("Невозможное перемещение (IMAP)",         "imap-travel"),
    ("Вход без TLS (IMAP)",                    "imap-plaintext"),
]

_SEV_RU = {"low": "низкая", "medium": "средняя", "high": "высокая",
           "critical": "критическая"}
_CONF_RU = {"low": "низкая", "medium": "средняя", "high": "высокая"}


def read(prompt: str) -> str:
    """Чтение ввода с очисткой пробелов (ведущий BOM срезает utf-8-sig на stdin)."""
    return input(prompt).strip()


def analyze_and_show(paths: dict) -> None:
    """Прогоняет анализ по созданным файлам и печатает результат."""
    result = Engine().run(
        postfix_log=paths.get("postfix"),
        dovecot_log=paths.get("dovecot"),
        emails_dir=paths.get("emails_dir"),
    )
    print("\n" + "-" * 60)
    if not result.incidents:
        print("  РЕЗУЛЬТАТ: инцидентов НЕ обнаружено (это и ожидалось для")
        print("  чистого письма — система не поднимает ложную тревогу).")
        print("-" * 60)
        return
    print(f"  РЕЗУЛЬТАТ: обнаружено инцидентов — {len(result.incidents)}")
    for inc in result.incidents:
        sev = _SEV_RU.get(inc.severity, inc.severity)
        conf = _CONF_RU.get(inc.confidence, inc.confidence)
        print(f"\n  • [{sev} / достоверность {conf}] балл {inc.score}"
              f"  (источник: {inc.origin})")
        print(f"    {inc.summary}")
        for reason in inc.evidence.get("reasons", [])[:8]:
            print(f"      - {reason}")
    print("-" * 60)


def choose_custom() -> tuple[str, list[str]]:
    """Ручной выбор: тип файла + список правил."""
    print("\nТипы: 1) smtp  2) eml  3) imap  4) smtp+eml")
    ftype = {"1": "smtp", "2": "eml", "3": "imap", "4": "smtp+eml"}.get(
        read("Выберите тип [1-4]: "), "eml")
    print("Доступные правила:")
    for r in sorted(make_case.RECIPES):
        print(f"   {r}")
    print("   account.bruteforce / account.takeover / account.impossible_travel /"
          " account.plaintext_login")
    rules = [r.strip() for r in read("Введите правила через запятую: ").split(",")
             if r.strip()]
    return ftype, rules


def main() -> None:
    print("=" * 60)
    print("   MailGuard — генератор тестовых сценариев (меню)")
    print("=" * 60)
    print("Выберите, какой тестовый случай создать и проверить:\n")

    while True:
        for i, (label, _) in enumerate(MENU, 1):
            print(f"  {i:2}. {label}")
        print(f"  {len(MENU) + 1:2}. Свой набор правил")
        print("   0. Выход")

        try:
            choice = read("\nВаш выбор: ")
        except EOFError:
            break
        if choice == "0":
            break

        if choice == str(len(MENU) + 1):
            ftype, rules = choose_custom()
        elif choice.isdigit() and 1 <= int(choice) <= len(MENU):
            ftype, rules = make_case.PRESETS[MENU[int(choice) - 1][1]]
        else:
            print("  Неверный пункт, попробуйте ещё раз.\n")
            continue

        paths = make_case.generate_case(ftype, rules)
        print(f"\nСоздан кейс: {paths['out']}")
        print(f"Тип: {ftype}; заложено правил: {len(rules)}"
              + (f" ({', '.join(rules)})" if rules else " (чистый)"))
        try:
            analyze_and_show(paths)
        except Exception as exc:   # noqa: BLE001
            print(f"  Ошибка анализа: {exc}")

        try:
            read("\nНажмите Enter для возврата в меню...")
        except EOFError:
            break
        print()

    print("Выход. Файлы кейсов сохранены в data/cases/.")


if __name__ == "__main__":
    main()
