#!/usr/bin/env python3
"""MailGuard — точка входа (CLI).

Примеры использования:

    # 1) Сгенерировать тестовые логи
    python tools/generate_sample_logs.py

    # 2) Проанализировать логи в консоли
    python run.py analyze --postfix data/sample_logs/postfix.log \
                          --dovecot data/sample_logs/dovecot.log

    # 3) Сохранить отчёт
    python run.py analyze --postfix data/sample_logs/postfix.log \
                          --report report.html --format html

    # 4) Запустить веб-дашборд
    python run.py web
"""

from __future__ import annotations

import argparse
import sys

# На Windows консоль по умолчанию cp1252 — переключаем вывод на UTF-8.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from mailguard.config import load_config
from mailguard.engine import Engine
from mailguard.reporting import to_csv, to_html, to_json
from mailguard.storage import Storage

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def cmd_analyze(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    engine = Engine(config)
    storage = Storage(args.db) if args.save else None

    result = engine.run(
        postfix_log=args.postfix,
        dovecot_log=args.dovecot,
        emails_dir=args.emails,
        storage=storage,
    )
    if storage:
        storage.close()

    s = result.stats
    print("=" * 64)
    print("  MailGuard — результаты анализа почтовых логов")
    print("=" * 64)
    print(f"  Писем SMTP:        {s['total_messages']} "
          f"(вход. {s['inbound']}, исх. {s['outbound']})")
    print(f"  Событий IMAP:      {s['total_imap_events']}")
    print(f"  Писем .eml:        {s.get('total_emails', 0)} "
          f"(вложений: {s.get('total_attachments', 0)})")
    print(f"  Всего инцидентов:  {s['total_incidents']}")
    print(f"    фишинг:  {s['by_category']['phishing']}")
    print(f"    утечки:  {s['by_category']['dlp']}")
    print(f"    аккаунты:{s['by_category']['account']}")
    print(f"  По серьёзности: critical={s['by_severity']['critical']} "
          f"high={s['by_severity']['high']} medium={s['by_severity']['medium']} "
          f"low={s['by_severity']['low']}")
    conf = s.get("by_confidence", {})
    print(f"  По достоверности: high={conf.get('high', 0)} "
          f"medium={conf.get('medium', 0)} low={conf.get('low', 0)}")
    print(f"  Собрано IoC:       {s.get('total_iocs', 0)}")
    print(f"  Блок-лист IoC:     {s.get('blocklist_size', 0)} записей")
    print("-" * 64)

    for inc in sorted(result.incidents,
                      key=lambda i: (SEV_ORDER.get(i.severity, 9), -i.score)):
        time_str = inc.timestamp.strftime("%m-%d %H:%M") if inc.timestamp else "  --  "
        print(f"  [{inc.severity.upper():8}/дост.{inc.confidence:6}] балл={inc.score:<3} "
              f"{time_str}  {inc.category:8} {inc.source or '-'}")
        print(f"             {inc.description}")

    if result.iocs:
        print("-" * 64)
        print(f"  Индикаторы компрометации (IoC) — {len(result.iocs)}:")
        for ioc in result.iocs[:15]:
            print(f"    [{ioc.max_severity:8}] {ioc.type:14} {ioc.value}"
                  + (f"  ({', '.join(sorted(ioc.labels))})" if ioc.labels else ""))

    if args.report:
        fmt = args.format
        text = {"json": to_json, "csv": to_csv, "html": to_html}[fmt](result)
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("-" * 64)
        print(f"  Отчёт сохранён: {args.report} ({fmt})")

    return 0


def cmd_web(args: argparse.Namespace) -> int:
    from mailguard.web import create_app

    app = create_app(config_path=args.config, db_path=args.db)
    print(f"  Веб-дашборд MailGuard: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def _blocklist_path(config) -> str:
    import os
    path = config.raw.get("ioc", {}).get("blocklist_file", "data/ioc_blocklist.csv")
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    return path


def cmd_blocklist(args: argparse.Namespace) -> int:
    from mailguard.blocklist import Blocklist

    config = load_config(args.config)
    bl = Blocklist(_blocklist_path(config))

    if args.action == "show":
        print(f"  Блок-лист IoC — записей: {bl.count()}")
        for e in bl.all():
            print(f"    {e.type:12} {e.value}  ({e.source})")
    elif args.action == "import":
        if not args.file:
            print("  Укажите --file с CSV (type,value[,source])")
            return 1
        entries = []
        with open(args.file, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = [p.strip() for p in line.replace(";", ",").split(",")]
                if len(parts) >= 2 and parts[0].lower() != "type" and parts[1]:
                    entries.append((parts[0], parts[1],
                                    parts[2] if len(parts) > 2 else "import"))
        print(f"  Импортировано: {bl.add_many(entries)} (всего {bl.count()})")
    elif args.action == "promote":
        store = Storage(args.db)
        iocs = store.get_iocs()
        store.close()
        mapping = {"ip": "ip", "sender_email": "email", "sender_domain": "domain",
                   "url_domain": "domain", "file_sha256": "file_sha256",
                   "subject": "subject"}
        entries = [(mapping[i["type"]], i["value"], "promoted")
                   for i in iocs if i["type"] in mapping]
        print(f"  Добавлено из собранных IoC: {bl.add_many(entries)} "
              f"(всего {bl.count()})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mailguard",
        description="Система анализа почтовых логов (IMAP/SMTP) "
                    "для выявления фишинга и утечек.",
    )
    p.add_argument("--config", help="путь к config.yaml")
    p.add_argument("--db", help="путь к файлу БД SQLite")
    sub = p.add_subparsers(dest="command", required=True)

    pa = sub.add_parser("analyze", help="проанализировать лог-файлы")
    pa.add_argument("--postfix", help="лог Postfix (SMTP)")
    pa.add_argument("--dovecot", help="лог Dovecot (IMAP)")
    pa.add_argument("--emails", help="каталог с письмами .eml (анализ тела и вложений)")
    pa.add_argument("--report", help="файл для сохранения отчёта")
    pa.add_argument("--format", choices=["json", "csv", "html"], default="html")
    pa.add_argument("--save", action="store_true",
                    help="сохранить инциденты в БД (для веб-дашборда)")
    pa.set_defaults(func=cmd_analyze)

    pw = sub.add_parser("web", help="запустить веб-дашборд")
    pw.add_argument("--host", default="127.0.0.1")
    pw.add_argument("--port", type=int, default=5000)
    pw.add_argument("--debug", action="store_true")
    pw.set_defaults(func=cmd_web)

    pb = sub.add_parser("blocklist", help="управление блок-листом IoC")
    pb.add_argument("action", choices=["show", "import", "promote"],
                    help="show — показать; import — импорт CSV (--file); "
                         "promote — добавить собранные IoC из БД")
    pb.add_argument("--file", help="CSV-файл для импорта (type,value[,source])")
    pb.set_defaults(func=cmd_blocklist)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze" and not (args.postfix or args.dovecot or args.emails):
        parser.error("укажите хотя бы один из --postfix / --dovecot / --emails")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
