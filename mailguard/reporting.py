"""Генерация отчётов по результатам анализа (JSON / CSV / HTML)."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime
from typing import Any

from .engine import AnalysisResult

_SEVERITY_RU = {
    "low": "низкая",
    "medium": "средняя",
    "high": "высокая",
    "critical": "критическая",
}
_CATEGORY_RU = {
    "phishing": "Фишинг",
    "dlp": "Утечка данных",
    "account": "Компрометация аккаунта",
}


_CONFIDENCE_RU = {"high": "высокая", "medium": "средняя", "low": "низкая"}


def to_json(result: AnalysisResult) -> str:
    payload = {
        "generated_at": datetime.now().isoformat(),
        "stats": result.stats,
        "incidents": [_incident_dict(i) for i in result.incidents],
        "iocs": [i.to_row() for i in result.iocs],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_csv(result: AnalysisResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(
        ["time", "category", "severity", "confidence", "score", "rule_id",
         "source", "description"]
    )
    for i in result.incidents:
        writer.writerow(
            [
                i.timestamp.isoformat() if i.timestamp else "",
                _CATEGORY_RU.get(i.category, i.category),
                _SEVERITY_RU.get(i.severity, i.severity),
                _CONFIDENCE_RU.get(i.confidence, i.confidence),
                i.score,
                i.rule_id,
                i.source or "",
                i.description,
            ]
        )
    return buf.getvalue()


def to_html(result: AnalysisResult) -> str:
    s = result.stats
    rows = []
    for i in result.incidents:
        rows.append(
            "<tr class='sev-{sev}'>"
            "<td>{time}</td><td>{cat}</td><td>{sevru}</td><td>{conf}</td>"
            "<td>{score}</td><td>{source}</td><td>{desc}</td></tr>".format(
                sev=html.escape(i.severity),
                time=html.escape(i.timestamp.isoformat() if i.timestamp else "—"),
                cat=html.escape(_CATEGORY_RU.get(i.category, i.category)),
                sevru=html.escape(_SEVERITY_RU.get(i.severity, i.severity)),
                conf=html.escape(_CONFIDENCE_RU.get(i.confidence, i.confidence)),
                score=i.score,
                source=html.escape(str(i.source or "—")),
                desc=html.escape(i.description),
            )
        )
    table = "\n".join(rows)
    return _HTML_TEMPLATE.format(
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_messages=s.get("total_messages", 0),
        total_imap=s.get("total_imap_events", 0),
        total_incidents=s.get("total_incidents", 0),
        phishing=s.get("by_category", {}).get("phishing", 0),
        dlp=s.get("by_category", {}).get("dlp", 0),
        account=s.get("by_category", {}).get("account", 0),
        critical=s.get("by_severity", {}).get("critical", 0),
        high=s.get("by_severity", {}).get("high", 0),
        rows=table,
    )


def _incident_dict(i) -> dict[str, Any]:
    return {
        "timestamp": i.timestamp.isoformat() if i.timestamp else None,
        "category": i.category,
        "rule_id": i.rule_id,
        "title": i.title,
        "description": i.description,
        "score": i.score,
        "severity": i.severity,
        "confidence": i.confidence,
        "source": i.source,
        "evidence": i.evidence,
    }


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Отчёт MailGuard</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 24px; color: #1f2937; }}
  h1 {{ color: #b91c1c; }}
  .cards {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }}
  .card {{ background: #f3f4f6; border-radius: 10px; padding: 16px 20px; min-width: 130px; }}
  .card .num {{ font-size: 28px; font-weight: 700; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 8px 10px; text-align: left; font-size: 14px; }}
  th {{ background: #111827; color: #fff; }}
  .sev-critical {{ background: #fee2e2; }}
  .sev-high {{ background: #ffedd5; }}
  .sev-medium {{ background: #fef9c3; }}
  .sev-low {{ background: #ecfccb; }}
</style>
</head>
<body>
  <h1>Отчёт системы анализа почтовых логов (MailGuard)</h1>
  <p>Сформирован: {generated}</p>
  <div class="cards">
    <div class="card"><div>Писем SMTP</div><div class="num">{total_messages}</div></div>
    <div class="card"><div>Событий IMAP</div><div class="num">{total_imap}</div></div>
    <div class="card"><div>Всего инцидентов</div><div class="num">{total_incidents}</div></div>
    <div class="card"><div>Фишинг</div><div class="num">{phishing}</div></div>
    <div class="card"><div>Утечки (DLP)</div><div class="num">{dlp}</div></div>
    <div class="card"><div>Аккаунты</div><div class="num">{account}</div></div>
    <div class="card"><div>Критических</div><div class="num">{critical}</div></div>
    <div class="card"><div>Высоких</div><div class="num">{high}</div></div>
  </div>
  <table>
    <thead>
      <tr><th>Время</th><th>Категория</th><th>Серьёзность</th><th>Достоверность</th>
          <th>Балл</th><th>Источник</th><th>Описание</th></tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
</body>
</html>
"""
