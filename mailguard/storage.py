"""Хранилище инцидентов и статистики анализа (SQLite, без внешних зависимостей)."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import Any

from .models import Incident

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "mailguard.db"
)


class Storage:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                category    TEXT,
                rule_id     TEXT,
                title       TEXT,
                description TEXT,
                score       INTEGER,
                severity    TEXT,
                confidence  TEXT,
                source      TEXT,
                summary     TEXT,
                origin      TEXT,
                evidence    TEXT
            );
            CREATE TABLE IF NOT EXISTS runs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT,
                stats       TEXT
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                type        TEXT,
                value       TEXT,
                first_seen  TEXT,
                last_seen   TEXT,
                count       INTEGER,
                max_severity TEXT,
                categories  TEXT,
                labels      TEXT,
                context     TEXT
            );
            """
        )
        # миграции старых БД: добавляем недостающие колонки
        inc_cols = [r[1] for r in self.conn.execute("PRAGMA table_info(incidents)")]
        for col in ("confidence", "summary", "origin"):
            if col not in inc_cols:
                self.conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} TEXT")
        ioc_cols = [r[1] for r in self.conn.execute("PRAGMA table_info(iocs)")]
        if "context" not in ioc_cols:
            self.conn.execute("ALTER TABLE iocs ADD COLUMN context TEXT")
        self.conn.commit()

    # ------------------------------------------------------------------ #

    def clear(self) -> None:
        self.conn.execute("DELETE FROM incidents")
        self.conn.execute("DELETE FROM runs")
        self.conn.execute("DELETE FROM iocs")
        # сбрасываем счётчик AUTOINCREMENT, чтобы id начинались с 1 при каждом анализе
        self.conn.execute(
            "DELETE FROM sqlite_sequence WHERE name IN ('incidents', 'runs', 'iocs')"
        )
        self.conn.commit()

    def save_incidents(self, incidents: list[Incident]) -> None:
        rows = [i.to_row() for i in incidents]
        self.conn.executemany(
            """
            INSERT INTO incidents
                (timestamp, category, rule_id, title, description, score, severity,
                 confidence, source, summary, origin, evidence)
            VALUES
                (:timestamp, :category, :rule_id, :title, :description, :score,
                 :severity, :confidence, :source, :summary, :origin, :evidence)
            """,
            rows,
        )
        self.conn.commit()

    def save_iocs(self, iocs: list[Any]) -> None:
        rows = [i.to_row() for i in iocs]
        if not rows:
            return
        self.conn.executemany(
            """
            INSERT INTO iocs
                (type, value, first_seen, last_seen, count, max_severity,
                 categories, labels, context)
            VALUES
                (:type, :value, :first_seen, :last_seen, :count, :max_severity,
                 :categories, :labels, :context)
            """,
            rows,
        )
        self.conn.commit()

    def get_iocs(self, type_: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM iocs"
        params: list[Any] = []
        if type_:
            query += " WHERE type = ?"
            params.append(type_)
        query += " ORDER BY count DESC, value"
        return [dict(r) for r in self.conn.execute(query, params).fetchall()]

    def save_run(self, stats: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO runs (created_at, stats) VALUES (?, ?)",
            (datetime.now().isoformat(), json.dumps(stats, ensure_ascii=False)),
        )
        self.conn.commit()

    # ------------------------------------------------------------------ #

    def get_incidents(
        self,
        category: str | None = None,
        severity: str | None = None,
        order_by_score: bool = True,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM incidents"
        clauses, params = [], []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY score DESC" if order_by_score else " ORDER BY timestamp DESC"
        rows = self.conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else {}
            except (json.JSONDecodeError, TypeError):
                d["evidence"] = {}
            result.append(d)
        return result

    def get_incident(self, incident_id: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["evidence"] = json.loads(d["evidence"]) if d["evidence"] else {}
        except (json.JSONDecodeError, TypeError):
            d["evidence"] = {}
        return d

    def latest_stats(self) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT stats FROM runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["stats"])
        except (json.JSONDecodeError, TypeError):
            return {}

    def close(self) -> None:
        self.conn.close()
