"""SQLite storage for enriched alert groups. Deliberately schema-simple --
one table, one row per alert group -- since a single analyst dashboard has
no need for a bigger database yet."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    group_key TEXT PRIMARY KEY,
    signature_id INTEGER,
    signature TEXT,
    category TEXT,
    suricata_severity INTEGER,
    src_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    app_proto TEXT,
    dest_hostname TEXT,
    count INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    sample_events TEXT,
    llm_severity TEXT,
    llm_summary TEXT,
    llm_technical_detail TEXT,
    llm_recommended_action TEXT,
    llm_confidence TEXT,
    status TEXT DEFAULT 'new',
    enriched_at TEXT
);
"""


@contextmanager
def connect(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(SCHEMA)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_group(conn: sqlite3.Connection, group, explanation: dict) -> None:
    conn.execute(
        """
        INSERT INTO alerts (
            group_key, signature_id, signature, category, suricata_severity,
            src_ip, dest_ip, dest_port, proto, app_proto, dest_hostname,
            count, first_seen, last_seen, sample_events,
            llm_severity, llm_summary, llm_technical_detail,
            llm_recommended_action, llm_confidence, enriched_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(group_key) DO UPDATE SET
            count=excluded.count,
            last_seen=excluded.last_seen,
            sample_events=excluded.sample_events,
            llm_severity=excluded.llm_severity,
            llm_summary=excluded.llm_summary,
            llm_technical_detail=excluded.llm_technical_detail,
            llm_recommended_action=excluded.llm_recommended_action,
            llm_confidence=excluded.llm_confidence,
            enriched_at=excluded.enriched_at
        """,
        (
            group.group_key,
            group.signature_id,
            group.signature,
            group.category,
            group.suricata_severity,
            group.src_ip,
            group.dest_ip,
            group.dest_port,
            group.proto,
            group.app_proto,
            group.dest_hostname,
            group.count,
            group.first_seen,
            group.last_seen,
            json.dumps(group.sample_events),
            explanation["severity"],
            explanation["summary"],
            explanation["technical_detail"],
            explanation["recommended_action"],
            explanation["confidence"],
        ),
    )


def existing_group_keys(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT group_key FROM alerts").fetchall()
    return {row["group_key"] for row in rows}


def all_alerts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    severity_order = "CASE llm_severity " \
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    return conn.execute(
        f"SELECT * FROM alerts ORDER BY {severity_order}, count DESC"
    ).fetchall()


def get_alert(conn: sqlite3.Connection, group_key: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM alerts WHERE group_key = ?", (group_key,)
    ).fetchone()


def set_status(conn: sqlite3.Connection, group_key: str, status: str) -> None:
    conn.execute(
        "UPDATE alerts SET status = ? WHERE group_key = ?", (status, group_key)
    )
