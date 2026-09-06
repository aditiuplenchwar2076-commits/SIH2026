import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from uuid import uuid4

DEFAULT_DB_PATH = "audit_history.db"


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Get a connection to the SQLite database and ensure tables exist.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Initialize SQLite database schema and indexes if they do not exist.
    """
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                audit_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                user_email TEXT,
                vendor TEXT NOT NULL,
                hostname TEXT,
                security_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                critical_findings INTEGER NOT NULL,
                high_findings INTEGER NOT NULL,
                medium_findings INTEGER NOT NULL,
                low_findings INTEGER NOT NULL,
                filename TEXT
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_timestamp 
            ON audit_history(user_id, timestamp DESC);
        """)
        conn.commit()


def save_audit_record(
    user_id: str,
    vendor: str,
    security_score: int,
    risk_level: str,
    findings: List[Dict[str, Any]],
    risk_data: Optional[Dict[str, Any]] = None,
    hostname: Optional[str] = None,
    user_email: Optional[str] = None,
    filename: Optional[str] = None,
    audit_id: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH
) -> str:
    """
    Persist an audit record in the SQLite database associated with the user's Firebase UID.

    Never stores raw network configuration, tokens, or credentials.
    Returns the assigned audit_id.
    """
    init_db(db_path)

    if not audit_id:
        audit_id = f"AUDIT-{datetime.now().strftime('%Y%m%d')}-{uuid4().hex[:6].upper()}"

    timestamp = datetime.now(timezone.utc).isoformat()

    total_findings = len(findings)
    critical_findings = sum(1 for f in findings if f.get("severity", "").lower() == "critical")

    if risk_data:
        high_findings = risk_data.get("high_findings", 0)
        medium_findings = risk_data.get("medium_findings", 0)
        low_findings = risk_data.get("low_findings", 0)
    else:
        high_findings = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_findings = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low_findings = sum(1 for f in findings if f.get("severity", "").lower() == "low")

    with get_connection(db_path) as conn:
        conn.execute("""
            INSERT INTO audit_history (
                audit_id,
                timestamp,
                user_id,
                user_email,
                vendor,
                hostname,
                security_score,
                risk_level,
                total_findings,
                critical_findings,
                high_findings,
                medium_findings,
                low_findings,
                filename
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            audit_id,
            timestamp,
            user_id,
            user_email,
            vendor,
            hostname,
            security_score,
            risk_level,
            total_findings,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            filename
        ))
        conn.commit()

    return audit_id


def get_user_audit_history(
    user_id: str,
    limit: int = 50,
    db_path: str = DEFAULT_DB_PATH
) -> List[Dict[str, Any]]:
    """
    Retrieve audit history exclusively for the specified user_id in newest-first order.

    Does not expose other users' records, raw configurations, or secrets.
    """
    init_db(db_path)

    with get_connection(db_path) as conn:
        cursor = conn.execute("""
            SELECT 
                audit_id,
                timestamp,
                vendor,
                hostname,
                security_score,
                risk_level,
                total_findings,
                critical_findings,
                high_findings,
                medium_findings,
                low_findings,
                filename
            FROM audit_history
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (user_id, limit))

        rows = cursor.fetchall()
        return [dict(row) for row in rows]
