import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from config import DATABASE_PATH


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL,
                last_login TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                input_summary TEXT,
                result_json TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS ai_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )


def create_user(username: str, email: str, password: str, role: str = "user") -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO users (username, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, email, generate_password_hash(password), role, utc_now()),
        )
        return cursor.lastrowid or 0


def get_user_by_username(username: str):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int):
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def verify_user(username: str, password: str):
    user = get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        with get_connection() as conn:
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (utc_now(), user["id"]),
            )
        return user
    return None


def save_scan(user_id: int, module: str, input_summary: str, result: dict, risk_level: str) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_history (user_id, module, input_summary, result_json, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, module, input_summary, json.dumps(result), risk_level, utc_now()),
        )
        return cursor.lastrowid or 0


def get_user_history(user_id: int, limit: int = 50):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, module, input_summary, risk_level, created_at
            FROM scan_history WHERE user_id = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int, user_id: int | None = None):
    with get_connection() as conn:
        if user_id is not None:
            row = conn.execute(
                "SELECT * FROM scan_history WHERE id = ? AND user_id = ?",
                (scan_id, user_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["result"] = json.loads(data["result_json"])
        return data


def get_threat_stats(user_id: int | None = None):
    with get_connection() as conn:
        if user_id:
            rows = conn.execute(
                """
                SELECT module, risk_level, COUNT(*) as count
                FROM scan_history WHERE user_id = ?
                GROUP BY module, risk_level
                """,
                (user_id,),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) as c FROM scan_history WHERE user_id = ?",
                (user_id,),
            ).fetchone()["c"]
        else:
            rows = conn.execute(
                """
                SELECT module, risk_level, COUNT(*) as count
                FROM scan_history
                GROUP BY module, risk_level
                """
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) as c FROM scan_history").fetchone()["c"]
        return {"breakdown": [dict(r) for r in rows], "total_scans": total}


def get_recent_scans(limit: int = 10, user_id: int | None = None):
    with get_connection() as conn:
        if user_id:
            rows = conn.execute(
                """
                SELECT s.*, u.username FROM scan_history s
                JOIN users u ON u.id = s.user_id
                WHERE s.user_id = ? ORDER BY s.created_at DESC LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT s.*, u.username FROM scan_history s
                JOIN users u ON u.id = s.user_id
                ORDER BY s.created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def get_all_users():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, username, email, role, created_at, last_login,
            (SELECT COUNT(*) FROM scan_history WHERE user_id = users.id) as scan_count
            FROM users ORDER BY created_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def save_ai_message(user_id: int, question: str, answer: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO ai_conversations (user_id, question, answer, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, question, answer, utc_now()),
        )


def get_ai_history(user_id: int, limit: int = 20):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT question, answer, created_at FROM ai_conversations
            WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def admin_stats():
    with get_connection() as conn:
        users = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        scans = conn.execute("SELECT COUNT(*) as c FROM scan_history").fetchone()["c"]
        high_risk = conn.execute(
            "SELECT COUNT(*) as c FROM scan_history WHERE risk_level IN ('high', 'critical')"
        ).fetchone()["c"]
        ai_msgs = conn.execute("SELECT COUNT(*) as c FROM ai_conversations").fetchone()["c"]
        return {
            "users": users,
            "scans": scans,
            "high_risk": high_risk,
            "ai_messages": ai_msgs,
        }
