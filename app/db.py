"""SQLite bootstrap + lightweight cursor helper."""
import sqlite3
import time
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "vulnshop.sqlite"


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            email        TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            password     TEXT NOT NULL,
            role         TEXT NOT NULL DEFAULT 'user',
            ssn          TEXT,
            credit_card  TEXT
        );

        CREATE TABLE IF NOT EXISTS reports (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            title     TEXT NOT NULL,
            body      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            window_start INTEGER NOT NULL,
            count INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS quote_cache (
            amount TEXT NOT NULL,
            currency TEXT NOT NULL,
            response TEXT NOT NULL,
            status INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (amount, currency)
        );
        """
    )
    conn.commit()
    conn.close()


def rate_limited(key: str, limit: int, window: int) -> bool:
    now = int(time.time())
    with closing(get_conn()) as conn:
        with conn:
            conn.execute(
                """INSERT INTO rate_limits (key, window_start, count) VALUES (?, ?, 1)
                   ON CONFLICT(key) DO UPDATE SET
                       window_start = CASE WHEN window_start <= ? THEN ? ELSE window_start END,
                       count = CASE WHEN window_start <= ? THEN 1 ELSE count + 1 END""",
                (key, now, now - window, now, now - window),
            )
            count = conn.execute("SELECT count FROM rate_limits WHERE key = ?", (key,)).fetchone()[0]
    return count > limit
