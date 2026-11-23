"""SQLite bootstrap + lightweight cursor helper."""
import sqlite3
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
        """
    )
    conn.commit()
    conn.close()
