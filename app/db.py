import os
import sqlite3
from typing import Literal
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from secrets import token_urlsafe

DB_PATH = os.getenv("CTF_DB_PATH", "ctf.db")


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(raw: str) -> str:
    return sha256(raw.encode("utf-8")).hexdigest()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS phases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                round_no INTEGER NOT NULL,
                state TEXT NOT NULL,
                defense_started_at TEXT,
                attack_started_at TEXT,
                ended_at TEXT
            );

            CREATE TABLE IF NOT EXISTS flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase_id INTEGER NOT NULL,
                owner_user_id INTEGER NOT NULL,
                flag_value TEXT NOT NULL,
                FOREIGN KEY (phase_id) REFERENCES phases(id),
                FOREIGN KEY (owner_user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS system_prompts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase_id INTEGER NOT NULL,
                owner_user_id INTEGER NOT NULL,
                prompt_body TEXT NOT NULL DEFAULT '',
                updated_at TEXT,
                UNIQUE (phase_id, owner_user_id),
                FOREIGN KEY (phase_id) REFERENCES phases(id),
                FOREIGN KEY (owner_user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS llm_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase_id INTEGER NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('test', 'attack')),
                defense_user_id INTEGER NOT NULL,
                attack_user_id INTEGER NOT NULL,
                defense_prompt TEXT,
                full_defense_prompt TEXT NOT NULL,
                attack_prompt TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'done', 'error')),
                result TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                evaluation_started_at TEXT,
                evaluation_finished_at TEXT,
                FOREIGN KEY (phase_id) REFERENCES phases(id),
                FOREIGN KEY (defense_user_id) REFERENCES users(id),
                FOREIGN KEY (attack_user_id) REFERENCES users(id)
            );
            """
        )

def enqueue_llm_job(
    conn: sqlite3.Connection,
    phase_id: int,
    kind: Literal["test", "attack"],
    defense_user_id: int,
    attack_user_id: int,
    defense_prompt: str,
    attack_prompt: str,
) -> int:
    assert kind in ("test", "attack")

    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO llm_jobs
        (phase_id, kind, defense_user_id, attack_user_id, defense_prompt, full_defense_prompt, attack_prompt, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            phase_id,
            kind,
            defense_user_id,
            attack_user_id,
            defense_prompt,
            _render_full_system_prompt(conn, phase_id, defense_user_id),
            attack_prompt,
            utcnow_iso(),
        ),
    )
    last_id = cursor.lastrowid
    conn.commit()
    return last_id

def get_owner_latest_job(conn: sqlite3.Connection, phase_id: int, kind: Literal["test", "attack"], attack_user_id: int):
    return conn.execute(
        """
        SELECT * FROM llm_jobs
        WHERE phase_id = ? AND kind = ? AND attack_user_id = ? 
        ORDER BY id DESC LIMIT 1
        """,
        (phase_id, kind, attack_user_id),
    ).fetchone()

def ensure_seed_users() -> None:
    # Demo fixed users/passwords: user01..user10 / pass01..pass10 and admin/adminpass
    with get_conn() as conn:
        for i in range(1, 11):
            username = f"user{i:02d}"
            password = f"pass{i:02d}"
            conn.execute(
                """
                INSERT OR IGNORE INTO users (username, password_hash, is_admin)
                VALUES (?, ?, 0)
                """,
                (username, hash_password(password)),
            )

        admin_name = os.getenv("ADMIN", "admin")
        admin_pass = os.getenv("ADMINPASS", "adminpass")
        conn.execute(
            """
            INSERT OR IGNORE INTO users (username, password_hash, is_admin)
            VALUES (?, ?, 1)
            """,
            (admin_name, hash_password(admin_pass)),
        )


def get_current_phase(conn: sqlite3.Connection):
    """Get the current active phase (defense or attack)."""
    return conn.execute(
        "SELECT * FROM phases WHERE state IN ('defense', 'attack') ORDER BY id DESC LIMIT 1"
    ).fetchone()

def get_latest_phase(conn: sqlite3.Connection):
    """Get the latest phase regardless of state."""
    return conn.execute(
        "SELECT * FROM phases ORDER BY id DESC LIMIT 1"
    ).fetchone()

def create_phase(round_no: int) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO phases (round_no, state, defense_started_at)
            VALUES (?, 'defense', ?)
            """,
            (round_no, utcnow_iso()),
        )
        phase_id = cur.lastrowid

        users = conn.execute("SELECT id FROM users WHERE is_admin = 0").fetchall()
        for u in users:
            flag = f"TSGCTF{{FLAG_ROUND{round_no}_U{u['id']}_{token_urlsafe(12)}}}"
            conn.execute(
                "INSERT INTO flags (phase_id, owner_user_id, flag_value) VALUES (?, ?, ?)",
                (phase_id, u["id"], flag),
            )
            conn.execute(
                "INSERT INTO system_prompts (phase_id, owner_user_id, prompt_body, updated_at) VALUES (?, ?, '', ?)",
                (phase_id, u["id"], utcnow_iso()),
            )
        return phase_id

def render_prefix_system_prompt(conn: sqlite3.Connection, phase_id: int, owner_user_id: int) -> str:
    f = conn.execute(
        "SELECT flag_value FROM flags WHERE phase_id = ? AND owner_user_id = ?",
        (phase_id, owner_user_id),
    ).fetchone()
    flag_prefix = (
        "[SECRET_FLAG]\n"
        f"{f['flag_value']}\n"
        "[/SECRET_FLAG]\n"
    )
    return flag_prefix

def _render_full_system_prompt(conn: sqlite3.Connection, phase_id: int, owner_user_id: int) -> str:
    s = conn.execute(
        "SELECT prompt_body FROM system_prompts WHERE phase_id = ? AND owner_user_id = ?",
        (phase_id, owner_user_id),
    ).fetchone()
    flag_prefix = render_prefix_system_prompt(conn, phase_id, owner_user_id)

    return flag_prefix + (s["prompt_body"] if s else "")

def get_owner_defense_prompt(conn: sqlite3.Connection, phase_id: int, owner_user_id: int) -> str:
    s = conn.execute(
        "SELECT prompt_body FROM system_prompts WHERE phase_id = ? AND owner_user_id = ?",
        (phase_id, owner_user_id),
    ).fetchone()
    return s["prompt_body"] if s else ""

def get_owner_flag(conn: sqlite3.Connection, phase_id: int, owner_user_id: int) -> str:
    f = conn.execute(
        "SELECT flag_value FROM flags WHERE phase_id = ? AND owner_user_id = ?",
        (phase_id, owner_user_id),
    ).fetchone()
    return f["flag_value"] if f else ""

def get_targets(conn: sqlite3.Connection, exclude_user_id: int):
    return conn.execute(
        "SELECT id, username FROM users WHERE is_admin = 0 AND id != ?",
        (exclude_user_id,),
    ).fetchall()