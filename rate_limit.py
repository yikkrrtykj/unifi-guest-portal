import hashlib
import hmac
import math
import sqlite3
import time


RATE_LIMIT_TABLE = "auth_rate_limits"


def ensure_rate_limit_table(conn):
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS {RATE_LIMIT_TABLE} (
            key_hash TEXT PRIMARY KEY,
            failures INTEGER NOT NULL,
            window_started REAL NOT NULL,
            blocked_until REAL NOT NULL,
            updated_at REAL NOT NULL
        )
    """)


def rate_limit_key(secret, scope, identifier):
    normalized = (identifier or "unknown").strip().lower()
    message = f"{scope}:{normalized}".encode("utf-8")

    return hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def retry_after(db_path, key_hashes, now=None):
    now = time.time() if now is None else float(now)
    keys = tuple(dict.fromkeys(key_hashes))

    if not keys:
        return 0

    conn = sqlite3.connect(db_path, timeout=10)

    try:
        ensure_rate_limit_table(conn)

        conn.commit()

        placeholders = ",".join(
            "?"
            for _ in keys
        )

        row = conn.execute(
            f"""
                SELECT MAX(blocked_until)
                FROM {RATE_LIMIT_TABLE}
                WHERE key_hash IN ({placeholders})
            """,
            keys,
        ).fetchone()

        blocked_until = float(row[0] or 0)

        return max(
            0,
            math.ceil(blocked_until - now),
        )

    finally:
        conn.close()


def record_failure(
    db_path,
    key_hash,
    max_failures,
    window_seconds,
    block_seconds,
    now=None,
):
    now = time.time() if now is None else float(now)
    conn = sqlite3.connect(db_path, timeout=10)

    try:
        conn.execute("BEGIN IMMEDIATE")
        ensure_rate_limit_table(conn)

        row = conn.execute(
            f"""
                SELECT failures,
                       window_started,
                       blocked_until
                FROM {RATE_LIMIT_TABLE}
                WHERE key_hash = ?
            """,
            (key_hash,),
        ).fetchone()

        if row and float(row[2]) > now:
            blocked_until = float(row[2])

            conn.execute(
                f"""
                    UPDATE {RATE_LIMIT_TABLE}
                    SET updated_at = ?
                    WHERE key_hash = ?
                """,
                (now, key_hash),
            )

        else:
            if (
                not row
                or now - float(row[1])
                >= window_seconds
            ):
                failures = 1
                window_started = now
            else:
                failures = int(row[0]) + 1
                window_started = float(row[1])

            blocked_until = (
                now + block_seconds
                if failures >= max_failures
                else 0
            )

            conn.execute(
                f"""
                    INSERT INTO {RATE_LIMIT_TABLE} (
                        key_hash,
                        failures,
                        window_started,
                        blocked_until,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(key_hash) DO UPDATE SET
                        failures = excluded.failures,
                        window_started = excluded.window_started,
                        blocked_until = excluded.blocked_until,
                        updated_at = excluded.updated_at
                """,
                (
                    key_hash,
                    failures,
                    window_started,
                    blocked_until,
                    now,
                ),
            )

        conn.execute(
            f"""
                DELETE FROM {RATE_LIMIT_TABLE}
                WHERE updated_at < ?
            """,
            (now - 604800,),
        )

        conn.commit()

        return max(
            0,
            math.ceil(blocked_until - now),
        )

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def clear_failures(db_path, key_hashes):
    keys = tuple(dict.fromkeys(key_hashes))

    if not keys:
        return

    conn = sqlite3.connect(db_path, timeout=10)

    try:
        ensure_rate_limit_table(conn)

        placeholders = ",".join(
            "?"
            for _ in keys
        )

        conn.execute(
            f"""
                DELETE FROM {RATE_LIMIT_TABLE}
                WHERE key_hash IN ({placeholders})
            """,
            keys,
        )

        conn.commit()

    finally:
        conn.close()
