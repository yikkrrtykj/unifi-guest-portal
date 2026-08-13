import os
import math
import sqlite3
import secrets
from datetime import datetime, timezone, timedelta

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    jsonify,
)

from rate_limit import (
    clear_failures,
    ensure_rate_limit_table,
    rate_limit_key,
    record_failure,
    retry_after,
)


app = Flask(__name__)
app.logger.setLevel("INFO")


DB_PATH = os.environ.get(
    "PORTAL_DB_PATH",
    "/opt/unifi-portal/portal.db"
)

STAFF_USER = os.environ.get(
    "STAFF_USER",
    ""
)

STAFF_PASSWORD = os.environ.get(
    "STAFF_PASSWORD",
    ""
)

PORTAL_SECRET = os.environ.get(
    "PORTAL_SECRET",
    ""
)

STAFF_COOKIE_SECURE = (
    os.environ.get(
        "STAFF_COOKIE_SECURE",
        "false"
    ).lower() == "true"
)

STAFF_LOGIN_MAX_FAILURES = int(
    os.environ.get(
        "STAFF_LOGIN_MAX_FAILURES",
        "5"
    )
)

STAFF_LOGIN_WINDOW_SECONDS = int(
    os.environ.get(
        "STAFF_LOGIN_WINDOW_SECONDS",
        "600"
    )
)

STAFF_LOGIN_BLOCK_SECONDS = int(
    os.environ.get(
        "STAFF_LOGIN_BLOCK_SECONDS",
        "900"
    )
)

DASHBOARD_PAGE_SIZE = int(
    os.environ.get(
        "DASHBOARD_PAGE_SIZE",
        "50"
    )
)


if not STAFF_USER.strip():
    raise RuntimeError(
        "STAFF_USER is not configured"
    )

if not STAFF_PASSWORD.strip():
    raise RuntimeError(
        "STAFF_PASSWORD is not configured"
    )

if not PORTAL_SECRET:
    raise RuntimeError(
        "PORTAL_SECRET is not configured"
    )

if (
    STAFF_LOGIN_MAX_FAILURES < 1
    or STAFF_LOGIN_WINDOW_SECONDS < 1
    or STAFF_LOGIN_BLOCK_SECONDS < 1
):
    raise RuntimeError(
        "Staff login rate-limit values "
        "must be positive integers"
    )

if not 10 <= DASHBOARD_PAGE_SIZE <= 100:
    raise RuntimeError(
        "DASHBOARD_PAGE_SIZE must be "
        "between 10 and 100"
    )


app.secret_key = PORTAL_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=STAFF_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


def utcnow():
    return datetime.now(timezone.utc)


def get_db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=10
    )

    conn.row_factory = sqlite3.Row

    return conn


def init_db():
    conn = get_db()

    try:
        conn.execute(
            "PRAGMA journal_mode=WAL"
        )
        conn.execute("BEGIN IMMEDIATE")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS guests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                client_mac TEXT,
                ap_mac TEXT,
                ssid TEXT,
                site TEXT,
                original_url TEXT,
                remote_ip TEXT,
                created_at TEXT NOT NULL,
                authorized INTEGER NOT NULL DEFAULT 0,
                authorized_at TEXT,
                expires_at TEXT,
                auth_error TEXT,
                registration_state TEXT
                    NOT NULL DEFAULT 'complete',
                revoked_at TEXT,
                revoked_by TEXT
            )
        """)

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(guests)"
            ).fetchall()
        }

        migrations = {
            "authorized":
                "INTEGER NOT NULL DEFAULT 0",

            "authorized_at":
                "TEXT",

            "expires_at":
                "TEXT",

            "auth_error":
                "TEXT",

            "registration_state":
                "TEXT NOT NULL DEFAULT 'complete'",

            "revoked_at":
                "TEXT",

            "revoked_by":
                "TEXT",
        }

        for column, definition in migrations.items():
            if column not in columns:
                conn.execute(
                    f"""
                    ALTER TABLE guests
                    ADD COLUMN {column} {definition}
                    """
                )

        conn.execute("""
            CREATE TABLE IF NOT EXISTS staff_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guest_id INTEGER,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                client_mac TEXT,
                result TEXT,
                created_at TEXT NOT NULL
            )
        """)

        ensure_rate_limit_table(conn)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
                idx_guests_created_at
            ON guests (created_at DESC)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
                idx_guests_status_fields
            ON guests (
                authorized,
                revoked_at,
                expires_at
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
                idx_staff_actions_created_at
            ON staff_actions (created_at DESC)
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


init_db()


def logged_in():
    return bool(
        session.get("staff_user")
    )


def client_ip():
    return request.headers.get(
        "X-Real-IP",
        request.remote_addr or "unknown"
    )


def staff_login_limit_keys(username):
    return (
        rate_limit_key(
            PORTAL_SECRET,
            "staff-ip",
            client_ip()
        ),
        rate_limit_key(
            PORTAL_SECRET,
            "staff-user",
            username or "empty"
        ),
    )


def staff_login_retry_after(username):
    return retry_after(
        DB_PATH,
        staff_login_limit_keys(username)
    )


def record_staff_login_failure(username):
    waits = [
        record_failure(
            DB_PATH,
            key,
            STAFF_LOGIN_MAX_FAILURES,
            STAFF_LOGIN_WINDOW_SECONDS,
            STAFF_LOGIN_BLOCK_SECONDS,
        )
        for key in staff_login_limit_keys(username)
    ]

    return max(waits)


def clear_staff_login_failures(username):
    clear_failures(
        DB_PATH,
        staff_login_limit_keys(username)
    )


def guest_status(row):
    if row["revoked_at"]:
        return "revoked"

    if (
        row["authorized"]
        and row["expires_at"]
    ):
        try:
            expires = datetime.fromisoformat(
                row["expires_at"]
            )

            if expires > utcnow():
                return "active"

        except Exception:
            pass

    return "expired"


def serialize_guest(row):
    return {
        "id": row["id"],
        "name": row["name"] or "",
        "phone": row["phone"] or "",
        "ssid": row["ssid"] or "",
        "created_at": row["created_at"] or "",
        "authorized_at": row["authorized_at"] or "",
        "expires_at": row["expires_at"] or "",
        "revoked_at": row["revoked_at"] or "",
        "status": guest_status(row),
    }


def positive_int(value, default, maximum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default

    if number < 1:
        return default

    if maximum is not None:
        return min(number, maximum)

    return number


def guest_filter(query, status):
    clauses = []
    parameters = []

    if query:
        like = f"%{query}%"
        clauses.append(
            "(name LIKE ? OR phone LIKE ? OR ssid LIKE ?)"
        )
        parameters.extend((like, like, like))

    now = utcnow().isoformat()

    if status == "active":
        clauses.append("""
            authorized = 1
            AND registration_state = 'complete'
            AND revoked_at IS NULL
            AND expires_at IS NOT NULL
            AND expires_at > ?
        """)
        parameters.append(now)

    elif status == "revoked":
        clauses.append("revoked_at IS NOT NULL")

    elif status == "expired":
        clauses.append("""
            revoked_at IS NULL
            AND NOT (
                authorized = 1
                AND registration_state = 'complete'
                AND expires_at IS NOT NULL
                AND expires_at > ?
            )
        """)
        parameters.append(now)

    where = (
        " WHERE " + " AND ".join(
            f"({clause})"
            for clause in clauses
        )
        if clauses
        else ""
    )

    return where, parameters


@app.after_request
def security_headers(response):
    response.headers[
        "Cache-Control"
    ] = "no-store"

    response.headers[
        "Pragma"
    ] = "no-cache"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "Referrer-Policy"
    ] = "same-origin"

    return response


@app.route(
    "/staff/login",
    methods=["GET", "POST"]
)
def staff_login():
    if logged_in():
        return redirect(
            url_for("staff")
        )

    error = ""

    if request.method == "POST":

        username = (
            request.form
            .get("username", "")
            .strip()
        )

        password = (
            request.form
            .get("password", "")
        )

        wait_seconds = staff_login_retry_after(
            username
        )

        if wait_seconds:
            app.logger.warning(
                "STAFF_LOGIN_RATE_LIMITED user=%s ip=%s",
                username,
                client_ip()
            )

            return render_template(
                "staff_login.html",
                error=(
                    "Too many sign-in attempts. "
                    "Please wait before trying again."
                )
            ), 429, {
                "Retry-After": str(wait_seconds)
            }

        valid = (
            secrets.compare_digest(
                username,
                STAFF_USER
            )
            and
            secrets.compare_digest(
                password,
                STAFF_PASSWORD
            )
        )

        if valid:
            clear_staff_login_failures(
                username
            )

            app.logger.info(
                "STAFF_LOGIN_SUCCESS user=%s ip=%s",
                username,
                request.headers.get(
                    "X-Real-IP",
                    request.remote_addr
                )
            )

            session.clear()

            session.permanent = True

            session["staff_user"] = username

            return redirect(
                url_for("staff")
            )

        app.logger.warning(
            "STAFF_LOGIN_FAILED user=%s ip=%s",
            username,
            request.headers.get(
                "X-Real-IP",
                request.remote_addr
            )
        )

        wait_seconds = record_staff_login_failure(
            username
        )

        if wait_seconds:
            return render_template(
                "staff_login.html",
                error=(
                    "Too many sign-in attempts. "
                    "Please wait before trying again."
                )
            ), 429, {
                "Retry-After": str(wait_seconds)
            }

        error = "Incorrect username or password."

    return render_template(
        "staff_login.html",
        error=error
    )


@app.route(
    "/staff/logout",
    methods=["POST"]
)
def staff_logout():
    session.clear()

    return redirect(
        url_for("staff_login")
    )


@app.route(
    "/staff/",
    methods=["GET"]
)
def staff():
    if not logged_in():
        return redirect(
            url_for("staff_login")
        )

    return render_template(
        "staff.html",
        staff_user=session["staff_user"]
    )


@app.route(
    "/staff/api/guests",
    methods=["GET"]
)
def api_guests():
    if not logged_in():
        return jsonify({
            "ok": False,
            "error": "Not authenticated"
        }), 401

    page = positive_int(
        request.args.get("page"),
        1,
        1000000
    )
    page_size = positive_int(
        request.args.get("page_size"),
        DASHBOARD_PAGE_SIZE,
        100
    )
    query = (
        request.args.get("q", "")
        .strip()[:100]
    )
    status = (
        request.args.get("status", "all")
        .strip().lower()
    )

    if status not in {
        "all",
        "active",
        "expired",
        "revoked",
    }:
        status = "all"

    where, parameters = guest_filter(
        query,
        status
    )

    conn = get_db()

    filtered_total = conn.execute(
        "SELECT COUNT(*) FROM guests" + where,
        parameters
    ).fetchone()[0]

    pages = max(
        1,
        math.ceil(filtered_total / page_size)
    )
    page = min(page, pages)
    offset = (page - 1) * page_size

    rows = conn.execute(
        "SELECT * FROM guests"
        + where
        + " ORDER BY id DESC LIMIT ? OFFSET ?",
        (*parameters, page_size, offset)
    ).fetchall()

    now = utcnow().isoformat()
    totals = conn.execute("""
        SELECT
            COUNT(*) AS total,
            COALESCE(SUM(
                CASE
                    WHEN authorized = 1
                     AND registration_state = 'complete'
                     AND revoked_at IS NULL
                     AND expires_at IS NOT NULL
                     AND expires_at > ?
                    THEN 1
                    ELSE 0
                END
            ), 0) AS active
        FROM guests
    """, (now,)).fetchone()

    conn.close()

    guests = [
        serialize_guest(row)
        for row in rows
    ]

    return jsonify({
        "ok": True,
        "guests": guests,
        "total": totals["total"],
        "active": totals["active"],
        "filtered_total": filtered_total,
        "page": page,
        "pages": pages,
        "page_size": page_size,
    })


@app.route(
    "/staff/health",
    methods=["GET"]
)
def health():
    return {
        "status": "ok"
    }


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8001
    )
