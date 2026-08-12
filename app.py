import os
import re
import math
import sqlite3
import secrets
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import requests

from flask import (
    Flask,
    request,
    render_template,
    Response
)

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)

from rate_limit import (
    clear_failures,
    rate_limit_key,
    record_failure,
    retry_after,
)


app = Flask(__name__)


DB_PATH = os.environ.get(
    "PORTAL_DB_PATH",
    "/opt/unifi-portal/portal.db"
)

ADMIN_USER = os.environ.get(
    "ADMIN_USER",
    ""
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    ""
)

UNIFI_URL = os.environ.get(
    "UNIFI_URL",
    "https://YOUR_UNIFI_CONTROLLER:8443"
).rstrip("/")

UNIFI_SITE = os.environ.get(
    "UNIFI_SITE",
    "default"
)

UNIFI_USERNAME = os.environ.get(
    "UNIFI_USERNAME",
    ""
)

UNIFI_PASSWORD = os.environ.get(
    "UNIFI_PASSWORD",
    ""
)

UNIFI_VERIFY_TLS = (
    os.environ.get(
        "UNIFI_VERIFY_TLS",
        "false"
    ).lower() == "true"
)

AUTH_MINUTES = int(
    os.environ.get(
        "AUTH_MINUTES",
        "480"
    )
)

ACCESS_CODE_MAX_FAILURES = int(
    os.environ.get(
        "ACCESS_CODE_MAX_FAILURES",
        "5"
    )
)

ACCESS_CODE_WINDOW_SECONDS = int(
    os.environ.get(
        "ACCESS_CODE_WINDOW_SECONDS",
        "600"
    )
)

ACCESS_CODE_BLOCK_SECONDS = int(
    os.environ.get(
        "ACCESS_CODE_BLOCK_SECONDS",
        "900"
    )
)
PORTAL_ACCESS_CODE = os.environ.get(
    "PORTAL_ACCESS_CODE",
    ""
)

if not PORTAL_ACCESS_CODE:
    raise RuntimeError(
        "PORTAL_ACCESS_CODE is not configured"
    )
PORTAL_SECRET = os.environ.get(
    "PORTAL_SECRET",
    ""
)

if not PORTAL_SECRET:
    raise RuntimeError(
        "PORTAL_SECRET is not configured"
    )

if not ADMIN_USER.strip():
    raise RuntimeError(
        "ADMIN_USER is not configured"
    )

if not ADMIN_PASSWORD.strip():
    raise RuntimeError(
        "ADMIN_PASSWORD is not configured"
    )

if (
    ACCESS_CODE_MAX_FAILURES < 1
    or ACCESS_CODE_WINDOW_SECONDS < 1
    or ACCESS_CODE_BLOCK_SECONDS < 1
):
    raise RuntimeError(
        "Access code rate-limit values "
        "must be positive integers"
    )


serializer = URLSafeTimedSerializer(
    PORTAL_SECRET,
    salt="unifi-guest-portal"
)


MAC_RE = re.compile(
    r"^[0-9a-fA-F]{2}:"
    r"[0-9a-fA-F]{2}:"
    r"[0-9a-fA-F]{2}:"
    r"[0-9a-fA-F]{2}:"
    r"[0-9a-fA-F]{2}:"
    r"[0-9a-fA-F]{2}$"
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
                    NOT NULL DEFAULT 'complete'
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
        }

        for column, definition in migrations.items():
            if column not in columns:
                conn.execute(
                    f"""
                    ALTER TABLE guests
                    ADD COLUMN {column} {definition}
                    """
                )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


init_db()


def check_admin():
    auth = request.authorization

    if not auth:
        return False

    if not ADMIN_USER or not ADMIN_PASSWORD:
        return False

    return (
        secrets.compare_digest(
            auth.username or "",
            ADMIN_USER
        )
        and
        secrets.compare_digest(
            auth.password or "",
            ADMIN_PASSWORD
        )
    )


def unauthorized():
    return Response(
        "Authentication required",
        401,
        {
            "WWW-Authenticate":
            'Basic realm="Guest WiFi Admin"'
        }
    )


def valid_name(name):
    if len(name) < 2 or len(name) > 80:
        return False

    if not any(
        char.isalpha()
        for char in name
    ):
        return False

    for char in name:
        if not (
            char.isalpha()
            or char.isspace()
            or char in "-'."
        ):
            return False

    return True


def valid_mobile_or_passport(value):
    value = value.strip()

    if len(value) < 6 or len(value) > 24:
        return False

    # Mobile number
    if re.fullmatch(
        r"[0-9+\-() ]+",
        value
    ):
        digits = re.sub(
            r"\D",
            "",
            value
        )

        return 7 <= len(digits) <= 15

    # Passport number
    passport = (
        value
        .replace(" ", "")
        .upper()
    )

    if not re.fullmatch(
        r"[A-Z0-9]{6,20}",
        passport
    ):
        return False

    if not any(
        c.isalpha()
        for c in passport
    ):
        return False

    if not any(
        c.isdigit()
        for c in passport
    ):
        return False

    return True


def safe_redirect_url(value):
    if not value:
        return None

    try:
        parsed = urlparse(value)

        if (
            parsed.scheme in ("http", "https")
            and parsed.netloc
        ):
            return value

    except Exception:
        pass

    return None


def authorize_guest(
    mac,
    site,
    minutes
):
    if not UNIFI_USERNAME:
        return False, (
            "UniFi username is not configured"
        )

    if not UNIFI_PASSWORD:
        return False, (
            "UniFi password is not configured"
        )

    session = requests.Session()

    session.verify = UNIFI_VERIFY_TLS

    try:
        login = session.post(
            UNIFI_URL + "/api/login",
            json={
                "username": UNIFI_USERNAME,
                "password": UNIFI_PASSWORD,
                "remember": True
            },
            timeout=10
        )

        if not login.ok:
            return False, (
                "UniFi login failed "
                f"(HTTP {login.status_code})"
            )

        auth = session.post(
            UNIFI_URL
            + f"/api/s/{site}/cmd/stamgr",
            json={
                "cmd": "authorize-guest",
                "mac": mac,
                "minutes": int(minutes)
            },
            timeout=10
        )

        if not auth.ok:
            return False, (
                "UniFi authorization failed "
                f"(HTTP {auth.status_code})"
            )

        try:
            result = auth.json()

            if (
                result
                .get("meta", {})
                .get("rc") != "ok"
            ):
                return False, (
                    "UniFi returned an "
                    "authorization error"
                )

        except Exception:
            return False, (
                "Invalid response from UniFi"
            )

        return True, None

    except requests.RequestException as exc:
        return False, (
            "Unable to contact UniFi: "
            + str(exc)
        )


def unauthorize_guest(mac, site):
    if not UNIFI_USERNAME or not UNIFI_PASSWORD:
        return False

    session = requests.Session()
    session.verify = UNIFI_VERIFY_TLS

    try:
        login = session.post(
            UNIFI_URL + "/api/login",
            json={
                "username": UNIFI_USERNAME,
                "password": UNIFI_PASSWORD,
                "remember": True
            },
            timeout=10
        )

        if not login.ok:
            return False

        revoke = session.post(
            UNIFI_URL
            + f"/api/s/{site}/cmd/stamgr",
            json={
                "cmd": "unauthorize-guest",
                "mac": mac
            },
            timeout=10
        )

        if not revoke.ok:
            return False

        result = revoke.json()

        return (
            result
            .get("meta", {})
            .get("rc") == "ok"
        )

    except (
        requests.RequestException,
        ValueError
    ):
        return False


def client_ip():
    return request.headers.get(
        "X-Real-IP",
        request.remote_addr or "unknown"
    )


def access_code_limit_keys(client_mac):
    return (
        rate_limit_key(
            PORTAL_SECRET,
            "guest-ip",
            client_ip()
        ),
        rate_limit_key(
            PORTAL_SECRET,
            "guest-mac",
            client_mac
        ),
    )


def access_code_retry_after(client_mac):
    return retry_after(
        DB_PATH,
        access_code_limit_keys(client_mac)
    )


def record_access_code_failure(client_mac):
    waits = [
        record_failure(
            DB_PATH,
            key,
            ACCESS_CODE_MAX_FAILURES,
            ACCESS_CODE_WINDOW_SECONDS,
            ACCESS_CODE_BLOCK_SECONDS,
        )
        for key in access_code_limit_keys(client_mac)
    ]

    return max(waits)


def clear_access_code_failures(client_mac):
    clear_failures(
        DB_PATH,
        access_code_limit_keys(client_mac)
    )


def get_active_guest(mac):
    conn = get_db()

    row = conn.execute("""
        SELECT *
        FROM guests
        WHERE client_mac = ?
          AND authorized = 1
          AND registration_state = 'complete'
          AND expires_at IS NOT NULL
        ORDER BY id DESC
        LIMIT 1
    """, (
        mac,
    )).fetchone()

    conn.close()

    if not row:
        return None, 0

    try:
        expires = datetime.fromisoformat(
            row["expires_at"]
        )

    except Exception:
        return None, 0

    remaining = (
        expires - utcnow()
    ).total_seconds()

    if remaining <= 0:
        return None, 0

    minutes = max(
        1,
        math.ceil(
            remaining / 60
        )
    )

    return row, minutes


def portal_payload(
    site,
    client_mac,
    ap_mac,
    ssid,
    original_url
):
    return serializer.dumps({
        "site": site,
        "mac": client_mac,
        "ap": ap_mac,
        "ssid": ssid,
        "url": original_url
    })


def portal_success(
    name,
    redirect_url=None,
    returning=False
):
    return render_template(
        "success.html",
        name=name,
        redirect_url=redirect_url,
        returning=returning
    )


def handle_portal(site):
    if request.method in (
        "GET",
        "HEAD"
    ):
        client_mac = (
            request.args
            .get("id", "")
            .strip()
            .lower()
        )

        ap_mac = (
            request.args
            .get("ap", "")
            .strip()
            .lower()
        )

        ssid = (
            request.args
            .get("ssid", "")
            .strip()
        )

        original_url = (
            request.args
            .get("url", "")
            .strip()
        )

        if not MAC_RE.fullmatch(
            client_mac
        ):
            return render_template(
                "error.html",
                message=(
                    "Unable to identify this "
                    "device. Please disconnect "
                    "and reconnect to WiFi."
                )
            ), 400

        active, remaining = (
            get_active_guest(
                client_mac
            )
        )

        if active:
            ok, error = authorize_guest(
                client_mac,
                site,
                remaining
            )

            if ok:
                return portal_success(
                    active["name"],
                    safe_redirect_url(
                        original_url
                    ),
                    returning=True
                )

            return render_template(
                "error.html",
                message=(
                    "Unable to restore network "
                    "access. Please try again."
                )
            ), 503

        token = portal_payload(
            site,
            client_mac,
            ap_mac,
            ssid,
            original_url
        )

        return render_template(
            "index.html",
            portal_token=token
        )

    token = request.form.get(
        "portal_token",
        ""
    )

    try:
        payload = serializer.loads(
            token,
            max_age=900
        )

    except SignatureExpired:
        return render_template(
            "error.html",
            message=(
                "This login session has expired. "
                "Please reconnect to WiFi."
            )
        ), 400

    except BadSignature:
        return render_template(
            "error.html",
            message=(
                "Invalid login session. "
                "Please reconnect to WiFi."
            )
        ), 400

    client_mac = (
        payload
        .get("mac", "")
        .strip()
        .lower()
    )

    ap_mac = (
        payload
        .get("ap", "")
        .strip()
        .lower()
    )

    ssid = (
        payload
        .get("ssid", "")
        .strip()
    )

    site = (
        payload
        .get("site", UNIFI_SITE)
        .strip()
    )

    original_url = (
        payload
        .get("url", "")
        .strip()
    )

    if not MAC_RE.fullmatch(
        client_mac
    ):
        return render_template(
            "error.html",
            message=(
                "Invalid client information. "
                "Please reconnect to WiFi."
            )
        ), 400

    # Prevent another registration for
    # the same MAC during the active period.
    active, remaining = (
        get_active_guest(
            client_mac
        )
    )

    if active:
        ok, error = authorize_guest(
            client_mac,
            site,
            remaining
        )

        if ok:
            return portal_success(
                active["name"],
                safe_redirect_url(
                    original_url
                ),
                returning=True
            )

        return render_template(
            "error.html",
            message=(
                "Unable to authorize network "
                "access. Please try again."
            )
        ), 503
    access_code = (
        request.form
        .get("access_code", "")
        .strip()
    )
    name = (
        request.form
        .get("name", "")
        .strip()
    )

    phone = (
        request.form
        .get("phone", "")
        .strip()
    )

    wait_seconds = access_code_retry_after(
        client_mac
    )

    if wait_seconds:
        return render_template(
            "index.html",
            portal_token=token,
            name=name,
            phone=phone,
            error=(
                "Too many incorrect access code "
                "attempts. Please wait before "
                "trying again."
            )
        ), 429, {
            "Retry-After": str(wait_seconds)
        }

    if not secrets.compare_digest(
        access_code,
        PORTAL_ACCESS_CODE
    ):
        wait_seconds = (
            record_access_code_failure(
                client_mac
            )
        )

        error = "Incorrect access code."

        if wait_seconds:
            error = (
                "Too many incorrect access code "
                "attempts. Please wait before "
                "trying again."
            )

        return render_template(
            "index.html",
            portal_token=token,
            name=name,
            phone=phone,
            error=error
        ), (429 if wait_seconds else 400), (
            {
                "Retry-After": str(wait_seconds)
            }
            if wait_seconds
            else {}
        )

    clear_access_code_failures(
        client_mac
    )

    if not valid_name(name):
        return render_template(
            "index.html",
            portal_token=token,
            name=name,
            phone=phone,
            error=(
                "Please enter a valid name. "
                "The name must contain letters "
                "and cannot be numbers only."
            )
        ), 400

    if not valid_mobile_or_passport(
        phone
    ):
        return render_template(
            "index.html",
            portal_token=token,
            name=name,
            phone=phone,
            error=(
                "Please enter a valid mobile "
                "number or passport number."
            )
        ), 400

    now = utcnow()

    expires = (
        now
        + timedelta(
            minutes=AUTH_MINUTES
        )
    )

    conn = None

    try:
        conn = get_db()

        cursor = conn.execute("""
            INSERT INTO guests (
                name,
                phone,
                client_mac,
                ap_mac,
                ssid,
                site,
                original_url,
                remote_ip,
                created_at,
                authorized,
                authorized_at,
                expires_at,
                auth_error,
                registration_state
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                0, NULL, NULL, NULL, 'pending'
            )
        """, (
            name,
            phone,
            client_mac,
            ap_mac,
            ssid,
            site,
            original_url,
            client_ip(),
            now.isoformat()
        ))

        guest_id = cursor.lastrowid
        conn.commit()

    except sqlite3.Error:
        if conn:
            conn.rollback()

        app.logger.exception(
            "Unable to create pending guest record"
        )

        return render_template(
            "index.html",
            portal_token=token,
            name=name,
            phone=phone,
            error=(
                "Unable to save this registration. "
                "Please try again."
            )
        ), 503

    finally:
        if conn:
            conn.close()

    ok, auth_error = authorize_guest(
        client_mac,
        site,
        AUTH_MINUTES
    )

    if not ok:
        cleanup_conn = None

        try:
            cleanup_conn = get_db()

            cleanup_conn.execute(
                "DELETE FROM guests WHERE id = ? "
                "AND registration_state = 'pending'",
                (guest_id,)
            )
            cleanup_conn.commit()

        except sqlite3.Error:
            if cleanup_conn:
                cleanup_conn.rollback()

            app.logger.exception(
                "Unable to remove failed pending "
                "guest record id=%s",
                guest_id
            )

        finally:
            if cleanup_conn:
                cleanup_conn.close()

        return render_template(
            "index.html",
            portal_token=token,
            name=name,
            phone=phone,
            error=(
                "Unable to enable network "
                "access. Please try again."
            )
        ), 503

    finalize_conn = None

    try:
        finalize_conn = get_db()

        cursor = finalize_conn.execute("""
            UPDATE guests
            SET authorized = 1,
                authorized_at = ?,
                expires_at = ?,
                auth_error = NULL,
                registration_state = 'complete'
            WHERE id = ?
              AND registration_state = 'pending'
        """, (
            now.isoformat(),
            expires.isoformat(),
            guest_id
        ))

        if cursor.rowcount != 1:
            raise sqlite3.DatabaseError(
                "Pending guest record was not finalized"
            )

        finalize_conn.commit()

    except sqlite3.Error:
        if finalize_conn:
            finalize_conn.rollback()

        compensated = unauthorize_guest(
            client_mac,
            site
        )

        app.logger.exception(
            "Unable to finalize guest record "
            "id=%s compensation_ok=%s",
            guest_id,
            compensated
        )

        recovery_conn = None

        try:
            recovery_conn = get_db()

            recovery_conn.execute("""
                UPDATE guests
                SET authorized = ?,
                    expires_at = ?,
                    auth_error = ?,
                    registration_state = 'failed'
                WHERE id = ?
            """, (
                0 if compensated else 1,
                (
                    utcnow().isoformat()
                    if compensated
                    else expires.isoformat()
                ),
                (
                    "Database finalization failed; "
                    "compensation "
                    + (
                        "succeeded"
                        if compensated
                        else "failed"
                    )
                ),
                guest_id
            ))
            recovery_conn.commit()

        except sqlite3.Error:
            if recovery_conn:
                recovery_conn.rollback()

            app.logger.exception(
                "Unable to record failed guest "
                "finalization id=%s",
                guest_id
            )

        finally:
            if recovery_conn:
                recovery_conn.close()

        return render_template(
            "index.html",
            portal_token=token,
            name=name,
            phone=phone,
            error=(
                "Unable to complete network "
                "access. Please try again."
            )
        ), 503

    finally:
        if finalize_conn:
            finalize_conn.close()

    return portal_success(
        name,
        safe_redirect_url(
            original_url
        ),
        returning=False
    )


@app.route(
    "/guest/s/<site>/",
    methods=[
        "GET",
        "POST",
        "HEAD"
    ]
)
def guest_portal(site):
    return handle_portal(site)


@app.route("/")
def root():
    return (
        "UniFi Guest WiFi Portal is running.",
        200
    )


@app.route("/health")
def health():
    return {
        "status": "ok"
    }


@app.route("/admin")
def admin():
    if not check_admin():
        return unauthorized()

    conn = get_db()

    rows = conn.execute("""
        SELECT *
        FROM guests
        ORDER BY id DESC
        LIMIT 500
    """).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        rows=rows
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000
    )
