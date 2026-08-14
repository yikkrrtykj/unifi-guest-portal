import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

import requests


DB_PATH = os.environ.get(
    "PORTAL_DB_PATH",
    "/opt/unifi-portal/portal.db",
)

UNIFI_URL = os.environ.get(
    "UNIFI_URL",
    "https://YOUR_UNIFI_CONTROLLER:8443",
).rstrip("/")

UNIFI_USERNAME = os.environ.get(
    "UNIFI_USERNAME",
    "",
)

UNIFI_PASSWORD = os.environ.get(
    "UNIFI_PASSWORD",
    "",
)

UNIFI_VERIFY_TLS = (
    os.environ.get(
        "UNIFI_VERIFY_TLS",
        "false",
    ).lower() == "true"
)

EXPIRY_DISCONNECT_LOOKBACK_HOURS = int(
    os.environ.get(
        "EXPIRY_DISCONNECT_LOOKBACK_HOURS",
        "24",
    )
)

MAC_RE = re.compile(
    r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$"
)

SITE_RE = re.compile(
    r"^[A-Za-z0-9_-]{1,64}$"
)

LOGGER = logging.getLogger(
    "unifi-portal-expiry"
)


class ControllerError(RuntimeError):
    pass


class UniFiController:
    def __init__(self):
        if not UNIFI_USERNAME:
            raise ControllerError(
                "UniFi username is not configured"
            )

        if not UNIFI_PASSWORD:
            raise ControllerError(
                "UniFi password is not configured"
            )

        self.session = requests.Session()
        self.session.verify = UNIFI_VERIFY_TLS

        # The controller is on the local network. A deployment
        # proxy must never receive controller credentials.
        self.session.trust_env = False

    def close(self):
        self.session.close()

    def request(
        self,
        method,
        path,
        *,
        retries=3,
        **kwargs,
    ):
        last_error = None

        for attempt in range(1, retries + 1):
            try:
                response = self.session.request(
                    method,
                    UNIFI_URL + path,
                    timeout=10,
                    **kwargs,
                )

                if response.ok:
                    return response

                last_error = ControllerError(
                    "UniFi request failed "
                    f"(HTTP {response.status_code})"
                )

            except requests.RequestException as exc:
                last_error = ControllerError(
                    "Unable to contact UniFi: "
                    f"{type(exc).__name__}"
                )

            if attempt < retries:
                time.sleep(2)

        raise last_error or ControllerError(
            "Unknown UniFi request failure"
        )

    @staticmethod
    def response_data(response):
        try:
            payload = response.json()

        except ValueError as exc:
            raise ControllerError(
                "Invalid response from UniFi"
            ) from exc

        if payload.get("meta", {}).get("rc") != "ok":
            raise ControllerError(
                "UniFi returned an API error"
            )

        return payload.get("data", [])

    def login(self):
        response = self.request(
            "POST",
            "/api/login",
            json={
                "username": UNIFI_USERNAME,
                "password": UNIFI_PASSWORD,
                "remember": False,
            },
        )
        self.response_data(response)

    def stations(self, site):
        if not SITE_RE.fullmatch(site):
            raise ControllerError(
                "Unsafe UniFi site identifier"
            )

        response = self.request(
            "GET",
            f"/api/s/{site}/stat/sta",
        )

        stations = {}

        for item in self.response_data(response):
            mac = str(
                item.get("mac", "")
            ).strip().lower()

            if MAC_RE.fullmatch(mac):
                stations[mac] = item

        return stations

    def command(self, site, command, mac):
        if not SITE_RE.fullmatch(site):
            raise ControllerError(
                "Unsafe UniFi site identifier"
            )

        if not MAC_RE.fullmatch(mac):
            raise ControllerError(
                "Unsafe client MAC address"
            )

        response = self.request(
            "POST",
            f"/api/s/{site}/cmd/stamgr",
            retries=1,
            json={
                "cmd": command,
                "mac": mac,
            },
        )
        self.response_data(response)


def utcnow():
    return datetime.now(timezone.utc)


def get_db(path):
    conn = sqlite3.connect(
        path,
        timeout=10,
    )
    conn.row_factory = sqlite3.Row

    return conn


def ensure_tracking_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS
            expiry_disconnects (
                guest_id INTEGER PRIMARY KEY,
                client_mac TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                outcome TEXT NOT NULL,
                detail TEXT
            )
    """)


def candidate_rows(conn, now, lookback_hours):
    cutoff = (
        now
        - timedelta(hours=lookback_hours)
    ).isoformat()

    return conn.execute("""
        WITH latest AS (
            SELECT lower(client_mac) AS mac,
                   MAX(id) AS guest_id
            FROM guests
            WHERE client_mac IS NOT NULL
              AND client_mac != ''
            GROUP BY lower(client_mac)
        )
        SELECT g.id,
               lower(g.client_mac) AS client_mac,
               COALESCE(NULLIF(g.site, ''), 'default') AS site,
               COALESCE(g.ssid, '') AS ssid,
               g.expires_at
        FROM latest
        JOIN guests AS g
          ON g.id = latest.guest_id
        LEFT JOIN expiry_disconnects AS d
          ON d.guest_id = g.id
        WHERE g.authorized = 1
          AND g.registration_state = 'complete'
          AND g.expires_at IS NOT NULL
          AND g.expires_at <= ?
          AND g.expires_at >= ?
          AND d.guest_id IS NULL
        ORDER BY g.id
    """, (
        now.isoformat(),
        cutoff,
    )).fetchall()


def find_candidates(db_path, now, lookback_hours):
    conn = get_db(db_path)

    try:
        ensure_tracking_table(conn)
        conn.commit()

        return [
            dict(row)
            for row in candidate_rows(
                conn,
                now,
                lookback_hours,
            )
        ]

    finally:
        conn.close()


def claim_candidates(db_path, now, lookback_hours):
    conn = get_db(db_path)
    claimed = []

    try:
        conn.execute("BEGIN IMMEDIATE")
        ensure_tracking_table(conn)

        for row in candidate_rows(
            conn,
            now,
            lookback_hours,
        ):
            cursor = conn.execute("""
                INSERT OR IGNORE INTO expiry_disconnects (
                    guest_id,
                    client_mac,
                    attempted_at,
                    outcome,
                    detail
                )
                VALUES (?, ?, ?, 'in-progress', NULL)
            """, (
                row["id"],
                row["client_mac"],
                now.isoformat(),
            ))

            if cursor.rowcount == 1:
                claimed.append(dict(row))

        conn.commit()
        return claimed

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def record_outcome(
    db_path,
    guest_id,
    outcome,
    detail=None,
):
    conn = get_db(db_path)

    try:
        conn.execute("""
            UPDATE expiry_disconnects
            SET outcome = ?,
                detail = ?
            WHERE guest_id = ?
        """, (
            outcome,
            detail,
            guest_id,
        ))
        conn.commit()

    finally:
        conn.close()


def station_decision(candidate, station):
    if station is None:
        return "offline", (
            "Client was not associated when checked"
        )

    expected_ssid = candidate["ssid"].strip()
    current_ssid = str(
        station.get("essid")
        or station.get("ssid")
        or ""
    ).strip()
    is_guest = station.get("is_guest")

    if is_guest is False:
        return "skipped-non-guest", (
            "Controller reports a non-guest client"
        )

    if (
        expected_ssid
        and current_ssid
        and expected_ssid != current_ssid
    ):
        return "skipped-ssid", (
            "Client is associated with another SSID"
        )

    if not (
        is_guest is True
        or (
            expected_ssid
            and current_ssid == expected_ssid
        )
    ):
        return "skipped-unverified", (
            "Guest association could not be verified"
        )

    return "disconnect", None


def disconnect_expired_guests(
    db_path=DB_PATH,
    now=None,
    lookback_hours=EXPIRY_DISCONNECT_LOOKBACK_HOURS,
    controller_factory=UniFiController,
):
    if lookback_hours < 1 or lookback_hours > 48:
        raise ValueError(
            "EXPIRY_DISCONNECT_LOOKBACK_HOURS "
            "must be between 1 and 48"
        )

    now = now or utcnow()
    candidates = find_candidates(
        db_path,
        now,
        lookback_hours,
    )

    summary = {
        "candidates": len(candidates),
        "disconnected": 0,
        "offline": 0,
        "skipped": 0,
        "failed": 0,
    }

    if not candidates:
        return summary

    controller = controller_factory()

    try:
        controller.login()

        stations_by_site = {}

        for site in sorted({
            row["site"]
            for row in candidates
        }):
            stations_by_site[site] = (
                controller.stations(site)
            )

        candidates = claim_candidates(
            db_path,
            now,
            lookback_hours,
        )
        summary["candidates"] = len(candidates)

        for candidate in candidates:
            guest_id = candidate["id"]
            mac = candidate["client_mac"]
            site = candidate["site"]
            station = (
                stations_by_site[site]
                .get(mac)
            )
            decision, detail = station_decision(
                candidate,
                station,
            )

            if decision == "offline":
                record_outcome(
                    db_path,
                    guest_id,
                    decision,
                    detail,
                )
                summary["offline"] += 1
                LOGGER.info(
                    "Expired guest offline mac=%s site=%s",
                    mac,
                    site,
                )
                continue

            if decision.startswith("skipped-"):
                record_outcome(
                    db_path,
                    guest_id,
                    decision,
                    detail,
                )
                summary["skipped"] += 1
                LOGGER.warning(
                    "Expired guest skipped mac=%s site=%s reason=%s",
                    mac,
                    site,
                    decision,
                )
                continue

            try:
                controller.command(
                    site,
                    "unauthorize-guest",
                    mac,
                )
                controller.command(
                    site,
                    "kick-sta",
                    mac,
                )

            except ControllerError as exc:
                record_outcome(
                    db_path,
                    guest_id,
                    "failed",
                    str(exc),
                )
                summary["failed"] += 1
                LOGGER.error(
                    "Expired guest disconnect failed "
                    "mac=%s site=%s error=%s",
                    mac,
                    site,
                    exc,
                )
                continue

            record_outcome(
                db_path,
                guest_id,
                "disconnected",
            )
            summary["disconnected"] += 1
            LOGGER.info(
                "Expired guest disconnected mac=%s site=%s",
                mac,
                site,
            )

        return summary

    finally:
        controller.close()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s %(levelname)s "
            "%(name)s %(message)s"
        ),
    )

    try:
        summary = disconnect_expired_guests()

    except Exception:
        LOGGER.exception(
            "Expiry disconnect run failed"
        )
        return 1

    LOGGER.info(
        "Expiry disconnect complete "
        "candidates=%d disconnected=%d "
        "offline=%d skipped=%d failed=%d",
        summary["candidates"],
        summary["disconnected"],
        summary["offline"],
        summary["skipped"],
        summary["failed"],
    )

    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
