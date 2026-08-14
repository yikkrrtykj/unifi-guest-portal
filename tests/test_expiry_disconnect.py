import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import expiry_disconnect


class FakeController:
    def __init__(self, stations=None):
        self.station_data = stations or {}
        self.commands = []
        self.logged_in = False
        self.closed = False

    def login(self):
        self.logged_in = True

    def stations(self, site):
        return self.station_data.get(site, {})

    def command(self, site, command, mac):
        self.commands.append((site, command, mac))

    def close(self):
        self.closed = True


class ExpiryDisconnectTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(
            Path(self.temp_dir.name) / "portal.db"
        )
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE guests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                client_mac TEXT,
                ssid TEXT,
                site TEXT,
                created_at TEXT NOT NULL,
                authorized INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT,
                registration_state TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

        self.now = datetime(
            2026,
            8,
            13,
            16,
            1,
            tzinfo=timezone.utc,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def add_guest(
        self,
        mac,
        expires_at,
        *,
        authorized=1,
        ssid="test",
        site="default",
        state="complete",
    ):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("""
            INSERT INTO guests (
                name,
                phone,
                client_mac,
                ssid,
                site,
                created_at,
                authorized,
                expires_at,
                registration_state
            )
            VALUES (
                'Guest',
                'P1234567',
                ?, ?, ?, ?, ?, ?, ?
            )
        """, (
            mac,
            ssid,
            site,
            self.now.isoformat(),
            authorized,
            expires_at,
            state,
        ))
        conn.commit()
        guest_id = cursor.lastrowid
        conn.close()

        return guest_id

    def outcome(self, guest_id):
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            """
                SELECT outcome
                FROM expiry_disconnects
                WHERE guest_id = ?
            """,
            (guest_id,),
        ).fetchone()
        conn.close()

        return row[0] if row else None

    def test_disconnects_verified_online_guest_once(self):
        mac = "02:00:00:00:00:61"
        guest_id = self.add_guest(
            mac,
            "2026-08-13T16:00:00+00:00",
        )
        controller = FakeController({
            "default": {
                mac: {
                    "mac": mac,
                    "is_guest": True,
                    "essid": "test",
                },
            },
        })

        summary = (
            expiry_disconnect
            .disconnect_expired_guests(
                db_path=self.db_path,
                now=self.now,
                controller_factory=lambda: controller,
            )
        )

        self.assertEqual(summary["disconnected"], 1)
        self.assertEqual(
            controller.commands,
            [
                (
                    "default",
                    "unauthorize-guest",
                    mac,
                ),
                (
                    "default",
                    "kick-sta",
                    mac,
                ),
            ],
        )
        self.assertEqual(
            self.outcome(guest_id),
            "disconnected",
        )

        second_controller = FakeController()
        second = (
            expiry_disconnect
            .disconnect_expired_guests(
                db_path=self.db_path,
                now=self.now,
                controller_factory=(
                    lambda: second_controller
                ),
            )
        )

        self.assertEqual(second["candidates"], 0)
        self.assertFalse(second_controller.logged_in)

    def test_does_not_disconnect_active_or_old_records(self):
        self.add_guest(
            "02:00:00:00:00:62",
            "2026-08-14T16:00:00+00:00",
        )
        self.add_guest(
            "02:00:00:00:00:63",
            "2026-08-11T16:00:00+00:00",
        )
        controller = FakeController()

        summary = (
            expiry_disconnect
            .disconnect_expired_guests(
                db_path=self.db_path,
                now=self.now,
                controller_factory=lambda: controller,
            )
        )

        self.assertEqual(summary["candidates"], 0)
        self.assertFalse(controller.logged_in)

    def test_latest_registration_controls_candidate(self):
        mac = "02:00:00:00:00:64"
        self.add_guest(
            mac,
            "2026-08-13T16:00:00+00:00",
        )
        self.add_guest(
            mac,
            "2026-08-14T16:00:00+00:00",
        )
        controller = FakeController()

        summary = (
            expiry_disconnect
            .disconnect_expired_guests(
                db_path=self.db_path,
                now=self.now,
                controller_factory=lambda: controller,
            )
        )

        self.assertEqual(summary["candidates"], 0)
        self.assertFalse(controller.logged_in)

    def test_newer_pending_registration_prevents_disconnect(self):
        mac = "02:00:00:00:00:67"
        self.add_guest(
            mac,
            "2026-08-13T16:00:00+00:00",
        )
        self.add_guest(
            mac,
            None,
            authorized=0,
            state="pending",
        )
        controller = FakeController()

        summary = (
            expiry_disconnect
            .disconnect_expired_guests(
                db_path=self.db_path,
                now=self.now,
                controller_factory=lambda: controller,
            )
        )

        self.assertEqual(summary["candidates"], 0)
        self.assertFalse(controller.logged_in)

    def test_offline_guest_is_not_kicked(self):
        guest_id = self.add_guest(
            "02:00:00:00:00:65",
            "2026-08-13T16:00:00+00:00",
        )
        controller = FakeController()

        summary = (
            expiry_disconnect
            .disconnect_expired_guests(
                db_path=self.db_path,
                now=self.now,
                controller_factory=lambda: controller,
            )
        )

        self.assertEqual(summary["offline"], 1)
        self.assertEqual(controller.commands, [])
        self.assertEqual(
            self.outcome(guest_id),
            "offline",
        )

    def test_other_ssid_is_not_kicked(self):
        mac = "02:00:00:00:00:66"
        guest_id = self.add_guest(
            mac,
            "2026-08-13T16:00:00+00:00",
        )
        controller = FakeController({
            "default": {
                mac: {
                    "mac": mac,
                    "is_guest": True,
                    "essid": "internal",
                },
            },
        })

        summary = (
            expiry_disconnect
            .disconnect_expired_guests(
                db_path=self.db_path,
                now=self.now,
                controller_factory=lambda: controller,
            )
        )

        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(controller.commands, [])
        self.assertEqual(
            self.outcome(guest_id),
            "skipped-ssid",
        )


if __name__ == "__main__":
    unittest.main()
