import importlib
import base64
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = str(
            Path(cls.temp_dir.name) / "portal-test.db"
        )

        os.environ.update({
            "PORTAL_DB_PATH": cls.db_path,
            "ADMIN_USER": "admin",
            "ADMIN_PASSWORD": "admin-password",
            "STAFF_USER": "staff",
            "STAFF_PASSWORD": "staff-password",
            "PORTAL_SECRET": "test-secret-for-automated-tests",
            "UNIFI_USERNAME": "unifi-user",
            "UNIFI_PASSWORD": "unifi-password",
            "STAFF_LOGIN_MAX_FAILURES": "5",
            "STAFF_LOGIN_WINDOW_SECONDS": "600",
            "STAFF_LOGIN_BLOCK_SECONDS": "900",
        })

        sys.path.insert(0, str(ROOT))
        cls.portal = importlib.import_module("app")
        cls.staff = importlib.import_module("staff_app")

    @classmethod
    def import_fails_without(cls, module_name, variable):
        script = (
            "import os, sys; "
            f"os.environ.pop({variable!r}, None); "
            f"import {module_name}"
        )
        env = os.environ.copy()
        env.pop(variable, None)

        import subprocess

        return subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM guests")
        conn.execute(
            """
                CREATE TABLE IF NOT EXISTS auth_rate_limits (
                    key_hash TEXT PRIMARY KEY,
                    failures INTEGER NOT NULL,
                    window_started REAL NOT NULL,
                    blocked_until REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """
        )
        conn.execute("DELETE FROM auth_rate_limits")
        conn.execute("DELETE FROM staff_actions")
        conn.commit()
        conn.close()

    def test_portal_fails_closed_without_admin_user(self):
        result = self.import_fails_without(
            "app",
            "ADMIN_USER",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "ADMIN_USER is not configured",
            result.stderr,
        )

    def test_portal_fails_closed_without_admin_password(self):
        result = self.import_fails_without(
            "app",
            "ADMIN_PASSWORD",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "ADMIN_PASSWORD is not configured",
            result.stderr,
        )

    def test_portal_rejects_non_positive_authorization_time(self):
        script = "import app"
        env = os.environ.copy()
        env["AUTH_MINUTES"] = "0"

        import subprocess

        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "AUTH_MINUTES must be a positive integer",
            result.stderr,
        )

    def test_staff_fails_closed_without_staff_user(self):
        result = self.import_fails_without(
            "staff_app",
            "STAFF_USER",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "STAFF_USER is not configured",
            result.stderr,
        )

    def test_staff_fails_closed_without_staff_password(self):
        result = self.import_fails_without(
            "staff_app",
            "STAFF_PASSWORD",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "STAFF_PASSWORD is not configured",
            result.stderr,
        )

    def portal_post(self, mac):
        token = self.portal.portal_payload(
            "default",
            mac,
            "",
            "Guest WiFi",
            "",
        )

        return self.portal.app.test_client().post(
            "/guest/s/default/",
            data={
                "portal_token": token,
                "name": "Test Guest",
                "phone": "T1234567",
            },
            environ_base={
                "REMOTE_ADDR": "192.0.2.10",
            },
        )

    def test_guest_form_does_not_request_access_code(self):
        response = self.portal.app.test_client().get(
            "/guest/s/default/"
            "?id=02%3A00%3A00%3A00%3A00%3A11"
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"Access Code", response.data)
        self.assertNotIn(b'name="access_code"', response.data)

    def test_staff_login_is_rate_limited(self):
        client = self.staff.app.test_client()

        for _ in range(4):
            response = client.post(
                "/staff/login",
                data={
                    "username": "staff",
                    "password": "wrong-password",
                },
                environ_base={
                    "REMOTE_ADDR": "192.0.2.20",
                },
            )
            self.assertEqual(response.status_code, 200)

        response = client.post(
            "/staff/login",
            data={
                "username": "staff",
                "password": "wrong-password",
            },
            environ_base={
                "REMOTE_ADDR": "192.0.2.20",
            },
        )

        self.assertEqual(response.status_code, 429)
        self.assertGreater(
            int(response.headers["Retry-After"]),
            0,
        )

    def test_successful_authorization_finalizes_pending_record(self):
        mac = "02:00:00:00:00:21"

        with mock.patch.object(
            self.portal,
            "authorize_guest",
            return_value=(True, None),
        ):
            response = self.portal_post(mac)

        self.assertEqual(response.status_code, 200)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            """
                SELECT authorized, registration_state
                FROM guests
                WHERE client_mac = ?
            """,
            (mac,),
        ).fetchone()
        conn.close()

        self.assertEqual(row, (1, "complete"))

    def test_database_initialization_is_concurrency_safe(self):
        errors = []

        def initialize():
            try:
                self.portal.init_db()
            except Exception as exc:
                errors.append(exc)

        workers = [
            threading.Thread(target=initialize)
            for _ in range(4)
        ]

        for worker in workers:
            worker.start()

        for worker in workers:
            worker.join()

        self.assertEqual(errors, [])

    def test_legacy_database_migrates_without_data_loss(self):
        legacy_path = str(
            Path(self.temp_dir.name) / "legacy.db"
        )
        conn = sqlite3.connect(legacy_path)
        conn.execute("""
            CREATE TABLE guests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                client_mac TEXT,
                ap_mac TEXT,
                ssid TEXT,
                site TEXT,
                original_url TEXT,
                remote_ip TEXT,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            INSERT INTO guests (
                name,
                phone,
                client_mac,
                created_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            "Existing Guest",
            "E1234567",
            "02:00:00:00:00:31",
            "2026-08-12T00:00:00+00:00",
        ))
        conn.commit()
        conn.close()

        portal_path = self.portal.DB_PATH
        staff_path = self.staff.DB_PATH

        try:
            self.portal.DB_PATH = legacy_path
            self.staff.DB_PATH = legacy_path
            self.portal.init_db()
            self.staff.init_db()

        finally:
            self.portal.DB_PATH = portal_path
            self.staff.DB_PATH = staff_path

        conn = sqlite3.connect(legacy_path)
        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(guests)"
            ).fetchall()
        }
        row = conn.execute(
            "SELECT name, phone FROM guests WHERE id = 1"
        ).fetchone()
        conn.close()

        self.assertEqual(
            row,
            ("Existing Guest", "E1234567"),
        )
        self.assertTrue({
            "authorized",
            "authorized_at",
            "expires_at",
            "auth_error",
            "registration_state",
            "revoked_at",
            "revoked_by",
        }.issubset(columns))

    def test_staff_service_can_initialize_an_empty_database(self):
        empty_path = str(
            Path(self.temp_dir.name) / "staff-first.db"
        )
        staff_path = self.staff.DB_PATH

        try:
            self.staff.DB_PATH = empty_path
            self.staff.init_db()

        finally:
            self.staff.DB_PATH = staff_path

        conn = sqlite3.connect(empty_path)
        tables = {
            row[0]
            for row in conn.execute(
                """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                """
            ).fetchall()
        }
        conn.close()

        self.assertIn("guests", tables)
        self.assertIn("staff_actions", tables)
        self.assertIn("auth_rate_limits", tables)

    def test_admin_basic_auth_is_rate_limited(self):
        client = self.portal.app.test_client()
        credentials = base64.b64encode(
            b"admin:wrong-password"
        ).decode("ascii")
        headers = {
            "Authorization": f"Basic {credentials}"
        }

        for _ in range(4):
            response = client.get(
                "/admin",
                headers=headers,
                environ_base={
                    "REMOTE_ADDR": "192.0.2.30",
                },
            )
            self.assertEqual(response.status_code, 401)

        response = client.get(
            "/admin",
            headers=headers,
            environ_base={
                "REMOTE_ADDR": "192.0.2.30",
            },
        )

        self.assertEqual(response.status_code, 429)
        self.assertGreater(
            int(response.headers["Retry-After"]),
            0,
        )

    def test_guest_responses_include_security_headers(self):
        response = self.portal.app.test_client().get(
            "/health"
        )

        self.assertEqual(
            response.headers["Cache-Control"],
            "no-store",
        )
        self.assertEqual(
            response.headers["X-Frame-Options"],
            "DENY",
        )
        self.assertEqual(
            response.headers["X-Content-Type-Options"],
            "nosniff",
        )

    def test_redirect_and_unifi_fields_are_bounded(self):
        self.assertEqual(
            self.portal.safe_site("../invalid"),
            self.portal.UNIFI_SITE,
        )
        self.assertEqual(
            len(self.portal.safe_ssid("x" * 500)),
            self.portal.MAX_SSID_LENGTH,
        )
        self.assertIsNone(
            self.portal.safe_redirect_url(
                "https://example.test/" + "x" * 3000
            )
        )
        self.assertEqual(
            self.portal.safe_optional_mac("not-a-mac"),
            "",
        )

    def test_duplicate_pending_registration_is_rejected(self):
        mac = "02:00:00:00:00:41"
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
                INSERT INTO guests (
                    name,
                    phone,
                    client_mac,
                    created_at,
                    authorized,
                    registration_state
                )
                VALUES (?, ?, ?, ?, 0, 'pending')
            """,
            (
                "Pending Guest",
                "P1234567",
                mac,
                self.portal.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        with mock.patch.object(
            self.portal,
            "authorize_guest",
        ) as authorize:
            response = self.portal_post(mac)

        self.assertEqual(response.status_code, 409)
        authorize.assert_not_called()

    def test_staff_guest_api_uses_server_side_pagination(self):
        now = self.portal.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path)

        for index in range(25):
            conn.execute(
                """
                    INSERT INTO guests (
                        name,
                        phone,
                        ssid,
                        created_at,
                        authorized,
                        registration_state
                    )
                    VALUES (?, ?, ?, ?, 0, 'complete')
                """,
                (
                    f"Paged Guest {index:02d}",
                    f"P12345{index:02d}",
                    "Guest WiFi",
                    now,
                ),
            )

        conn.commit()
        conn.close()

        client = self.staff.app.test_client()

        with client.session_transaction() as session:
            session["staff_user"] = "staff"

        response = client.get(
            "/staff/api/guests?page=2&page_size=10&q=Paged"
        )
        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["filtered_total"], 25)
        self.assertEqual(data["page"], 2)
        self.assertEqual(data["pages"], 3)
        self.assertEqual(len(data["guests"]), 10)

    def test_staff_dashboard_exposes_status_and_audit_sections(self):
        client = self.staff.app.test_client()

        with client.session_transaction() as session:
            session["staff_user"] = "staff"

        response = client.get("/staff/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"System Status", response.data)
        self.assertIn(b"Recent Staff Actions", response.data)

    def test_staff_actions_api_returns_audit_records(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
                INSERT INTO staff_actions (
                    guest_id,
                    action,
                    actor,
                    client_mac,
                    result,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                7,
                "force-reregister",
                "staff",
                "02:00:00:00:00:51",
                "Access revoked.",
                self.portal.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()

        client = self.staff.app.test_client()

        with client.session_transaction() as session:
            session["staff_user"] = "staff"

        response = client.get("/staff/api/actions")
        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["total"], 1)
        self.assertEqual(
            data["actions"][0]["actor"],
            "staff",
        )

    def test_staff_status_api_checks_database_and_unifi(self):
        client = self.staff.app.test_client()

        with client.session_transaction() as session:
            session["staff_user"] = "staff"

        unifi = mock.Mock()

        with mock.patch.object(
            self.staff,
            "unifi_login",
            return_value=(unifi, None),
        ):
            response = client.get(
                "/staff/api/status",
                headers={
                    "X-Forwarded-Proto": "https",
                },
            )

        data = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["database"])
        self.assertTrue(data["unifi"])
        self.assertEqual(data["transport"], "https")
        unifi.close.assert_called_once_with()

    def test_failed_authorization_removes_pending_record(self):
        mac = "02:00:00:00:00:22"

        with mock.patch.object(
            self.portal,
            "authorize_guest",
            return_value=(False, "test failure"),
        ):
            response = self.portal_post(mac)

        self.assertEqual(response.status_code, 503)

        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM guests WHERE client_mac = ?",
            (mac,),
        ).fetchone()[0]
        conn.close()

        self.assertEqual(count, 0)

    def test_finalization_failure_revokes_authorization(self):
        mac = "02:00:00:00:00:23"
        real_get_db = self.portal.get_db
        calls = 0

        class FailingFinalizeConnection:
            def __init__(self, conn):
                self.conn = conn

            def execute(self, sql, parameters=()):
                if "UPDATE guests" in sql:
                    raise sqlite3.DatabaseError(
                        "injected finalization failure"
                    )

                return self.conn.execute(sql, parameters)

            def commit(self):
                return self.conn.commit()

            def rollback(self):
                return self.conn.rollback()

            def close(self):
                return self.conn.close()

        def get_db_with_failure():
            nonlocal calls
            calls += 1
            conn = real_get_db()

            if calls == 3:
                return FailingFinalizeConnection(conn)

            return conn

        with (
            mock.patch.object(
                self.portal,
                "authorize_guest",
                return_value=(True, None),
            ),
            mock.patch.object(
                self.portal,
                "unauthorize_guest",
                return_value=True,
            ) as revoke,
            mock.patch.object(
                self.portal,
                "get_db",
                side_effect=get_db_with_failure,
            ),
        ):
            response = self.portal_post(mac)

        self.assertEqual(response.status_code, 503)
        revoke.assert_called_once_with(mac, "default")

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            """
                SELECT authorized, registration_state
                FROM guests
                WHERE client_mac = ?
            """,
            (mac,),
        ).fetchone()
        conn.close()

        self.assertEqual(row, (0, "failed"))

    def test_failed_compensation_remains_visible_as_authorized(self):
        mac = "02:00:00:00:00:24"
        real_get_db = self.portal.get_db
        calls = 0

        class FailingFinalizeConnection:
            def __init__(self, conn):
                self.conn = conn

            def execute(self, sql, parameters=()):
                if "UPDATE guests" in sql:
                    raise sqlite3.DatabaseError(
                        "injected finalization failure"
                    )

                return self.conn.execute(sql, parameters)

            def commit(self):
                return self.conn.commit()

            def rollback(self):
                return self.conn.rollback()

            def close(self):
                return self.conn.close()

        def get_db_with_failure():
            nonlocal calls
            calls += 1
            conn = real_get_db()

            if calls == 3:
                return FailingFinalizeConnection(conn)

            return conn

        with (
            mock.patch.object(
                self.portal,
                "authorize_guest",
                return_value=(True, None),
            ),
            mock.patch.object(
                self.portal,
                "unauthorize_guest",
                return_value=False,
            ) as revoke,
            mock.patch.object(
                self.portal,
                "get_db",
                side_effect=get_db_with_failure,
            ),
        ):
            response = self.portal_post(mac)

        self.assertEqual(response.status_code, 503)
        revoke.assert_called_once_with(mac, "default")

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            """
                SELECT authorized,
                       registration_state,
                       auth_error
                FROM guests
                WHERE client_mac = ?
            """,
            (mac,),
        ).fetchone()
        conn.close()

        self.assertEqual(row[0], 1)
        self.assertEqual(row[1], "failed")
        self.assertIn("compensation failed", row[2])


if __name__ == "__main__":
    unittest.main()
