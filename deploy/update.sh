#!/usr/bin/env bash

set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/unifi-portal}"
ENV_FILE="${ENV_FILE:-/etc/unifi-portal.env}"
REPOSITORY="${REPOSITORY:-yikkrrtykj/unifi-guest-portal}"
TARGET_COMMIT="${1:-main}"
RELEASE_DIR="$(mktemp -d /tmp/unifi-portal-release.XXXXXX)"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/unifi-portal-backups}"
BACKUP_DIR="${BACKUP_ROOT}/release-$(date +%Y%m%d-%H%M%S)"
DB_PATH="/opt/unifi-portal/portal.db"
DEPLOY_STARTED=0
PORTAL_WAS_ACTIVE=0
STAFF_WAS_ACTIVE=0
EXPIRY_TIMER_WAS_ACTIVE=0
EXPIRY_TIMER_WAS_ENABLED=0
EXPIRY_SERVICE_UNIT="/etc/systemd/system/unifi-portal-expiry.service"
EXPIRY_TIMER_UNIT="/etc/systemd/system/unifi-portal-expiry.timer"

FILES=(
    app.py
    expiry_disconnect.py
    staff_app.py
    rate_limit.py
    requirements.txt
    templates
    static
    deploy
)

cleanup() {
    rm -rf -- "$RELEASE_DIR"
}

service_was_active() {
    systemctl is-active --quiet "$1"
}

wait_for_url() {
    local name="$1"
    local unit="$2"
    local url="$3"
    local attempt

    for attempt in $(seq 1 30); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            echo "$name: healthy"
            return 0
        fi

        echo "Waiting for $name: ${attempt}/30"
        sleep 1
    done

    systemctl status "$unit" --no-pager --full || true
    journalctl -u "$unit" -n 50 --no-pager || true
    return 1
}

restore_backup() {
    local item

    for item in "${FILES[@]}"; do
        rm -rf -- "$APP_DIR/$item"

        if [ -e "$BACKUP_DIR/application/$item" ]; then
            cp -a \
                "$BACKUP_DIR/application/$item" \
                "$APP_DIR/$item"
        fi
    done

    rm -f -- \
        "$DB_PATH" \
        "${DB_PATH}-wal" \
        "${DB_PATH}-shm"

    if [ -f "$BACKUP_DIR/portal.db" ]; then
        cp -a "$BACKUP_DIR/portal.db" "$DB_PATH"
    fi

    if [ -f "$BACKUP_DIR/deployed-commit" ]; then
        cp -a \
            "$BACKUP_DIR/deployed-commit" \
            "$APP_DIR/.deployed-commit"
    else
        rm -f -- "$APP_DIR/.deployed-commit"
    fi
}

restore_expiry_units() {
    systemctl disable --now \
        unifi-portal-expiry.timer \
        >/dev/null 2>&1 || true
    systemctl stop \
        unifi-portal-expiry.service \
        >/dev/null 2>&1 || true

    rm -f -- \
        "$EXPIRY_SERVICE_UNIT" \
        "$EXPIRY_TIMER_UNIT"

    if [ -f "$BACKUP_DIR/systemd/unifi-portal-expiry.service" ]; then
        cp -a \
            "$BACKUP_DIR/systemd/unifi-portal-expiry.service" \
            "$EXPIRY_SERVICE_UNIT"
    fi

    if [ -f "$BACKUP_DIR/systemd/unifi-portal-expiry.timer" ]; then
        cp -a \
            "$BACKUP_DIR/systemd/unifi-portal-expiry.timer" \
            "$EXPIRY_TIMER_UNIT"
    fi

    systemctl daemon-reload

    if [ "$EXPIRY_TIMER_WAS_ENABLED" -eq 1 ]; then
        systemctl enable \
            unifi-portal-expiry.timer \
            >/dev/null
    fi

    if [ "$EXPIRY_TIMER_WAS_ACTIVE" -eq 1 ]; then
        systemctl start \
            unifi-portal-expiry.timer
    fi
}

rollback_on_error() {
    local status=$?

    trap - ERR
    set +e

    echo
    echo "Deployment failed."

    if [ "$DEPLOY_STARTED" -eq 1 ]; then
        echo "Restoring the previous application and database..."
        systemctl stop \
            unifi-portal-expiry.timer \
            unifi-portal-expiry.service \
            2>/dev/null || true
        systemctl stop unifi-portal unifi-portal-staff 2>/dev/null || true
        restore_backup
        restore_expiry_units

        if [ "$PORTAL_WAS_ACTIVE" -eq 1 ]; then
            systemctl restart unifi-portal
        fi

        if [ "$STAFF_WAS_ACTIVE" -eq 1 ]; then
            systemctl restart unifi-portal-staff
        fi

        echo "Rollback completed."
    fi

    echo "The SSH session remains open."
    exit "$status"
}

trap cleanup EXIT
trap rollback_on_error ERR

if [ "${EUID}" -ne 0 ]; then
    echo "Run this script with sudo."
    exit 1
fi

case "$APP_DIR" in
    /*) ;;
    *)
        echo "APP_DIR must be an absolute path."
        exit 1
        ;;
esac

if [ "$APP_DIR" = "/" ] || [ "$APP_DIR" = "/opt" ]; then
    echo "APP_DIR is too broad; deployment stopped."
    exit 1
fi

case "$BACKUP_ROOT" in
    /*) ;;
    *)
        echo "BACKUP_ROOT must be an absolute path."
        exit 1
        ;;
esac

if [ "$BACKUP_ROOT" = "/" ] || [ "$BACKUP_ROOT" = "/opt" ]; then
    echo "BACKUP_ROOT is too broad; deployment stopped."
    exit 1
fi

echo "=== Validate environment ==="

test -d "$APP_DIR"
test -x "$APP_DIR/venv/bin/python"
test -f "$ENV_FILE"

if service_was_active unifi-portal; then
    PORTAL_WAS_ACTIVE=1
fi

if service_was_active unifi-portal-staff; then
    STAFF_WAS_ACTIVE=1
fi

if service_was_active unifi-portal-expiry.timer; then
    EXPIRY_TIMER_WAS_ACTIVE=1
fi

if systemctl is-enabled --quiet unifi-portal-expiry.timer 2>/dev/null; then
    EXPIRY_TIMER_WAS_ENABLED=1
fi

if [ "$PORTAL_WAS_ACTIVE" -ne 1 ]; then
    echo "unifi-portal is not running; deployment stopped."
    exit 1
fi

DB_PATH="$(
    "$APP_DIR/venv/bin/python" - "$ENV_FILE" <<'PY'
import sys

path = "/opt/unifi-portal/portal.db"

with open(sys.argv[1], encoding="utf-8") as handle:
    for raw_line in handle:
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)

        if key.strip() == "PORTAL_DB_PATH":
            value = value.strip().strip("'\"").strip()

            if value:
                path = value

            break

print(path)
PY
)"

case "$DB_PATH" in
    /*) ;;
    *)
        echo "PORTAL_DB_PATH must be an absolute path."
        exit 1
        ;;
esac

test "$DB_PATH" != "/"

echo "Database: $DB_PATH"

echo "=== Download release ==="

mkdir -p "$RELEASE_DIR/source"

RESOLVED_COMMIT="$(
    curl -fsSL \
        "https://api.github.com/repos/${REPOSITORY}/commits/${TARGET_COMMIT}" \
        | "$APP_DIR/venv/bin/python" -c \
            'import json,sys; print(json.load(sys.stdin)["sha"])'
)"

test "$RESOLVED_COMMIT" != ""

curl -fsSL --retry 3 \
    --connect-timeout 10 \
    --max-time 60 \
    -o "$RELEASE_DIR/tree.json" \
    "https://api.github.com/repos/${REPOSITORY}/git/trees/${RESOLVED_COMMIT}?recursive=1"

"$APP_DIR/venv/bin/python" \
    - "$RELEASE_DIR/tree.json" \
    > "$RELEASE_DIR/manifest.txt" <<'PY'
import json
import pathlib
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    tree = json.load(handle)

if tree.get("truncated"):
    raise SystemExit("GitHub returned a truncated release manifest")

paths = []

for item in tree.get("tree", []):
    if item.get("type") != "blob":
        continue

    path = item.get("path", "")
    parts = pathlib.PurePosixPath(path).parts

    if not path or path.startswith("/") or ".." in parts:
        raise SystemExit("Unsafe release path returned by GitHub")

    paths.append(path)

if not paths:
    raise SystemExit("GitHub returned an empty release manifest")

for path in sorted(paths):
    print(path)
PY

while IFS= read -r path; do
    destination="$RELEASE_DIR/source/$path"
    mkdir -p "$(dirname "$destination")"

    curl -fsSL --retry 3 \
        --connect-timeout 10 \
        --max-time 60 \
        -o "$destination" \
        "https://raw.githubusercontent.com/${REPOSITORY}/${RESOLVED_COMMIT}/${path}"
done < "$RELEASE_DIR/manifest.txt"

for item in "${FILES[@]}" tests; do
    test -e "$RELEASE_DIR/source/$item"
done

echo "Release: $RESOLVED_COMMIT"

echo "=== Validate release ==="

systemd-analyze calendar \
    '*-*-* 00:01:00 Asia/Shanghai' \
    >/dev/null

"$APP_DIR/venv/bin/python" -m py_compile \
    "$RELEASE_DIR/source/app.py" \
    "$RELEASE_DIR/source/expiry_disconnect.py" \
    "$RELEASE_DIR/source/staff_app.py" \
    "$RELEASE_DIR/source/rate_limit.py" \
    "$RELEASE_DIR/source/tests/test_security.py" \
    "$RELEASE_DIR/source/tests/test_expiry_disconnect.py"

(
    cd "$RELEASE_DIR/source"
    "$APP_DIR/venv/bin/python" \
        -m unittest discover -s tests -q
)

nginx -t

echo "=== Prepare dependencies ==="

"$APP_DIR/venv/bin/python" -m pip install \
    --disable-pip-version-check \
    -r "$RELEASE_DIR/source/requirements.txt"

echo "=== Back up current release ==="

install -d -m 0700 \
    "$BACKUP_DIR/application" \
    "$BACKUP_DIR/systemd"

for item in "${FILES[@]}"; do
    if [ -e "$APP_DIR/$item" ]; then
        cp -a \
            "$APP_DIR/$item" \
            "$BACKUP_DIR/application/$item"
    fi
done

if [ -f "$APP_DIR/.deployed-commit" ]; then
    cp -a \
        "$APP_DIR/.deployed-commit" \
        "$BACKUP_DIR/deployed-commit"
fi

if [ -f "$DB_PATH" ]; then
    "$APP_DIR/venv/bin/python" \
        - "$DB_PATH" "$BACKUP_DIR/portal.db" <<'PY'
import sqlite3
import sys

source = sqlite3.connect(sys.argv[1], timeout=30)
backup = sqlite3.connect(sys.argv[2])

try:
    source.backup(backup)
finally:
    backup.close()
    source.close()
PY

    chmod 0600 "$BACKUP_DIR/portal.db"
fi

if [ -f "$EXPIRY_SERVICE_UNIT" ]; then
    cp -a \
        "$EXPIRY_SERVICE_UNIT" \
        "$BACKUP_DIR/systemd/unifi-portal-expiry.service"
fi

if [ -f "$EXPIRY_TIMER_UNIT" ]; then
    cp -a \
        "$EXPIRY_TIMER_UNIT" \
        "$BACKUP_DIR/systemd/unifi-portal-expiry.timer"
fi

echo "Backup: $BACKUP_DIR"
DEPLOY_STARTED=1

echo "=== Install release ==="

systemctl stop unifi-portal

if [ "$STAFF_WAS_ACTIVE" -eq 1 ]; then
    systemctl stop unifi-portal-staff
fi

for item in "${FILES[@]}"; do
    rm -rf -- "$APP_DIR/$item"
    cp -a \
        "$RELEASE_DIR/source/$item" \
        "$APP_DIR/$item"
done

printf '%s\n' "$RESOLVED_COMMIT" \
    > "$APP_DIR/.deployed-commit"

install -m 0644 \
    "$APP_DIR/deploy/unifi-portal-expiry.service" \
    "$EXPIRY_SERVICE_UNIT"

install -m 0644 \
    "$APP_DIR/deploy/unifi-portal-expiry.timer" \
    "$EXPIRY_TIMER_UNIT"

systemctl daemon-reload

echo "=== Start services ==="

systemctl restart unifi-portal

if [ "$STAFF_WAS_ACTIVE" -eq 1 ]; then
    systemctl restart unifi-portal-staff
fi

wait_for_url \
    "Guest Portal" \
    "unifi-portal" \
    "http://127.0.0.1:8000/health"

if [ "$STAFF_WAS_ACTIVE" -eq 1 ]; then
    wait_for_url \
        "Staff Portal" \
        "unifi-portal-staff" \
        "http://127.0.0.1:8001/staff/health"
fi

HTTP_CODE="$(
    curl -sS -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:8000/guest/s/default/?id=02%3A00%3A00%3A00%3A00%3A01"
)"

test "$HTTP_CODE" = "200"

echo "=== Enable expiry disconnect timer ==="

systemctl enable --now \
    unifi-portal-expiry.timer \
    >/dev/null

systemctl is-enabled --quiet \
    unifi-portal-expiry.timer
systemctl is-active --quiet \
    unifi-portal-expiry.timer

DEPLOY_STARTED=0

echo
echo "Deployment successful."
echo "Version: $RESOLVED_COMMIT"
echo "Backup: $BACKUP_DIR"
echo "unifi-portal: $(systemctl is-active unifi-portal)"

if [ "$STAFF_WAS_ACTIVE" -eq 1 ]; then
    echo "unifi-portal-staff: $(systemctl is-active unifi-portal-staff)"
fi

echo "unifi-portal-expiry.timer: $(systemctl is-active unifi-portal-expiry.timer)"
echo "Next expiry disconnect:"
systemctl list-timers \
    unifi-portal-expiry.timer \
    --no-pager

echo "The SSH session remains open."
