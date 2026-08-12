# UniFi Guest Portal

External captive portal and guest access management for a self-hosted UniFi Network Server.

This project provides:

- Guest captive portal with an **Access Code**
- Guest **Name** collection
- **Mobile Number / Passport Number** collection
- Client MAC, AP MAC and SSID capture from UniFi redirect parameters
- Automatic guest authorization through the legacy self-hosted UniFi controller API
- Configurable authorization lifetime
- Third-party / police guest management dashboard
- Live dashboard refresh every 3 seconds
- Force re-registration action
- Staff login and action audit logging
- SQLite storage
- Nginx + Gunicorn + systemd deployment

> This project targets a traditional self-hosted UniFi Network Server such as `https://CONTROLLER_IP:8443`.

## Architecture

```text
Guest device
    |
    | UniFi captive portal redirect
    v
Nginx :80
    |
    +--> Guest portal   -> Gunicorn :8000 -> app.py
    |
    +--> /staff/        -> Gunicorn :8001 -> staff_app.py
                                |
                                +--> SQLite
                                +--> UniFi Network Server :8443
```

## Important security note

The repository intentionally does **not** contain any real usernames, passwords, access codes, secrets, guest records, phone numbers or passport numbers.

Do not commit:

- `/etc/unifi-portal.env`
- `portal.db`
- `portal.db-wal`
- `portal.db-shm`
- virtual environments
- logs

These are already covered by `.gitignore` where applicable.

Because the system can collect mobile or passport information, use HTTPS before production deployment and restrict the staff dashboard to trusted staff/police networks where possible.

## 1. Server requirements

Example platform:

- Ubuntu 24.04
- Python 3
- Nginx
- SQLite
- self-hosted UniFi Network Server

Install packages:

```bash
sudo apt update
sudo apt install -y nginx python3 python3-venv python3-pip sqlite3
```

Create application directory:

```bash
sudo mkdir -p /opt/unifi-portal
sudo chown -R $USER:$USER /opt/unifi-portal
```

Clone the repository:

```bash
git clone https://github.com/yikkrrtykj/unifi-guest-portal.git /opt/unifi-portal
cd /opt/unifi-portal
```

Create the Python environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 2. Environment configuration

Create the real runtime environment file:

```bash
sudo cp .env.example /etc/unifi-portal.env
sudo chmod 600 /etc/unifi-portal.env
sudo nano /etc/unifi-portal.env
```

Fill in every required blank value:

```ini
# Internal admin page (/admin)
ADMIN_USER=
ADMIN_PASSWORD=

# Third-party / police dashboard (/staff/)
STAFF_USER=
STAFF_PASSWORD=

# Code users enter on the guest portal
PORTAL_ACCESS_CODE=

# Random signing/session secret
PORTAL_SECRET=

# Self-hosted UniFi Network Server
UNIFI_URL=https://YOUR_UNIFI_CONTROLLER:8443
UNIFI_SITE=default
UNIFI_USERNAME=
UNIFI_PASSWORD=
UNIFI_VERIFY_TLS=false

# Guest authorization period in minutes
AUTH_MINUTES=480

# Leave false while testing with HTTP.
# Change to true after HTTPS is enabled.
STAFF_COOKIE_SECURE=false
```

Generate a strong `PORTAL_SECRET`:

```bash
openssl rand -hex 32
```

### Required values

You must fill in:

- `ADMIN_USER`
- `ADMIN_PASSWORD`
- `STAFF_USER`
- `STAFF_PASSWORD`
- `PORTAL_ACCESS_CODE`
- `PORTAL_SECRET`
- `UNIFI_URL`
- `UNIFI_USERNAME`
- `UNIFI_PASSWORD`

The UniFi credentials should preferably belong to a dedicated account used only by this portal.

## 3. UniFi configuration

On the guest SSID:

1. Set **Application** to `Hotspot`.
2. Set Hotspot Type to **Captive Portal**.
3. Configure the external portal server to point to the portal server IP or hostname.
4. Configure the portal server IP as **allowed before authorization**.
5. If desired, configure the same portal server IP as **restricted after authorization** so normal authorized guests cannot browse back to the portal/staff server.

Example:

```text
Portal server: 192.168.16.25

Allowed before authorization:
192.168.16.25/32

Restricted after authorization:
192.168.16.25/32
```

The portal receives UniFi redirect parameters such as:

```text
/guest/s/default/?id=CLIENT_MAC&ap=AP_MAC&ssid=SSID&url=ORIGINAL_URL
```

The user never needs to type a MAC address.

## 4. Nginx

Copy the supplied configuration:

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/unifi-portal
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/unifi-portal /etc/nginx/sites-enabled/unifi-portal
sudo nginx -t
sudo systemctl reload nginx
```

## 5. systemd services

Install the services:

```bash
sudo cp deploy/unifi-portal.service /etc/systemd/system/
sudo cp deploy/unifi-portal-staff.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now unifi-portal
sudo systemctl enable --now unifi-portal-staff
```

Check them:

```bash
systemctl status unifi-portal --no-pager
systemctl status unifi-portal-staff --no-pager
```

Health checks:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8001/staff/health
```

Expected result:

```json
{"status":"ok"}
```

## 6. Guest workflow

The intended guest flow is:

```text
Connect to open Hotspot SSID
        |
        v
UniFi opens captive portal
        |
        v
Access Code
Name
Mobile Number / Passport Number
        |
        v
Server validates input
        |
        v
Server uses the client MAC supplied by UniFi
        |
        v
UniFi authorize-guest
        |
        v
Internet access
```

The default authorization period is 480 minutes (8 hours).

During that active period, if the same MAC returns to the portal, the application can restore the remaining authorization instead of asking for another registration.

## 7. Input validation

### Name

Names:

- must contain at least one letter
- cannot be numbers only
- may contain letters, spaces, hyphen, apostrophe and period

Examples:

```text
John Smith      valid
O'Connor        valid
张三             valid
123456          invalid
```

### Mobile / Passport

Phone numbers:

- 7 to 15 actual digits
- common separators are supported

Examples:

```text
+65 9123 4567
13800138000
```

Passport values:

- 6 to 20 alphanumeric characters
- require at least one letter and at least one digit

Example:

```text
E12345678
```

## 8. Staff / police dashboard

Open:

```text
http://PORTAL_SERVER/staff/
```

Sign in with:

```ini
STAFF_USER=
STAFF_PASSWORD=
```

The dashboard shows:

- Name
- Mobile / Passport
- SSID
- Registration time
- Expiration time
- Current portal status
- Force Re-register action

The page automatically reloads guest data every 3 seconds without a browser refresh.

### Force Re-register

When staff chooses **Force Re-register**:

1. the server calls `unauthorize-guest`
2. the server attempts `kick-sta`
3. the server repeats revoke/kick after one second
4. active database registration for that MAC is marked revoked
5. the user must complete registration again once UniFi removes access

### Known self-hosted controller behavior

On some self-hosted UniFi Network Server versions, `unauthorize-guest` succeeds but `kick-sta` returns HTTP 400.

Example log:

```text
UNIFI_STA_COMMAND cmd=unauthorize-guest ... http=200 rc=ok ok=True
UNIFI_STA_COMMAND cmd=kick-sta ... http=400 rc=error ok=False
```

In that case, guest authorization is still revoked, but traffic may continue briefly until the controller/AP applies the new guest state. A delay of tens of seconds can occur.

Do not assume `kick-sta` works on every self-hosted controller version.

## 9. Logging and audit

Staff service logs include:

- successful staff logins
- failed staff logins
- force re-registration requests
- UniFi station command results
- force re-registration results

View live logs:

```bash
journalctl -u unifi-portal-staff -f
```

Example:

```text
STAFF_LOGIN_SUCCESS user=admin ip=192.168.x.x
FORCE_REREGISTER_REQUEST actor=admin guest_id=13 mac=xx:xx:xx:xx:xx:xx
UNIFI_STA_COMMAND cmd=unauthorize-guest ... rc=ok ok=True
FORCE_REREGISTER_RESULT ... ok=True
```

The SQLite database also stores staff actions in the `staff_actions` table.

Example audit query:

```bash
sqlite3 /opt/unifi-portal/portal.db \
'SELECT id,guest_id,action,actor,result,created_at FROM staff_actions ORDER BY id DESC LIMIT 20;'
```

## 10. Database

Runtime database:

```text
/opt/unifi-portal/portal.db
```

It is created automatically and must not be committed to Git.

Basic guest query:

```bash
sqlite3 /opt/unifi-portal/portal.db \
'SELECT id,name,phone,client_mac,ssid,authorized,expires_at FROM guests ORDER BY id DESC LIMIT 20;'
```

## 11. HTTPS for production

The initial examples use HTTP for testing.

Before production, especially when collecting mobile/passport data:

- use a DNS name for the portal
- enable HTTPS
- set `STAFF_COOKIE_SECURE=true`
- restrict `/staff/` to a trusted staff/police network where possible
- avoid exposing the staff dashboard to the guest VLAN

## 12. Service logs

Guest portal:

```bash
journalctl -u unifi-portal -f
```

Staff dashboard:

```bash
journalctl -u unifi-portal-staff -f
```

Nginx:

```bash
journalctl -u nginx -f
```

## Repository files

```text
.
├── app.py
├── staff_app.py
├── templates/
│   ├── index.html
│   ├── success.html
│   ├── error.html
│   ├── admin.html
│   ├── staff.html
│   └── staff_login.html
├── deploy/
│   ├── nginx.conf
│   ├── unifi-portal.service
│   └── unifi-portal-staff.service
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Current compatibility target

Developed and tested around:

- self-hosted UniFi Network Server
- controller access over port `8443`
- legacy controller login endpoint `/api/login`
- guest authorization endpoint `/api/s/{site}/cmd/stamgr`
- `authorize-guest`
- `unauthorize-guest`

The code does not use the newer UniFi OS Integrations API key flow.
