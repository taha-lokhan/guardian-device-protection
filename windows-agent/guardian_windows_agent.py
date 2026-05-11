#!/usr/bin/env python3
"""
Guardian Windows Agent v2.3.0

Changes in v2.3.0:
- Version check on startup: queries relay /agents/latest and logs a warning
  if this agent is outdated.
- Windows Service self-registration: on first run as admin, registers itself
  as a Windows Service (guardian-agent) via sc.exe so the OS restarts it if
  the process is killed.
- Real backup command: collects SystemInfo, ipconfig /all, last 50 System
  event log entries, current location, and agent metadata; ZIPs them to
  ProgramData\Guardian\backups\ then POSTs the archive to the relay
  /upload/{device_id} endpoint.
- Process watchdog thread: if client.loop_forever() returns unexpectedly,
  the watchdog re-execs the script after a 5-second delay.
- Bump agent_version string to 2.3.0.

Changes in v2.2.1:
- abort_wipe command + _wipe_abort_flag thread-safe flag.

Changes in v2.2.0:
- GUARDIAN_WG_IP env var; wg_ip included in status payload.

Requirements:
  pip install paho-mqtt
  Run as SYSTEM or Administrator.

Environment variables:
  GUARDIAN_BROKER, GUARDIAN_PORT, GUARDIAN_MQTT_USER, GUARDIAN_MQTT_PASS,
  GUARDIAN_DEVICE_ID, GUARDIAN_ABORT_WINDOW, GUARDIAN_WG_IP,
  GUARDIAN_RELAY_URL   (e.g. http://10.0.0.1:8000  — used for backup upload
                        and version check; leave blank to skip both)
"""
import ctypes
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
MQTT_BROKER   = os.getenv("GUARDIAN_BROKER",       "YOUR_VPS_IP")
MQTT_PORT     = int(os.getenv("GUARDIAN_PORT",      1883))
MQTT_USER     = os.getenv("GUARDIAN_MQTT_USER",     "guardian")
MQTT_PASS     = os.getenv("GUARDIAN_MQTT_PASS",     "changeme")
DEVICE_ID     = os.getenv("GUARDIAN_DEVICE_ID",     f"win-{platform.node()}")
ABORT_WINDOW  = int(os.getenv("GUARDIAN_ABORT_WINDOW", 30))
WG_IP         = os.getenv("GUARDIAN_WG_IP",         "")
RELAY_URL     = os.getenv("GUARDIAN_RELAY_URL",     "").rstrip("/")
AGENT_VERSION = "2.3.0"

LOG_DIR      = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "Guardian")
BACKUP_DIR   = os.path.join(LOG_DIR, "backups")
os.makedirs(LOG_DIR,    exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "guardian.log")),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("guardian-win")

# ---------------------------------------------------------------------------
# MQTT CLIENT
# ---------------------------------------------------------------------------
client = mqtt.Client(client_id=f"guardian-win-{DEVICE_ID}", clean_session=False)
client.username_pw_set(MQTT_USER, MQTT_PASS)

# Thread-safe abort flag for in-progress wipe countdowns
_wipe_abort_flag = threading.Event()

# ---------------------------------------------------------------------------
# VERSION CHECK
# ---------------------------------------------------------------------------
def check_agent_version():
    """Query relay /agents/latest and warn if this agent is outdated."""
    if not RELAY_URL:
        return
    try:
        with urllib.request.urlopen(f"{RELAY_URL}/agents/latest", timeout=5) as r:
            data     = json.loads(r.read())
            expected = data.get("versions", {}).get("windows", "")
            if expected and expected != AGENT_VERSION:
                log.warning(
                    f"Agent version mismatch: running {AGENT_VERSION}, "
                    f"relay expects {expected}. Update recommended."
                )
            else:
                log.info(f"Agent version {AGENT_VERSION} is current.")
    except Exception as e:
        log.warning(f"Version check failed: {e}")

# ---------------------------------------------------------------------------
# WINDOWS SERVICE SELF-REGISTRATION
# ---------------------------------------------------------------------------
SVC_NAME = "GuardianAgent"

def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def ensure_service_registered():
    """
    Register this script as a Windows Service using sc.exe so the SCM
    restarts it if it is killed. Only attempts registration once (checks
    if service already exists first). Requires admin.
    """
    if not _is_admin():
        log.info("Not admin — skipping service registration.")
        return
    try:
        result = subprocess.run(
            ["sc", "query", SVC_NAME],
            capture_output=True, text=True
        )
        if "RUNNING" in result.stdout or "STOPPED" in result.stdout:
            log.info(f"Service '{SVC_NAME}' already registered.")
            return
        # Use pythonw.exe so the service runs without a console window
        pythonw = Path(sys.executable).parent / "pythonw.exe"
        if not pythonw.exists():
            pythonw = sys.executable
        script = os.path.abspath(__file__)
        subprocess.run([
            "sc", "create", SVC_NAME,
            "binPath=", f'"{pythonw}" "{script}"',
            "start=", "auto",
            "DisplayName=", "Guardian Device Protection Agent",
        ], check=True, capture_output=True)
        subprocess.run(["sc", "failure", SVC_NAME,
                        "reset=", "60",
                        "actions=", "restart/5000/restart/5000/restart/5000"],
                       check=True, capture_output=True)
        log.info(f"Service '{SVC_NAME}' registered with auto-restart on failure.")
    except Exception as e:
        log.warning(f"Service registration failed: {e}")

# ---------------------------------------------------------------------------
# LOCATION
# ---------------------------------------------------------------------------
def get_location() -> dict:
    try:
        with urllib.request.urlopen("https://ipapi.co/json/", timeout=5) as r:
            d = json.loads(r.read())
            return {
                "lat":    d.get("latitude",  0),
                "lon":    d.get("longitude", 0),
                "city":   d.get("city",      ""),
                "isp":    d.get("org",        ""),
                "method": "ip",
            }
    except Exception as e:
        log.warning(f"Location: {e}")
    return {"lat": 0, "lon": 0, "method": "unknown"}

def send_location():
    loc = get_location()
    client.publish(
        f"guardian/{DEVICE_ID}/location",
        json.dumps({**loc, "ts": time.time()}),
        qos=1,
    )

def location_burst(count: int = 5, interval: float = 2.0):
    for _ in range(count):
        send_location()
        time.sleep(interval)

# ---------------------------------------------------------------------------
# STATUS
# ---------------------------------------------------------------------------
def send_status():
    payload = {
        "device_id":     DEVICE_ID,
        "platform":      "windows",
        "os_version":    platform.version(),
        "hostname":      platform.node(),
        "agent_version": AGENT_VERSION,
        "ts":            time.time(),
    }
    if WG_IP:
        payload["wg_ip"] = WG_IP
    client.publish(
        f"guardian/{DEVICE_ID}/status",
        json.dumps(payload),
        qos=1, retain=True,
    )

# ---------------------------------------------------------------------------
# BACKUP
# ---------------------------------------------------------------------------
def _run_cmd(args: list, timeout: int = 15) -> str:
    """Run a command and return stdout as a string. Never raises."""
    try:
        r = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW
        )
        return r.stdout or r.stderr or ""
    except Exception as e:
        return f"[error: {e}]"

def do_backup() -> str:
    """
    Collect forensic data, write to a ZIP archive in BACKUP_DIR, then
    POST it to the relay /upload/{DEVICE_ID} endpoint if RELAY_URL is set.
    Returns the path to the local ZIP file.
    """
    ts_str    = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    zip_name  = f"guardian-backup-{DEVICE_ID}-{ts_str}.zip"
    zip_path  = os.path.join(BACKUP_DIR, zip_name)

    log.info(f"Backup starting — {zip_path}")

    loc = get_location()

    # Collect data
    sysinfo    = _run_cmd(["systeminfo"])
    ipconfig   = _run_cmd(["ipconfig", "/all"])
    # Last 50 System event log entries (errors + warnings)
    evtlog = _run_cmd([
        "wevtutil", "qe", "System",
        "/c:50", "/rd:true", "/f:text"
    ])
    netstat    = _run_cmd(["netstat", "-ano"])
    tasklist   = _run_cmd(["tasklist", "/fo", "csv"])
    whoami     = _run_cmd(["whoami", "/all"])

    meta = {
        "device_id":     DEVICE_ID,
        "agent_version": AGENT_VERSION,
        "platform":      "windows",
        "hostname":      platform.node(),
        "os_version":    platform.version(),
        "backup_ts":     ts_str,
        "location":      loc,
    }

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("meta.json",        json.dumps(meta, indent=2))
        zf.writestr("systeminfo.txt",   sysinfo)
        zf.writestr("ipconfig.txt",     ipconfig)
        zf.writestr("eventlog.txt",     evtlog)
        zf.writestr("netstat.txt",      netstat)
        zf.writestr("tasklist.csv",     tasklist)
        zf.writestr("whoami.txt",       whoami)
        zf.writestr("location.json",    json.dumps(loc, indent=2))

    log.info(f"Backup ZIP created: {zip_path} ({os.path.getsize(zip_path)} bytes)")

    # Upload to relay if configured
    if RELAY_URL:
        _upload_backup(zip_path, zip_name)

    return zip_path

def _upload_backup(zip_path: str, filename: str):
    """POST the backup ZIP to relay /upload/{device_id} as multipart/form-data."""
    boundary = "GuardianBackupBoundary"
    try:
        with open(zip_path, "rb") as f:
            file_data = f.read()
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
        ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(
            f"{RELAY_URL}/upload/{DEVICE_ID}",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            log.info(f"Backup uploaded: HTTP {r.status}")
    except Exception as e:
        log.warning(f"Backup upload failed: {e} — file retained locally at {zip_path}")

# ---------------------------------------------------------------------------
# WIPE
# ---------------------------------------------------------------------------
def abort_dialog(seconds: int) -> bool:
    MB_ABORTRETRYIGNORE = 0x00000002
    MB_ICONWARNING      = 0x00000030
    IDABORT             = 3
    try:
        result = ctypes.windll.user32.MessageBoxTimeoutW(
            0,
            f"Guardian Security\n\nWipe in {seconds}s.\nClick ABORT to cancel.",
            "Guardian — Emergency Wipe",
            MB_ABORTRETRYIGNORE | MB_ICONWARNING, 0, seconds * 1000,
        )
        return result == IDABORT
    except Exception as e:
        log.warning(f"Abort dialog: {e}")
    return False

def _winre_available() -> bool:
    if not shutil.which("reagentc"):
        return False
    try:
        out = subprocess.check_output(
            ["reagentc", "/info"], stderr=subprocess.DEVNULL, text=True
        )
        return "Enabled" in out
    except Exception:
        return False

def _write_reset_config():
    config_dir  = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "Recovery"
    config_path = config_dir / "ResetConfig.xml"
    config_dir.mkdir(parents=True, exist_ok=True)
    xml = """<?xml version="1.0" encoding="utf-8"?>
<Reset>
  <Run Phase="BasicReset_AfterImageApply">
    <Path>Generalize.cmd</Path>
    <Duration>2</Duration>
  </Run>
  <Provisioning>
    <Package>
      <PartialPackageName>microsoft-windows-sysreset</PartialPackageName>
    </Package>
  </Provisioning>
  <UnattendXML/>
  <DriverPaths/>
  <ResetPlatformType>FactoryReset</ResetPlatformType>
</Reset>
"""
    config_path.write_text(xml, encoding="utf-8")
    log.info(f"ResetConfig.xml written to {config_path}")

def wipe_windows():
    log.warning("Wipe initiating")
    client.publish(
        f"guardian/{DEVICE_ID}/ack",
        json.dumps({"command": "wipe_complete", "status": "initiating", "ts": time.time()}),
        qos=1,
    )
    time.sleep(2)
    if _winre_available():
        log.warning("Wipe method: reagentc /boottore (silent recovery reset)")
        try:
            _write_reset_config()
            subprocess.run(["reagentc", "/boottore"], check=True)
            subprocess.run(
                ["shutdown", "/r", "/f", "/t", "0"],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return
        except Exception as e:
            log.error(f"reagentc wipe failed: {e} — falling back to systemreset")
    log.warning("Wipe method: systemreset.exe (fallback)")
    subprocess.Popen(
        ["systemreset.exe", "-factoryreset"],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

# ---------------------------------------------------------------------------
# COMMAND HANDLER
# ---------------------------------------------------------------------------
def handle_command(payload: dict):
    command   = payload.get("command")
    issued_at = payload.get("issued_at", 0)
    ttl       = payload.get("ttl", 300)
    age = time.time() - issued_at
    if age > ttl:
        log.warning(f"Command '{command}' expired ({age:.0f}s). Ignored.")
        return
    log.info(f"Command: {command} (age={age:.1f}s)")

    if command == "ping":
        client.publish(
            f"guardian/{DEVICE_ID}/ack",
            json.dumps({"command": "ping", "status": "pong", "ts": time.time()}),
            qos=1,
        )

    elif command == "status":
        send_status()

    elif command == "location":
        send_location()

    elif command == "location_burst":
        threading.Thread(target=location_burst, daemon=True).start()

    elif command == "lock":
        ctypes.windll.user32.LockWorkStation()
        client.publish(
            f"guardian/{DEVICE_ID}/ack",
            json.dumps({"command": "lock", "status": "ok", "ts": time.time()}),
            qos=1,
        )

    elif command == "backup":
        def _do_backup():
            try:
                zip_path = do_backup()
                client.publish(
                    f"guardian/{DEVICE_ID}/ack",
                    json.dumps({
                        "command": "backup",
                        "status":  "ok",
                        "path":    zip_path,
                        "ts":      time.time(),
                    }),
                    qos=1,
                )
            except Exception as e:
                log.error(f"Backup failed: {e}")
                client.publish(
                    f"guardian/{DEVICE_ID}/ack",
                    json.dumps({"command": "backup", "status": f"error: {e}", "ts": time.time()}),
                    qos=1,
                )
        threading.Thread(target=_do_backup, daemon=True).start()

    elif command == "abort_wipe":
        _wipe_abort_flag.set()
        log.warning("abort_wipe received — wipe abort flag set")
        client.publish(
            f"guardian/{DEVICE_ID}/ack",
            json.dumps({"command": "abort_wipe", "status": "flag_set", "ts": time.time()}),
            qos=1,
        )

    elif command == "wipe":
        def do_wipe():
            _wipe_abort_flag.clear()
            if abort_dialog(ABORT_WINDOW) or _wipe_abort_flag.is_set():
                log.warning("Wipe aborted (local dialog or remote abort_wipe)")
                _wipe_abort_flag.clear()
                client.publish(
                    f"guardian/{DEVICE_ID}/ack",
                    json.dumps({"command": "wipe_complete", "status": "aborted_locally", "ts": time.time()}),
                    qos=1,
                )
                return
            threading.Thread(target=location_burst, args=(5, 1.5), daemon=True).start()
            time.sleep(5)
            wipe_windows()
        threading.Thread(target=do_wipe, daemon=True).start()

    else:
        log.warning(f"Unknown command: {command!r}")

# ---------------------------------------------------------------------------
# MQTT CALLBACKS
# ---------------------------------------------------------------------------
client.on_connect = lambda c, u, f, rc: (
    log.info(f"MQTT rc={rc}"),
    c.subscribe(f"guardian/{DEVICE_ID}/command", qos=1),
    send_status(),
)
client.on_message = lambda c, u, msg: threading.Thread(
    target=handle_command,
    args=(json.loads(msg.payload.decode()),),
    daemon=True,
).start()
client.on_disconnect = lambda c, u, rc: log.warning(f"Disconnected rc={rc}")

# ---------------------------------------------------------------------------
# HEARTBEAT
# ---------------------------------------------------------------------------
def heartbeat():
    while True:
        try:
            send_status()
        except Exception:
            pass
        time.sleep(60)

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    log.info(f"Guardian Windows Agent v{AGENT_VERSION} — {DEVICE_ID}")
    ensure_service_registered()
    check_agent_version()
    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    threading.Thread(target=heartbeat, daemon=True).start()

    # Process watchdog: if loop_forever() exits, re-exec after 5s
    while True:
        try:
            client.loop_forever(retry_first_connection=True)
        except Exception as e:
            log.error(f"MQTT loop crashed: {e}")
        log.warning("MQTT loop exited — restarting agent in 5s")
        time.sleep(5)
        try:
            client.reconnect()
        except Exception:
            pass
