#!/usr/bin/env python3
"""
Guardian Windows Agent v2.1
Command TTL, location burst, abort dialog, silent recovery-mode wipe.

Wipe method (v2.1):
  Uses reagentc /boottore + ResetConfig.xml to trigger a silent, unattended
  factory reset on next boot — the user cannot cancel this from the lock screen.
  Falls back to systemreset.exe -factoryreset if reagentc is not available
  (e.g. WinRE is disabled or older Windows versions).

Requirements:
  - Run as SYSTEM or Administrator
  - WinRE enabled (reagentc /info shows 'Enabled')
  - paho-mqtt: pip install paho-mqtt

Environment variables:
  GUARDIAN_BROKER, GUARDIAN_PORT, GUARDIAN_MQTT_USER, GUARDIAN_MQTT_PASS,
  GUARDIAN_DEVICE_ID, GUARDIAN_ABORT_WINDOW
"""
import json, os, sys, time, threading, subprocess, platform, ctypes, logging, shutil
from pathlib import Path
import paho.mqtt.client as mqtt
import urllib.request

MQTT_BROKER  = os.getenv("GUARDIAN_BROKER",      "YOUR_VPS_IP")
MQTT_PORT    = int(os.getenv("GUARDIAN_PORT",     1883))
MQTT_USER    = os.getenv("GUARDIAN_MQTT_USER",    "guardian")
MQTT_PASS    = os.getenv("GUARDIAN_MQTT_PASS",    "changeme")
DEVICE_ID    = os.getenv("GUARDIAN_DEVICE_ID",    f"win-{platform.node()}")
ABORT_WINDOW = int(os.getenv("GUARDIAN_ABORT_WINDOW", 30))

LOG_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "Guardian")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "guardian.log")),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("guardian-win")

client = mqtt.Client(client_id=f"guardian-win-{DEVICE_ID}", clean_session=False)
client.username_pw_set(MQTT_USER, MQTT_PASS)

def get_location():
    try:
        with urllib.request.urlopen("https://ipapi.co/json/", timeout=5) as r:
            d = json.loads(r.read())
            return {
                "lat":    d.get("latitude",  0),
                "lon":    d.get("longitude", 0),
                "city":   d.get("city",      ""),
                "isp":    d.get("org",        ""),
                # NOTE: IP geolocation only — inaccurate on VPNs/corporate networks.
                # GPS/Wi-Fi triangulation is not available on Windows agents.
                "method": "ip",
            }
    except Exception as e:
        log.warning(f"Location: {e}")
    return {"lat": 0, "lon": 0, "method": "unknown"}

def send_location():
    loc = get_location()
    client.publish(f"guardian/{DEVICE_ID}/location",
                   json.dumps({**loc, "ts": time.time()}), qos=1)

def location_burst(count=5, interval=2.0):
    for _ in range(count):
        send_location()
        time.sleep(interval)

def send_status():
    client.publish(f"guardian/{DEVICE_ID}/status", json.dumps({
        "device_id":     DEVICE_ID,
        "platform":      "windows",
        "os_version":    platform.version(),
        "hostname":      platform.node(),
        "agent_version": "2.1.0",
        "ts":            time.time(),
    }), qos=1, retain=True)

def abort_dialog(seconds):
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
    """Return True if Windows Recovery Environment is enabled and reagentc is present."""
    reagentc = shutil.which("reagentc")
    if not reagentc:
        return False
    try:
        out = subprocess.check_output(
            ["reagentc", "/info"], stderr=subprocess.DEVNULL, text=True
        )
        return "Enabled" in out
    except Exception:
        return False

def _write_reset_config():
    """
    Write a ResetConfig.xml that instructs WinRE to perform a fully unattended
     'Remove everything' reset without user interaction.

    Path: %SystemRoot%\\System32\\Recovery\\ResetConfig.xml
    This file is read by WinRE during the recovery boot.
    """
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
  <!-- Fully unattended: no user prompts during reset -->
  <ResetPlatformType>FactoryReset</ResetPlatformType>
</Reset>
"""
    config_path.write_text(xml, encoding="utf-8")
    log.info(f"ResetConfig.xml written to {config_path}")

def wipe_windows():
    """
    Attempt a silent, unattended wipe via WinRE (reagentc /boottore).
    This schedules a recovery-mode factory reset on next boot and immediately
    reboots the machine — the user cannot cancel from the lock screen.

    Falls back to systemreset.exe -factoryreset (cancellable GUI wizard) if
    WinRE is not available.
    """
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
            # Schedule WinRE to run on next boot
            subprocess.run(["reagentc", "/boottore"], check=True)
            # Immediate forced reboot — no user prompt
            subprocess.run(
                ["shutdown", "/r", "/f", "/t", "0"],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return
        except Exception as e:
            log.error(f"reagentc wipe failed: {e} — falling back to systemreset")

    # Fallback: GUI reset wizard (user may be able to cancel at keyboard)
    log.warning("Wipe method: systemreset.exe (fallback — cancellable by user at keyboard)")
    subprocess.Popen(
        ["systemreset.exe", "-factoryreset"],
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

def handle_command(payload):
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
    elif command == "wipe":
        def do_wipe():
            if abort_dialog(ABORT_WINDOW):
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

def heartbeat():
    while True:
        try:
            send_status()
        except Exception:
            pass
        time.sleep(60)

if __name__ == "__main__":
    log.info(f"Guardian Windows Agent v2.1 — {DEVICE_ID}")
    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    threading.Thread(target=heartbeat, daemon=True).start()
    client.loop_forever(retry_first_connection=True)
