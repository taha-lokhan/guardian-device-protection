#!/usr/bin/env python3
"""
Guardian Mac Agent v2.2.1
Wipe method: Full erase + reinstall macOS (Option A)
Runs as a LaunchDaemon (root). Survives login/logout.

Changes in v2.2.1:
- Add 'abort_wipe' command handler: sets a thread-safe threading.Event flag
  that the running do_wipe() goroutine checks before calling wipe_mac(),
  allowing the relay/dashboard to remotely cancel a countdown in progress.

Changes in v2.2.0:
- Add WG_IP env var (GUARDIAN_WG_IP) and include wg_ip in status payload
  so the dashboard can display the WireGuard IP for this device

Changes in v2.1.0:
- fix: get_location() no longer spawns a subprocess-inside-python subprocess
- fix: lock command replaces hard-coded CGSession path (broken on macOS 13+ Ventura)
  with cascading fallback: pmset displaysleepnow -> osascript -> CGSession legacy
- fix: nvram fallback in wipe_mac() guarded with os.path.exists; Apple Silicon
  boot argument set via bless --nextonly --legacyboot as alternative path
"""
import json, os, sys, time, subprocess, threading, logging, platform
import urllib.request
import paho.mqtt.client as mqtt

MQTT_BROKER   = os.getenv("GUARDIAN_BROKER", "YOUR_VPS_IP")
MQTT_PORT     = int(os.getenv("GUARDIAN_PORT", 1883))
MQTT_USER     = os.getenv("GUARDIAN_MQTT_USER", "guardian")
MQTT_PASS     = os.getenv("GUARDIAN_MQTT_PASS", "changeme")
DEVICE_ID     = os.getenv("GUARDIAN_DEVICE_ID", f"mac-{platform.node()}")
ABORT_WINDOW  = int(os.getenv("GUARDIAN_ABORT_WINDOW", 30))
WG_IP         = os.getenv("GUARDIAN_WG_IP", "")   # WireGuard IP shown in dashboard

LOG_FILE = "/var/log/guardian_mac.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("guardian-mac")

client = mqtt.Client(client_id=f"guardian-mac-{DEVICE_ID}", clean_session=False)
client.username_pw_set(MQTT_USER, MQTT_PASS)

# Thread-safe flag: set to True by 'abort_wipe' command to cancel a running wipe.
_wipe_abort_flag = threading.Event()


def get_location() -> dict:
    try:
        with urllib.request.urlopen("https://ipapi.co/json/", timeout=7) as resp:
            data = json.loads(resp.read().decode())
        return {
            "lat":    data.get("latitude", 0),
            "lon":    data.get("longitude", 0),
            "city":   data.get("city", ""),
            "org":    data.get("org", ""),
            "method": "ip",
        }
    except Exception as e:
        log.warning(f"Location lookup failed: {e}")
    return {"lat": 0, "lon": 0, "method": "unknown"}


def send_location():
    loc = get_location()
    client.publish(
        f"guardian/{DEVICE_ID}/location",
        json.dumps({**loc, "device_id": DEVICE_ID, "ts": time.time()}),
        qos=1,
    )
    log.info(f"Location published: {loc}")


def location_burst(count: int = 5, interval: float = 2.0):
    log.info(f"Location burst x{count}")
    for _ in range(count):
        send_location()
        time.sleep(interval)


def lock_mac() -> bool:
    """
    Cascading fallback strategy (Ventura-safe):
      1. pmset displaysleepnow
      2. osascript screensaver
      3. CGSession -suspend (legacy, pre-Ventura)
    """
    r = subprocess.run(["pmset", "displaysleepnow"], capture_output=True)
    if r.returncode == 0:
        log.info("Lock: pmset displaysleepnow OK")
        return True

    script = ('tell application "System Events" to '
               'tell process "loginwindow" to '
               'key code 12 using {control down, command down}')
    r = subprocess.run(["osascript", "-e", script], capture_output=True)
    if r.returncode == 0:
        log.info("Lock: osascript OK")
        return True

    cgsession = ("/System/Library/CoreServices/Menu Extras/User.menu"
                 "/Contents/Resources/CGSession")
    if os.path.exists(cgsession):
        r = subprocess.run([cgsession, "-suspend"], capture_output=True)
        if r.returncode == 0:
            log.info("Lock: CGSession OK")
            return True

    log.error("Lock: all methods failed")
    return False


def wipe_mac():
    log.warning("WIPE -- Option A: eraseinstall")
    client.publish(
        f"guardian/{DEVICE_ID}/ack",
        json.dumps({"command": "wipe_complete", "status": "initiating", "ts": time.time()}),
        qos=1,
    )
    time.sleep(2)

    installers = [
        "/Applications/Install macOS Sequoia.app/Contents/Resources/startosinstall",
        "/Applications/Install macOS Sonoma.app/Contents/Resources/startosinstall",
        "/Applications/Install macOS Ventura.app/Contents/Resources/startosinstall",
        "/Applications/Install macOS Monterey.app/Contents/Resources/startosinstall",
        "/Applications/Install macOS Big Sur.app/Contents/Resources/startosinstall",
    ]
    for installer in installers:
        if os.path.exists(installer):
            log.warning(f"Using installer: {installer}")
            subprocess.Popen(
                [installer, "--eraseinstall", "--rebootdelay", "0",
                 "--agreetolicense", "--nointeraction"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return

    log.warning("Installer not found -- attempting recovery reboot")
    nvram = "/usr/sbin/nvram"
    if os.path.exists(nvram):
        subprocess.run([nvram, "internet-recovery-mode=RecoveryModeDisk"], check=False)
        subprocess.run(["reboot", "-n"], check=False)
    else:
        log.warning("nvram not found -- attempting bless recovery (Apple Silicon)")
        subprocess.run(
            ["bless", "--mount", "/", "--setBoot", "--nextonly", "--legacyboot"],
            check=False,
        )
        subprocess.run(["shutdown", "-r", "now"], check=False)


def show_abort_window(seconds: int) -> bool:
    script = (
        f'tell application "System Events" to '
        f'set r to button returned of (display dialog '
        f'"\u26a0\ufe0f Guardian Wipe in {seconds}s\\nClick Abort to cancel." '
        f'buttons {{"Abort"}} default button "Abort" '
        f'with title "Guardian Security" giving up after {seconds})'
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=seconds + 5,
        )
        return "abort" in result.stdout.lower()
    except Exception as e:
        log.warning(f"Abort dialog error: {e}")
    return False


def handle_command(payload: dict):
    command   = payload.get("command")
    issued_at = payload.get("issued_at", 0)
    ttl       = payload.get("ttl", 300)
    age = time.time() - issued_at
    if issued_at > 0 and age > ttl:
        log.warning(f"Command '{command}' expired ({age:.0f}s > {ttl}s). Ignored.")
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
        ok = lock_mac()
        client.publish(
            f"guardian/{DEVICE_ID}/ack",
            json.dumps({"command": "lock", "status": "ok" if ok else "failed", "ts": time.time()}),
            qos=1,
        )
    elif command == "abort_wipe":
        # Signal any running wipe countdown to cancel before execution.
        _wipe_abort_flag.set()
        log.warning("abort_wipe received — wipe abort flag set")
        client.publish(
            f"guardian/{DEVICE_ID}/ack",
            json.dumps({"command": "abort_wipe", "status": "flag_set", "ts": time.time()}),
            qos=1,
        )
    elif command == "wipe":
        def do_wipe():
            _wipe_abort_flag.clear()  # reset flag for this wipe attempt
            if show_abort_window(ABORT_WINDOW) or _wipe_abort_flag.is_set():
                log.warning("Wipe aborted (local dialog or remote abort_wipe)")
                _wipe_abort_flag.clear()
                client.publish(
                    f"guardian/{DEVICE_ID}/ack",
                    json.dumps({"command": "wipe_complete", "status": "aborted_locally", "ts": time.time()}),
                    qos=1,
                )
                return
            location_burst(count=5, interval=1.5)
            wipe_mac()
        threading.Thread(target=do_wipe, daemon=True).start()
    else:
        log.warning(f"Unknown command: {command!r}")


def send_status():
    payload = {
        "device_id":     DEVICE_ID,
        "platform":      "mac",
        "os_version":    platform.mac_ver()[0],
        "hostname":      platform.node(),
        "agent_version": "2.2.1",
        "ts":            time.time(),
    }
    if WG_IP:
        payload["wg_ip"] = WG_IP
    client.publish(
        f"guardian/{DEVICE_ID}/status",
        json.dumps(payload),
        qos=1, retain=True,
    )


client.on_connect    = lambda c, u, f, rc: (
    log.info(f"MQTT connected rc={rc}"),
    c.subscribe(f"guardian/{DEVICE_ID}/command", qos=1),
    send_status(),
)
client.on_message    = lambda c, u, msg: threading.Thread(
    target=handle_command,
    args=(json.loads(msg.payload.decode()),),
    daemon=True,
).start()
client.on_disconnect = lambda c, u, rc: log.warning(f"MQTT disconnected rc={rc}")


def heartbeat():
    while True:
        try:
            send_status()
        except Exception as e:
            log.warning(f"Heartbeat error: {e}")
        time.sleep(60)


if __name__ == "__main__":
    log.info(f"Guardian Mac Agent v2.2.1 -- {DEVICE_ID}")
    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    threading.Thread(target=heartbeat, daemon=True).start()
    client.loop_forever(retry_first_connection=True)
