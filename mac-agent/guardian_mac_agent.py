#!/usr/bin/env python3
"""
Guardian Mac Agent v2.0
Wipe method: Full erase + reinstall macOS (Option A)
Runs as a LaunchDaemon (root). Survives login/logout.
"""

import json, os, sys, time, subprocess, threading, logging, platform
import paho.mqtt.client as mqtt

MQTT_BROKER   = os.getenv("GUARDIAN_BROKER", "YOUR_VPS_IP")
MQTT_PORT     = int(os.getenv("GUARDIAN_PORT", 1883))
MQTT_USER     = os.getenv("GUARDIAN_MQTT_USER", "guardian")
MQTT_PASS     = os.getenv("GUARDIAN_MQTT_PASS", "changeme")
DEVICE_ID     = os.getenv("GUARDIAN_DEVICE_ID", f"mac-{platform.node()}")
ABORT_WINDOW  = int(os.getenv("GUARDIAN_ABORT_WINDOW", 30))

LOG_FILE = "/var/log/guardian_mac.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("guardian-mac")

client = mqtt.Client(client_id=f"guardian-mac-{DEVICE_ID}", clean_session=False)
client.username_pw_set(MQTT_USER, MQTT_PASS)

def get_location():
    try:
        result = subprocess.run(
            ["python3", "-c",
             "import urllib.request,json; d=json.loads(urllib.request.urlopen('https://ipapi.co/json/',timeout=5).read()); print(d.get('latitude',0),d.get('longitude',0),d.get('city',''),d.get('org',''))"],
            capture_output=True, text=True, timeout=10
        )
        parts = result.stdout.strip().split()
        if len(parts) >= 2:
            return {"lat": float(parts[0]), "lon": float(parts[1]),
                    "city": parts[2] if len(parts)>2 else "", "method": "ip"}
    except Exception as e:
        log.warning(f"Location: {e}")
    return {"lat": 0, "lon": 0, "method": "unknown"}

def send_location():
    loc = get_location()
    client.publish(f"guardian/{DEVICE_ID}/location",
                   json.dumps({**loc, "device_id": DEVICE_ID, "ts": time.time()}), qos=1)
    log.info(f"Location: {loc}")

def location_burst(count=5, interval=2.0):
    log.info(f"Location burst x{count}")
    for _ in range(count):
        send_location()
        time.sleep(interval)

def wipe_mac():
    log.warning("WIPE — Option A: eraseinstall")
    client.publish(f"guardian/{DEVICE_ID}/ack",
                   json.dumps({"command": "wipe_complete", "status": "initiating", "ts": time.time()}), qos=1)
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
            log.warning(f"Using: {installer}")
            subprocess.Popen([installer, "--eraseinstall", "--rebootdelay", "0",
                              "--agreetolicense", "--nointeraction"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
    log.warning("Installer not found — nvram recovery reboot")
    subprocess.run(["nvram", "internet-recovery-mode=RecoveryModeDisk"], check=False)
    subprocess.run(["reboot", "-n"], check=False)

def show_abort_window(seconds):
    script = f'tell application "System Events" to set r to button returned of (display dialog "\u26a0\ufe0f Guardian Wipe in {seconds}s\\nClick Abort to cancel." buttons {{"Abort"}} default button "Abort" with title "Guardian Security" giving up after {seconds})'
    try:
        result = subprocess.run(["osascript", "-e", script],
                                capture_output=True, text=True, timeout=seconds+5)
        return "abort" in result.stdout.lower()
    except Exception as e:
        log.warning(f"Abort dialog: {e}")
    return False

def handle_command(payload):
    command   = payload.get("command")
    issued_at = payload.get("issued_at", 0)
    ttl       = payload.get("ttl", 300)
    age = time.time() - issued_at
    if age > ttl:
        log.warning(f"Command '{command}' expired ({age:.0f}s > {ttl}s). Ignored.")
        return
    log.info(f"Command: {command} (age={age:.1f}s)")
    if command == "ping":
        client.publish(f"guardian/{DEVICE_ID}/ack",
                       json.dumps({"command": "ping", "status": "pong", "ts": time.time()}), qos=1)
    elif command == "status":  send_status()
    elif command == "location": send_location()
    elif command == "location_burst":
        threading.Thread(target=location_burst, daemon=True).start()
    elif command == "lock":
        subprocess.run(["/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-suspend"], check=False)
        client.publish(f"guardian/{DEVICE_ID}/ack",
                       json.dumps({"command": "lock", "status": "ok", "ts": time.time()}), qos=1)
    elif command == "wipe":
        def do_wipe():
            if show_abort_window(ABORT_WINDOW):
                client.publish(f"guardian/{DEVICE_ID}/ack",
                               json.dumps({"command": "wipe_complete", "status": "aborted_locally", "ts": time.time()}), qos=1)
                return
            location_burst(count=5, interval=1.5)
            wipe_mac()
        threading.Thread(target=do_wipe, daemon=True).start()

def send_status():
    client.publish(f"guardian/{DEVICE_ID}/status", json.dumps({
        "device_id": DEVICE_ID, "platform": "mac",
        "os_version": platform.mac_ver()[0], "hostname": platform.node(),
        "agent_version": "2.0.0", "ts": time.time(),
    }), qos=1, retain=True)

client.on_connect    = lambda c,u,f,rc: (log.info(f"MQTT rc={rc}"), c.subscribe(f"guardian/{DEVICE_ID}/command", qos=1), send_status())
client.on_message    = lambda c,u,msg: threading.Thread(target=handle_command, args=(json.loads(msg.payload.decode()),), daemon=True).start()
client.on_disconnect = lambda c,u,rc: log.warning(f"Disconnected rc={rc}")

def heartbeat():
    while True:
        try: send_status()
        except: pass
        time.sleep(60)

if __name__ == "__main__":
    log.info(f"Guardian Mac Agent v2.0 — {DEVICE_ID}")
    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    threading.Thread(target=heartbeat, daemon=True).start()
    client.loop_forever(retry_first_connection=True)
