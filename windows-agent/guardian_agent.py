"""
Guardian Windows Agent — v1
Install: pip install paho-mqtt psutil requests
Run: python guardian_agent.py
Auto-start: run install_startup.bat as Administrator
"""

import sys, os, json, time, threading, subprocess, socket, platform
import paho.mqtt.client as mqtt
import psutil

# ── CONFIG — FILL THESE IN ───────────────────────────────────────────────────────
RELAY_IP    = "10.99.0.1"
MQTT_PORT   = 1883
MQTT_USER   = "guardian"
MQTT_PASS   = "REPLACE_WITH_MQTT_PASS"
DEVICE_ID   = "laptop-01"
DEVICE_NAME = "My Laptop"
BACKUP_PATH = r"C:\GuardianBackup"

# ── ABORT STATE ──────────────────────────────────────────────────────────────────
_wipe_abort = threading.Event()

# ── MQTT CLIENT — FIX: clean_session=False so commands survive offline periods ──
client = mqtt.Client(client_id=DEVICE_ID, clean_session=False)
client.username_pw_set(MQTT_USER, MQTT_PASS)

def send_heartbeat():
    payload = json.dumps({
        "device_id": DEVICE_ID, "name": DEVICE_NAME, "type": "windows",
        "wg_ip": "10.99.0.3", "battery": get_battery(),
        "hostname": socket.gethostname(), "os": platform.version(),
    })
    client.publish("guardian/heartbeat", payload, qos=1)

def get_wifi_location():
    """Try Windows Location API first (20-100m accuracy), fall back to IP geolocation."""
    try:
        result = subprocess.run([
            "powershell", "-Command",
            """
            Add-Type -AssemblyName System.Device
            $watcher = New-Object System.Device.Location.GeoCoordinateWatcher([System.Device.Location.GeoPositionAccuracy]::High)
            $watcher.Start()
            $timeout = 0
            while ($watcher.Status -ne 'Ready' -and $timeout -lt 10) {
                Start-Sleep -Milliseconds 500
                $timeout++
            }
            $coord = $watcher.Position.Location
            $watcher.Stop()
            if ($coord.IsUnknown) { Write-Output 'UNKNOWN' }
            else { Write-Output "$($coord.Latitude),$($coord.Longitude),$($coord.HorizontalAccuracy)" }
            """
        ], capture_output=True, text=True, timeout=15)
        output = result.stdout.strip()
        if output and output != "UNKNOWN" and "," in output:
            parts = output.split(",")
            lat, lon, acc = float(parts[0]), float(parts[1]), float(parts[2])
            if lat != 0.0 and lon != 0.0:
                log(f"Location via Windows API: {lat:.4f}, {lon:.4f} acc={acc:.0f}m")
                return lat, lon, acc, "windows_location_api"
    except Exception as e:
        log(f"Windows Location API failed: {e}")
    return get_ip_location()

def get_ip_location():
    try:
        import requests
        r = requests.get("https://ipapi.co/json/", timeout=5).json()
        lat, lon = r.get("latitude"), r.get("longitude")
        if lat and lon:
            log(f"Location via IP: {lat}, {lon} (city-level only)")
            return lat, lon, 5000, "ip_geolocation"
    except Exception as e:
        log(f"IP location failed: {e}")
    return None, None, None, "failed"

def send_location():
    lat, lon, acc, method = get_wifi_location()
    if lat is None:
        log("Could not determine location")
        return
    payload = json.dumps({
        "device_id": DEVICE_ID, "lat": lat, "lon": lon,
        "accuracy": acc, "method": method,
    })
    client.publish("guardian/location", payload, qos=1)

def get_battery():
    try:
        b = psutil.sensors_battery()
        return b.percent if b else None
    except:
        return None

def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line)
    os.makedirs(r"C:\Guardian", exist_ok=True)
    with open(r"C:\Guardian\agent.log", "a") as f:
        f.write(line + "\n")

def handle_command(cmd: dict):
    action = cmd.get("action")
    log(f"Received command: {action}")
    if action == "locate":
        send_location()
    elif action == "lock":
        subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"])
    elif action == "backup":
        do_backup(cmd.get("backup_target"))
    elif action == "wipe":
        do_wipe_with_abort()
    elif action == "abort_wipe":
        log("ABORT signal received — cancelling any pending wipe")
        _wipe_abort.set()

def do_wipe_with_abort():
    """30-second abort window. Send abort_wipe command from dashboard to cancel."""
    _wipe_abort.clear()
    log("⚠️ WIPE COMMAND RECEIVED — 30 seconds to abort. Send abort_wipe to cancel.")
    for remaining in range(30, 0, -5):
        if _wipe_abort.is_set():
            log("✅ WIPE ABORTED successfully.")
            client.publish("guardian/status", json.dumps({
                "device_id": DEVICE_ID, "event": "wipe_aborted"
            }), qos=1)
            _wipe_abort.clear()
            return
        log(f"Wipe in {remaining}s — send abort_wipe to cancel")
        time.sleep(5)
    if _wipe_abort.is_set():
        log("✅ WIPE ABORTED in final window.")
        _wipe_abort.clear()
        return
    log("EXECUTING WIPE — no abort received")
    do_wipe()

def do_backup(target=None):
    import shutil
    user_profile = os.environ.get("USERPROFILE", r"C:\Users\Default")
    backup_id    = f"backup_{int(time.time())}"
    local_backup = os.path.join(BACKUP_PATH, backup_id)
    os.makedirs(local_backup, exist_ok=True)
    for folder in ["Desktop", "Documents", "Pictures", "Downloads"]:
        src = os.path.join(user_profile, folder)
        dst = os.path.join(local_backup, folder)
        if os.path.exists(src):
            try:
                # FIX: dirs_exist_ok=True prevents FileExistsError on repeat runs
                shutil.copytree(src, dst, dirs_exist_ok=True)
                log(f"Backed up {folder}")
            except Exception as e:
                log(f"Backup error {folder}: {e}")
    if target:
        try:
            shutil.copytree(local_backup, f"\\\\{target}\\GuardianBackup\\{backup_id}", dirs_exist_ok=True)
        except Exception as e:
            log(f"Remote backup error: {e}")
    client.publish("guardian/backup_complete", json.dumps({
        "device_id": DEVICE_ID, "backup_id": backup_id, "path": local_backup,
    }), qos=1)
    log(f"Backup complete: {backup_id}")

def do_wipe():
    log("EXECUTING WIPE")
    subprocess.run(["reagentc", "/disable"], capture_output=True)
    subprocess.run([
        "powershell", "-Command",
        "Reset-Computer -WipeData -WhatIf"  # REMOVE -WhatIf IN PRODUCTION after testing on spare device
    ], capture_output=True)

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        log("Connected to Guardian relay")
        client.subscribe(f"guardian/cmd/{DEVICE_ID}", qos=1)
        send_heartbeat()
        send_location()
    else:
        log(f"Connection failed rc={rc}")

def on_message(client, userdata, msg):
    try:
        cmd = json.loads(msg.payload.decode())
        threading.Thread(target=handle_command, args=(cmd,), daemon=True).start()
    except Exception as e:
        log(f"Command parse error: {e}")

def on_disconnect(client, userdata, rc):
    log(f"Disconnected rc={rc}, reconnecting in 15s...")
    time.sleep(15)
    try:
        client.reconnect()
    except:
        pass

client.on_connect    = on_connect
client.on_message    = on_message
client.on_disconnect = on_disconnect

def heartbeat_loop():
    while True:
        try:
            send_heartbeat()
            send_location()
        except Exception as e:
            log(f"Heartbeat error: {e}")
        time.sleep(30)

def run_agent():
    log(f"Guardian Windows Agent starting — Device: {DEVICE_ID} — Relay: {RELAY_IP}:{MQTT_PORT}")
    client.connect(RELAY_IP, MQTT_PORT, keepalive=60)
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    client.loop_forever()

if __name__ == "__main__":
    run_agent()