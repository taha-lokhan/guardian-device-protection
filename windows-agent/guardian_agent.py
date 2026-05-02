"""
Guardian Windows Agent
Install: pip install paho-mqtt psutil requests
Run: python guardian_agent.py
Auto-start: run install_startup.bat as Administrator
"""

import sys, os, json, time, threading, subprocess, socket, platform
import paho.mqtt.client as mqtt
import psutil

# ── CONFIG — FILL THESE IN ──────────────────────────────────────────────────────
RELAY_IP    = "10.99.0.1"
MQTT_PORT   = 1883
MQTT_USER   = "guardian"
MQTT_PASS   = "REPLACE_WITH_MQTT_PASS"
DEVICE_ID   = "laptop-01"
DEVICE_NAME = "My Laptop"
BACKUP_PATH = r"C:\GuardianBackup"

client = mqtt.Client()
client.username_pw_set(MQTT_USER, MQTT_PASS)

def send_heartbeat():
    payload = json.dumps({
        "device_id": DEVICE_ID, "name": DEVICE_NAME, "type": "windows",
        "wg_ip": "10.99.0.3", "battery": get_battery(),
        "hostname": socket.gethostname(), "os": platform.version(),
    })
    client.publish("guardian/heartbeat", payload)

def send_location():
    try:
        import requests
        r = requests.get("https://ipapi.co/json/", timeout=5).json()
        payload = json.dumps({
            "device_id": DEVICE_ID, "lat": r.get("latitude"), "lon": r.get("longitude"),
            "accuracy": 5000, "method": "ip_geolocation",
            "city": r.get("city"), "country": r.get("country_name"),
        })
        client.publish("guardian/location", payload)
    except Exception as e:
        log(f"Location error: {e}")

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
        log("WIPE COMMAND — executing in 10 seconds. Kill this process NOW to abort.")
        time.sleep(10)
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
                shutil.copytree(src, dst)
                log(f"Backed up {folder}")
            except Exception as e:
                log(f"Backup error {folder}: {e}")
    if target:
        try:
            shutil.copytree(local_backup, f"\\\\{target}\\GuardianBackup\\{backup_id}")
        except Exception as e:
            log(f"Remote backup error: {e}")
    client.publish("guardian/backup_complete", json.dumps({
        "device_id": DEVICE_ID, "backup_id": backup_id, "path": local_backup,
    }))
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
        client.subscribe(f"guardian/cmd/{DEVICE_ID}")
        send_heartbeat()
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

def run_agent():
    log(f"Guardian Windows Agent starting — Device: {DEVICE_ID} — Relay: {RELAY_IP}:{MQTT_PORT}")
    client.connect(RELAY_IP, MQTT_PORT, keepalive=60)
    threading.Thread(target=lambda: [send_heartbeat() or send_location() or time.sleep(30) for _ in iter(int, 1)], daemon=True).start()
    client.loop_forever()

if __name__ == "__main__":
    run_agent()