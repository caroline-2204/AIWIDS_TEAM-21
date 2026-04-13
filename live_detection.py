#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Live Detection
===============================================================================
Streams Wi-Fi packets from an OpenWrt router via SSH/tcpdump, runs ML
inference per packet, and serves a real-time Flask/SocketIO dashboard.

Detection methods (applied in priority order):
  1. SSID conflict  — same SSID broadcast from multiple BSSIDs (deterministic)
  2. ML model       — DNN classifies each packet as normal/evil_twin/deauth
  3. Mobile OUI     — locally-administered MAC indicates a mobile hotspot

Improvements over original:
  - 3-class model support (normal / evil_twin / deauth)
  - SSH reconnection with exponential back-off
  - Clean comments (design rationale, not line-by-line narration)
===============================================================================
"""

import json
import time
import threading
import subprocess
from collections import defaultdict, deque
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
from scapy.all import Dot11, Dot11Elt, PcapReader
from flask import Flask, render_template_string
from flask_socketio import SocketIO
import colorama
from colorama import Fore, Style, Back

colorama.init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────
OPENWRT_IP = "192.168.32.55"
INTERFACE = "phy0-mon0"
PRINT_INTERVAL = 2          # seconds between dashboard pushes
ALERT_HISTORY_LIMIT = 50
NET_HISTORY_LIMIT = 200
MAX_SSH_RETRIES = 10        # reconnection attempts before giving up

# ── Mobile OUI database ───────────────────────────────────────────────────────
# Locally-administered MAC prefixes common to mobile hotspots
MOBILE_OUIS = {
    "02:00:00", "06:00:00", "0a:00:00", "0e:00:00",
    "12:00:00", "16:00:00", "1a:00:00", "1e:00:00",
    "f6:55:a8", "ee:55:a8", "fa:c6:f7", "fe:55:a8",
    "f2:55:a8", "ea:55:a8", "e6:55:a8", "e2:55:a8",
    "92:74:fb", "a2:74:fb", "b2:74:fb", "c2:74:fb",
    "82:74:fb", "72:74:fb", "62:74:fb", "52:74:fb",
    "34:02:86", "44:4e:1a", "64:a2:f9", "78:f7:be",
    "ac:5f:3e", "e8:50:8b", "f8:d0:ac",
    "34:80:b3", "50:8f:4c", "74:23:44", "78:02:f8",
    "c4:0b:cb", "f8:a4:5f",
    "00:9a:cd", "18:31:bf", "20:47:ed", "54:25:ea",
    "a4:d5:78", "c8:85:50", "38:d5:7a", "ac:37:43",
    "f4:f5:24", "f8:cf:c5",
}


# ── Neural network (must match train_model.py architecture) ───────────────────
class WIDSDetector(nn.Module):
    """4-layer DNN: 128→64→32→NUM_CLASSES with dropout(0.3)."""

    def __init__(self, input_size: int, num_classes: int = 3):
        super().__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, num_classes)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.dropout(x)
        x = self.relu(self.fc3(x))
        return self.fc4(x)


# ── Global state ──────────────────────────────────────────────────────────────
class GlobalState:
    def __init__(self):
        self.ssid_map = defaultdict(set)          # ssid → set of BSSIDs
        self.bssid_to_ssid = {}
        self.packet_count = defaultdict(int)      # (ssid, bssid) → count
        self.alerts = deque(maxlen=ALERT_HISTORY_LIMIT)
        self.network_history = deque(maxlen=NET_HISTORY_LIMIT)
        self.net_confidence = defaultdict(float)  # ssid → highest evil prob seen
        self.net_class = defaultdict(int)         # ssid → predicted class (0/1/2)
        self.stats = {
            "total_packets": 0,
            "normal_packets": 0,
            "evil_twin_packets": 0,
            "deauth_packets": 0,
            "alerts_count": 0,
            "mobile_hotspots": 0,
            "unique_ssids": 0,
            "unique_bssids": 0,
            "conflict_ssids": 0,
        }
        self.lock = threading.Lock()
        self.last_update = time.time()


state = GlobalState()


# ── Helpers ───────────────────────────────────────────────────────────────────
def is_mobile(bssid: str) -> bool:
    """Return True if BSSID belongs to a mobile hotspot (OUI or randomised MAC)."""
    if not bssid or len(bssid) < 8:
        return False
    bssid = bssid.lower()
    if bssid[:8] in MOBILE_OUIS:
        return True
    try:
        # U/L bit set → locally administered → likely randomised mobile MAC
        if int(bssid[:2], 16) & 0x02:
            return True
    except ValueError:
        pass
    return bssid[1] in {"2", "6", "a", "e"}


def safe_decode_ssid(raw) -> str | None:
    if raw is None:
        return None
    try:
        ssid = raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
    except Exception:
        return None
    ssid = ssid.replace("\x00", "").strip()
    if not ssid or ssid == "UNKNOWN" or all(c == "\x00" for c in ssid):
        return None
    return ssid


def get_device_name(bssid: str) -> str:
    return "Mobile Hotspot" if is_mobile(bssid) else "Router/AP"


def extract_features(pkt, deauth_buf: deque, beacon_buf: deque) -> dict:
    """Extract the same feature set used during training."""
    features = {}
    features["frame_length"] = len(bytes(pkt))
    features["frame_type"] = pkt.type if pkt.haslayer(Dot11) else 0
    features["frame_subtype"] = pkt.subtype if pkt.haslayer(Dot11) else 0

    is_beacon = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8)
    is_deauth = int(pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12)
    features["is_mgmt"] = int(pkt.haslayer(Dot11) and pkt.type == 0)
    features["is_beacon"] = is_beacon
    features["is_deauth"] = is_deauth

    ssid = bssid = None
    if pkt.haslayer(Dot11):
        bssid = pkt.addr3 or pkt.addr2
        if is_beacon and pkt.haslayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                if getattr(elt, "ID", None) == 0:
                    ssid = safe_decode_ssid(getattr(elt, "info", None))
                    break
                elt = elt.payload.getlayer(Dot11Elt)

    features["ssid"] = ssid
    features["bssid"] = bssid

    deauth_buf.append(is_deauth)
    beacon_buf.append(is_beacon)
    features["deauth_rate"] = sum(deauth_buf) / max(1, len(deauth_buf)) * 10
    features["beacon_rate"] = sum(beacon_buf) / max(1, len(beacon_buf)) * 10
    return features


# ── SSH stream with reconnection ──────────────────────────────────────────────
def stream_packets(cmd: list):
    """
    Generator that yields Scapy packets from an SSH/tcpdump stream.
    On connection loss, retries with exponential back-off up to MAX_SSH_RETRIES.
    """
    retries = 0
    while retries < MAX_SSH_RETRIES:
        try:
            print(f"{Fore.CYAN}  Connecting to OpenWrt (attempt {retries + 1})...{Style.RESET_ALL}")
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            reader = PcapReader(proc.stdout)
            for pkt in reader:
                yield pkt
            proc.wait()
            # Clean EOF — router closed the connection
            retries += 1
        except Exception as e:
            retries += 1
            wait = min(2 ** retries, 60)
            print(f"{Fore.YELLOW}  Connection lost ({e}). Retry in {wait}s...{Style.RESET_ALL}")
            time.sleep(wait)

    print(f"{Fore.RED}  Max retries reached. Stopping capture.{Style.RESET_ALL}")


# ── Flask dashboard ───────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = "ai-wids-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>AI-WIDS Live Dashboard</title>
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:'Segoe UI',sans-serif; background:#0a0e27; color:#eee; }
        .header { background:linear-gradient(135deg,#667eea,#764ba2); padding:20px; text-align:center; }
        .header h1 { font-size:2em; margin-bottom:5px; }
        .live-dot { width:12px; height:12px; border-radius:50%; background:#2ed573;
                    display:inline-block; animation:pulse 2s infinite; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        .container { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
                     gap:20px; padding:20px; max-width:1400px; margin:0 auto; }
        .card { background:#1a1f3a; border-radius:10px; padding:20px;
                box-shadow:0 4px 6px rgba(0,0,0,.5); }
        .card h2 { color:#00d4ff; margin-bottom:15px; border-bottom:2px solid #00d4ff; padding-bottom:10px; }
        .stat-box { display:flex; justify-content:space-between; padding:12px;
                    background:#0f1729; border-radius:5px; margin:8px 0; }
        .stat-label { color:#aaa; }
        .stat-value { font-weight:bold; font-size:1.3em; }
        .alert { background:#ff4757; color:#fff; padding:12px; border-radius:5px; margin:8px 0; }
        .alert-mobile { background:#ffa502; }
        .alert-deauth  { background:#9b59b6; }
        #alerts-list { max-height:400px; overflow-y:auto; }
        table { width:100%; border-collapse:collapse; }
        th,td { padding:12px; text-align:left; border-bottom:1px solid #2c3e50; }
        th { background:#0f1729; color:#00d4ff; }
        tr:hover { background:#0f1729; }
        .type-evil-twin { color:#ff4757; font-weight:bold; }
        .type-deauth    { color:#9b59b6; font-weight:bold; }
        .type-mobile    { color:#ffa502; font-weight:bold; }
        .type-normal    { color:#2ed573; }
        .ts { color:#ddd; font-size:.85em; }
    </style>
</head>
<body>
<div class="header">
    <h1>🛡️ AI-WIDS Live Dashboard</h1>
    <p><span class="live-dot"></span> Real-time Wi-Fi Attack Detection</p>
</div>
<div class="container">
    <div class="card">
        <h2>📊 Statistics</h2>
        <div class="stat-box"><span class="stat-label">Total Packets</span>
            <span class="stat-value" id="total">0</span></div>
        <div class="stat-box"><span class="stat-label">Normal</span>
            <span class="stat-value" style="color:#2ed573" id="normal">0</span></div>
        <div class="stat-box"><span class="stat-label">Evil Twin</span>
            <span class="stat-value" style="color:#ff4757" id="evil">0</span></div>
        <div class="stat-box"><span class="stat-label">Deauth/DoS</span>
            <span class="stat-value" style="color:#9b59b6" id="deauth">0</span></div>
        <div class="stat-box"><span class="stat-label">Mobile Hotspots</span>
            <span class="stat-value" style="color:#ffa502" id="mobile">0</span></div>
        <div class="stat-box"><span class="stat-label">Alerts</span>
            <span class="stat-value" style="color:#ff6348" id="alerts">0</span></div>
        <div class="stat-box"><span class="stat-label">Conflict SSIDs</span>
            <span class="stat-value" style="color:#ff9f43" id="conflicts">0</span></div>
    </div>
    <div class="card">
        <h2>🚨 Recent Alerts</h2>
        <div id="alerts-list"></div>
    </div>
    <div class="card" style="grid-column:span 2">
        <h2>🌐 Detected Networks</h2>
        <table>
            <thead><tr>
                <th>SSID</th><th>Packets</th><th>BSSIDs</th>
                <th>Type</th><th>Confidence (%)</th>
            </tr></thead>
            <tbody id="networks"></tbody>
        </table>
    </div>
</div>
<script>
const socket = io();
let lastStats={}, lastNetworks=[], lastRefresh=Date.now();

function renderStats(d) {
    document.getElementById('total').textContent   = d.total_packets    ?? 0;
    document.getElementById('normal').textContent  = d.normal_packets   ?? 0;
    document.getElementById('evil').textContent    = d.evil_twin_packets ?? 0;
    document.getElementById('deauth').textContent  = d.deauth_packets   ?? 0;
    document.getElementById('mobile').textContent  = d.mobile_hotspots  ?? 0;
    document.getElementById('alerts').textContent  = d.alerts_count     ?? 0;
    document.getElementById('conflicts').textContent = d.conflict_ssids ?? 0;
}

function renderNetworks(data) {
    document.getElementById('networks').innerHTML = data.map(n => {
        const cls = (n.type||'normal').toLowerCase().replace(/[^a-z]/g,'-').split('(')[0].trim();
        return `<tr>
            <td>${n.ssid}</td><td>${n.packets}</td><td>${n.bssids}</td>
            <td class="type-${cls}">${n.type}</td>
            <td>${Number(n.confidence||0).toFixed(1)}%</td>
        </tr>`;
    }).join('');
}

function renderAlert(d) {
    const div = document.getElementById('alerts-list');
    const el  = document.createElement('div');
    let cls = 'alert';
    if (d.is_mobile)  cls += ' alert-mobile';
    if ((d.type||'').includes('DEAUTH')) cls += ' alert-deauth';
    el.className = cls;
    el.innerHTML = `<strong>${d.type}</strong><br>SSID: ${d.ssid}<br>
                    BSSID: ${d.bssid}<br><span class="ts">${d.time}</span>`;
    div.insertBefore(el, div.firstChild);
    while (div.children.length > 50) div.lastChild.remove();
}

socket.on('connect',  () => { renderStats(lastStats); renderNetworks(lastNetworks); });
socket.on('stats',    d  => { lastStats=d;    renderStats(d); });
socket.on('networks', d  => { lastNetworks=d; renderNetworks(d); });
socket.on('alert',    d  => renderAlert(d));

setInterval(() => {
    if (Date.now()-lastRefresh > 15000) {
        socket.emit('client_ping', {time:Date.now()});
        lastRefresh = Date.now();
    }
}, 5000);
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


# ── Dashboard worker ──────────────────────────────────────────────────────────
def dashboard_worker():
    """Background thread: builds network snapshot and pushes to dashboard every PRINT_INTERVAL seconds."""
    while True:
        time.sleep(PRINT_INTERVAL)
        with state.lock:
            networks = []
            conflict_count = 0

            for ssid, bssids in state.ssid_map.items():
                if not ssid:
                    continue

                total_pkts = sum(state.packet_count.get((ssid, b), 0) for b in bssids)
                conflict = len(bssids) > 1
                if conflict:
                    conflict_count += 1

                evil_prob = float(state.net_confidence.get(ssid, 0.0))
                ml_class = state.net_class.get(ssid, 0)

                # Priority: deterministic conflict → ML prediction → mobile OUI → normal
                if conflict:
                    net_type = "EVIL-TWIN (Conflict)"
                    confidence = 100.0
                elif ml_class == 1:
                    net_type = "EVIL-TWIN (ML)"
                    confidence = round(evil_prob * 100.0, 1)
                elif ml_class == 2:
                    net_type = "DEAUTH (ML)"
                    confidence = round(evil_prob * 100.0, 1)
                elif any(is_mobile(b) for b in bssids):
                    net_type = "MOBILE"
                    confidence = 100.0
                else:
                    net_type = "NORMAL"
                    confidence = round((1.0 - evil_prob) * 100.0, 1)

                networks.append({
                    "ssid": ssid,
                    "packets": total_pkts,
                    "bssids": len(bssids),
                    "type": net_type,
                    "confidence": confidence,
                })

            networks.sort(key=lambda n: (
                n["type"] not in {"EVIL-TWIN (Conflict)", "EVIL-TWIN (ML)", "DEAUTH (ML)"},
                -n["confidence"],
                -n["packets"],
            ))

            state.stats["unique_ssids"] = len(state.ssid_map)
            state.stats["unique_bssids"] = len(state.bssid_to_ssid)
            state.stats["conflict_ssids"] = conflict_count

            socketio.emit("stats", dict(state.stats))
            socketio.emit("networks", networks)


def build_alert(alert_type: str, ssid: str, bssid: str, is_mobile_device: bool) -> dict:
    return {
        "type": alert_type,
        "ssid": ssid,
        "bssid": bssid,
        "is_mobile": is_mobile_device,
        "time": datetime.now().strftime("%H:%M:%S"),
    }


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{Back.BLUE}{Fore.WHITE} AI-WIDS LIVE DETECTION {Style.RESET_ALL}\n")

    # Load model
    print(f"{Fore.CYAN}[1/3] Loading model...{Style.RESET_ALL}")
    checkpoint = torch.load("../data/models/wireless_ids.pt", map_location="cpu")
    num_classes = checkpoint.get("num_classes", 2)
    class_names = checkpoint.get("class_names", ["Normal", "Evil Twin"])
    label_map_inv = {v: k for k, v in checkpoint.get("label_map", {0: "normal", 1: "evil_twin"}).items()}

    model = WIDSDetector(checkpoint["scaler"].n_features_in_, num_classes=num_classes)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    scaler = checkpoint["scaler"]
    feature_order = checkpoint.get("feature_order", [])

    print(f"  ✓ Classes: {Fore.GREEN}{', '.join(class_names)}{Style.RESET_ALL}")
    print(f"  ✓ Features: {Fore.GREEN}{len(feature_order)}{Style.RESET_ALL}\n")

    # Start dashboard
    print(f"{Fore.CYAN}[2/3] Starting dashboard...{Style.RESET_ALL}")
    print(f"  ✓ URL: {Fore.GREEN}http://localhost:5000{Style.RESET_ALL}\n")
    threading.Thread(target=dashboard_worker, daemon=True).start()
    threading.Thread(
        target=lambda: socketio.run(app, host="0.0.0.0", port=5000, debug=False,
                                    use_reloader=False, log_output=False),
        daemon=True,
    ).start()
    time.sleep(2)

    # Start capture
    print(f"{Fore.CYAN}[3/3] Starting capture...{Style.RESET_ALL}")
    print(f"  ✓ Router:    {Fore.YELLOW}{OPENWRT_IP}{Style.RESET_ALL}")
    print(f"  ✓ Interface: {Fore.YELLOW}{INTERFACE}{Style.RESET_ALL}\n")
    print(f"{Fore.GREEN}📡 Monitoring... (Ctrl+C to stop){Style.RESET_ALL}\n")

    deauth_buf = deque(maxlen=20)
    beacon_buf = deque(maxlen=20)
    alerts_seen = set()

    cmd = [
        "ssh", f"root@{OPENWRT_IP}",
        "tcpdump", "-i", INTERFACE, "-w", "-", "-s", "0",
        "not", "port", "22",
    ]

    for pkt in stream_packets(cmd):
        if not pkt.haslayer(Dot11):
            continue

        features = extract_features(pkt, deauth_buf, beacon_buf)
        ssid = features["ssid"]
        bssid = features["bssid"]
        if not ssid or not bssid:
            continue

        with state.lock:
            state.ssid_map[ssid].add(bssid)
            state.bssid_to_ssid[bssid] = ssid
            state.packet_count[(ssid, bssid)] += 1
            state.stats["total_packets"] += 1

            is_mobile_device = is_mobile(bssid)
            if is_mobile_device:
                state.stats["mobile_hotspots"] += 1

            # ML inference
            pred = 0
            conf = 0.0
            evil_prob = 0.0
            try:
                x = np.array(
                    [features.get(k, 0) for k in feature_order], dtype=float
                ).reshape(1, -1)
                x = scaler.transform(x)
                with torch.no_grad():
                    out = model(torch.FloatTensor(x))
                    probs = torch.softmax(out, dim=1)[0]
                    pred = int(torch.argmax(probs).item())
                    conf = float(probs[pred].item())
                    # evil_prob is used for confidence display (class 1 = evil_twin)
                    evil_prob = float(probs[1].item()) if num_classes > 1 else conf
            except Exception:
                pass

            # Update per-SSID threat tracking
            state.net_confidence[ssid] = max(state.net_confidence.get(ssid, 0.0), evil_prob)
            state.net_class[ssid] = pred if evil_prob > 0.5 else state.net_class.get(ssid, 0)

            # Update counters
            if pred == 1:
                state.stats["evil_twin_packets"] += 1
            elif pred == 2:
                state.stats["deauth_packets"] += 1
            else:
                state.stats["normal_packets"] += 1

            conflict = len(state.ssid_map[ssid]) > 1

            # Alert logic
            key = (ssid, bssid)
            if key not in alerts_seen:
                rules = []
                if conflict:
                    rules.append("SSID_CONFLICT")
                if is_mobile_device:
                    rules.append("MOBILE_HOTSPOT")
                if pred == 1:
                    rules.append("ML_EVIL_TWIN")
                if pred == 2:
                    rules.append("ML_DEAUTH")

                if rules:
                    alert_msg = " + ".join(rules)
                    alert = build_alert(alert_msg, ssid, bssid, is_mobile_device)
                    state.alerts.appendleft(alert)
                    state.stats["alerts_count"] += 1
                    alerts_seen.add(key)
                    socketio.emit("alert", alert)

                    color = Fore.MAGENTA if is_mobile_device else (
                        Fore.RED if pred == 1 else Fore.CYAN
                    )
                    print(f"{color}🚨 {alert_msg}{Style.RESET_ALL}")
                    print(f"  SSID:       {ssid}")
                    print(f"  BSSID:      {bssid}")
                    print(f"  Device:     {get_device_name(bssid)}")
                    print(f"  Confidence: {conf:.3f}\n")

            state.last_update = time.time()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Stopped.{Style.RESET_ALL}\n")
