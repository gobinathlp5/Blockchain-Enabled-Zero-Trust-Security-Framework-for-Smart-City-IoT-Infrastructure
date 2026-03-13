import hashlib
import hmac
import json
import time
from collections import defaultdict, deque

import numpy as np
import paho.mqtt.client as mqtt
from sklearn.ensemble import IsolationForest

from .config import (
    AUTHORIZED_DEVICES,
    INPUT_TOPIC,
    MQTT_BROKER,
    MQTT_PORT,
    OUTPUT_TOPIC,
    SECRET_KEY,
)

# Blockchain log
blockchain = []
previous_hash = "0000"

# ── ML: Per-device data history ──────────────────────────────────────────────
MIN_SAMPLES = 15  # minimum messages before ML activates

device_msg_times = defaultdict(lambda: deque(maxlen=50))   # for rate anomaly
device_temp_hist = defaultdict(lambda: deque(maxlen=50))   # for z-score
device_hum_hist  = defaultdict(lambda: deque(maxlen=50))   # for z-score
isolation_models = {}                                       # device_id -> IsolationForest


def _rate_features(times):
    """Compute [mean, std, min] of inter-message intervals from a list of timestamps."""
    if len(times) < 2:
        return None
    intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
    return [np.mean(intervals), np.std(intervals), np.min(intervals)]


def _train_isolation_forest(device_id):
    """(Re)train IsolationForest on all collected rate windows for a device."""
    times = list(device_msg_times[device_id])
    if len(times) < MIN_SAMPLES + 1:
        return
    features = []
    for i in range(2, len(times) + 1):
        window = times[max(0, i - 10):i]
        feat = _rate_features(window)
        if feat:
            features.append(feat)
    if len(features) < MIN_SAMPLES:
        return
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)
    isolation_models[device_id] = model


def _check_rate_anomaly(device_id):
    """Return True if the current message rate pattern is anomalous."""
    if device_id not in isolation_models:
        return False
    times = list(device_msg_times[device_id])
    feat = _rate_features(times[-10:])
    if feat is None:
        return False
    return isolation_models[device_id].predict([feat])[0] == -1


def _check_payload_anomaly(device_id, temp, hum):
    """Z-score check: flag values > 3 std deviations from device's own history."""
    reasons = []
    if len(device_temp_hist[device_id]) >= MIN_SAMPLES:
        arr = np.array(device_temp_hist[device_id])
        z = abs(temp - arr.mean()) / (arr.std() + 1e-6)
        if z > 3:
            reasons.append(f"TEMP_ANOMALY(z={z:.1f})")
    if len(device_hum_hist[device_id]) >= MIN_SAMPLES:
        arr = np.array(device_hum_hist[device_id])
        z = abs(hum - arr.mean()) / (arr.std() + 1e-6)
        if z > 3:
            reasons.append(f"HUM_ANOMALY(z={z:.1f})")
    return reasons
# ─────────────────────────────────────────────────────────────────────────────


def create_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


def add_block(data):
    global previous_hash

    block = {
        "timestamp": time.time(),
        "data": data,
        "previous_hash": previous_hash,
    }

    block_string = json.dumps(block)
    block["hash"] = create_hash(block_string)

    blockchain.append(block)
    previous_hash = block["hash"]

    print("BLOCK ADDED:", block)
    return block["hash"]


def verify_signature(message, signature):
    generated = hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()
    return generated == signature


def detect_attack(data):
    if data["device_id"] not in AUTHORIZED_DEVICES:
        return "UNAUTHORIZED DEVICE"

    if data["temperature"] > 80:
        return "ABNORMAL TEMPERATURE"

    return None


def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        print("Invalid JSON received")
        return

    required_fields = ["device_id", "temperature", "humidity", "signature"]
    for field in required_fields:
        if field not in data:
            print("Invalid message format:", data)
            return

    device = data["device_id"]
    temp = data["temperature"]
    hum = data["humidity"]
    signature = data["signature"]
    message = f"{device}:{temp}:{hum}"
    event_hash = create_hash(
        json.dumps(
            {
                "device_id": device,
                "temperature": temp,
                "humidity": hum,
                "signature": signature,
            },
            sort_keys=True,
        )
    )

    # ── ML: record data BEFORE checks so history always grows ─────────────────
    device_msg_times[device].append(time.time())
    device_temp_hist[device].append(temp)
    device_hum_hist[device].append(hum)
    _train_isolation_forest(device)   # no-op until MIN_SAMPLES reached
    # ─────────────────────────────────────────────────────────────────────────

    if not verify_signature(message, signature):
        print("🚨 ATTACK DETECTED: Invalid Signature")
        client.publish(
            OUTPUT_TOPIC,
            json.dumps(
                {
                    "device_id": device,
                    "temperature": temp,
                    "humidity": hum,
                    "signature": signature,
                    "event_hash": event_hash,
                    "verified": False,
                    "reason": "INVALID_SIGNATURE",
                    "timestamp": time.time(),
                }
            ),
        )
        return

    attack = detect_attack(data)
    if attack:
        print("🚨 ATTACK:", attack)
        client.publish(
            OUTPUT_TOPIC,
            json.dumps(
                {
                    "device_id": device,
                    "temperature": temp,
                    "humidity": hum,
                    "signature": signature,
                    "event_hash": event_hash,
                    "verified": False,
                    "reason": attack,
                    "timestamp": time.time(),
                }
            ),
        )
        return

    # ── ML anomaly checks (run after rule-based checks pass) ─────────────────
    ml_flags = _check_payload_anomaly(device, temp, hum)
    if _check_rate_anomaly(device):
        ml_flags.append("RATE_ANOMALY_ML")
    if ml_flags:
        reason = "ML_ANOMALY: " + ", ".join(ml_flags)
        print(f"🤖 ML ANOMALY DETECTED [{device}]: {reason}")
        client.publish(
            OUTPUT_TOPIC,
            json.dumps(
                {
                    "device_id": device,
                    "temperature": temp,
                    "humidity": hum,
                    "signature": signature,
                    "event_hash": event_hash,
                    "verified": False,
                    "reason": reason,
                    "timestamp": time.time(),
                }
            ),
        )
        return
    # ─────────────────────────────────────────────────────────────────────────

    block_hash = add_block(data)

    client.publish(
        OUTPUT_TOPIC,
        json.dumps(
            {
                "device_id": device,
                "temperature": temp,
                "humidity": hum,
                "signature": signature,
                "event_hash": block_hash,
                "verified": True,
                "reason": "OK",
                "timestamp": time.time(),
            }
        ),
    )

    print("✅ VALID DATA RECEIVED")


def main():
    client = mqtt.Client()
    client.connect(MQTT_BROKER, MQTT_PORT)
    client.subscribe(INPUT_TOPIC)
    client.on_message = on_message

    print("Security Engine Running...")
    client.loop_forever()


if __name__ == "__main__":
    main()
