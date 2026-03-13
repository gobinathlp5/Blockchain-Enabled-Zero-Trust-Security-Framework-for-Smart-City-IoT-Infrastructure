import hashlib
import hmac
import json
import math
import statistics
import time
from collections import defaultdict, deque

import paho.mqtt.client as mqtt

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

# ── ML: Per-device data history (pure Python, no extra packages) ──────────────
MIN_SAMPLES = 15  # minimum messages before ML activates

device_msg_times = defaultdict(lambda: deque(maxlen=50))   # timestamps for rate anomaly
device_temp_hist = defaultdict(lambda: deque(maxlen=50))   # temperature history
device_hum_hist  = defaultdict(lambda: deque(maxlen=50))   # humidity history


def _zscore(value, history):
    """Return z-score of value against a history list.
    Uses a sigma floor of 0.5 so identical baselines still catch extreme outliers
    while near-normal variation (e.g. +/-1 unit) is not mis-flagged.
    """
    if len(history) < MIN_SAMPLES:
        return 0.0
    mu  = statistics.mean(history)
    sig = max(statistics.pstdev(history), 0.5)  # floor avoids near-zero sigma issue
    return abs(value - mu) / sig


def _check_rate_anomaly(device_id):
    """
    Rolling inter-arrival anomaly: flag if the latest interval is an extreme
    outlier (z-score > 3) compared to the device's own interval history.
    Returns True = anomalous (burst / flood).
    """
    times = list(device_msg_times[device_id])
    if len(times) < MIN_SAMPLES + 1:
        return False
    intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]
    latest    = intervals[-1]
    baseline  = intervals[:-1]
    return _zscore(latest, baseline) > 3.0


def _check_payload_anomaly(device_id, temp, hum):
    """Z-score payload check: flag values > 3 std deviations from device history."""
    reasons = []
    z_temp = _zscore(temp, list(device_temp_hist[device_id]))
    z_hum  = _zscore(hum,  list(device_hum_hist[device_id]))
    if z_temp > 3:
        reasons.append(f"TEMP_ANOMALY(z={z_temp:.1f})")
    if z_hum > 3:
        reasons.append(f"HUM_ANOMALY(z={z_hum:.1f})")
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
