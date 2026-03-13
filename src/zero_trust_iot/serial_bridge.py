import argparse
import hashlib
import json
import re
import time

import paho.mqtt.client as mqtt
import serial

from .config import MQTT_BROKER, MQTT_PORT, OUTPUT_TOPIC


BLOCK_HASH_RE = re.compile(r"Hash:\s*([0-9a-fA-F]+)")


class BridgeState:
    def __init__(self):
        self.pending_event = None
        self.last_block_hash = None

    def reset(self):
        self.pending_event = None
        self.last_block_hash = None


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_event_from_payload(raw_payload: str) -> dict | None:
    try:
        envelope = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None

    data = envelope.get("data", {})
    payload_data = data.get("data", {})
    device_id = data.get("device", "UNKNOWN_DEVICE")
    device_type = data.get("type", "unknown")
    signature = envelope.get("sig", "")
    event_time = data.get("timestamp", time.time())

    temperature = payload_data.get("temperature", 0)
    humidity = payload_data.get("humidity", 0)
    preview = summarize_payload(device_type, payload_data)

    return {
        "device_id": device_id,
        "device_type": device_type,
        "temperature": temperature,
        "humidity": humidity,
        "signature": signature,
        "event_hash": sha256_hex(raw_payload),
        "verified": False,
        "reason": "PENDING",
        "timestamp": event_time,
        "payload_preview": preview,
        "raw_payload": raw_payload,
    }


def summarize_payload(device_type: str, payload_data: dict) -> str:
    if device_type == "environmental":
        return f"Temp:{payload_data.get('temperature', 0)} Hum:{payload_data.get('humidity', 0)}"
    if device_type == "traffic":
        return f"Vehicles:{payload_data.get('vehicle_count', 0)} Speed:{payload_data.get('avg_speed_kmh', 0)}"
    if device_type == "meter":
        return f"Power:{payload_data.get('power_kw', 0)} Voltage:{payload_data.get('voltage_v', 0)}"
    return "Payload received"


def publish_event(client: mqtt.Client, state: BridgeState, verified: bool, reason: str):
    if not state.pending_event:
        return

    event = dict(state.pending_event)
    event["verified"] = verified
    event["reason"] = reason
    if verified and state.last_block_hash:
        event["event_hash"] = state.last_block_hash

    event.pop("raw_payload", None)
    client.publish(OUTPUT_TOPIC, json.dumps(event))
    print(f"Published dashboard event: {event['device_id']} | {reason}")
    state.reset()


def process_line(client: mqtt.Client, state: BridgeState, line: str):
    if line.startswith("Payload: "):
        payload = line.split("Payload: ", 1)[1].strip()
        pending = build_event_from_payload(payload)
        if pending:
            state.pending_event = pending
            state.last_block_hash = None
        return

    block_match = BLOCK_HASH_RE.search(line)
    if block_match:
        state.last_block_hash = block_match.group(1)
        return

    if "CHECK 1 FAILED — Unknown device" in line:
        publish_event(client, state, False, "UNKNOWN_DEVICE")
    elif "CHECK 1 FAILED — Device quarantined" in line:
        publish_event(client, state, False, "QUARANTINED")
    elif "CHECK 2 FAILED — Bad signature" in line:
        publish_event(client, state, False, "BAD_SIGNATURE")
    elif "CHECK 3 FAILED — Rate Exceeded" in line or "CHECK 3 FAILED — Rate exceeded" in line:
        publish_event(client, state, False, "RATE_EXCEEDED")
    elif line.startswith("✅ AUTHENTICATED"):
        publish_event(client, state, True, "OK")


def main():
    parser = argparse.ArgumentParser(description="Bridge single-ESP32 serial output into dashboard MQTT events")
    parser.add_argument("--port", required=True, help="Serial port for the ESP32, e.g. COM5")
    parser.add_argument("--baud", type=int, default=115200, help="Serial baud rate")
    args = parser.parse_args()

    mqtt_client = mqtt.Client()
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
    mqtt_client.loop_start()

    state = BridgeState()

    print(f"Opening serial port {args.port} at {args.baud} baud")
    with serial.Serial(args.port, args.baud, timeout=1) as ser:
        while True:
            raw_line = ser.readline()
            if not raw_line:
                continue

            line = raw_line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            print(line)
            process_line(mqtt_client, state, line)


if __name__ == "__main__":
    main()