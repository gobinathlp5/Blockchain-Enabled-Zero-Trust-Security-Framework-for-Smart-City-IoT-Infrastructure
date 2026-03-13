import argparse
import hashlib
import hmac
import json
import paho.mqtt.publish as publish

from .config import INPUT_TOPIC, MQTT_BROKER, SECRET_KEY


def sign_payload(device_id, temperature, humidity):
    message = f"{device_id}:{temperature}:{humidity}"
    return hmac.new(SECRET_KEY, message.encode(), hashlib.sha256).hexdigest()


def build_payload(attack=False):
    if attack:
        return {
            "device_id": "hacker_device",
            "temperature": 120,
            "humidity": 10,
            "signature": "fake_signature",
        }

    device_id = "sensor_1"
    temperature = 26
    humidity = 58

    return {
        "device_id": device_id,
        "temperature": temperature,
        "humidity": humidity,
        "signature": sign_payload(device_id, temperature, humidity),
    }


def main():
    parser = argparse.ArgumentParser(description="Send valid or attack IoT payload")
    parser.add_argument("--attack", action="store_true", help="Send malicious payload")
    args = parser.parse_args()

    payload = build_payload(attack=args.attack)

    publish.single(
        INPUT_TOPIC,
        json.dumps(payload),
        hostname=MQTT_BROKER,
    )

    if args.attack:
        print("Attack payload sent")
    else:
        print("Valid payload sent")


if __name__ == "__main__":
    main()
