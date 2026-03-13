# Blockchain-Enabled Zero Trust Security Framework for Smart City IoT Infrastructure

## Securing IoT Networks with Blockchain and Zero Trust Architecture

### A Hardware Implementation Workflow Using ESP32 and DHT11

## 1) Project Overview

**Objective**  
Design and implement a prototype that demonstrates how Blockchain and Zero Trust can protect smart city IoT devices from unauthorized access, data tampering, and botnet-style behavior.

**Hardware target**

- 2x ESP32 DevKit microcontrollers
- 1x DHT11 temperature/humidity sensor
- USB cables for programming and serial monitoring
- Laptop/PC for monitoring and analytics

**Core claim**  
A resource-constrained IoT node (ESP32 + DHT11) can securely send telemetry using cryptographic authentication and blockchain-style logging without cloud dependence or high-end hardware.

---

## 2) Problem Statement

Smart city IoT deployments often face three recurring weaknesses:

1. **No strong authentication**  
   Devices send data without proving identity.
2. **No integrity guarantee**  
   Data may be altered in transit with no tamper evidence.
3. **No behavior monitoring**  
   Compromised nodes may flood traffic or behave abnormally without enforcement.

This project addresses all three with a practical prototype architecture.

---

## 3) Proposed 3-Layer Architecture

```
┌─────────────────────────────────────────────┐
│           LAYER 1: DEVICE LAYER             │
│   ESP32 #1 + DHT11                          │
│   Sensor Node — collects and signs data     │
└─────────────────┬───────────────────────────┘
						│ WiFi (MQTT)
						▼
┌─────────────────────────────────────────────┐
│         LAYER 2: SECURITY LAYER             │
│   ESP32 #2                                  │
│   Zero Trust Gateway — verifies every msg   │
│   Blockchain Logger — records verified data │
└─────────────────┬───────────────────────────┘
						│ Serial / WiFi
						▼
┌─────────────────────────────────────────────┐
│        LAYER 3: MONITORING LAYER            │
│   Laptop Serial Monitor / Python Dashboard  │
│   Admin view — live logs, alerts, blocks    │
└─────────────────────────────────────────────┘
```

---

## 4) Component Roles

### ESP32 #1 — IoT Sensor Node

- Reads temperature and humidity every 5 seconds
- Builds structured payload
- Signs payload with HMAC-SHA256
- Publishes signed message over MQTT

### ESP32 #2 — Zero Trust Gateway + Blockchain Node

- Receives all incoming device messages
- Verifies identity, signature, and behavior limits
- Rejects/quarantines failed messages
- Adds verified messages to blockchain ledger
- Streams security decisions to monitor

---

## 5) Workflow (Step-by-Step)

### Step 1: Boot + Identity Assignment

Device loads static identity and secret:

```text
DEVICE_ID = "SMARTCITY_NODE_001"
SECRET_KEY = "mysecretkey12345"
```

Then joins gateway network and becomes transmission-ready.

### Step 2: Data Collection

DHT11 samples environment:

```json
{
  "device": "SMARTCITY_NODE_001",
  "temp": 28.5,
  "humidity": 64,
  "ts": 14523
}
```

### Step 3: Cryptographic Signing

Payload is signed using HMAC-SHA256 and sent as:

```json
{
  "data": {
    "device": "SMARTCITY_NODE_001",
    "temp": 28.5,
    "humidity": 64,
    "ts": 14523
  },
  "sig": "3f7a2b9c4e1d..."
}
```

Published to topic `smartcity/env`.

### Step 4: Zero Trust Verification at Gateway

Each message passes all checks:

1. Device registered?
2. Signature valid?
3. Rate allowed?

Any failure => immediate deny/quarantine.

### Step 5: Blockchain Logging

Verified messages are chained using hash links:

```json
{
  "index": 1,
  "device": "SMARTCITY_NODE_001",
  "data_hash": "a3f9c2...",
  "timestamp": 14523,
  "previous_hash": "0000...0"
}
```

### Step 6: Rogue Device Simulation

Forged payload from unregistered device is denied and not logged.

### Step 7: Monitoring

Admin sees live pass/fail decisions, alerts, and accepted blocks.

---

## 6) Security Properties Demonstrated

| Security Property              | Demonstration                           |
| ------------------------------ | --------------------------------------- |
| Device Authentication          | HMAC verification per message           |
| Data Integrity                 | Hash-linked blockchain entries          |
| Unauthorized Access Prevention | Unknown devices denied                  |
| Tamper Detection               | Signature mismatch rejected             |
| DDoS/Botnet Detection          | Rate limit + quarantine logic           |
| Audit Trail                    | Accepted events stored in chain         |
| Zero Trust Enforcement         | No implicit trust; verify every request |

---

## 7) Mapping to Smart City Case Requirements

| Case Requirement                 | Prototype Mapping                   |
| -------------------------------- | ----------------------------------- |
| Resource-constrained IoT devices | ESP32-based node/gateway model      |
| Environmental sensing            | DHT11 telemetry payload             |
| Unauthorized device prevention   | Registration whitelist check        |
| Tamper-resistant records         | SHA-256 chained ledger              |
| Continuous verification          | Multi-check Zero Trust pipeline     |
| Botnet / DDoS response           | Behavior/rate enforcement           |
| Admin monitoring                 | Live dashboard + event stream       |
| Rogue attack demonstration       | Simulated malicious payload blocked |

---

## 8) Current Repository Implementation (Python Simulation)

This repository currently implements a software simulation of the same architecture:

- MQTT ingestion and verification engine
- HMAC signature validation
- Authorized-device checks
- Basic anomaly check (abnormal temperature)
- In-memory blockchain-style chain for accepted telemetry
- Dash dashboard for live monitoring
- Attack payload simulation

### Current project structure

```
Zero Trust IoT/
├── src/
│   └── zero_trust_iot/
│       ├── config.py
│       ├── security_engine.py
│       ├── dashboard.py
│       └── simulator.py
├── scripts/
│   ├── run_security_engine.py
│   ├── run_dashboard.py
│   └── send_data.py
├── security_engine.py
├── dashboard.py
├── attack_simulator.py
├── requirements.txt
└── README.md
```

---

## 9) How to Run (Software Prototype)

Install dependencies:

```bash
pip install -r requirements.txt
```

Run services:

```bash
python scripts/run_security_engine.py
python scripts/run_dashboard.py
```

Send traffic:

```bash
python scripts/send_data.py
python scripts/send_data.py --attack
```

Backward-compatible root launchers:

```bash
python security_engine.py
python dashboard.py
python attack_simulator.py
python attack_simulator.py --attack
```

---

## 10) ESP32 Firmware (No DHT11 Mode)

Arduino sketches are available for direct hardware testing without DHT11:

- `firmware/gateway_node/gateway_node.ino`
- `firmware/sensor_node/sensor_node.ino`
- `firmware/single_esp32_demo/single_esp32_demo.ino`

Current behavior:

- Sensor node publishes to ESP32 gateway over MQTT
- Sensor node cycles through three legitimate smart city device roles:
  - `ENV_NODE_001`
  - `TRAFFIC_NODE_001`
  - `METER_NODE_001`
- Sensor node can also simulate:
  - rogue device access
  - payload tampering
  - DDoS / flood traffic
- Each legitimate role has its own HMAC-SHA256 secret key
- Gateway runs as WiFi Access Point, embedded MQTT broker, Zero Trust verifier, and blockchain node
- Gateway maintains a device registry, rate-limit tracking, quarantine state, and hash-chain ledger in RAM
- Gateway now publishes each verification decision to dashboard topic `zerotrust/gobinath/iot/verified`

Required Arduino libraries:

- `ArduinoJson`
- `PubSubClient`
- `uMQTTBroker`

Upload order:

1. Flash `gateway_node.ino` to ESP32 #2 and open Serial Monitor
2. Flash `sensor_node.ino` to ESP32 #1
3. Observe Zero Trust verification and block creation logs on gateway Serial output
4. Run the Python dashboard (`python scripts/run_dashboard.py`) and watch live events

Dashboard integration notes:

- Preferred: use the updated `gateway_node.ino` (direct MQTT publish to dashboard topic)
- Fallback for older gateway firmware: run `python scripts/run_esp32_bridge.py --port COMx` on the **gateway** serial port

Sensor node Serial commands:

1. Open Serial Monitor for `sensor_node.ino` (115200 baud)
2. Enter one of these commands:
   - `auto` -> cycle ENV / TRAFFIC / METER every 10s
   - `demo` -> run scripted 40-second demo sequence
   - `env` -> only environmental node traffic
   - `traffic` -> only traffic node traffic
   - `meter` -> only smart meter traffic
   - `rogue` -> unknown device attack
   - `tamper` -> bad-signature / modified-payload attack
   - `flood` -> DDoS burst using meter role
   - `status` -> print current mode
3. Watch gateway monitor for expected decisions (`Unknown device`, `Bad signature`, `Rate Exceeded`)

Gateway Serial commands:

- `SHOW_CHAIN` -> print all blocks
- `CHECK_CHAIN` -> validate blockchain integrity
- `SHOW_REGISTRY` -> show quarantine and rate-limit state

Scripted demo sequence:

1. `ENV_NODE_001` legitimate message
2. `TRAFFIC_NODE_001` legitimate message
3. `METER_NODE_001` legitimate message
4. `ROGUE_DEVICE_999` unauthorized access attempt
5. Tampered environmental payload
6. Meter flood burst
7. Legitimate traffic node recovery message
8. Run `SHOW_CHAIN` and `CHECK_CHAIN` on gateway

### Single ESP32 fallback

If one ESP32 is not working, use:

- `firmware/single_esp32_demo/single_esp32_demo.ino`

What it does:

- Simulates the IoT node and the Zero Trust gateway on the same ESP32
- Generates ENV / TRAFFIC / METER / ROGUE device traffic internally
- Signs, verifies, rate-limits, quarantines, and blockchain-logs messages in one firmware
- Prints all security decisions to Serial Monitor

Single-board commands:

- `auto` -> cycle ENV / TRAFFIC / METER every 10s
- `demo` -> run scripted 40-second demo
- `env`
- `traffic`
- `meter`
- `rogue`
- `tamper`
- `flood`
- `show_chain`
- `check_chain`
- `show_registry`
- `status`

Single-board limitation:

- This preserves the cryptographic verification, Zero Trust policy enforcement, attack simulation, and blockchain logging logic.
- It does **not** demonstrate a real network boundary between two physical devices, because node and gateway are looped back internally on the same ESP32.

---

## 11) Limitations and Production Improvements

1. **Hardcoded key material**  
   Production should use secure key provisioning and hardware-backed key storage.
2. **In-memory blockchain**  
   Production should persist chain data in flash/edge server storage.
3. **Single sensor profile**  
   Security model generalizes to GPS, CO2, motion, and other sensors.
4. **Non-persistent quarantine**  
   Persist deny/quarantine state across restarts.

---

## 12) Conclusion

The prototype validates that Blockchain-style tamper evidence and Zero Trust verification can run on constrained IoT-oriented architecture. The software implementation in this repo demonstrates the security workflow end-to-end and serves as a direct stepping stone to the two-ESP32 hardware deployment.

---

## 13) Future Scope

- Add multiple sensor nodes to emulate city-scale topology
- Integrate Raspberry Pi as persistent edge ledger node
- Add richer Python web monitoring and policy controls
- Add on-device status display at gateway
- Extend transport/interconnect scenarios (for example, CAN integrations)
- Package findings into a publishable research artifact
