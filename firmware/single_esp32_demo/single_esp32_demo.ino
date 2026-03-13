#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

const char *WIFI_SSID = "Omnitrix";
const char *WIFI_PASSWORD = "12345678";
const char *MQTT_BROKER = "broker.hivemq.com";
const uint16_t MQTT_PORT = 1883;
const char *DASHBOARD_TOPIC = "zerotrust/gobinath/iot/verified";

const unsigned long AUTO_SEND_INTERVAL_MS = 10000;
const unsigned long FLOOD_GAP_MS = 150;
const uint8_t FLOOD_MESSAGE_COUNT = 30;
const uint8_t MAX_MESSAGES_PER_MINUTE = 20;
const uint8_t MAX_RATE_HISTORY = 24;
const uint16_t MAX_BLOCKS = 100;
const char *GENESIS_PREVIOUS_HASH = "0000000000000000";

struct DeviceRole
{
    const char *deviceId;
    const char *type;
    const char *secretKey;
    bool authorized;
};

struct DeviceRecord
{
    const char *deviceId;
    const char *secretKey;
    uint8_t maxMessagesPerMinute;
    bool quarantined;
    unsigned long recentTimestamps[MAX_RATE_HISTORY];
    uint8_t recentCount;
};

struct Block
{
    uint16_t index;
    String deviceId;
    String type;
    String canonicalData;
    String payloadPreview;
    String dataHash;
    String previousHash;
    String hash;
    uint32_t timestamp;
};

DeviceRole deviceRoles[] = {
    {"ENV_NODE_001", "environmental", "env_secret_key_2025", true},
    {"TRAFFIC_NODE_001", "traffic", "traffic_secret_key_2025", true},
    {"METER_NODE_001", "meter", "meter_secret_key_2025", true},
    {"ROGUE_DEVICE_999", "rogue", "", false},
};

DeviceRecord deviceRegistry[] = {
    {"ENV_NODE_001", "env_secret_key_2025", MAX_MESSAGES_PER_MINUTE, false, {0}, 0},
    {"TRAFFIC_NODE_001", "traffic_secret_key_2025", MAX_MESSAGES_PER_MINUTE, false, {0}, 0},
    {"METER_NODE_001", "meter_secret_key_2025", MAX_MESSAGES_PER_MINUTE, false, {0}, 0},
};

Block blockchain[MAX_BLOCKS];
uint16_t blockCount = 0;

enum Mode
{
    MODE_AUTO,
    MODE_DEMO,
    MODE_ENV,
    MODE_TRAFFIC,
    MODE_METER,
    MODE_ROGUE,
    MODE_TAMPER,
    MODE_FLOOD,
};

Mode currentMode = MODE_AUTO;
unsigned long lastSendMs = 0;
unsigned long demoStartMs = 0;
int demoStage = -1;
bool baselineShown = false;
WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);

String toHex(const uint8_t *bytes, size_t length)
{
    String out;
    out.reserve(length * 2);
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < length; i++)
    {
        uint8_t b = bytes[i];
        out += hex[(b >> 4) & 0x0F];
        out += hex[b & 0x0F];
    }
    return out;
}

String sha256Hex(const String &input)
{
    uint8_t digest[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, reinterpret_cast<const unsigned char *>(input.c_str()), input.length());
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);
    return toHex(digest, sizeof(digest));
}

String hmacSha256(const String &key, const String &message)
{
    uint8_t hmacResult[32];

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx, mdInfo, 1);

    mbedtls_md_hmac_starts(&ctx, reinterpret_cast<const unsigned char *>(key.c_str()), key.length());
    mbedtls_md_hmac_update(&ctx, reinterpret_cast<const unsigned char *>(message.c_str()), message.length());
    mbedtls_md_hmac_finish(&ctx, hmacResult);

    mbedtls_md_free(&ctx);
    return toHex(hmacResult, sizeof(hmacResult));
}

String modeName(Mode mode)
{
    switch (mode)
    {
    case MODE_DEMO:
        return "DEMO";
    case MODE_ENV:
        return "ENV";
    case MODE_TRAFFIC:
        return "TRAFFIC";
    case MODE_METER:
        return "METER";
    case MODE_ROGUE:
        return "ROGUE";
    case MODE_TAMPER:
        return "TAMPER";
    case MODE_FLOOD:
        return "FLOOD";
    default:
        return "AUTO";
    }
}

DeviceRole &roleByIndex(size_t index)
{
    return deviceRoles[index];
}

DeviceRole &autoRoleForWindow()
{
    size_t roleIndex = (millis() / AUTO_SEND_INTERVAL_MS) % 3;
    return roleByIndex(roleIndex);
}

DeviceRecord *findDevice(const String &deviceId)
{
    for (size_t i = 0; i < sizeof(deviceRegistry) / sizeof(deviceRegistry[0]); i++)
    {
        if (deviceId == deviceRegistry[i].deviceId)
        {
            return &deviceRegistry[i];
        }
    }

    return nullptr;
}

void compactRateWindow(DeviceRecord &device, unsigned long now)
{
    uint8_t writeIndex = 0;
    for (uint8_t i = 0; i < device.recentCount; i++)
    {
        if (now - device.recentTimestamps[i] <= 60000UL)
        {
            device.recentTimestamps[writeIndex++] = device.recentTimestamps[i];
        }
    }
    device.recentCount = writeIndex;
}

bool exceedsRateLimit(DeviceRecord &device, unsigned long now)
{
    compactRateWindow(device, now);
    return device.recentCount >= device.maxMessagesPerMinute;
}

void recordMessage(DeviceRecord &device, unsigned long now)
{
    compactRateWindow(device, now);
    if (device.recentCount < MAX_RATE_HISTORY)
    {
        device.recentTimestamps[device.recentCount++] = now;
        return;
    }

    for (uint8_t i = 1; i < MAX_RATE_HISTORY; i++)
    {
        device.recentTimestamps[i - 1] = device.recentTimestamps[i];
    }
    device.recentTimestamps[MAX_RATE_HISTORY - 1] = now;
}

String summarizePayload(const String &type, JsonObject payload)
{
    if (type == "environmental")
    {
        return "Temp:" + String(payload["temperature"].as<float>(), 1) + " Hum:" + String(payload["humidity"].as<int>());
    }
    if (type == "traffic")
    {
        return "Vehicles:" + String(payload["vehicle_count"].as<int>()) + " Speed:" + String(payload["avg_speed_kmh"].as<int>());
    }
    if (type == "meter")
    {
        return "Power:" + String(payload["power_kw"].as<float>(), 1) + " Voltage:" + String(payload["voltage_v"].as<int>());
    }
    return "Payload received";
}

void ensureWifi()
{
    if (WiFi.status() == WL_CONNECTED)
    {
        return;
    }

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("Connecting to WiFi");
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 40)
    {
        delay(500);
        Serial.print(".");
        attempts++;
    }
    Serial.println();

    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.print("WiFi connected. IP: ");
        Serial.println(WiFi.localIP());
    }
    else
    {
        Serial.println("WiFi connection failed. Dashboard publishing unavailable.");
    }
}

void ensureMqtt()
{
    if (mqttClient.connected() || WiFi.status() != WL_CONNECTED)
    {
        return;
    }

    mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
    mqttClient.setBufferSize(1024);

    while (!mqttClient.connected() && WiFi.status() == WL_CONNECTED)
    {
        String clientId = "single-esp32-" + String(static_cast<uint32_t>(esp_random()), HEX);
        Serial.print("Connecting to MQTT broker...");
        if (mqttClient.connect(clientId.c_str()))
        {
            Serial.println("connected");
            return;
        }

        Serial.print("failed (state=");
        Serial.print(mqttClient.state());
        Serial.println(") -> retrying in 1s");
        delay(1000);
    }
}

void publishDashboardEvent(
    const String &deviceId,
    const String &deviceType,
    JsonObject payloadValues,
    const String &signature,
    const String &eventHash,
    bool verified,
    const String &reason,
    uint32_t timestamp,
    const String &payloadPreview)
{
    ensureWifi();
    ensureMqtt();

    if (!mqttClient.connected())
    {
        Serial.println("⚠️ Dashboard publish skipped: MQTT not connected");
        return;
    }

    StaticJsonDocument<512> eventDoc;
    eventDoc["device_id"] = deviceId;
    eventDoc["device_type"] = deviceType;
    eventDoc["temperature"] = payloadValues.containsKey("temperature") ? payloadValues["temperature"].as<float>() : 0;
    eventDoc["humidity"] = payloadValues.containsKey("humidity") ? payloadValues["humidity"].as<int>() : 0;
    eventDoc["signature"] = signature;
    eventDoc["event_hash"] = eventHash;
    eventDoc["verified"] = verified;
    eventDoc["reason"] = reason;
    eventDoc["timestamp"] = timestamp;
    eventDoc["payload_preview"] = payloadPreview;

    String body;
    serializeJson(eventDoc, body);
    bool published = mqttClient.publish(DASHBOARD_TOPIC, body.c_str());
    if (published)
    {
        Serial.print("📡 Published to dashboard topic: ");
        Serial.print(deviceId);
        Serial.print(" | ");
        Serial.println(reason);
    }
    else
    {
        Serial.println("⚠️ MQTT publish failed for dashboard event");
    }
}

void createGenesisBlock()
{
    Block &genesis = blockchain[0];
    genesis.index = 0;
    genesis.deviceId = "GENESIS";
    genesis.type = "genesis";
    genesis.canonicalData = "GENESIS";
    genesis.payloadPreview = "GENESIS";
    genesis.dataHash = sha256Hex(genesis.canonicalData);
    genesis.previousHash = GENESIS_PREVIOUS_HASH;
    genesis.timestamp = 0;
    genesis.hash = sha256Hex(String(genesis.index) + "|" + genesis.deviceId + "|" + genesis.dataHash + "|" + genesis.previousHash + "|" + String(genesis.timestamp));
    blockCount = 1;
}

void addBlock(const String &deviceId, const String &type, const String &canonicalData, const String &payloadPreview, uint32_t timestamp)
{
    if (blockCount >= MAX_BLOCKS)
    {
        Serial.println("⚠️ Chain full, block not stored");
        return;
    }

    Block &previous = blockchain[blockCount - 1];
    Block &block = blockchain[blockCount];
    block.index = blockCount;
    block.deviceId = deviceId;
    block.type = type;
    block.canonicalData = canonicalData;
    block.payloadPreview = payloadPreview;
    block.dataHash = sha256Hex(canonicalData);
    block.previousHash = previous.hash;
    block.timestamp = timestamp;
    block.hash = sha256Hex(String(block.index) + "|" + block.deviceId + "|" + block.dataHash + "|" + block.previousHash + "|" + String(block.timestamp));
    blockCount++;

    Serial.print("✅ Block #");
    Serial.print(block.index);
    Serial.print(" added | Hash: ");
    Serial.println(block.hash);
}

void showChain()
{
    Serial.println("=== BLOCKCHAIN STATE ===");
    for (uint16_t i = 0; i < blockCount; i++)
    {
        Block &block = blockchain[i];
        Serial.print("BLOCK #");
        Serial.print(block.index);
        Serial.print(" | ");
        Serial.print(block.deviceId);
        Serial.print(" | ");
        Serial.print(block.payloadPreview);
        Serial.print(" | Hash: ");
        Serial.println(block.hash);
    }
}

void checkChain()
{
    for (uint16_t i = 0; i < blockCount; i++)
    {
        Block &block = blockchain[i];
        String expectedDataHash = sha256Hex(block.canonicalData);
        String expectedPreviousHash = (i == 0) ? String(GENESIS_PREVIOUS_HASH) : blockchain[i - 1].hash;
        String expectedHash = sha256Hex(String(block.index) + "|" + block.deviceId + "|" + expectedDataHash + "|" + expectedPreviousHash + "|" + String(block.timestamp));
        if (block.dataHash != expectedDataHash || block.previousHash != expectedPreviousHash || block.hash != expectedHash)
        {
            Serial.print("🚫 Block #");
            Serial.print(block.index);
            Serial.println(" hash mismatch — Tamper detected (ALERT)");
            return;
        }
    }

    Serial.println("✅ All blocks valid — Chain intact (SECURE)");
}

void showRegistry()
{
    Serial.println("=== DEVICE REGISTRY ===");
    for (size_t i = 0; i < sizeof(deviceRegistry) / sizeof(deviceRegistry[0]); i++)
    {
        Serial.print(deviceRegistry[i].deviceId);
        Serial.print(" | max/min: ");
        Serial.print(deviceRegistry[i].maxMessagesPerMinute);
        Serial.print(" | quarantined: ");
        Serial.println(deviceRegistry[i].quarantined ? "yes" : "no");
    }
}

void buildRoleData(const DeviceRole &role, StaticJsonDocument<384> &dataDoc)
{
    uint32_t ts = millis() / 1000;
    dataDoc["device"] = role.deviceId;
    dataDoc["type"] = role.type;
    dataDoc["timestamp"] = ts;

    JsonObject values = dataDoc.createNestedObject("data");
    if (String(role.type) == "environmental")
    {
        values["temperature"] = 25.0f + static_cast<float>(esp_random() % 150) / 10.0f;
        values["humidity"] = 40 + static_cast<int>(esp_random() % 41);
        values["aqi"] = 60 + static_cast<int>(esp_random() % 91);
        values["co2_ppm"] = 400 + static_cast<int>(esp_random() % 201);
    }
    else if (String(role.type) == "traffic")
    {
        values["vehicle_count"] = 10 + static_cast<int>(esp_random() % 71);
        values["avg_speed_kmh"] = 20 + static_cast<int>(esp_random() % 61);
        const char *levels[] = {"low", "medium", "high"};
        values["congestion"] = levels[esp_random() % 3];
    }
    else if (String(role.type) == "meter")
    {
        values["power_kw"] = 1.0f + static_cast<float>(esp_random() % 71) / 10.0f;
        values["voltage_v"] = 220 + static_cast<int>(esp_random() % 21);
        values["current_amp"] = 5 + static_cast<int>(esp_random() % 31);
    }
    else
    {
        values["garbage"] = "intrusion";
        values["value"] = 9999;
    }
}

void gatewayProcess(const String &rawEnvelope)
{
    StaticJsonDocument<768> wrapperDoc;
    DeserializationError err = deserializeJson(wrapperDoc, rawEnvelope);
    if (err)
    {
        Serial.println("🚫 Invalid JSON");
        return;
    }

    if (!wrapperDoc.containsKey("data") || !wrapperDoc.containsKey("sig"))
    {
        Serial.println("🚫 Invalid message format");
        return;
    }

    JsonObject data = wrapperDoc["data"].as<JsonObject>();
    JsonObject payloadValues = data["data"].as<JsonObject>();
    if (data.isNull() || payloadValues.isNull())
    {
        Serial.println("🚫 Invalid data payload");
        return;
    }

    String deviceId = data["device"].as<String>();
    String type = data["type"].as<String>();
    uint32_t timestamp = data["timestamp"].as<uint32_t>();
    String receivedSignature = wrapperDoc["sig"].as<String>();
    String preview = summarizePayload(type, payloadValues);
    String dashboardHash = sha256Hex(rawEnvelope);

    Serial.print("📨 Message from: ");
    Serial.println(deviceId);

    DeviceRecord *device = findDevice(deviceId);
    if (device == nullptr)
    {
        Serial.println("🚫 CHECK 1 FAILED — Unknown device");
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, dashboardHash, false, "UNKNOWN_DEVICE", timestamp, preview);
        return;
    }
    if (device->quarantined)
    {
        Serial.println("🚫 CHECK 1 FAILED — Device quarantined");
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, dashboardHash, false, "QUARANTINED", timestamp, preview);
        return;
    }
    Serial.println("✅ CHECK 1 PASSED — Device registered");

    String canonicalData;
    serializeJson(data, canonicalData);
    String expectedSignature = hmacSha256(device->secretKey, canonicalData);
    if (expectedSignature != receivedSignature)
    {
        device->quarantined = true;
        Serial.println("🚫 CHECK 2 FAILED — Bad signature -> QUARANTINED");
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, dashboardHash, false, "BAD_SIGNATURE", timestamp, preview);
        return;
    }
    Serial.println("✅ CHECK 2 PASSED — Signature valid");

    unsigned long now = millis();
    if (exceedsRateLimit(*device, now))
    {
        device->quarantined = true;
        Serial.println("🚫 CHECK 3 FAILED — Rate Exceeded -> QUARANTINED");
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, dashboardHash, false, "RATE_EXCEEDED", timestamp, preview);
        return;
    }
    recordMessage(*device, now);
    Serial.println("✅ CHECK 3 PASSED — Rate within limit");

    addBlock(deviceId, type, canonicalData, preview, timestamp);
    String blockHash = blockchain[blockCount - 1].hash;

    Serial.print("✅ AUTHENTICATED — ");
    Serial.println(preview);
    publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, blockHash, true, "OK", timestamp, preview);
}

void emitEnvelope(const DeviceRole &role, bool tamperPayload, bool forceBadSignature)
{
    StaticJsonDocument<384> dataDoc;
    buildRoleData(role, dataDoc);

    String signTarget;
    serializeJson(dataDoc, signTarget);

    String signature = role.authorized ? hmacSha256(role.secretKey, signTarget) : "fake_signature";
    if (forceBadSignature)
    {
        signature = "bad_signature_for_test";
    }

    if (tamperPayload)
    {
        JsonObject values = dataDoc["data"];
        if (values.containsKey("temperature"))
        {
            values["temperature"] = values["temperature"].as<float>() + 5.5f;
        }
        else if (values.containsKey("vehicle_count"))
        {
            values["vehicle_count"] = values["vehicle_count"].as<int>() + 25;
        }
        else if (values.containsKey("power_kw"))
        {
            values["power_kw"] = values["power_kw"].as<float>() + 2.5f;
        }
    }

    StaticJsonDocument<512> wrapperDoc;
    wrapperDoc["sig"] = signature;
    JsonObject wrappedData = wrapperDoc.createNestedObject("data");
    wrappedData.set(dataDoc.as<JsonObject>());

    String payload;
    serializeJson(wrapperDoc, payload);

    Serial.print("TX Mode: ");
    Serial.println(modeName(currentMode));
    Serial.print("Role: ");
    Serial.println(role.deviceId);
    Serial.print("Payload: ");
    Serial.println(payload);

    gatewayProcess(payload);
}

void showBaselineMessage()
{
    if (baselineShown)
    {
        return;
    }

    baselineShown = true;
    Serial.println("Message received: Hello from Node 001");
}

void runFloodBurst()
{
    DeviceRole &meterRole = roleByIndex(2);
    Serial.println("Starting flood burst (30 messages)");
    for (uint8_t i = 0; i < FLOOD_MESSAGE_COUNT; i++)
    {
        emitEnvelope(meterRole, false, false);
        delay(FLOOD_GAP_MS);
    }
}

void startDemo()
{
    currentMode = MODE_DEMO;
    demoStartMs = millis();
    demoStage = 0;
    Serial.println("Starting scripted 40-second demo sequence");
}

void handleAutoMode()
{
    unsigned long now = millis();
    if (now - lastSendMs < AUTO_SEND_INTERVAL_MS)
    {
        return;
    }

    lastSendMs = now;
    emitEnvelope(autoRoleForWindow(), false, false);
}

void handleDemoMode()
{
    unsigned long elapsed = millis() - demoStartMs;

    if (demoStage == 0 && elapsed >= 0)
    {
        emitEnvelope(roleByIndex(0), false, false);
        demoStage++;
    }
    else if (demoStage == 1 && elapsed >= 10000)
    {
        emitEnvelope(roleByIndex(1), false, false);
        demoStage++;
    }
    else if (demoStage == 2 && elapsed >= 20000)
    {
        emitEnvelope(roleByIndex(2), false, false);
        demoStage++;
    }
    else if (demoStage == 3 && elapsed >= 25000)
    {
        emitEnvelope(roleByIndex(3), false, false);
        demoStage++;
    }
    else if (demoStage == 4 && elapsed >= 28000)
    {
        emitEnvelope(roleByIndex(0), true, false);
        demoStage++;
    }
    else if (demoStage == 5 && elapsed >= 32000)
    {
        runFloodBurst();
        demoStage++;
    }
    else if (demoStage == 6 && elapsed >= 38000)
    {
        emitEnvelope(roleByIndex(1), false, false);
        demoStage++;
        Serial.println("Demo sequence complete. Run SHOW_CHAIN and CHECK_CHAIN.");
    }
}

void handleManualMode()
{
    unsigned long now = millis();
    if (now - lastSendMs < AUTO_SEND_INTERVAL_MS)
    {
        return;
    }

    lastSendMs = now;

    if (currentMode == MODE_ENV)
    {
        emitEnvelope(roleByIndex(0), false, false);
    }
    else if (currentMode == MODE_TRAFFIC)
    {
        emitEnvelope(roleByIndex(1), false, false);
    }
    else if (currentMode == MODE_METER)
    {
        emitEnvelope(roleByIndex(2), false, false);
    }
    else if (currentMode == MODE_ROGUE)
    {
        emitEnvelope(roleByIndex(3), false, false);
    }
    else if (currentMode == MODE_TAMPER)
    {
        emitEnvelope(roleByIndex(0), true, false);
    }
    else if (currentMode == MODE_FLOOD)
    {
        runFloodBurst();
    }
}

void printHelp()
{
    Serial.println("\n=== SINGLE ESP32 COMMANDS ===");
    Serial.println("auto          -> cycle ENV / TRAFFIC / METER every 10s");
    Serial.println("demo          -> run scripted 40-second demo");
    Serial.println("env           -> only environmental node traffic");
    Serial.println("traffic       -> only traffic node traffic");
    Serial.println("meter         -> only smart meter traffic");
    Serial.println("rogue         -> unauthorized device attack");
    Serial.println("tamper        -> signed-then-modified payload attack");
    Serial.println("flood         -> DDoS burst using meter role");
    Serial.println("show_chain    -> print all blockchain blocks");
    Serial.println("check_chain   -> validate blockchain integrity");
    Serial.println("show_registry -> print quarantine and rate state");
    Serial.println("status        -> print current mode");
    Serial.println("help          -> show commands\n");
}

void processSerialCommands()
{
    if (!Serial.available())
    {
        return;
    }

    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    cmd.toLowerCase();

    if (cmd == "auto")
    {
        currentMode = MODE_AUTO;
        demoStage = -1;
    }
    else if (cmd == "demo")
    {
        startDemo();
        return;
    }
    else if (cmd == "env")
    {
        currentMode = MODE_ENV;
    }
    else if (cmd == "traffic")
    {
        currentMode = MODE_TRAFFIC;
    }
    else if (cmd == "meter")
    {
        currentMode = MODE_METER;
    }
    else if (cmd == "rogue")
    {
        currentMode = MODE_ROGUE;
    }
    else if (cmd == "tamper")
    {
        currentMode = MODE_TAMPER;
    }
    else if (cmd == "flood")
    {
        currentMode = MODE_FLOOD;
    }
    else if (cmd == "show_chain")
    {
        showChain();
        return;
    }
    else if (cmd == "check_chain")
    {
        checkChain();
        return;
    }
    else if (cmd == "show_registry")
    {
        showRegistry();
        return;
    }
    else if (cmd == "status")
    {
        Serial.print("Current mode: ");
        Serial.println(modeName(currentMode));
        return;
    }
    else
    {
        printHelp();
        return;
    }

    lastSendMs = 0;
    Serial.print("Switched mode to: ");
    Serial.println(modeName(currentMode));
}

void setup()
{
    Serial.begin(115200);
    delay(500);
    Serial.println("=== SINGLE ESP32 ZERO TRUST DEMO ===");
    Serial.println("Node and gateway are simulated internally on one board.");
    ensureWifi();
    ensureMqtt();
    createGenesisBlock();
    showBaselineMessage();
    printHelp();
    Serial.println("Blockchain initialized. Genesis block created.");
}

void loop()
{
    ensureWifi();
    ensureMqtt();
    mqttClient.loop();
    processSerialCommands();

    if (currentMode == MODE_AUTO)
    {
        handleAutoMode();
    }
    else if (currentMode == MODE_DEMO)
    {
        handleDemoMode();
    }
    else
    {
        handleManualMode();
    }

    delay(20);
}