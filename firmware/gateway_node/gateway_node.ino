#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

const char *WIFI_SSID = "Omnitrix";
const char *WIFI_PASSWORD = "12345678";
const char *MQTT_HOST = "broker.hivemq.com";
const uint16_t MQTT_PORT = 1883;
const char *MQTT_TOPIC_DATA = "smartcity/iot";
const char *MQTT_TOPIC_TEST = "smartcity/test";
const char *DASHBOARD_TOPIC = "zerotrust/gobinath/iot/verified";

const uint8_t MAX_MESSAGES_PER_MINUTE = 20;
const uint8_t MAX_RATE_HISTORY = 24;
const uint16_t MAX_BLOCKS = 100;
const char *GENESIS_PREVIOUS_HASH = "0000000000000000";

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

DeviceRecord deviceRegistry[] = {
    {"ENV_NODE_001", "env_secret_key_2025", MAX_MESSAGES_PER_MINUTE, false, {0}, 0},
    {"TRAFFIC_NODE_001", "traffic_secret_key_2025", MAX_MESSAGES_PER_MINUTE, false, {0}, 0},
    {"METER_NODE_001", "meter_secret_key_2025", MAX_MESSAGES_PER_MINUTE, false, {0}, 0},
};

WiFiClient subscriberNetwork;
PubSubClient subscriberClient(subscriberNetwork);

Block blockchain[MAX_BLOCKS];
uint16_t blockCount = 0;

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
    if (!subscriberClient.connected())
    {
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

    if (!subscriberClient.publish(DASHBOARD_TOPIC, body.c_str()))
    {
        Serial.println("⚠️ Failed to publish dashboard event");
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

void printHelp()
{
    Serial.println("\n=== GATEWAY COMMANDS ===");
    Serial.println("SHOW_CHAIN   -> print all blockchain blocks");
    Serial.println("CHECK_CHAIN  -> verify blockchain integrity");
    Serial.println("SHOW_REGISTRY -> print device registry state");
    Serial.println("HELP         -> show commands\n");
}

void handleDataMessage(byte *payload, unsigned int length)
{
    String raw;
    raw.reserve(length + 1);
    for (unsigned int i = 0; i < length; i++)
    {
        raw += static_cast<char>(payload[i]);
    }

    Serial.print("Payload: ");
    Serial.println(raw);

    StaticJsonDocument<768> wrapperDoc;
    DeserializationError err = deserializeJson(wrapperDoc, raw);
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

    Serial.print("📨 Message from: ");
    Serial.println(deviceId);

    DeviceRecord *device = findDevice(deviceId);
    if (device == nullptr)
    {
        String eventHash = sha256Hex(raw);
        String payloadPreview = summarizePayload(type, payloadValues);
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, eventHash, false, "UNKNOWN_DEVICE", timestamp, payloadPreview);
        Serial.println("🚫 CHECK 1 FAILED — Unknown device");
        return;
    }
    if (device->quarantined)
    {
        String eventHash = sha256Hex(raw);
        String payloadPreview = summarizePayload(type, payloadValues);
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, eventHash, false, "QUARANTINED", timestamp, payloadPreview);
        Serial.println("🚫 CHECK 1 FAILED — Device quarantined");
        return;
    }
    Serial.println("✅ CHECK 1 PASSED — Device registered");

    String canonicalData;
    serializeJson(data, canonicalData);
    String expectedSignature = hmacSha256(device->secretKey, canonicalData);
    if (expectedSignature != receivedSignature)
    {
        device->quarantined = true;
        String eventHash = sha256Hex(raw);
        String payloadPreview = summarizePayload(type, payloadValues);
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, eventHash, false, "BAD_SIGNATURE", timestamp, payloadPreview);
        Serial.println("🚫 CHECK 2 FAILED — Bad signature -> QUARANTINED");
        return;
    }
    Serial.println("✅ CHECK 2 PASSED — Signature valid");

    unsigned long now = millis();
    if (exceedsRateLimit(*device, now))
    {
        device->quarantined = true;
        String eventHash = sha256Hex(raw);
        String payloadPreview = summarizePayload(type, payloadValues);
        publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, eventHash, false, "RATE_EXCEEDED", timestamp, payloadPreview);
        Serial.println("🚫 CHECK 3 FAILED — Rate Exceeded -> QUARANTINED");
        return;
    }
    recordMessage(*device, now);
    Serial.println("✅ CHECK 3 PASSED — Rate within limit");

    String preview = summarizePayload(type, payloadValues);
    addBlock(deviceId, type, canonicalData, preview, timestamp);
    String blockHash = (blockCount > 0) ? blockchain[blockCount - 1].hash : sha256Hex(raw);
    publishDashboardEvent(deviceId, type, payloadValues, receivedSignature, blockHash, true, "OK", timestamp, preview);

    Serial.print("✅ AUTHENTICATED — ");
    Serial.println(preview);
}

void mqttCallback(char *topic, byte *payload, unsigned int length)
{
    String topicName(topic);
    if (topicName == MQTT_TOPIC_TEST)
    {
        String message;
        for (unsigned int i = 0; i < length; i++)
        {
            message += static_cast<char>(payload[i]);
        }
        Serial.print("Message received: ");
        Serial.println(message);
        return;
    }

    if (topicName == MQTT_TOPIC_DATA)
    {
        handleDataMessage(payload, length);
    }
}

void ensureSubscriberConnected()
{
    if (subscriberClient.connected())
    {
        return;
    }

    subscriberClient.setServer(MQTT_HOST, MQTT_PORT);
    subscriberClient.setCallback(mqttCallback);
    subscriberClient.setBufferSize(1024);

    while (!subscriberClient.connected())
    {
        String clientId = "zta-gateway-" + String(static_cast<uint32_t>(esp_random()), HEX);
        if (subscriberClient.connect(clientId.c_str()))
        {
            subscriberClient.subscribe("smartcity/#");
            Serial.println("Gateway subscriber connected to MQTT broker");
            return;
        }

        Serial.println("Retrying gateway subscriber connection in 1s");
        delay(1000);
    }
}

void processSerialCommands()
{
    if (!Serial.available())
    {
        return;
    }

    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    cmd.toUpperCase();

    if (cmd == "SHOW_CHAIN")
    {
        showChain();
    }
    else if (cmd == "CHECK_CHAIN")
    {
        checkChain();
    }
    else if (cmd == "SHOW_REGISTRY")
    {
        showRegistry();
    }
    else
    {
        printHelp();
    }
}

void setup()
{
    Serial.begin(115200);
    delay(500);

    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("Connecting to WiFi");
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 40)
    {
        delay(250);
        Serial.print(".");
        attempts++;
    }
    Serial.println();

    Serial.println("=== ZERO TRUST GATEWAY ACTIVE ===");
    if (WiFi.status() == WL_CONNECTED)
    {
        Serial.print("Gateway IP: ");
        Serial.println(WiFi.localIP());
    }
    else
    {
        Serial.println("WiFi connection failed");
    }

    createGenesisBlock();
    ensureSubscriberConnected();
    printHelp();

    Serial.println("Blockchain initialized. Genesis block created.");
}

void loop()
{
    ensureSubscriberConnected();
    subscriberClient.loop();
    processSerialCommands();
    delay(10);
}
