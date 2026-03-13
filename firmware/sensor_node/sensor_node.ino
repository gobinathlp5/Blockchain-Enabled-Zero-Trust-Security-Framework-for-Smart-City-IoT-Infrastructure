#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>

const char *WIFI_SSID = "Omnitrix";
const char *WIFI_PASSWORD = "12345678";
const char *MQTT_HOST = "broker.hivemq.com";
const uint16_t MQTT_PORT = 1883;
const char *MQTT_TOPIC_DATA = "smartcity/iot";
const char *MQTT_TOPIC_TEST = "smartcity/test";

const unsigned long AUTO_SEND_INTERVAL_MS = 10000;
const unsigned long FLOOD_GAP_MS = 150;
const uint8_t FLOOD_MESSAGE_COUNT = 30;

struct DeviceRole
{
    const char *deviceId;
    const char *type;
    const char *secretKey;
    bool authorized;
};

DeviceRole deviceRoles[] = {
    {"ENV_NODE_001", "environmental", "env_secret_key_2025", true},
    {"TRAFFIC_NODE_001", "traffic", "traffic_secret_key_2025", true},
    {"METER_NODE_001", "meter", "meter_secret_key_2025", true},
    {"ROGUE_DEVICE_999", "rogue", "", false},
};

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

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);

Mode currentMode = MODE_AUTO;
unsigned long lastSendMs = 0;
unsigned long demoStartMs = 0;
int demoStage = -1;
bool helloPublished = false;

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

void publishEnvelope(const DeviceRole &role, bool tamperPayload, bool forceBadSignature)
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

    mqttClient.publish(MQTT_TOPIC_DATA, payload.c_str());

    Serial.print("TX Mode: ");
    Serial.println(modeName(currentMode));
    Serial.print("Role: ");
    Serial.println(role.deviceId);
    Serial.print("Payload: ");
    Serial.println(payload);
}

void publishHelloMessage()
{
    if (helloPublished || !mqttClient.connected())
    {
        return;
    }

    mqttClient.publish(MQTT_TOPIC_TEST, "Hello from Node 001");
    helloPublished = true;
    Serial.println("Baseline test message published to smartcity/test");
}

void ensureWifi()
{
    if (WiFi.status() == WL_CONNECTED)
    {
        return;
    }

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    Serial.print("Connecting to gateway AP");
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 40)
    {
        delay(250);
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
        Serial.println("WiFi connection failed");
    }
}

void ensureMqtt()
{
    if (mqttClient.connected())
    {
        return;
    }

    mqttClient.setServer(MQTT_HOST, MQTT_PORT);
    mqttClient.setBufferSize(1024);

    while (!mqttClient.connected() && WiFi.status() == WL_CONNECTED)
    {
        String clientId = "sensor-node-" + String(static_cast<uint32_t>(esp_random()), HEX);
        Serial.print("Connecting to MQTT broker...");
        if (mqttClient.connect(clientId.c_str()))
        {
            Serial.println("connected");
            helloPublished = false;
            publishHelloMessage();
            return;
        }

        Serial.println("retrying in 1s");
        delay(1000);
    }
}

void startDemo()
{
    currentMode = MODE_DEMO;
    demoStartMs = millis();
    demoStage = 0;
    Serial.println("Starting scripted 40-second demo sequence");
}

void runFloodBurst()
{
    DeviceRole &meterRole = roleByIndex(2);
    Serial.println("Starting flood burst (30 messages)");
    for (uint8_t i = 0; i < FLOOD_MESSAGE_COUNT; i++)
    {
        ensureWifi();
        ensureMqtt();
        mqttClient.loop();
        publishEnvelope(meterRole, false, false);
        delay(FLOOD_GAP_MS);
    }
}

void handleAutoMode()
{
    unsigned long now = millis();
    if (now - lastSendMs < AUTO_SEND_INTERVAL_MS)
    {
        return;
    }

    lastSendMs = now;
    publishEnvelope(autoRoleForWindow(), false, false);
}

void handleDemoMode()
{
    unsigned long elapsed = millis() - demoStartMs;

    if (demoStage == 0 && elapsed >= 0)
    {
        publishEnvelope(roleByIndex(0), false, false);
        demoStage++;
    }
    else if (demoStage == 1 && elapsed >= 10000)
    {
        publishEnvelope(roleByIndex(1), false, false);
        demoStage++;
    }
    else if (demoStage == 2 && elapsed >= 20000)
    {
        publishEnvelope(roleByIndex(2), false, false);
        demoStage++;
    }
    else if (demoStage == 3 && elapsed >= 25000)
    {
        publishEnvelope(roleByIndex(3), false, false);
        demoStage++;
    }
    else if (demoStage == 4 && elapsed >= 28000)
    {
        publishEnvelope(roleByIndex(0), true, false);
        demoStage++;
    }
    else if (demoStage == 5 && elapsed >= 32000)
    {
        runFloodBurst();
        demoStage++;
    }
    else if (demoStage == 6 && elapsed >= 38000)
    {
        publishEnvelope(roleByIndex(1), false, false);
        demoStage++;
        Serial.println("Demo sequence complete. Run SHOW_CHAIN and CHECK_CHAIN on gateway.");
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
        publishEnvelope(roleByIndex(0), false, false);
    }
    else if (currentMode == MODE_TRAFFIC)
    {
        publishEnvelope(roleByIndex(1), false, false);
    }
    else if (currentMode == MODE_METER)
    {
        publishEnvelope(roleByIndex(2), false, false);
    }
    else if (currentMode == MODE_ROGUE)
    {
        publishEnvelope(roleByIndex(3), false, false);
    }
    else if (currentMode == MODE_TAMPER)
    {
        publishEnvelope(roleByIndex(0), true, false);
    }
    else if (currentMode == MODE_FLOOD)
    {
        runFloodBurst();
    }
}

void printHelp()
{
    Serial.println("\n=== SENSOR NODE COMMANDS ===");
    Serial.println("auto     -> cycle ENV, TRAFFIC, METER every 10s");
    Serial.println("demo     -> run scripted 40-second attack demo");
    Serial.println("env      -> publish environmental node messages");
    Serial.println("traffic  -> publish traffic node messages");
    Serial.println("meter    -> publish meter node messages");
    Serial.println("rogue    -> publish rogue device messages");
    Serial.println("tamper   -> publish a signed-then-modified payload");
    Serial.println("flood    -> send 30 high-rate meter messages");
    Serial.println("status   -> print current mode");
    Serial.println("help     -> show commands\n");
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
    delay(400);
    ensureWifi();
    ensureMqtt();
    printHelp();
}

void loop()
{
    ensureWifi();
    ensureMqtt();
    mqttClient.loop();
    publishHelloMessage();
    processSerialCommands();

    if (!mqttClient.connected())
    {
        delay(50);
        return;
    }

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
