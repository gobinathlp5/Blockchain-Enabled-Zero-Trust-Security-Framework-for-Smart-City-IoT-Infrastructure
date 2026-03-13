from collections import deque
import datetime
import json

import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import paho.mqtt.client as mqtt

from .config import MQTT_BROKER, MQTT_PORT, OUTPUT_TOPIC

# Data buffers
time_data = deque(maxlen=50)
temp_data = deque(maxlen=50)
hum_data = deque(maxlen=50)
status_data = deque(maxlen=50)
device_data = deque(maxlen=50)
reason_data = deque(maxlen=50)
signature_data = deque(maxlen=50)
hash_data = deque(maxlen=50)
device_type_data = deque(maxlen=50)
payload_preview_data = deque(maxlen=50)


def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        return

    required_fields = [
        "device_id",
        "temperature",
        "humidity",
        "signature",
        "event_hash",
        "verified",
        "reason",
        "timestamp",
    ]
    if any(field not in payload for field in required_fields):
        return

    device_id = payload["device_id"]
    temperature = payload["temperature"]
    humidity = payload["humidity"]
    verified = payload["verified"]
    reason = payload["reason"]
    signature = payload["signature"]
    event_hash = payload["event_hash"]
    device_type = payload.get("device_type", "unknown")
    payload_preview = payload.get("payload_preview", "No payload summary")
    # Use laptop local time — ESP32 has no RTC/NTP so its timestamp is unreliable
    time_data.append(pd.Timestamp(datetime.datetime.now()))
    temp_data.append(temperature)
    hum_data.append(humidity)
    status_data.append("Valid" if verified else "Tampered")
    device_data.append(device_id)
    reason_data.append(reason)
    signature_data.append(signature)
    hash_data.append(event_hash)
    device_type_data.append(device_type)
    payload_preview_data.append(payload_preview)


def create_app():
    client = mqtt.Client()
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.subscribe(OUTPUT_TOPIC)
    client.loop_start()

    app = dash.Dash(__name__)
    shell_style = {
        "maxWidth": "1200px",
        "margin": "0 auto",
        "padding": "24px 20px 40px",
        "fontFamily": '"Segoe UI", "Helvetica Neue", sans-serif',
        "color": "#10233a",
    }
    section_style = {
        "backgroundColor": "#ffffff",
        "border": "1px solid #d8e1ea",
        "borderRadius": "14px",
        "padding": "18px",
        "boxShadow": "0 10px 28px rgba(16, 35, 58, 0.08)",
    }
    app.layout = html.Div(
        [
            html.Div(
                [
                    html.Div(
                        [
                            html.P(
                                "Zero Trust Security Operations Console",
                                style={"margin": "0 0 6px", "fontSize": "14px", "fontWeight": "600", "letterSpacing": "1px", "textTransform": "uppercase", "color": "#2e6f95"},
                            ),
                            html.H1(
                                "Smart City IoT Security Dashboard",
                                style={"margin": "0 0 10px", "fontSize": "34px", "fontWeight": "700"},
                            ),
                            html.Div(id="status", style={"fontSize": "18px", "fontWeight": "600"}),
                        ],
                        style={"marginBottom": "18px"},
                    ),
                    html.Div(
                        id="summary",
                        style={"display": "grid", "gridTemplateColumns": "repeat(auto-fit, minmax(180px, 1fr))", "gap": "12px", "marginBottom": "16px"},
                    ),
                    html.Div(
                        [
                            html.Div(id="last-event", style=section_style),
                            html.Div(id="device-hashes", style=section_style),
                        ],
                        style={"display": "grid", "gridTemplateColumns": "1.1fr 0.9fr", "gap": "16px", "marginBottom": "16px"},
                    ),
                    html.Div(
                        [
                            html.Div(id="fleet-status", style=section_style),
                            html.Div(id="alert-feed", style=section_style),
                        ],
                        style={"display": "grid", "gridTemplateColumns": "1.1fr 0.9fr", "gap": "16px", "marginBottom": "16px"},
                    ),
                    html.Div(id="recent-events", style=section_style),
                    dcc.Interval(id="update", interval=2000),
                ],
                style=shell_style,
            )
        ],
        style={"background": "linear-gradient(180deg, #eef4f8 0%, #f7fafc 100%)", "minHeight": "100vh"},
    )

    @app.callback(
        [
            Output("status", "children"),
            Output("summary", "children"),
            Output("last-event", "children"),
            Output("device-hashes", "children"),
            Output("fleet-status", "children"),
            Output("alert-feed", "children"),
            Output("recent-events", "children"),
        ],
        [Input("update", "n_intervals")],
    )
    def update_graph(_):
        total_events = len(status_data)
        valid_events = sum(1 for item in status_data if item == "Valid")
        tampered_events = total_events - valid_events
        verification_rate = 0 if total_events == 0 else round((valid_events / total_events) * 100)
        devices_seen = sorted(set(device_data))

        if total_events == 0:
            status = "Monitoring active. Waiting for inbound telemetry."
            last_event = [
                html.H3("Latest Security Posture", style={"marginTop": "0"}),
                html.P("No events received yet.", style={"margin": "0", "fontSize": "16px"}),
            ]
        else:
            latest_status = status_data[-1]
            latest_device = device_data[-1]
            latest_reason = reason_data[-1]
            latest_signature = signature_data[-1]
            latest_hash = hash_data[-1]
            latest_type = device_type_data[-1]
            latest_preview = payload_preview_data[-1]
            latest_time = pd.Timestamp(time_data[-1]).strftime("%Y-%m-%d %H:%M:%S")

            if latest_status == "Valid":
                status = "System state: secure. Latest event passed all verification checks."
            else:
                status = "System state: attention required. Latest event was rejected or flagged."

            last_event = [
                html.H3("Latest Security Posture", style={"marginTop": "0", "marginBottom": "12px"}),
                html.Div(
                    [
                        html.Div(f"Device: {latest_device}", style={"fontWeight": "700", "fontSize": "20px", "marginBottom": "8px"}),
                        html.Div(f"Type: {latest_type}", style={"marginBottom": "6px"}),
                        html.Div(f"Decision: {latest_status}", style={"marginBottom": "6px"}),
                        html.Div(f"Reason: {latest_reason}", style={"marginBottom": "6px"}),
                        html.Div(f"Payload: {latest_preview}", style={"marginBottom": "6px"}),
                        html.Div(f"Time: {latest_time}", style={"marginBottom": "12px"}),
                        html.Div("Signature", style={"fontWeight": "600", "marginBottom": "4px"}),
                        html.Div(latest_signature, style={"fontFamily": "monospace", "wordBreak": "break-all", "marginBottom": "12px", "fontSize": "12px"}),
                        html.Div("Hash", style={"fontWeight": "600", "marginBottom": "4px"}),
                        html.Div(latest_hash, style={"fontFamily": "monospace", "wordBreak": "break-all", "fontSize": "12px"}),
                    ]
                ),
            ]

        latest_hash_per_device = {}
        latest_status_per_device = {}
        latest_reason_per_device = {}
        latest_time_per_device = {}
        latest_preview_per_device = {}
        for dev, event_hash, event_status, event_reason, event_time in zip(
            reversed(device_data),
            reversed(hash_data),
            reversed(status_data),
            reversed(reason_data),
            reversed(time_data),
        ):
            if dev not in latest_hash_per_device:
                latest_hash_per_device[dev] = event_hash
                latest_status_per_device[dev] = event_status
                latest_reason_per_device[dev] = event_reason
                latest_time_per_device[dev] = pd.Timestamp(event_time).strftime("%Y-%m-%d %H:%M:%S")

        for dev, preview in zip(reversed(device_data), reversed(payload_preview_data)):
            if dev not in latest_preview_per_device:
                latest_preview_per_device[dev] = preview

        device_hashes = [
            html.H3("Device Hash Registry", style={"marginTop": "0", "marginBottom": "10px"}),
            html.Ul(
                [
                    html.Li(
                        f"{device_id}: {event_hash}",
                        style={"fontFamily": "monospace", "marginBottom": "6px", "wordBreak": "break-all"},
                    )
                    for device_id, event_hash in latest_hash_per_device.items()
                ],
                style={"paddingLeft": "22px"},
            ),
        ]

        fleet_rows = [
            html.Tr(
                [
                    html.Th("Device", style={"textAlign": "left", "padding": "10px"}),
                    html.Th("Latest Status", style={"textAlign": "left", "padding": "10px"}),
                    html.Th("Reason", style={"textAlign": "left", "padding": "10px"}),
                    html.Th("Payload", style={"textAlign": "left", "padding": "10px"}),
                    html.Th("Last Seen", style={"textAlign": "left", "padding": "10px"}),
                ],
                style={"backgroundColor": "#eff5f9"},
            )
        ]
        for device_id in devices_seen:
            fleet_rows.append(
                html.Tr(
                    [
                        html.Td(device_id, style={"padding": "10px", "fontWeight": "600"}),
                        html.Td(latest_status_per_device.get(device_id, "Unknown"), style={"padding": "10px"}),
                        html.Td(latest_reason_per_device.get(device_id, "Unknown"), style={"padding": "10px"}),
                        html.Td(latest_preview_per_device.get(device_id, "-"), style={"padding": "10px"}),
                        html.Td(latest_time_per_device.get(device_id, "-"), style={"padding": "10px"}),
                    ],
                    style={"borderTop": "1px solid #e5edf4"},
                )
            )

        fleet_status = [
            html.H3("Fleet Status", style={"marginTop": "0", "marginBottom": "10px"}),
            html.Table(fleet_rows, style={"width": "100%", "borderCollapse": "collapse", "fontSize": "14px"}),
        ]

        alert_items = []
        for index in range(total_events - 1, -1, -1):
            if status_data[index] == "Tampered":
                event_time = pd.Timestamp(time_data[index]).strftime("%Y-%m-%d %H:%M:%S")
                alert_items.append(
                    html.Li(
                        f"{event_time} | {device_data[index]} | {reason_data[index]}",
                        style={"marginBottom": "8px"},
                    )
                )
            if len(alert_items) == 6:
                break

        alert_feed = [
            html.H3("Alert Feed", style={"marginTop": "0", "marginBottom": "10px"}),
            html.Div(
                "Latest rejected, tampered, or suspicious device activity.",
                style={"fontSize": "14px", "marginBottom": "10px", "color": "#4b5d73"},
            ),
            html.Ul(alert_items, style={"paddingLeft": "22px", "margin": "0"}) if alert_items else html.Div("No active alerts.", style={"fontWeight": "600", "color": "#2f6b3b"}),
        ]

        if total_events == 0:
            recent_events = [html.Div("No recent events", style={"textAlign": "center"})]
        else:
            recent_rows = [
                html.Tr(
                    [
                        html.Th("Time", style={"textAlign": "left", "padding": "10px"}),
                        html.Th("Device", style={"textAlign": "left", "padding": "10px"}),
                        html.Th("Type", style={"textAlign": "left", "padding": "10px"}),
                        html.Th("Status", style={"textAlign": "left", "padding": "10px"}),
                        html.Th("Reason", style={"textAlign": "left", "padding": "10px"}),
                        html.Th("Payload", style={"textAlign": "left", "padding": "10px"}),
                        html.Th("Hash", style={"textAlign": "left", "padding": "10px"}),
                    ],
                    style={"backgroundColor": "#eff5f9"},
                )
            ]
            start_index = max(0, total_events - 10)
            for index in range(total_events - 1, start_index - 1, -1):
                event_time = pd.Timestamp(time_data[index]).strftime("%Y-%m-%d %H:%M:%S")
                recent_rows.append(
                    html.Tr(
                        [
                            html.Td(event_time, style={"padding": "10px"}),
                            html.Td(device_data[index], style={"padding": "10px", "fontWeight": "600"}),
                            html.Td(device_type_data[index], style={"padding": "10px"}),
                            html.Td(status_data[index], style={"padding": "10px"}),
                            html.Td(reason_data[index], style={"padding": "10px"}),
                            html.Td(payload_preview_data[index], style={"padding": "10px"}),
                            html.Td(hash_data[index][:18] + "...", style={"padding": "10px", "fontFamily": "monospace"}),
                        ],
                        style={"borderTop": "1px solid #e5edf4"},
                    )
                )

            recent_events = [
                html.H3("Recent Event Log", style={"marginTop": "0", "marginBottom": "10px"}),
                html.Div(
                    "Most recent telemetry and security decisions across the monitored fleet.",
                    style={"fontSize": "14px", "marginBottom": "10px", "color": "#4b5d73"},
                ),
                html.Table(recent_rows, style={"width": "100%", "borderCollapse": "collapse", "fontSize": "14px"}),
            ]

        summary = [
            html.Div(
                [html.Div("Total Events", style={"fontSize": "13px", "color": "#597089"}), html.Div(str(total_events), style={"fontSize": "30px", "fontWeight": "700"})],
                style={"padding": "14px", "border": "1px solid #d8e1ea", "borderRadius": "12px", "backgroundColor": "#ffffff", "boxShadow": "0 8px 22px rgba(16, 35, 58, 0.06)"},
            ),
            html.Div(
                [html.Div("Verified", style={"fontSize": "13px", "color": "#597089"}), html.Div(str(valid_events), style={"fontSize": "30px", "fontWeight": "700", "color": "#24613d"})],
                style={"padding": "14px", "border": "1px solid #d8e1ea", "borderRadius": "12px", "backgroundColor": "#ffffff", "boxShadow": "0 8px 22px rgba(16, 35, 58, 0.06)"},
            ),
            html.Div(
                [html.Div("Rejected", style={"fontSize": "13px", "color": "#597089"}), html.Div(str(tampered_events), style={"fontSize": "30px", "fontWeight": "700", "color": "#a33636"})],
                style={"padding": "14px", "border": "1px solid #d8e1ea", "borderRadius": "12px", "backgroundColor": "#ffffff", "boxShadow": "0 8px 22px rgba(16, 35, 58, 0.06)"},
            ),
            html.Div(
                [html.Div("Devices Seen", style={"fontSize": "13px", "color": "#597089"}), html.Div(str(len(devices_seen)), style={"fontSize": "30px", "fontWeight": "700"})],
                style={"padding": "14px", "border": "1px solid #d8e1ea", "borderRadius": "12px", "backgroundColor": "#ffffff", "boxShadow": "0 8px 22px rgba(16, 35, 58, 0.06)"},
            ),
            html.Div(
                [html.Div("Verification Rate", style={"fontSize": "13px", "color": "#597089"}), html.Div(f"{verification_rate}%", style={"fontSize": "30px", "fontWeight": "700"})],
                style={"padding": "14px", "border": "1px solid #d8e1ea", "borderRadius": "12px", "backgroundColor": "#ffffff", "boxShadow": "0 8px 22px rgba(16, 35, 58, 0.06)"},
            ),
        ]

        return status, summary, last_event, device_hashes, fleet_status, alert_feed, recent_events

    return app


def main():
    app = create_app()
    app.run(debug=False)


if __name__ == "__main__":
    main()
