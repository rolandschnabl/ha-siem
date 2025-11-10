"""Lovelace dashboard configuration for SIEM."""
from typing import Any, Dict

SIEM_DASHBOARD_CONFIG = {
    "views": [
        {
            "title": "SIEM Security",
            "icon": "mdi:shield-check",
            "path": "siem",
            "badges": [],
            "cards": [
                {
                    "type": "vertical-stack",
                    "cards": [
                {
                    "type": "markdown",
                    "title": "🛡️ SIEM Security Center",
                    "content": (
                        "**Security Information and Event Management**\n\n"
                        "Monitoring Home Assistant and external devices (Sophos XGS, UniFi)"
                    ),
                },
                {
                    "type": "glance",
                    "title": "Event Summary",
                    "columns": 5,
                    "state_color": True,
                    "entities": [
                        {
                            "entity": "sensor.siem_total_events",
                            "name": "Total",
                        },
                        {
                            "entity": "sensor.siem_critical_events",
                            "name": "Critical",
                        },
                        {
                            "entity": "sensor.siem_high_events",
                            "name": "High",
                        },
                        {
                            "entity": "sensor.siem_medium_events",
                            "name": "Medium",
                        },
                        {
                            "entity": "sensor.siem_low_events",
                            "name": "Low",
                        },
                    ],
                },
                    ],
                },
                {
                    "type": "horizontal-stack",
                    "cards": [
                {
                    "type": "entities",
                    "title": "Home Assistant Events",
                    "entities": [
                        {
                            "entity": "sensor.siem_auth_failures",
                            "icon": "mdi:shield-alert",
                        },
                        {
                            "entity": "sensor.siem_state_changes",
                            "icon": "mdi:state-machine",
                        },
                        {
                            "entity": "sensor.siem_service_calls",
                            "icon": "mdi:cog",
                        },
                    ],
                },
                {
                    "type": "entities",
                    "title": "External Device Events",
                    "entities": [
                        {
                            "entity": "sensor.siem_firewall_blocks",
                            "icon": "mdi:wall-fire",
                        },
                        {
                            "entity": "sensor.siem_ips_alerts",
                            "icon": "mdi:shield-alert-outline",
                        },
                        {
                            "entity": "sensor.siem_vpn_connections",
                            "icon": "mdi:vpn",
                        },
                        {
                            "entity": "sensor.siem_wifi_clients",
                            "icon": "mdi:wifi",
                        },
                    ],
                },
                    ],
                },
                {
                    "type": "conditional",
            "conditions": [
                {
                    "entity": "sensor.siem_critical_events",
                    "state_not": "0",
                }
            ],
            "card": {
                "type": "entities",
                "title": "⚠️ CRITICAL SECURITY ALERTS",
                "state_color": True,
                    "entities": [
                        "sensor.siem_critical_events",
                    ],
                },
                },
                {
                    "type": "history-graph",
            "title": "Event Trends (24 hours)",
            "hours_to_show": 24,
            "entities": [
                {
                    "entity": "sensor.siem_critical_events",
                },
                {
                    "entity": "sensor.siem_high_events",
                },
                {
                    "entity": "sensor.siem_firewall_blocks",
                },
                    {
                        "entity": "sensor.siem_ips_alerts",
                    },
                ],
                },
                {
                    "type": "entities",
                    "title": "SIEM Actions",
            "entities": [
                {
                    "type": "button",
                    "name": "Query Recent Events (100)",
                    "icon": "mdi:database-search",
                    "action_name": "Query",
                    "tap_action": {
                        "action": "call-service",
                        "service": "siem.query_events",
                        "service_data": {
                            "limit": 100,
                        },
                    },
                },
                {
                    "type": "button",
                    "name": "Get Statistics",
                    "icon": "mdi:chart-bar",
                    "action_name": "Stats",
                    "tap_action": {
                        "action": "call-service",
                        "service": "siem.get_stats",
                    },
                },
                {
                    "type": "button",
                    "name": "Clear All Events",
                    "icon": "mdi:delete-sweep",
                    "action_name": "Clear",
                    "tap_action": {
                        "action": "call-service",
                        "service": "siem.clear_events",
                        "confirmation": {
                            "text": "Are you sure you want to clear all SIEM events?",
                        },
                    },
                    },
                ],
                },
            ],
        }
    ],
}


def get_dashboard_config() -> Dict[str, Any]:
    """Get the SIEM dashboard configuration."""
    return SIEM_DASHBOARD_CONFIG
