"""Constants for the SIEM Server integration."""

DOMAIN = "siem"
NAME = "SIEM Server"
VERSION = "1.0.0"

# Configuration
CONF_MAX_EVENTS = "max_events"
CONF_RETENTION_DAYS = "retention_days"
CONF_ENABLE_SYSLOG = "enable_syslog"
CONF_SYSLOG_PORT = "syslog_port"
CONF_SYSLOG_HOST = "syslog_host"

# Defaults
DEFAULT_MAX_EVENTS = 50000
DEFAULT_RETENTION_DAYS = 30
DEFAULT_SYSLOG_PORT = 5514
DEFAULT_SYSLOG_HOST = "0.0.0.0"

# Event types - Home Assistant
EVENT_TYPE_AUTH_FAILURE = "auth_failure"
EVENT_TYPE_STATE_CHANGE = "state_change"
EVENT_TYPE_SERVICE_CALL = "service_call"
EVENT_TYPE_AUTOMATION_TRIGGER = "automation_trigger"
EVENT_TYPE_SCRIPT_RUN = "script_run"

# Event types - External devices
EVENT_TYPE_FIREWALL_BLOCK = "firewall_block"
EVENT_TYPE_FIREWALL_ALLOW = "firewall_allow"
EVENT_TYPE_IPS_ALERT = "ips_alert"
EVENT_TYPE_ATP_ALERT = "atp_alert"
EVENT_TYPE_VPN_CONNECTION = "vpn_connection"
EVENT_TYPE_WIFI_CLIENT = "wifi_client"
EVENT_TYPE_NETWORK_AUTH = "network_auth"

# Services
SERVICE_QUERY_EVENTS = "query_events"
SERVICE_CLEAR_EVENTS = "clear_events"
SERVICE_GET_STATS = "get_stats"

# Attributes
ATTR_EVENT_TYPE = "event_type"
ATTR_ENTITY_ID = "entity_id"
ATTR_USER_ID = "user_id"
ATTR_TIMESTAMP = "timestamp"
ATTR_SEVERITY = "severity"
ATTR_MESSAGE = "message"
ATTR_DATA = "data"

# Severity levels
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
