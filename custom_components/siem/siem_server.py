"""SIEM Server core logic."""
import logging
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional
import voluptuous as vol

from homeassistant.core import HomeAssistant, Event, callback, ServiceCall
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers import service
from homeassistant.const import (
    EVENT_STATE_CHANGED,
    EVENT_CALL_SERVICE,
    EVENT_HOMEASSISTANT_START,
    EVENT_HOMEASSISTANT_STOP,
)

from .const import (
    DOMAIN,
    CONF_MAX_EVENTS,
    CONF_RETENTION_DAYS,
    CONF_ENABLE_SYSLOG,
    CONF_SYSLOG_PORT,
    CONF_SYSLOG_HOST,
    DEFAULT_MAX_EVENTS,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_SYSLOG_PORT,
    DEFAULT_SYSLOG_HOST,
    EVENT_TYPE_AUTH_FAILURE,
    EVENT_TYPE_STATE_CHANGE,
    EVENT_TYPE_SERVICE_CALL,
    EVENT_TYPE_AUTOMATION_TRIGGER,
    EVENT_TYPE_SCRIPT_RUN,
    EVENT_TYPE_FIREWALL_BLOCK,
    EVENT_TYPE_FIREWALL_ALLOW,
    EVENT_TYPE_IPS_ALERT,
    EVENT_TYPE_VPN_CONNECTION,
    EVENT_TYPE_WIFI_CLIENT,
    EVENT_TYPE_NETWORK_AUTH,
    SERVICE_QUERY_EVENTS,
    SERVICE_CLEAR_EVENTS,
    SERVICE_GET_STATS,
    ATTR_EVENT_TYPE,
    ATTR_ENTITY_ID,
    ATTR_USER_ID,
    ATTR_TIMESTAMP,
    ATTR_SEVERITY,
    ATTR_MESSAGE,
    ATTR_DATA,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
from .syslog_server import SyslogServer
from .parsers import parse_external_device

_LOGGER = logging.getLogger(__name__)


class SiemEvent:
    """Represents a SIEM event."""

    def __init__(
        self,
        event_type: str,
        severity: str,
        message: str,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ):
        """Initialize SIEM event."""
        self.timestamp = datetime.now()
        self.event_type = event_type
        self.severity = severity
        self.message = message
        self.entity_id = entity_id
        self.user_id = user_id
        self.data = data or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            ATTR_TIMESTAMP: self.timestamp.isoformat(),
            ATTR_EVENT_TYPE: self.event_type,
            ATTR_SEVERITY: self.severity,
            ATTR_MESSAGE: self.message,
            ATTR_ENTITY_ID: self.entity_id,
            ATTR_USER_ID: self.user_id,
            ATTR_DATA: self.data,
        }


class SiemServer:
    """SIEM Server implementation."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry):
        """Initialize SIEM server."""
        self.hass = hass
        self.entry = entry
        self.events: deque = deque(maxlen=self._get_max_events())
        self.stats = defaultdict(int)
        self._listeners = []
        self._cleanup_task = None
        self._syslog_server: Optional[SyslogServer] = None

    def _get_max_events(self) -> int:
        """Get max events from config."""
        return self.entry.options.get(
            CONF_MAX_EVENTS,
            self.entry.data.get(CONF_MAX_EVENTS, DEFAULT_MAX_EVENTS),
        )

    def _get_retention_days(self) -> int:
        """Get retention days from config."""
        return self.entry.options.get(
            CONF_RETENTION_DAYS,
            self.entry.data.get(CONF_RETENTION_DAYS, DEFAULT_RETENTION_DAYS),
        )

    async def async_initialize(self):
        """Initialize the SIEM server."""
        _LOGGER.info("Initializing SIEM Server")

        # Register event listeners
        self._listeners.append(
            self.hass.bus.async_listen(EVENT_STATE_CHANGED, self._handle_state_changed)
        )
        self._listeners.append(
            self.hass.bus.async_listen(EVENT_CALL_SERVICE, self._handle_service_call)
        )
        self._listeners.append(
            self.hass.bus.async_listen(
                "automation_triggered", self._handle_automation_triggered
            )
        )
        self._listeners.append(
            self.hass.bus.async_listen("script_started", self._handle_script_started)
        )
        self._listeners.append(
            self.hass.bus.async_listen(
                "persistent_notifications", self._handle_notification
            )
        )

        # Register services
        self._register_services()

        # Start syslog server if enabled
        if self._is_syslog_enabled():
            await self._start_syslog_server()

        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_old_events())

        _LOGGER.info("SIEM Server initialized successfully")

    async def async_shutdown(self):
        """Shutdown the SIEM server."""
        _LOGGER.info("Shutting down SIEM Server")

        # Stop syslog server
        if self._syslog_server:
            await self._syslog_server.stop()

        # Remove event listeners
        for remove_listener in self._listeners:
            remove_listener()
        self._listeners.clear()

        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    def _is_syslog_enabled(self) -> bool:
        """Check if syslog server is enabled."""
        return self.entry.options.get(
            CONF_ENABLE_SYSLOG,
            self.entry.data.get(CONF_ENABLE_SYSLOG, True),
        )

    def _get_syslog_port(self) -> int:
        """Get syslog server port."""
        return self.entry.options.get(
            CONF_SYSLOG_PORT,
            self.entry.data.get(CONF_SYSLOG_PORT, DEFAULT_SYSLOG_PORT),
        )

    def _get_syslog_host(self) -> str:
        """Get syslog server host."""
        return self.entry.options.get(
            CONF_SYSLOG_HOST,
            self.entry.data.get(CONF_SYSLOG_HOST, DEFAULT_SYSLOG_HOST),
        )

    async def _start_syslog_server(self):
        """Start the syslog server for external devices."""
        try:
            host = self._get_syslog_host()
            port = self._get_syslog_port()
            
            self._syslog_server = SyslogServer(
                host=host,
                port=port,
                callback=self._handle_syslog_event,
            )
            
            await self._syslog_server.start()
            _LOGGER.info("Syslog server started on %s:%d for external devices", host, port)
            
        except Exception as err:
            _LOGGER.error("Failed to start syslog server: %s", err)
            self._syslog_server = None

    async def _handle_syslog_event(self, syslog_data: dict):
        """Handle syslog event from external device.
        
        Args:
            syslog_data: Raw syslog data from syslog_server
        """
        try:
            # Parse the syslog message using device-specific parsers
            parsed_event = parse_external_device(syslog_data)
            
            if parsed_event:
                # Create SIEM event from parsed data
                siem_event = SiemEvent(
                    event_type=parsed_event.get("event_type", "external_event"),
                    severity=parsed_event.get("severity", SEVERITY_LOW),
                    message=parsed_event.get("message", "External device event"),
                    entity_id=parsed_event.get("entity_id"),
                    user_id=parsed_event.get("user_id"),
                    data={
                        **parsed_event.get("data", {}),
                        "device_type": parsed_event.get("device_type", "unknown"),
                        "hostname": parsed_event.get("hostname", "unknown"),
                        "source_ip": parsed_event.get("source_ip", "unknown"),
                    },
                )
                
                self._add_event(siem_event)
                
                _LOGGER.debug(
                    "External device event: %s from %s",
                    parsed_event.get("event_type"),
                    parsed_event.get("source_ip"),
                )
            
        except Exception as err:
            _LOGGER.error("Error handling syslog event: %s", err)

    def _register_services(self):
        """Register SIEM services."""
        
        # Query events service
        self.hass.services.async_register(
            DOMAIN,
            SERVICE_QUERY_EVENTS,
            self._handle_query_events,
            schema=vol.Schema({
                vol.Optional(ATTR_EVENT_TYPE): str,
                vol.Optional(ATTR_ENTITY_ID): str,
                vol.Optional(ATTR_SEVERITY): str,
                vol.Optional("limit", default=100): vol.Coerce(int),
            }),
        )

        # Clear events service
        self.hass.services.async_register(
            DOMAIN,
            SERVICE_CLEAR_EVENTS,
            self._handle_clear_events,
        )

        # Get stats service
        self.hass.services.async_register(
            DOMAIN,
            SERVICE_GET_STATS,
            self._handle_get_stats,
        )

    @callback
    def _handle_state_changed(self, event: Event):
        """Handle state changed events."""
        entity_id = event.data.get("entity_id")
        old_state = event.data.get("old_state")
        new_state = event.data.get("new_state")

        if old_state is None or new_state is None:
            return

        # Track state changes for security-relevant entities
        if self._is_security_entity(entity_id):
            severity = self._calculate_severity(entity_id, old_state, new_state)
            siem_event = SiemEvent(
                event_type=EVENT_TYPE_STATE_CHANGE,
                severity=severity,
                message=f"State changed: {entity_id} from {old_state.state} to {new_state.state}",
                entity_id=entity_id,
                data={
                    "old_state": old_state.state,
                    "new_state": new_state.state,
                },
            )
            self._add_event(siem_event)

    @callback
    def _handle_service_call(self, event: Event):
        """Handle service call events."""
        domain = event.data.get("domain")
        service_name = event.data.get("service")
        service_data = event.data.get("service_data", {})

        # Track security-relevant service calls
        if self._is_security_service(domain, service_name):
            siem_event = SiemEvent(
                event_type=EVENT_TYPE_SERVICE_CALL,
                severity=SEVERITY_MEDIUM,
                message=f"Service called: {domain}.{service_name}",
                data={
                    "domain": domain,
                    "service": service_name,
                    "service_data": service_data,
                },
            )
            self._add_event(siem_event)

    @callback
    def _handle_automation_triggered(self, event: Event):
        """Handle automation triggered events."""
        name = event.data.get("name")
        entity_id = event.data.get("entity_id")

        siem_event = SiemEvent(
            event_type=EVENT_TYPE_AUTOMATION_TRIGGER,
            severity=SEVERITY_LOW,
            message=f"Automation triggered: {name}",
            entity_id=entity_id,
            data=event.data,
        )
        self._add_event(siem_event)

    @callback
    def _handle_script_started(self, event: Event):
        """Handle script started events."""
        name = event.data.get("name")
        entity_id = event.data.get("entity_id")

        siem_event = SiemEvent(
            event_type=EVENT_TYPE_SCRIPT_RUN,
            severity=SEVERITY_LOW,
            message=f"Script started: {name}",
            entity_id=entity_id,
            data=event.data,
        )
        self._add_event(siem_event)

    @callback
    def _handle_notification(self, event: Event):
        """Handle notification events for auth failures."""
        message = event.data.get("message", "")
        
        # Detect authentication failures
        if "login" in message.lower() and ("fail" in message.lower() or "invalid" in message.lower()):
            siem_event = SiemEvent(
                event_type=EVENT_TYPE_AUTH_FAILURE,
                severity=SEVERITY_HIGH,
                message=f"Authentication failure detected: {message}",
                data=event.data,
            )
            self._add_event(siem_event)

    def _is_security_entity(self, entity_id: str) -> bool:
        """Check if entity is security-relevant."""
        security_domains = [
            "alarm_control_panel",
            "lock",
            "binary_sensor",
            "camera",
            "person",
            "device_tracker",
        ]
        domain = entity_id.split(".")[0] if "." in entity_id else ""
        return domain in security_domains

    def _is_security_service(self, domain: str, service: str) -> bool:
        """Check if service call is security-relevant."""
        security_services = [
            ("alarm_control_panel", "alarm_arm_away"),
            ("alarm_control_panel", "alarm_arm_home"),
            ("alarm_control_panel", "alarm_disarm"),
            ("lock", "lock"),
            ("lock", "unlock"),
            ("homeassistant", "restart"),
            ("homeassistant", "stop"),
        ]
        return (domain, service) in security_services

    def _calculate_severity(self, entity_id: str, old_state, new_state) -> str:
        """Calculate severity based on state change."""
        domain = entity_id.split(".")[0] if "." in entity_id else ""
        
        if domain == "alarm_control_panel":
            if new_state.state == "triggered":
                return SEVERITY_CRITICAL
            elif new_state.state in ["armed_away", "armed_home"]:
                return SEVERITY_MEDIUM
        
        elif domain == "lock":
            if old_state.state == "locked" and new_state.state == "unlocked":
                return SEVERITY_HIGH
        
        elif domain == "binary_sensor":
            if "motion" in entity_id or "door" in entity_id or "window" in entity_id:
                if new_state.state == "on":
                    return SEVERITY_MEDIUM
        
        return SEVERITY_LOW

    def _add_event(self, event: SiemEvent):
        """Add event to storage."""
        self.events.append(event)
        self.stats[event.event_type] += 1
        self.stats[f"severity_{event.severity}"] += 1
        self.stats["total_events"] += 1

        _LOGGER.debug(
            "SIEM event recorded: %s - %s - %s",
            event.event_type,
            event.severity,
            event.message,
        )

    async def _cleanup_old_events(self):
        """Periodically cleanup old events."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                retention_days = self._get_retention_days()
                cutoff_time = datetime.now() - timedelta(days=retention_days)
                
                # Remove old events
                original_count = len(self.events)
                self.events = deque(
                    [e for e in self.events if e.timestamp > cutoff_time],
                    maxlen=self._get_max_events(),
                )
                removed_count = original_count - len(self.events)
                
                if removed_count > 0:
                    _LOGGER.info("Cleaned up %d old SIEM events", removed_count)
                    
            except asyncio.CancelledError:
                break
            except Exception as err:
                _LOGGER.error("Error during SIEM cleanup: %s", err)

    async def _handle_query_events(self, call: ServiceCall):
        """Handle query events service."""
        event_type = call.data.get(ATTR_EVENT_TYPE)
        entity_id = call.data.get(ATTR_ENTITY_ID)
        severity = call.data.get(ATTR_SEVERITY)
        limit = call.data.get("limit", 100)

        # Filter events
        filtered_events = []
        for event in reversed(self.events):
            if event_type and event.event_type != event_type:
                continue
            if entity_id and event.entity_id != entity_id:
                continue
            if severity and event.severity != severity:
                continue
            
            filtered_events.append(event.to_dict())
            
            if len(filtered_events) >= limit:
                break

        _LOGGER.info("Query returned %d events", len(filtered_events))
        
        # Fire event with results
        self.hass.bus.async_fire(
            f"{DOMAIN}_query_result",
            {"events": filtered_events, "count": len(filtered_events)},
        )
        
        # Return data for service response
        return {
            "events": filtered_events,
            "count": len(filtered_events)
        }

    async def _handle_clear_events(self, call: ServiceCall):
        """Handle clear events service."""
        count = len(self.events)
        self.events.clear()
        self.stats.clear()
        _LOGGER.info("Cleared %d SIEM events", count)

    async def _handle_get_stats(self, call: ServiceCall):
        """Handle get stats service."""
        stats_data = dict(self.stats)
        stats_data["event_count"] = len(self.events)
        
        self.hass.bus.async_fire(
            f"{DOMAIN}_stats_result",
            stats_data,
        )
        
        # Return data for service response
        return stats_data

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return {
            "total_events": len(self.events),
            "event_types": dict(self.stats),
            "max_events": self._get_max_events(),
            "retention_days": self._get_retention_days(),
        }
