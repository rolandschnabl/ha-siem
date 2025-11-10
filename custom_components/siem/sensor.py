"""Sensor platform for SIEM Server."""
import logging
from datetime import timedelta

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import DOMAIN, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
from .siem_server import SiemServer

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=30)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SIEM Server sensors."""
    siem_server: SiemServer = hass.data[DOMAIN][entry.entry_id]

    # Create coordinator for updating sensor data
    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name="siem_sensor",
        update_method=lambda: siem_server.get_stats(),
        update_interval=SCAN_INTERVAL,
    )

    # Initial refresh
    await coordinator.async_config_entry_first_refresh()

    # Create sensors
    sensors = [
        SiemTotalEventsSensor(coordinator, siem_server),
        SiemAuthFailuresSensor(coordinator, siem_server),
        SiemStateChangesSensor(coordinator, siem_server),
        SiemServiceCallsSensor(coordinator, siem_server),
        SiemCriticalEventsSensor(coordinator, siem_server),
        SiemHighEventsSensor(coordinator, siem_server),
        SiemMediumEventsSensor(coordinator, siem_server),
        SiemLowEventsSensor(coordinator, siem_server),
        # External device sensors
        SiemFirewallBlocksSensor(coordinator, siem_server),
        SiemIPSAlertsSensor(coordinator, siem_server),
        SiemVPNConnectionsSensor(coordinator, siem_server),
        SiemWiFiClientsSensor(coordinator, siem_server),
    ]

    async_add_entities(sensors)


class SiemSensorBase(CoordinatorEntity, SensorEntity):
    """Base class for SIEM sensors."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        siem_server: SiemServer,
        name: str,
        icon: str,
    ):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._siem_server = siem_server
        self._attr_name = name
        self._attr_icon = icon
        self._attr_unique_id = f"siem_{name.lower().replace(' ', '_')}"

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, "siem_server")},
            "name": "SIEM Server",
            "manufacturer": "Home Assistant Community",
            "model": "SIEM Server",
        }


class SiemTotalEventsSensor(SiemSensorBase):
    """Sensor for total events."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(coordinator, siem_server, "SIEM Total Events", "mdi:database")

    @property
    def native_value(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get("total_events", 0)

    @property
    def extra_state_attributes(self):
        """Return additional attributes."""
        stats = self.coordinator.data.get("event_types", {})
        return {
            "max_events": self.coordinator.data.get("max_events", 0),
            "retention_days": self.coordinator.data.get("retention_days", 0),
            **stats,
        }


class SiemAuthFailuresSensor(SiemSensorBase):
    """Sensor for authentication failures."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM Auth Failures", "mdi:shield-alert"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get("auth_failure", 0)


class SiemStateChangesSensor(SiemSensorBase):
    """Sensor for state changes."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM State Changes", "mdi:state-machine"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get("state_change", 0)


class SiemServiceCallsSensor(SiemSensorBase):
    """Sensor for service calls."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM Service Calls", "mdi:cog"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get("service_call", 0)


class SiemCriticalEventsSensor(SiemSensorBase):
    """Sensor for critical severity events."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM Critical Events", "mdi:alert-circle"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get(f"severity_{SEVERITY_CRITICAL}", 0)


class SiemHighEventsSensor(SiemSensorBase):
    """Sensor for high severity events."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM High Events", "mdi:alert"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get(f"severity_{SEVERITY_HIGH}", 0)


class SiemMediumEventsSensor(SiemSensorBase):
    """Sensor for medium severity events."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM Medium Events", "mdi:information"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get(f"severity_{SEVERITY_MEDIUM}", 0)


class SiemLowEventsSensor(SiemSensorBase):
    """Sensor for low severity events."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM Low Events", "mdi:information-outline"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get(f"severity_{SEVERITY_LOW}", 0)


class SiemFirewallBlocksSensor(SiemSensorBase):
    """Sensor for firewall blocks from external devices."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM Firewall Blocks", "mdi:wall-fire"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get("firewall_block", 0)


class SiemIPSAlertsSensor(SiemSensorBase):
    """Sensor for IPS alerts from external devices."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM IPS Alerts", "mdi:shield-alert-outline"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get("ips_alert", 0)


class SiemVPNConnectionsSensor(SiemSensorBase):
    """Sensor for VPN connections from external devices."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM VPN Connections", "mdi:vpn"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get("vpn_connection", 0)


class SiemWiFiClientsSensor(SiemSensorBase):
    """Sensor for WiFi client events from external devices."""

    def __init__(self, coordinator, siem_server):
        """Initialize the sensor."""
        super().__init__(
            coordinator, siem_server, "SIEM WiFi Clients", "mdi:wifi"
        )

    @property
    def native_value(self):
        """Return the state of the sensor."""
        stats = self.coordinator.data.get("event_types", {})
        return stats.get("wifi_client", 0)
