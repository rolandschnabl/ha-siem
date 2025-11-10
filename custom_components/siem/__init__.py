"""The SIEM Server integration."""
import logging
import yaml
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import Platform

from .const import DOMAIN
from .siem_server import SiemServer
from .api import SiemLogViewerView
from .dashboard import get_dashboard_config

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the SIEM Server component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up SIEM Server from a config entry."""
    _LOGGER.info("Setting up SIEM Server")
    
    # Create SIEM server instance
    siem_server = SiemServer(hass, entry)
    hass.data[DOMAIN][entry.entry_id] = siem_server
    
    # Initialize the SIEM server
    await siem_server.async_initialize()
    
    # Register API endpoint
    hass.http.register_view(SiemLogViewerView(hass))
    
    # Register Lovelace dashboard
    await _async_setup_dashboard(hass)
    
    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    
    return True


async def _async_setup_dashboard(hass: HomeAssistant) -> None:
    """Set up the SIEM dashboard."""
    try:
        dashboard_config = get_dashboard_config()
        dashboard_path = hass.config.path("siem_dashboard.yaml")
        
        # Write dashboard YAML file
        def write_dashboard():
            with open(dashboard_path, 'w') as f:
                yaml.dump(dashboard_config, f, default_flow_style=False, allow_unicode=True)
        
        await hass.async_add_executor_job(write_dashboard)
        
        _LOGGER.info(
            "SIEM dashboard YAML created at: %s\n"
            "To use it:\n"
            "1. Go to Settings -> Dashboards\n"
            "2. Click 'Add Dashboard'\n"
            "3. Choose 'New dashboard from scratch'\n"
            "4. Go to Edit mode (pencil icon)\n"
            "5. Click three dots -> Raw configuration editor\n"
            "6. Copy content from %s",
            dashboard_path,
            dashboard_path
        )
        
    except Exception as err:
        _LOGGER.warning("Failed to create SIEM dashboard file: %s", err)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info("Unloading SIEM Server")
    
    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    if unload_ok:
        siem_server = hass.data[DOMAIN].pop(entry.entry_id)
        await siem_server.async_shutdown()
    
    return unload_ok
