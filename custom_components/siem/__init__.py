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
    """Set up the SIEM dashboard by creating it in Lovelace storage."""
    try:
        import json
        from homeassistant.components.lovelace.const import MODE_STORAGE
        
        dashboard_config = get_dashboard_config()
        
        # Path to lovelace dashboards storage
        lovelace_path = hass.config.path(".storage", "lovelace.lovelace_dashboards")
        
        def create_dashboard():
            # Read existing dashboards
            dashboards = {"data": {"items": []}, "key": "lovelace.lovelace_dashboards", "version": 1}
            try:
                with open(lovelace_path, 'r') as f:
                    dashboards = json.load(f)
            except FileNotFoundError:
                pass
            
            # Check if SIEM dashboard already exists
            siem_dashboard_exists = any(
                item.get("url_path") == "siem-security" 
                for item in dashboards.get("data", {}).get("items", [])
            )
            
            if not siem_dashboard_exists:
                # Add SIEM dashboard
                dashboards.setdefault("data", {}).setdefault("items", []).append({
                    "icon": "mdi:shield-check",
                    "id": "siem_security",
                    "mode": MODE_STORAGE,
                    "require_admin": True,
                    "show_in_sidebar": True,
                    "title": "SIEM Security",
                    "url_path": "siem-security",
                })
                
                # Save dashboards list
                with open(lovelace_path, 'w') as f:
                    json.dump(dashboards, f, indent=2)
            
            # Create dashboard content file
            dashboard_content_path = hass.config.path(".storage", "lovelace.siem_security")
            with open(dashboard_content_path, 'w') as f:
                json.dump({
                    "data": {
                        "config": dashboard_config
                    },
                    "key": "lovelace.siem_security",
                    "version": 1
                }, f, indent=2)
        
        await hass.async_add_executor_job(create_dashboard)
        
        _LOGGER.info(
            "SIEM dashboard automatically created!\n"
            "Access it at: /lovelace-siem-security or via sidebar 'SIEM Security'\n"
            "Restart Home Assistant or reload Lovelace to see the dashboard"
        )
        
    except Exception as err:
        _LOGGER.warning("Failed to auto-create SIEM dashboard: %s", err)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info("Unloading SIEM Server")
    
    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    if unload_ok:
        siem_server = hass.data[DOMAIN].pop(entry.entry_id)
        await siem_server.async_shutdown()
    
    return unload_ok
