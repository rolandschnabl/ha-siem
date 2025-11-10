"""The SIEM Server integration."""
import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import Platform

from .const import DOMAIN
from .siem_server import SiemServer

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
    
    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info("Unloading SIEM Server")
    
    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    if unload_ok:
        siem_server = hass.data[DOMAIN].pop(entry.entry_id)
        await siem_server.async_shutdown()
    
    return unload_ok
