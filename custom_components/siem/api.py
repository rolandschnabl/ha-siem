"""Custom API endpoint for SIEM log viewer."""
import logging
from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class SiemLogViewerView(HomeAssistantView):
    """SIEM Log Viewer API endpoint."""

    url = "/api/siem/events"
    name = "api:siem:events"
    requires_auth = True

    def __init__(self, hass: HomeAssistant):
        """Initialize the view."""
        self.hass = hass

    async def get(self, request):
        """Get SIEM events via HTTP API."""
        try:
            # Get query parameters
            event_type = request.query.get("event_type")
            entity_id = request.query.get("entity_id")
            severity = request.query.get("severity")
            limit = int(request.query.get("limit", 100))

            # Get SIEM server instance
            entries = self.hass.config_entries.async_entries(DOMAIN)
            if not entries:
                return web.json_response(
                    {"error": "SIEM not configured"},
                    status=404
                )

            siem_server = self.hass.data[DOMAIN][entries[0].entry_id]

            # Filter events
            filtered_events = []
            for event in reversed(siem_server.events):
                if event_type and event.event_type != event_type:
                    continue
                if entity_id and event.entity_id != entity_id:
                    continue
                if severity and event.severity != severity:
                    continue

                filtered_events.append(event.to_dict())

                if len(filtered_events) >= limit:
                    break

            return web.json_response({
                "events": filtered_events,
                "count": len(filtered_events),
                "total": len(siem_server.events)
            })

        except Exception as err:
            _LOGGER.error("Error in SIEM log viewer API: %s", err)
            return web.json_response(
                {"error": str(err)},
                status=500
            )
