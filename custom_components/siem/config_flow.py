"""Config flow for SIEM Server integration."""
import logging
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

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
)

_LOGGER = logging.getLogger(__name__)


class SiemConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SIEM Server."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            # Validate input
            max_events = user_input.get(CONF_MAX_EVENTS, DEFAULT_MAX_EVENTS)
            retention_days = user_input.get(CONF_RETENTION_DAYS, DEFAULT_RETENTION_DAYS)
            syslog_port = user_input.get(CONF_SYSLOG_PORT, DEFAULT_SYSLOG_PORT)

            if max_events < 100:
                errors[CONF_MAX_EVENTS] = "min_events"
            elif max_events > 100000:
                errors[CONF_MAX_EVENTS] = "max_events"

            if retention_days < 1:
                errors[CONF_RETENTION_DAYS] = "min_retention"
            elif retention_days > 365:
                errors[CONF_RETENTION_DAYS] = "max_retention"

            if syslog_port < 1024 or syslog_port > 65535:
                errors[CONF_SYSLOG_PORT] = "invalid_port"

            if not errors:
                return self.async_create_entry(
                    title="SIEM Server",
                    data=user_input,
                )

        # Show configuration form
        data_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_MAX_EVENTS,
                    default=DEFAULT_MAX_EVENTS,
                ): vol.Coerce(int),
                vol.Optional(
                    CONF_RETENTION_DAYS,
                    default=DEFAULT_RETENTION_DAYS,
                ): vol.Coerce(int),
                vol.Optional(
                    CONF_ENABLE_SYSLOG,
                    default=True,
                ): bool,
                vol.Optional(
                    CONF_SYSLOG_PORT,
                    default=DEFAULT_SYSLOG_PORT,
                ): vol.Coerce(int),
                vol.Optional(
                    CONF_SYSLOG_HOST,
                    default=DEFAULT_SYSLOG_HOST,
                ): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Get the options flow for this handler."""
        return SiemOptionsFlow(config_entry)


class SiemOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow for SIEM Server."""

    def __init__(self, config_entry):
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(self, user_input=None):
        """Manage the options."""
        errors = {}

        if user_input is not None:
            # Validate input
            max_events = user_input.get(CONF_MAX_EVENTS)
            retention_days = user_input.get(CONF_RETENTION_DAYS)
            syslog_port = user_input.get(CONF_SYSLOG_PORT)

            if max_events < 100 or max_events > 100000:
                errors[CONF_MAX_EVENTS] = "invalid_range"

            if retention_days < 1 or retention_days > 365:
                errors[CONF_RETENTION_DAYS] = "invalid_range"

            if syslog_port and (syslog_port < 1024 or syslog_port > 65535):
                errors[CONF_SYSLOG_PORT] = "invalid_port"

            if not errors:
                return self.async_create_entry(title="", data=user_input)

        options_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_MAX_EVENTS,
                    default=self.config_entry.options.get(
                        CONF_MAX_EVENTS,
                        self.config_entry.data.get(CONF_MAX_EVENTS, DEFAULT_MAX_EVENTS),
                    ),
                ): vol.Coerce(int),
                vol.Optional(
                    CONF_RETENTION_DAYS,
                    default=self.config_entry.options.get(
                        CONF_RETENTION_DAYS,
                        self.config_entry.data.get(
                            CONF_RETENTION_DAYS, DEFAULT_RETENTION_DAYS
                        ),
                    ),
                ): vol.Coerce(int),
                vol.Optional(
                    CONF_ENABLE_SYSLOG,
                    default=self.config_entry.options.get(
                        CONF_ENABLE_SYSLOG,
                        self.config_entry.data.get(CONF_ENABLE_SYSLOG, True),
                    ),
                ): bool,
                vol.Optional(
                    CONF_SYSLOG_PORT,
                    default=self.config_entry.options.get(
                        CONF_SYSLOG_PORT,
                        self.config_entry.data.get(CONF_SYSLOG_PORT, DEFAULT_SYSLOG_PORT),
                    ),
                ): vol.Coerce(int),
                vol.Optional(
                    CONF_SYSLOG_HOST,
                    default=self.config_entry.options.get(
                        CONF_SYSLOG_HOST,
                        self.config_entry.data.get(CONF_SYSLOG_HOST, DEFAULT_SYSLOG_HOST),
                    ),
                ): str,
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=options_schema,
            errors=errors,
        )
