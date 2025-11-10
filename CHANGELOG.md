# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-11-10

### Added
- Initial release of SIEM Server for Home Assistant
- Event collection for security-relevant events
- Support for authentication failures, state changes, service calls, automations, and scripts
- Severity classification (critical, high, medium, low)
- Configurable event storage (max events and retention period)
- Eight sensors for monitoring event statistics
- Three services: query_events, clear_events, get_stats
- UI-based configuration flow
- Automatic cleanup of old events
- In-memory event storage
- Support for filtering events by type, entity, and severity
- HACS compatibility
