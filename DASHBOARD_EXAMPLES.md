# SIEM Log Viewer Dashboard Examples

## Einfache Event-Liste (Markdown Card)

```yaml
type: markdown
title: SIEM Recent Events
content: >-
  {% set events = state_attr('sensor.siem_total_events', 'recent_events') | default([]) %}
  {% if events | length > 0 %}
    {% for event in events[:10] %}
      **{{ event.severity | upper }}** - {{ event.timestamp }}  
      {{ event.message }}  
      ---
    {% endfor %}
  {% else %}
    No recent events
  {% endif %}
```

## Entities Card mit SIEM Statistiken

```yaml
type: entities
title: SIEM Server Status
entities:
  - entity: sensor.siem_total_events
    name: Total Events
  - entity: sensor.siem_critical_events
    name: Critical
    icon: mdi:alert-circle
  - entity: sensor.siem_high_events
    name: High Priority
    icon: mdi:alert
  - entity: sensor.siem_medium_events
    name: Medium Priority
  - entity: sensor.siem_low_events
    name: Low Priority
  - type: divider
  - entity: sensor.siem_auth_failures
    name: Auth Failures
    icon: mdi:shield-alert
  - entity: sensor.siem_firewall_blocks
    name: Firewall Blocks
    icon: mdi:wall-fire
  - entity: sensor.siem_ips_alerts
    name: IPS Alerts
    icon: mdi:shield-alert-outline
  - entity: sensor.siem_vpn_connections
    name: VPN Connections
    icon: mdi:vpn
  - entity: sensor.siem_wifi_clients
    name: WiFi Events
    icon: mdi:wifi
```

## Auto-Entities Card (Requires custom component)

```yaml
type: custom:auto-entities
card:
  type: entities
  title: SIEM Sensors
filter:
  include:
    - entity_id: sensor.siem_*
  exclude:
    - entity_id: sensor.siem_total_events
sort:
  method: state
  numeric: true
  reverse: true
```

## Button Card zum Abfragen von Events

```yaml
type: button
name: Query Recent Events
icon: mdi:database-search
tap_action:
  action: call-service
  service: siem.query_events
  service_data:
    limit: 50
```

## Conditional Card für Kritische Events

```yaml
type: conditional
conditions:
  - entity: sensor.siem_critical_events
    state_not: '0'
card:
  type: entities
  title: ⚠️ CRITICAL SECURITY ALERTS
  entities:
    - sensor.siem_critical_events
  state_color: true
```

## Glance Card

```yaml
type: glance
title: SIEM Overview
entities:
  - entity: sensor.siem_critical_events
    name: Critical
  - entity: sensor.siem_high_events
    name: High
  - entity: sensor.siem_firewall_blocks
    name: Firewall
  - entity: sensor.siem_ips_alerts
    name: IPS
  - entity: sensor.siem_auth_failures
    name: Auth Fail
columns: 5
state_color: true
```

## History Graph

```yaml
type: history-graph
title: SIEM Events Over Time
hours_to_show: 24
entities:
  - entity: sensor.siem_critical_events
  - entity: sensor.siem_high_events
  - entity: sensor.siem_firewall_blocks
  - entity: sensor.siem_ips_alerts
```

## Vollständiges Dashboard Layout

```yaml
title: SIEM Security Dashboard
views:
  - title: Overview
    path: siem-overview
    icon: mdi:shield-check
    cards:
      - type: vertical-stack
        cards:
          - type: markdown
            title: 🛡️ SIEM Security Center
            content: |
              Security Information and Event Management System
              Monitoring Home Assistant and external devices
          
          - type: glance
            title: Event Summary
            entities:
              - entity: sensor.siem_total_events
                name: Total
              - entity: sensor.siem_critical_events
                name: Critical
              - entity: sensor.siem_high_events
                name: High
              - entity: sensor.siem_medium_events
                name: Medium
              - entity: sensor.siem_low_events
                name: Low
            columns: 5
            state_color: true
      
      - type: horizontal-stack
        cards:
          - type: entities
            title: Home Assistant
            entities:
              - sensor.siem_auth_failures
              - sensor.siem_state_changes
              - sensor.siem_service_calls
          
          - type: entities
            title: External Devices
            entities:
              - sensor.siem_firewall_blocks
              - sensor.siem_ips_alerts
              - sensor.siem_vpn_connections
              - sensor.siem_wifi_clients
      
      - type: conditional
        conditions:
          - entity: sensor.siem_critical_events
            state_not: '0'
        card:
          type: markdown
          title: ⚠️ CRITICAL ALERTS
          content: |
            ## Critical security events detected!
            **Count:** {{ states('sensor.siem_critical_events') }}
            
            Please review immediately!
          card_mod:
            style: |
              ha-card {
                background-color: rgba(255,0,0,0.1);
                border: 2px solid red;
              }
      
      - type: history-graph
        title: Event Trends (24h)
        hours_to_show: 24
        entities:
          - sensor.siem_critical_events
          - sensor.siem_high_events
          - sensor.siem_firewall_blocks
          - sensor.siem_ips_alerts
      
      - type: button
        name: Query Recent Events
        icon: mdi:database-search
        tap_action:
          action: call-service
          service: siem.query_events
          service_data:
            limit: 100
      
      - type: button
        name: Clear All Events
        icon: mdi:delete-sweep
        tap_action:
          action: call-service
          service: siem.clear_events
          confirmation:
            text: Are you sure you want to clear all SIEM events?
```

## Verwendung mit Automationen

### Benachrichtigung bei kritischen Events

```yaml
automation:
  - alias: "SIEM Critical Alert"
    trigger:
      - platform: state
        entity_id: sensor.siem_critical_events
    condition:
      - condition: template
        value_template: >
          {{ trigger.to_state.state | int > trigger.from_state.state | int }}
    action:
      - service: notify.mobile_app
        data:
          title: "🚨 Critical Security Event"
          message: "Critical SIEM event detected!"
          data:
            priority: high
            tag: siem-critical
```

### Event-Abfrage in Automatisierung

```yaml
automation:
  - alias: "Query SIEM Events Daily"
    trigger:
      - platform: time
        at: "09:00:00"
    action:
      - service: siem.query_events
        data:
          severity: high
          limit: 50
        response_variable: siem_events
      - service: notify.admin
        data:
          title: "Daily SIEM Report"
          message: "Found {{ siem_events.count }} high-priority events"
```

## Script für Event-Abfrage

```yaml
script:
  siem_get_firewall_blocks:
    alias: Get Recent Firewall Blocks
    sequence:
      - service: siem.query_events
        data:
          event_type: firewall_block
          limit: 20
        response_variable: firewall_events
      - service: persistent_notification.create
        data:
          title: "Firewall Blocks"
          message: "{{ firewall_events.count }} blocks in last events"
```
