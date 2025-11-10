# SIEM Server for Home Assistant

A simple Security Information and Event Management (SIEM) server as a custom component for Home Assistant. This integration monitors and logs security-relevant events in your Home Assistant instance.

## Features

- **Event Collection**: Automatically collects security-relevant events including:
  - Authentication failures
  - State changes for security entities (locks, alarms, sensors, cameras)
  - Security-related service calls (lock/unlock, arm/disarm)
  - Automation triggers
  - Script executions
  - **External device events via Syslog** (Sophos XGS, UniFi, etc.)

- **External Device Monitoring**:
  - **Sophos XGS Firewall**: Firewall blocks/allows, IPS alerts, VPN connections, authentication
  - **UniFi Devices**: WiFi client connections, authentication, IPS/IDS alerts, guest portal
  - Built-in Syslog server (UDP) for receiving logs
  - Automatic device-specific log parsing

- **Severity Classification**: Events are classified by severity:
  - Critical: Alarm triggered
  - High: Authentication failures, unauthorized unlocks, IPS alerts
  - Medium: Door/window sensors, lock operations, firewall blocks, VPN connections
  - Low: General automations and scripts, WiFi client events

- **Event Storage**: Configurable event storage with:
  - Maximum event limit (100-100,000 events)
  - Automatic retention cleanup (1-365 days)
  - In-memory storage for fast access

- **Sensors**: Multiple sensors to monitor:
  - Total events
  - Events by type (auth failures, state changes, service calls)
  - Events by severity (critical, high, medium, low)
  - External device events (firewall blocks, IPS alerts, VPN connections, WiFi clients)

- **Services**: Query and manage events:
  - `siem.query_events`: Query events with filters
  - `siem.clear_events`: Clear all stored events
  - `siem.get_stats`: Get current statistics

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Go to "Integrations"
3. Click the three dots in the top right
4. Select "Custom repositories"
5. Add this repository URL with category "Integration"
6. Click "Install"
7. Restart Home Assistant

### Manual Installation

1. Copy the `custom_components/siem` folder to your Home Assistant `custom_components` directory
2. Restart Home Assistant

## Configuration

1. Go to **Settings** → **Devices & Services**
2. Click **Add Integration**
3. Search for "SIEM Server"
4. Configure:
   - **Maximum Events**: Maximum number of events to store (default: 10,000)
   - **Retention Days**: How long to keep events (default: 7 days)
   - **Enable Syslog**: Enable syslog server for external devices (default: enabled)
   - **Syslog Port**: UDP port for syslog server (default: 5514)
   - **Syslog Host**: Bind address for syslog server (default: 0.0.0.0)

## Usage

### Sensors

After installation, the following sensors will be available:

**Home Assistant Events:**
- `sensor.siem_total_events`: Total number of events stored
- `sensor.siem_auth_failures`: Count of authentication failures
- `sensor.siem_state_changes`: Count of state change events
- `sensor.siem_service_calls`: Count of service call events
- `sensor.siem_critical_events`: Count of critical severity events
- `sensor.siem_high_events`: Count of high severity events
- `sensor.siem_medium_events`: Count of medium severity events
- `sensor.siem_low_events`: Count of low severity events

**External Device Events:**
- `sensor.siem_firewall_blocks`: Count of firewall block events
- `sensor.siem_ips_alerts`: Count of IPS/IDS alerts
- `sensor.siem_vpn_connections`: Count of VPN connection events
- `sensor.siem_wifi_clients`: Count of WiFi client events

### Services

#### Query Events

Query events with optional filters:

```yaml
service: siem.query_events
data:
  event_type: "auth_failure"  # Optional: auth_failure, state_change, service_call, automation_trigger, script_run
  entity_id: "lock.front_door"  # Optional
  severity: "high"  # Optional: low, medium, high, critical
  limit: 50  # Optional, default: 100
```

Results are published as a `siem_query_result` event on the event bus.

#### Clear Events

Clear all stored events:

```yaml
service: siem.clear_events
```

#### Get Statistics

Get current statistics:

```yaml
service: siem.get_stats
```

Results are published as a `siem_stats_result` event on the event bus.

### Example Automation

Create an automation to notify on critical events:

```yaml
automation:
  - alias: "SIEM Critical Alert"
    trigger:
      - platform: state
        entity_id: sensor.siem_critical_events
    condition:
      - condition: template
        value_template: "{{ trigger.to_state.state | int > trigger.from_state.state | int }}"
    action:
      - service: notify.mobile_app
        data:
          title: "🚨 Critical Security Event"
          message: "A critical security event has been detected!"
```

### Example Dashboard Card

Display SIEM statistics on your dashboard:

```yaml
type: entities
title: SIEM Server
entities:
  - entity: sensor.siem_total_events
  - entity: sensor.siem_critical_events
  - entity: sensor.siem_high_events
  - entity: sensor.siem_auth_failures
  - entity: sensor.siem_state_changes
```

## Monitored Entities

### Home Assistant

The SIEM server automatically monitors:

- **Alarm Control Panels**: All state changes
- **Locks**: Lock/unlock operations
- **Binary Sensors**: Motion, door, window sensors
- **Cameras**: State changes
- **Persons**: Location changes
- **Device Trackers**: Location changes

### Security Services Monitored

- Alarm arm/disarm operations
- Lock/unlock service calls
- Home Assistant restart/stop commands

## External Device Integration

### Sophos XGS Firewall

The SIEM server can monitor Sophos XGS firewalls via syslog.

**Monitored Events:**
- Firewall allow/deny rules
- IPS/ATP/DPI alerts
- Authentication events (admin, user)
- VPN connections (SSL-VPN, IPsec)

**Configuration on Sophos XGS:**

1. Log into Sophos XGS web interface
2. Go to **System** → **Log Settings**
3. Under **Syslog Servers**, click **Add**
4. Configure:
   - **Server IP**: Your Home Assistant IP address
   - **Port**: 5514 (or your configured syslog port)
   - **Protocol**: UDP
   - **Format**: Default or RFC 5424
5. Select log types to forward:
   - Firewall
   - IPS
   - Authentication
   - VPN
   - ATP
6. Click **Save**

**Example Sophos Log Format:**
```
<134>log_id="1234567890" log_type="Firewall" log_subtype="Denied" src_ip=192.168.1.100 dst_ip=8.8.8.8 protocol="TCP"
```

### UniFi Devices (Access Points, Gateways, Switches)

The SIEM server can monitor UniFi network devices via syslog.

**Monitored Events:**
- WiFi client connections/disconnections
- Authentication events
- IPS/IDS alerts
- Guest portal authorizations

**Configuration on UniFi Controller:**

1. Log into UniFi Network Controller
2. Go to **Settings** → **System** → **Advanced**
3. Scroll to **Remote Logging**
4. Enable **Remote Logging**
5. Configure:
   - **IP Address**: Your Home Assistant IP address
   - **Port**: 5514 (or your configured syslog port)
6. Click **Apply Changes**

**Configuration on UniFi OS (Dream Machine, etc.):**

1. SSH into your UniFi device
2. Edit syslog configuration:
   ```bash
   configure
   set system syslog host <HOME_ASSISTANT_IP> port 5514
   commit
   save
   ```

**Example UniFi Log Format:**
```
hostapd: AP-NAME[123]: STA 00:11:22:33:44:55 IEEE 802.11: authenticated
```

### Firewall Rules

**Important:** Ensure your firewall allows UDP traffic on port 5514 (or your configured port) from your external devices to Home Assistant.

Example iptables rule:
```bash
iptables -A INPUT -p udp --dport 5514 -s <DEVICE_IP> -j ACCEPT
```

### Testing Syslog Integration

Send a test syslog message from your terminal:

**Linux/Mac:**
```bash
logger -n <HOME_ASSISTANT_IP> -P 5514 -t test "Test SIEM syslog message"
```

**Windows PowerShell:**
```powershell
$UdpClient = New-Object System.Net.Sockets.UdpClient
$Bytes = [System.Text.Encoding]::ASCII.GetBytes("<134>Test SIEM syslog message")
$UdpClient.Send($Bytes, $Bytes.Length, "<HOME_ASSISTANT_IP>", 5514)
$UdpClient.Close()
```

Check the Home Assistant logs to verify the message was received:
```bash
tail -f /config/home-assistant.log | grep SIEM
```

## Development

### File Structure

```
custom_components/siem/
├── __init__.py          # Component initialization
├── config_flow.py       # Configuration UI
├── const.py             # Constants and configuration
├── manifest.json        # Component metadata
├── sensor.py            # Sensor platform
├── services.yaml        # Service definitions
├── siem_server.py       # Core SIEM logic
└── strings.json         # UI translations
```

### Testing

To test the integration:

1. Copy to your development Home Assistant instance
2. Enable debug logging in `configuration.yaml`:

```yaml
logger:
  default: info
  logs:
    custom_components.siem: debug
```

3. Restart Home Assistant
4. Add the integration via UI

## License

MIT License - feel free to modify and distribute

## Contributing

Contributions are welcome! Please open an issue or pull request.

## Disclaimer

This is a basic SIEM implementation for Home Assistant. For production security monitoring, consider professional SIEM solutions. This integration stores events in memory and will lose data on restart.
