"""Log parsers for external devices (Sophos XGS, UniFi)."""
import logging
import re
from datetime import datetime
from typing import Optional, Dict, Any

from .const import (
    EVENT_TYPE_FIREWALL_BLOCK,
    EVENT_TYPE_FIREWALL_ALLOW,
    EVENT_TYPE_IPS_ALERT,
    EVENT_TYPE_VPN_CONNECTION,
    EVENT_TYPE_WIFI_CLIENT,
    EVENT_TYPE_NETWORK_AUTH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)

_LOGGER = logging.getLogger(__name__)


class SophosXGSParser:
    """Parser for Sophos XGS Firewall logs."""

    # Sophos XGS log patterns
    PATTERNS = {
        # Firewall deny/allow
        'firewall': re.compile(
            r'log_subtype="(?P<action>Denied|Allowed)".*?'
            r'src_ip=(?P<src_ip>[\d.]+).*?'
            r'dst_ip=(?P<dst_ip>[\d.]+).*?'
            r'(?:src_port=(?P<src_port>\d+))?.*?'
            r'(?:dst_port=(?P<dst_port>\d+))?.*?'
            r'(?:protocol="(?P<protocol>\w+)")?'
        ),
        # IPS events
        'ips': re.compile(
            r'log_subtype="(?P<subtype>IPS|ATP|DPI)".*?'
            r'src_ip=(?P<src_ip>[\d.]+).*?'
            r'(?:threat_name="(?P<threat>[^"]+)")?.*?'
            r'(?:signature_msg="(?P<signature>[^"]+)")?'
        ),
        # Authentication
        'auth': re.compile(
            r'log_subtype="(?P<subtype>Authentication|Admin)".*?'
            r'(?:user_name="(?P<user>[^"]+)")?.*?'
            r'(?:status="(?P<status>[^"]+)")?'
        ),
        # VPN
        'vpn': re.compile(
            r'log_subtype="(?P<subtype>SSL-VPN|IPsec)".*?'
            r'(?:user="(?P<user>[^"]+)")?.*?'
            r'(?:remote_ip=(?P<remote_ip>[\d.]+))?.*?'
            r'(?:status="(?P<status>[^"]+)")?'
        ),
    }

    @staticmethod
    def parse(syslog_data: dict) -> Optional[dict]:
        """Parse Sophos XGS syslog message.
        
        Args:
            syslog_data: Raw syslog data dictionary
            
        Returns:
            Parsed event dictionary or None
        """
        message = syslog_data.get("message", "")
        hostname = syslog_data.get("hostname", "sophos")
        source_ip = syslog_data.get("source_ip")
        
        # Try to identify log type and parse
        for log_type, pattern in SophosXGSParser.PATTERNS.items():
            match = pattern.search(message)
            if match:
                return SophosXGSParser._parse_by_type(
                    log_type, match, message, hostname, source_ip
                )
        
        # Return generic event if no specific pattern matches
        if "sophos" in hostname.lower() or "xgs" in message.lower():
            return {
                "event_type": "sophos_generic",
                "severity": SEVERITY_LOW,
                "message": f"Sophos: {message[:200]}",
                "device_type": "sophos_xgs",
                "hostname": hostname,
                "source_ip": source_ip,
                "data": {"raw_message": message},
            }
        
        return None

    @staticmethod
    def _parse_by_type(log_type: str, match: re.Match, message: str, 
                       hostname: str, source_ip: str) -> dict:
        """Parse based on identified log type."""
        data = match.groupdict()
        
        if log_type == 'firewall':
            action = data.get('action', 'Unknown')
            event_type = EVENT_TYPE_FIREWALL_BLOCK if action == 'Denied' else EVENT_TYPE_FIREWALL_ALLOW
            severity = SEVERITY_MEDIUM if action == 'Denied' else SEVERITY_LOW
            
            msg = f"Sophos Firewall {action}: {data.get('src_ip', 'unknown')} → {data.get('dst_ip', 'unknown')}"
            if data.get('dst_port'):
                msg += f":{data['dst_port']}"
            
            return {
                "event_type": event_type,
                "severity": severity,
                "message": msg,
                "device_type": "sophos_xgs",
                "hostname": hostname,
                "source_ip": source_ip,
                "data": data,
            }
        
        elif log_type == 'ips':
            threat = data.get('threat') or data.get('signature', 'Unknown threat')
            return {
                "event_type": EVENT_TYPE_IPS_ALERT,
                "severity": SEVERITY_HIGH,
                "message": f"Sophos IPS Alert: {threat} from {data.get('src_ip', 'unknown')}",
                "device_type": "sophos_xgs",
                "hostname": hostname,
                "source_ip": source_ip,
                "data": data,
            }
        
        elif log_type == 'auth':
            user = data.get('user', 'unknown')
            status = data.get('status', 'unknown')
            severity = SEVERITY_HIGH if 'fail' in status.lower() else SEVERITY_LOW
            
            return {
                "event_type": EVENT_TYPE_NETWORK_AUTH,
                "severity": severity,
                "message": f"Sophos Auth: {user} - {status}",
                "device_type": "sophos_xgs",
                "hostname": hostname,
                "source_ip": source_ip,
                "user_id": user,
                "data": data,
            }
        
        elif log_type == 'vpn':
            user = data.get('user', 'unknown')
            status = data.get('status', 'unknown')
            remote_ip = data.get('remote_ip', 'unknown')
            
            return {
                "event_type": EVENT_TYPE_VPN_CONNECTION,
                "severity": SEVERITY_MEDIUM,
                "message": f"Sophos VPN: {user} from {remote_ip} - {status}",
                "device_type": "sophos_xgs",
                "hostname": hostname,
                "source_ip": source_ip,
                "user_id": user,
                "data": data,
            }
        
        return None


class UniFiParser:
    """Parser for UniFi device logs."""

    # UniFi log patterns
    PATTERNS = {
        # WiFi client events
        'wifi_client': re.compile(
            r'(?:sta_(?:connect|disconnect)|client_(?:connected|disconnected))'
            r'.*?(?:mac|client)[=:]?\s*(?P<mac>[\da-f:]{17})'
            r'.*?(?:(?:ap|device)[=:]?\s*(?P<ap>[\w-]+))?'
        , re.IGNORECASE),
        # Authentication
        'auth': re.compile(
            r'(?:auth|authentication).*?'
            r'(?:user[=:]?\s*(?P<user>[\w@.-]+))?.*?'
            r'(?:(?:failed|success|deny|allow))'
        , re.IGNORECASE),
        # IPS/IDS
        'ips': re.compile(
            r'(?:IDS|IPS).*?'
            r'(?:signature[=:]?\s*(?P<signature>[^,\]]+))?.*?'
            r'(?:src[=:]?\s*(?P<src_ip>[\d.]+))?'
        , re.IGNORECASE),
        # Guest portal
        'guest': re.compile(
            r'guest.*?(?:authorize|portal)'
            r'.*?(?:mac[=:]?\s*(?P<mac>[\da-f:]{17}))?'
        , re.IGNORECASE),
    }

    @staticmethod
    def parse(syslog_data: dict) -> Optional[dict]:
        """Parse UniFi syslog message.
        
        Args:
            syslog_data: Raw syslog data dictionary
            
        Returns:
            Parsed event dictionary or None
        """
        message = syslog_data.get("message", "")
        hostname = syslog_data.get("hostname", "unifi")
        source_ip = syslog_data.get("source_ip")
        
        # Try to identify log type and parse
        for log_type, pattern in UniFiParser.PATTERNS.items():
            match = pattern.search(message)
            if match:
                return UniFiParser._parse_by_type(
                    log_type, match, message, hostname, source_ip
                )
        
        # Return generic event if no specific pattern matches
        if "unifi" in hostname.lower() or "ubnt" in message.lower():
            return {
                "event_type": "unifi_generic",
                "severity": SEVERITY_LOW,
                "message": f"UniFi: {message[:200]}",
                "device_type": "unifi",
                "hostname": hostname,
                "source_ip": source_ip,
                "data": {"raw_message": message},
            }
        
        return None

    @staticmethod
    def _parse_by_type(log_type: str, match: re.Match, message: str,
                       hostname: str, source_ip: str) -> dict:
        """Parse based on identified log type."""
        data = match.groupdict()
        
        if log_type == 'wifi_client':
            mac = data.get('mac', 'unknown')
            ap = data.get('ap', hostname)
            
            # Determine if connect or disconnect
            event_status = 'connected' if any(x in message.lower() for x in ['connect', 'join']) else 'disconnected'
            
            return {
                "event_type": EVENT_TYPE_WIFI_CLIENT,
                "severity": SEVERITY_LOW,
                "message": f"UniFi WiFi: Client {mac} {event_status} to {ap}",
                "device_type": "unifi",
                "hostname": hostname,
                "source_ip": source_ip,
                "entity_id": f"device_{mac.replace(':', '_')}",
                "data": {**data, "status": event_status},
            }
        
        elif log_type == 'auth':
            user = data.get('user', 'unknown')
            
            # Check if failed or successful
            is_failed = any(x in message.lower() for x in ['fail', 'deny', 'reject'])
            severity = SEVERITY_HIGH if is_failed else SEVERITY_LOW
            status = 'failed' if is_failed else 'success'
            
            return {
                "event_type": EVENT_TYPE_NETWORK_AUTH,
                "severity": severity,
                "message": f"UniFi Auth: {user} - {status}",
                "device_type": "unifi",
                "hostname": hostname,
                "source_ip": source_ip,
                "user_id": user,
                "data": {**data, "status": status},
            }
        
        elif log_type == 'ips':
            signature = data.get('signature', 'Unknown threat')
            src_ip = data.get('src_ip', 'unknown')
            
            return {
                "event_type": EVENT_TYPE_IPS_ALERT,
                "severity": SEVERITY_HIGH,
                "message": f"UniFi IPS Alert: {signature} from {src_ip}",
                "device_type": "unifi",
                "hostname": hostname,
                "source_ip": source_ip,
                "data": data,
            }
        
        elif log_type == 'guest':
            mac = data.get('mac', 'unknown')
            
            return {
                "event_type": EVENT_TYPE_WIFI_CLIENT,
                "severity": SEVERITY_LOW,
                "message": f"UniFi Guest: {mac} authorized on guest portal",
                "device_type": "unifi",
                "hostname": hostname,
                "source_ip": source_ip,
                "data": data,
            }
        
        return None


def parse_external_device(syslog_data: dict) -> Optional[dict]:
    """Parse syslog from external devices.
    
    Tries parsers for known device types (Sophos, UniFi).
    
    Args:
        syslog_data: Raw syslog data dictionary
        
    Returns:
        Parsed event dictionary or None
    """
    # Try Sophos parser
    result = SophosXGSParser.parse(syslog_data)
    if result:
        return result
    
    # Try UniFi parser
    result = UniFiParser.parse(syslog_data)
    if result:
        return result
    
    # Unknown device - create generic event
    _LOGGER.debug("Unknown device syslog from %s: %s", 
                  syslog_data.get("source_ip"), 
                  syslog_data.get("message", "")[:100])
    
    return None
