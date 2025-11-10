"""Syslog server for receiving logs from external devices."""
import asyncio
import logging
import socket
from datetime import datetime
from typing import Callable, Optional

_LOGGER = logging.getLogger(__name__)


class SyslogServer:
    """UDP Syslog server to receive logs from external devices."""

    def __init__(self, host: str, port: int, callback: Callable):
        """Initialize syslog server.
        
        Args:
            host: Host IP to bind to (usually '0.0.0.0')
            port: Port to listen on (default: 514)
            callback: Async callback function to handle parsed events
        """
        self.host = host
        self.port = port
        self.callback = callback
        self.transport = None
        self._running = False

    async def start(self):
        """Start the syslog server."""
        try:
            loop = asyncio.get_event_loop()
            
            # Create UDP endpoint
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self.callback),
                local_addr=(self.host, self.port),
            )
            
            self._running = True
            _LOGGER.info("Syslog server started on %s:%d", self.host, self.port)
            
        except Exception as err:
            _LOGGER.error("Failed to start syslog server: %s", err)
            raise

    async def stop(self):
        """Stop the syslog server."""
        if self.transport:
            self.transport.close()
            self._running = False
            _LOGGER.info("Syslog server stopped")

    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


class SyslogProtocol(asyncio.DatagramProtocol):
    """Protocol handler for syslog messages."""

    def __init__(self, callback: Callable):
        """Initialize protocol handler."""
        self.callback = callback
        super().__init__()

    def connection_made(self, transport):
        """Handle connection made."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle received syslog message.
        
        Args:
            data: Raw syslog message bytes
            addr: Source address (ip, port)
        """
        try:
            message = data.decode('utf-8', errors='ignore').strip()
            
            if not message:
                return
            
            # Parse basic syslog format
            syslog_data = self._parse_syslog(message, addr[0])
            
            # Call the callback with parsed data
            asyncio.create_task(self.callback(syslog_data))
            
        except Exception as err:
            _LOGGER.error("Error processing syslog message from %s: %s", addr[0], err)

    def _parse_syslog(self, message: str, source_ip: str) -> dict:
        """Parse syslog message into structured data.
        
        RFC 3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        RFC 5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MESSAGE
        
        Args:
            message: Raw syslog message
            source_ip: Source IP address
            
        Returns:
            Dictionary with parsed syslog data
        """
        data = {
            "raw_message": message,
            "source_ip": source_ip,
            "timestamp": datetime.now(),
            "facility": None,
            "severity": None,
            "hostname": None,
            "tag": None,
            "message": message,
        }
        
        try:
            # Parse priority (PRI) if present
            if message.startswith('<'):
                pri_end = message.find('>')
                if pri_end > 0:
                    pri = int(message[1:pri_end])
                    data["facility"] = pri >> 3
                    data["severity"] = pri & 0x07
                    message = message[pri_end + 1:].strip()
            
            # Try to parse RFC 3164 format
            parts = message.split(None, 3)
            
            if len(parts) >= 3:
                # parts[0] = timestamp (often), parts[1] = hostname, parts[2+] = tag/message
                # Simple heuristic: if second part looks like hostname
                if self._looks_like_hostname(parts[1]):
                    data["hostname"] = parts[1]
                    
                    if len(parts) >= 3:
                        # Check for tag (before colon)
                        tag_msg = ' '.join(parts[2:])
                        if ':' in tag_msg:
                            tag, msg = tag_msg.split(':', 1)
                            data["tag"] = tag.strip()
                            data["message"] = msg.strip()
                        else:
                            data["message"] = tag_msg
                else:
                    data["hostname"] = source_ip
                    data["message"] = ' '.join(parts[1:])
            
        except Exception as err:
            _LOGGER.debug("Error parsing syslog structure: %s", err)
            # Keep raw message as fallback
        
        return data

    def _looks_like_hostname(self, text: str) -> bool:
        """Check if text looks like a hostname or IP."""
        if not text:
            return False
        
        # Check for IP address pattern
        parts = text.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return True
        
        # Check for hostname pattern (alphanumeric, hyphens, dots)
        return all(c.isalnum() or c in '.-_' for c in text)

    def error_received(self, exc):
        """Handle error."""
        _LOGGER.error("Syslog protocol error: %s", exc)

    def connection_lost(self, exc):
        """Handle connection lost."""
        if exc:
            _LOGGER.error("Syslog connection lost: %s", exc)
