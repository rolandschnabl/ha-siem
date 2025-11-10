"""InfluxDB handler for SIEM events."""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from influxdb import InfluxDBClient
import json

_LOGGER = logging.getLogger(__name__)


class SiemInfluxDB:
    """Manages InfluxDB connection and queries for SIEM events."""

    def __init__(
        self,
        host: str = "a0d7b954-influxdb.local.hass.io",
        port: int = 8086,
        username: str = "mcl_sim",
        password: str = "mcl_sim",
        database: str = "mcl_siem",
    ):
        """Initialize InfluxDB connection.
        
        Args:
            host: InfluxDB host
            port: InfluxDB port
            username: Username
            password: Password
            database: Database name
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.client: Optional[InfluxDBClient] = None
        
        self._connect()
        self._ensure_database()

    def _connect(self):
        """Connect to InfluxDB."""
        try:
            self.client = InfluxDBClient(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                database=self.database,
                ssl=True,
                verify_ssl=False,
            )
            # Test connection
            self.client.ping()
            _LOGGER.info(
                "Connected to InfluxDB at %s:%s, database: %s",
                self.host,
                self.port,
                self.database,
            )
        except Exception as err:
            _LOGGER.error("Failed to connect to InfluxDB: %s", err)
            raise

    def _ensure_database(self):
        """Create database if it doesn't exist."""
        try:
            databases = self.client.get_list_database()
            db_names = [db['name'] for db in databases]
            
            if self.database not in db_names:
                self.client.create_database(self.database)
                _LOGGER.info("Created InfluxDB database: %s", self.database)
                
                # Create retention policy: keep data for 30 days
                self.client.create_retention_policy(
                    name='siem_retention',
                    duration='30d',
                    replication='1',
                    database=self.database,
                    default=True
                )
                _LOGGER.info("Created retention policy: 30 days")
            else:
                _LOGGER.debug("Database %s already exists", self.database)
        except Exception as err:
            _LOGGER.error("Failed to ensure database: %s", err)

    def write_event(self, event: Dict[str, Any]) -> bool:
        """Write a single event to InfluxDB.
        
        Args:
            event: Event dictionary
            
        Returns:
            True if successful
        """
        try:
            # Extract data for fields
            data = event.get('data', {})
            
            # Parse raw_message if exists
            raw_message = data.get('raw_message', '')
            
            # Build point
            point = {
                'measurement': 'siem_events',
                'time': event.get('timestamp', datetime.now().isoformat()),
                'tags': {
                    'event_type': event.get('event_type', 'unknown'),
                    'severity': event.get('severity', 'low'),
                    'device_type': data.get('device_type', 'unknown'),
                },
                'fields': {
                    'message': event.get('message', ''),
                    'entity_id': event.get('entity_id') or '',
                    'user_id': event.get('user_id') or '',
                    'source_ip': data.get('source_ip') or data.get('hostname') or '',
                    'data_json': json.dumps(data),
                }
            }
            
            # Add optional tags if they exist
            if event.get('entity_id'):
                point['tags']['entity_id'] = event['entity_id']
            
            if data.get('source_ip'):
                point['tags']['source_ip'] = data['source_ip']
            
            # Parse additional fields from raw_message
            if raw_message:
                point['fields']['raw_message'] = raw_message[:1000]  # Limit size
                
                # Extract key fields
                if 'user_name=' in raw_message:
                    import re
                    match = re.search(r'user_name="([^"]+)"', raw_message)
                    if match:
                        point['tags']['user_name'] = match.group(1)
                
                if 'src_ip=' in raw_message:
                    import re
                    match = re.search(r'src_ip=([^\s]+)', raw_message)
                    if match:
                        point['fields']['src_ip'] = match.group(1)
                
                if 'dst_ip=' in raw_message:
                    import re
                    match = re.search(r'dst_ip=([^\s]+)', raw_message)
                    if match:
                        point['fields']['dst_ip'] = match.group(1)
                
                if 'protocol=' in raw_message:
                    import re
                    match = re.search(r'protocol="([^"]+)"', raw_message)
                    if match:
                        point['tags']['protocol'] = match.group(1)
            
            self.client.write_points([point])
            return True
            
        except Exception as err:
            _LOGGER.error("Failed to write event to InfluxDB: %s", err)
            return False

    def write_events_bulk(self, events: List[Dict[str, Any]]) -> int:
        """Write multiple events efficiently.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            Number of successfully written events
        """
        try:
            points = []
            for event in events:
                data = event.get('data', {})
                raw_message = data.get('raw_message', '')
                
                point = {
                    'measurement': 'siem_events',
                    'time': event.get('timestamp', datetime.now().isoformat()),
                    'tags': {
                        'event_type': event.get('event_type', 'unknown'),
                        'severity': event.get('severity', 'low'),
                        'device_type': data.get('device_type', 'unknown'),
                    },
                    'fields': {
                        'message': event.get('message', ''),
                        'entity_id': event.get('entity_id') or '',
                        'user_id': event.get('user_id') or '',
                        'source_ip': data.get('source_ip') or '',
                        'data_json': json.dumps(data),
                    }
                }
                
                if raw_message:
                    point['fields']['raw_message'] = raw_message[:1000]
                
                points.append(point)
            
            self.client.write_points(points)
            _LOGGER.info("Bulk wrote %d events to InfluxDB", len(points))
            return len(points)
            
        except Exception as err:
            _LOGGER.error("Failed to bulk write events: %s", err)
            return 0

    def query_events(
        self,
        limit: int = 1000,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        device_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Query events with filters.
        
        Args:
            limit: Maximum number of events
            event_type: Filter by event type
            severity: Filter by severity
            device_type: Filter by device type
            entity_id: Filter by entity ID
            source_ip: Filter by source IP
            user_name: Filter by user name
            start_time: Start time
            end_time: End time
            
        Returns:
            List of event dictionaries
        """
        try:
            # Build WHERE clause
            where_clauses = []
            
            if event_type:
                where_clauses.append(f"event_type = '{event_type}'")
            
            if severity:
                where_clauses.append(f"severity = '{severity}'")
            
            if device_type:
                where_clauses.append(f"device_type = '{device_type}'")
            
            if entity_id:
                where_clauses.append(f"entity_id = '{entity_id}'")
            
            if source_ip:
                where_clauses.append(f"source_ip = '{source_ip}'")
            
            if user_name:
                where_clauses.append(f"user_name = '{user_name}'")
            
            if start_time:
                where_clauses.append(f"time >= '{start_time.isoformat()}'")
            
            if end_time:
                where_clauses.append(f"time <= '{end_time.isoformat()}'")
            
            # Build query
            query = f"SELECT * FROM siem_events"
            
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
            
            query += f" ORDER BY time DESC LIMIT {limit}"
            
            _LOGGER.debug("InfluxDB query: %s", query)
            
            result = self.client.query(query)
            
            # Convert to list of dicts
            events = []
            for point in result.get_points():
                # Parse data_json back to dict
                data = {}
                if point.get('data_json'):
                    try:
                        data = json.loads(point['data_json'])
                    except:
                        pass
                
                event = {
                    'timestamp': point['time'],
                    'event_type': point.get('event_type', ''),
                    'severity': point.get('severity', ''),
                    'message': point.get('message', ''),
                    'entity_id': point.get('entity_id') or None,
                    'user_id': point.get('user_id') or None,
                    'data': data,
                }
                events.append(event)
            
            return events
            
        except Exception as err:
            _LOGGER.error("Failed to query events: %s", err)
            return []

    def count_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        """Count events with optional filters.
        
        Args:
            event_type: Filter by event type
            severity: Filter by severity
            
        Returns:
            Number of events
        """
        try:
            where_clauses = []
            
            if event_type:
                where_clauses.append(f"event_type = '{event_type}'")
            
            if severity:
                where_clauses.append(f"severity = '{severity}'")
            
            query = "SELECT COUNT(message) FROM siem_events"
            
            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)
            
            result = self.client.query(query)
            points = list(result.get_points())
            
            if points and 'count' in points[0]:
                return points[0]['count']
            
            return 0
            
        except Exception as err:
            _LOGGER.error("Failed to count events: %s", err)
            return 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get event statistics.
        
        Returns:
            Statistics dictionary
        """
        try:
            stats = {
                'total_events': 0,
                'by_severity': {},
                'by_type': {},
                'by_device': {},
            }
            
            # Total events
            result = self.client.query("SELECT COUNT(message) FROM siem_events")
            points = list(result.get_points())
            if points and 'count' in points[0]:
                stats['total_events'] = points[0]['count']
            
            # By severity
            result = self.client.query(
                "SELECT COUNT(message) FROM siem_events GROUP BY severity"
            )
            for series_key, points in result.items():
                severity = series_key[1]['severity']
                for point in points:
                    stats['by_severity'][severity] = point['count']
            
            # By type
            result = self.client.query(
                "SELECT COUNT(message) FROM siem_events GROUP BY event_type LIMIT 20"
            )
            for series_key, points in result.items():
                event_type = series_key[1]['event_type']
                for point in points:
                    stats['by_type'][event_type] = point['count']
            
            # By device
            result = self.client.query(
                "SELECT COUNT(message) FROM siem_events GROUP BY device_type"
            )
            for series_key, points in result.items():
                device_type = series_key[1]['device_type']
                for point in points:
                    stats['by_device'][device_type] = point['count']
            
            return stats
            
        except Exception as err:
            _LOGGER.error("Failed to get statistics: %s", err)
            return {}

    def delete_old_events(self, days: int = 30) -> bool:
        """Delete events older than specified days.
        
        Note: InfluxDB retention policy handles this automatically.
        This method is for manual cleanup if needed.
        
        Args:
            days: Number of days to keep
            
        Returns:
            True if successful
        """
        try:
            cutoff = datetime.now() - timedelta(days=days)
            query = f"DELETE FROM siem_events WHERE time < '{cutoff.isoformat()}'"
            self.client.query(query)
            _LOGGER.info("Deleted events older than %d days", days)
            return True
        except Exception as err:
            _LOGGER.error("Failed to delete old events: %s", err)
            return False

    def clear_all_events(self) -> bool:
        """Delete all events.
        
        Returns:
            True if successful
        """
        try:
            self.client.query("DROP MEASUREMENT siem_events")
            _LOGGER.info("Cleared all SIEM events")
            return True
        except Exception as err:
            _LOGGER.error("Failed to clear all events: %s", err)
            return False

    def close(self):
        """Close InfluxDB connection."""
        if self.client:
            self.client.close()
            _LOGGER.debug("InfluxDB connection closed")
