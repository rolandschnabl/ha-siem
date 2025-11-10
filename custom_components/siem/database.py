"""SQLite Database handler for SIEM events."""
import logging
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

_LOGGER = logging.getLogger(__name__)


class SiemDatabase:
    """Manages SQLite database for SIEM events."""

    def __init__(self, db_path: str):
        """Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = None
        self._ensure_directory()
        self._connect()
        self._create_schema()
        self._create_indices()

    def _ensure_directory(self):
        """Ensure database directory exists."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _connect(self):
        """Connect to database."""
        try:
            self.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            # Enable WAL mode for better concurrency
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.row_factory = sqlite3.Row
            _LOGGER.info("Connected to SIEM database: %s", self.db_path)
        except Exception as err:
            _LOGGER.error("Failed to connect to database: %s", err)
            raise

    def _create_schema(self):
        """Create database schema if not exists."""
        try:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    entity_id TEXT,
                    user_id TEXT,
                    data TEXT,
                    device_type TEXT,
                    source_ip TEXT,
                    hostname TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            self.conn.commit()
            _LOGGER.debug("Database schema created/verified")
        except Exception as err:
            _LOGGER.error("Failed to create schema: %s", err)
            raise

    def _create_indices(self):
        """Create database indices for fast queries."""
        indices = [
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)",
            "CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)",
            "CREATE INDEX IF NOT EXISTS idx_entity_id ON events(entity_id)",
            "CREATE INDEX IF NOT EXISTS idx_device_type ON events(device_type)",
            "CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_created_at ON events(created_at)",
        ]
        
        try:
            for index_sql in indices:
                self.conn.execute(index_sql)
            self.conn.commit()
            _LOGGER.debug("Database indices created/verified")
        except Exception as err:
            _LOGGER.error("Failed to create indices: %s", err)

    def insert_event(self, event: Dict[str, Any]) -> int:
        """Insert a single event into database.
        
        Args:
            event: Event dictionary
            
        Returns:
            Event ID
        """
        try:
            # Serialize data as JSON
            data_json = json.dumps(event.get('data', {}))
            
            cursor = self.conn.execute("""
                INSERT INTO events (
                    timestamp, event_type, severity, message,
                    entity_id, user_id, data, device_type, source_ip, hostname
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get('timestamp'),
                event.get('event_type'),
                event.get('severity'),
                event.get('message'),
                event.get('entity_id'),
                event.get('user_id'),
                data_json,
                event.get('device_type'),
                event.get('source_ip'),
                event.get('hostname'),
            ))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as err:
            _LOGGER.error("Failed to insert event: %s", err)
            self.conn.rollback()
            raise

    def insert_events_bulk(self, events: List[Dict[str, Any]]) -> int:
        """Insert multiple events efficiently.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            Number of inserted events
        """
        try:
            data = []
            for event in events:
                data.append((
                    event.get('timestamp'),
                    event.get('event_type'),
                    event.get('severity'),
                    event.get('message'),
                    event.get('entity_id'),
                    event.get('user_id'),
                    json.dumps(event.get('data', {})),
                    event.get('device_type'),
                    event.get('source_ip'),
                    event.get('hostname'),
                ))
            
            self.conn.executemany("""
                INSERT INTO events (
                    timestamp, event_type, severity, message,
                    entity_id, user_id, data, device_type, source_ip, hostname
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, data)
            self.conn.commit()
            _LOGGER.info("Bulk inserted %d events", len(events))
            return len(events)
        except Exception as err:
            _LOGGER.error("Failed to bulk insert events: %s", err)
            self.conn.rollback()
            raise

    def query_events(
        self,
        limit: int = 1000,
        offset: int = 0,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        entity_id: Optional[str] = None,
        device_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        search: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """Query events with filters.
        
        Args:
            limit: Maximum number of events to return
            offset: Offset for pagination
            event_type: Filter by event type
            severity: Filter by severity
            entity_id: Filter by entity ID
            device_type: Filter by device type
            source_ip: Filter by source IP
            search: Search in message field
            start_time: Filter events after this time
            end_time: Filter events before this time
            
        Returns:
            List of event dictionaries
        """
        try:
            sql = "SELECT * FROM events WHERE 1=1"
            params = []

            if event_type:
                sql += " AND event_type = ?"
                params.append(event_type)
            
            if severity:
                sql += " AND severity = ?"
                params.append(severity)
            
            if entity_id:
                sql += " AND entity_id = ?"
                params.append(entity_id)
            
            if device_type:
                sql += " AND device_type = ?"
                params.append(device_type)
            
            if source_ip:
                sql += " AND source_ip = ?"
                params.append(source_ip)
            
            if search:
                sql += " AND message LIKE ?"
                params.append(f"%{search}%")
            
            if start_time:
                sql += " AND timestamp >= ?"
                params.append(start_time.isoformat())
            
            if end_time:
                sql += " AND timestamp <= ?"
                params.append(end_time.isoformat())

            sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = self.conn.execute(sql, params)
            rows = cursor.fetchall()

            events = []
            for row in rows:
                event = dict(row)
                # Parse JSON data field
                if event.get('data'):
                    try:
                        event['data'] = json.loads(event['data'])
                    except:
                        pass
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
            sql = "SELECT COUNT(*) as count FROM events WHERE 1=1"
            params = []

            if event_type:
                sql += " AND event_type = ?"
                params.append(event_type)
            
            if severity:
                sql += " AND severity = ?"
                params.append(severity)

            cursor = self.conn.execute(sql, params)
            result = cursor.fetchone()
            return result['count'] if result else 0
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
            cursor = self.conn.execute("SELECT COUNT(*) as count FROM events")
            result = cursor.fetchone()
            stats['total_events'] = result['count'] if result else 0

            # By severity
            cursor = self.conn.execute("""
                SELECT severity, COUNT(*) as count 
                FROM events 
                GROUP BY severity
            """)
            stats['by_severity'] = {row['severity']: row['count'] for row in cursor}

            # By type
            cursor = self.conn.execute("""
                SELECT event_type, COUNT(*) as count 
                FROM events 
                GROUP BY event_type
                ORDER BY count DESC
                LIMIT 20
            """)
            stats['by_type'] = {row['event_type']: row['count'] for row in cursor}

            # By device type
            cursor = self.conn.execute("""
                SELECT device_type, COUNT(*) as count 
                FROM events 
                WHERE device_type IS NOT NULL
                GROUP BY device_type
            """)
            stats['by_device'] = {row['device_type']: row['count'] for row in cursor}

            return stats
        except Exception as err:
            _LOGGER.error("Failed to get statistics: %s", err)
            return {}

    def cleanup_old_events(self, retention_days: int) -> int:
        """Delete events older than retention period.
        
        Args:
            retention_days: Number of days to keep events
            
        Returns:
            Number of deleted events
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            cursor = self.conn.execute(
                "DELETE FROM events WHERE timestamp < ?",
                (cutoff_date.isoformat(),)
            )
            self.conn.commit()
            deleted = cursor.rowcount
            
            if deleted > 0:
                _LOGGER.info("Cleaned up %d events older than %d days", deleted, retention_days)
                # Optimize database after cleanup
                self.conn.execute("VACUUM")
            
            return deleted
        except Exception as err:
            _LOGGER.error("Failed to cleanup old events: %s", err)
            self.conn.rollback()
            return 0

    def clear_all_events(self) -> int:
        """Delete all events.
        
        Returns:
            Number of deleted events
        """
        try:
            cursor = self.conn.execute("DELETE FROM events")
            self.conn.commit()
            deleted = cursor.rowcount
            _LOGGER.info("Cleared all events: %d deleted", deleted)
            
            # Optimize database
            self.conn.execute("VACUUM")
            
            return deleted
        except Exception as err:
            _LOGGER.error("Failed to clear events: %s", err)
            self.conn.rollback()
            return 0

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            _LOGGER.debug("Database connection closed")
