#!/usr/bin/env python3
"""Update SIEM configuration to 50k events and 30 days retention."""
import json

# Load config
with open('/config/.storage/core.config_entries', 'r') as f:
    config = json.load(f)

# Find and update SIEM entry
for entry in config['data']['entries']:
    if entry['domain'] == 'siem':
        entry['data']['max_events'] = 50000
        entry['data']['retention_days'] = 30
        print('Updated SIEM config:')
        print(f"  max_events: {entry['data']['max_events']}")
        print(f"  retention_days: {entry['data']['retention_days']}")
        break

# Save back
with open('/config/.storage/core.config_entries', 'w') as f:
    json.dump(config, f, indent=2)

print('Config updated successfully!')
