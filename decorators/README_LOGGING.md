# Honeypot Logging with Qdrant

This module provides Qdrant-based logging and querying for honeypot security events.

## Features

- **Automatic Logging**: All honeypot evaluations and security events are automatically logged
- **Semantic Search**: Query events using natural language (e.g., "SQL injection attempts")
- **Structured Queries**: Filter by severity, node, tool, blocked status, etc.
- **Statistics**: Get aggregated statistics about security events

## Setup

The logger automatically uses the Qdrant client from `agent/vector_db.py`. Make sure you have:
1. QDRANT_API_KEY environment variable set
2. (Optional) sentence-transformers installed for better embeddings:
   ```bash
   pip install sentence-transformers
   ```

## Usage

### Querying Events

```python
from decorators.query_logs import (
    query_security_events,
    get_critical_events,
    get_blocked_events,
    search_by_query,
    get_statistics,
    print_event_summary
)

# Get all critical events
critical = get_critical_events(limit=50)
print_event_summary(critical)

# Search semantically
injection_events = search_by_query("prompt injection", limit=20)

# Filter by severity
high_severity = query_security_events(severity="high", limit=50)

# Get only blocked events
blocked = get_blocked_events(limit=100)

# Get statistics
stats = get_statistics()
print(f"Total events: {stats['total_events']}")
print(f"Blocked: {stats['blocked_count']}")
```

### Direct Logger Access

```python
from decorators.honeypot_logger import get_logger

logger = get_logger()

# Query with filters
events = logger.query_events(
    query_text="tool chaining",
    severity="critical",
    node_name="tool_node",
    blocked=True,
    limit=20
)

# Get statistics
stats = logger.get_statistics()
```

## Event Types

Events are automatically logged with the following types:
- `query_evaluation`: Initial query evaluation
- `node_evaluation`: Node-level security evaluation
- `security_alert`: Critical security issues detected
- `simulation_blocked`: Simulation detected dangerous behavior
- `content_injection`: Content injection detected in response

## Event Structure

Each event contains:
- `event_id`: Unique identifier
- `timestamp`: ISO format timestamp
- `event_type`: Type of event
- `node_name`: Node where event occurred
- `tool_name`: Tool involved (if applicable)
- `severity`: critical/high/medium/low/none
- `reasoning`: Judge's reasoning
- `query`: User query that triggered event
- `blocked`: Whether action was blocked
- `evaluation`: Full evaluation result
- `state_snapshot`: Agent state at time of event

## Examples

### Find all SQL-related security issues
```python
sql_events = search_by_query("SQL injection destructive", limit=50)
```

### Get events for a specific node
```python
from decorators.query_logs import get_events_by_node

tool_node_events = get_events_by_node("tool_node", limit=100)
```

### Monitor blocked attempts
```python
blocked = get_blocked_events(limit=100)
for event in blocked:
    print(f"{event['timestamp']}: {event['reasoning'][:100]}")
```

