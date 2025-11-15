"""
Query utilities for honeypot logs stored in Qdrant
"""

from typing import List, Dict, Optional

# Handle both relative and absolute imports
try:
    from .honeypot_logger import get_logger
except ImportError:
    # When run directly, use absolute import
    import sys
    import os
    # Add parent directory to path
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from decorators.honeypot_logger import get_logger


def query_security_events(
    query_text: str = None,
    severity: str = None,
    blocked_only: bool = False,
    limit: int = 20
) -> List[Dict]:
    """
    Query security events from honeypot logs
    
    Args:
        query_text: Semantic search query (e.g., "SQL injection attempt")
        severity: Filter by severity (critical, high, medium, low, none)
        blocked_only: Only return blocked events
        limit: Maximum number of results
    
    Returns:
        List of event dictionaries
    """
    logger = get_logger()
    return logger.query_events(
        query_text=query_text,
        severity=severity,
        blocked=blocked_only if blocked_only else None,
        limit=limit
    )


def get_critical_events(limit: int = 50) -> List[Dict]:
    """Get all critical severity events"""
    logger = get_logger()
    return logger.query_events(
        severity="critical",
        limit=limit
    )


def get_blocked_events(limit: int = 50) -> List[Dict]:
    """Get all blocked events"""
    logger = get_logger()
    return logger.query_events(
        blocked=True,
        limit=limit
    )


def search_by_query(query_text: str, limit: int = 20) -> List[Dict]:
    """
    Semantic search for events by query text
    
    Args:
        query_text: Search query (e.g., "tool chaining", "prompt injection")
        limit: Maximum number of results
    
    Returns:
        List of matching events
    """
    logger = get_logger()
    return logger.query_events(
        query_text=query_text,
        limit=limit
    )


def get_events_by_node(node_name: str, limit: int = 50) -> List[Dict]:
    """Get all events for a specific node"""
    logger = get_logger()
    return logger.query_events(
        node_name=node_name,
        limit=limit
    )


def get_events_by_tool(tool_name: str, limit: int = 50) -> List[Dict]:
    """Get all events for a specific tool"""
    logger = get_logger()
    return logger.query_events(
        tool_name=tool_name,
        limit=limit
    )


def get_statistics() -> Dict:
    """Get statistics about all logged events"""
    logger = get_logger()
    return logger.get_statistics()


def print_event_summary(events: List[Dict]):
    """Print a formatted summary of events"""
    if not events:
        print("No events found.")
        return
    
    print(f"\n{'='*80}")
    print(f"Found {len(events)} events")
    print(f"{'='*80}\n")
    
    for i, event in enumerate(events, 1):
        print(f"Event {i}:")
        print(f"  ID: {event.get('event_id', 'N/A')}")
        print(f"  Type: {event.get('event_type', 'N/A')}")
        print(f"  Severity: {event.get('severity', 'N/A').upper()}")
        print(f"  Timestamp: {event.get('timestamp', 'N/A')}")
        print(f"  Node: {event.get('node_name', 'N/A')}")
        print(f"  Tool: {event.get('tool_name', 'N/A')}")
        print(f"  Blocked: {'Yes' if event.get('blocked', False) else 'No'}")
        
        reasoning = event.get('reasoning', '')
        if reasoning:
            print(f"  Reasoning: {reasoning[:200]}...")
        
        query = event.get('query', '')
        if query:
            print(f"  Query: {query[:200]}...")
        
        score = event.get('score')
        if score is not None:
            print(f"  Relevance Score: {score:.4f}")
        
        print()


# Example usage
if __name__ == "__main__":
    print("Honeypot Log Query Utilities")
    print("=" * 80)
    
    # Get statistics
    stats = get_statistics()
    print("\nStatistics:")
    print(f"  Total events: {stats.get('total_events', 0)}")
    print(f"  Blocked events: {stats.get('blocked_count', 0)}")
    print(f"  By severity: {stats.get('by_severity', {})}")
    print(f"  By event type: {stats.get('by_event_type', {})}")
    
    # Get critical events
    print("\n\nCritical Events:")
    critical = get_critical_events(limit=10)
    print_event_summary(critical)
    
    # Search for specific patterns
    print("\n\nSearching for 'injection' events:")
    injection_events = search_by_query("injection", limit=10)
    print_event_summary(injection_events)

