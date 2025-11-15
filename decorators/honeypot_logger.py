"""
Qdrant-based logging system for honeypot events
Stores and queries security events in a vector database
"""

import os
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue
import hashlib

# Try to import sentence transformers for embeddings, fallback to simple hash-based
try:
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    HAS_SENTENCE_TRANSFORMERS = False
    print("Warning: sentence-transformers not installed. Using simple text-based embeddings.")


class HoneypotLogger:
    """Logs honeypot events to Qdrant vector database"""
    
    COLLECTION_NAME = "honeypot_logs"
    VECTOR_SIZE = 384  # Default for sentence-transformers/all-MiniLM-L6-v2
    
    def __init__(self, qdrant_client: QdrantClient = None):
        """
        Initialize the honeypot logger
        
        Args:
            qdrant_client: Optional QdrantClient instance. If None, creates from vector_db
        """
        if qdrant_client is None:
            try:
                import sys
                import os
                # Add parent directory to path to import vector_db
                parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                from agent.vector_db import qdrant_client as default_client
                self.client = default_client
            except ImportError:
                # Fallback: create client from environment
                self.client = QdrantClient(
                    url=os.getenv("QDRANT_URL", "https://d4eac50d-6ba0-45f4-8fae-f83a7596c55d.eu-west-1-0.aws.cloud.qdrant.io:6333/"),
                    api_key=os.getenv("QDRANT_API_KEY")
                )
        else:
            self.client = qdrant_client
        
        # Initialize embedding model if available
        if HAS_SENTENCE_TRANSFORMERS:
            try:
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                self.vector_size = self.embedding_model.get_sentence_embedding_dimension()
            except Exception as e:
                print(f"Warning: Could not load embedding model: {e}")
                self.embedding_model = None
                self.vector_size = self.VECTOR_SIZE
        else:
            self.embedding_model = None
            self.vector_size = self.VECTOR_SIZE
        
        self._ensure_collection()
    
    def _ensure_collection(self):
        """Create collection if it doesn't exist"""
        try:
            collections = self.client.get_collections()
            collection_names = [c.name for c in collections.collections]
            
            if self.COLLECTION_NAME not in collection_names:
                self.client.create_collection(
                    collection_name=self.COLLECTION_NAME,
                    vectors_config=VectorParams(
                        size=self.vector_size,
                        distance=Distance.COSINE
                    )
                )
                print(f"Created Qdrant collection: {self.COLLECTION_NAME}")
        except Exception as e:
            print(f"Error ensuring collection exists: {e}")
    
    def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for text"""
        if self.embedding_model:
            try:
                return self.embedding_model.encode(text).tolist()
            except Exception as e:
                print(f"Error generating embedding: {e}")
                return self._simple_embedding(text)
        else:
            return self._simple_embedding(text)
    
    def _simple_embedding(self, text: str) -> List[float]:
        """Simple hash-based embedding fallback"""
        # Create a simple embedding using hash
        hash_obj = hashlib.sha256(text.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Convert to vector of fixed size
        vector = []
        for i in range(0, min(len(hash_hex), self.vector_size * 2), 2):
            byte_val = int(hash_hex[i:i+2], 16)
            vector.append(byte_val / 255.0)  # Normalize to 0-1
        
        # Pad or truncate to vector_size
        while len(vector) < self.vector_size:
            vector.append(0.0)
        
        return vector[:self.vector_size]
    
    def log_event(
        self,
        event_type: str,
        node_name: str = None,
        tool_name: str = None,
        severity: str = "medium",
        reasoning: str = None,
        query: str = None,
        state: Dict = None,
        evaluation: Dict = None,
        blocked: bool = False,
        metadata: Dict = None
    ) -> str:
        """
        Log a honeypot event to Qdrant
        
        Args:
            event_type: Type of event (e.g., "security_alert", "tool_call", "node_evaluation")
            node_name: Name of the node where event occurred
            tool_name: Name of tool if applicable
            severity: Severity level (critical, high, medium, low, none)
            reasoning: Reasoning from the judge/evaluation
            query: User query that triggered the event
            state: Agent state snapshot
            evaluation: Full evaluation result from judge
            blocked: Whether the action was blocked
            metadata: Additional metadata
        
        Returns:
            Event ID (UUID string)
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Build searchable text
        searchable_text_parts = []
        if query:
            searchable_text_parts.append(f"Query: {query}")
        if reasoning:
            searchable_text_parts.append(f"Reasoning: {reasoning}")
        if tool_name:
            searchable_text_parts.append(f"Tool: {tool_name}")
        if node_name:
            searchable_text_parts.append(f"Node: {node_name}")
        
        searchable_text = " | ".join(searchable_text_parts) or event_type
        
        # Generate embedding
        vector = self._generate_embedding(searchable_text)
        
        # Build payload
        payload = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "node_name": node_name or "",
            "tool_name": tool_name or "",
            "severity": severity,
            "reasoning": reasoning or "",
            "query": query or "",
            "blocked": blocked,
            "searchable_text": searchable_text
        }
        
        # Add evaluation details if provided
        if evaluation:
            payload["evaluation"] = json.dumps(evaluation) if isinstance(evaluation, dict) else str(evaluation)
        
        # Add state snapshot (truncated to avoid huge payloads)
        if state:
            state_snapshot = {}
            messages = state.get("messages", [])
            if messages:
                # Store last few messages
                state_snapshot["last_messages"] = [
                    {
                        "type": getattr(msg, 'type', 'unknown'),
                        "content": str(getattr(msg, 'content', ''))[:500]
                    }
                    for msg in messages[-3:]
                ]
            payload["state_snapshot"] = json.dumps(state_snapshot)
        
        # Add custom metadata
        if metadata:
            payload.update(metadata)
        
        # Store in Qdrant
        try:
            point = PointStruct(
                id=event_id,
                vector=vector,
                payload=payload
            )
            
            self.client.upsert(
                collection_name=self.COLLECTION_NAME,
                points=[point]
            )
            
            return event_id
        except Exception as e:
            print(f"Error logging event to Qdrant: {e}")
            return event_id
    
    def query_events(
        self,
        query_text: str = None,
        event_type: str = None,
        severity: str = None,
        node_name: str = None,
        tool_name: str = None,
        blocked: bool = None,
        limit: int = 10,
        start_date: str = None,
        end_date: str = None
    ) -> List[Dict]:
        """
        Query honeypot events from Qdrant
        
        Args:
            query_text: Semantic search query
            event_type: Filter by event type
            severity: Filter by severity level
            node_name: Filter by node name
            tool_name: Filter by tool name
            blocked: Filter by blocked status
            limit: Maximum number of results
            start_date: Start date filter (ISO format)
            end_date: End date filter (ISO format)
        
        Returns:
            List of event dictionaries
        """
        try:
            # Build filter conditions
            filter_conditions = []
            
            if event_type:
                filter_conditions.append(
                    FieldCondition(key="event_type", match=MatchValue(value=event_type))
                )
            
            if severity:
                filter_conditions.append(
                    FieldCondition(key="severity", match=MatchValue(value=severity))
                )
            
            if node_name:
                filter_conditions.append(
                    FieldCondition(key="node_name", match=MatchValue(value=node_name))
                )
            
            if tool_name:
                filter_conditions.append(
                    FieldCondition(key="tool_name", match=MatchValue(value=tool_name))
                )
            
            if blocked is not None:
                filter_conditions.append(
                    FieldCondition(key="blocked", match=MatchValue(value=blocked))
                )
            
            # Build filter
            query_filter = None
            if filter_conditions:
                from qdrant_client.models import Filter, Condition
                query_filter = Filter(must=filter_conditions)
            
            # Perform search
            if query_text:
                # Semantic search
                query_vector = self._generate_embedding(query_text)
                results = self.client.search(
                    collection_name=self.COLLECTION_NAME,
                    query_vector=query_vector,
                    query_filter=query_filter,
                    limit=limit
                )
            else:
                # Filter-only search (no semantic query)
                # Use a zero vector for filter-only searches
                zero_vector = [0.0] * self.vector_size
                results = self.client.search(
                    collection_name=self.COLLECTION_NAME,
                    query_vector=zero_vector,
                    query_filter=query_filter,
                    limit=limit
                )
            
            # Process results
            events = []
            for result in results:
                event = result.payload.copy()
                event["score"] = result.score
                event["id"] = result.id
                
                # Parse JSON fields
                if "evaluation" in event and isinstance(event["evaluation"], str):
                    try:
                        event["evaluation"] = json.loads(event["evaluation"])
                    except:
                        pass
                
                if "state_snapshot" in event and isinstance(event["state_snapshot"], str):
                    try:
                        event["state_snapshot"] = json.loads(event["state_snapshot"])
                    except:
                        pass
                
                # Apply date filters if provided
                if start_date or end_date:
                    timestamp = event.get("timestamp", "")
                    if start_date and timestamp < start_date:
                        continue
                    if end_date and timestamp > end_date:
                        continue
                
                events.append(event)
            
            return events
        
        except Exception as e:
            print(f"Error querying events: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get statistics about logged events"""
        try:
            # Get all events (with a reasonable limit)
            all_events = self.query_events(limit=1000)
            
            stats = {
                "total_events": len(all_events),
                "by_severity": {},
                "by_event_type": {},
                "by_node": {},
                "blocked_count": 0,
                "recent_events": []
            }
            
            for event in all_events:
                # Count by severity
                severity = event.get("severity", "unknown")
                stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
                
                # Count by event type
                event_type = event.get("event_type", "unknown")
                stats["by_event_type"][event_type] = stats["by_event_type"].get(event_type, 0) + 1
                
                # Count by node
                node_name = event.get("node_name", "unknown")
                if node_name:
                    stats["by_node"][node_name] = stats["by_node"].get(node_name, 0) + 1
                
                # Count blocked
                if event.get("blocked", False):
                    stats["blocked_count"] += 1
            
            # Get recent events (last 10)
            stats["recent_events"] = sorted(
                all_events,
                key=lambda x: x.get("timestamp", ""),
                reverse=True
            )[:10]
            
            return stats
        
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {"error": str(e)}


# Global logger instance
_honeypot_logger = None

def get_logger() -> HoneypotLogger:
    """Get or create global logger instance"""
    global _honeypot_logger
    if _honeypot_logger is None:
        _honeypot_logger = HoneypotLogger()
    return _honeypot_logger

