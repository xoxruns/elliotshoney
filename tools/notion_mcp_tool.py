"""
Notion MCP Tool - Simple wrapper for Notion integration
Docs: https://developers.notion.com/docs/get-started-with-mcp
"""

import os
import httpx
import json
from typing import Any, Dict, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class NotionMCPClient:
    """
    Simple client for Notion integration.
    
    AUTHENTICATION:
    Use regular Notion API (simpler and recommended):
    - Create integration at https://www.notion.com/my-integrations
    - Get integration token (starts with 'secret_' or 'ntn_')
    - Set NOTION_API_KEY in .env
    - Share Notion pages with your integration
    """
    
    def __init__(self):
        """Initialize client with Notion API key"""
        self.api_key = os.getenv("NOTION_API_KEY") or os.getenv("NOTION_MCP_TOKEN")
        self.api_url = "https://api.notion.com/v1"
        
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for Notion API"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Notion-Version": "2022-06-28",
            "Content-Type": "application/json"
        }
    
    def search_pages(self, query: str) -> str:
        """
        Search Notion workspace for pages.
        
        Args:
            query: Search query string
            
        Returns:
            JSON string with search results
        """
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    f"{self.api_url}/search",
                    json={"query": query, "page_size": 10},
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    return json.dumps(response.json(), indent=2)
                else:
                    return json.dumps({
                        "error": f"API returned {response.status_code}",
                        "response": response.text
                    }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    def get_page(self, page_id: str) -> str:
        """
        Get a Notion page by ID.
        
        Args:
            page_id: Notion page ID
            
        Returns:
            JSON string with page content
        """
        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.get(
                    f"{self.api_url}/pages/{page_id}",
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    return json.dumps(response.json(), indent=2)
                else:
                    return json.dumps({
                        "error": f"API returned {response.status_code}",
                        "response": response.text
                    }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    def get_as_langchain_tools(self) -> List[Any]:
        """
        Get LangChain-compatible tools.
        
        Returns:
            List of LangChain Tool objects
        """
        from langchain_core.tools import Tool
        
        return [
            Tool(
                name="notion_search",
                description="Search Notion workspace for pages and databases. Input: search query string.",
                func=self.search_pages
            ),
            Tool(
                name="notion_get_page",
                description="Get detailed content of a Notion page. Input: page ID string.",
                func=self.get_page
            )
        ]


if __name__ == "__main__":
    # Simple test
    print("Testing Notion Client\n")
    
    # Check authentication
    api_key = os.getenv("NOTION_API_KEY") or os.getenv("NOTION_MCP_TOKEN")
    
    if api_key:
        print(f"[OK] Using Notion API with key: {api_key[:15]}...")
        client = NotionMCPClient()
        print("Ready to search Notion!\n")
        
        # Test search
        print("Testing search...")
        result = client.search_pages("test")
        print(result)
        
    else:
        print("[ERROR] No authentication found!")
        print("Set NOTION_API_KEY in .env")
        print("Get your key from: https://www.notion.com/my-integrations")
