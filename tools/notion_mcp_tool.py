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
    
    def search_pages(self, query: str = "") -> str:
        """
        Search Notion workspace for pages.
        If no query provided, returns all accessible pages.
        
        Args:
            query: Search query string (optional, empty returns all pages)
            
        Returns:
            JSON string with search results
        """
        print(f"\n[NOTION SEARCH]: {query}\n")
        try:
            with httpx.Client(timeout=30.0) as client:
                # If query is empty or "all", search for everything
                search_data = {"page_size": 10}
                if query and query.lower() not in ["all", "*", ""]:
                    search_data["query"] = query
                
                response = client.post(
                    f"{self.api_url}/search",
                    json=search_data,
                    headers=self._get_headers()
                )
                
                if response.status_code == 200:
                    result = response.json()
                    # Format results in a more readable way
                    if result.get("results"):
                        formatted = {
                            "found": len(result["results"]),
                            "pages": []
                        }
                        for page in result["results"]:
                            page_info = {
                                "id": page["id"],
                                "title": self._extract_title(page),
                                "url": page.get("url", ""),
                                "last_edited": page.get("last_edited_time", "")
                            }
                            formatted["pages"].append(page_info)
                        return json.dumps(formatted, indent=2)
                    else:
                        return json.dumps({"found": 0, "pages": []}, indent=2)
                else:
                    return json.dumps({
                        "error": f"API returned {response.status_code}",
                        "response": response.text
                    }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    def _extract_title(self, page: dict) -> str:
        """Extract title from a Notion page object"""
        try:
            if "properties" in page and "title" in page["properties"]:
                title_prop = page["properties"]["title"]
                if title_prop.get("title") and len(title_prop["title"]) > 0:
                    return title_prop["title"][0]["plain_text"]
            return "Untitled"
        except:
            return "Untitled"
    
    def get_page(self, page_id: str) -> str:
        """
        Get a Notion page by ID including its content.
        
        Args:
            page_id: Notion page ID (with or without hyphens)
            
        Returns:
            JSON string with page metadata and content
        """
        print(f"\n[NOTION GET PAGE]: {page_id}\n")
        try:
            # Clean page ID (remove hyphens if present)
            page_id = page_id.replace("-", "")
            
            with httpx.Client(timeout=30.0) as client:
                # Get page properties
                page_response = client.get(
                    f"{self.api_url}/pages/{page_id}",
                    headers=self._get_headers()
                )
                
                if page_response.status_code != 200:
                    return json.dumps({
                        "error": f"Failed to get page: {page_response.status_code}",
                        "response": page_response.text
                    }, indent=2)
                
                page_data = page_response.json()
                
                # Get page content blocks
                blocks_response = client.get(
                    f"{self.api_url}/blocks/{page_id}/children",
                    headers=self._get_headers()
                )
                
                if blocks_response.status_code != 200:
                    return json.dumps({
                        "error": f"Failed to get page content: {blocks_response.status_code}",
                        "response": blocks_response.text
                    }, indent=2)
                
                blocks_data = blocks_response.json()
                
                # Format the result
                result = {
                    "id": page_data["id"],
                    "title": self._extract_title(page_data),
                    "url": page_data.get("url", ""),
                    "created_time": page_data.get("created_time", ""),
                    "last_edited_time": page_data.get("last_edited_time", ""),
                    "content": self._extract_content_from_blocks(blocks_data.get("results", []))
                }
                
                return json.dumps(result, indent=2)
                
        except Exception as e:
            return json.dumps({"error": str(e)}, indent=2)
    
    def _extract_content_from_blocks(self, blocks: list) -> list:
        """
        Extract readable content from Notion blocks.
        
        Args:
            blocks: List of block objects from Notion API
            
        Returns:
            List of content items with type and text
        """
        content = []
        
        for block in blocks:
            block_type = block.get("type")
            block_content = block.get(block_type, {})
            
            # Extract text from rich_text field
            if "rich_text" in block_content:
                text = "".join([
                    rt.get("plain_text", "") 
                    for rt in block_content["rich_text"]
                ])
                
                if text:  # Only add non-empty blocks
                    content.append({
                        "type": block_type,
                        "text": text
                    })
            
            # Handle special block types
            elif block_type == "child_page":
                content.append({
                    "type": "child_page",
                    "text": f"[Child page: {block_content.get('title', 'Untitled')}]"
                })
            elif block_type == "image":
                content.append({
                    "type": "image",
                    "text": "[Image]"
                })
            elif block_type == "divider":
                content.append({
                    "type": "divider",
                    "text": "---"
                })
        
        return content
    
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
                description=(
                    "Search Notion workspace for pages and databases. "
                    "Input: search query string. Leave empty or use 'all' to get all pages. "
                    "Returns: JSON with found pages including id, title, url, and last_edited time."
                ),
                func=self.search_pages
            ),
            Tool(
                name="notion_get_page",
                description=(
                    "Get detailed content of a Notion page by ID. "
                    "Input: page ID string (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). "
                    "Returns: JSON with page details and properties."
                ),
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
