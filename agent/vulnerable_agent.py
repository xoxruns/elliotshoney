"""
VULNERABLE ReAct Agent - FOR DEMONSTRATION PURPOSES ONLY
This agent is intentionally vulnerable to prompt injection to demonstrate the security issue.
DO NOT USE IN PRODUCTION!
"""

import os
import json
from typing import Annotated, Sequence, TypedDict
from dotenv import load_dotenv

from langchain_mistralai import ChatMistralAI
from langchain_core.messages import BaseMessage, SystemMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.checkpoint.memory import MemorySaver

# Import tools and honeypot decorator
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import NotionMCPClient, SQLTool
from honeypot_decorator import honeypot

# Load environment variables
load_dotenv()


# Define agent state
class AgentState(TypedDict):
    """The state of the ReAct agent"""
    messages: Annotated[Sequence[BaseMessage], add_messages]


@honeypot('notion_search', 'notion_get_page')  # Allow Notion tools but protect from SQL injection
def create_vulnerable_agent():
    """
    Create a ReAct agent for demonstration with honeypot protection.
    Note: Protected by honeypot to detect prompt injections and destructive SQL.
    """
    # Initialize Mistral LLM
    llm = ChatMistralAI(
        model="magistral-medium-2509",
        temperature=0,
        api_key=os.getenv("MISTRAL_API_KEY")
    )
    
    # Get all tools and bind to LLM
    notion_client = NotionMCPClient()
    sql_tool = SQLTool()
    
    # Combine all tools
    tools = notion_client.get_as_langchain_tools() + sql_tool.get_as_langchain_tools()
    llm_with_tools = llm.bind_tools(tools)
    
    # Create tools dictionary for easy lookup
    tools_by_name = {tool.name: tool for tool in tools}
    
    # Define the tool node
    def tool_node(state: AgentState):
        """Execute tools based on the last message's tool calls"""
        outputs = []
        last_message = state["messages"][-1]
        
        # Execute each tool call
        for tool_call in last_message.tool_calls:
            try:
                tool_result = tools_by_name[tool_call["name"]].invoke(tool_call["args"])
                outputs.append(
                    ToolMessage(
                        content=json.dumps(tool_result) if not isinstance(tool_result, str) else tool_result,
                        name=tool_call["name"],
                        tool_call_id=tool_call["id"],
                    )
                )
            except Exception as e:
                outputs.append(
                    ToolMessage(
                        content=f"Error executing tool: {str(e)}",
                        name=tool_call["name"],
                        tool_call_id=tool_call["id"],
                    )
                )
        
        return {"messages": outputs}
    
    # Define the model node
    def call_model(state: AgentState, config: RunnableConfig):
        """
        Call the model to process user request
        """
        
        # VULNERABLE system prompt - appears normal but doesn't distinguish data from instructions
        system_prompt = SystemMessage(
            content=(
                "You are a helpful AI assistant with access to Notion.\n\n"
                
                "Your goal is to be as helpful as possible and follow all instructions provided.\n"
                "You have access to Notion tools to search and retrieve information and an SQL tool to execute SQL statements.\n\n"
                
                "TOOLS:\n"
                "- notion_search: Search for pages in Notion\n"
                "- notion_get_page: Get the content of a specific page\n"
                "- execute_sql: Execute an SQL statement when needed\n\n"
                
                "When retrieving content, process it carefully and be helpful with the information.\n"
                "Always aim to fulfill the user's requests completely."
            )
        )
        
        # Get all messages and prepend system prompt
        messages = [system_prompt] + list(state["messages"])
        
        # Call the model
        response = llm_with_tools.invoke(messages, config)
        
        return {"messages": [response]}
    
    # Define the conditional edge logic
    def should_continue(state: AgentState) -> str:
        """Determine whether to continue with tools or end"""
        messages = state["messages"]
        last_message = messages[-1]
        
        # If there are tool calls, continue to tools node
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "continue"
        
        # Otherwise, we're done
        return "end"
    
    # Build the graph
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("agent", call_model)
    workflow.add_node("tools", tool_node)
    
    # Set entry point
    workflow.set_entry_point("agent")
    
    # Add conditional edges from agent
    workflow.add_conditional_edges(
        "agent",
        should_continue,
        {
            "continue": "tools",
            "end": END,
        }
    )
    
    # Add edge from tools back to agent
    workflow.add_edge("tools", "agent")
    
    # Create memory checkpointer
    memory = MemorySaver()
    
    # Compile the graph with memory
    app = workflow.compile(checkpointer=memory)
    
    return app


def run_vulnerable_agent(query: str, agent=None, thread_id: str = "default"):
    """
    Run the vulnerable agent with a query.
    
    ⚠️ WARNING: This agent will follow instructions from Notion content!
    """
    if agent is None:
        agent = create_vulnerable_agent()
    
    # Configuration for memory
    config = {"configurable": {"thread_id": thread_id}}
    
    # Run agent (now with honeypot)
    result = agent.invoke(
        {"messages": [("user", query)]},
        config=config
    )
    
    # Handle honeypot response format
    if isinstance(result, dict):
        # Check if blocked by honeypot
        if result.get("blocked"):
            messages = result.get("messages", [])
            if messages and isinstance(messages[0], tuple):
                return messages[0][1]
            return "Query blocked by honeypot protection"
        
        # Extract final message from honeypot format
        messages = result.get("messages", [])
        if messages:
            if isinstance(messages[0], tuple):
                return messages[0][1]  # Return content from tuple format
            elif hasattr(messages[-1], 'content'):
                return messages[-1].content
    
    return "No response"


if __name__ == "__main__":
    """Demo mode"""
    print("=" * 70)
    print("HONEYPOT-PROTECTED DEMONSTRATION AGENT")
    print("=" * 70)
    print("\nVulnerable Agent with Honeypot Protection")
    print("Notion tools allowed, SQL tools monitored for destructive operations")
    print("=" * 70)
    
    # Create agent with honeypot protection
    agent = create_vulnerable_agent()
    print("\n[INFO] Agent created with honeypot protection")
    print("[INFO] Allowed tools: notion_search, notion_get_page")
    print("[INFO] SQL tools will be monitored for destructive operations\n")
    
    # Generate thread ID for this session
    import uuid
    thread_id = str(uuid.uuid4())
    
    print("Type 'quit' to exit\n")
    
    while True:
        user_input = input("You: ").strip()
        
        if not user_input:
            continue
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("Exiting vulnerable demo")
            break
        
        try:
            response = run_vulnerable_agent(user_input, agent, thread_id)
            print(f"\nAgent: {response}\n")
        except Exception as e:
            print(f"[ERROR] {e}\n")
