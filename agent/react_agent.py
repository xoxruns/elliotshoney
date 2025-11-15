"""
Simple ReAct Agent using LangGraph prebuilt function
"""

import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver

# Import Notion tools
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import NotionMCPClient

# Load environment variables
load_dotenv()


def create_agent():
    """
    Create a simple ReAct agent with Notion tools and memory.
    """
    # Initialize LLM
    llm = ChatOpenAI(
        model="gpt-4.1",
        temperature=0,
        api_key=os.getenv("OPENAI_API_KEY")
    )
    
    # Get Notion tools
    notion_client = NotionMCPClient()
    tools = notion_client.get_as_langchain_tools()
    
    # Create memory
    memory = MemorySaver()
    
    # Create agent using prebuilt function
    agent = create_react_agent(
        llm,
        tools,
        checkpointer=memory
    )
    
    return agent


def run_agent(query: str, agent=None, thread_id: str = "default"):
    """
    Run the agent with a query.
    
    Args:
        query: User query
        agent: Pre-created agent
        thread_id: Thread ID for memory persistence
    
    Returns:
        Final response string
    """
    if agent is None:
        agent = create_agent()
    
    # Configuration for memory
    config = {"configurable": {"thread_id": thread_id}}
    
    # Run agent
    result = agent.invoke(
        {"messages": [("user", query)]},
        config=config
    )
    
    # Extract final message
    messages = result.get("messages", [])
    if messages:
        return messages[-1].content
    
    return "No response"


if __name__ == "__main__":
    """Interactive mode"""
    print("ReAct Agent with Notion Tools + Memory\n")
    
    # Create agent
    agent = create_agent()
    print("[OK] Agent ready\n")
    
    # Generate thread ID for this session
    import uuid
    thread_id = str(uuid.uuid4())
    
    print("Type 'quit' to exit, 'clear' to reset memory\n")
    
    while True:
        user_input = input("You: ").strip()
        
        if not user_input:
            continue
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            print("Goodbye!")
            break
        
        if user_input.lower() == 'clear':
            thread_id = str(uuid.uuid4())
            print("[Memory cleared]\n")
            continue
        
        try:
            response = run_agent(user_input, agent, thread_id)
            print(f"\nAgent: {response}\n")
        except Exception as e:
            print(f"[ERROR] {e}\n")
