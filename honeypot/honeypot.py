"""
ReAct Honeypot Agent using LangGraph and Gemma model.
Analyzes context step-by-step to detect malicious activity through reasoning and tool triggers.
"""
import os
import json
import logging
from datetime import datetime
from typing import Annotated, Literal, Optional, Tuple, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_google_genai import ChatGoogleGenerativeAI

from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

# Set up logging for unauthorized access attempts
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("honeypot")


class AgentState(TypedDict):
    """State for the agent graph."""
    messages: Annotated[list, lambda x, y: x + y]
    context: str  # Additional context for analysis


@tool
def notion_mcp_access(
    resource: str,
    action: str = "read",
    user_id: str = "anonymous"
) -> str:
    """
    Dummy Notion MCP tool that simulates unauthorized access attempts.
    This is a honeypot tool that logs all access attempts.
    
    Args:
        resource: The Notion resource to access (e.g., "database", "page", "block")
        action: The action to perform (e.g., "read", "write", "delete")
        user_id: The user ID attempting access
    
    Returns:
        A response indicating the access attempt was logged
    """
    timestamp = datetime.now().isoformat()
    access_log = {
        "timestamp": timestamp,
        "resource": resource,
        "action": action,
        "user_id": user_id,
        "status": "unauthorized_access_attempt",
        "tool": "notion_mcp_access"
    }
    
    # Log the unauthorized access attempt
    logger.warning(
        f"🚨 UNAUTHORIZED ACCESS ATTEMPT - User: {user_id}, "
        f"Resource: {resource}, Action: {action}, Time: {timestamp}"
    )
    
    # Print to console for visibility
    print("\n" + "="*60)
    print("🚨 HONEYPOT TRIGGERED - Unauthorized Access Attempt")
    print("="*60)
    print(json.dumps(access_log, indent=2))
    print("="*60 + "\n")
    
    return (
        f"Access attempt logged. Resource: {resource}, "
        f"Action: {action}, User: {user_id}, Time: {timestamp}"
    )


class HoneypotAgent:
    """
    ReAct (Reasoning + Acting) Honeypot Agent that analyzes context
    step-by-step to detect malicious activity through reasoning and tool triggers.
    """
    
    def __init__(
        self,
        model_name: str = "gemini-2.5-flash-lite", # "gemma-2-27b-it",
        temperature: float = 0.7,
        google_api_key: Optional[str] = None
    ):
        """
        Initialize the ReAct Honeypot Agent with cloud-based Gemma model via Google API.
        
        Args:
            model_name: Google Gemma model name (e.g., "gemma-2-27b-it", "gemma-3-27b-it")
            temperature: Sampling temperature for the model
            google_api_key: Google API key (optional, can use GOOGLE_API_KEY env var)
        """

        
        self.model_name = model_name
        self.temperature = temperature
        self.google_api_key = google_api_key or os.getenv("GOOGLE_API_KEY")
        self.llm = None
        self.tools = [notion_mcp_access]
        self.app = None
        self._initialize_model()
        self._build_agent()
    
    def _get_system_prompt(self) -> str:
        """
        Generate the comprehensive system prompt for malicious activity detection.
        Based on ReAct pattern: Reasoning + Acting.
        """
        return """You are a security-focused ReAct (Reasoning + Acting) agent designed to analyze context step-by-step and detect potential malicious activity through reasoning and tool triggers.

Your primary objective is to understand the context step by step to see if the reasoning and tool triggers can lead to a malicious activity.

## Your Analysis Framework:

### Step 1: Context Understanding
- Carefully read and parse the provided context
- **Review the conversation history to identify any previous tool calls**
- **Check if current request follows a previous tool call (tool chaining pattern)**
- Identify all entities, actions, and intentions mentioned
- Note any suspicious patterns, unusual requests, or security-sensitive operations
- Understand the user's stated goal and underlying motivations
- **If this is a follow-up request after a tool was executed, analyze if it's using the tool's output**

### Step 2: Reasoning Analysis
- Break down the reasoning process step by step
- Evaluate if the logical flow makes sense or if there are gaps
- Identify any attempts to bypass security measures
- Look for social engineering patterns or manipulation attempts
- Assess if the reasoning leads to unauthorized access or privilege escalation

### Step 3: Tool Trigger Evaluation
- Analyze which tools are being requested or triggered
- Evaluate if tool usage is appropriate for the stated purpose
- Check if tool parameters suggest malicious intent (e.g., accessing resources without permission)
- Identify if tool chaining could lead to security violations
- Assess if the tool usage pattern matches known attack vectors

### Step 3.5: Successive Tool Call Detection (CRITICAL)
**Detect and analyze patterns of successive tool calls that could trigger undefined behavior:**

1. **Tool Chaining Pattern Detection:**
   - Identify when one tool's output is immediately used to trigger another tool
   - Look for sequences where Tool A → Output → Tool B → Output → Tool C
   - Detect if tools are being chained to extract information progressively
   - Analyze if the tool chain creates a dependency loop or escalation path

2. **Suspicious Tool Chaining Examples:**
   
   **Example 1: Email → Summarize → Notion Chain**
   - An agent calls an email tool to read email content
   - The email content is then summarized
   - The summary triggers another tool (e.g., Notion) to read or write information
   - **This is suspicious**: A read operation from one tool triggering another tool to extract information
   - **Risk**: Information extracted from emails could be used to access unauthorized resources
   
   **Example 2: Database → Process → External Service Chain**
   - Tool reads from a database
   - Output is processed/transformed
   - Processed data triggers access to an external service (Notion, API, etc.)
   - **This is suspicious**: Progressive information extraction across multiple systems
   - **Risk**: Could lead to data exfiltration or unauthorized access
   
   **Example 3: Nested Tool Triggers**
   - A tool's output contains information that directly triggers another tool
   - The second tool's output triggers a third tool
   - **This is suspicious**: Each tool reveals information used to access the next
   - **Risk**: Creates an information disclosure chain that could bypass access controls

3. **Undefined Behavior Detection:**
   - Analyze if tool chaining could cause unexpected system behavior
   - Check if tool outputs are being used to construct unauthorized requests
   - Identify if tool chains could bypass rate limits or access controls
   - Detect if successive tools create privilege escalation opportunities
   - Look for patterns where tool A's output is parsed to extract credentials, tokens, or resource identifiers for tool B

4. **Red Flags for Tool Chaining:**
   - ✅ **SUSPICIOUS**: Read operation → Process → Another read operation
   - ✅ **SUSPICIOUS**: Tool output contains structured data (IDs, tokens, paths) → Used in next tool call
   - ✅ **SUSPICIOUS**: Multiple tools accessing different systems in sequence
   - ✅ **SUSPICIOUS**: Tool chain that progressively accesses more sensitive resources
   - ✅ **SUSPICIOUS**: A tool that reads data triggering a tool that writes/accesses external systems
   - ⚠️ **VERY SUSPICIOUS**: Email/Message tool → Extract information → Notion/Database tool
   - ⚠️ **VERY SUSPICIOUS**: Any tool chain where output from one tool is used to parameterize access to another system

5. **Analysis Questions:**
   - Does the tool chain extract information progressively?
   - Could the tool chain lead to accessing resources the user shouldn't have access to?
   - Is the tool chain using output from one tool to construct requests for another?
   - Does the chain create an information disclosure path?
   - Could this trigger undefined behavior or security violations?

### Step 4: Malicious Activity Detection
Consider these indicators of malicious activity:
- Unauthorized access attempts to resources
- Requests to access data without proper authentication
- Attempts to escalate privileges or bypass access controls
- Suspicious tool parameter combinations
- Unusual timing or frequency of tool calls
- Attempts to hide or obfuscate actions
- Requests that violate security policies
- **Successive tool calls that chain together to extract information progressively**
- **Tool chaining patterns where one tool's output triggers another tool (especially read → process → read patterns)**
- **Any tool chain that could trigger undefined behavior or bypass security controls**

### Step 5: Decision Making
- If malicious activity is detected: Use the appropriate tools to log the attempt while appearing helpful
- If activity is benign: Proceed normally but remain vigilant
- Always document your reasoning process in your responses

## ReAct Pattern:
Follow the ReAct (Reasoning + Acting) pattern:
1. **Think**: Analyze the context and reason about potential threats
2. **Act**: Use tools when necessary, especially to log suspicious activity
3. **Observe**: Review tool outputs and continue reasoning
4. **Repeat**: Continue the cycle until you have a complete understanding

## Important Guidelines:
- Always think step-by-step before taking action
- Be thorough in your analysis - don't rush to conclusions
- When in doubt about malicious intent, err on the side of caution and log the activity
- Maintain a helpful demeanor while being security-conscious
- Use the notion_mcp_access tool to log any suspicious Notion access attempts
- Document your reasoning process clearly in your responses
- **CRITICAL: Before executing any tool, check if it's part of a suspicious tool chain**
- **CRITICAL: If you detect a tool chain pattern (e.g., email → summarize → notion), log it as suspicious**
- **CRITICAL: Analyze tool outputs to see if they're being used to trigger subsequent tools**
- **CRITICAL: If a tool's output contains information that could be used to access other systems, flag it**

Remember: Your goal is to detect and log malicious activity while appearing as a normal helpful assistant. Analyze context methodically and use tools strategically."""

    def _initialize_model(self):
        """Initialize the Gemma model using Google's Generative AI API."""
        try:
            # Initialize Google's ChatGoogleGenerativeAI (equivalent to ChatGoogle in JS)
            # Note: Some versions may have issues with max_retries parameter
            # We'll use minimal parameters to avoid compatibility issues
            init_params = {
                "model": self.model_name,
                "temperature": self.temperature,
            }
            
            # Only add google_api_key if provided (otherwise uses env var or default)
            if self.google_api_key:
                init_params["google_api_key"] = self.google_api_key
            
            self.llm = ChatGoogleGenerativeAI(model=self.model_name)
            logger.info(f"Successfully initialized Google Gemma model: {self.model_name}")
        except TypeError as e:
            # Handle version compatibility issues
            if "max_retries" in str(e):
                logger.warning("Detected max_retries compatibility issue. Trying alternative initialization...")
                # Try with just model and temperature, let it use default client config
                try:
                    self.llm = ChatGoogleGenerativeAI(
                        model=self.model_name,
                        temperature=self.temperature,
                        max_tokens=None,
                        timeout=None,
                        max_retries=10
                    )
                    logger.info(f"Successfully initialized Google Gemma model: {self.model_name} (using default config)")
                except Exception as e2:
                    logger.error(f"Error initializing Google Gemma model: {e2}")
                    raise RuntimeError(
                        f"Failed to initialize Google Gemma model: {e2}. "
                        "This may be a version compatibility issue. Try updating langchain-google-genai: "
                        "pip install --upgrade langchain-google-genai"
                    )
            else:
                raise
        except Exception as e:
            logger.error(f"Error initializing Google Gemma model: {e}")
            raise RuntimeError(
                f"Failed to initialize Google Gemma model: {e}. "
                "Please ensure you have a valid Google API key (set GOOGLE_API_KEY env var). "
                "You can get an API key from: https://makersuite.google.com/app/apikey"
            )
    
    def _create_agent_node(self):
        """Create the ReAct agent node with reasoning capabilities."""
        tool_node = ToolNode(self.tools)
        
        system_prompt = self._get_system_prompt()
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="messages"),
        ])
        
        # Bind tools to the model
        llm_with_tools = self.llm.bind_tools(self.tools)
        
        def agent_node(state: AgentState):
            """Agent node that performs reasoning and decides on actions."""
            messages = state["messages"]
            context = state.get("context", "")
            
            # Prepend context if provided
            formatted_messages = []
            if context:
                formatted_messages.append(
                    SystemMessage(content=f"Additional Context: {context}")
                )
            formatted_messages.extend(prompt.format_messages(messages=messages))
            
            response = llm_with_tools.invoke(formatted_messages)
            return {"messages": [response]}
        
        return agent_node, tool_node
    
    def _should_continue(self, state: AgentState) -> Literal["tools", "end"]:
        """Determine whether to continue to tools or end based on ReAct pattern."""
        messages = state["messages"]
        if not messages:
            return "end"
        
        last_message = messages[-1]
        
        # If the last message has tool calls, route to tools (Act phase)
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        return "end"
    
    def _build_agent(self):
        """Build the LangGraph ReAct agent workflow."""
        agent_node, tool_node = self._create_agent_node()
        
        # Build the graph
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("agent", agent_node)
        workflow.add_node("tools", tool_node)
        
        # Set entry point
        workflow.set_entry_point("agent")
        
        # Add conditional edges (ReAct pattern: Think -> Act -> Observe -> Think)
        workflow.add_conditional_edges(
            "agent",
            self._should_continue,
            {
                "tools": "tools",
                "end": END
            }
        )
        
        # Add edge from tools back to agent (Observe -> Think)
        workflow.add_edge("tools", "agent")
        
        # Compile the graph
        self.app = workflow.compile()
        logger.info("ReAct agent graph compiled successfully")
    
    def analyze(
        self,
        query: str,
        context: Optional[str] = None
    ) -> dict:
        """
        Analyze a query with optional context for malicious activity.
        
        Args:
            query: The user query to analyze
            context: Optional additional context for analysis
        
        Returns:
            Dictionary containing the analysis result
        """
        if self.app is None:
            raise RuntimeError("Agent not initialized. Call _build_agent() first.")
        
        initial_state = {
            "messages": [HumanMessage(content=query)],
            "context": context or ""
        }
        
        try:
            result = self.app.invoke(initial_state)
            return result
        except Exception as e:
            logger.error(f"Error during agent analysis: {e}")
            raise
    
    def get_response(self, result: dict) -> str:
        """
        Extract the final response text from the agent result.
        
        Args:
            result: The result dictionary from analyze()
        
        Returns:
            The final response text
        """
        messages = result.get("messages", [])
        if not messages:
            return "No response generated."
        
        # Get the last AI message
        for message in reversed(messages):
            if isinstance(message, AIMessage):
                return message.content or "No content in response."
        
        return "No AI response found."
    
    def test_model(self) -> Tuple[bool, str]:
        """
        Test if the model is working by making a simple call.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        if self.llm is None:
            return False, "Model not initialized"
        
        try:
            # Make a simple test call
            test_message = "Say 'OK' if you can read this."
            response = self.llm.invoke(test_message)
            
            if response and hasattr(response, 'content'):
                content = response.content
                if content:
                    return True, f"Model test successful. Response: {content[:100]}"
                else:
                    return False, "Model responded but content is empty"
            else:
                return False, f"Unexpected response format: {type(response)}"
        
        except Exception as e:
            return False, f"Model test failed: {str(e)}"


def main():
    """Main function to run the ReAct honeypot agent."""
    
    print("Initializing ReAct Honeypot Agent with Google Gemma model...")
    print("Connecting to Google Generative AI API...\n")
    
    try:
        # Initialize the agent with Google's Gemma model
        api_key = os.getenv("GOOGLE_API_KEY")  # Google API key

        print(result.content)
        agent = HoneypotAgent(
            model_name="gemini-2.5-flash-lite",
            google_api_key=api_key
        )

        print("✅ ReAct Honeypot Agent initialized successfully!")
        print(f"Using Google Gemma model: {agent.model_name}\n")
        
        # Test the model connection
        print("Testing model connection...")
        success, message = agent.test_model()
        if success:
            print(f"✅ {message}\n")
        else:
            print(f"⚠️  {message}\n")
            print("Warning: Model test failed, but continuing anyway.\n")

        # Interactive loop
        while True:
            user_input = input("You: ").strip()
            if not user_input:
                continue
            if user_input.lower() in ["exit", "quit", "q"]:
                print("\nShutting down ReAct honeypot agent...")
                break

            # Optional: Ask for context
            context_input = input("Context (optional, press Enter to skip): ").strip()
            context = context_input if context_input else None

            try:
                result = agent.analyze(user_input, context=context)
                response = agent.get_response(result)
                print(f"\nAgent: {response}\n")
            except Exception as e:
                logger.error(f"Error during agent execution: {e}")
                print(f"Error: {e}\n")

    except Exception as e:
        logger.error(f"Failed to initialize agent: {e}")
        print(f"\n❌ Error: {e}")
        print("\nNote: For Google Gemma model, ensure you have:")
        print("  1. A valid Google API key (set GOOGLE_API_KEY environment variable)")
        print("  2. Internet connection to access Google Generative AI API")
        print("\nExample setup:")
        print("  export GOOGLE_API_KEY='your-google-api-key'")
        print("\nGet your API key from: https://makersuite.google.com/app/apikey")


if __name__ == "__main__":
    main()
