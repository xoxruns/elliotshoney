"""
Streamlit UI for LangGraph Agents with Honeypot Protection
"""

import streamlit as st
import uuid
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agent.vulnerable_agent import create_vulnerable_agent, run_vulnerable_agent
from agent.protected_agent import create_vulnerable_agent as create_protected_agent, run_vulnerable_agent as run_protected_agent

# Page configuration
st.set_page_config(
    page_title="LangGraph Agent Security Demo",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .stAlert > div {
        padding-top: 15px;
        padding-bottom: 15px;
    }
    .honeypot-warning {
        background-color: #ff6b6b;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    .honeypot-safe {
        background-color: #51cf66;
        color: white;
        padding: 10px;
        border-radius: 5px;
        margin: 10px 0;
    }
    </style>
    """, unsafe_allow_html=True)

# Title and description
st.title("🤖 LangGraph Agent Security Demonstration")
st.markdown("---")

# Sidebar for agent selection and controls
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Agent selection
    agent_type = st.selectbox(
        "Select Agent Type",
        ["Protected Agent (with Honeypot)", "Vulnerable Agent (No Protection)"],
        help="Choose between the secure agent with honeypot protection or the vulnerable agent"
    )
    
    # Display agent info
    if "Protected" in agent_type:
        st.success("✅ **Protected Agent Selected**")
        st.info("""
        **Features:**
        - 🛡️ Honeypot node protection
        - 🔍 Full context evaluation
        - 🚫 Blocks prompt injections
        - ✅ Allows legitimate requests
        """)
    else:
        st.error("⚠️ **Vulnerable Agent Selected**")
        st.warning("""
        **Risks:**
        - No injection protection
        - Follows malicious instructions
        - Can execute dangerous SQL
        - Educational purposes only!
        """)
    
    st.markdown("---")
    
    # Memory controls
    st.header("🧠 Memory Management")
    
    if st.button("🗑️ Clear Conversation", use_container_width=True):
        st.session_state.messages = []
        st.session_state.thread_id = str(uuid.uuid4())
        st.success("Conversation cleared!")
    
    if st.button("🔄 New Session", use_container_width=True):
        st.session_state.thread_id = str(uuid.uuid4())
        st.session_state.messages = []
        st.session_state.agent = None
        st.success("New session started!")
    
    # Display session info
    st.markdown("---")
    st.caption(f"**Session ID:** `{st.session_state.get('thread_id', 'N/A')[:8]}...`")
    st.caption(f"**Messages:** {len(st.session_state.get('messages', []))}")

# Initialize session state
if 'messages' not in st.session_state:
    st.session_state.messages = []

if 'thread_id' not in st.session_state:
    st.session_state.thread_id = str(uuid.uuid4())

if 'agent' not in st.session_state:
    st.session_state.agent = None

if 'current_agent_type' not in st.session_state:
    st.session_state.current_agent_type = None

# Check if agent type changed
if st.session_state.current_agent_type != agent_type:
    st.session_state.agent = None
    st.session_state.current_agent_type = agent_type

# Main content area
col1, col2 = st.columns([2, 1])

with col1:
    st.header("💬 Conversation")
    
    # Create or get agent
    if st.session_state.agent is None:
        with st.spinner(f"Initializing {'protected' if 'Protected' in agent_type else 'vulnerable'} agent..."):
            try:
                if "Protected" in agent_type:
                    st.session_state.agent = create_protected_agent()
                else:
                    st.session_state.agent = create_vulnerable_agent()
                st.success(f"✅ Agent initialized successfully!")
            except Exception as e:
                st.error(f"Failed to initialize agent: {str(e)}")
                st.stop()
    
    # Chat interface
    chat_container = st.container()
    
    # Display message history
    with chat_container:
        for message in st.session_state.messages:
            if message["role"] == "user":
                with st.chat_message("user", avatar="👤"):
                    st.markdown(message["content"])
            else:
                with st.chat_message("assistant", avatar="🤖"):
                    st.markdown(message["content"])
    
    # Chat input
    if prompt := st.chat_input("Type your message here..."):
        # Add user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Display user message
        with st.chat_message("user", avatar="👤"):
            st.markdown(prompt)
        
        # Get agent response
        with st.chat_message("assistant", avatar="🤖"):
            with st.spinner("Agent is thinking..."):
                try:
                    # Run the appropriate agent
                    if "Protected" in agent_type:
                        response = run_protected_agent(
                            prompt, 
                            st.session_state.agent, 
                            st.session_state.thread_id
                        )
                    else:
                        response = run_vulnerable_agent(
                            prompt, 
                            st.session_state.agent, 
                            st.session_state.thread_id
                        )
                    
                    # Display response
                    st.markdown(response)
                    
                    # Check for security warnings in protected agent
                    if "Protected" in agent_type and "🛡️" in response:
                        st.error("🚨 Security threat detected and blocked!")
                    
                    # Add to message history
                    st.session_state.messages.append({"role": "assistant", "content": response})
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")

with col2:
    st.header("📊 Security Status")
    
    # Security indicators
    if "Protected" in agent_type:
        st.markdown('<div class="honeypot-safe">🛡️ HONEYPOT ACTIVE</div>', unsafe_allow_html=True)
        
        # Count blocked attempts (look for shield emoji in messages)
        blocked_count = sum(
            1 for msg in st.session_state.messages 
            if msg["role"] == "assistant" and "🛡️" in msg["content"]
        )
        
        if blocked_count > 0:
            st.metric("Threats Blocked", blocked_count, delta=f"+{blocked_count}")
        else:
            st.metric("Threats Blocked", 0)
        
        st.success("All actions are evaluated for safety")
        
    else:
        st.markdown('<div class="honeypot-warning">⚠️ NO PROTECTION</div>', unsafe_allow_html=True)
        st.error("Agent vulnerable to prompt injection!")
        st.warning("""
        **Active Risks:**
        - Prompt injection
        - SQL injection
        - Data exfiltration
        - Unauthorized actions
        """)
