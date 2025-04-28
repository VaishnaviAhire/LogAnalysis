import streamlit as st
import os
import pandas as pd
import numpy as np
from components.sidebar import sidebar
import time
import base64

# Page configuration
st.set_page_config(
    page_title="CyberSentry - ML Anomaly Detection Platform",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS to make UI more attractive
st.markdown("""
<style>
    .stApp {
        background-size: cover;
        background-position: center;
    }
    .stTitleBlock {
        text-align: center;
        padding: 1rem;
        background: rgba(13, 17, 23, 0.7);
        border-radius: 5px;
        margin-bottom: 20px;
    }
    .st-emotion-cache-16txtl3 h1, .st-emotion-cache-16txtl3 h2 {
        color: #4d31e0;
        letter-spacing: 1px;
    }
    .dashboard-card {
        background: rgba(38, 39, 48, 0.8);
        border-radius: 10px;
        padding: 15px;
        border-left: 5px solid #4d31e0;
        margin-bottom: 15px;
        transition: transform 0.3s ease;
    }
    .dashboard-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 20px rgba(0,0,0,0.3);
    }
    .floating-chat-btn {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background-color: #4d31e0;
        color: white;
        text-align: center;
        line-height: 60px;
        font-size: 24px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        z-index: 1000;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    .floating-chat-btn:hover {
        background-color: #6e58e8;
        transform: scale(1.1);
    }
    .chat-container {
        position: fixed;
        bottom: 90px;
        right: 20px;
        width: 350px;
        height: 450px;
        background-color: #1e1e2d;
        border-radius: 10px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.3);
        z-index: 1000;
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }
    .chat-header {
        background-color: #4d31e0;
        color: white;
        padding: 10px 15px;
        font-weight: bold;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .chat-body {
        flex: 1;
        overflow-y: auto;
        padding: 15px;
    }
    .chat-input {
        display: flex;
        border-top: 1px solid #444;
        padding: 10px;
    }
    .user-message {
        background-color: #4d31e0;
        color: white;
        border-radius: 15px 15px 0 15px;
        padding: 8px 15px;
        margin: 5px 0;
        max-width: 80%;
        align-self: flex-end;
        margin-left: auto;
    }
    .bot-message {
        background-color: #3a3a4a;
        color: white;
        border-radius: 15px 15px 15px 0;
        padding: 8px 15px;
        margin: 5px 0;
        max-width: 80%;
    }
    .plotly-graph {
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    .metric-card {
        background: rgba(38, 39, 48, 0.7);
        border-radius: 10px;
        padding: 15px;
        border-bottom: 3px solid #4d31e0;
        transition: all 0.3s ease;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 16px rgba(0,0,0,0.2);
    }
    .st-emotion-cache-1wmy9hl:hover {
        border-color: #4d31e0 !important;
    }
    div.stButton > button:hover {
        background-color: #4d31e0;
        color: white;
        border: none;
    }
</style>
""", unsafe_allow_html=True)

# Check if session state exists for navigation and chatbot
if 'current_page' not in st.session_state:
    st.session_state['current_page'] = 'dashboard'
if 'chat_visible' not in st.session_state:
    st.session_state['chat_visible'] = False
if 'chat_messages' not in st.session_state:
    st.session_state['chat_messages'] = [
        {"role": "assistant", "content": "Hello! I'm your CyberSentry AI assistant. How can I help you with security monitoring today?"}
    ]

# Import pages
from pages.dashboard import show_dashboard
from pages.logs_analysis import show_logs_analysis
from pages.user_behavior import show_user_behavior
from pages.chatbot import show_chatbot, generate_fallback_response
from utils.data_processor import LogProcessor, UserActivityProcessor

# Title and description with animated background
st.markdown("""
<div class="stTitleBlock">
    <h1>CyberSentry</h1>
    <h3>ML-based Cybersecurity Anomaly Detection Platform</h3>
</div>
""", unsafe_allow_html=True)

# Sidebar for navigation
selected_page = sidebar()

# Display the selected page
if selected_page == "dashboard":
    show_dashboard()
elif selected_page == "logs_analysis":
    show_logs_analysis()
elif selected_page == "user_behavior":
    show_user_behavior()
elif selected_page == "chatbot":
    show_chatbot()

# Add floating chat button
st.markdown("""
<div class="floating-chat-btn" onclick="toggleChat()" id="chat-button">
    💬
</div>
""", unsafe_allow_html=True)

# Chatbot container (initially hidden)
if st.session_state['chat_visible']:
    st.markdown("""
    <div class="chat-container" id="chat-container">
        <div class="chat-header">
            <div>CyberSentry Assistant</div>
            <div style="cursor: pointer;" onclick="toggleChat()">✕</div>
        </div>
        <div class="chat-body" id="chat-body">
    """, unsafe_allow_html=True)
    
    # Display chat messages
    for message in st.session_state['chat_messages']:
        if message["role"] == "user":
            st.markdown(f'<div class="user-message">{message["content"]}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="bot-message">{message["content"]}</div>', unsafe_allow_html=True)
    
    st.markdown("""
        </div>
        <div class="chat-input">
            <input type="text" id="chat-input-field" placeholder="Type your question..." style="flex-grow: 1; margin-right: 10px; padding: 8px; border-radius: 5px; border: 1px solid #444; background: #2d2d3a; color: white;">
            <button onclick="sendMessage()" style="background: #4d31e0; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer;">Send</button>
        </div>
    </div>
    """, unsafe_allow_html=True)

# JavaScript for chatbot functionality
st.markdown("""
<script>
function toggleChat() {
    const event = new CustomEvent('streamlit:toggleChat');
    window.dispatchEvent(event);
}

function sendMessage() {
    const inputField = document.getElementById('chat-input-field');
    const message = inputField.value.trim();
    
    if (message) {
        const event = new CustomEvent('streamlit:sendMessage', {
            detail: { message: message }
        });
        window.dispatchEvent(event);
        inputField.value = '';
    }
}

// Support for Enter key
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('chat-input-field').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
});
</script>
""", unsafe_allow_html=True)

# Handle chatbot toggle
if 'chat_toggle_key' not in st.session_state:
    st.session_state['chat_toggle_key'] = 0

# Create a container for the chat input
chat_input_container = st.empty()

# Process chatbot input (hidden from main UI)
with st.sidebar:
    # Hidden buttons for JavaScript to trigger
    toggle_chat = st.button("Toggle Chat", key=f"toggle_chat_{st.session_state['chat_toggle_key']}", 
                           help="This button is controlled by JavaScript and toggles the chat visibility")
    
    if toggle_chat:
        st.session_state['chat_visible'] = not st.session_state['chat_visible']
        st.session_state['chat_toggle_key'] += 1
        st.rerun()
    
    # Process chat message if visible
    if st.session_state['chat_visible']:
        chat_input = st.text_input("Chat Input", key="chat_text_input", 
                                  label_visibility="collapsed",
                                  help="Type your message here")
        
        if chat_input:
            # Add user message to chat
            st.session_state['chat_messages'].append({
                "role": "user",
                "content": chat_input
            })
            
            # Generate response
            try:
                # Initialize data processors if not already in session state
                if 'log_processor' not in st.session_state:
                    log_processor = LogProcessor()
                    st.session_state['log_processor'] = log_processor
                
                if 'user_activity_processor' not in st.session_state:
                    user_activity_processor = UserActivityProcessor()
                    st.session_state['user_activity_processor'] = user_activity_processor
                
                # Generate sample data for context
                log_data = st.session_state['log_processor'].generate_sample_logs(
                    num_logs=1000, 
                    include_anomalies=True
                )
                
                user_activity = st.session_state['user_activity_processor'].generate_sample_user_activity(
                    num_users=50,
                    num_activities=1000
                )
                
                # Generate fallback response
                response = generate_fallback_response(chat_input, log_data, user_activity)
                
                # Add assistant response to chat
                st.session_state['chat_messages'].append({
                    "role": "assistant",
                    "content": response
                })
            except Exception as e:
                # Add error response to chat
                st.session_state['chat_messages'].append({
                    "role": "assistant",
                    "content": f"I'm sorry, I encountered an error: {str(e)}"
                })
            
            # Force a page rerun to update the chat
            st.rerun()

# Footer with improved styling
st.markdown("---")
footer_cols = st.columns(3)
with footer_cols[0]:
    st.markdown("<div style='text-align: left;'>© 2025 CyberSentry</div>", unsafe_allow_html=True)
with footer_cols[1]:
    st.markdown("<div style='text-align: center;'>Advanced ML-based Anomaly Detection</div>", unsafe_allow_html=True)
with footer_cols[2]:
    st.markdown("<div style='text-align: right;'>v1.0.0</div>", unsafe_allow_html=True)
