import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import google.generativeai as genai
import os
from utils.data_processor import LogProcessor, UserActivityProcessor
from models.anomaly_detector import LogAnomalyDetector, AnomalyClassifier
from models.user_behavior import UserBehaviorAnalyzer

def show_chatbot():
    """
    Display the Gemini chatbot integration page
    """
    st.header("Gemini Security Chatbot")
    
    # Initialize Gemini API
    gemini_api_key = os.getenv("GEMINI_API_KEY", "REPLACE_WITH_GEMINI_API_KEY")
    
    # Configure the generative AI
    try:
        genai.configure(api_key=gemini_api_key)
        model = genai.GenerativeModel('gemini-pro')
    except Exception as e:
        st.error(f"Error initializing Gemini API: {str(e)}")
        st.info("Using a simplified chatbot experience for this demonstration.")
        model = None
    
    # Initialize chat history in session state if it doesn't exist
    if 'chat_history' not in st.session_state:
        st.session_state['chat_history'] = []
    
    # Initialize data processors if not already in session state
    if 'log_processor' not in st.session_state:
        st.session_state['log_processor'] = LogProcessor()
    
    if 'user_activity_processor' not in st.session_state:
        st.session_state['user_activity_processor'] = UserActivityProcessor()
    
    # Generate sample data for context
    with st.spinner("Preparing security context..."):
        # Generate sample log data
        log_data = st.session_state['log_processor'].generate_sample_logs(
            num_logs=1000, 
            include_anomalies=True
        )
        
        # Generate sample user activity data
        user_activity = st.session_state['user_activity_processor'].generate_sample_user_activity(
            num_users=50,
            num_activities=1000
        )
    
    # Prepare system context for the chatbot
    system_context = prepare_system_context(log_data, user_activity)
    
    # Display welcome message
    if not st.session_state['chat_history']:
        st.info("""
        # Welcome to the Gemini Security Chatbot
        
        I'm here to help you analyze security data and provide insights about your system. You can ask me questions like:
        
        - "Show me the latest critical anomalies"
        - "What unusual user behavior was detected today?"
        - "Analyze the authentication anomalies"
        - "Summarize the security status of our systems"
        - "What actions should I take regarding the network anomalies?"
        
        How can I assist with your security monitoring today?
        """)
    
    # Display chat history
    for message in st.session_state['chat_history']:
        if message['role'] == 'user':
            st.markdown(f"**You:** {message['content']}")
        else:
            st.markdown(f"**Gemini:** {message['content']}")
    
    # Chat input
    user_input = st.text_input("Ask a security question:", key="user_input")
    
    if user_input:
        # Add user message to chat history
        st.session_state['chat_history'].append({
            'role': 'user',
            'content': user_input
        })
        
        # Display user message
        st.markdown(f"**You:** {user_input}")
        
        # Generate response
        if model:
            try:
                # Process with Gemini API
                with st.spinner("Analyzing security data..."):
                    prompt = f"{system_context}\n\nUser question: {user_input}"
                    response = model.generate_content(prompt)
                    response_text = response.text
            except Exception as e:
                st.error(f"Error generating response: {str(e)}")
                response_text = generate_fallback_response(user_input, log_data, user_activity)
        else:
            # Fall back to pre-defined responses
            response_text = generate_fallback_response(user_input, log_data, user_activity)
        
        # Add response to chat history
        st.session_state['chat_history'].append({
            'role': 'assistant',
            'content': response_text
        })
        
        # Display assistant message
        st.markdown(f"**Gemini:** {response_text}")
        
        # Clear the input box after submitting
        st.rerun()

def prepare_system_context(log_data, user_activity):
    """
    Prepare system context from security data for the chatbot
    
    Parameters:
    -----------
    log_data : pd.DataFrame
        DataFrame containing log data
    user_activity : pd.DataFrame
        DataFrame containing user activity data
    
    Returns:
    --------
    str
        System context for the chatbot
    """
    # Calculate key metrics
    total_logs = len(log_data)
    anomaly_count = log_data['is_anomaly'].sum()
    anomaly_percentage = (anomaly_count / total_logs) * 100 if total_logs > 0 else 0
    
    unique_users = user_activity['user_id'].nunique()
    users_with_anomalies = user_activity[user_activity['is_anomaly']]['user_id'].nunique()
    
    # Create anomaly summary by source
    anomaly_by_source = log_data[log_data['is_anomaly']].groupby('source').size()
    anomaly_sources = ", ".join([f"{source}: {count}" for source, count in anomaly_by_source.items()])
    
    # Prepare list of critical anomalies
    critical_anomalies = log_data[(log_data['is_anomaly']) & (log_data['level'] == 'CRITICAL')]
    critical_list = "\n".join([
        f"- {row['timestamp']}: {row['message']} (Source: {row['source']})"
        for _, row in critical_anomalies.head(5).iterrows()
    ])
    
    if not critical_list:
        critical_list = "No critical anomalies detected."
    
    # Time range of data
    if 'timestamp' in log_data.columns and not log_data.empty:
        start_time = log_data['timestamp'].min()
        end_time = log_data['timestamp'].max()
        time_range = f"{start_time} to {end_time}"
    else:
        time_range = "Unknown time range"
    
    # Create context
    context = f"""
    You are a cybersecurity analyst AI assistant integrated into a security monitoring platform.
    Answer questions about the security data based on the following context.
    
    CURRENT SECURITY SUMMARY:
    - Time range: {time_range}
    - Total logs analyzed: {total_logs}
    - Anomalies detected: {anomaly_count} ({anomaly_percentage:.2f}%)
    - Total users monitored: {unique_users}
    - Users with suspicious activity: {users_with_anomalies}
    
    ANOMALY DISTRIBUTION BY SOURCE:
    {anomaly_sources}
    
    RECENT CRITICAL ANOMALIES:
    {critical_list}
    
    When answering:
    1. Focus on security insights and actionable recommendations
    2. Provide specific details from the data when available
    3. For questions outside this context, suggest what data might help answer them
    4. Keep responses security-focused and professional
    5. When recommending actions, prioritize by severity
    """
    
    return context

def generate_fallback_response(user_input, log_data, user_activity):
    """
    Generate a fallback response when Gemini API is not available
    
    Parameters:
    -----------
    user_input : str
        User's question
    log_data : pd.DataFrame
        DataFrame containing log data
    user_activity : pd.DataFrame
        DataFrame containing user activity data
    
    Returns:
    --------
    str
        Fallback response
    """
    # Convert to lowercase for easier matching
    input_lower = user_input.lower()
    
    # Calculate basic metrics for responses
    anomaly_count = log_data['is_anomaly'].sum()
    critical_count = len(log_data[(log_data['is_anomaly']) & (log_data['level'] == 'CRITICAL')])
    users_with_anomalies = user_activity[user_activity['is_anomaly']]['user_id'].nunique()
    
    # Pattern matching for common questions
    if any(term in input_lower for term in ['critical', 'severe', 'urgent', 'important']):
        return f"""
        I've identified {critical_count} critical security anomalies in the logs. These represent the highest severity issues requiring immediate attention.
        
        The most concerning anomalies are:
        1. Multiple failed authentication attempts from unusual locations
        2. Suspicious configuration changes to critical systems
        3. Unusual network traffic patterns potentially indicating data exfiltration
        
        I recommend prioritizing investigation of these issues, starting with the authentication anomalies as they could indicate an active compromise attempt.
        """
    
    elif any(term in input_lower for term in ['user', 'behavior', 'activity', 'suspicious']):
        return f"""
        Analysis of user behavior has identified {users_with_anomalies} users with suspicious activity patterns. 
        
        Key concerns include:
        - Users accessing systems outside normal working hours
        - Unusual resource access patterns for 3 administrative users
        - Excessive failed login attempts for several accounts
        - Abnormal data access volumes for 2 users in the finance department
        
        I recommend investigating user21 and user45 first as their behavior deviation is most significant.
        """
    
    elif any(term in input_lower for term in ['network', 'traffic', 'connection', 'communication']):
        return """
        Network analysis shows several anomalous patterns:
        
        1. Unusual outbound connections to IP ranges not typically seen in your environment
        2. Periodic beaconing activity from 3 internal hosts
        3. Unencrypted data transfers containing potentially sensitive information
        4. DNS queries to domains with low reputation scores
        
        This could indicate command and control activity or data exfiltration attempts. I recommend isolating the affected hosts (192.168.32.15, 192.168.45.7, 192.168.28.9) for further investigation.
        """
    
    elif any(term in input_lower for term in ['summary', 'overview', 'status', 'report']):
        return f"""
        Current Security Status Summary:
        
        - Total anomalies detected: {anomaly_count}
        - Critical severity issues: {critical_count}
        - Users with suspicious activity: {users_with_anomalies}
        - Systems showing signs of compromise: 5
        
        Overall security posture: ELEVATED CONCERN
        
        Most affected systems: Authentication servers, Database servers, and File storage systems
        
        Key recommendations:
        1. Investigate critical authentication anomalies
        2. Review recent configuration changes
        3. Monitor suspicious user accounts closely
        4. Analyze network traffic patterns for data exfiltration
        """
    
    elif any(term in input_lower for term in ['recommend', 'action', 'step', 'what should', 'how to']):
        return """
        Based on the current security analysis, I recommend the following actions:
        
        Immediate actions:
        1. Investigate and contain hosts showing signs of compromise
        2. Reset credentials for accounts with suspicious login activity
        3. Block outbound connections to flagged IP addresses
        
        Short-term actions:
        1. Review all privileged user accounts and their access patterns
        2. Verify integrity of critical configuration files
        3. Implement additional monitoring for sensitive data access
        
        Long-term improvements:
        1. Enhance authentication controls with multi-factor authentication
        2. Implement network segmentation for critical systems
        3. Develop baseline profiles for normal user behavior
        4. Conduct security awareness training focusing on current threats
        """
    
    else:
        # Generic response for other queries
        return """
        Based on the security data analysis, I can provide insights on several areas of concern:
        
        1. Authentication systems show unusual patterns of failed login attempts
        2. Several users have accessed sensitive resources outside their normal patterns
        3. Network traffic analysis indicates potential data exfiltration attempts
        4. Configuration changes have been made outside approved maintenance windows
        
        Would you like me to focus on a specific aspect of this analysis? I can provide more details on anomalies by type, affected systems, user behavior, or recommended actions.
        """
