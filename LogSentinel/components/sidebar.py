import streamlit as st
from datetime import datetime, timedelta
import pandas as pd
import random

def sidebar():
    """
    Creates and manages the sidebar navigation and app controls
    Returns the selected page name
    """
    with st.sidebar:
        # Add enhanced logo and header
        st.markdown("""
        <div style="text-align: center; margin-bottom: 20px;">
            <h1 style="color: #4d31e0; margin-bottom: 0;">CyberSentry</h1>
            <p style="opacity: 0.7; margin-top: 0;">Security Intelligence</p>
        </div>
        """, unsafe_allow_html=True)
        
        # User profile section
        user_container = st.container()
        with user_container:
            col1, col2 = st.columns([1, 3])
            with col1:
                st.markdown("""
                <div style="width: 50px; height: 50px; border-radius: 50%; background: #4d31e0; 
                     display: flex; align-items: center; justify-content: center; margin: 0 auto;">
                    <span style="color: white; font-size: 24px;">👤</span>
                </div>
                """, unsafe_allow_html=True)
            with col2:
                st.markdown("""
                <div>
                    <h4 style="margin: 0; padding: 0;">Security Analyst</h4>
                    <p style="margin: 0; padding: 0; opacity: 0.7;">Admin</p>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("<hr style='margin: 20px 0; opacity: 0.2;'>", unsafe_allow_html=True)
        
        # Navigation with icons and enhanced style
        st.markdown("<h3>Navigation</h3>", unsafe_allow_html=True)
        
        # Create custom navigation buttons
        nav_options = [
            {"name": "Dashboard", "icon": "📊", "id": "dashboard"},
            {"name": "Log Anomaly Analysis", "icon": "🔍", "id": "logs_analysis"},
            {"name": "User Behavior Analytics", "icon": "👥", "id": "user_behavior"},
            {"name": "Gemini Chatbot", "icon": "🤖", "id": "chatbot"}
        ]
        
        # Determine current page index
        current_index = 0
        if 'current_page' in st.session_state:
            for i, option in enumerate(nav_options):
                if option["id"] == st.session_state['current_page']:
                    current_index = i
        
        # Create enhanced radio buttons
        selected_idx = 0
        for i, option in enumerate(nav_options):
            is_active = i == current_index
            bg_color = "#4d31e0" if is_active else "rgba(255,255,255,0.05)"
            text_color = "white" if is_active else "#cccccc"
            border_left = "4px solid #4d31e0" if is_active else "4px solid transparent"
            
            if st.button(
                f"{option['icon']} {option['name']}", 
                key=f"nav_{option['id']}",
                use_container_width=True,
                help=f"Navigate to {option['name']}",
                type="primary" if is_active else "secondary"
            ):
                selected_idx = i
        
        # Update session state with selected page
        selected_page = nav_options[selected_idx]["id"]
        st.session_state['current_page'] = selected_page
        
        # Add visual separator
        st.markdown("<hr style='margin: 20px 0; opacity: 0.2;'>", unsafe_allow_html=True)
        
        # System Status with enhanced styling
        st.markdown("""
        <h3 style="margin-bottom: 15px;">System Status</h3>
        """, unsafe_allow_html=True)
        
        # Create custom system status indicators
        status_cols = st.columns(2)
        
        with status_cols[0]:
            st.markdown("""
            <div style="background: rgba(38, 39, 48, 0.8); padding: 10px; border-radius: 5px; text-align: center;">
                <h4 style="margin: 0; color: #4d31e0;">ML Engine</h4>
                <div style="display: flex; align-items: center; justify-content: center; margin-top: 5px;">
                    <span style="width: 10px; height: 10px; background: #28a745; border-radius: 50%; margin-right: 5px;"></span>
                    <span>Online</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
        with status_cols[1]:
            st.markdown("""
            <div style="background: rgba(38, 39, 48, 0.8); padding: 10px; border-radius: 5px; text-align: center;">
                <h4 style="margin: 0; color: #4d31e0;">Processing</h4>
                <div style="display: flex; align-items: center; justify-content: center; margin-top: 5px;">
                    <span style="width: 10px; height: 10px; background: #28a745; border-radius: 50%; margin-right: 5px;"></span>
                    <span>Real-time</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Add live activity feed
        st.markdown("""
        <h3 style="margin: 15px 0 10px 0;">Live Activity</h3>
        """, unsafe_allow_html=True)
        
        # Generate some random activity for the live feed
        if 'last_activity_time' not in st.session_state:
            st.session_state['last_activity_time'] = datetime.now()
        
        # Every 5 seconds, update the activity feed
        now = datetime.now()
        if (now - st.session_state['last_activity_time']).total_seconds() > 5:
            if 'activities' not in st.session_state:
                st.session_state['activities'] = []
            
            # Generate a new activity and add it to the beginning of the list
            activity_types = ["Log analysis", "Authentication", "Network scan", "File access", "Config change"]
            systems = ["Web server", "Database", "Firewall", "Auth system", "File server"]
            
            new_activity = {
                "type": random.choice(activity_types),
                "system": random.choice(systems),
                "time": now,
                "is_anomaly": random.random() < 0.3  # 30% chance of being anomalous
            }
            
            st.session_state['activities'].insert(0, new_activity)
            
            # Keep only the most recent 5 activities
            if len(st.session_state['activities']) > 5:
                st.session_state['activities'] = st.session_state['activities'][:5]
            
            st.session_state['last_activity_time'] = now
        
        # Display activities
        if 'activities' in st.session_state:
            for activity in st.session_state['activities']:
                activity_time = activity['time']
                seconds_ago = int((now - activity_time).total_seconds())
                time_str = f"{seconds_ago}s ago" if seconds_ago < 60 else f"{seconds_ago // 60}m ago"
                
                color = "#dc3545" if activity['is_anomaly'] else "#6c757d"
                icon = "⚠️" if activity['is_anomaly'] else "✓"
                
                st.markdown(f"""
                <div style="padding: 8px; margin-bottom: 8px; border-radius: 5px; 
                     background: rgba(38, 39, 48, 0.8); border-left: 3px solid {color};">
                    <div style="display: flex; justify-content: space-between;">
                        <span>{activity['type']} on {activity['system']}</span>
                        <span style="opacity: 0.7;">{time_str}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 5px;">
                        <span style="opacity: 0.7;">{"Anomalous activity detected" if activity['is_anomaly'] else "Normal activity"}</span>
                        <span>{icon}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        # Settings section with enhanced styling
        st.markdown("<hr style='margin: 20px 0; opacity: 0.2;'>", unsafe_allow_html=True)
        st.markdown("<h3>Settings</h3>", unsafe_allow_html=True)
        
        with st.expander("Dashboard Settings", expanded=False):
            # Settings options with improved UI
            refresh_rate = st.slider("Dashboard Refresh (min)", 1, 30, 5)
            st.session_state['refresh_rate'] = refresh_rate
            
            # More settings options
            st.checkbox("Enable real-time alerts", value=True)
            st.checkbox("Show critical events only", value=False)
            
            # Add a select for visualization type
            viz_type = st.selectbox(
                "Visualization Style",
                options=["Modern", "Classic", "Minimal", "High Contrast"]
            )
            st.session_state['viz_style'] = viz_type
        
        # Time range selector with improved UI
        with st.expander("Time Range", expanded=False):
            time_range = st.selectbox(
                "Select Time Range",
                options=["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom"]
            )
            st.session_state['time_range'] = time_range
            
            if time_range == "Custom":
                col1, col2 = st.columns(2)
                with col1:
                    start_date = st.date_input("Start Date", datetime.now() - timedelta(days=7))
                with col2:
                    end_date = st.date_input("End Date", datetime.now())
                st.session_state['custom_start'] = start_date
                st.session_state['custom_end'] = end_date
        
        return selected_page
