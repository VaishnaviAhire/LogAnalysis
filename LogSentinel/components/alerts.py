import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import numpy as np
import time
import random

def display_alerts(alerts_df=None, max_alerts=5):
    """
    Displays a list of recent alerts with their details
    
    Parameters:
    -----------
    alerts_df : pd.DataFrame
        DataFrame containing alert information with columns:
        - timestamp: when the alert was generated
        - severity: the alert severity (Critical, High, Medium, Low)
        - type: type of alert
        - message: detailed alert message
        - source: source of the anomaly
    max_alerts : int
        Maximum number of alerts to display
    """
    # Check if we have alert data
    if alerts_df is None or alerts_df.empty:
        st.info("No active alerts at this time.")
        return
    
    # Severity color mapping
    severity_colors = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#28a745"
    }
    
    # Sort alerts by timestamp (newest first) and severity
    alerts_df = alerts_df.sort_values(by=['timestamp', 'severity'], 
                                     ascending=[False, True])
    
    # Display only the top alerts based on max_alerts
    display_df = alerts_df.head(max_alerts)
    
    # Create live-looking alerts with animation effects
    for i, alert in display_df.iterrows():
        # Calculate how recent the alert is
        time_diff = datetime.now() - alert['timestamp']
        is_recent = time_diff.total_seconds() < 600  # Less than 10 minutes old
        
        # Create a pulsing effect for recent alerts
        pulse_effect = """
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(255, 82, 82, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(255, 82, 82, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 82, 82, 0); }
        }
        """
        
        # Format time string
        if time_diff.days > 0:
            time_str = f"{time_diff.days}d ago"
        elif time_diff.seconds // 3600 > 0:
            time_str = f"{time_diff.seconds // 3600}h ago"
        else:
            time_str = f"{time_diff.seconds // 60}m ago"
            
        # Get color for this severity
        color = severity_colors.get(alert['severity'], '#6c757d')
        
        # Create alert container with enhanced styling
        alert_container = st.container()
        with alert_container:
            st.markdown(f"""
            <style>
                {pulse_effect if is_recent else ""}
                .alert-{i} {{
                    background: rgba(38, 39, 48, 0.8);
                    border-left: 5px solid {color};
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 15px;
                    transition: transform 0.3s ease, box-shadow 0.3s ease;
                    {f"animation: pulse 2s infinite;" if is_recent else ""}
                }}
                .alert-{i}:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0,0,0,0.3);
                }}
                .alert-header {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 10px;
                }}
                .severity-badge {{
                    background-color: {color};
                    color: white;
                    padding: 4px 8px;
                    border-radius: 50px;
                    font-size: 0.8em;
                    font-weight: bold;
                }}
                .alert-type {{
                    font-weight: bold;
                    font-size: 1.1em;
                    margin: 0;
                }}
                .alert-time {{
                    opacity: 0.7;
                    font-size: 0.9em;
                }}
                .alert-details {{
                    display: flex;
                    gap: 5px;
                    flex-direction: column;
                    margin-top: 10px;
                }}
                .detail-row {{
                    display: flex;
                    align-items: flex-start;
                }}
                .detail-label {{
                    width: 80px;
                    opacity: 0.7;
                    font-size: 0.9em;
                }}
                .alert-actions {{
                    display: flex;
                    gap: 10px;
                    margin-top: 15px;
                }}
                .action-button {{
                    background-color: rgba(77, 49, 224, 0.8);
                    color: white;
                    border: none;
                    padding: 8px 12px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 0.9em;
                    transition: background-color 0.2s;
                }}
                .action-button:hover {{
                    background-color: rgba(77, 49, 224, 1);
                }}
                .new-badge {{
                    background-color: #dc3545;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 50px;
                    font-size: 0.7em;
                    margin-left: 10px;
                }}
            </style>
            
            <div class="alert-{i}">
                <div class="alert-header">
                    <div style="display: flex; align-items: center;">
                        <p class="alert-type">{alert['type']}</p>
                        {f'<span class="new-badge">NEW</span>' if is_recent else ''}
                    </div>
                    <span class="severity-badge">{alert['severity']}</span>
                </div>
                
                <p class="alert-time">{time_str} • {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="alert-details">
                    <div class="detail-row">
                        <span class="detail-label">Source:</span>
                        <span>{alert['source']}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Message:</span>
                        <span>{alert['message']}</span>
                    </div>
                </div>
                
                <div class="alert-actions">
                    <button class="action-button" id="investigate-{i}" onclick="
                        document.dispatchEvent(new CustomEvent('streamlit:investigate', {{
                            detail: {{ alertId: {i} }}
                        }}))
                    ">Investigate</button>
                    
                    <button class="action-button" id="acknowledge-{i}" style="background-color: rgba(255,255,255,0.2);" onclick="
                        document.dispatchEvent(new CustomEvent('streamlit:acknowledge', {{
                            detail: {{ alertId: {i} }}
                        }}))
                    ">Acknowledge</button>
                    
                    <button class="action-button" id="dismiss-{i}" style="background-color: rgba(255,255,255,0.2);" onclick="
                        document.dispatchEvent(new CustomEvent('streamlit:dismiss', {{
                            detail: {{ alertId: {i} }}
                        }}))
                    ">Dismiss</button>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Add button actions
        col1, col2, col3 = st.columns(3)
        with col1:
            investigate = st.button("Investigate", key=f"investigate_{i}", help="Investigate this alert")
            if investigate:
                st.session_state['current_page'] = 'logs_analysis'
                st.rerun()
        with col2:
            if st.button("Acknowledge", key=f"acknowledge_{i}", help="Acknowledge this alert"):
                st.success(f"Alert acknowledged: {alert['type']}")
        with col3:
            if st.button("Dismiss", key=f"dismiss_{i}", help="Dismiss this alert"):
                st.info(f"Alert dismissed: {alert['type']}")

def create_sample_alerts(num_alerts=10):
    """
    Creates a sample dataframe of alerts for demonstration purposes.
    In a real application, this would be replaced with actual alert data.
    
    Parameters:
    -----------
    num_alerts : int
        Number of sample alerts to generate
    
    Returns:
    --------
    pd.DataFrame
        DataFrame with sample alert data
    """
    # Enhanced alert types and sources
    alert_types = [
        "Unusual Login Attempt", 
        "Brute Force Attack", 
        "Privilege Escalation", 
        "Data Exfiltration",
        "Configuration Change",
        "Unusual Process Execution",
        "Network Scan Detected",
        "Suspicious File Access",
        "Malware Detected",
        "DDoS Attack Attempt",
        "Ransomware Activity",
        "Lateral Movement",
        "API Key Misuse",
        "Unauthorized Access"
    ]
    
    alert_sources = [
        "Authentication System",
        "Firewall",
        "Database Server",
        "Web Application",
        "Active Directory",
        "File Server",
        "Network IDS",
        "Email Gateway",
        "Web Proxy",
        "Cloud Infrastructure",
        "VPN Gateway",
        "Endpoint Protection",
        "DNS Server",
        "Container Environment"
    ]
    
    # Enhanced alert messages
    alert_messages = [
        "Multiple failed login attempts detected from IP {ip_address}",
        "Excessive authentication failures detected for user {user_name}",
        "User {user_name} attempted to access restricted resources",
        "Large data transfer ({data_size}MB) to external IP {ip_address}",
        "Critical system configuration modified outside change window",
        "Unusual process executed with elevated privileges on {server_name}",
        "Port scanning activity detected from internal IP {ip_address}",
        "Sensitive file access by unauthorized user {user_name}",
        "Signature match: {malware_name} malware detected on {server_name}",
        "Unusual network traffic spike detected ({traffic}Mbps)",
        "Encryption of multiple files detected - possible ransomware",
        "Unusual cross-system authentication detected",
        "API key {key_id} used from unauthorized location",
        "Unusual hours access to critical system by {user_name}"
    ]
    
    # Generate random timestamps within the last 48 hours
    now = datetime.now()
    
    # Create a distribution that favors more recent timestamps
    # With a few very recent alerts for the "NEW" badge effect
    timestamps = []
    for i in range(num_alerts):
        if i < 3:  # Very recent alerts (< 10 minutes)
            minutes = np.random.randint(1, 10)
            timestamps.append(now - timedelta(minutes=minutes))
        elif i < 7:  # Recent alerts (< 3 hours)
            hours = np.random.randint(0, 3)
            minutes = np.random.randint(10, 59)
            timestamps.append(now - timedelta(hours=hours, minutes=minutes))
        else:  # Older alerts
            hours = np.random.randint(3, 48)
            minutes = np.random.randint(0, 59)
            timestamps.append(now - timedelta(hours=hours, minutes=minutes))
    
    # Generate severity with weighted distribution
    severity_options = ["Critical", "High", "Medium", "Low"]
    # Make critical alerts more common for demonstration
    severity_weights = [0.2, 0.3, 0.3, 0.2]
    severities = np.random.choice(severity_options, size=num_alerts, p=severity_weights)
    
    # Generate random indices for types, sources, and messages
    type_indices = np.random.randint(0, len(alert_types), size=num_alerts)
    source_indices = np.random.randint(0, len(alert_sources), size=num_alerts)
    message_indices = np.random.randint(0, len(alert_messages), size=num_alerts)
    
    # Dynamic message parameters
    user_names = ["admin", "johndoe", "alice", "bob", "sysadmin", "dbuser", "guest", "root", "jenkins", "serviceaccount"]
    server_names = ["web-01", "db-02", "auth-server", "file-srv", "app-server", "dc-01", "proxy-01", "container-host"]
    malware_names = ["Emotet", "TrickBot", "Ryuk", "WannaCry", "Dridex", "Mimikatz", "CobaltStrike", "BlackBasta"]
    key_ids = ["API-KEY-01392", "AWS-KEY-5271", "GCP-KEY-9382", "OAUTH-TOKEN-274", "JWT-274891", "SAML-TOKEN-4792"]
    
    # Generate formatted messages
    messages = []
    for i in range(num_alerts):
        msg_template = alert_messages[message_indices[i]]
        ip_octets = np.random.randint(1, 255, size=4)
        ip_address = f"{ip_octets[0]}.{ip_octets[1]}.{ip_octets[2]}.{ip_octets[3]}"
        data_size = np.random.randint(50, 5000)
        traffic = np.random.randint(100, 10000)
        user_name = np.random.choice(user_names)
        server_name = np.random.choice(server_names)
        malware_name = np.random.choice(malware_names)
        key_id = np.random.choice(key_ids)
        
        msg = msg_template.format(
            ip_address=ip_address,
            user_name=user_name,
            data_size=data_size,
            server_name=server_name,
            malware_name=malware_name,
            traffic=traffic,
            key_id=key_id
        )
        messages.append(msg)
    
    # Create DataFrame
    alerts_df = pd.DataFrame({
        'timestamp': timestamps,
        'severity': severities,
        'type': [alert_types[i] for i in type_indices],
        'source': [alert_sources[i] for i in source_indices],
        'message': messages
    })
    
    # Sort by timestamp (newest first)
    alerts_df = alerts_df.sort_values('timestamp', ascending=False)
    
    return alerts_df
