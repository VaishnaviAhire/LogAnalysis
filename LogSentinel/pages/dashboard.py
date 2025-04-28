import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import altair as alt
from datetime import datetime, timedelta
from utils.data_processor import LogProcessor, UserActivityProcessor
from models.anomaly_detector import LogAnomalyDetector, AnomalyClassifier
from models.user_behavior import UserBehaviorAnalyzer
from components.anomaly_card import anomaly_card
from components.alerts import display_alerts, create_sample_alerts
import time
import random

def show_dashboard():
    """
    Display the main dashboard with key metrics and visualizations
    """
    # Add interactive welcome message that disappears after 3 seconds
    if 'dashboard_first_load' not in st.session_state:
        st.session_state['dashboard_first_load'] = True
        st.session_state['dashboard_load_time'] = time.time()
    
    current_time = time.time()
    if st.session_state['dashboard_first_load'] and current_time - st.session_state['dashboard_load_time'] < 4:
        welcome_container = st.container()
        with welcome_container:
            st.markdown("""
            <div style="background: linear-gradient(90deg, rgba(77, 49, 224, 0.9), rgba(77, 49, 224, 0.7)); 
                        padding: 20px; border-radius: 10px; text-align: center; margin-bottom: 20px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.3); animation: fadeIn 0.5s ease-in;">
                <h2 style="margin: 0; color: white;">Welcome to the CyberSentry Dashboard</h2>
                <p style="margin: 5px 0 0 0; color: rgba(255,255,255,0.9);">
                    Your security data is being analyzed in real-time
                </p>
            </div>
            <style>
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(-20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            </style>
            """, unsafe_allow_html=True)
            time.sleep(3)
            st.session_state['dashboard_first_load'] = False
            st.rerun()
    
    # Header with tabs for different views
    st.markdown("""
    <div style="margin-bottom: 20px;">
        <h2 style="margin: 0; color: #4d31e0;">Security Dashboard</h2>
        <p style="opacity: 0.7; margin-top: 0;">Real-time security monitoring and analytics</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Dashboard tabs
    tab1, tab2, tab3 = st.tabs(["📊 Overview", "🔔 Alerts", "🔍 Detailed Analysis"])
    
    # Initialize data processors if not already in session state
    if 'log_processor' not in st.session_state:
        st.session_state['log_processor'] = LogProcessor()
    
    if 'user_activity_processor' not in st.session_state:
        st.session_state['user_activity_processor'] = UserActivityProcessor()
    
    # For demonstration, generate sample data each time
    # In a real application, this would come from actual log sources
    with st.spinner("Loading security data..."):
        # Generate sample log data
        log_data = st.session_state['log_processor'].generate_sample_logs(
            num_logs=1000, 
            include_anomalies=True, 
            anomaly_percentage=0.05
        )
        
        # Generate sample user activity data
        user_activity = st.session_state['user_activity_processor'].generate_sample_user_activity(
            num_users=50,
            num_activities=1000,
            include_anomalies=True
        )
        
        # Generate sample alerts
        alerts = create_sample_alerts(15)
    
    # Calculate metrics
    total_anomalies = log_data['is_anomaly'].sum()
    anomaly_percentage = (total_anomalies / len(log_data)) * 100
    critical_anomalies = len(log_data[(log_data['is_anomaly']) & (log_data['level'] == 'CRITICAL')])
    users_with_anomalies = user_activity[user_activity['is_anomaly']]['user_id'].nunique()
    systems_affected = log_data[log_data['is_anomaly']]['source'].nunique()
    
    # Initialize anomaly classifier
    anomaly_classifier = AnomalyClassifier()
    
    # Classify anomalies
    log_data_anomalies = log_data[log_data['is_anomaly']]
    if not log_data_anomalies.empty:
        log_data_anomalies['category'] = anomaly_classifier.classify_batch(log_data_anomalies)
        log_data_anomalies['severity'] = anomaly_classifier.calculate_severity_batch(log_data_anomalies)
        
        # Count by category
        category_counts = log_data_anomalies.groupby('category').size().reset_index(name='count')
    
    #####################
    # OVERVIEW TAB
    #####################
    with tab1:
        # Animated summary metrics in cards with gradient backgrounds
        st.markdown("""
        <div style="display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 24px;">
        """, unsafe_allow_html=True)
        
        # Calculate security score (demonstration value)
        security_score = 100 - min(100, (anomaly_percentage * 10))
        score_color = "#28a745" if security_score >= 80 else "#ffc107" if security_score >= 60 else "#dc3545"
        
        # Metrics in individual cards with enhanced styling
        metrics = [
            {
                "title": "Security Score", 
                "value": f"{security_score:.1f}", 
                "delta": "+2.5%" if security_score > 80 else "-1.3%",
                "icon": "🛡️",
                "color": score_color
            },
            {
                "title": "Anomalies Detected", 
                "value": f"{total_anomalies}", 
                "delta": f"{anomaly_percentage:.1f}%",
                "icon": "⚠️",
                "color": "#fd7e14"
            },
            {
                "title": "Critical Events", 
                "value": f"{critical_anomalies}", 
                "delta": f"+{random.randint(1, 3)}" if critical_anomalies > 0 else "0",
                "icon": "🔥",
                "color": "#dc3545"
            },
            {
                "title": "Suspicious Users", 
                "value": f"{users_with_anomalies}", 
                "delta": f"+{random.randint(0, 2)}" if users_with_anomalies > 0 else "0",
                "icon": "👤",
                "color": "#4d31e0"
            }
        ]
        
        metric_cols = st.columns(len(metrics))
        
        for i, metric in enumerate(metrics):
            with metric_cols[i]:
                st.markdown(f"""
                <div class="metric-card" style="cursor: pointer;" onclick="alert('Detailed {metric['title']} metrics')">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <p style="margin: 0; opacity: 0.7; font-size: 0.9em;">{metric['title']}</p>
                            <h2 style="margin: 5px 0; font-size: 2.2em; font-weight: bold; color: {metric['color']};">
                                {metric['value']}
                            </h2>
                            <p style="margin: 0; font-size: 0.9em; color: {metric['color']};">{metric['delta']}</p>
                        </div>
                        <div style="font-size: 2em; opacity: 0.8;">{metric['icon']}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Middle row - Anomaly trend and distribution
        col1, col2 = st.columns(2)
        
        with col1:
            # Enhanced anomaly trend over time with area chart
            log_data['date'] = log_data['timestamp'].dt.floor('h')  # Using 'h' instead of 'H'
            anomaly_trend = log_data.groupby(['date', 'is_anomaly']).size().reset_index(name='count')
            anomaly_trend = anomaly_trend.pivot(index='date', columns='is_anomaly', values='count').reset_index()
            anomaly_trend.columns = ['date', 'normal', 'anomaly']
            anomaly_trend.fillna(0, inplace=True)
            
            # Calculate the moving average for smoother lines
            window_size = 3
            if len(anomaly_trend) > window_size:
                anomaly_trend['anomaly_smooth'] = anomaly_trend['anomaly'].rolling(window=window_size, min_periods=1).mean()
                anomaly_trend['normal_smooth'] = anomaly_trend['normal'].rolling(window=window_size, min_periods=1).mean()
            else:
                anomaly_trend['anomaly_smooth'] = anomaly_trend['anomaly']
                anomaly_trend['normal_smooth'] = anomaly_trend['normal']
            
            # Create enhanced figure with area fills
            fig = go.Figure()
            
            # Add normal activity area
            fig.add_trace(go.Scatter(
                x=anomaly_trend['date'],
                y=anomaly_trend['normal_smooth'],
                name='Normal Activity',
                line=dict(color='rgba(53, 151, 255, 1)', width=3),
                mode='lines',
            ))
            
            # Add anomaly area with gradient fill
            fig.add_trace(go.Scatter(
                x=anomaly_trend['date'],
                y=anomaly_trend['anomaly_smooth'],
                name='Anomalies',
                line=dict(color='rgba(220, 53, 69, 1)', width=3),
                mode='lines',
                fill='tozeroy',
                fillcolor='rgba(220, 53, 69, 0.2)'
            ))
            
            # Enhance layout
            fig.update_layout(
                title='Activity Trend (Last 7 Days)',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="center",
                    x=0.5
                ),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=10, r=10, t=60, b=10),
                hovermode='x unified',
                xaxis=dict(
                    showgrid=False,
                    gridcolor='rgba(255,255,255,0.1)',
                    showline=True,
                    linewidth=1,
                    linecolor='rgba(255,255,255,0.2)',
                ),
                yaxis=dict(
                    showgrid=True,
                    gridcolor='rgba(255,255,255,0.1)',
                    showline=True,
                    linewidth=1,
                    linecolor='rgba(255,255,255,0.2)',
                ),
                height=350,
                hoverlabel=dict(
                    bgcolor="#262730",
                    font_size=12,
                )
            )
            
            # Add annotations for peaks
            if len(anomaly_trend) > 0:
                max_anomaly_idx = anomaly_trend['anomaly'].idxmax()
                max_anomaly_date = anomaly_trend.iloc[max_anomaly_idx]['date']
                max_anomaly_count = anomaly_trend.iloc[max_anomaly_idx]['anomaly']
                
                if max_anomaly_count > 0:
                    fig.add_annotation(
                        x=max_anomaly_date,
                        y=max_anomaly_count,
                        text="Peak",
                        showarrow=True,
                        arrowhead=2,
                        arrowsize=1,
                        arrowwidth=2,
                        arrowcolor="#dc3545",
                        font=dict(color="#ffffff"),
                        bgcolor="#dc3545",
                        bordercolor="#dc3545",
                        borderwidth=2,
                        borderpad=4,
                        opacity=0.8
                    )
            
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
        
        with col2:
            # Create an enhanced 3D distribution chart for anomalies
            if 'category' in log_data_anomalies.columns and not log_data_anomalies.empty:
                # Get severity levels in correct order
                severity_order = ["Critical", "High", "Medium", "Low"]
                
                # Aggregate anomalies by category and severity
                severity_category = log_data_anomalies.groupby(['category', 'severity']).size().reset_index(name='count')
                
                # Create categorical color scale
                color_scale = {
                    'Critical': '#dc3545',
                    'High': '#fd7e14',
                    'Medium': '#ffc107',
                    'Low': '#28a745'
                }
                
                # Create 3D bubble chart
                fig = px.scatter_3d(
                    severity_category,
                    x='category',
                    y='severity',
                    z='count',
                    size='count',
                    color='severity',
                    color_discrete_map=color_scale,
                    opacity=0.7,
                    title='Anomaly Distribution by Category and Severity',
                    labels={'count': 'Count', 'category': 'Category', 'severity': 'Severity'},
                    height=350
                )
                
                # Customize 3D chart
                fig.update_layout(
                    scene=dict(
                        xaxis=dict(
                            showbackground=False,
                            gridcolor='rgba(255,255,255,0.1)',
                            title_font=dict(color='white'),
                        ),
                        yaxis=dict(
                            showbackground=False,
                            gridcolor='rgba(255,255,255,0.1)',
                            title_font=dict(color='white'),
                            categoryorder='array',
                            categoryarray=severity_order
                        ),
                        zaxis=dict(
                            showbackground=False,
                            gridcolor='rgba(255,255,255,0.1)',
                            title_font=dict(color='white'),
                        ),
                        bgcolor='rgba(0,0,0,0)',
                    ),
                    margin=dict(l=0, r=0, t=50, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white'),
                )
                
                # Make the chart interactive
                fig.update_traces(
                    hovertemplate='<b>%{x}</b><br>Severity: %{y}<br>Count: %{z}'
                )
                
                st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': True})
            else:
                st.info("No anomalies detected in the current dataset.")
        
        # Bottom section - Anomaly cards with enhanced visualization
        st.markdown("""
        <h3 style="margin-top: 20px; margin-bottom: 10px; color: #4d31e0;">
            Highlighted Security Issues
        </h3>
        """, unsafe_allow_html=True)
        
        # Create enhanced anomaly cards for top categories
        if not log_data_anomalies.empty:
            # Get top categories
            top_categories = category_counts.sort_values('count', ascending=False).head(3)
            
            card_cols = st.columns(3)
            
            for i, (_, category_row) in enumerate(top_categories.iterrows()):
                category = category_row['category']
                count = category_row['count']
                
                # Get sample anomaly from this category
                sample_anomaly = log_data_anomalies[log_data_anomalies['category'] == category].iloc[0]
                severity = sample_anomaly['severity']
                
                # Create trend data for visualization
                category_trend = log_data_anomalies[log_data_anomalies['category'] == category].copy()
                category_trend['time'] = category_trend['timestamp']
                category_trend['value'] = 1  # Counting occurrences
                category_trend = category_trend.set_index('time').resample('h').count()['value'].reset_index()  # Using 'h' instead of 'H'
                
                # Description based on category
                descriptions = {
                    'Authentication': "Unusual login patterns or authentication failures detected.",
                    'Network': "Suspicious network traffic or connection attempts observed.",
                    'System': "System resource anomalies or unusual process behavior detected.",
                    'Database': "Database access patterns show potentially malicious activity.",
                    'Application': "Application errors or unusual behavior detected.",
                    'Access': "Unauthorized access attempts to restricted resources.",
                    'Configuration': "Critical configuration changes detected outside normal procedures.",
                    'Data': "Unusual data transfer patterns or potential data exfiltration attempts."
                }
                
                description = descriptions.get(category, f"Anomalies related to {category} systems detected.")
                
                with card_cols[i]:
                    anomaly_card(
                        title=f"{category} Anomalies",
                        count=count,
                        severity=severity,
                        description=description,
                        trend_data=category_trend
                    )
        else:
            st.info("No anomalies detected to analyze.")
    
    #####################
    # ALERTS TAB
    #####################
    with tab2:
        st.markdown("""
        <h3 style="margin-bottom: 15px;">Active Security Alerts</h3>
        """, unsafe_allow_html=True)
        
        # Alert filtering controls
        col1, col2, col3 = st.columns(3)
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["Critical", "High", "Medium", "Low"],
                default=["Critical", "High"]
            )
        with col2:
            source_filter = st.multiselect(
                "Filter by Source",
                options=list(set([alert['source'] for _, alert in alerts.iterrows()])),
                default=[]
            )
        with col3:
            sort_by = st.selectbox(
                "Sort by",
                options=["Time (newest first)", "Severity (highest first)", "Source"]
            )
        
        # Apply filters to alerts
        filtered_alerts = alerts.copy()
        if severity_filter:
            filtered_alerts = filtered_alerts[filtered_alerts['severity'].isin(severity_filter)]
        if source_filter:
            filtered_alerts = filtered_alerts[filtered_alerts['source'].isin(source_filter)]
            
        # Apply sorting
        if sort_by == "Time (newest first)":
            filtered_alerts = filtered_alerts.sort_values('timestamp', ascending=False)
        elif sort_by == "Severity (highest first)":
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            filtered_alerts['severity_order'] = filtered_alerts['severity'].map(severity_order)
            filtered_alerts = filtered_alerts.sort_values(['severity_order', 'timestamp'], ascending=[True, False])
        else:  # Sort by source
            filtered_alerts = filtered_alerts.sort_values(['source', 'timestamp'], ascending=[True, False])
        
        # Display alerts with enhanced UI
        display_alerts(filtered_alerts, max_alerts=10)
        
        # Add export functionality
        if st.button("Export Alerts", type="secondary"):
            st.info("In a real application, this would export the filtered alerts to CSV/PDF.")
    
    #####################
    # DETAILED ANALYSIS TAB
    #####################
    with tab3:
        st.markdown("""
        <h3 style="margin-bottom: 15px;">Security Analysis</h3>
        """, unsafe_allow_html=True)
        
        # Add geo map of anomalies
        st.markdown("#### Geographic Distribution of Anomalies")
        
        # Create sample geo data
        geo_data = pd.DataFrame({
            'lat': np.random.uniform(20, 60, size=30),
            'lon': np.random.uniform(-130, -60, size=30),
            'severity': np.random.choice(['Critical', 'High', 'Medium', 'Low'], size=30, 
                                         p=[0.1, 0.2, 0.3, 0.4]),
            'count': np.random.randint(1, 20, size=30)
        })
        
        # Map severity to colors
        geo_data['color'] = geo_data['severity'].map({
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745'
        })
        
        # Create geo map
        fig = px.scatter_mapbox(
            geo_data,
            lat='lat',
            lon='lon',
            color='severity',
            size='count',
            color_discrete_map={
                'Critical': '#dc3545',
                'High': '#fd7e14',
                'Medium': '#ffc107',
                'Low': '#28a745'
            },
            zoom=3,
            center={"lat": 40, "lon": -95},
            opacity=0.7,
            hover_name='severity',
            height=400
        )
        
        fig.update_layout(
            mapbox_style="carto-darkmatter",
            margin=dict(l=0, r=0, t=0, b=0),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Add advanced analysis sections
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Correlation Analysis")
            
            # Create a heatmap of correlated events
            correlation_matrix = pd.DataFrame(
                np.random.uniform(0, 1, size=(8, 8)),
                columns=['Auth', 'Network', 'Database', 'App', 'OS', 'Web', 'API', 'Config'],
                index=['Auth', 'Network', 'Database', 'App', 'OS', 'Web', 'API', 'Config']
            )
            
            # Create triangular correlation matrix
            mask = np.triu(np.ones_like(correlation_matrix, dtype=bool))
            for i in range(len(correlation_matrix)):
                correlation_matrix.iloc[i, i] = 1.0
            
            fig = px.imshow(
                correlation_matrix, 
                color_continuous_scale=[[0, '#0e1117'], [0.5, '#4d31e0'], [1, '#dc3545']],
                labels=dict(color="Correlation"),
                height=350
            )
            
            fig.update_layout(
                title="Anomaly Cross-Correlation Matrix",
                xaxis_title="Event Type",
                yaxis_title="Event Type",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=10, r=10, t=50, b=10),
                coloraxis_showscale=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### Time-of-Day Analysis")
            
            # Create hourly distribution data
            hours = list(range(24))
            normal_counts = [random.randint(20, 100) for _ in range(24)]
            anomaly_counts = [random.randint(0, int(normal_counts[i] * 0.3)) if i not in [2, 3, 4, 13, 14] 
                             else random.randint(int(normal_counts[i] * 0.3), int(normal_counts[i] * 0.5)) 
                             for i in range(24)]
            
            hour_data = pd.DataFrame({
                'hour': hours,
                'normal': normal_counts,
                'anomaly': anomaly_counts
            })
            
            fig = go.Figure()
            
            # Add normal activity bars
            fig.add_trace(go.Bar(
                x=hour_data['hour'],
                y=hour_data['normal'],
                name='Normal Activity',
                marker_color='rgba(53, 151, 255, 0.7)'
            ))
            
            # Add anomaly bars
            fig.add_trace(go.Bar(
                x=hour_data['hour'],
                y=hour_data['anomaly'],
                name='Anomalies',
                marker_color='rgba(220, 53, 69, 0.7)'
            ))
            
            fig.update_layout(
                title='Activity by Hour of Day',
                xaxis=dict(
                    title='Hour of Day',
                    tickmode='array',
                    tickvals=list(range(0, 24, 2)),
                    ticktext=[f"{h:02d}:00" for h in range(0, 24, 2)]
                ),
                yaxis=dict(title='Event Count'),
                barmode='overlay',
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                ),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=10, r=10, t=50, b=10),
                height=350
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Add user risk scoring table with interactive elements
        st.markdown("#### User Risk Assessment")
        
        # Create risk score data for users
        if 'user_risk_scores' not in st.session_state:
            user_ids = [f"user{i}" for i in range(1, 11)]
            risk_scores = np.random.uniform(10, 95, size=10)
            last_activity = [(datetime.now() - timedelta(hours=random.randint(0, 72))) for _ in range(10)]
            anomaly_count = np.random.randint(0, 15, size=10)
            risk_factors = [
                ", ".join(random.sample([
                    "Unusual login times", 
                    "Multiple IPs", 
                    "Sensitive resource access", 
                    "Failed logins", 
                    "Unusual file transfers",
                    "Configuration changes",
                    "Elevated privilege usage"
                ], random.randint(1, 3))) for _ in range(10)
            ]
            
            user_risk_df = pd.DataFrame({
                'user_id': user_ids,
                'risk_score': risk_scores,
                'last_activity': last_activity,
                'anomaly_count': anomaly_count,
                'risk_factors': risk_factors
            })
            
            # Sort by risk score (highest first)
            user_risk_df = user_risk_df.sort_values('risk_score', ascending=False)
            st.session_state['user_risk_scores'] = user_risk_df
        
        user_risk_df = st.session_state['user_risk_scores']
        
        # Create interactive HTML table with colored risk scores
        html_table = """
        <div style="overflow-x: auto; margin-top: 15px;">
            <table style="width: 100%; border-collapse: collapse; border-radius: 10px; overflow: hidden;">
                <thead>
                    <tr style="background-color: rgba(77, 49, 224, 0.8);">
                        <th style="padding: 12px 15px; text-align: left;">User</th>
                        <th style="padding: 12px 15px; text-align: center;">Risk Score</th>
                        <th style="padding: 12px 15px; text-align: center;">Last Activity</th>
                        <th style="padding: 12px 15px; text-align: center;">Anomalies</th>
                        <th style="padding: 12px 15px; text-align: left;">Risk Factors</th>
                        <th style="padding: 12px 15px; text-align: center;">Actions</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for _, user in user_risk_df.iterrows():
            risk_score = user['risk_score']
            
            # Determine color based on risk score
            if risk_score >= 75:
                score_color = "#dc3545"  # High risk - red
            elif risk_score >= 50:
                score_color = "#fd7e14"  # Medium risk - orange
            elif risk_score >= 25:
                score_color = "#ffc107"  # Low risk - yellow
            else:
                score_color = "#28a745"  # Very low risk - green
            
            # Format last activity
            last_activity = user['last_activity']
            if isinstance(last_activity, datetime):
                time_diff = datetime.now() - last_activity
                if time_diff.days > 0:
                    last_activity_str = f"{time_diff.days}d ago"
                elif time_diff.seconds // 3600 > 0:
                    last_activity_str = f"{time_diff.seconds // 3600}h ago"
                else:
                    last_activity_str = f"{time_diff.seconds // 60}m ago"
            else:
                last_activity_str = "Unknown"
            
            html_table += f"""
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); background-color: rgba(38, 39, 48, 0.6);">
                    <td style="padding: 12px 15px; font-weight: bold;">{user['user_id']}</td>
                    <td style="padding: 12px 15px; text-align: center;">
                        <div style="width: 45px; height: 45px; border-radius: 50%; background: {score_color}; 
                                   display: flex; align-items: center; justify-content: center; margin: 0 auto;
                                   font-weight: bold; box-shadow: 0 2px 5px rgba(0,0,0,0.2);">
                            {int(risk_score)}
                        </div>
                    </td>
                    <td style="padding: 12px 15px; text-align: center; opacity: 0.8;">{last_activity_str}</td>
                    <td style="padding: 12px 15px; text-align: center;">{user['anomaly_count']}</td>
                    <td style="padding: 12px 15px; opacity: 0.9;">{user['risk_factors']}</td>
                    <td style="padding: 12px 15px; text-align: center;">
                        <button onclick="alert('Investigating {user['user_id']}')" 
                                style="background: rgba(77, 49, 224, 0.7); border: none; color: white; 
                                       padding: 5px 10px; border-radius: 4px; cursor: pointer; margin-right: 5px;">
                            Investigate
                        </button>
                    </td>
                </tr>
            """
        
        html_table += """
                </tbody>
            </table>
        </div>
        """
        
        st.markdown(html_table, unsafe_allow_html=True)
        
        # Add export functionality for the table
        if st.button("Export Risk Assessment", type="secondary"):
            st.info("In a real application, this would export the risk assessment to CSV/PDF.")
            
    # Floating refresh button (positioned at bottom right, above chat)
    st.markdown("""
    <div style="position: fixed; bottom: 90px; right: 20px; z-index: 999;">
        <button onclick="location.reload()" style="width: 40px; height: 40px; border-radius: 50%; 
                background-color: rgba(77, 49, 224, 0.8); color: white; border: none;
                display: flex; align-items: center; justify-content: center; cursor: pointer;
                box-shadow: 0 2px 5px rgba(0,0,0,0.3);">
            🔄
        </button>
    </div>
    """, unsafe_allow_html=True)
