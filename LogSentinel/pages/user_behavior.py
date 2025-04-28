import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from utils.data_processor import UserActivityProcessor
from models.user_behavior import UserBehaviorAnalyzer, UserActivityProfiler
import altair as alt

def show_user_behavior():
    """
    Display the user behavior analytics page
    """
    st.header("User Behavior Analytics")
    
    # Initialize data processors if not already in session state
    if 'user_activity_processor' not in st.session_state:
        st.session_state['user_activity_processor'] = UserActivityProcessor()
    
    # For demonstration, generate sample data
    # In a real application, this would come from actual user activity logs
    with st.spinner("Processing user activity data..."):
        # Generate sample user activity data
        user_activity = st.session_state['user_activity_processor'].generate_sample_user_activity(
            num_users=50,
            num_activities=2000,
            include_anomalies=True
        )
    
    # Top section - user filtering and time range controls
    st.subheader("User Activity Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # User selection
        users = sorted(user_activity['user_id'].unique().tolist())
        selected_user = st.selectbox("Select User", ['All Users'] + users)
    
    with col2:
        # Activity type filter
        actions = ['All Actions'] + sorted(user_activity['action'].unique().tolist())
        selected_action = st.selectbox("Filter by Activity Type", actions)
    
    # Apply filters
    filtered_activity = user_activity.copy()
    
    if selected_user != 'All Users':
        filtered_activity = filtered_activity[filtered_activity['user_id'] == selected_user]
    
    if selected_action != 'All Actions':
        filtered_activity = filtered_activity[filtered_activity['action'] == selected_action]
    
    # Middle section - Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        # User activity over time
        st.subheader("Activity Timeline")
        
        # Resample by hour
        filtered_activity['hour'] = filtered_activity['timestamp'].dt.floor('H')
        activity_by_time = filtered_activity.groupby(['hour', 'user_id']).size().reset_index(name='count')
        
        if selected_user == 'All Users':
            # For all users, show top 10 most active
            top_users = filtered_activity.groupby('user_id').size().nlargest(10).index.tolist()
            activity_by_time = activity_by_time[activity_by_time['user_id'].isin(top_users)]
        
        fig = px.line(
            activity_by_time,
            x='hour',
            y='count',
            color='user_id',
            title='User Activity Over Time',
            labels={'hour': 'Time', 'count': 'Number of Activities'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Activity distribution by action type
        st.subheader("Activity Distribution")
        
        action_counts = filtered_activity.groupby('action').size().reset_index(name='count')
        action_counts = action_counts.sort_values('count', ascending=False)
        
        fig = px.bar(
            action_counts,
            x='action',
            y='count',
            title='Activities by Type',
            color='action'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # User behavior analysis
    st.subheader("User Behavior Analysis")
    
    # Extract features for user behavior analysis
    user_features = st.session_state['user_activity_processor'].extract_user_features(filtered_activity)
    
    # Create and train user behavior analyzer
    behavior_analyzer = UserBehaviorAnalyzer()
    
    with st.spinner("Analyzing user behavior patterns..."):
        behavior_analyzer.train(user_features)
        
        # Get anomaly scores for users
        user_scores = behavior_analyzer.predict_anomaly_score(user_features)
    
    # Join user scores with features
    user_analysis = user_features.merge(user_scores, on='user_id')
    
    # Mark anomalous users
    user_analysis['is_anomalous'] = user_analysis['anomaly_score'] < 0
    
    # Display anomalous users
    if user_analysis['is_anomalous'].any():
        st.subheader("Detected Unusual User Behavior")
        
        # Filter to anomalous users
        anomalous_users = user_analysis[user_analysis['is_anomalous']].sort_values('anomaly_score')
        
        # Display in expanders
        for _, user_row in anomalous_users.iterrows():
            user_id = user_row['user_id']
            
            with st.expander(f"Unusual behavior: {user_id} (Score: {user_row['anomaly_score']:.3f})"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown("#### Activity Metrics")
                    st.markdown(f"**Activity Count:** {user_row['timestamp_count']}")
                    st.markdown(f"**Session Duration:** {user_row['session_duration']:.2f} hours")
                    st.markdown(f"**Actions per Hour:** {user_row['actions_per_hour']:.2f}")
                    st.markdown(f"**Unique Resources Accessed:** {user_row['resource_nunique']}")
                    st.markdown(f"**Unique IP Addresses:** {user_row['ip_address_nunique']}")
                
                with col2:
                    # Get user details
                    user_data = filtered_activity[filtered_activity['user_id'] == user_id]
                    
                    # Get anomalous activities for this user
                    anomalous_activities = user_data[user_data['is_anomaly']]
                    
                    st.markdown("#### Anomalous Activities")
                    if not anomalous_activities.empty:
                        for _, activity in anomalous_activities.head(5).iterrows():
                            st.markdown(f"""
                            - {activity['timestamp']}: {activity['action']} on {activity['resource']} from {activity['ip_address']}
                            """)
                    else:
                        st.markdown("No specific anomalous activities detected.")
                
                # Show activity pattern
                st.markdown("#### Activity Pattern")
                
                # Hour distribution chart
                user_data['hour'] = user_data['timestamp'].dt.hour
                hour_counts = user_data.groupby('hour').size().reset_index(name='count')
                
                hour_chart = alt.Chart(hour_counts).mark_bar().encode(
                    x=alt.X('hour:O', title='Hour of Day'),
                    y=alt.Y('count:Q', title='Activity Count')
                ).properties(
                    title='Activity by Hour of Day'
                )
                
                st.altair_chart(hour_chart, use_container_width=True)
                
                # Show potential risk factors
                st.markdown("#### Potential Risk Indicators")
                
                risk_factors = []
                
                # Unusual hours
                night_activity = user_data[(user_data['hour'] < 6) | (user_data['hour'] > 22)]
                if len(night_activity) > 0:
                    risk_factors.append(f"⚠️ {len(night_activity)} activities during unusual hours (10PM-6AM)")
                
                # Multiple IPs
                ip_count = user_data['ip_address'].nunique()
                if ip_count > 2:
                    risk_factors.append(f"⚠️ Activities from {ip_count} different IP addresses")
                
                # Sensitive resources
                sensitive_resources = ['system settings', 'admin console', 'security settings', 'audit logs', 'confidential data']
                sensitive_access = user_data[user_data['resource'].isin(sensitive_resources)]
                if len(sensitive_access) > 0:
                    risk_factors.append(f"⚠️ {len(sensitive_access)} accesses to sensitive resources")
                
                # Unusual action frequency
                if user_row['actions_per_hour'] > 20:
                    risk_factors.append(f"⚠️ High activity rate: {user_row['actions_per_hour']:.2f} actions per hour")
                
                if risk_factors:
                    for factor in risk_factors:
                        st.markdown(factor)
                else:
                    st.markdown("No significant risk indicators detected.")
                
                # Add action buttons
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.button("Investigate User", key=f"investigate_{user_id}")
                with col2:
                    st.button("Mark as False Positive", key=f"false_positive_{user_id}")
                with col3:
                    st.button("Alert Security Team", key=f"alert_{user_id}")
    else:
        st.info("No unusual user behavior detected with current filtering.")
    
    # User profiling section
    if selected_user != 'All Users':
        st.subheader(f"User Profile: {selected_user}")
        
        # Create user activity profiler
        profiler = UserActivityProfiler()
        profiler.build_profiles(user_activity)
        
        # Get user-specific data
        user_data = user_activity[user_activity['user_id'] == selected_user]
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Activity by hour of day
            user_data['hour'] = user_data['timestamp'].dt.hour
            hour_counts = user_data.groupby('hour').size().reset_index(name='count')
            
            fig = px.bar(
                hour_counts,
                x='hour',
                y='count',
                title='Activity by Hour of Day',
                labels={'hour': 'Hour', 'count': 'Activity Count'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Activity by day of week
            user_data['day'] = user_data['timestamp'].dt.day_name()
            day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            day_counts = user_data.groupby('day').size().reset_index(name='count')
            day_counts['day'] = pd.Categorical(day_counts['day'], categories=day_order, ordered=True)
            day_counts = day_counts.sort_values('day')
            
            fig = px.bar(
                day_counts,
                x='day',
                y='count',
                title='Activity by Day of Week',
                labels={'day': 'Day', 'count': 'Activity Count'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Resources accessed
        st.subheader("Resources Accessed")
        
        resource_counts = user_data.groupby('resource').size().reset_index(name='count')
        resource_counts = resource_counts.sort_values('count', ascending=False)
        
        fig = px.bar(
            resource_counts.head(10),
            x='resource',
            y='count',
            title='Top 10 Resources Accessed',
            color='resource'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Recent activity table
        st.subheader("Recent Activity")
        
        # Sort by timestamp (newest first)
        recent_activity = user_data.sort_values('timestamp', ascending=False)
        
        # Show last 10 activities
        st.dataframe(
            recent_activity[['timestamp', 'action', 'resource', 'ip_address']].head(10),
            use_container_width=True
        )
