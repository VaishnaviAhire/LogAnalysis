import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from utils.data_processor import LogProcessor
from models.anomaly_detector import LogAnomalyDetector, AnomalyClassifier
import altair as alt

def show_logs_analysis():
    """
    Display the log anomaly analysis page
    """
    st.header("Log Anomaly Analysis")
    
    # Initialize data processors if not already in session state
    if 'log_processor' not in st.session_state:
        st.session_state['log_processor'] = LogProcessor()
    
    # For demonstration, generate sample data
    # In a real application, this would come from actual log sources
    with st.spinner("Processing log data..."):
        # Generate sample log data
        log_data = st.session_state['log_processor'].generate_sample_logs(
            num_logs=2000, 
            include_anomalies=True, 
            anomaly_percentage=0.05
        )
    
    # Initialize anomaly detector and classifier
    anomaly_detector = LogAnomalyDetector()
    anomaly_classifier = AnomalyClassifier()
    
    # Extract features from log data
    features_df = st.session_state['log_processor'].extract_features(log_data)
    
    # Train the model on the features
    with st.spinner("Training anomaly detection model..."):
        anomaly_detector.train(features_df)
    
    # Predict anomalies and get scores
    predictions = anomaly_detector.predict(features_df)
    scores = anomaly_detector.predict_anomaly_score(features_df)
    
    # Add predictions and scores to the log data
    log_data['predicted_anomaly'] = predictions == -1
    log_data['anomaly_score'] = scores
    
    # Classify anomalies
    anomalies = log_data[log_data['predicted_anomaly']]
    if not anomalies.empty:
        anomalies['category'] = anomaly_classifier.classify_batch(anomalies)
        anomalies['severity'] = anomaly_classifier.calculate_severity_batch(anomalies)
    
    # Top section - Filtering and controls
    st.subheader("Log Analysis Controls")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Filter by log source
        sources = ['All Sources'] + sorted(log_data['source'].unique().tolist())
        selected_source = st.selectbox("Filter by Source", sources)
    
    with col2:
        # Filter by log level
        levels = ['All Levels'] + sorted(log_data['level'].unique().tolist())
        selected_level = st.selectbox("Filter by Level", levels)
    
    with col3:
        # Filter by anomaly status
        anomaly_filter = st.selectbox("Show", ["All Logs", "Anomalies Only", "Normal Logs Only"])
    
    # Apply filters
    filtered_data = log_data.copy()
    
    if selected_source != 'All Sources':
        filtered_data = filtered_data[filtered_data['source'] == selected_source]
    
    if selected_level != 'All Levels':
        filtered_data = filtered_data[filtered_data['level'] == selected_level]
    
    if anomaly_filter == "Anomalies Only":
        filtered_data = filtered_data[filtered_data['predicted_anomaly']]
    elif anomaly_filter == "Normal Logs Only":
        filtered_data = filtered_data[~filtered_data['predicted_anomaly']]
    
    # Middle section - Visualizations
    st.subheader("Log Anomaly Visualizations")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Anomaly score distribution
        fig = px.histogram(
            filtered_data, 
            x='anomaly_score',
            color='predicted_anomaly',
            nbins=50,
            title='Distribution of Anomaly Scores',
            color_discrete_map={True: 'red', False: 'blue'},
            labels={'predicted_anomaly': 'Is Anomaly'}
        )
        
        # Add vertical line at threshold
        fig.add_vline(x=0, line_dash="dash", line_color="black")
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Anomalies by time and source
        if 'predicted_anomaly' in filtered_data.columns:
            # Resample by hour
            filtered_data['hour'] = filtered_data['timestamp'].dt.floor('H')
            anomaly_by_time = filtered_data.groupby(['hour', 'source', 'predicted_anomaly']).size().reset_index(name='count')
            anomaly_by_time = anomaly_by_time[anomaly_by_time['predicted_anomaly']]
            
            if not anomaly_by_time.empty:
                fig = px.line(
                    anomaly_by_time,
                    x='hour',
                    y='count',
                    color='source',
                    title='Anomalies by Time and Source',
                    labels={'hour': 'Time', 'count': 'Number of Anomalies'}
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No anomalies found with current filters.")
        else:
            st.info("No anomaly data available.")
    
    # Add anomaly category breakdown if anomalies exist
    if 'category' in anomalies.columns and not anomalies.empty:
        st.subheader("Anomaly Categories")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Category distribution
            category_counts = anomalies.groupby('category').size().reset_index(name='count')
            
            fig = px.pie(
                category_counts,
                values='count',
                names='category',
                title='Anomaly Categories'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Severity distribution
            severity_counts = anomalies.groupby('severity').size().reset_index(name='count')
            
            # Ensure correct order of severity levels
            severity_order = ["Critical", "High", "Medium", "Low"]
            severity_counts['severity'] = pd.Categorical(
                severity_counts['severity'], 
                categories=severity_order, 
                ordered=True
            )
            severity_counts = severity_counts.sort_values('severity')
            
            fig = px.bar(
                severity_counts,
                x='severity',
                y='count',
                title='Anomaly Severity Distribution',
                color='severity',
                color_discrete_map={
                    'Critical': '#dc3545',
                    'High': '#fd7e14',
                    'Medium': '#ffc107',
                    'Low': '#28a745'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Bottom section - Log table
    st.subheader("Log Entries")
    
    # Convert boolean to string for better display
    display_data = filtered_data.copy()
    display_data['anomaly'] = display_data['predicted_anomaly'].map({True: '⚠️ Yes', False: 'No'})
    
    # Format score for display
    display_data['score'] = display_data['anomaly_score'].round(3)
    
    # Select columns for display
    display_cols = ['timestamp', 'level', 'source', 'message', 'anomaly', 'score']
    
    # Add severity and category if available
    if 'severity' in anomalies.columns:
        # Join anomalies to display_data to get severity and category
        anomalies_data = anomalies[['timestamp', 'severity', 'category']].copy()
        display_data = display_data.merge(
            anomalies_data, 
            on='timestamp', 
            how='left'
        )
        display_cols = ['timestamp', 'level', 'source', 'message', 'anomaly', 'score', 'severity', 'category']
    
    # Sort by anomaly status and timestamp
    display_data = display_data.sort_values(['predicted_anomaly', 'timestamp'], ascending=[False, False])
    
    # Display the table
    st.dataframe(
        display_data[display_cols],
        use_container_width=True,
        height=400
    )
    
    # Load sample log entry for detailed analysis if clicked
    with st.expander("Log Entry Detail Analysis"):
        if not anomalies.empty:
            sample_anomaly = anomalies.iloc[0]
            
            st.markdown(f"### Selected Log Entry")
            st.markdown(f"**Timestamp:** {sample_anomaly['timestamp']}")
            st.markdown(f"**Level:** {sample_anomaly['level']}")
            st.markdown(f"**Source:** {sample_anomaly['source']}")
            st.markdown(f"**Message:** {sample_anomaly['message']}")
            st.markdown(f"**Anomaly Score:** {sample_anomaly['anomaly_score']:.4f}")
            st.markdown(f"**Category:** {sample_anomaly['category']}")
            st.markdown(f"**Severity:** {sample_anomaly['severity']}")
            
            st.markdown("### Analysis")
            st.markdown("""
            This log entry was flagged as anomalous due to unusual patterns detected by the machine learning model.
            The system has classified it as a potential security concern based on:
            
            - Unusual timing or frequency of the event
            - Deviation from normal log patterns for this source
            - Suspicious keywords or patterns in the message
            - Correlation with other anomalous events
            """)
            
            st.markdown("### Recommended Actions")
            st.markdown("""
            1. Investigate the source system for signs of compromise
            2. Check user activity around this timeframe
            3. Review related logs for context
            4. Verify if this is a legitimate activity or a security issue
            5. Document findings and update security policies if needed
            """)
        else:
            st.info("No anomalies detected to analyze in detail.")
