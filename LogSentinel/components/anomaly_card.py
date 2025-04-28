import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
import plotly.graph_objects as go
import random

def anomaly_card(title, count, severity, description, trend_data=None):
    """
    Creates a card displaying anomaly information
    
    Parameters:
    -----------
    title : str
        Title of the anomaly
    count : int
        Number of anomalies detected
    severity : str
        Severity level (Critical, High, Medium, Low)
    description : str
        Brief description of the anomaly
    trend_data : pd.DataFrame (optional)
        DataFrame with columns 'time' and 'value' for trend visualization
    """
    # Define severity colors
    severity_colors = {
        "Critical": "#dc3545",  # Red
        "High": "#fd7e14",      # Orange
        "Medium": "#ffc107",    # Yellow
        "Low": "#28a745"        # Green
    }
    
    # Get the color for this severity level
    color = severity_colors.get(severity, '#6c757d')
    
    # Create card with enhanced styling
    with st.container():
        st.markdown(f"""
        <div class="dashboard-card" style="border-left-color: {color};">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <h3 style="margin: 0; color: #ffffff;">{title}</h3>
                <span style="
                    background-color: {color}; 
                    color: white; 
                    padding: 4px 10px; 
                    border-radius: 15px; 
                    font-size: 0.8em;
                    font-weight: bold;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                ">{severity}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Create two columns for count and description
        col1, col2 = st.columns([1, 3])
        
        with col1:
            # Add some animation/interactivity through CSS
            st.markdown(f"""
            <div class="metric-card" style="text-align: center;">
                <h1 style="color: {color}; font-size: 2.5rem; margin: 0; font-weight: bold;">{count}</h1>
                <p style="margin: 0; opacity: 0.7;">anomalies</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div style="padding: 10px; background: rgba(255,255,255,0.05); border-radius: 5px;">
                <p style="margin: 0;">{description}</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Trend visualization if provided with improved styling
        if trend_data is not None and isinstance(trend_data, pd.DataFrame):
            if 'time' in trend_data.columns and 'value' in trend_data.columns:
                # If trend data is empty or has invalid values, generate sample data for demo
                if trend_data.empty or trend_data['time'].isnull().all() or trend_data['value'].isnull().all():
                    # Create sample trend data
                    now = pd.Timestamp.now()
                    hours = 24
                    times = [now - pd.Timedelta(hours=h) for h in range(hours, 0, -1)]
                    if severity == "Critical":
                        values = [random.randint(0, 2) for _ in range(hours-4)] + [random.randint(3, 8) for _ in range(4)]
                    else:
                        values = [random.randint(0, 5) for _ in range(hours)]
                    trend_data = pd.DataFrame({'time': times, 'value': values})
                
                # Use Plotly for more interactive charts
                fig = px.line(trend_data, x='time', y='value',
                             title="Trend Over Last 24 Hours",
                             labels={"time": "Time", "value": "Count"},
                             color_discrete_sequence=[color])
                
                # Add area fill under the line
                fig.add_trace(
                    go.Scatter(
                        x=trend_data['time'],
                        y=trend_data['value'],
                        fill='tozeroy',
                        fillcolor=f"rgba{tuple(int(color.lstrip('#')[i:i+2], 16) for i in (0, 2, 4)) + (0.2,)}",
                        line=dict(width=0),
                        showlegend=False
                    )
                )
                
                # Style the chart
                fig.update_layout(
                    height=180,
                    margin=dict(l=0, r=0, t=40, b=0),
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    xaxis=dict(
                        showgrid=False,
                        zeroline=False
                    ),
                    yaxis=dict(
                        showgrid=True,
                        gridcolor='rgba(255,255,255,0.1)',
                        zeroline=False
                    ),
                    hovermode='x unified',
                    hoverlabel=dict(
                        bgcolor='#1e1e2d',
                        font_size=12,
                        font_color='white'
                    ),
                    font=dict(
                        color='white'
                    )
                )
                
                # Add trend indicator
                if len(trend_data) > 1:
                    first_half = trend_data['value'].iloc[:len(trend_data)//2].mean()
                    second_half = trend_data['value'].iloc[len(trend_data)//2:].mean()
                    delta = second_half - first_half
                    
                    if delta > 0:
                        trend = f"↗ +{delta:.1f}"
                        delta_color = "#dc3545" if severity == "Critical" or severity == "High" else "#28a745"
                    elif delta < 0:
                        trend = f"↘ {delta:.1f}"
                        delta_color = "#28a745" if severity == "Critical" or severity == "High" else "#dc3545"
                    else:
                        trend = "→ 0.0"
                        delta_color = "#ffc107"
                    
                    fig.add_annotation(
                        x=1, y=1,
                        xref="paper", yref="paper",
                        text=trend,
                        showarrow=False,
                        font=dict(
                            size=16,
                            color=delta_color
                        ),
                        align="right",
                        bgcolor="rgba(0,0,0,0.5)",
                        bordercolor="rgba(0,0,0,0)",
                        borderwidth=0,
                        borderpad=4
                    )
                
                st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
            
        # Add interactive buttons for taking action
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f"Investigate {title}", key=f"investigate_{title.replace(' ', '_')}"):
                st.session_state['current_page'] = 'logs_analysis'
                st.rerun()
        with col2:
            if st.button(f"Set Alert Rules", key=f"alert_{title.replace(' ', '_')}"):
                st.info(f"Would configure alert rules for {title} anomalies")
                
        # Visual separator
        st.markdown("<hr style='margin: 5px 0; opacity: 0.2;'>", unsafe_allow_html=True)
