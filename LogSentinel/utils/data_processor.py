import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import re

class LogProcessor:
    """
    Class for processing log data for anomaly detection and analysis
    """
    def __init__(self):
        pass
    
    def parse_log_line(self, log_line):
        """
        Parse a single log line into structured data
        
        Parameters:
        -----------
        log_line : str
            Raw log line to parse
        
        Returns:
        --------
        dict
            Structured log entry
        """
        # This is a simplified example of log parsing
        # In a real system, this would be more sophisticated and handle various log formats
        
        # Common log format pattern (example)
        timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
        level_pattern = r'(INFO|WARNING|ERROR|CRITICAL|DEBUG)'
        source_pattern = r'\[(.*?)\]'
        message_pattern = r': (.*)'
        
        try:
            timestamp = re.search(timestamp_pattern, log_line)
            level = re.search(level_pattern, log_line)
            source = re.search(source_pattern, log_line)
            message = re.search(message_pattern, log_line)
            
            result = {
                'timestamp': timestamp.group(1) if timestamp else '',
                'level': level.group(1) if level else '',
                'source': source.group(1) if source else '',
                'message': message.group(1) if message else log_line
            }
            
            return result
        except Exception as e:
            # Fall back to a simple structure if parsing fails
            return {
                'timestamp': '',
                'level': '',
                'source': '',
                'message': log_line
            }
    
    def extract_features(self, log_df):
        """
        Extract features from structured log data for machine learning
        
        Parameters:
        -----------
        log_df : pd.DataFrame
            DataFrame containing structured log data
        
        Returns:
        --------
        pd.DataFrame
            DataFrame with extracted features
        """
        if log_df.empty:
            return pd.DataFrame()
            
        features_df = pd.DataFrame()
        
        # Convert timestamp to datetime if it's not already
        if 'timestamp' in log_df.columns:
            log_df['timestamp'] = pd.to_datetime(log_df['timestamp'], errors='coerce')
        
        # Extract time-based features
        features_df['hour_of_day'] = log_df['timestamp'].dt.hour
        features_df['day_of_week'] = log_df['timestamp'].dt.dayofweek
        features_df['is_weekend'] = (log_df['timestamp'].dt.dayofweek >= 5).astype(int)
        
        # Message length as a feature
        if 'message' in log_df.columns:
            features_df['message_length'] = log_df['message'].str.len()
        
        # Level encoding
        if 'level' in log_df.columns:
            level_mapping = {
                'DEBUG': 0,
                'INFO': 1,
                'WARNING': 2,
                'ERROR': 3,
                'CRITICAL': 4
            }
            features_df['level_code'] = log_df['level'].map(level_mapping).fillna(0)
        
        # Extract potential IP addresses from message
        if 'message' in log_df.columns:
            features_df['has_ip'] = log_df['message'].str.contains(
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}').astype(int)
        
        # Fill NaN values
        features_df = features_df.fillna(0)
        
        return features_df

    def preprocess_logs(self, log_data):
        """
        Preprocess raw log data into structured format for analysis
        
        Parameters:
        -----------
        log_data : list or str
            Raw log data, either as a list of log lines or a single string
        
        Returns:
        --------
        pd.DataFrame
            Preprocessed log data in structured format
        """
        if isinstance(log_data, str):
            log_lines = log_data.strip().split('\n')
        elif isinstance(log_data, list):
            log_lines = log_data
        else:
            return pd.DataFrame()
        
        # Parse each log line
        parsed_logs = [self.parse_log_line(line) for line in log_lines]
        
        # Convert to DataFrame
        log_df = pd.DataFrame(parsed_logs)
        
        # Convert timestamp to datetime
        if 'timestamp' in log_df.columns:
            log_df['timestamp'] = pd.to_datetime(log_df['timestamp'], errors='coerce')
            
        return log_df
    
    def generate_sample_logs(self, num_logs=1000, include_anomalies=True, anomaly_percentage=0.05):
        """
        Generate sample log data for demonstration purposes
        
        Parameters:
        -----------
        num_logs : int
            Number of log entries to generate
        include_anomalies : bool
            Whether to include anomalous log entries
        anomaly_percentage : float
            Percentage of logs that should be anomalous
        
        Returns:
        --------
        pd.DataFrame
            Generated log data
        """
        # Define log sources
        sources = ['WebServer', 'Database', 'AuthService', 'Firewall', 'ApplicationServer', 'LoadBalancer']
        
        # Define log levels with weighted distribution
        levels = ['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'DEBUG']
        level_weights = [0.7, 0.15, 0.1, 0.03, 0.02]
        
        # Define normal log message templates
        normal_templates = [
            "User {user_id} logged in successfully",
            "Request processed in {time}ms",
            "Database query completed successfully",
            "File {filename} accessed by user {user_id}",
            "Service {service} started successfully",
            "Connection established from {ip_address}",
            "Cache refreshed for {service}",
            "Scheduled task {task_id} completed"
        ]
        
        # Define anomalous log message templates
        anomaly_templates = [
            "Failed login attempt for user {user_id} from {ip_address}",
            "Unusual file access pattern detected for user {user_id}",
            "Excessive resource usage detected on {service}",
            "Multiple authentication failures from {ip_address}",
            "Unexpected service termination: {service}",
            "Configuration file modified outside maintenance window",
            "Unusual network traffic pattern detected from {ip_address}",
            "Potential data exfiltration detected: {details}"
        ]
        
        # Generate timestamps spanning the last 7 days
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        timestamps = [start_time + (end_time - start_time) * i / num_logs for i in range(num_logs)]
        
        # Generate log data
        logs = []
        
        for i in range(num_logs):
            # Determine if this log should be anomalous
            is_anomaly = include_anomalies and np.random.random() < anomaly_percentage
            
            # Select source and level
            source = np.random.choice(sources)
            level = np.random.choice(levels, p=level_weights if not is_anomaly else [0.1, 0.2, 0.4, 0.3, 0])
            
            # Generate user ID, IP, etc.
            user_id = f"user{np.random.randint(1, 1000)}"
            ip_octet = np.random.randint(1, 256, size=4)
            ip_address = f"{ip_octet[0]}.{ip_octet[1]}.{ip_octet[2]}.{ip_octet[3]}"
            
            # Select message template
            if is_anomaly:
                template = np.random.choice(anomaly_templates)
            else:
                template = np.random.choice(normal_templates)
            
            # Fill in template
            message = template.format(
                user_id=user_id,
                ip_address=ip_address,
                service=np.random.choice(sources),
                time=np.random.randint(10, 5000),
                filename=f"file{np.random.randint(1, 100)}.txt",
                task_id=f"task{np.random.randint(1, 50)}",
                details=f"Transfer of {np.random.randint(50, 500)}MB data to external server"
            )
            
            # Create log entry
            log_entry = {
                'timestamp': timestamps[i],
                'level': level,
                'source': source,
                'message': message,
                'is_anomaly': is_anomaly  # This field is for training/evaluation only
            }
            
            logs.append(log_entry)
        
        # Convert to DataFrame and sort by timestamp
        log_df = pd.DataFrame(logs)
        log_df = log_df.sort_values('timestamp')
        
        return log_df

class UserActivityProcessor:
    """
    Class for processing user activity data for behavior analytics
    """
    def __init__(self):
        pass
    
    def extract_user_features(self, activity_df):
        """
        Extract features from user activity data for behavior analysis
        
        Parameters:
        -----------
        activity_df : pd.DataFrame
            DataFrame containing user activity data
        
        Returns:
        --------
        pd.DataFrame
            DataFrame with extracted user behavior features
        """
        if activity_df.empty:
            return pd.DataFrame()
        
        # Convert timestamp to datetime if needed
        if 'timestamp' in activity_df.columns:
            activity_df['timestamp'] = pd.to_datetime(activity_df['timestamp'], errors='coerce')
        
        # Group by user_id
        user_features = activity_df.groupby('user_id').agg({
            'timestamp': ['min', 'max', 'count'],
            'action': 'nunique',
            'resource': 'nunique',
            'ip_address': 'nunique'
        })
        
        # Flatten column names
        user_features.columns = ['_'.join(col).strip() for col in user_features.columns.values]
        
        # Calculate session duration
        user_features['session_duration'] = (
            user_features['timestamp_max'] - user_features['timestamp_min']
        ).dt.total_seconds() / 3600  # in hours
        
        # Calculate actions per hour
        user_features['actions_per_hour'] = user_features['timestamp_count'] / user_features['session_duration'].clip(lower=1/60)
        
        # Reset index to make user_id a column
        user_features = user_features.reset_index()
        
        return user_features
    
    def generate_sample_user_activity(self, num_users=50, num_activities=1000, include_anomalies=True):
        """
        Generate sample user activity data for demonstration purposes
        
        Parameters:
        -----------
        num_users : int
            Number of users to simulate
        num_activities : int
            Total number of activities to generate
        include_anomalies : bool
            Whether to include anomalous user behavior
        
        Returns:
        --------
        pd.DataFrame
            Generated user activity data
        """
        # Define common actions and resources
        actions = ['login', 'logout', 'view', 'edit', 'download', 'upload', 'delete', 'create', 'search']
        resources = ['file', 'dashboard', 'report', 'user settings', 'system settings', 
                    'database', 'customer data', 'financial data', 'employee data', 'logs']
        
        # Generate user IDs
        user_ids = [f"user{i}" for i in range(1, num_users + 1)]
        
        # Generate timestamps spanning the last 7 days
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        
        # Define normal working hours (9 AM to 5 PM)
        work_start_hour = 9
        work_end_hour = 17
        
        activities = []
        
        for _ in range(num_activities):
            # Select a random user
            user_id = np.random.choice(user_ids)
            
            # Generate random timestamp
            random_timestamp = start_time + (end_time - start_time) * np.random.random()
            
            # Determine if this activity should be anomalous (outside working hours)
            is_anomaly = False
            if include_anomalies and np.random.random() < 0.05:  # 5% chance for anomaly
                # Anomalous activities can be:
                # 1. Outside working hours
                # 2. Unusual resource access
                # 3. Rapid succession of actions
                anomaly_type = np.random.choice([1, 2, 3])
                
                if anomaly_type == 1:
                    # Outside working hours
                    hour_shift = np.random.choice([-5, -4, -3, 6, 7, 8])  # Early morning or late night
                    random_timestamp = random_timestamp.replace(
                        hour=(random_timestamp.hour + hour_shift) % 24
                    )
                    is_anomaly = True
                elif anomaly_type == 2:
                    # Unusual resource access
                    resources += ['confidential data', 'admin console', 'security settings', 'audit logs']
                    is_anomaly = True
                # Type 3 is handled by generating clustered timestamps for a user
            
            # For normal activities, adjust to working hours
            if not is_anomaly:
                # Adjust to a weekday
                if random_timestamp.weekday() >= 5:  # Saturday or Sunday
                    days_to_subtract = random_timestamp.weekday() - 4  # Move to Friday
                    random_timestamp = random_timestamp - timedelta(days=days_to_subtract)
                
                # Adjust to working hours
                if random_timestamp.hour < work_start_hour or random_timestamp.hour >= work_end_hour:
                    random_timestamp = random_timestamp.replace(
                        hour=np.random.randint(work_start_hour, work_end_hour)
                    )
            
            # Generate IP address
            # Normal users have consistent IPs, anomalous might have different ones
            user_index = int(user_id.replace('user', ''))
            ip_base = f"192.168.{user_index // 256}.{user_index % 256}"
            
            if is_anomaly and np.random.random() < 0.7:  # 70% chance for anomalous IP
                ip_octet = np.random.randint(1, 256, size=4)
                ip_address = f"{ip_octet[0]}.{ip_octet[1]}.{ip_octet[2]}.{ip_octet[3]}"
            else:
                ip_address = ip_base
            
            # Create activity entry
            activity = {
                'user_id': user_id,
                'timestamp': random_timestamp,
                'action': np.random.choice(actions),
                'resource': np.random.choice(resources),
                'ip_address': ip_address,
                'is_anomaly': is_anomaly  # This field is for training/evaluation only
            }
            
            activities.append(activity)
        
        # Convert to DataFrame and sort by timestamp
        activity_df = pd.DataFrame(activities)
        activity_df = activity_df.sort_values(['user_id', 'timestamp'])
        
        # Generate type 3 anomalies (rapid succession)
        if include_anomalies:
            # Select a few random users for rapid activity
            rapid_users = np.random.choice(user_ids, size=int(num_users * 0.1), replace=False)
            
            for user_id in rapid_users:
                # Create a burst of activities within a short timeframe
                burst_time = start_time + (end_time - start_time) * np.random.random()
                burst_count = np.random.randint(10, 30)
                
                for i in range(burst_count):
                    # Activities separated by just seconds
                    timestamp = burst_time + timedelta(seconds=i * np.random.randint(1, 10))
                    
                    activity = {
                        'user_id': user_id,
                        'timestamp': timestamp,
                        'action': np.random.choice(actions),
                        'resource': np.random.choice(resources),
                        'ip_address': f"192.168.{int(user_id.replace('user', '')) // 256}.{int(user_id.replace('user', '')) % 256}",
                        'is_anomaly': True  # Marked as anomaly for evaluation
                    }
                    
                    activities.append(activity)
        
        # Convert to DataFrame and sort by timestamp
        activity_df = pd.DataFrame(activities)
        activity_df = activity_df.sort_values(['timestamp'])
        
        return activity_df
