import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime, timedelta

class LogAnomalyDetector:
    """
    Class for detecting anomalies in log data using ML techniques
    """
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def train(self, features_df, contamination=0.05):
        """
        Train the anomaly detection model
        
        Parameters:
        -----------
        features_df : pd.DataFrame
            DataFrame containing extracted features
        contamination : float
            Expected proportion of anomalies in the dataset
        
        Returns:
        --------
        self
            Trained model instance
        """
        if features_df.empty:
            raise ValueError("Empty features dataframe provided for training")
        
        # Save feature column names
        self.feature_columns = features_df.columns.tolist()
        
        # Scale features
        X = self.scaler.fit_transform(features_df)
        
        # Train Isolation Forest model
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=contamination,
            random_state=42
        )
        
        self.model.fit(X)
        
        return self
    
    def predict(self, features_df):
        """
        Predict anomalies in log data
        
        Parameters:
        -----------
        features_df : pd.DataFrame
            DataFrame containing extracted features
        
        Returns:
        --------
        np.ndarray
            Array with 1 for normal points and -1 for anomalies
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")
        
        if features_df.empty:
            return np.array([])
        
        # Ensure features match what the model was trained on
        missing_cols = set(self.feature_columns) - set(features_df.columns)
        if missing_cols:
            # Add missing columns with zeros
            for col in missing_cols:
                features_df[col] = 0
        
        # Ensure columns are in the same order
        features_df = features_df[self.feature_columns]
        
        # Scale features
        X = self.scaler.transform(features_df)
        
        # Predict
        return self.model.predict(X)
    
    def predict_anomaly_score(self, features_df):
        """
        Calculate anomaly scores for log data
        
        Parameters:
        -----------
        features_df : pd.DataFrame
            DataFrame containing extracted features
        
        Returns:
        --------
        np.ndarray
            Array with anomaly scores (negative values are more anomalous)
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")
        
        if features_df.empty:
            return np.array([])
        
        # Ensure features match what the model was trained on
        missing_cols = set(self.feature_columns) - set(features_df.columns)
        if missing_cols:
            # Add missing columns with zeros
            for col in missing_cols:
                features_df[col] = 0
        
        # Ensure columns are in the same order
        features_df = features_df[self.feature_columns]
        
        # Scale features
        X = self.scaler.transform(features_df)
        
        # Calculate anomaly scores
        return self.model.decision_function(X)
    
    def save_model(self, filepath):
        """
        Save the trained model to a file
        
        Parameters:
        -----------
        filepath : str
            Path to save the model
        """
        if self.model is None:
            raise ValueError("Model not trained yet. Call train() first.")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns
        }
        
        joblib.dump(model_data, filepath)
    
    def load_model(self, filepath):
        """
        Load a trained model from a file
        
        Parameters:
        -----------
        filepath : str
            Path to the saved model
        
        Returns:
        --------
        self
            Model instance with loaded model
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_columns = model_data['feature_columns']
        
        return self

class AnomalyClassifier:
    """
    Class for classifying detected anomalies into different categories
    """
    def __init__(self):
        # Categories of anomalies with their keywords and patterns
        self.anomaly_categories = {
            'Authentication': [
                'login', 'password', 'authentication', 'credentials', 'failed', 'user', 'account'
            ],
            'Network': [
                'connection', 'network', 'packet', 'traffic', 'ip', 'port', 'firewall', 'dns'
            ],
            'System': [
                'cpu', 'memory', 'disk', 'load', 'process', 'service', 'crash', 'reboot', 'startup'
            ],
            'Database': [
                'sql', 'query', 'database', 'table', 'record', 'transaction', 'timeout'
            ],
            'Application': [
                'exception', 'error', 'warning', 'api', 'request', 'response', 'timeout', 'function'
            ],
            'Access': [
                'permission', 'access', 'denied', 'unauthorized', 'restricted', 'file', 'resource'
            ],
            'Configuration': [
                'config', 'setting', 'parameter', 'change', 'modified', 'update', 'property'
            ],
            'Data': [
                'data', 'file', 'transfer', 'upload', 'download', 'sync', 'backup', 'corrupt'
            ]
        }
        
    def classify(self, log_entry):
        """
        Classify a log entry into an anomaly category
        
        Parameters:
        -----------
        log_entry : dict or pd.Series
            Log entry containing message and other fields
        
        Returns:
        --------
        str
            Anomaly category
        """
        if isinstance(log_entry, pd.Series):
            log_entry = log_entry.to_dict()
        
        # Get the log message to classify
        message = log_entry.get('message', '').lower()
        
        # Check each category for keyword matches
        category_scores = {}
        
        for category, keywords in self.anomaly_categories.items():
            score = sum(1 for keyword in keywords if keyword.lower() in message)
            category_scores[category] = score
        
        # Find the category with the highest score
        if max(category_scores.values()) > 0:
            return max(category_scores.items(), key=lambda x: x[1])[0]
        else:
            # Default category if no keywords match
            return 'Unknown'
    
    def classify_batch(self, log_df):
        """
        Classify multiple log entries
        
        Parameters:
        -----------
        log_df : pd.DataFrame
            DataFrame containing log entries
        
        Returns:
        --------
        pd.Series
            Series with anomaly categories
        """
        if log_df.empty:
            return pd.Series()
        
        return log_df.apply(self.classify, axis=1)
    
    def calculate_severity(self, log_entry):
        """
        Calculate severity score for an anomaly
        
        Parameters:
        -----------
        log_entry : dict or pd.Series
            Log entry
        
        Returns:
        --------
        str
            Severity level (Critical, High, Medium, Low)
        """
        if isinstance(log_entry, pd.Series):
            log_entry = log_entry.to_dict()
        
        message = log_entry.get('message', '').lower()
        level = log_entry.get('level', '').upper()
        
        # Severity indicators in the message
        critical_indicators = ['critical', 'emergency', 'fatal', 'breach', 'attack', 'compromise']
        high_indicators = ['error', 'failure', 'failed', 'denied', 'unauthorized', 'invalid']
        medium_indicators = ['warning', 'denied', 'timeout', 'exceeded', 'unusual']
        
        # Check log level first
        if level in ['CRITICAL', 'EMERGENCY', 'FATAL']:
            base_severity = 'Critical'
        elif level == 'ERROR':
            base_severity = 'High'
        elif level == 'WARNING':
            base_severity = 'Medium'
        else:
            base_severity = 'Low'
        
        # Check for indicators in the message to potentially escalate severity
        if any(indicator in message for indicator in critical_indicators):
            return 'Critical'
        elif base_severity != 'Critical' and any(indicator in message for indicator in high_indicators):
            return 'High' if base_severity == 'Low' else base_severity
        elif base_severity == 'Low' and any(indicator in message for indicator in medium_indicators):
            return 'Medium'
        
        return base_severity
    
    def calculate_severity_batch(self, log_df):
        """
        Calculate severity for multiple log entries
        
        Parameters:
        -----------
        log_df : pd.DataFrame
            DataFrame containing log entries
        
        Returns:
        --------
        pd.Series
            Series with severity levels
        """
        if log_df.empty:
            return pd.Series()
        
        return log_df.apply(self.calculate_severity, axis=1)
