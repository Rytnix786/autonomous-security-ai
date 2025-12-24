from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from ..core.schemas import Event, FeatureWindow
from ..core.logger import logger


class FeatureExtractor:
    """Extract features from security events for anomaly detection"""
    
    def __init__(self, config):
        self.config = config
        self.feature_names = self._get_feature_names()
    
    def _get_feature_names(self) -> List[str]:
        """Get the names of all features in order"""
        features = []
        
        # Event count features
        features.extend([
            'events_per_min',
            'failures_per_min', 
            'success_rate',
            'login_count',
            'api_call_count',
            'file_read_count',
            'file_write_count',
            'admin_action_count',
            'privilege_change_count'
        ])
        
        # Resource access features
        features.extend([
            'unique_resources',
            'sensitive_access_count',
            'sensitive_ratio',
            'high_sensitivity_access'
        ])
        
        # Data volume features
        features.extend([
            'bytes_in_total',
            'bytes_out_total', 
            'bytes_out_rate',
            'bytes_out_to_in_ratio',
            'avg_latency'
        ])
        
        # Geographic and device features
        features.extend([
            'new_device_flag',
            'new_ip_flag', 
            'geo_change_flag',
            'unique_ips',
            'unique_devices'
        ])
        
        # Behavioral features
        features.extend([
            'action_entropy',
            'action_rarity_score',
            'time_of_day_deviation_score',
            'burstiness_score'
        ])
        
        # Rolling statistics
        features.extend([
            'rolling_events_mean',
            'rolling_events_std',
            'rolling_failures_mean',
            'rolling_failures_std',
            'rolling_bytes_out_mean',
            'rolling_bytes_out_std'
        ])
        
        return features
    
    def extract_features_from_events(self, events: List[Event]) -> pd.DataFrame:
        """Extract features from a list of events"""
        if not events:
            return pd.DataFrame(columns=self.feature_names)
        
        # Convert events to DataFrame
        df = pd.DataFrame([event.model_dump() for event in events])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Sort by timestamp
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Extract features for each event
        feature_data = []
        for idx, row in df.iterrows():
            features = self._extract_single_event_features(row, df, idx)
            feature_data.append(features)
        
        # Create DataFrame with features
        features_df = pd.DataFrame(feature_data)
        
        # Ensure all expected feature columns exist
        for col in self.feature_names:
            if col not in features_df.columns:
                features_df[col] = 0.0
        
        # Select only the feature columns in the correct order
        features_df = features_df[self.feature_names]
        
        return features_df
    
    def _extract_single_event_features(self, event_row: pd.Series, full_df: pd.DataFrame, idx: int) -> Dict[str, float]:
        """Extract features for a single event based on context"""
        features = {}
        
        # Get the event timestamp
        event_time = event_row['timestamp']
        actor_id = event_row['actor_id']
        
        # Define time window for aggregations
        window_start = event_time - timedelta(minutes=self.config.features.rolling_window_minutes)
        
        # Filter events in the time window for this actor
        window_mask = (
            (full_df['timestamp'] >= window_start) & 
            (full_df['timestamp'] <= event_time) & 
            (full_df['actor_id'] == actor_id)
        )
        window_events = full_df[window_mask]
        
        # Calculate time-based features
        time_window_minutes = (event_time - window_start).total_seconds() / 60.0
        if time_window_minutes == 0:
            time_window_minutes = 1.0  # Avoid division by zero
        
        # Event count features
        total_events = len(window_events)
        failure_events = len(window_events[window_events['result'] == 'fail'])
        success_events = total_events - failure_events
        
        features['events_per_min'] = total_events / time_window_minutes
        features['failures_per_min'] = failure_events / time_window_minutes
        features['success_rate'] = success_events / total_events if total_events > 0 else 0.0
        
        # Action type counts
        features['login_count'] = len(window_events[window_events['action_type'] == 'login'])
        features['api_call_count'] = len(window_events[window_events['action_type'] == 'api_call'])
        features['file_read_count'] = len(window_events[window_events['action_type'] == 'file_read'])
        features['file_write_count'] = len(window_events[window_events['action_type'] == 'file_write'])
        features['admin_action_count'] = len(window_events[window_events['action_type'] == 'admin_action'])
        features['privilege_change_count'] = len(window_events[window_events['action_type'] == 'privilege_change'])
        
        # Resource access features
        features['unique_resources'] = window_events['resource_id'].nunique()
        sensitive_mask = window_events['resource_sensitivity'] >= 2
        features['sensitive_access_count'] = len(window_events[sensitive_mask])
        features['sensitive_ratio'] = features['sensitive_access_count'] / total_events if total_events > 0 else 0.0
        features['high_sensitivity_access'] = window_events['resource_sensitivity'].max() if len(window_events) > 0 else 0.0
        
        # Data volume features
        features['bytes_in_total'] = window_events['bytes_in'].sum()
        features['bytes_out_total'] = window_events['bytes_out'].sum()
        features['bytes_out_rate'] = features['bytes_out_total'] / time_window_minutes
        features['bytes_out_to_in_ratio'] = (
            features['bytes_out_total'] / features['bytes_in_total'] 
            if features['bytes_in_total'] > 0 else 0.0
        )
        features['avg_latency'] = window_events['latency_ms'].mean() if len(window_events) > 0 else 0.0
        
        # Geographic and device features
        current_ip = event_row['ip']
        current_device = event_row['device_id']
        current_geo = event_row['geo']
        
        # Check if this is a new IP/device for this actor
        prev_ips = full_df[(full_df['actor_id'] == actor_id) & (full_df.index < idx)]['ip'].unique()
        prev_devices = full_df[(full_df['actor_id'] == actor_id) & (full_df.index < idx)]['device_id'].unique()
        prev_geos = full_df[(full_df['actor_id'] == actor_id) & (full_df.index < idx)]['geo'].unique()
        
        features['new_ip_flag'] = 1.0 if current_ip not in prev_ips else 0.0
        features['new_device_flag'] = 1.0 if current_device not in prev_devices else 0.0
        features['geo_change_flag'] = 1.0 if current_geo not in prev_geos else 0.0
        
        features['unique_ips'] = len(prev_ips) + (0 if current_ip in prev_ips else 1)
        features['unique_devices'] = len(prev_devices) + (0 if current_device in prev_devices else 1)
        
        # Behavioral features
        action_types = window_events['action_type'].tolist()
        if action_types:
            action_counts = Counter(action_types)
            # Calculate entropy of action types
            total_actions = len(action_types)
            entropy = 0.0
            for count in action_counts.values():
                p = count / total_actions
                if p > 0:
                    entropy -= p * np.log2(p)
            features['action_entropy'] = entropy
        else:
            features['action_entropy'] = 0.0
        
        # Time of day features
        hour = event_time.hour
        # Compare to typical working hours (9am-5pm)
        typical_hours = [9, 10, 11, 12, 13, 14, 15, 16]
        features['time_of_day_deviation_score'] = 0.0 if hour in typical_hours else 1.0
        
        # Burstiness score - measure of how clustered events are in time
        if len(window_events) > 1:
            time_diffs = np.diff(pd.to_datetime(window_events['timestamp']).astype(int) // 10**9)
            if len(time_diffs) > 0:
                mean_time_diff = np.mean(time_diffs)
                std_time_diff = np.std(time_diffs)
                # Higher std means more bursty behavior
                features['burstiness_score'] = std_time_diff / mean_time_diff if mean_time_diff > 0 else 0.0
            else:
                features['burstiness_score'] = 0.0
        else:
            features['burstiness_score'] = 0.0
        
        # Rolling statistics (comparing to historical behavior)
        # For this implementation, we'll use the window statistics as proxy for historical
        all_actor_events = full_df[full_df['actor_id'] == actor_id]
        if len(all_actor_events) > 0:
            # Use events up to current index to avoid data leakage
            prev_actor_events = all_actor_events[all_actor_events.index < idx]
            if len(prev_actor_events) > 0:
                features['rolling_events_mean'] = prev_actor_events['action_type'].count() / len(prev_actor_events) if len(prev_actor_events) > 0 else 0.0
                features['rolling_events_std'] = 1.0  # Placeholder - would need more history
                features['rolling_failures_mean'] = len(prev_actor_events[prev_actor_events['result'] == 'fail']) / len(prev_actor_events) if len(prev_actor_events) > 0 else 0.0
                features['rolling_failures_std'] = 1.0  # Placeholder
                features['rolling_bytes_out_mean'] = prev_actor_events['bytes_out'].mean() if len(prev_actor_events) > 0 else 0.0
                features['rolling_bytes_out_std'] = prev_actor_events['bytes_out'].std() if len(prev_actor_events) > 0 else 0.0
            else:
                # No previous history, use current window as baseline
                features['rolling_events_mean'] = total_events
                features['rolling_events_std'] = 1.0
                features['rolling_failures_mean'] = failure_events
                features['rolling_failures_std'] = 1.0
                features['rolling_bytes_out_mean'] = features['bytes_out_total']
                features['rolling_bytes_out_std'] = 1.0
        else:
            features['rolling_events_mean'] = total_events
            features['rolling_events_std'] = 1.0
            features['rolling_failures_mean'] = failure_events
            features['rolling_failures_std'] = 1.0
            features['rolling_bytes_out_mean'] = features['bytes_out_total']
            features['rolling_bytes_out_std'] = 1.0
        
        return features
    
    def extract_window_features(self, events: List[Event]) -> List[FeatureWindow]:
        """Extract features for fixed time windows"""
        if not events:
            return []
        
        # Convert to DataFrame
        df = pd.DataFrame([event.model_dump() for event in events])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Create time windows
        window_size = timedelta(minutes=self.config.features.rolling_window_minutes)
        feature_windows = []
        
        # Group events into windows
        start_time = df['timestamp'].min()
        end_time = df['timestamp'].max()
        
        current_time = start_time
        while current_time < end_time:
            window_end = current_time + window_size
            
            # Get events in this window
            window_events = df[
                (df['timestamp'] >= current_time) & 
                (df['timestamp'] < window_end)
            ]
            
            if len(window_events) > 0:
                # Group by actor_id to create separate windows per actor
                for actor_id in window_events['actor_id'].unique():
                    actor_window_events = window_events[window_events['actor_id'] == actor_id]
                    if len(actor_window_events) > 0:
                        # Extract features for this actor's window
                        features = self._extract_window_features_for_actor(actor_window_events, current_time, window_end, actor_id)
                        
                        # Determine if this window is anomalous based on original events
                        is_anomaly = any([Event(**row).ground_truth_is_anomaly for _, row in actor_window_events.iterrows()])
                        
                        feature_window = FeatureWindow(
                            start_time=current_time,
                            end_time=window_end,
                            features=features,
                            actor_id=actor_id,
                            session_id=actor_window_events['session_id'].iloc[0] if len(actor_window_events) > 0 else "unknown",
                            is_anomaly=is_anomaly
                        )
                        feature_windows.append(feature_window)
            
            current_time = window_end
        
        return feature_windows
    
    def _extract_window_features_for_actor(self, window_events: pd.DataFrame, start_time: datetime, end_time: datetime, actor_id: str) -> Dict[str, float]:
        """Extract aggregate features for a time window for a specific actor"""
        features = {}
        
        # Time window duration in minutes
        duration_minutes = (end_time - start_time).total_seconds() / 60.0
        if duration_minutes == 0:
            duration_minutes = 1.0
        
        # Event count features
        total_events = len(window_events)
        failure_events = len(window_events[window_events['result'] == 'fail'])
        success_events = total_events - failure_events
        
        features['events_per_min'] = total_events / duration_minutes
        features['failures_per_min'] = failure_events / duration_minutes
        features['success_rate'] = success_events / total_events if total_events > 0 else 0.0
        
        # Action type counts
        action_counts = window_events['action_type'].value_counts()
        features['login_count'] = action_counts.get('login', 0)
        features['api_call_count'] = action_counts.get('api_call', 0)
        features['file_read_count'] = action_counts.get('file_read', 0)
        features['file_write_count'] = action_counts.get('file_write', 0)
        features['admin_action_count'] = action_counts.get('admin_action', 0)
        features['privilege_change_count'] = action_counts.get('privilege_change', 0)
        
        # Resource access features
        features['unique_resources'] = window_events['resource_id'].nunique()
        sensitive_mask = window_events['resource_sensitivity'] >= 2
        features['sensitive_access_count'] = len(window_events[sensitive_mask])
        features['sensitive_ratio'] = features['sensitive_access_count'] / total_events if total_events > 0 else 0.0
        features['high_sensitivity_access'] = window_events['resource_sensitivity'].max() if len(window_events) > 0 else 0.0
        
        # Data volume features
        features['bytes_in_total'] = window_events['bytes_in'].sum()
        features['bytes_out_total'] = window_events['bytes_out'].sum()
        features['bytes_out_rate'] = features['bytes_out_total'] / duration_minutes
        features['bytes_out_to_in_ratio'] = (
            features['bytes_out_total'] / features['bytes_in_total'] 
            if features['bytes_in_total'] > 0 else 0.0
        )
        features['avg_latency'] = window_events['latency_ms'].mean() if len(window_events) > 0 else 0.0
        
        # Geographic and device features
        features['unique_ips'] = window_events['ip'].nunique()
        features['unique_devices'] = window_events['device_id'].nunique()
        
        # Since we're looking at a window, we can't determine new_ip_flag, etc. without historical context
        # We'll set these to 0 for now
        features['new_ip_flag'] = 0.0
        features['new_device_flag'] = 0.0
        features['geo_change_flag'] = 0.0
        
        # Behavioral features
        action_types = window_events['action_type'].tolist()
        if action_types:
            action_counts = Counter(action_types)
            total_actions = len(action_types)
            entropy = 0.0
            for count in action_counts.values():
                p = count / total_actions
                if p > 0:
                    entropy -= p * np.log2(p)
            features['action_entropy'] = entropy
        else:
            features['action_entropy'] = 0.0
        
        # Time of day features (use the middle of the window)
        mid_time = start_time + (end_time - start_time) / 2
        hour = mid_time.hour
        typical_hours = [9, 10, 11, 12, 13, 14, 15, 16]
        features['time_of_day_deviation_score'] = 0.0 if hour in typical_hours else 1.0
        
        # Burstiness score
        if len(window_events) > 1:
            time_diffs = np.diff(pd.to_datetime(window_events['timestamp']).astype(int) // 10**9)
            if len(time_diffs) > 0:
                mean_time_diff = np.mean(time_diffs)
                std_time_diff = np.std(time_diffs)
                features['burstiness_score'] = std_time_diff / mean_time_diff if mean_time_diff > 0 else 0.0
            else:
                features['burstiness_score'] = 0.0
        else:
            features['burstiness_score'] = 0.0
        
        # Rolling statistics - for this implementation we'll use window statistics as baseline
        features['rolling_events_mean'] = total_events
        features['rolling_events_std'] = 1.0
        features['rolling_failures_mean'] = failure_events
        features['rolling_failures_std'] = 1.0
        features['rolling_bytes_out_mean'] = features['bytes_out_total']
        features['rolling_bytes_out_std'] = 1.0
        
        return features
    
    def get_feature_names(self) -> List[str]:
        """Get the ordered list of feature names"""
        return self.feature_names.copy()


def extract_features_main(config, events: List[Event]) -> List[FeatureWindow]:
    """Main function to extract features from events"""
    extractor = FeatureExtractor(config)
    feature_windows = extractor.extract_window_features(events)
    logger.info(f"Extracted features for {len(feature_windows)} windows")
    return feature_windows