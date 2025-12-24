from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import pandas as pd
from ..core.schemas import Event, FeatureWindow
from ..core.logger import logger


class TimeWindower:
    """Create time-based windows from events for feature extraction"""
    
    def __init__(self, config):
        self.config = config
    
    def create_rolling_windows(self, events: List[Event], window_size_minutes: int = None) -> List[FeatureWindow]:
        """Create rolling time windows from events"""
        if not events:
            return []
        
        if window_size_minutes is None:
            window_size_minutes = self.config.features.rolling_window_minutes
        
        # Convert events to DataFrame for easier processing
        df = pd.DataFrame([event.model_dump() for event in events])
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        if df.empty:
            return []
        
        # Create rolling windows
        windows = []
        window_duration = timedelta(minutes=window_size_minutes)
        
        # Get the time range
        start_time = df['timestamp'].min()
        end_time = df['timestamp'].max()
        
        # Create windows at regular intervals
        current_time = start_time
        while current_time <= end_time:
            window_end = current_time + window_duration
            
            # Get events in this window
            mask = (df['timestamp'] >= current_time) & (df['timestamp'] < window_end)
            window_events = df[mask]
            
            if not window_events.empty:
                # Group by actor_id to create separate windows per actor
                for actor_id in window_events['actor_id'].unique():
                    actor_events = window_events[window_events['actor_id'] == actor_id]
                    
                    if not actor_events.empty:
                        # Create feature window for this actor
                        feature_window = self._create_feature_window(actor_events, current_time, window_end, actor_id)
                        windows.append(feature_window)
            
            # Move to next window (with potential overlap)
            current_time += timedelta(minutes=window_size_minutes//2)  # 50% overlap
        
        return windows
    
    def create_session_windows(self, events: List[Event], session_timeout_minutes: int = None) -> List[FeatureWindow]:
        """Create session-based windows from events"""
        if not events:
            return []
        
        if session_timeout_minutes is None:
            session_timeout_minutes = self.config.features.session_timeout_minutes
        
        session_duration = timedelta(minutes=session_timeout_minutes)
        
        # Group events by actor
        actor_events = {}
        for event in events:
            if event.actor_id not in actor_events:
                actor_events[event.actor_id] = []
            actor_events[event.actor_id].append(event)
        
        windows = []
        
        # Process each actor's events to create sessions
        for actor_id, actor_event_list in actor_events.items():
            # Sort events by timestamp
            sorted_events = sorted(actor_event_list, key=lambda x: x.timestamp)
            
            # Create sessions based on timeout
            current_session_start = None
            current_session_events = []
            
            for event in sorted_events:
                if current_session_start is None:
                    # Start first session
                    current_session_start = event.timestamp
                    current_session_events = [event]
                else:
                    # Check if this event starts a new session
                    time_since_last = event.timestamp - current_session_events[-1].timestamp
                    if time_since_last > session_duration:
                        # End current session and start new one
                        if current_session_events:
                            feature_window = self._create_feature_window_from_events(
                                current_session_events, 
                                current_session_start, 
                                current_session_events[-1].timestamp
                            )
                            windows.append(feature_window)
                        
                        current_session_start = event.timestamp
                        current_session_events = [event]
                    else:
                        # Add to current session
                        current_session_events.append(event)
            
            # Add the last session if it exists
            if current_session_events:
                feature_window = self._create_feature_window_from_events(
                    current_session_events,
                    current_session_start,
                    current_session_events[-1].timestamp
                )
                windows.append(feature_window)
        
        return windows
    
    def _create_feature_window(self, events_df: pd.DataFrame, start_time: datetime, end_time: datetime, actor_id: str) -> FeatureWindow:
        """Create a feature window from events in a DataFrame"""
        # Convert back to Event objects to check for anomalies
        events = [Event(**row) for _, row in events_df.iterrows()]
        
        # Check if any events in this window are anomalies
        is_anomaly = any(event.ground_truth_is_anomaly for event in events)
        
        # Create a basic feature dictionary (will be filled by feature extraction)
        features = {
            'event_count': len(events),
            'actor_id': actor_id
        }
        
        # Get a session ID (use the first event's session_id if available)
        session_id = events[0].session_id if events else "unknown"
        
        return FeatureWindow(
            start_time=start_time,
            end_time=end_time,
            features=features,
            actor_id=actor_id,
            session_id=session_id,
            is_anomaly=is_anomaly
        )
    
    def _create_feature_window_from_events(self, events: List[Event], start_time: datetime, end_time: datetime) -> FeatureWindow:
        """Create a feature window from a list of Event objects"""
        # Check if any events in this window are anomalies
        is_anomaly = any(event.ground_truth_is_anomaly for event in events)
        
        # Create a basic feature dictionary
        features = {
            'event_count': len(events),
            'actor_id': events[0].actor_id if events else "unknown"
        }
        
        # Get a session ID (use the first event's session_id if available)
        session_id = events[0].session_id if events else "unknown"
        
        return FeatureWindow(
            start_time=start_time,
            end_time=end_time,
            features=features,
            actor_id=events[0].actor_id if events else "unknown",
            session_id=session_id,
            is_anomaly=is_anomaly
        )


class FeatureAggregator:
    """Aggregate features across different window types"""
    
    def __init__(self, config):
        self.config = config
    
    def aggregate_windows(self, windows: List[FeatureWindow]) -> pd.DataFrame:
        """Aggregate feature windows into a DataFrame"""
        if not windows:
            return pd.DataFrame()
        
        # Convert windows to a list of feature dictionaries
        feature_data = []
        for window in windows:
            # Flatten the features dictionary and add window metadata
            row_data = window.features.copy()
            row_data['window_start'] = window.start_time
            row_data['window_end'] = window.end_time
            row_data['actor_id'] = window.actor_id
            row_data['session_id'] = window.session_id
            row_data['is_anomaly'] = window.is_anomaly
            feature_data.append(row_data)
        
        # Create DataFrame
        df = pd.DataFrame(feature_data)
        
        return df


def create_windows_main(config, events: List[Event]) -> List[FeatureWindow]:
    """Main function to create windows from events"""
    windower = TimeWindower(config)
    
    # Create both time-based and session-based windows
    time_windows = windower.create_rolling_windows(events)
    session_windows = windower.create_session_windows(events)
    
    # Combine windows (in a real implementation, you might want to handle overlaps differently)
    all_windows = time_windows + session_windows
    
    logger.info(f"Created {len(time_windows)} time-based windows and {len(session_windows)} session-based windows")
    
    return all_windows