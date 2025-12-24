from typing import List, Dict, Any
from datetime import datetime, timedelta
import numpy as np
import uuid
from .profiles import get_user_profile
from .scenarios import get_all_scenarios, inject_scenario
from ..core.schemas import Event
from ..core.logger import logger


class LogGenerator:
    """Generate synthetic security logs with normal behavior and anomalies"""
    
    def __init__(self, config):
        self.config = config
        self.scenarios = get_all_scenarios()
    
    def generate_users(self) -> List[Dict[str, str]]:
        """Generate user profiles"""
        users = []
        
        # Define user distribution
        profile_types = ["normal_user", "power_user", "admin", "service_account"]
        # Most users are normal, few admins and service accounts
        profile_weights = [0.7, 0.2, 0.05, 0.05]
        
        for i in range(self.config.simulator.user_count):
            user_id = f"user_{i:04d}"
            profile_type = np.random.choice(profile_types, p=profile_weights)
            users.append({"user_id": user_id, "profile_type": profile_type})
        
        return users
    
    def generate_normal_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Generate normal events based on user profiles"""
        events = []
        users = self.generate_users()
        
        current_time = start_time
        
        # Generate events over the time period
        while current_time < end_time:
            # Determine how many sessions to generate in this time window
            # Use a small time window to space out events
            time_window = timedelta(minutes=10)
            window_end = min(current_time + time_window, end_time)
            
            # Generate sessions for random users
            num_sessions = np.random.poisson(2)  # Average 2 sessions per 10-minute window
            for _ in range(num_sessions):
                if current_time >= end_time:
                    break
                    
                # Pick a random user
                user_data = np.random.choice(users)
                user_id = user_data["user_id"]
                profile_type = user_data["profile_type"]
                
                # Create user profile
                profile = get_user_profile(user_id, profile_type)
                
                # Generate a session
                session_events = profile.generate_session(current_time)
                
                # Add events to our collection if they're within our time window
                for event in session_events:
                    if event["timestamp"] <= window_end:
                        events.append(event)
                    else:
                        # If session extends beyond window, add partial events
                        if event["timestamp"] <= end_time:
                            events.append(event)
            
            current_time = window_end
        
        return events
    
    def inject_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Inject anomalies into the normal events"""
        if not events:
            return events
        
        # Calculate how many anomalies to inject based on anomaly rate
        total_events = len(events)
        target_anomalies = int(total_events * self.config.simulator.anomaly_rate)
        
        if target_anomalies == 0 and total_events > 0:
            target_anomalies = 1  # At least one anomaly if we have events
        
        anomalies_injected = 0
        anomaly_events = events.copy()
        
        while anomalies_injected < target_anomalies:
            # Pick a random scenario
            scenario = np.random.choice(self.scenarios)
            
            # Pick a random user for the anomaly
            if events:
                base_event = np.random.choice(events)
                user_id = base_event["actor_id"]
                
                # Inject the anomaly
                try:
                    anomaly_events = inject_scenario(anomaly_events, scenario, user_id)
                    anomalies_injected += 1
                    logger.info(f"Injected {scenario.name} anomaly for user {user_id}")
                except Exception as e:
                    logger.warning(f"Failed to inject {scenario.name} anomaly: {e}")
                    continue
            else:
                break
        
        return anomaly_events
    
    def generate_logs(self, days: int = 7) -> List[Event]:
        """Generate synthetic security logs"""
        logger.info(f"Generating logs for {days} days with {self.config.simulator.user_count} users")
        
        start_time = datetime.now() - timedelta(days=days)
        end_time = datetime.now()
        
        # Generate normal events
        logger.info("Generating normal events...")
        normal_events = self.generate_normal_events(start_time, end_time)
        logger.info(f"Generated {len(normal_events)} normal events")
        
        # Inject anomalies
        logger.info("Injecting anomalies...")
        anomaly_events = self.inject_anomalies(normal_events)
        logger.info(f"Final dataset has {len(anomaly_events)} events with anomalies")
        
        # Convert to Event objects
        event_objects = []
        for event_dict in anomaly_events:
            # Ensure timestamp is datetime
            if not isinstance(event_dict['timestamp'], datetime):
                event_dict['timestamp'] = datetime.fromisoformat(str(event_dict['timestamp']))
            event_objects.append(Event(**event_dict))
        
        # Sort events by timestamp
        event_objects.sort(key=lambda x: x.timestamp)
        
        return event_objects
    
    def save_logs(self, events: List[Event], output_path: str) -> None:
        """Save events to file"""
        from ..core.storage import EventStorage
        storage = EventStorage(output_path)
        storage.save_events(events)
        logger.info(f"Saved {len(events)} events to {output_path}")


def generate_logs_main(config, output_path: str, days: int, user_count: int) -> None:
    """Main function to generate logs"""
    # Update config with command line parameters
    config.simulator.days = days
    config.simulator.user_count = user_count
    
    generator = LogGenerator(config)
    events = generator.generate_logs(days=days)
    generator.save_logs(events, output_path)
    
    logger.info(f"Log generation completed. Generated {len(events)} events to {output_path}")