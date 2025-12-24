from typing import Dict, List, Tuple
import numpy as np
from datetime import datetime, timedelta
import uuid


class UserProfile:
    """Base class for user profiles"""
    
    def __init__(self, user_id: str, role: str):
        self.user_id = user_id
        self.role = role
        self.session_count = 0
    
    def generate_session(self, start_time: datetime) -> List[dict]:
        """Generate a session of events for this user profile"""
        raise NotImplementedError


class NormalUserProfile(UserProfile):
    """Normal user profile with typical work patterns"""
    
    def __init__(self, user_id: str):
        super().__init__(user_id, "normal_user")
        # Work hours: 9 AM to 5 PM
        self.work_start_hour = 9
        self.work_end_hour = 17
        # Moderate activity level
        self.avg_events_per_hour = 10
        self.action_types = [
            "login", "api_call", "file_read", "file_write", 
            "payment", "chat", "logout"
        ]
        self.resource_sensitivity_distribution = [0.6, 0.3, 0.1, 0.0]  # Mostly low sensitivity
    
    def generate_session(self, start_time: datetime) -> List[dict]:
        """Generate a normal user session"""
        # Determine session length (typically 30-120 minutes)
        session_duration = np.random.normal(60, 20)  # minutes
        session_duration = max(10, session_duration)  # minimum 10 minutes
        
        # Determine number of events in session
        num_events = max(1, int(np.random.poisson(self.avg_events_per_hour * (session_duration / 60))))
        
        events = []
        current_time = start_time
        session_id = str(uuid.uuid4())
        
        # Add login event
        events.append({
            "timestamp": current_time,
            "actor_id": self.user_id,
            "actor_role": self.role,
            "session_id": session_id,
            "action_type": "login",
            "resource_id": f"session_{session_id}",
            "resource_sensitivity": 0,
            "result": "success",
            "latency_ms": np.random.normal(50, 10),
            "bytes_in": np.random.normal(100, 50),
            "bytes_out": np.random.normal(200, 100),
            "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            "device_id": f"device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
            "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL'])}",
            "ground_truth_is_anomaly": False,
            "scenario_tag": "normal"
        })
        
        current_time += timedelta(seconds=np.random.randint(30, 120))
        
        # Add intermediate events
        for _ in range(num_events - 2):
            action_type = np.random.choice(self.action_types[1:-1])  # Exclude login/logout
            resource_sensitivity = np.random.choice([0, 1, 2, 3], p=self.resource_sensitivity_distribution)
            
            events.append({
                "timestamp": current_time,
                "actor_id": self.user_id,
                "actor_role": self.role,
                "session_id": session_id,
                "action_type": action_type,
                "resource_id": f"resource_{np.random.randint(1000, 9999)}",
                "resource_sensitivity": resource_sensitivity,
                "result": np.random.choice(["success", "fail"], p=[0.95, 0.05]),
                "latency_ms": np.random.normal(100, 30),
                "bytes_in": np.random.normal(500, 200),
                "bytes_out": np.random.normal(800, 300),
                "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "device_id": f"device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
                "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL'])}",
                "ground_truth_is_anomaly": False,
                "scenario_tag": "normal"
            })
            
            # Time between events (typically 1-10 minutes)
            time_diff = timedelta(minutes=np.random.exponential(3))
            current_time += time_diff
        
        # Add logout event
        events.append({
            "timestamp": current_time,
            "actor_id": self.user_id,
            "actor_role": self.role,
            "session_id": session_id,
            "action_type": "logout",
            "resource_id": f"session_{session_id}",
            "resource_sensitivity": 0,
            "result": "success",
            "latency_ms": np.random.normal(30, 5),
            "bytes_in": np.random.normal(50, 20),
            "bytes_out": np.random.normal(100, 50),
            "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            "device_id": f"device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
            "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL'])}",
            "ground_truth_is_anomaly": False,
            "scenario_tag": "normal"
        })
        
        return events


class PowerUserProfile(UserProfile):
    """Power user profile with higher activity"""
    
    def __init__(self, user_id: str):
        super().__init__(user_id, "power_user")
        # Work hours: 8 AM to 7 PM
        self.work_start_hour = 8
        self.work_end_hour = 19
        # Higher activity level
        self.avg_events_per_hour = 30
        self.action_types = [
            "login", "api_call", "file_read", "file_write", 
            "payment", "chat", "admin_action", "privilege_change", "logout"
        ]
        self.resource_sensitivity_distribution = [0.4, 0.3, 0.2, 0.1]  # More sensitive access
    
    def generate_session(self, start_time: datetime) -> List[dict]:
        """Generate a power user session"""
        # Longer session (typically 60-240 minutes)
        session_duration = np.random.normal(120, 40)  # minutes
        session_duration = max(30, session_duration)  # minimum 30 minutes
        
        # More events due to higher activity
        num_events = max(1, int(np.random.poisson(self.avg_events_per_hour * (session_duration / 60))))
        
        events = []
        current_time = start_time
        session_id = str(uuid.uuid4())
        
        # Add login event
        events.append({
            "timestamp": current_time,
            "actor_id": self.user_id,
            "actor_role": self.role,
            "session_id": session_id,
            "action_type": "login",
            "resource_id": f"session_{session_id}",
            "resource_sensitivity": 1,
            "result": "success",
            "latency_ms": np.random.normal(40, 8),
            "bytes_in": np.random.normal(150, 60),
            "bytes_out": np.random.normal(300, 120),
            "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            "device_id": f"power_device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
            "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL', 'WA'])}",
            "ground_truth_is_anomaly": False,
            "scenario_tag": "normal"
        })
        
        current_time += timedelta(seconds=np.random.randint(30, 120))
        
        # Add intermediate events
        for _ in range(num_events - 2):
            action_type = np.random.choice(self.action_types[1:-1])  # Exclude login/logout
            resource_sensitivity = np.random.choice([0, 1, 2, 3], p=self.resource_sensitivity_distribution)
            
            events.append({
                "timestamp": current_time,
                "actor_id": self.user_id,
                "actor_role": self.role,
                "session_id": session_id,
                "action_type": action_type,
                "resource_id": f"resource_{np.random.randint(1000, 9999)}",
                "resource_sensitivity": resource_sensitivity,
                "result": np.random.choice(["success", "fail"], p=[0.97, 0.03]),
                "latency_ms": np.random.normal(80, 25),
                "bytes_in": np.random.normal(800, 300),
                "bytes_out": np.random.normal(1200, 400),
                "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "device_id": f"power_device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
                "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL', 'WA'])}",
                "ground_truth_is_anomaly": False,
                "scenario_tag": "normal"
            })
            
            # Time between events (typically 30 seconds - 5 minutes)
            time_diff = timedelta(minutes=np.random.exponential(1.5))
            current_time += time_diff
        
        # Add logout event
        events.append({
            "timestamp": current_time,
            "actor_id": self.user_id,
            "actor_role": self.role,
            "session_id": session_id,
            "action_type": "logout",
            "resource_id": f"session_{session_id}",
            "resource_sensitivity": 0,
            "result": "success",
            "latency_ms": np.random.normal(25, 5),
            "bytes_in": np.random.normal(60, 25),
            "bytes_out": np.random.normal(120, 60),
            "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            "device_id": f"power_device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
            "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL', 'WA'])}",
            "ground_truth_is_anomaly": False,
            "scenario_tag": "normal"
        })
        
        return events


class AdminUserProfile(UserProfile):
    """Admin user profile with rare but sensitive actions"""
    
    def __init__(self, user_id: str):
        super().__init__(user_id, "admin")
        # Irregular hours
        self.work_start_hour = np.random.choice([6, 7, 8, 9])
        self.work_end_hour = np.random.choice([16, 17, 18, 19, 20, 21])
        # Lower frequency but sensitive actions
        self.avg_events_per_hour = 5
        self.action_types = [
            "login", "api_call", "file_read", "file_write", 
            "admin_action", "privilege_change", "logout"
        ]
        self.resource_sensitivity_distribution = [0.1, 0.2, 0.3, 0.4]  # Mostly high sensitivity
    
    def generate_session(self, start_time: datetime) -> List[dict]:
        """Generate an admin user session"""
        # Shorter but more intense session (typically 15-60 minutes)
        session_duration = np.random.normal(30, 10)  # minutes
        session_duration = max(5, session_duration)  # minimum 5 minutes
        
        # Fewer but more sensitive events
        num_events = max(1, int(np.random.poisson(self.avg_events_per_hour * (session_duration / 60))))
        
        events = []
        current_time = start_time
        session_id = str(uuid.uuid4())
        
        # Add login event
        events.append({
            "timestamp": current_time,
            "actor_id": self.user_id,
            "actor_role": self.role,
            "session_id": session_id,
            "action_type": "login",
            "resource_id": f"session_{session_id}",
            "resource_sensitivity": 2,
            "result": "success",
            "latency_ms": np.random.normal(35, 7),
            "bytes_in": np.random.normal(200, 80),
            "bytes_out": np.random.normal(400, 150),
            "ip": f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",  # Internal IP
            "device_id": f"admin_device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
            "geo": "US-DC",  # Data center location
            "ground_truth_is_anomaly": False,
            "scenario_tag": "normal"
        })
        
        current_time += timedelta(seconds=np.random.randint(10, 60))
        
        # Add intermediate events (mostly admin actions)
        for _ in range(num_events - 2):
            # Admins more likely to perform admin actions
            action_type = np.random.choice(
                self.action_types[1:-1], 
                p=[0.1, 0.1, 0.2, 0.2, 0.4]  # Higher probability for admin actions
            )
            resource_sensitivity = np.random.choice([0, 1, 2, 3], p=self.resource_sensitivity_distribution)
            
            events.append({
                "timestamp": current_time,
                "actor_id": self.user_id,
                "actor_role": self.role,
                "session_id": session_id,
                "action_type": action_type,
                "resource_id": f"resource_{np.random.randint(1000, 9999)}",
                "resource_sensitivity": resource_sensitivity,
                "result": np.random.choice(["success", "fail"], p=[0.98, 0.02]),
                "latency_ms": np.random.normal(120, 40),
                "bytes_in": np.random.normal(1000, 400),
                "bytes_out": np.random.normal(1500, 500),
                "ip": f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",  # Internal IP
                "device_id": f"admin_device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
                "geo": "US-DC",  # Data center location
                "ground_truth_is_anomaly": False,
                "scenario_tag": "normal"
            })
            
            # Time between events (typically 1-10 minutes)
            time_diff = timedelta(minutes=np.random.exponential(2))
            current_time += time_diff
        
        # Add logout event
        events.append({
            "timestamp": current_time,
            "actor_id": self.user_id,
            "actor_role": self.role,
            "session_id": session_id,
            "action_type": "logout",
            "resource_id": f"session_{session_id}",
            "resource_sensitivity": 1,
            "result": "success",
            "latency_ms": np.random.normal(20, 5),
            "bytes_in": np.random.normal(80, 30),
            "bytes_out": np.random.normal(150, 70),
            "ip": f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",  # Internal IP
            "device_id": f"admin_device_{self.user_id[-4:]}_{np.random.randint(1000, 9999)}",
            "geo": "US-DC",  # Data center location
            "ground_truth_is_anomaly": False,
            "scenario_tag": "normal"
        })
        
        return events


class ServiceAccountProfile(UserProfile):
    """Service account profile with high frequency but predictable actions"""
    
    def __init__(self, user_id: str):
        super().__init__(user_id, "service_account")
        # 24/7 operation
        self.work_start_hour = 0
        self.work_end_hour = 23
        # Very high frequency but predictable
        self.avg_events_per_hour = 100
        self.action_types = [
            "api_call", "file_read", "file_write"
        ]
        self.resource_sensitivity_distribution = [0.7, 0.2, 0.1, 0.0]  # Mostly low sensitivity
    
    def generate_session(self, start_time: datetime) -> List[dict]:
        """Generate a service account session"""
        # Service accounts may have very long sessions
        session_duration = np.random.normal(360, 60)  # minutes (6 hours average)
        session_duration = max(60, session_duration)  # minimum 60 minutes
        
        # Very high number of events
        num_events = max(1, int(np.random.poisson(self.avg_events_per_hour * (session_duration / 60))))
        
        events = []
        current_time = start_time
        session_id = str(uuid.uuid4())
        
        # Service accounts don't typically "login" in the traditional sense
        # Instead, they might have an "activation" or "start" event
        events.append({
            "timestamp": current_time,
            "actor_id": self.user_id,
            "actor_role": self.role,
            "session_id": session_id,
            "action_type": "api_call",
            "resource_id": f"service_{self.user_id}_init",
            "resource_sensitivity": 0,
            "result": "success",
            "latency_ms": np.random.normal(20, 5),
            "bytes_in": np.random.normal(50, 20),
            "bytes_out": np.random.normal(100, 40),
            "ip": f"10.10.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",  # Service IP range
            "device_id": f"service_{self.user_id}",
            "geo": "US-DC",
            "ground_truth_is_anomaly": False,
            "scenario_tag": "normal"
        })
        
        current_time += timedelta(seconds=np.random.randint(1, 30))
        
        # Add intermediate events
        for _ in range(num_events - 1):
            action_type = np.random.choice(self.action_types)
            resource_sensitivity = np.random.choice([0, 1, 2, 3], p=self.resource_sensitivity_distribution)
            
            events.append({
                "timestamp": current_time,
                "actor_id": self.user_id,
                "actor_role": self.role,
                "session_id": session_id,
                "action_type": action_type,
                "resource_id": f"resource_{np.random.randint(1000, 9999)}",
                "resource_sensitivity": resource_sensitivity,
                "result": np.random.choice(["success", "fail"], p=[0.99, 0.01]),
                "latency_ms": np.random.normal(15, 3),
                "bytes_in": np.random.normal(300, 100),
                "bytes_out": np.random.normal(400, 150),
                "ip": f"10.10.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",  # Service IP range
                "device_id": f"service_{self.user_id}",
                "geo": "US-DC",
                "ground_truth_is_anomaly": False,
                "scenario_tag": "normal"
            })
            
            # Very short time between events (typically milliseconds to seconds)
            time_diff = timedelta(seconds=np.random.exponential(0.5))
            current_time += time_diff
        
        return events


def get_user_profile(user_id: str, profile_type: str) -> UserProfile:
    """Factory function to create user profiles"""
    if profile_type == "normal_user":
        return NormalUserProfile(user_id)
    elif profile_type == "power_user":
        return PowerUserProfile(user_id)
    elif profile_type == "admin":
        return AdminUserProfile(user_id)
    elif profile_type == "service_account":
        return ServiceAccountProfile(user_id)
    else:
        # Default to normal user
        return NormalUserProfile(user_id)