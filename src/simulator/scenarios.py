from typing import List, Dict, Any
from datetime import datetime, timedelta
import numpy as np
import uuid


class AnomalyScenario:
    """Base class for anomaly scenarios"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        """Inject anomaly into base events"""
        raise NotImplementedError


class BruteForceLoginScenario(AnomalyScenario):
    """Simulate brute force login attempts"""
    
    def __init__(self):
        super().__init__("brute_force_login", "Multiple failed login attempts from same IP")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        # Find a time window to inject the anomaly
        if not base_events:
            return base_events
        
        # Choose a random time to start the attack
        base_time = base_events[0]['timestamp']
        attack_start = base_time + timedelta(minutes=np.random.randint(0, 120))
        
        # Generate multiple failed login attempts in a short time
        attack_events = []
        attack_ip = f"203.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"  # Suspicious IP
        attack_device = f"suspicious_device_{np.random.randint(1000, 9999)}"
        
        # Generate 20-50 failed login attempts within 5 minutes
        num_attempts = np.random.randint(20, 51)
        attack_timestamp = attack_start
        
        for i in range(num_attempts):
            attack_events.append({
                "timestamp": attack_timestamp,
                "actor_id": user_id,
                "actor_role": "normal_user",  # Even normal users can be targeted
                "session_id": f"attack_session_{str(uuid.uuid4())[:8]}",
                "action_type": "login",
                "resource_id": f"login_attempt_{i}",
                "resource_sensitivity": 0,
                "result": "fail",
                "latency_ms": np.random.normal(200, 50),  # Slower due to rate limiting
                "bytes_in": np.random.normal(80, 20),
                "bytes_out": np.random.normal(120, 40),
                "ip": attack_ip,
                "device_id": attack_device,
                "geo": f"XX-{np.random.choice(['RU', 'CN', 'BR', 'NG'])}",  # Suspicious location
                "ground_truth_is_anomaly": True,
                "scenario_tag": self.name
            })
            
            # Time between attempts (very fast for brute force)
            attack_timestamp += timedelta(seconds=np.random.uniform(0.1, 2.0))
        
        # Combine original events with attack events
        all_events = base_events + attack_events
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


class CredentialStuffingScenario(AnomalyScenario):
    """Simulate credential stuffing attack"""
    
    def __init__(self):
        super().__init__("credential_stuffing", "Multiple login attempts with different usernames but same IP")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        if not base_events:
            return base_events
        
        # Choose a time to start the attack
        base_time = base_events[0]['timestamp']
        attack_start = base_time + timedelta(minutes=np.random.randint(0, 120))
        
        # Generate credential stuffing attack
        attack_events = []
        attack_ip = f"204.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"  # Suspicious IP
        attack_device = f"credential_stuffing_{np.random.randint(1000, 9999)}"
        
        # Generate 30-100 login attempts with different users but same IP
        num_attempts = np.random.randint(30, 101)
        attack_timestamp = attack_start
        
        for i in range(num_attempts):
            fake_user_id = f"user_{np.random.randint(1000, 99999)}"
            attack_events.append({
                "timestamp": attack_timestamp,
                "actor_id": fake_user_id,
                "actor_role": "normal_user",
                "session_id": f"stuffing_session_{str(uuid.uuid4())[:8]}",
                "action_type": "login",
                "resource_id": f"login_attempt_{i}",
                "resource_sensitivity": 0,
                "result": np.random.choice(["success", "fail"], p=[0.01, 0.99]),  # Mostly fail
                "latency_ms": np.random.normal(150, 40),
                "bytes_in": np.random.normal(70, 20),
                "bytes_out": np.random.normal(100, 30),
                "ip": attack_ip,
                "device_id": attack_device,
                "geo": f"XX-{np.random.choice(['RU', 'CN', 'BR', 'NG'])}",  # Suspicious location
                "ground_truth_is_anomaly": True,
                "scenario_tag": self.name
            })
            
            # Time between attempts (fast but not as fast as brute force)
            attack_timestamp += timedelta(seconds=np.random.uniform(0.5, 3.0))
        
        # Combine original events with attack events
        all_events = base_events + attack_events
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


class ImpossibleTravelScenario(AnomalyScenario):
    """Simulate impossible travel - user logging in from distant locations rapidly"""
    
    def __init__(self):
        super().__init__("impossible_travel", "User logging in from geographically distant locations in short time")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        if len(base_events) < 2:
            return base_events
        
        # Find a normal login event to duplicate and make suspicious
        login_events = [e for e in base_events if e['action_type'] == 'login' and e['result'] == 'success']
        if not login_events:
            return base_events
        
        # Pick a normal login to duplicate
        normal_login = login_events[np.random.randint(0, len(login_events))]
        
        # Create an impossible travel event shortly after
        travel_time = normal_login['timestamp'] + timedelta(minutes=np.random.randint(1, 30))
        
        # Different geo location (impossible to travel to in such short time)
        original_geo = normal_login['geo']
        possible_geos = ['US-CA', 'US-NY', 'US-TX', 'US-FL', 'US-WA', 'US-IL']
        # Remove original geo to ensure it's different
        possible_geos = [g for g in possible_geos if g != original_geo]
        if not possible_geos:
            possible_geos = ['US-CA', 'US-NY', 'US-TX', 'US-FL', 'US-WA', 'US-IL']
        new_geo = np.random.choice(possible_geos)
        
        impossible_event = {
            "timestamp": travel_time,
            "actor_id": user_id,
            "actor_role": normal_login['actor_role'],
            "session_id": f"travel_session_{str(uuid.uuid4())[:8]}",
            "action_type": "login",
            "resource_id": f"travel_login_{str(uuid.uuid4())[:8]}",
            "resource_sensitivity": 0,
            "result": "success",
            "latency_ms": np.random.normal(100, 20),
            "bytes_in": np.random.normal(90, 25),
            "bytes_out": np.random.normal(180, 50),
            "ip": f"205.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            "device_id": f"travel_device_{np.random.randint(1000, 9999)}",
            "geo": new_geo,
            "ground_truth_is_anomaly": True,
            "scenario_tag": self.name
        }
        
        # Insert the impossible travel event into the timeline
        all_events = base_events + [impossible_event]
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


class DataExfiltrationScenario(AnomalyScenario):
    """Simulate data exfiltration - unusual amount of data being downloaded"""
    
    def __init__(self):
        super().__init__("data_exfiltration", "Unusual amount of data being downloaded by user")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        if not base_events:
            return base_events
        
        # Choose a time to inject the exfiltration
        base_time = base_events[0]['timestamp']
        exfil_start = base_time + timedelta(minutes=np.random.randint(0, 120))
        
        # Generate multiple file read events with high data output
        exfil_events = []
        session_id = f"exfil_session_{str(uuid.uuid4())[:8]}"
        
        # Generate 10-30 file read events with high data output
        num_files = np.random.randint(10, 31)
        current_time = exfil_start
        
        for i in range(num_files):
            exfil_events.append({
                "timestamp": current_time,
                "actor_id": user_id,
                "actor_role": "normal_user",
                "session_id": session_id,
                "action_type": "file_read",
                "resource_id": f"confidential_file_{np.random.randint(10000, 99999)}",
                "resource_sensitivity": 3,  # High sensitivity
                "result": "success",
                "latency_ms": np.random.normal(500, 100),  # Slower due to large files
                "bytes_in": np.random.normal(100, 50),
                "bytes_out": np.random.normal(5000000, 1000000),  # Large data output
                "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "device_id": f"exfil_device_{np.random.randint(1000, 9999)}",
                "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL'])}",
                "ground_truth_is_anomaly": True,
                "scenario_tag": self.name
            })
            
            # Time between file reads (quick succession)
            current_time += timedelta(seconds=np.random.uniform(1, 10))
        
        # Combine original events with exfiltration events
        all_events = base_events + exfil_events
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


class PrivilegeEscalationScenario(AnomalyScenario):
    """Simulate privilege escalation - user attempting unauthorized admin actions"""
    
    def __init__(self):
        super().__init__("privilege_escalation", "User attempting unauthorized admin actions")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        if not base_events:
            return base_events
        
        # Choose a time to inject the escalation
        base_time = base_events[0]['timestamp']
        escalation_start = base_time + timedelta(minutes=np.random.randint(0, 120))
        
        # Generate admin-level actions by a non-admin user
        escalation_events = []
        session_id = f"escalation_session_{str(uuid.uuid4())[:8]}"
        
        # Generate 3-10 unauthorized admin actions
        num_actions = np.random.randint(3, 11)
        current_time = escalation_start
        
        for i in range(num_actions):
            escalation_events.append({
                "timestamp": current_time,
                "actor_id": user_id,
                "actor_role": "normal_user",  # Normal user attempting admin action
                "session_id": session_id,
                "action_type": np.random.choice(["admin_action", "privilege_change"]),
                "resource_id": f"admin_resource_{np.random.randint(1000, 9999)}",
                "resource_sensitivity": 3,  # High sensitivity
                "result": np.random.choice(["success", "fail"], p=[0.1, 0.9]),  # Usually fails
                "latency_ms": np.random.normal(200, 50),
                "bytes_in": np.random.normal(500, 200),
                "bytes_out": np.random.normal(800, 300),
                "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "device_id": f"escalation_device_{np.random.randint(1000, 9999)}",
                "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL'])}",
                "ground_truth_is_anomaly": True,
                "scenario_tag": self.name
            })
            
            # Time between admin actions
            current_time += timedelta(minutes=np.random.uniform(0.5, 5.0))
        
        # Combine original events with escalation events
        all_events = base_events + escalation_events
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


class ResourceAbuseSpikeScenario(AnomalyScenario):
    """Simulate resource abuse - sudden spike in API calls or resource usage"""
    
    def __init__(self):
        super().__init__("resource_abuse_spike", "Sudden spike in API calls or resource usage")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        if not base_events:
            return base_events
        
        # Choose a time to inject the abuse
        base_time = base_events[0]['timestamp']
        abuse_start = base_time + timedelta(minutes=np.random.randint(0, 120))
        
        # Generate a spike of API calls
        abuse_events = []
        session_id = f"abuse_session_{str(uuid.uuid4())[:8]}"
        
        # Generate 50-200 API calls in a short time window
        num_calls = np.random.randint(50, 201)
        current_time = abuse_start
        
        for i in range(num_calls):
            abuse_events.append({
                "timestamp": current_time,
                "actor_id": user_id,
                "actor_role": "normal_user",
                "session_id": session_id,
                "action_type": "api_call",
                "resource_id": f"api_endpoint_{np.random.randint(100, 999)}",
                "resource_sensitivity": np.random.choice([0, 1], p=[0.7, 0.3]),  # Mostly low sensitivity
                "result": "success",
                "latency_ms": np.random.normal(50, 15),  # Fast due to automation
                "bytes_in": np.random.normal(200, 80),
                "bytes_out": np.random.normal(400, 150),
                "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "device_id": f"abuse_device_{np.random.randint(1000, 9999)}",
                "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL'])}",
                "ground_truth_is_anomaly": True,
                "scenario_tag": self.name
            })
            
            # Very short time between API calls (automated)
            current_time += timedelta(milliseconds=np.random.uniform(10, 100))
        
        # Combine original events with abuse events
        all_events = base_events + abuse_events
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


class LateralMovementScenario(AnomalyScenario):
    """Simulate lateral movement - user accessing unusual resources"""
    
    def __init__(self):
        super().__init__("lateral_movement", "User accessing resources outside their normal scope")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        if not base_events:
            return base_events
        
        # Choose a time to inject the lateral movement
        base_time = base_events[0]['timestamp']
        movement_start = base_time + timedelta(minutes=np.random.randint(0, 120))
        
        # Generate access to sensitive resources by a user who normally doesn't access them
        movement_events = []
        session_id = f"lateral_session_{str(uuid.uuid4())[:8]}"
        
        # Generate 5-15 accesses to unusual resources
        num_accesses = np.random.randint(5, 16)
        current_time = movement_start
        
        for i in range(num_accesses):
            movement_events.append({
                "timestamp": current_time,
                "actor_id": user_id,
                "actor_role": "normal_user",  # Normal user accessing sensitive resources
                "session_id": session_id,
                "action_type": np.random.choice(["file_read", "file_write", "api_call"]),
                "resource_id": f"sensitive_resource_{np.random.randint(10000, 99999)}",
                "resource_sensitivity": 3,  # High sensitivity
                "result": "success",
                "latency_ms": np.random.normal(150, 40),
                "bytes_in": np.random.normal(600, 250),
                "bytes_out": np.random.normal(900, 350),
                "ip": f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",  # Internal IP
                "device_id": f"lateral_device_{np.random.randint(1000, 9999)}",
                "geo": "US-DC",  # Data center
                "ground_truth_is_anomaly": True,
                "scenario_tag": self.name
            })
            
            # Time between accesses
            current_time += timedelta(minutes=np.random.uniform(1, 10))
        
        # Combine original events with movement events
        all_events = base_events + movement_events
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


class InsiderSensitiveSweepScenario(AnomalyScenario):
    """Simulate insider threat - user systematically accessing sensitive data"""
    
    def __init__(self):
        super().__init__("insider_sensitive_sweep", "User systematically accessing sensitive data over time")
    
    def inject_anomaly(self, base_events: List[Dict[str, Any]], user_id: str) -> List[Dict[str, Any]]:
        if not base_events:
            return base_events
        
        # Choose a time to start the systematic access
        base_time = base_events[0]['timestamp']
        sweep_start = base_time + timedelta(minutes=np.random.randint(0, 120))
        
        # Generate systematic access to sensitive resources over time
        sweep_events = []
        session_id = f"insider_session_{str(uuid.uuid4())[:8]}"
        
        # Generate 20-50 accesses to sensitive resources over several hours
        num_accesses = np.random.randint(20, 51)
        current_time = sweep_start
        
        for i in range(num_accesses):
            sweep_events.append({
                "timestamp": current_time,
                "actor_id": user_id,
                "actor_role": "normal_user",  # Normal user accessing sensitive data
                "session_id": session_id,
                "action_type": np.random.choice(["file_read", "file_write"]),
                "resource_id": f"confidential_data_{np.random.randint(100000, 999999)}",
                "resource_sensitivity": 3,  # High sensitivity
                "result": "success",
                "latency_ms": np.random.normal(300, 100),  # Slower due to large sensitive files
                "bytes_in": np.random.normal(800, 300),
                "bytes_out": np.random.normal(1200000, 400000),  # Large data output
                "ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "device_id": f"insider_device_{np.random.randint(1000, 9999)}",
                "geo": f"US-{np.random.choice(['CA', 'NY', 'TX', 'FL'])}",
                "ground_truth_is_anomaly": True,
                "scenario_tag": self.name
            })
            
            # Time between accesses (spaced out to look normal)
            current_time += timedelta(minutes=np.random.uniform(30, 120))
        
        # Combine original events with sweep events
        all_events = base_events + sweep_events
        all_events.sort(key=lambda x: x['timestamp'])
        
        return all_events


def get_all_scenarios() -> List[AnomalyScenario]:
    """Get all available anomaly scenarios"""
    return [
        BruteForceLoginScenario(),
        CredentialStuffingScenario(),
        ImpossibleTravelScenario(),
        DataExfiltrationScenario(),
        PrivilegeEscalationScenario(),
        ResourceAbuseSpikeScenario(),
        LateralMovementScenario(),
        InsiderSensitiveSweepScenario()
    ]


def inject_scenario(
    base_events: List[Dict[str, Any]], 
    scenario: AnomalyScenario, 
    user_id: str
) -> List[Dict[str, Any]]:
    """Inject a specific scenario into base events"""
    return scenario.inject_anomaly(base_events, user_id)