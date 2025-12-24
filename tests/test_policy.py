import pytest
from datetime import datetime, timedelta
from src.policy.decision_engine import DecisionEngine, PolicyEngine
from src.policy.actions import ActionExecutor, ActionManager
from src.core.config import SecurityAIConfig
from src.core.schemas import Event, Incident


class TestDecisionEngine:
    """Test decision engine functionality"""
    
    def setup_method(self):
        """Setup test configuration"""
        self.config = SecurityAIConfig()
        self.engine = DecisionEngine(self.config)
    
    def test_determine_action_from_risk_low_risk(self):
        """Test action determination for low risk score"""
        action = self.engine._determine_action_from_risk(10, "normal_user")
        assert action.value == "ALLOW"
    
    def test_determine_action_from_risk_medium_risk(self):
        """Test action determination for medium risk score"""
        action = self.engine._determine_action_from_risk(50, "normal_user")
        assert action.value == "STEP_UP_AUTH"
    
    def test_determine_action_from_risk_high_risk(self):
        """Test action determination for high risk score"""
        action = self.engine._determine_action_from_risk(95, "normal_user")
        assert action.value == "LOCK"  # Risk score 95 should trigger LOCK, not QUARANTINE (which requires > 95)
    
    def test_make_decision_low_risk(self):
        """Test making decision for low risk"""
        event_context = {
            "actor_id": "test_user",
            "actor_role": "normal_user",
            "action_type": "api_call",
            "resource_id": "resource_123",
            "resource_sensitivity": 1,
            "ip": "192.168.1.1",
            "device_id": "device_123",
            "geo": "US-CA"
        }
        
        decision = self.engine.make_decision(15, event_context, "normal_user")
        assert decision["action"] == "ALLOW"
        assert decision["risk_score"] == 15
        assert decision["actor_id"] == "test_user"
    
    def test_make_decision_high_risk(self):
        """Test making decision for high risk"""
        event_context = {
            "actor_id": "test_user",
            "actor_role": "normal_user",
            "action_type": "api_call",
            "resource_id": "resource_123",
            "resource_sensitivity": 3,
            "ip": "203.0.113.1",
            "device_id": "device_999",
            "geo": "XX-XX"
        }
        
        decision = self.engine.make_decision(95, event_context, "normal_user")
        assert decision["action"] == "LOCK"  # Risk score 95 should trigger LOCK (>90 and <=95)
        assert decision["risk_score"] == 95
        assert decision["actor_id"] == "test_user"


class TestActionExecutor:
    """Test action execution functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.executor = ActionExecutor()
    
    def test_allow_action(self):
        """Test allow action execution"""
        result = self.executor._allow_access("test_user")
        assert result is True
    
    def test_rate_limit_action(self):
        """Test rate limit action execution"""
        result = self.executor._apply_rate_limit("test_user")
        assert result is True
        assert "test_user" in self.executor.rate_limits
    
    def test_lock_account_action(self):
        """Test lock account action execution"""
        result = self.executor._lock_account("test_user", 30)
        assert result is True
        assert "test_user" in self.executor.account_locks
    
    def test_is_action_active_lock(self):
        """Test checking if lock action is active"""
        # Set up a lock that expires in the future
        from datetime import datetime, timedelta
        future_time = datetime.now() + timedelta(minutes=30)
        self.executor.account_locks["test_user"] = future_time
        
        is_active = self.executor.is_action_active("test_user", "LOCK")
        assert is_active is True
    
    def test_is_action_active_expired(self):
        """Test checking if expired action is active"""
        # Set up a lock that expired in the past
        past_time = datetime.now() - timedelta(minutes=30)
        self.executor.account_locks["test_user"] = past_time
        
        is_active = self.executor.is_action_active("test_user", "LOCK")
        assert is_active is False


class TestPolicyEngine:
    """Test policy engine functionality"""
    
    def setup_method(self):
        """Setup test configuration"""
        self.config = SecurityAIConfig()
        self.policy_engine = PolicyEngine(self.config)
    
    def test_evaluate_incident_low_risk(self):
        """Test evaluating low risk incident"""
        event = Event(
            timestamp=datetime.now(),
            actor_id="test_user",
            actor_role="normal_user",
            session_id="session_123",
            action_type="api_call",
            resource_id="resource_123",
            resource_sensitivity=1,
            result="success",
            latency_ms=100.0,
            bytes_in=200,
            bytes_out=300,
            ip="192.168.1.1",
            device_id="device_123",
            geo="US-CA",
            ground_truth_is_anomaly=False,
            scenario_tag="normal"
        )
        
        incident = self.policy_engine.evaluate_incident(
            risk_score=20,
            events=[event],
            top_features=["events_per_min", "bytes_out_rate"],
            explanation="Normal activity"
        )
        
        assert incident.actor_id == "test_user"
        assert incident.risk_score == 20
        assert incident.explanation == "Normal activity"
        assert incident.action_taken in ["ALLOW", "ALERT"]  # Low risk action
    
    def test_evaluate_incident_high_risk(self):
        """Test evaluating high risk incident"""
        event = Event(
            timestamp=datetime.now(),
            actor_id="test_user",
            actor_role="normal_user",
            session_id="session_123",
            action_type="api_call",
            resource_id="resource_123",
            resource_sensitivity=3,
            result="success",
            latency_ms=100.0,
            bytes_in=200,
            bytes_out=3000000,  # High data output
            ip="203.0.113.1",
            device_id="device_999",
            geo="XX-XX",
            ground_truth_is_anomaly=True,
            scenario_tag="data_exfiltration"
        )
        
        incident = self.policy_engine.evaluate_incident(
            risk_score=90,
            events=[event],
            top_features=["bytes_out_total", "new_ip_flag"],
            explanation="High data exfiltration detected"
        )
        
        assert incident.actor_id == "test_user"
        assert incident.risk_score == 90
        assert "exfiltration" in incident.explanation
        assert incident.action_taken == "RESTRICT"  # Risk score 90 should trigger RESTRICT (75 < 90 <= 90)