from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from enum import Enum
from ..core.schemas import Event, Incident, Action
from ..core.logger import logger


class SecurityAction(Enum):
    """Security actions that can be taken"""
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    RATE_LIMIT = "RATE_LIMIT"
    RESTRICT = "RESTRICT"
    LOCK = "LOCK"
    QUARANTINE = "QUARANTINE"


class DecisionEngine:
    """Policy engine that decides security actions based on risk scores and context"""
    
    def __init__(self, config):
        self.config = config
        self.action_cooldowns = {}  # Track when actions were taken
    
    def make_decision(self, 
                     risk_score: float, 
                     event_context: Dict[str, Any], 
                     actor_role: str) -> Dict[str, Any]:
        """Make a security decision based on risk score and context"""
        
        # Determine action based on risk score thresholds
        action = self._determine_action_from_risk(risk_score, actor_role)
        
        # Check cooldowns to prevent repeated actions
        actor_id = event_context.get('actor_id', 'unknown')
        if self._is_on_cooldown(actor_id, action):
            # If on cooldown, step down to a less severe action
            action = self._get_reduced_action(action, actor_role)
        
        # Create rationale for the decision
        rationale = self._create_rationale(risk_score, action, event_context, actor_role)
        
        # Record action in cooldown tracking
        self._record_action(actor_id, action)
        
        return {
            "action": action.value,
            "rationale": rationale,
            "risk_score": risk_score,
            "actor_id": actor_id
        }
    
    def _determine_action_from_risk(self, risk_score: float, actor_role: str) -> SecurityAction:
        """Determine action based on risk score thresholds"""
        thresholds = self.config.policy.risk_thresholds
        
        if risk_score <= thresholds["allow"]:
            return SecurityAction.ALLOW
        elif risk_score <= thresholds["alert"]:
            return SecurityAction.ALERT
        elif risk_score <= thresholds["step_up_auth"]:
            return SecurityAction.STEP_UP_AUTH
        elif risk_score <= thresholds["rate_limit"]:
            return SecurityAction.RATE_LIMIT
        elif risk_score <= thresholds["restrict"]:
            return SecurityAction.RESTRICT
        elif risk_score <= thresholds["lock"]:
            return SecurityAction.LOCK
        elif risk_score <= thresholds["quarantine"]:
            return SecurityAction.LOCK
        else:
            return SecurityAction.QUARANTINE
    
    def _is_on_cooldown(self, actor_id: str, action: SecurityAction) -> bool:
        """Check if an action is on cooldown for an actor"""
        if actor_id not in self.action_cooldowns:
            return False
        
        action_str = action.value
        if action_str not in self.action_cooldowns[actor_id]:
            return False
        
        last_action_time, duration_minutes = self.action_cooldowns[actor_id][action_str]
        cooldown_duration = timedelta(minutes=duration_minutes)
        time_since_action = datetime.now() - last_action_time
        
        return time_since_action < cooldown_duration
    
    def _record_action(self, actor_id: str, action: SecurityAction) -> None:
        """Record that an action was taken for cooldown tracking"""
        if actor_id not in self.action_cooldowns:
            self.action_cooldowns[actor_id] = {}
        
        action_str = action.value
        duration_minutes = self.config.policy.cooldowns.get(
            action_str.lower().replace('_', ''), 60  # default 60 minutes
        )
        
        self.action_cooldowns[actor_id][action_str] = (datetime.now(), duration_minutes)
    
    def _get_reduced_action(self, original_action: SecurityAction, actor_role: str) -> SecurityAction:
        """Get a less severe action when on cooldown"""
        action_hierarchy = [
            SecurityAction.ALLOW,
            SecurityAction.ALERT,
            SecurityAction.STEP_UP_AUTH,
            SecurityAction.RATE_LIMIT,
            SecurityAction.RESTRICT,
            SecurityAction.LOCK,
            SecurityAction.QUARANTINE
        ]
        
        current_index = action_hierarchy.index(original_action)
        if current_index > 0:
            # Step down to less severe action
            return action_hierarchy[current_index - 1]
        else:
            # If already at lowest level, stay at current level but extend cooldown
            return original_action
    
    def _create_rationale(self, risk_score: float, action: SecurityAction, 
                         event_context: Dict[str, Any], actor_role: str) -> str:
        """Create a human-readable rationale for the decision"""
        base_rationale = f"Risk score of {risk_score:.2f} triggered action '{action.value}'"
        
        # Add context-specific rationale
        if action == SecurityAction.ALERT:
            return f"{base_rationale}. Suspicious activity detected, issuing alert for review."
        elif action == SecurityAction.STEP_UP_AUTH:
            return f"{base_rationale}. Requiring additional authentication for user '{event_context.get('actor_id', 'unknown')}'."
        elif action == SecurityAction.RATE_LIMIT:
            return f"{base_rationale}. Applying rate limiting to user '{event_context.get('actor_id', 'unknown')}' to prevent abuse."
        elif action == SecurityAction.RESTRICT:
            return f"{base_rationale}. Restricting access for user '{event_context.get('actor_id', 'unknown')}' due to suspicious behavior."
        elif action == SecurityAction.LOCK:
            return f"{base_rationale}. Locking account for user '{event_context.get('actor_id', 'unknown')}' due to high-risk activity."
        elif action == SecurityAction.QUARANTINE:
            return f"{base_rationale}. Quarantining session for user '{event_context.get('actor_id', 'unknown')}' due to extreme risk."
        else:  # ALLOW
            return f"{base_rationale}. Activity appears normal, allowing access."
    
    def process_event(self, event: Event, risk_score: float) -> Optional[Action]:
        """Process an event and return the appropriate action"""
        # Create context from event
        event_context = {
            "actor_id": event.actor_id,
            "actor_role": event.actor_role,
            "action_type": event.action_type,
            "resource_id": event.resource_id,
            "resource_sensitivity": event.resource_sensitivity,
            "ip": event.ip,
            "device_id": event.device_id,
            "geo": event.geo
        }
        
        # Make decision
        decision = self.make_decision(risk_score, event_context, event.actor_role)
        
        # Create Action object if action is not ALLOW
        if decision["action"] != SecurityAction.ALLOW.value:
            action = Action(
                incident_id=f"inc_{event.event_id[:8]}",  # Create incident ID based on event
                action_type=decision["action"],
                timestamp=datetime.now(),
                rationale=decision["rationale"],
                actor_id=event.actor_id
            )
            return action
        
        return None  # No action needed for ALLOW


class PolicyEngine:
    """Main policy engine that orchestrates decision making"""
    
    def __init__(self, config):
        self.config = config
        self.decision_engine = DecisionEngine(config)
    
    def evaluate_incident(self, 
                         risk_score: float, 
                         events: List[Event], 
                         top_features: List[str],
                         explanation: str) -> Incident:
        """Evaluate an incident and create an Incident object"""
        if not events:
            raise ValueError("Events list cannot be empty")
        
        # Get the primary event for context
        primary_event = events[0]
        
        # Make a decision based on the risk score
        event_context = {
            "actor_id": primary_event.actor_id,
            "actor_role": primary_event.actor_role,
            "action_type": primary_event.action_type,
            "resource_id": primary_event.resource_id,
            "resource_sensitivity": primary_event.resource_sensitivity,
            "ip": primary_event.ip,
            "device_id": primary_event.device_id,
            "geo": primary_event.geo
        }
        
        decision = self.decision_engine.make_decision(
            risk_score, 
            event_context, 
            primary_event.actor_role
        )
        
        # Create incident
        incident = Incident(
            event_ids=[event.event_id for event in events],
            timestamp=datetime.now(),
            actor_id=primary_event.actor_id,
            risk_score=risk_score,
            explanation=explanation,
            action_taken=decision["action"],
            top_features=top_features
        )
        
        return incident


def make_decision_main(config, risk_score: float, event_context: Dict[str, Any], actor_role: str) -> Dict[str, Any]:
    """Main function to make a security decision"""
    engine = DecisionEngine(config)
    return engine.make_decision(risk_score, event_context, actor_role)