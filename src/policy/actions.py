from typing import Dict, Any, List
from datetime import datetime, timedelta
from enum import Enum
from ..core.schemas import Action
from ..core.logger import logger


class ActionExecutor:
    """Execute security actions in the system"""
    
    def __init__(self):
        # In-memory state for tracking active actions
        self.active_restrictions = {}  # {actor_id: {action_type: expiration_time}}
        self.account_locks = {}  # {actor_id: expiration_time}
        self.session_quarantines = {}  # {session_id: expiration_time}
        self.rate_limits = {}  # {actor_id: (request_count, reset_time)}
    
    def execute_action(self, action: Action) -> bool:
        """Execute a security action"""
        action_type = action.action_type
        actor_id = action.actor_id
        
        logger.info(f"Executing action {action_type} for actor {actor_id}")
        
        try:
            if action_type == "ALLOW":
                return self._allow_access(actor_id)
            elif action_type == "ALERT":
                return self._issue_alert(action)
            elif action_type == "STEP_UP_AUTH":
                return self._require_step_up_auth(actor_id)
            elif action_type == "RATE_LIMIT":
                return self._apply_rate_limit(actor_id)
            elif action_type == "RESTRICT":
                return self._apply_restriction(actor_id)
            elif action_type == "LOCK":
                return self._lock_account(actor_id, action.duration_minutes)
            elif action_type == "QUARANTINE":
                return self._quarantine_session(actor_id, action.duration_minutes)
            else:
                logger.warning(f"Unknown action type: {action_type}")
                return False
        except Exception as e:
            logger.error(f"Error executing action {action_type} for {actor_id}: {e}")
            return False
    
    def _allow_access(self, actor_id: str) -> bool:
        """Allow access (no action needed)"""
        logger.debug(f"Allowing access for {actor_id}")
        return True
    
    def _issue_alert(self, action: Action) -> bool:
        """Issue an alert (log for review)"""
        logger.warning(f"ALERT: {action.rationale}")
        return True
    
    def _require_step_up_auth(self, actor_id: str) -> bool:
        """Require additional authentication"""
        # In a real system, this would trigger MFA or similar
        logger.info(f"Step-up authentication required for {actor_id}")
        return True
    
    def _apply_rate_limit(self, actor_id: str) -> bool:
        """Apply rate limiting to an actor"""
        # Set a default rate limit (e.g., 10 requests per minute)
        reset_time = datetime.now() + timedelta(minutes=1)
        self.rate_limits[actor_id] = (0, reset_time)
        logger.info(f"Applied rate limiting for {actor_id}")
        return True
    
    def _apply_restriction(self, actor_id: str) -> bool:
        """Apply access restrictions to an actor"""
        # Apply a temporary restriction
        expiration = datetime.now() + timedelta(minutes=30)  # Default 30 minutes
        if actor_id not in self.active_restrictions:
            self.active_restrictions[actor_id] = {}
        self.active_restrictions[actor_id]["RESTRICT"] = expiration
        
        logger.info(f"Applied access restrictions for {actor_id}")
        return True
    
    def _lock_account(self, actor_id: str, duration_minutes: int = 60) -> bool:
        """Lock an account"""
        if duration_minutes is None:
            duration_minutes = 60  # Default 1 hour
        
        expiration = datetime.now() + timedelta(minutes=duration_minutes)
        self.account_locks[actor_id] = expiration
        
        logger.warning(f"Locked account for {actor_id} until {expiration}")
        return True
    
    def _quarantine_session(self, actor_id: str, duration_minutes: int = 120) -> bool:
        """Quarantine a session"""
        if duration_minutes is None:
            duration_minutes = 120  # Default 2 hours
        
        # In a real system, this would isolate the session
        expiration = datetime.now() + timedelta(minutes=duration_minutes)
        # For now, we'll use actor_id as a proxy for session tracking
        self.session_quarantines[actor_id] = expiration
        
        logger.warning(f"Quarantined session for {actor_id} until {expiration}")
        return True
    
    def is_action_active(self, actor_id: str, action_type: str) -> bool:
        """Check if a specific action is currently active for an actor"""
        if action_type == "LOCK":
            if actor_id in self.account_locks:
                if datetime.now() < self.account_locks[actor_id]:
                    return True
                else:
                    # Clean up expired lock
                    del self.account_locks[actor_id]
                    return False
        elif action_type == "QUARANTINE":
            if actor_id in self.session_quarantines:
                if datetime.now() < self.session_quarantines[actor_id]:
                    return True
                else:
                    # Clean up expired quarantine
                    del self.session_quarantines[actor_id]
                    return False
        elif action_type in ["RESTRICT", "RATE_LIMIT"]:
            if actor_id in self.active_restrictions:
                if action_type in self.active_restrictions[actor_id]:
                    if datetime.now() < self.active_restrictions[actor_id][action_type]:
                        return True
                    else:
                        # Clean up expired restriction
                        del self.active_restrictions[actor_id][action_type]
                        if not self.active_restrictions[actor_id]:
                            del self.active_restrictions[actor_id]
                        return False
        
        return False
    
    def cleanup_expired_actions(self) -> None:
        """Clean up any expired actions"""
        now = datetime.now()
        
        # Clean up account locks
        expired_locks = []
        for actor_id, expiration in self.account_locks.items():
            if now >= expiration:
                expired_locks.append(actor_id)
        for actor_id in expired_locks:
            del self.account_locks[actor_id]
            logger.info(f"Expired lock for {actor_id}")
        
        # Clean up session quarantines
        expired_quarantines = []
        for actor_id, expiration in self.session_quarantines.items():
            if now >= expiration:
                expired_quarantines.append(actor_id)
        for actor_id in expired_quarantines:
            del self.session_quarantines[actor_id]
            logger.info(f"Expired quarantine for {actor_id}")
        
        # Clean up restrictions
        expired_restrictions = []
        for actor_id, restrictions in self.active_restrictions.items():
            for action_type, expiration in list(restrictions.items()):
                if now >= expiration:
                    expired_restrictions.append((actor_id, action_type))
        
        for actor_id, action_type in expired_restrictions:
            if actor_id in self.active_restrictions:
                if action_type in self.active_restrictions[actor_id]:
                    del self.active_restrictions[actor_id][action_type]
                    if not self.active_restrictions[actor_id]:
                        del self.active_restrictions[actor_id]
                    logger.info(f"Expired restriction {action_type} for {actor_id}")


class ActionManager:
    """Manage security actions"""
    
    def __init__(self):
        self.executor = ActionExecutor()
    
    def apply_action(self, action: Action) -> bool:
        """Apply a security action"""
        success = self.executor.execute_action(action)
        return success
    
    def check_active_actions(self, actor_id: str) -> List[str]:
        """Check what actions are currently active for an actor"""
        active_actions = []
        
        for action_type in ["LOCK", "QUARANTINE", "RESTRICT", "RATE_LIMIT"]:
            if self.executor.is_action_active(actor_id, action_type):
                active_actions.append(action_type)
        
        return active_actions
    
    def cleanup(self) -> None:
        """Clean up expired actions"""
        self.executor.cleanup_expired_actions()


def execute_action_main(action: Action) -> bool:
    """Main function to execute a security action"""
    executor = ActionExecutor()
    return executor.execute_action(action)