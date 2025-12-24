from typing import List, Dict, Any, Optional
from datetime import datetime
from ..core.schemas import Feedback, Incident
from ..core.storage import FeedbackStorage
from ..core.logger import logger


class FeedbackStore:
    """Store and manage feedback on incidents"""
    
    def __init__(self, storage_path: str = "data/processed/feedback.jsonl"):
        self.storage = FeedbackStorage(storage_path)
        self.max_feedback = 500  # Limit to prevent storage bloat
    
    def submit_feedback(self, feedback: Feedback) -> bool:
        """Submit feedback for an incident"""
        try:
            self.storage.save_feedback(feedback)
            logger.info(f"Feedback submitted for incident {feedback.incident_id}: {feedback.feedback_type}")
            self._enforce_storage_limits()
            return True
        except Exception as e:
            logger.error(f"Error submitting feedback: {e}")
            return False
    
    def get_feedback_for_incident(self, incident_id: str) -> Optional[Feedback]:
        """Get feedback for a specific incident"""
        all_feedback = self.storage.load_feedback()
        for fb in all_feedback:
            if fb.incident_id == incident_id:
                return fb
        return None
    
    def get_all_feedback(self) -> List[Feedback]:
        """Get all stored feedback"""
        return self.storage.load_feedback()
    
    def get_feedback_summary(self) -> Dict[str, Any]:
        """Get summary statistics of feedback"""
        all_feedback = self.get_all_feedback()
        
        if not all_feedback:
            return {
                "total_feedback": 0,
                "benign_count": 0,
                "malicious_count": 0,
                "benign_percentage": 0.0,
                "malicious_percentage": 0.0
            }
        
        benign_count = sum(1 for fb in all_feedback if fb.feedback_type == "benign")
        malicious_count = sum(1 for fb in all_feedback if fb.feedback_type == "malicious")
        
        total = len(all_feedback)
        
        return {
            "total_feedback": total,
            "benign_count": benign_count,
            "malicious_count": malicious_count,
            "benign_percentage": (benign_count / total) * 100 if total > 0 else 0.0,
            "malicious_percentage": (malicious_count / total) * 100 if total > 0 else 0.0
        }
    
    def _enforce_storage_limits(self) -> None:
        """Enforce storage limits by removing old feedback if necessary"""
        all_feedback = self.storage.load_feedback()
        
        if len(all_feedback) > self.max_feedback:
            # Sort by timestamp (oldest first) and remove excess
            sorted_feedback = sorted(all_feedback, key=lambda x: x.timestamp)
            feedback_to_keep = sorted_feedback[-self.max_feedback:]
            
            # Clear and rewrite storage with limited feedback
            if self.storage.data_path.exists():
                self.storage.data_path.unlink()
            
            for fb in feedback_to_keep:
                # Use direct save to avoid recursion
                with open(self.storage.data_path, 'a', encoding='utf-8') as f:
                    import json
                    f.write(json.dumps(fb.model_dump(mode='json')) + '\n')
    
    def mark_incident_reviewed(self, incident: Incident, feedback_type: str, user_id: str, comment: str = None) -> bool:
        """Mark an incident as reviewed with feedback"""
        feedback = Feedback(
            incident_id=incident.incident_id,
            timestamp=datetime.now(),
            feedback_type=feedback_type,
            user_id=user_id,
            comment=comment
        )
        
        return self.submit_feedback(feedback)


def submit_feedback_main(incident_id: str, feedback_type: str, user_id: str, comment: str = None) -> bool:
    """Main function to submit feedback"""
    store = FeedbackStore()
    
    feedback = Feedback(
        incident_id=incident_id,
        timestamp=datetime.now(),
        feedback_type=feedback_type,
        user_id=user_id,
        comment=comment
    )
    
    return store.submit_feedback(feedback)


def get_feedback_summary_main() -> Dict[str, Any]:
    """Main function to get feedback summary"""
    store = FeedbackStore()
    return store.get_feedback_summary()