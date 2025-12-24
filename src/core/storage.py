import json
import jsonlines
from pathlib import Path
from typing import List, Optional, Iterator, Dict, Any
from datetime import datetime
import sqlite3
import pandas as pd
from .schemas import Event, Incident, Action, Feedback
from .logger import logger


class EventStorage:
    """
    Storage for security events using JSONL format
    """
    
    def __init__(self, data_path: str = "data/raw/logs.jsonl"):
        self.data_path = Path(data_path)
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
    
    def save_events(self, events: List[Event]) -> None:
        """Save events to JSONL file"""
        with jsonlines.open(self.data_path, mode='a') as writer:
            for event in events:
                writer.write(event.model_dump(mode='json'))
    
    def load_events(self) -> List[Event]:
        """Load events from JSONL file"""
        events = []
        if self.data_path.exists():
            with jsonlines.open(self.data_path) as reader:
                for item in reader:
                    events.append(Event(**item))
        return events
    
    def load_events_as_dataframe(self) -> pd.DataFrame:
        """Load events as pandas DataFrame"""
        events = self.load_events()
        if not events:
            return pd.DataFrame()
        
        # Convert to list of dicts then to DataFrame
        event_dicts = [event.model_dump() for event in events]
        df = pd.DataFrame(event_dicts)
        
        # Convert timestamp to datetime
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        return df
    
    def clear_events(self) -> None:
        """Clear all events from storage"""
        if self.data_path.exists():
            self.data_path.unlink()


class IncidentStorage:
    """
    Storage for incidents using JSONL format
    """
    
    def __init__(self, data_path: str = "data/processed/incidents.jsonl"):
        self.data_path = Path(data_path)
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
    
    def save_incident(self, incident: Incident) -> None:
        """Save incident to JSONL file"""
        with jsonlines.open(self.data_path, mode='a') as writer:
            writer.write(incident.model_dump(mode='json'))
    
    def save_incidents(self, incidents: List[Incident]) -> None:
        """Save multiple incidents to JSONL file"""
        with jsonlines.open(self.data_path, mode='a') as writer:
            for incident in incidents:
                writer.write(incident.model_dump(mode='json'))
    
    def load_incidents(self) -> List[Incident]:
        """Load incidents from JSONL file"""
        incidents = []
        if self.data_path.exists():
            with jsonlines.open(self.data_path) as reader:
                for item in reader:
                    incidents.append(Incident(**item))
        return incidents
    
    def update_incident_feedback(self, incident_id: str, feedback_status: str) -> bool:
        """Update feedback status for an incident"""
        all_incidents = self.load_incidents()
        updated = False
        
        # Clear the file and rewrite with updated incident
        if self.data_path.exists():
            self.data_path.unlink()
        
        for incident in all_incidents:
            if incident.incident_id == incident_id:
                incident.feedback_status = feedback_status
                updated = True
            with jsonlines.open(self.data_path, mode='a') as writer:
                writer.write(incident.model_dump(mode='json'))
        
        return updated


class ActionStorage:
    """
    Storage for security actions using JSONL format
    """
    
    def __init__(self, data_path: str = "data/processed/actions.jsonl"):
        self.data_path = Path(data_path)
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
    
    def save_action(self, action: Action) -> None:
        """Save action to JSONL file"""
        with jsonlines.open(self.data_path, mode='a') as writer:
            writer.write(action.model_dump(mode='json'))
    
    def load_actions(self) -> List[Action]:
        """Load actions from JSONL file"""
        actions = []
        if self.data_path.exists():
            with jsonlines.open(self.data_path) as reader:
                for item in reader:
                    actions.append(Action(**item))
        return actions


class FeedbackStorage:
    """
    Storage for feedback using JSONL format
    """
    
    def __init__(self, data_path: str = "data/processed/feedback.jsonl"):
        self.data_path = Path(data_path)
        self.data_path.parent.mkdir(parents=True, exist_ok=True)
    
    def save_feedback(self, feedback: Feedback) -> None:
        """Save feedback to JSONL file"""
        with jsonlines.open(self.data_path, mode='a') as writer:
            writer.write(feedback.model_dump(mode='json'))
    
    def load_feedback(self) -> List[Feedback]:
        """Load feedback from JSONL file"""
        feedback = []
        if self.data_path.exists():
            with jsonlines.open(self.data_path) as reader:
                for item in reader:
                    feedback.append(Feedback(**item))
        return feedback
    
    def get_feedback_for_incident(self, incident_id: str) -> Optional[Feedback]:
        """Get feedback for a specific incident"""
        all_feedback = self.load_feedback()
        for fb in all_feedback:
            if fb.incident_id == incident_id:
                return fb
        return None


class SecurityStorage:
    """
    Main storage class that combines all storage components
    """
    
    def __init__(
        self,
        events_path: str = "data/raw/logs.jsonl",
        incidents_path: str = "data/processed/incidents.jsonl",
        actions_path: str = "data/processed/actions.jsonl",
        feedback_path: str = "data/processed/feedback.jsonl"
    ):
        self.events = EventStorage(events_path)
        self.incidents = IncidentStorage(incidents_path)
        self.actions = ActionStorage(actions_path)
        self.feedback = FeedbackStorage(feedback_path)
    
    def clear_all(self) -> None:
        """Clear all storage"""
        self.events.clear_events()
        if self.incidents.data_path.exists():
            self.incidents.data_path.unlink()
        if self.actions.data_path.exists():
            self.actions.data_path.unlink()
        if self.feedback.data_path.exists():
            self.feedback.data_path.unlink()
    
    def get_storage_stats(self) -> Dict[str, int]:
        """Get statistics about stored data"""
        return {
            "events_count": len(self.events.load_events()),
            "incidents_count": len(self.incidents.load_incidents()),
            "actions_count": len(self.actions.load_actions()),
            "feedback_count": len(self.feedback.load_feedback())
        }