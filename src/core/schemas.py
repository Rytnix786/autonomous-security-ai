from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import datetime
import uuid


class Event(BaseModel):
    """Schema for security events"""
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    actor_id: str
    actor_role: str
    session_id: str
    action_type: str
    resource_id: str
    resource_sensitivity: int = Field(ge=0, le=3)  # 0-3 scale
    result: str  # success/fail
    latency_ms: float
    bytes_in: float
    bytes_out: float
    ip: str
    device_id: str
    geo: str
    ground_truth_is_anomaly: bool = False
    scenario_tag: str = "normal"


class FeatureWindow(BaseModel):
    """Schema for feature windows used for model training/prediction"""
    window_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    start_time: datetime
    end_time: datetime
    features: dict  # Dictionary of feature names and values
    actor_id: str
    session_id: str
    is_anomaly: Optional[bool] = None  # For training data


class Incident(BaseModel):
    """Schema for detected incidents"""
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_ids: List[str]
    timestamp: datetime
    actor_id: str
    risk_score: float  # 0-100 scale
    explanation: str
    action_taken: str
    top_features: List[str]
    feedback_status: Literal["unreviewed", "benign", "malicious"] = "unreviewed"


class Action(BaseModel):
    """Schema for security actions"""
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    action_type: str  # ALLOW, ALERT, STEP_UP_AUTH, RATE_LIMIT, RESTRICT, LOCK, QUARANTINE
    timestamp: datetime
    rationale: str
    actor_id: str
    duration_minutes: Optional[int] = None  # For temporary actions


class Feedback(BaseModel):
    """Schema for feedback on incidents"""
    feedback_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    timestamp: datetime
    feedback_type: Literal["benign", "malicious"]
    confidence: float = 1.0  # 0-1 confidence in feedback
    comment: Optional[str] = None
    user_id: str