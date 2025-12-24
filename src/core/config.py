from pydantic import BaseModel
from typing import Optional
import yaml
import os
from pathlib import Path


class SimulatorConfig(BaseModel):
    user_count: int = 50
    days: int = 7
    anomaly_rate: float = 0.05
    window_size_minutes: int = 5


class FeaturesConfig(BaseModel):
    rolling_window_minutes: int = 5
    session_timeout_minutes: int = 30


class ModelConfig(BaseModel):
    contamination: float = 0.05
    random_state: int = 42
    min_samples_for_training: int = 100


class PolicyConfig(BaseModel):
    risk_thresholds: dict = {
        "allow": 20,
        "alert": 40,
        "step_up_auth": 60,
        "rate_limit": 75,
        "restrict": 90,
        "lock": 90,
        "quarantine": 95
    }
    cooldowns: dict = {
        "step_up_auth": 5,
        "rate_limit": 15,
        "restrict": 30,
        "lock": 60,
        "quarantine": 120
    }


class FeedbackConfig(BaseModel):
    min_feedback_for_retrain: int = 10
    retrain_interval_minutes: int = 1440  # 24 hours
    fp_threshold_for_retrain: float = 0.15  # 15% false positive rate


class StorageConfig(BaseModel):
    max_incidents: int = 1000
    max_feedback: int = 500


class SecurityAIConfig(BaseModel):
    simulator: SimulatorConfig = SimulatorConfig()
    features: FeaturesConfig = FeaturesConfig()
    model: ModelConfig = ModelConfig()
    policy: PolicyConfig = PolicyConfig()
    feedback: FeedbackConfig = FeedbackConfig()
    storage: StorageConfig = StorageConfig()


def load_config(config_path: Optional[str] = None) -> SecurityAIConfig:
    """
    Load configuration from YAML file
    """
    if config_path is None:
        # Look for config.yaml in the project root
        config_path = Path(__file__).parent.parent.parent / "config.yaml"
    
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        yaml_config = yaml.safe_load(f)
    
    return SecurityAIConfig(**yaml_config)