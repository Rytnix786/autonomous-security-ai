from typing import List, Dict, Any
from datetime import datetime
import numpy as np
from ..core.schemas import FeatureWindow
from ..model.anomaly_model import AnomalyModel, train_model_main
from ..model.versioning import ModelVersionManager
from ..core.logger import logger
from .tuner import ThresholdTuner


class ModelRetrainer:
    """Handle automatic retraining of models based on feedback"""
    
    def __init__(self, config):
        self.config = config
        self.tuner = ThresholdTuner(config)
        self.version_manager = ModelVersionManager()
        self.last_retrain_time = None
    
    def should_retrain(self) -> bool:
        """Determine if model should be retrained"""
        # Check if enough time has passed since last retrain
        if self.last_retrain_time:
            time_since_retrain = datetime.now() - self.last_retrain_time
            if (time_since_retrain.total_seconds() / 60) < self.config.feedback.retrain_interval_minutes:
                return False
        
        # Check if we have enough feedback
        return self.tuner.should_retrain()
    
    def retrain_model(self, feature_windows: List[FeatureWindow], 
                     current_model_path: str = "models/anomaly_model.joblib") -> bool:
        """Retrain the model with updated data"""
        if not self.should_retrain():
            logger.info("Model retraining not required at this time")
            return False
        
        logger.info("Starting model retraining process...")
        
        try:
            # Create a backup of the current model
            backup_version = self.version_manager.create_version(
                current_model_path,
                version_name=f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                metadata={"type": "backup", "reason": "before_retrain"}
            )
            logger.info(f"Created backup version: {backup_version}")
            
            # Train the new model
            model, training_meta = train_model_main(
                self.config,
                feature_windows,
                current_model_path
            )
            
            # Create a new version for the retrained model
            new_version = self.version_manager.create_version(
                current_model_path,
                version_name=f"retrained_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                metadata={
                    "type": "retrained",
                    "samples_used": len(feature_windows),
                    "training_timestamp": datetime.now().isoformat(),
                    "training_meta": training_meta
                }
            )
            
            logger.info(f"Model retrained successfully. New version: {new_version}")
            self.last_retrain_time = datetime.now()
            
            return True
            
        except Exception as e:
            logger.error(f"Error during model retraining: {e}")
            # Try to restore from backup if available
            try:
                latest_backup = self.version_manager.get_latest_version()
                if latest_backup and "backup" in latest_backup:
                    self.version_manager.rollback_to_version(latest_backup, current_model_path)
                    logger.info(f"Rolled back to backup version: {latest_backup}")
            except Exception as rollback_error:
                logger.error(f"Failed to rollback after retraining error: {rollback_error}")
            
            return False
    
    def adaptive_retrain(self, feature_windows: List[FeatureWindow], 
                        current_model_path: str = "models/anomaly_model.joblib") -> Dict[str, Any]:
        """Perform adaptive retraining based on feedback"""
        result = {
            "retrained": False,
            "should_retrain": self.should_retrain(),
            "feedback_metrics": self.tuner.calculate_performance_metrics(),
            "action_taken": "none"
        }
        
        if result["should_retrain"]:
            success = self.retrain_model(feature_windows, current_model_path)
            result["retrained"] = success
            result["action_taken"] = "retrained" if success else "failed"
        else:
            # Even if not retraining, we might want to adjust thresholds
            threshold_adjustment = self.tuner.get_adaptation_recommendation()
            if threshold_adjustment.get("threshold_adjustments"):
                result["threshold_adjustments"] = threshold_adjustment["threshold_adjustments"]
                result["action_taken"] = "threshold_adjustment"
        
        return result


def retrain_model_main(config, feature_windows: List[FeatureWindow], 
                      model_path: str = "models/anomaly_model.joblib") -> Dict[str, Any]:
    """Main function to handle model retraining"""
    retrainer = ModelRetrainer(config)
    return retrainer.adaptive_retrain(feature_windows, model_path)