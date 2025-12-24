from typing import Dict, Any, List
from datetime import datetime, timedelta
import numpy as np
from ..core.logger import logger
from .feedback_store import FeedbackStore


class ThresholdTuner:
    """Tune model thresholds based on feedback"""
    
    def __init__(self, config):
        self.config = config
        self.feedback_store = FeedbackStore()
    
    def calculate_performance_metrics(self) -> Dict[str, float]:
        """Calculate performance metrics based on feedback"""
        feedback_list = self.feedback_store.get_all_feedback()
        
        if not feedback_list:
            return {
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "total_feedback": 0
            }
        
        # Count false positives (benign events marked as anomalous)
        false_positives = sum(1 for fb in feedback_list if fb.feedback_type == "benign")
        
        # For false negatives, we'd need to know which events were NOT flagged but should have been
        # This is more complex and would require additional tracking
        # For now, we'll focus on false positive rate
        total_benign_marked_anomalous = len([fb for fb in feedback_list if fb.feedback_type == "benign"])
        total_malicious_marked_anomalous = len([fb for fb in feedback_list if fb.feedback_type == "malicious"])
        
        total_feedback = len(feedback_list)
        
        false_positive_rate = total_benign_marked_anomalous / total_feedback if total_feedback > 0 else 0.0
        
        return {
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": 0.0,  # Placeholder - would need more complex tracking
            "total_feedback": total_feedback,
            "benign_feedback": total_benign_marked_anomalous,
            "malicious_feedback": total_malicious_marked_anomalous
        }
    
    def should_retrain(self) -> bool:
        """Determine if model should be retrained based on feedback"""
        metrics = self.calculate_performance_metrics()
        
        if metrics["total_feedback"] < self.config.feedback.min_feedback_for_retrain:
            logger.info(f"Not enough feedback for retraining: {metrics['total_feedback']} < {self.config.feedback.min_feedback_for_retrain}")
            return False
        
        if metrics["false_positive_rate"] > self.config.feedback.fp_threshold_for_retrain:
            logger.info(f"Retraining triggered: FPR {metrics['false_positive_rate']:.3f} > threshold {self.config.feedback.fp_threshold_for_retrain}")
            return True
        
        return False
    
    def adjust_thresholds(self, current_config) -> Dict[str, Any]:
        """Adjust thresholds based on feedback"""
        metrics = self.calculate_performance_metrics()
        
        # Create a copy of the current config to modify
        new_config = current_config.copy()
        
        # If we have high false positive rate, we might want to increase thresholds to be less sensitive
        if metrics["false_positive_rate"] > 0.1:  # 10% false positive rate
            # Increase risk thresholds to be less sensitive
            adjustment_factor = 1.1  # Increase thresholds by 10%
            
            for threshold_name in new_config["policy"]["risk_thresholds"]:
                new_config["policy"]["risk_thresholds"][threshold_name] = min(
                    100,  # Cap at 100
                    new_config["policy"]["risk_thresholds"][threshold_name] * adjustment_factor
                )
        
        # If we have low false positive rate but suspect missed anomalies, decrease thresholds
        elif metrics["false_positive_rate"] < 0.02:  # Very low FPR
            # Decrease risk thresholds to be more sensitive
            adjustment_factor = 0.9  # Decrease thresholds by 10%
            
            for threshold_name in new_config["policy"]["risk_thresholds"]:
                new_config["policy"]["risk_thresholds"][threshold_name] = max(
                    0,  # Cap at 0
                    new_config["policy"]["risk_thresholds"][threshold_name] * adjustment_factor
                )
        
        logger.info(f"Thresholds adjusted based on FPR: {metrics['false_positive_rate']:.3f}")
        return new_config
    
    def get_adaptation_recommendation(self) -> Dict[str, Any]:
        """Get recommendations for system adaptation"""
        metrics = self.calculate_performance_metrics()
        
        recommendation = {
            "should_retrain": self.should_retrain(),
            "metrics": metrics,
            "threshold_adjustments": self.adjust_thresholds(self.config.dict()) if metrics["total_feedback"] > 0 else None,
            "retraining_reason": ""
        }
        
        if metrics["false_positive_rate"] > self.config.feedback.fp_threshold_for_retrain:
            recommendation["retraining_reason"] = f"False positive rate {metrics['false_positive_rate']:.3f} exceeds threshold {self.config.feedback.fp_threshold_for_retrain}"
        elif metrics["total_feedback"] >= self.config.feedback.min_feedback_for_retrain:
            recommendation["retraining_reason"] = "Sufficient feedback collected for model improvement"
        
        return recommendation


def tune_thresholds_main(config) -> Dict[str, Any]:
    """Main function to tune thresholds based on feedback"""
    tuner = ThresholdTuner(config)
    return tuner.get_adaptation_recommendation()