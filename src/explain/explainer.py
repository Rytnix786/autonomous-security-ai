from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd
from ..core.schemas import FeatureWindow
from ..core.logger import logger


class Explainer:
    """Generate explanations for anomaly detections"""
    
    def __init__(self, config):
        self.config = config
    
    def explain_anomaly(self, 
                       risk_score: float, 
                       features: Dict[str, float], 
                       feature_names: List[str],
                       baseline_features: Dict[str, float] = None) -> Dict[str, Any]:
        """Generate explanation for why an event/window was flagged as anomalous"""
        
        # Identify top deviating features
        top_features = self._get_top_deviating_features(features, baseline_features)
        
        # Generate natural language explanation
        explanation = self._generate_natural_explanation(risk_score, top_features, features)
        
        return {
            "explanation": explanation,
            "top_features": top_features,
            "risk_score": risk_score,
            "feature_contributions": self._calculate_feature_contributions(features, top_features)
        }
    
    def _get_top_deviating_features(self, 
                                   features: Dict[str, float], 
                                   baseline_features: Dict[str, float] = None,
                                   top_n: int = 5) -> List[str]:
        """Get the top N features that deviate most from baseline"""
        if baseline_features is None:
            # If no baseline, just return features with highest absolute values
            sorted_features = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
            return [feature[0] for feature in sorted_features[:top_n]]
        
        # Calculate deviation from baseline for each feature
        deviations = {}
        for feature_name, feature_value in features.items():
            baseline_value = baseline_features.get(feature_name, 0.0)
            deviation = abs(feature_value - baseline_value)
            deviations[feature_name] = deviation
        
        # Return top N features with highest deviations
        sorted_deviations = sorted(deviations.items(), key=lambda x: x[1], reverse=True)
        return [deviation[0] for deviation in sorted_deviations[:top_n]]
    
    def _generate_natural_explanation(self, risk_score: float, top_features: List[str], features: Dict[str, float]) -> str:
        """Generate a natural language explanation"""
        # Create templates for different types of anomalies
        templates = {
            "high_volume": [
                "Unusual volume of activity detected",
                "Significantly more events than normal",
                "Activity level is much higher than expected"
            ],
            "data_exfiltration": [
                "Unusual data access patterns",
                "Large amount of data being accessed",
                "Suspicious data download activity"
            ],
            "geographic": [
                "Login from unusual location",
                "Access from unexpected geographic region",
                "Possible impossible travel detected"
            ],
            "behavioral": [
                "Behavioral pattern deviation detected",
                "Unusual action sequence",
                "Activity doesn't match typical user pattern"
            ]
        }
        
        # Determine the type of anomaly based on top features
        anomaly_type = self._classify_anomaly_type(top_features)
        
        # Select an appropriate template
        template_options = templates.get(anomaly_type, ["Anomalous activity detected"])
        template = template_options[0]  # For simplicity, use the first option
        
        # Add specific details based on features
        details = []
        for feature in top_features[:3]:  # Use top 3 features for details
            value = features.get(feature, 0)
            details.append(f"{feature}={value:.2f}")
        
        explanation = f"{template}. Key indicators: {', '.join(details)}. Risk score: {risk_score:.2f}/100."
        
        return explanation
    
    def _classify_anomaly_type(self, top_features: List[str]) -> str:
        """Classify the type of anomaly based on top features"""
        feature_categories = {
            "high_volume": ["events_per_min", "api_call_count", "login_count"],
            "data_exfiltration": ["bytes_out_total", "bytes_out_rate", "unique_resources"],
            "geographic": ["new_ip_flag", "new_device_flag", "geo_change_flag", "unique_ips"],
            "behavioral": ["action_entropy", "burstiness_score", "time_of_day_deviation_score"]
        }
        
        # Count matches for each category
        category_scores = {}
        for category, category_features in feature_categories.items():
            score = sum(1 for feature in top_features if any(cat_feat in feature for cat_feat in category_features))
            category_scores[category] = score
        
        # Return the category with highest score
        if max(category_scores.values()) > 0:
            return max(category_scores, key=category_scores.get)
        else:
            return "behavioral"  # Default classification
    
    def _calculate_feature_contributions(self, features: Dict[str, float], top_features: List[str]) -> Dict[str, float]:
        """Calculate how much each feature contributed to the anomaly score"""
        # For now, we'll use a simple approach based on feature magnitude
        # In a real implementation, this would use more sophisticated attribution methods
        contributions = {}
        
        for feature in top_features:
            value = features.get(feature, 0.0)
            # Use absolute value as a proxy for contribution
            contributions[feature] = abs(value)
        
        # Normalize contributions to sum to 100
        total = sum(contributions.values())
        if total > 0:
            for feature in contributions:
                contributions[feature] = (contributions[feature] / total) * 100
        
        return contributions
    
    def explain_model_prediction(self, 
                                model_prediction: Dict[str, Any], 
                                feature_window: FeatureWindow) -> Dict[str, Any]:
        """Explain a model prediction"""
        return self.explain_anomaly(
            risk_score=model_prediction.get("risk_score", 0.0),
            features=feature_window.features,
            feature_names=list(feature_window.features.keys())
        )


def explain_anomaly_main(risk_score: float, features: Dict[str, float], 
                       feature_names: List[str], baseline_features: Dict[str, float] = None) -> Dict[str, Any]:
    """Main function to explain an anomaly"""
    explainer = Explainer.__new__(Explainer)  # Create instance without __init__ to avoid config dependency
    explainer.config = None  # Set config to None as it's not used in this function
    return explainer.explain_anomaly(risk_score, features, feature_names, baseline_features)