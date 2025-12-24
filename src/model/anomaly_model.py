from typing import List, Dict, Any, Optional, Tuple
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime
import json
from pathlib import Path
from ..core.schemas import FeatureWindow
from ..core.logger import logger


class AnomalyModel:
    """Anomaly detection model using Isolation Forest"""
    
    def __init__(self, config):
        self.config = config
        self.model = IsolationForest(
            contamination=self.config.model.contamination,
            random_state=self.config.model.random_state,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_trained = False
        self.training_meta = {}
    
    def prepare_features(self, windows: List[FeatureWindow]) -> Tuple[pd.DataFrame, np.ndarray]:
        """Prepare features from windows for model training/prediction"""
        if not windows:
            return pd.DataFrame(), np.array([])
        
        if not self.feature_names and windows:
            # If we don't have feature names yet, extract from first window
            self.feature_names = list(windows[0].features.keys())
        
        if not self.feature_names:
            # If still no feature names, return empty DataFrame
            return pd.DataFrame(), np.array([])
        
        # Convert windows to DataFrame
        data = []
        labels = []
        
        for window in windows:
            # Extract feature values, ensuring consistent order
            feature_vector = []
            for feature_name in self.feature_names:
                value = window.features.get(feature_name, 0.0)
                feature_vector.append(float(value))
            
            data.append(feature_vector)
            # Use ground truth for training, or None for prediction
            labels.append(window.is_anomaly if window.is_anomaly is not None else -1)
        
        if not data:
            # If no data, return empty DataFrame with proper columns
            df = pd.DataFrame(columns=self.feature_names)
            labels = np.array([])
        else:
            # Convert to DataFrame with proper column names
            df = pd.DataFrame(data, columns=self.feature_names)
            labels = np.array(labels)
        
        # Replace any NaN or infinite values
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0.0)
        
        return df, labels
    
    def train(self, windows: List[FeatureWindow]) -> Dict[str, Any]:
        """Train the anomaly detection model"""
        if len(windows) < self.config.model.min_samples_for_training:
            raise ValueError(
                f"Need at least {self.config.model.min_samples_for_training} samples for training, "
                f"but only {len(windows)} provided"
            )
        
        logger.info(f"Training model on {len(windows)} windows")
        
        # If we don't have feature names yet, extract them from the first window
        if not self.feature_names and windows:
            self.feature_names = list(windows[0].features.keys())
        
        # Prepare features
        X, y = self.prepare_features(windows)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train the model
        self.model.fit(X_scaled)
        self.is_trained = True
        
        # Calculate training metrics
        training_predictions = self.model.predict(X_scaled)
        training_anomaly_scores = self.model.decision_function(X_scaled)
        
        # Convert to 0-100 risk score (higher is more anomalous)
        risk_scores = self._anomaly_scores_to_risk(training_anomaly_scores)
        
        # Calculate metrics
        true_anomalies = y if len(y) > 0 and y[0] != -1 else None
        if true_anomalies is not None:
            # Calculate accuracy metrics if ground truth is available
            predicted_anomalies = training_predictions == -1  # Isolation Forest returns -1 for anomalies
            true_positive = np.sum((true_anomalies == True) & (predicted_anomalies))
            false_positive = np.sum((true_anomalies == False) & (predicted_anomalies))
            true_negative = np.sum((true_anomalies == False) & (~predicted_anomalies))
            false_negative = np.sum((true_anomalies == True) & (~predicted_anomalies))
            
            precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0
            recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            training_meta = {
                "timestamp": datetime.now().isoformat(),
                "samples_count": len(windows),
                "true_positive": int(true_positive),
                "false_positive": int(false_positive),
                "true_negative": int(true_negative),
                "false_negative": int(false_negative),
                "precision": precision,
                "recall": recall,
                "f1_score": f1_score,
                "avg_risk_score_normal": float(np.mean(risk_scores[y == False])) if np.any(y == False) else 0.0,
                "avg_risk_score_anomaly": float(np.mean(risk_scores[y == True])) if np.any(y == True) else 0.0
            }
        else:
            training_meta = {
                "timestamp": datetime.now().isoformat(),
                "samples_count": len(windows),
                "avg_risk_score": float(np.mean(risk_scores))
            }
        
        self.training_meta = training_meta
        logger.info(f"Model training completed. Samples: {len(windows)}, F1 Score: {training_meta.get('f1_score', 'N/A')}")
        
        return training_meta
    
    def predict(self, windows: List[FeatureWindow]) -> List[Dict[str, Any]]:
        """Predict anomalies for given windows"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        if not windows:
            return []
        
        # Prepare features
        X, _ = self.prepare_features(windows)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Make predictions
        predictions = self.model.predict(X_scaled)  # -1 for anomaly, 1 for normal
        anomaly_scores = self.model.decision_function(X_scaled)  # Raw anomaly scores
        
        # Convert to risk scores (0-100)
        risk_scores = self._anomaly_scores_to_risk(anomaly_scores)
        
        results = []
        for i, window in enumerate(windows):
            is_anomaly = predictions[i] == -1
            risk_score = risk_scores[i]
            
            results.append({
                "window_id": window.window_id,
                "actor_id": window.actor_id,
                "session_id": window.session_id,
                "is_anomaly": bool(is_anomaly),
                "risk_score": float(risk_score),
                "raw_anomaly_score": float(anomaly_scores[i]),
                "features": window.features
            })
        
        return results
    
    def _anomaly_scores_to_risk(self, anomaly_scores: np.ndarray) -> np.ndarray:
        """Convert anomaly scores to risk scores (0-100 scale)"""
        # Anomaly scores from Isolation Forest are negative for anomalies
        # We want higher scores to indicate higher risk
        # Normalize scores to 0-100 range
        min_score = anomaly_scores.min()
        max_score = anomaly_scores.max()
        
        if max_score == min_score:
            # If all scores are the same, return 50 for all
            return np.full_like(anomaly_scores, 50.0, dtype=float)
        
        # Normalize to 0-1 range and invert (so low anomaly score = high risk)
        normalized = (anomaly_scores - min_score) / (max_score - min_score)
        risk_scores = (1 - normalized) * 100  # Invert so anomalies get higher scores
        
        return risk_scores
    
    def detect_drift(self, windows: List[FeatureWindow], threshold: float = 2.0) -> bool:
        """Detect if there's concept drift in the data"""
        if not self.is_trained or not windows:
            return False
        
        # Get predictions for the new windows
        predictions = self.predict(windows)
        current_avg_risk = np.mean([p['risk_score'] for p in predictions])
        
        # Compare with historical average risk from training
        historical_avg_risk = self.training_meta.get('avg_risk_score', 50.0)
        
        # Calculate drift as the absolute difference
        drift_magnitude = abs(current_avg_risk - historical_avg_risk)
        
        logger.info(f"Drift detection: historical avg risk {historical_avg_risk:.2f}, "
                   f"current avg risk {current_avg_risk:.2f}, drift magnitude {drift_magnitude:.2f}")
        
        return drift_magnitude > threshold
    
    def save_model(self, model_path: str = "models/anomaly_model.joblib"):
        """Save the trained model"""
        model_dir = Path(model_path).parent
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save model and scaler
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'training_meta': self.training_meta
        }
        
        joblib.dump(model_data, model_path)
        logger.info(f"Model saved to {model_path}")
        
        # Also save feature names separately for easy access
        feature_names_path = str(model_path).replace('.joblib', '_features.json')
        with open(feature_names_path, 'w') as f:
            json.dump(self.feature_names, f)
        
        # Save training metadata
        meta_path = str(model_path).replace('.joblib', '_meta.json')
        with open(meta_path, 'w') as f:
            json.dump(self.training_meta, f)
    
    def load_model(self, model_path: str = "models/anomaly_model.joblib"):
        """Load a trained model"""
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        model_data = joblib.load(model_path)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        self.training_meta = model_data['training_meta'] if 'training_meta' in model_data else {}
        
        logger.info(f"Model loaded from {model_path}")
        
        return self


def train_model_main(config, feature_windows: List[FeatureWindow], model_path: str = "models/anomaly_model.joblib"):
    """Main function to train the anomaly detection model"""
    model = AnomalyModel(config)
    training_meta = model.train(feature_windows)
    model.save_model(model_path)
    
    logger.info(f"Model training completed and saved to {model_path}")
    return model, training_meta


def load_model_main(model_path: str = "models/anomaly_model.joblib"):
    """Main function to load a trained model"""
    model = AnomalyModel.__new__(AnomalyModel)  # Create instance without calling __init__
    model.load_model(model_path)
    return model