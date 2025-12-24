from typing import List, Dict, Any
import numpy as np
import pandas as pd
from datetime import datetime
from ..core.schemas import Event, Incident
from ..core.logger import logger


class EvaluationMetrics:
    """Calculate evaluation metrics for the security AI system"""
    
    def __init__(self):
        pass
    
    def calculate_detection_metrics(self, predicted_incidents: List[Incident], 
                                  ground_truth_events: List[Event]) -> Dict[str, float]:
        """Calculate detection metrics comparing predictions to ground truth"""
        
        if not ground_truth_events:
            return {
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "true_positive": 0,
                "false_positive": 0,
                "true_negative": 0,
                "false_negative": 0
            }
        
        # Create mapping from event_id to ground truth
        ground_truth_map = {}
        for event in ground_truth_events:
            ground_truth_map[event.event_id] = event.ground_truth_is_anomaly
        
        # Count true/false positives and negatives
        true_positive = 0  # Correctly identified anomalies
        false_positive = 0  # Normal events flagged as anomalies
        false_negative = 0  # Anomalies missed by the system
        true_negative = 0   # Correctly identified normal events (hard to calculate without full event list)
        
        # For each predicted incident, check if the associated events were truly anomalous
        for incident in predicted_incidents:
            incident_events = [eid for eid in incident.event_ids if eid in ground_truth_map]
            
            if incident_events:
                # Determine if this was a true positive or false positive
                # If any of the events in the incident were truly anomalous, consider it a detection
                truly_anomalous_events = [eid for eid in incident_events if ground_truth_map[eid]]
                
                if truly_anomalous_events:
                    # This is a true positive (anomaly correctly detected)
                    true_positive += len(truly_anomalous_events)
                    # Count any normal events in the same incident as false positives
                    normal_events_in_incident = [eid for eid in incident_events if not ground_truth_map[eid]]
                    false_positive += len(normal_events_in_incident)
                else:
                    # This is a false positive (normal events incorrectly flagged)
                    false_positive += len(incident_events)
        
        # Calculate false negatives (missed anomalies)
        for event_id, is_anomaly in ground_truth_map.items():
            if is_anomaly and not any(event_id in inc.event_ids for inc in predicted_incidents):
                false_negative += 1
        
        # Calculate metrics
        precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0.0
        recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        false_positive_rate = false_positive / (false_positive + true_negative) if (false_positive + true_negative) > 0 else 0.0
        false_negative_rate = false_negative / (false_negative + true_positive) if (false_negative + true_positive) > 0 else 0.0
        
        return {
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
            "true_positive": true_positive,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "false_negative": false_negative
        }
    
    def calculate_response_metrics(self, incidents: List[Incident], 
                                 actions_taken: List[str]) -> Dict[str, float]:
        """Calculate response effectiveness metrics"""
        
        if not incidents:
            return {
                "avg_response_time": 0.0,
                "action_effectiveness": 0.0,
                "escalation_rate": 0.0
            }
        
        # Calculate average risk score across all incidents
        avg_risk_score = np.mean([inc.risk_score for inc in incidents]) if incidents else 0.0
        
        # Calculate how many incidents had high risk scores (indicating appropriate escalation)
        high_risk_incidents = sum(1 for inc in incidents if inc.risk_score > 75)
        escalation_rate = high_risk_incidents / len(incidents) if incidents else 0.0
        
        return {
            "avg_risk_score": float(avg_risk_score),
            "escalation_rate": escalation_rate,
            "total_incidents": len(incidents),
            "high_risk_incidents": high_risk_incidents
        }
    
    def calculate_time_to_detection(self, events: List[Event], 
                                  incidents: List[Incident]) -> Dict[str, float]:
        """Calculate time metrics like MTTD (Mean Time To Detection)"""
        
        if not events or not incidents:
            return {
                "mttd_seconds": 0.0,
                "mttd_minutes": 0.0,
                "total_detection_time": 0.0
            }
        
        # Calculate time from first anomalous event to incident detection
        detection_times = []
        
        for incident in incidents:
            # Find the earliest anomalous event in this incident
            incident_events = [e for e in events if e.event_id in incident.event_ids]
            anomalous_events = [e for e in incident_events if e.ground_truth_is_anomaly]
            
            if anomalous_events:
                earliest_anomalous = min(anomalous_events, key=lambda x: x.timestamp)
                detection_time = (incident.timestamp - earliest_anomalous.timestamp).total_seconds()
                detection_times.append(max(0, detection_time))  # Ensure non-negative
        
        if detection_times:
            avg_detection_time = np.mean(detection_times)
            return {
                "mttd_seconds": float(avg_detection_time),
                "mttd_minutes": float(avg_detection_time / 60),
                "total_detection_time": float(sum(detection_times)),
                "detection_events_count": len(detection_times)
            }
        else:
            return {
                "mttd_seconds": 0.0,
                "mttd_minutes": 0.0,
                "total_detection_time": 0.0,
                "detection_events_count": 0
            }
    
    def calculate_overall_metrics(self, predicted_incidents: List[Incident], 
                                ground_truth_events: List[Event],
                                actions_taken: List[str] = None) -> Dict[str, Any]:
        """Calculate overall system metrics"""
        
        detection_metrics = self.calculate_detection_metrics(predicted_incidents, ground_truth_events)
        response_metrics = self.calculate_response_metrics(predicted_incidents, actions_taken or [])
        time_metrics = self.calculate_time_to_detection(ground_truth_events, predicted_incidents)
        
        # Calculate overall effectiveness score
        effectiveness_score = (
            detection_metrics["f1_score"] * 0.5 +
            (1 - detection_metrics["false_positive_rate"]) * 0.3 +
            (1 / (1 + time_metrics["mttd_minutes"])) * 0.2
        ) if time_metrics["mttd_minutes"] > 0 else detection_metrics["f1_score"] * 0.8
        
        return {
            "detection_metrics": detection_metrics,
            "response_metrics": response_metrics,
            "time_metrics": time_metrics,
            "overall_effectiveness": effectiveness_score,
            "evaluation_timestamp": datetime.now().isoformat()
        }


def calculate_metrics_main(predicted_incidents: List[Incident], 
                         ground_truth_events: List[Event],
                         actions_taken: List[str] = None) -> Dict[str, Any]:
    """Main function to calculate evaluation metrics"""
    evaluator = EvaluationMetrics()
    return evaluator.calculate_overall_metrics(predicted_incidents, ground_truth_events, actions_taken)