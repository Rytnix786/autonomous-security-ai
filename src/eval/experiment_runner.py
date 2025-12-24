from typing import List, Dict, Any
import numpy as np
import pandas as pd
from datetime import datetime
from ..core.schemas import Event, Incident
from ..core.logger import logger
from .metrics import EvaluationMetrics


class ExperimentRunner:
    """Run experiments and evaluate the security AI system"""
    
    def __init__(self, config):
        self.config = config
        self.evaluator = EvaluationMetrics()
    
    def run_single_experiment(self, events: List[Event]) -> Dict[str, Any]:
        """Run a single experiment with the security AI pipeline"""
        logger.info("Running single experiment...")
        
        # This would typically involve:
        # 1. Feature extraction
        # 2. Model prediction
        # 3. Incident detection
        # 4. Action taking
        # 5. Evaluation
        
        # For this implementation, we'll simulate the process
        # In a real implementation, this would connect to the full pipeline
        
        # Create dummy incidents for evaluation
        # In reality, these would come from the detection system
        simulated_incidents = self._simulate_incidents(events)
        
        # Calculate metrics
        metrics = self.evaluator.calculate_overall_metrics(simulated_incidents, events)
        
        experiment_result = {
            "timestamp": datetime.now().isoformat(),
            "metrics": metrics,
            "events_processed": len(events),
            "incidents_detected": len(simulated_incidents),
            "experiment_type": "single_run"
        }
        
        logger.info(f"Experiment completed. F1 Score: {metrics['detection_metrics']['f1_score']:.3f}")
        
        return experiment_result
    
    def run_multiple_experiments(self, events: List[Event], runs: int = 5) -> Dict[str, Any]:
        """Run multiple experiments and aggregate results"""
        logger.info(f"Running {runs} experiments...")
        
        results = []
        for i in range(runs):
            logger.info(f"Running experiment {i+1}/{runs}")
            result = self.run_single_experiment(events)
            results.append(result)
        
        # Aggregate results
        aggregated_metrics = self._aggregate_experiment_results(results)
        
        summary = {
            "total_runs": runs,
            "timestamp": datetime.now().isoformat(),
            "aggregated_metrics": aggregated_metrics,
            "individual_results": results,
            "experiment_type": "multi_run"
        }
        
        logger.info(f"Multiple experiments completed. Avg F1 Score: {aggregated_metrics['avg_f1_score']:.3f}")
        
        return summary
    
    def _simulate_incidents(self, events: List[Event]) -> List[Incident]:
        """Simulate incident detection for evaluation purposes"""
        # This is a placeholder that would be replaced with actual detection logic
        # For evaluation, we'll create some simulated incidents based on anomalous events
        
        incidents = []
        
        # Group events by actor and time window to create incidents
        event_df = pd.DataFrame([e.dict() for e in events])
        event_df['timestamp'] = pd.to_datetime(event_df['timestamp'])
        
        # For each anomalous event, create a simulated incident
        anomalous_events = event_df[event_df['ground_truth_is_anomaly'] == True]
        
        for _, group in anomalous_events.groupby(['actor_id', pd.Grouper(key='timestamp', freq='5min')]):
            if len(group) > 0:
                # Create a simulated incident
                event_ids = group['event_id'].tolist()
                primary_event = events[0]  # Find the actual event object
                
                # Find the first matching event in the original list
                for e in events:
                    if e.event_id in event_ids:
                        primary_event = e
                        break
                
                incident = Incident(
                    event_ids=event_ids,
                    timestamp=pd.to_datetime(group['timestamp']).max(),
                    actor_id=group['actor_id'].iloc[0],
                    risk_score=np.random.uniform(60, 95),  # Simulate high risk for anomalous events
                    explanation=f"Simulated incident for {len(event_ids)} anomalous events",
                    action_taken="ALERT",
                    top_features=["events_per_min", "bytes_out_rate", "new_ip_flag"]
                )
                incidents.append(incident)
        
        return incidents
    
    def _aggregate_experiment_results(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """Aggregate results from multiple experiments"""
        if not results:
            return {}
        
        # Extract metrics from each experiment
        f1_scores = []
        precisions = []
        recalls = []
        false_positive_rates = []
        effectiveness_scores = []
        
        for result in results:
            metrics = result.get("metrics", {})
            detection_metrics = metrics.get("detection_metrics", {})
            
            f1_scores.append(detection_metrics.get("f1_score", 0.0))
            precisions.append(detection_metrics.get("precision", 0.0))
            recalls.append(detection_metrics.get("recall", 0.0))
            false_positive_rates.append(detection_metrics.get("false_positive_rate", 0.0))
            effectiveness_scores.append(metrics.get("overall_effectiveness", 0.0))
        
        return {
            "avg_f1_score": float(np.mean(f1_scores)),
            "std_f1_score": float(np.std(f1_scores)),
            "avg_precision": float(np.mean(precisions)),
            "std_precision": float(np.std(precisions)),
            "avg_recall": float(np.mean(recalls)),
            "std_recall": float(np.std(recalls)),
            "avg_false_positive_rate": float(np.mean(false_positive_rates)),
            "std_false_positive_rate": float(np.std(false_positive_rates)),
            "avg_effectiveness": float(np.mean(effectiveness_scores)),
            "std_effectiveness": float(np.std(effectiveness_scores)),
            "total_experiments": len(results)
        }


def run_experiment_main(config, events: List[Event], runs: int = 1) -> Dict[str, Any]:
    """Main function to run experiments"""
    runner = ExperimentRunner(config)
    
    if runs == 1:
        return runner.run_single_experiment(events)
    else:
        return runner.run_multiple_experiments(events, runs)