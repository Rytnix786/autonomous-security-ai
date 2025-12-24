import typer
from typing_extensions import Annotated
from typing import Optional
import json
from pathlib import Path
from datetime import datetime
from .core.config import load_config
from .core.storage import SecurityStorage
from .simulator.generator import generate_logs_main
from .features.feature_engineering import extract_features_main
from .features.windowing import create_windows_main
from .model.anomaly_model import train_model_main, load_model_main
from .model.versioning import list_versions_main
from .policy.decision_engine import PolicyEngine
from .explain.explainer import explain_anomaly_main
from .feedback.feedback_store import submit_feedback_main, get_feedback_summary_main
from .feedback.retrainer import retrain_model_main
from .eval.experiment_runner import run_experiment_main
from .core.logger import logger


app = typer.Typer()


@app.command()
def simulate(
    output: Annotated[str, typer.Option("--out", "-o", help="Output file path")] = "data/raw/logs.jsonl",
    days: Annotated[int, typer.Option("--days", "-d", help="Number of days to simulate")] = 7,
    users: Annotated[int, typer.Option("--users", "-u", help="Number of users to simulate")] = 50,
    anomaly_rate: Annotated[float, typer.Option("--anomaly-rate", "-a", help="Anomaly rate (0.0-1.0)")] = 0.05
):
    """Generate synthetic security logs"""
    config = load_config()
    storage = SecurityStorage()
    
    # Update config with command line parameters
    config.simulator.days = days
    config.simulator.user_count = users
    config.simulator.anomaly_rate = anomaly_rate
    
    logger.info(f"Starting simulation: {days} days, {users} users, {anomaly_rate} anomaly rate")
    
    generate_logs_main(config, output, days, users)
    
    stats = storage.get_storage_stats()
    logger.info(f"Simulation completed. Generated {stats['events_count']} events")


@app.command()
def train(
    logs: Annotated[str, typer.Option("--logs", "-l", help="Path to logs for training")] = "data/raw/logs.jsonl"
):
    """Train the anomaly detection model"""
    config = load_config()
    storage = SecurityStorage()
    
    logger.info(f"Loading events from {logs}")
    events = storage.events.load_events()
    
    if not events:
        logger.error(f"No events found in {logs}")
        raise typer.Exit(code=1)
    
    logger.info(f"Extracting features from {len(events)} events")
    feature_windows = extract_features_main(config, events)
    
    if not feature_windows:
        logger.error("No feature windows created from events")
        raise typer.Exit(code=1)
    
    logger.info(f"Training model on {len(feature_windows)} windows")
    model, training_meta = train_model_main(config, feature_windows)
    
    logger.info("Model training completed successfully")


@app.command()
def run(
    logs: Annotated[str, typer.Option("--logs", "-l", help="Path to logs for detection")] = "data/raw/logs.jsonl",
    stream: Annotated[bool, typer.Option("--stream", "-s", help="Process logs in streaming mode")] = False
):
    """Run the security AI to detect anomalies"""
    config = load_config()
    storage = SecurityStorage()
    
    logger.info(f"Loading events from {logs}")
    events = storage.events.load_events()
    
    if not events:
        logger.error(f"No events found in {logs}")
        raise typer.Exit(code=1)
    
    logger.info(f"Loading trained model")
    try:
        model = load_model_main()
    except FileNotFoundError:
        logger.error("No trained model found. Please run 'train' command first.")
        raise typer.Exit(code=1)
    
    logger.info(f"Extracting features from {len(events)} events")
    feature_windows = extract_features_main(config, events)
    
    logger.info(f"Making predictions on {len(feature_windows)} windows")
    predictions = model.predict(feature_windows)
    
    # Create policy engine to make decisions
    policy_engine = PolicyEngine(config)
    
    # Process predictions and create incidents
    incidents = []
    for i, pred in enumerate(predictions):
        if pred["is_anomaly"]:
            # Get the corresponding feature window
            if i < len(feature_windows):
                window = feature_windows[i]
                
                # Create explanation for the anomaly
                explanation = explain_anomaly_main(
                    pred["risk_score"],
                    window.features,
                    list(window.features.keys())
                )
                
                # Create incident using policy engine
                incident = policy_engine.evaluate_incident(
                    pred["risk_score"],
                    events[:1],  # Using first event as placeholder
                    explanation["top_features"],
                    explanation["explanation"]
                )
                
                incidents.append(incident)
    
    # Save incidents
    storage.incidents.save_incidents(incidents)
    
    logger.info(f"Detection completed. Found {len(incidents)} anomalies")
    
    # Print summary
    print(f"\nDetection Summary:")
    print(f"- Total events processed: {len(events)}")
    print(f"- Feature windows created: {len(feature_windows)}")
    print(f"- Anomalies detected: {len(incidents)}")
    print(f"- Model used: anomaly_model.joblib")


@app.command()
def incidents(
    action: str = typer.Argument(..., help="Action to perform: list, show <id>, or mark <id> <status>"),
    incident_id: Optional[str] = typer.Argument(None),
    status: Optional[str] = typer.Argument(None)
):
    """Manage incidents"""
    storage = SecurityStorage()
    
    if action == "list":
        incidents = storage.incidents.load_incidents()
        print(f"\nFound {len(incidents)} incidents:")
        for i, incident in enumerate(incidents):
            print(f"{i+1:3d}. ID: {incident.incident_id[:12]}... | Actor: {incident.actor_id} | Risk: {incident.risk_score:.2f} | Action: {incident.action_taken} | Status: {incident.feedback_status}")
    
    elif action == "show" and incident_id:
        incidents = storage.incidents.load_incidents()
        incident = next((inc for inc in incidents if inc.incident_id.startswith(incident_id)), None)
        
        if incident:
            print(f"\nIncident Details:")
            print(f"ID: {incident.incident_id}")
            print(f"Timestamp: {incident.timestamp}")
            print(f"Actor: {incident.actor_id}")
            print(f"Risk Score: {incident.risk_score}")
            print(f"Action Taken: {incident.action_taken}")
            print(f"Explanation: {incident.explanation}")
            print(f"Top Features: {', '.join(incident.top_features)}")
            print(f"Feedback Status: {incident.feedback_status}")
        else:
            print(f"Incident with ID {incident_id} not found")
    
    elif action == "mark" and incident_id and status:
        if status not in ["benign", "malicious"]:
            print("Status must be either 'benign' or 'malicious'")
            raise typer.Exit(code=1)
        
        success = storage.incidents.update_incident_feedback(incident_id, status)
        if success:
            print(f"Incident {incident_id} marked as {status}")
            
            # Also submit to feedback store
            submit_feedback_main(incident_id, status, "cli_user")
        else:
            print(f"Failed to update incident {incident_id}")
    
    else:
        print("Invalid command. Use 'incidents list', 'incidents show <id>', or 'incidents mark <id> <benign|malicious>'")


@app.command()
def report(
    output: Annotated[str, typer.Option("--out", "-o", help="Output file path")] = "reports/latest.md"
):
    """Generate a report on system performance"""
    storage = SecurityStorage()
    config = load_config()
    
    # Load data
    events = storage.events.load_events()
    incidents = storage.incidents.load_incidents()
    feedback = storage.feedback.load_feedback()
    
    # Generate report
    report_content = f"""# Autonomous Security AI Report

**Generated:** {typer.style(str(datetime.now()), fg=typer.colors.BLUE)}

## Storage Statistics
- Events: {len(events)}
- Incidents: {len(incidents)}
- Feedback items: {len(feedback)}

## Model Performance
- Not available (requires evaluation run)

## Feedback Summary
"""
    
    feedback_summary = get_feedback_summary_main()
    report_content += f"""- Total feedback: {feedback_summary['total_feedback']}
- Benign feedback: {feedback_summary['benign_count']} ({feedback_summary['benign_percentage']:.1f}%)
- Malicious feedback: {feedback_summary['malicious_count']} ({feedback_summary['malicious_percentage']:.1f}%)
"""
    
    if incidents:
        report_content += f"""

## Incident Summary
- Total incidents: {len(incidents)}
- Average risk score: {sum(inc.risk_score for inc in incidents) / len(incidents):.2f}
- Action distribution:
"""
        action_counts = {}
        for incident in incidents:
            action = incident.action_taken
            action_counts[action] = action_counts.get(action, 0) + 1
        
        for action, count in action_counts.items():
            report_content += f"  - {action}: {count}\n"
    
    # Create output directory if it doesn't exist
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    
    # Write report
    with open(output, 'w') as f:
        f.write(report_content)
    
    print(f"Report generated: {output}")


@app.command()
def eval(
    logs: Annotated[str, typer.Option("--logs", "-l", help="Path to logs for evaluation")] = "data/raw/logs.jsonl",
    runs: Annotated[int, typer.Option("--runs", "-r", help="Number of evaluation runs")] = 5
):
    """Evaluate the system performance"""
    config = load_config()
    storage = SecurityStorage()
    
    logger.info(f"Loading events from {logs}")
    events = storage.events.load_events()
    
    if not events:
        logger.error(f"No events found in {logs}")
        raise typer.Exit(code=1)
    
    logger.info(f"Running evaluation with {runs} runs")
    results = run_experiment_main(config, events, runs)
    
    # Print evaluation results
    if results["experiment_type"] == "multi_run":
        metrics = results["aggregated_metrics"]
        print(f"\nEvaluation Results ({runs} runs):")
        print(f"Average F1 Score: {metrics['avg_f1_score']:.3f} ± {metrics['std_f1_score']:.3f}")
        print(f"Average Precision: {metrics['avg_precision']:.3f} ± {metrics['std_precision']:.3f}")
        print(f"Average Recall: {metrics['avg_recall']:.3f} ± {metrics['std_recall']:.3f}")
        print(f"Average False Positive Rate: {metrics['avg_false_positive_rate']:.3f} ± {metrics['std_false_positive_rate']:.3f}")
        print(f"Overall Effectiveness: {metrics['avg_effectiveness']:.3f} ± {metrics['std_effectiveness']:.3f}")
    else:
        metrics = results["metrics"]
        detection_metrics = metrics["detection_metrics"]
        print(f"\nEvaluation Results (single run):")
        print(f"F1 Score: {detection_metrics['f1_score']:.3f}")
        print(f"Precision: {detection_metrics['precision']:.3f}")
        print(f"Recall: {detection_metrics['recall']:.3f}")
        print(f"False Positive Rate: {detection_metrics['false_positive_rate']:.3f}")
        print(f"Overall Effectiveness: {metrics['overall_effectiveness']:.3f}")


@app.command()
def versions():
    """List model versions"""
    versions = list_versions_main()
    print(f"\nModel Versions:")
    for version in versions:
        print(f"- {version['version']}: {version['timestamp']} - {version['metadata'].get('type', 'unknown')}")


@app.command()
def status():
    """Show system status"""
    storage = SecurityStorage()
    stats = storage.get_storage_stats()
    
    print("\nSystem Status:")
    print(f"- Events stored: {stats['events_count']}")
    print(f"- Incidents stored: {stats['incidents_count']}")
    print(f"- Actions stored: {stats['actions_count']}")
    print(f"- Feedback items: {stats['feedback_count']}")
    
    # Check if model exists
    import os
    model_exists = os.path.exists("models/anomaly_model.joblib")
    print(f"- Model available: {'Yes' if model_exists else 'No'}")
    
    # Check for recent incidents
    incidents = storage.incidents.load_incidents()
    recent_incidents = [inc for inc in incidents if (datetime.now() - inc.timestamp).days <= 1]
    print(f"- Recent incidents (last 24h): {len(recent_incidents)}")


if __name__ == "__main__":
    from datetime import datetime
    app()