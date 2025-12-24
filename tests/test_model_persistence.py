import pytest
import tempfile
import os
from datetime import datetime
import numpy as np
from src.model.anomaly_model import AnomalyModel, train_model_main, load_model_main
from src.model.versioning import ModelVersionManager, create_version_main, list_versions_main, rollback_version_main
from src.core.config import SecurityAIConfig
from src.core.schemas import FeatureWindow


class TestModelPersistence:
    """Test model persistence functionality"""
    
    def setup_method(self):
        """Setup test configuration"""
        self.config = SecurityAIConfig()
        # Adjust config for testing
        self.config.model.min_samples_for_training = 10
    
    def test_model_save_and_load(self):
        """Test saving and loading a trained model"""
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "test_model.joblib")
            
            # Create sample feature windows for training
            sample_windows = []
            for i in range(50):  # Create 50 sample windows
                window = FeatureWindow(
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    features={
                        "events_per_min": float(np.random.uniform(0, 10)),
                        "failures_per_min": float(np.random.uniform(0, 2)),
                        "success_rate": float(np.random.uniform(0.8, 1.0)),
                        "bytes_out_total": float(np.random.uniform(0, 10000)),
                        "new_device_flag": float(np.random.choice([0, 1])),
                        "new_ip_flag": float(np.random.choice([0, 1])),
                        "unique_resources": float(np.random.uniform(1, 20)),
                        "sensitive_access_count": float(np.random.uniform(0, 5)),
                        "action_entropy": float(np.random.uniform(0, 2)),
                        "burstiness_score": float(np.random.uniform(0, 5))
                    },
                    actor_id=f"user_{i % 10}",  # 10 different users
                    session_id=f"session_{i}",
                    is_anomaly=bool(np.random.choice([True, False], p=[0.1, 0.9]))  # 10% anomalies
                )
                sample_windows.append(window)
            
            # Train and save model
            model, training_meta = train_model_main(self.config, sample_windows, model_path)
            
            # Verify model was saved
            assert os.path.exists(model_path)
            
            # Load the model
            loaded_model = load_model_main(model_path)
            
            # Verify the loaded model has the same properties
            assert loaded_model.is_trained is True
            assert len(loaded_model.feature_names) > 0
            assert loaded_model.training_meta is not None
    
    def test_model_prediction_consistency(self):
        """Test that saved and loaded model gives consistent predictions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "test_model.joblib")
            
            # Create sample feature windows for training
            training_windows = []
            for i in range(30):
                window = FeatureWindow(
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    features={
                        "events_per_min": float(np.random.uniform(0, 10)),
                        "failures_per_min": float(np.random.uniform(0, 2)),
                        "success_rate": float(np.random.uniform(0.8, 1.0)),
                        "bytes_out_total": float(np.random.uniform(0, 10000)),
                        "new_device_flag": float(np.random.choice([0, 1])),
                        "new_ip_flag": float(np.random.choice([0, 1])),
                        "unique_resources": float(np.random.uniform(1, 20)),
                        "sensitive_access_count": float(np.random.uniform(0, 5)),
                        "action_entropy": float(np.random.uniform(0, 2)),
                        "burstiness_score": float(np.random.uniform(0, 5))
                    },
                    actor_id=f"user_{i % 5}",
                    session_id=f"session_{i}",
                    is_anomaly=bool(np.random.choice([True, False], p=[0.1, 0.9]))
                )
                training_windows.append(window)
            
            # Train and save model
            original_model, _ = train_model_main(self.config, training_windows, model_path)
            
            # Create test windows
            test_windows = []
            for i in range(10):
                window = FeatureWindow(
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    features={
                        "events_per_min": float(np.random.uniform(0, 10)),
                        "failures_per_min": float(np.random.uniform(0, 2)),
                        "success_rate": float(np.random.uniform(0.8, 1.0)),
                        "bytes_out_total": float(np.random.uniform(0, 10000)),
                        "new_device_flag": float(np.random.choice([0, 1])),
                        "new_ip_flag": float(np.random.choice([0, 1])),
                        "unique_resources": float(np.random.uniform(1, 20)),
                        "sensitive_access_count": float(np.random.uniform(0, 5)),
                        "action_entropy": float(np.random.uniform(0, 2)),
                        "burstiness_score": float(np.random.uniform(0, 5))
                    },
                    actor_id=f"test_user_{i}",
                    session_id=f"test_session_{i}",
                    is_anomaly=bool(np.random.choice([True, False], p=[0.2, 0.8]))
                )
                test_windows.append(window)
            
            # Get predictions from original model
            original_predictions = original_model.predict(test_windows)
            
            # Load the model and get predictions
            loaded_model = load_model_main(model_path)
            loaded_predictions = loaded_model.predict(test_windows)
            
            # Compare predictions (they should be very similar)
            assert len(original_predictions) == len(loaded_predictions)
            
            # Check that risk scores are similar (allowing for small numerical differences)
            for orig, loaded in zip(original_predictions, loaded_predictions):
                assert abs(orig["risk_score"] - loaded["risk_score"]) < 0.01  # Very small tolerance
                assert orig["is_anomaly"] == loaded["is_anomaly"]


class TestModelVersioning:
    """Test model versioning functionality"""
    
    def setup_method(self):
        """Setup test configuration"""
        self.config = SecurityAIConfig()
        self.config.model.min_samples_for_training = 5
    
    def test_version_creation_and_listing(self):
        """Test creating and listing model versions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set up version manager
            version_manager = ModelVersionManager(models_dir=temp_dir)
            
            # Create a dummy model file
            dummy_model_path = os.path.join(temp_dir, "dummy_model.joblib")
            with open(dummy_model_path, 'w') as f:
                f.write("dummy model content")
            
            # Create a version
            version_name = version_manager.create_version(dummy_model_path, "test_version_1")
            
            # List versions
            versions = version_manager.list_versions()
            
            assert len(versions) == 1
            assert versions[0]["version"] == version_name
            assert versions[0]["model_path"] == dummy_model_path
    
    def test_version_rollback(self):
        """Test rolling back to a previous version"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set up version manager
            version_manager = ModelVersionManager(models_dir=temp_dir)
            
            # Create initial model file
            model_path = os.path.join(temp_dir, "model.joblib")
            with open(model_path, 'w') as f:
                f.write("initial model content")
            
            # Create a version of the initial model
            version_1 = version_manager.create_version(model_path, "version_1")
            
            # Update the model file
            with open(model_path, 'w') as f:
                f.write("updated model content")
            
            # Create a version of the updated model
            version_2 = version_manager.create_version(model_path, "version_2")
            
            # Rollback to version 1
            rollback_success = version_manager.rollback_to_version(version_1, model_path)
            
            assert rollback_success is True
            
            # Verify the content was rolled back
            with open(model_path, 'r') as f:
                content = f.read()
                assert content == "initial model content"
    
    def test_version_manager_functions(self):
        """Test version manager functions through main functions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a dummy model file
            dummy_model_path = os.path.join(temp_dir, "dummy_model.joblib")
            with open(dummy_model_path, 'w') as f:
                f.write("dummy model content")
            
            # Create version using main function
            version_name = create_version_main(dummy_model_path, "test_version_main")
            assert version_name is not None
            
            # List versions using main function
            versions = list_versions_main()
            assert len(versions) >= 1
            
            # Check that our version is in the list
            version_exists = any(v["version"] == version_name for v in versions)
            assert version_exists is True