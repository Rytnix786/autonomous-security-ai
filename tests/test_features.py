import pytest
import pandas as pd
from datetime import datetime, timedelta
from src.features.feature_engineering import FeatureExtractor
from src.features.windowing import TimeWindower
from src.core.config import SecurityAIConfig
from src.core.schemas import Event


class TestFeatureExtraction:
    """Test feature extraction functionality"""
    
    def setup_method(self):
        """Setup test configuration"""
        self.config = SecurityAIConfig()
        self.extractor = FeatureExtractor(self.config)
    
    def test_feature_names(self):
        """Test that feature names are properly defined"""
        feature_names = self.extractor.get_feature_names()
        assert len(feature_names) >= 30  # Should have at least 30 features
        assert 'events_per_min' in feature_names
        assert 'bytes_out_total' in feature_names
        assert 'new_device_flag' in feature_names
    
    def test_extract_features_from_empty_events(self):
        """Test feature extraction with empty events list"""
        features_df = self.extractor.extract_features_from_events([])
        assert features_df.empty
        assert list(features_df.columns) == self.extractor.get_feature_names()
    
    def test_extract_features_from_single_event(self):
        """Test feature extraction from a single event"""
        event = Event(
            timestamp=datetime.now(),
            actor_id="test_user",
            actor_role="normal_user",
            session_id="test_session",
            action_type="login",
            resource_id="login_resource",
            resource_sensitivity=0,
            result="success",
            latency_ms=100.0,
            bytes_in=100,
            bytes_out=200,
            ip="192.168.1.1",
            device_id="device_123",
            geo="US-CA",
            ground_truth_is_anomaly=False,
            scenario_tag="normal"
        )
        
        features_df = self.extractor.extract_features_from_events([event])
        assert not features_df.empty
        assert len(features_df) == 1
        assert list(features_df.columns) == self.extractor.get_feature_names()
    
    def test_extract_window_features(self):
        """Test window-based feature extraction"""
        events = [
            Event(
                timestamp=datetime.now() - timedelta(minutes=2),
                actor_id="test_user",
                actor_role="normal_user",
                session_id="test_session",
                action_type="login",
                resource_id="login_resource",
                resource_sensitivity=0,
                result="success",
                latency_ms=100.0,
                bytes_in=100,
                bytes_out=200,
                ip="192.168.1.1",
                device_id="device_123",
                geo="US-CA",
                ground_truth_is_anomaly=False,
                scenario_tag="normal"
            ),
            Event(
                timestamp=datetime.now() - timedelta(minutes=1),
                actor_id="test_user",
                actor_role="normal_user",
                session_id="test_session",
                action_type="api_call",
                resource_id="api_resource",
                resource_sensitivity=1,
                result="success",
                latency_ms=150.0,
                bytes_in=200,
                bytes_out=300,
                ip="192.168.1.1",
                device_id="device_123",
                geo="US-CA",
                ground_truth_is_anomaly=False,
                scenario_tag="normal"
            )
        ]
        
        feature_windows = self.extractor.extract_window_features(events)
        assert len(feature_windows) >= 1
        for window in feature_windows:
            assert hasattr(window, 'features')
            assert hasattr(window, 'actor_id')
            assert hasattr(window, 'start_time')


class TestWindowing:
    """Test windowing functionality"""
    
    def setup_method(self):
        """Setup test configuration"""
        self.config = SecurityAIConfig()
        self.windower = TimeWindower(self.config)
    
    def test_create_rolling_windows_empty(self):
        """Test creating rolling windows with empty events"""
        windows = self.windower.create_rolling_windows([])
        assert windows == []
    
    def test_create_session_windows_empty(self):
        """Test creating session windows with empty events"""
        windows = self.windower.create_session_windows([])
        assert windows == []
    
    def test_create_rolling_windows_single_event(self):
        """Test creating rolling windows with single event"""
        event = Event(
            timestamp=datetime.now(),
            actor_id="test_user",
            actor_role="normal_user",
            session_id="test_session",
            action_type="login",
            resource_id="login_resource",
            resource_sensitivity=0,
            result="success",
            latency_ms=100.0,
            bytes_in=100,
            bytes_out=200,
            ip="192.168.1.1",
            device_id="device_123",
            geo="US-CA",
            ground_truth_is_anomaly=False,
            scenario_tag="normal"
        )
        
        windows = self.windower.create_rolling_windows([event])
        assert len(windows) >= 1
    
    def test_create_session_windows_single_event(self):
        """Test creating session windows with single event"""
        event = Event(
            timestamp=datetime.now(),
            actor_id="test_user",
            actor_role="normal_user",
            session_id="test_session",
            action_type="login",
            resource_id="login_resource",
            resource_sensitivity=0,
            result="success",
            latency_ms=100.0,
            bytes_in=100,
            bytes_out=200,
            ip="192.168.1.1",
            device_id="device_123",
            geo="US-CA",
            ground_truth_is_anomaly=False,
            scenario_tag="normal"
        )
        
        windows = self.windower.create_session_windows([event])
        assert len(windows) == 1
        assert windows[0].actor_id == "test_user"