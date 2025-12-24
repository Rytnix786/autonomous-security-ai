from typing import List, Dict, Any, Optional
import json
from datetime import datetime
from pathlib import Path
import shutil
from ..core.logger import logger


class ModelVersionManager:
    """Manage model versions and provide rollback capabilities"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.versions_file = self.models_dir / "versions.json"
        self._load_versions()
    
    def _load_versions(self):
        """Load version information from file"""
        if self.versions_file.exists():
            with open(self.versions_file, 'r') as f:
                self.versions = json.load(f)
        else:
            self.versions = {}
    
    def _save_versions(self):
        """Save version information to file"""
        with open(self.versions_file, 'w') as f:
            json.dump(self.versions, f, indent=2)
    
    def create_version(self, model_path: str, version_name: str = None, metadata: Dict[str, Any] = None) -> str:
        """Create a new model version"""
        if version_name is None:
            version_name = f"v{len(self.versions) + 1}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create version directory
        version_dir = self.models_dir / version_name
        version_dir.mkdir(exist_ok=True)
        
        # Copy model files to version directory
        model_path_obj = Path(model_path)
        if model_path_obj.exists():
            shutil.copy2(model_path, version_dir / model_path_obj.name)
        
        # Copy related files (features, meta)
        feature_path = str(model_path).replace('.joblib', '_features.json')
        meta_path = str(model_path).replace('.joblib', '_meta.json')
        
        if Path(feature_path).exists():
            shutil.copy2(feature_path, version_dir / Path(feature_path).name)
        if Path(meta_path).exists():
            shutil.copy2(meta_path, version_dir / Path(meta_path).name)
        
        # Record version metadata
        version_info = {
            "version": version_name,
            "timestamp": datetime.now().isoformat(),
            "model_path": str(model_path),
            "files": [model_path_obj.name],
            "metadata": metadata or {}
        }
        
        # Add related files to version info
        if Path(feature_path).exists():
            version_info["files"].append(Path(feature_path).name)
        if Path(meta_path).exists():
            version_info["files"].append(Path(meta_path).name)
        
        self.versions[version_name] = version_info
        self._save_versions()
        
        logger.info(f"Created model version: {version_name}")
        return version_name
    
    def list_versions(self) -> List[Dict[str, Any]]:
        """List all model versions"""
        return list(self.versions.values())
    
    def get_latest_version(self) -> Optional[str]:
        """Get the latest model version"""
        if not self.versions:
            return None
        
        # Sort by timestamp to get the most recent
        sorted_versions = sorted(
            self.versions.values(),
            key=lambda x: x['timestamp'],
            reverse=True
        )
        return sorted_versions[0]['version']
    
    def get_version_path(self, version_name: str) -> Optional[Path]:
        """Get the path to a specific version's model file"""
        if version_name not in self.versions:
            return None
        
        version_info = self.versions[version_name]
        version_dir = self.models_dir / version_name
        model_filename = [f for f in version_info['files'] if f.endswith('.joblib')][0]
        return version_dir / model_filename
    
    def rollback_to_version(self, version_name: str, target_path: str = "models/anomaly_model.joblib") -> bool:
        """Rollback to a specific model version"""
        if version_name not in self.versions:
            logger.error(f"Version {version_name} not found")
            return False
        
        version_dir = self.models_dir / version_name
        if not version_dir.exists():
            logger.error(f"Version directory {version_dir} not found")
            return False
        
        # Find the model file in the version directory
        model_files = list(version_dir.glob("*.joblib"))
        if not model_files:
            logger.error(f"No model file found in version {version_name}")
            return False
        
        # Copy the model file to the target location
        source_model = model_files[0]
        target_path_obj = Path(target_path)
        target_path_obj.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_model, target_path_obj)
        
        # Also copy related files
        for file_name in self.versions[version_name]['files']:
            if file_name.endswith(('.json')):
                source_file = version_dir / file_name
                if source_file.exists():
                    target_file = target_path_obj.parent / file_name
                    shutil.copy2(source_file, target_file)
        
        logger.info(f"Rolled back to version {version_name}")
        return True
    
    def delete_version(self, version_name: str) -> bool:
        """Delete a model version"""
        if version_name not in self.versions:
            logger.error(f"Version {version_name} not found")
            return False
        
        version_dir = self.models_dir / version_name
        if version_dir.exists():
            shutil.rmtree(version_dir)
        
        del self.versions[version_name]
        self._save_versions()
        
        logger.info(f"Deleted model version: {version_name}")
        return True


def create_version_main(model_path: str, version_name: str = None, metadata: Dict[str, Any] = None) -> str:
    """Main function to create a model version"""
    version_manager = ModelVersionManager()
    return version_manager.create_version(model_path, version_name, metadata)


def list_versions_main() -> List[Dict[str, Any]]:
    """Main function to list model versions"""
    version_manager = ModelVersionManager()
    return version_manager.list_versions()


def rollback_version_main(version_name: str, target_path: str = "models/anomaly_model.joblib") -> bool:
    """Main function to rollback to a model version"""
    version_manager = ModelVersionManager()
    return version_manager.rollback_to_version(version_name, target_path)