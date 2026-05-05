"""
ML Model Training Pipeline
Train custom LightGBM model for malware detection
"""

import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Tuple, Optional
import pickle

# ML imports
try:
    import lightgbm as lgb
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: ML libraries not available. Install with: pip install lightgbm scikit-learn")

# ONNX conversion
try:
    import onnx
    import skl2onnx
    from skl2onnx.common.data_types import FloatTensorType
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    print("Warning: ONNX libraries not available. Install with: pip install onnx skl2onnx")

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ai_engine.feature_extractor import extract_features
from ai_engine.entropy import calculate_entropy


class MLModelTrainer:
    """
    Training pipeline for LightAV ML model.
    
    Features:
    - Automatic feature extraction
    - Dataset balancing
    - Hyperparameter tuning
    - Cross-validation
    - ONNX export
    """
    
    def __init__(self, model_dir: str = "production/ai_engine/models"):
        """
        Initialize trainer.
        
        Args:
            model_dir: Directory to save models
        """
        if not ML_AVAILABLE:
            raise RuntimeError("ML libraries not available")
        
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        
    def extract_features_from_file(self, file_path: str) -> Optional[np.ndarray]:
        """
        Extract features from a single file.
        
        Args:
            file_path: Path to PE file
            
        Returns:
            Feature vector or None if error
        """
        try:
            # Get basic features (10 from LightAV)
            basic_features = extract_features(file_path)
            
            # Add advanced features
            advanced_features = self._extract_advanced_features(file_path)
            
            # Combine
            return np.concatenate([basic_features, advanced_features])
            
        except Exception as e:
            print(f"[MLTrainer] Error extracting features from {file_path}: {e}")
            return None
    
    def _extract_advanced_features(self, file_path: str) -> np.ndarray:
        """
        Extract 20 advanced features.
        
        Args:
            file_path: Path to file
            
        Returns:
            Array of 20 features
        """
        import pefile
        
        features = np.zeros(20, dtype=np.float32)
        
        try:
            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Feature 1-10: Byte histogram (compressed to 10 bins)
            if len(data) > 0:
                hist, _ = np.histogram(list(data[:8192]), bins=10, range=(0, 256))
                features[0:10] = hist / len(data[:8192])
            
            # Parse PE
            pe = pefile.PE(file_path, fast_load=True)
            
            # Feature 11: String entropy
            strings_data = b''
            for i in range(0, min(len(data), 65536), 100):
                chunk = data[i:i+100]
                if b'\x00' not in chunk:
                    strings_data += chunk
            
            if len(strings_data) > 0:
                features[10] = calculate_entropy(strings_data)
            
            # Feature 12-16: API category counts
            api_categories = self._count_api_categories(pe)
            features[11:16] = api_categories
            
            # Feature 17-20: Section characteristics
            section_features = self._extract_section_features(pe)
            features[16:20] = section_features
            
            pe.close()
            
        except Exception as e:
            pass
        
        return features
    
    def _count_api_categories(self, pe) -> np.ndarray:
        """Count APIs by category."""
        categories = np.zeros(5, dtype=np.float32)
        
        suspicious_apis = {'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'}
        network_apis = {'InternetOpen', 'InternetConnect', 'HttpSendRequest'}
        file_apis = {'CreateFile', 'WriteFile', 'ReadFile'}
        registry_apis = {'RegOpenKey', 'RegSetValue', 'RegCreateKey'}
        process_apis = {'CreateProcess', 'WinExec', 'ShellExecute'}
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if hasattr(entry, 'imports'):
                    for imp in entry.imports:
                        if imp.name:
                            api_name = imp.name.decode('utf-8', errors='ignore')
                            if api_name in suspicious_apis:
                                categories[0] += 1
                            elif api_name in network_apis:
                                categories[1] += 1
                            elif api_name in file_apis:
                                categories[2] += 1
                            elif api_name in registry_apis:
                                categories[3] += 1
                            elif api_name in process_apis:
                                categories[4] += 1
        
        return categories
    
    def _extract_section_features(self, pe) -> np.ndarray:
        """Extract section characteristics."""
        features = np.zeros(4, dtype=np.float32)
        
        if hasattr(pe, 'sections'):
            sections = pe.sections
            if sections:
                # Feature 1: Executable sections count
                exec_count = sum(1 for s in sections if s.Characteristics & 0x20000000)
                features[0] = exec_count
                
                # Feature 2: Writable sections count
                write_count = sum(1 for s in sections if s.Characteristics & 0x80000000)
                features[1] = write_count
                
                # Feature 3: Max section entropy
                entropies = []
                for section in sections:
                    try:
                        data = section.get_data()
                        if data:
                            entropies.append(calculate_entropy(data))
                    except:
                        pass
                
                if entropies:
                    features[2] = max(entropies)
                
                # Feature 4: Total sections
                features[3] = len(sections)
        
        return features
    
    def build_dataset(self, malware_dir: str, benign_dir: str, 
                     limit_per_class: int = 5000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build training dataset from directories.
        
        Args:
            malware_dir: Directory with malware samples
            benign_dir: Directory with benign samples
            limit_per_class: Maximum samples per class
            
        Returns:
            Tuple of (X, y) arrays
        """
        print("[MLTrainer] Building dataset...")
        
        X = []
        y = []
        
        # Process malware
        print(f"[MLTrainer] Processing malware from: {malware_dir}")
        malware_count = 0
        if os.path.exists(malware_dir):
            for root, dirs, files in os.walk(malware_dir):
                for file in files:
                    if malware_count >= limit_per_class:
                        break
                    
                    file_path = os.path.join(root, file)
                    features = self.extract_features_from_file(file_path)
                    
                    if features is not None:
                        X.append(features)
                        y.append(1)  # Malware = 1
                        malware_count += 1
                        
                        if malware_count % 100 == 0:
                            print(f"[MLTrainer] Processed {malware_count} malware samples")
        
        print(f"[MLTrainer] Loaded {malware_count} malware samples")
        
        # Process benign
        print(f"[MLTrainer] Processing benign from: {benign_dir}")
        benign_count = 0
        if os.path.exists(benign_dir):
            for root, dirs, files in os.walk(benign_dir):
                for file in files:
                    if benign_count >= limit_per_class:
                        break
                    
                    file_path = os.path.join(root, file)
                    features = self.extract_features_from_file(file_path)
                    
                    if features is not None:
                        X.append(features)
                        y.append(0)  # Benign = 0
                        benign_count += 1
                        
                        if benign_count % 100 == 0:
                            print(f"[MLTrainer] Processed {benign_count} benign samples")
        
        print(f"[MLTrainer] Loaded {benign_count} benign samples")
        print(f"[MLTrainer] Total dataset size: {len(X)} samples")
        
        return np.array(X), np.array(y)
    
    def train_model(self, X: np.ndarray, y: np.ndarray, 
                   test_size: float = 0.2) -> dict:
        """
        Train LightGBM model.
        
        Args:
            X: Feature matrix
            y: Labels
            test_size: Fraction for test set
            
        Returns:
            Dictionary with training results
        """
        print("[MLTrainer] Training model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"[MLTrainer] Training set: {len(X_train)} samples")
        print(f"[MLTrainer] Test set: {len(X_test)} samples")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model = lgb.LGBMClassifier(
            objective='binary',
            metric='binary_logloss',
            boosting_type='gbdt',
            num_leaves=31,
            learning_rate=0.05,
            feature_fraction=0.9,
            bagging_fraction=0.8,
            bagging_freq=5,
            verbose=-1,
            n_estimators=100,
            random_state=42
        )
        
        print("[MLTrainer] Fitting model...")
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        print("[MLTrainer] Evaluating model...")
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'auc': roc_auc_score(y_test, y_pred_proba),
            'train_size': len(X_train),
            'test_size': len(X_test)
        }
        
        print("[MLTrainer] Model performance:")
        for metric, value in metrics.items():
            if isinstance(value, float):
                print(f"  {metric}: {value:.4f}")
        
        return metrics
    
    def save_model(self, filename: str = "lightgbm_custom_v1"):
        """
        Save model to file.
        
        Args:
            filename: Base filename (without extension)
        """
        if self.model is None:
            raise ValueError("No model trained yet")
        
        # Save as pickle
        pickle_path = self.model_dir / f"{filename}.pkl"
        with open(pickle_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names
            }, f)
        
        print(f"[MLTrainer] Model saved to: {pickle_path}")
        
        # Export to ONNX
        if ONNX_AVAILABLE:
            self._export_onnx(filename)
    
    def _export_onnx(self, filename: str):
        """Export model to ONNX format."""
        try:
            initial_type = [('float_input', FloatTensorType([None, 30]))]
            onnx_model = skl2onnx.convert_lightgbm(self.model, initial_types=initial_type)
            
            onnx_path = self.model_dir / f"{filename}.onnx"
            onnx.save_model(onnx_model, str(onnx_path))
            
            print(f"[MLTrainer] ONNX model saved to: {onnx_path}")
            
        except Exception as e:
            print(f"[MLTrainer] Error exporting to ONNX: {e}")
    
    def cross_validate(self, X: np.ndarray, y: np.ndarray, cv: int = 5) -> dict:
        """
        Perform cross-validation.
        
        Args:
            X: Features
            y: Labels
            cv: Number of folds
            
        Returns:
            CV scores
        """
        print(f"[MLTrainer] Performing {cv}-fold cross-validation...")
        
        X_scaled = self.scaler.fit_transform(X)
        
        scores = cross_val_score(self.model, X_scaled, y, cv=cv, scoring='accuracy')
        
        return {
            'cv_scores': scores,
            'mean_accuracy': scores.mean(),
            'std_accuracy': scores.std()
        }


def train_production_model(malware_dir: str = None, benign_dir: str = None):
    """
    Train a production-ready ML model.
    
    Args:
        malware_dir: Directory with malware samples
        benign_dir: Directory with benign samples
    """
    print("=" * 60)
    print("LightAV ML Model Training")
    print("=" * 60)
    print()
    
    # Default directories
    if malware_dir is None:
        malware_dir = "data/malware"
    if benign_dir is None:
        benign_dir = "data/benign"
    
    # Check if directories exist
    if not os.path.exists(malware_dir):
        print(f"[Trainer] Malware directory not found: {malware_dir}")
        print("[Trainer] Please add malware samples to train the model")
        return False
    
    if not os.path.exists(benign_dir):
        print(f"[Trainer] Benign directory not found: {benign_dir}")
        print("[Trainer] Please add benign samples to train the model")
        return False
    
    # Create trainer
    trainer = MLModelTrainer()
    
    # Build dataset
    X, y = trainer.build_dataset(malware_dir, benign_dir, limit_per_class=5000)
    
    if len(X) == 0:
        print("[Trainer] No training data available")
        return False
    
    # Train model
    metrics = trainer.train_model(X, y)
    
    # Cross-validation
    cv_results = trainer.cross_validate(X, y)
    print(f"\n[Trainer] Cross-validation accuracy: {cv_results['mean_accuracy']:.4f} (+/- {cv_results['std_accuracy']*2:.4f})")
    
    # Save model
    trainer.save_model("lightgbm_custom_v1")
    
    print()
    print("=" * 60)
    print("Training complete!")
    print("=" * 60)
    print(f"Model saved to: production/ai_engine/models/")
    
    return True


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Train LightAV ML Model")
    parser.add_argument('--malware-dir', default='data/malware',
                       help='Directory with malware samples')
    parser.add_argument('--benign-dir', default='data/benign',
                       help='Directory with benign samples')
    parser.add_argument('--limit', type=int, default=5000,
                       help='Max samples per class')
    
    args = parser.parse_args()
    
    train_production_model(args.malware_dir, args.benign_dir)
