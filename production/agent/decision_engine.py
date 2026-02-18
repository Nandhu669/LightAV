"""
Production Decision Engine
4-layer detection: Hash → YARA → Heuristic → ML (with early exit)
"""

import numpy as np
from pathlib import Path
from typing import Tuple, Optional, Dict
from dataclasses import dataclass

# Import our new production modules
from production.agent.hash_database import HashDatabase
from production.ai_engine.yara_engine import YARAEngine
from production.ai_engine.heuristic_engine import EnhancedHeuristicEngine
from production.testing.whitelist import WhitelistDB

# Import existing modules
from agent.decision_types import Verdict
from ai_engine.feature_extractor import extract_features


@dataclass
class DetectionResult:
    """Complete detection result with all details."""
    verdict: Verdict
    source: str
    confidence: float
    details: Dict
    scan_time_ms: float


class ProductionDecisionEngine:
    """
    Production-grade decision engine with 4-layer detection.
    
    Layers (in order of execution):
    1. Hash Database - O(1) lookup, instant detection
    2. YARA Rules - Pattern matching, ~50ms
    3. Heuristic Analysis - Static analysis, ~100ms
    4. ML Model - Machine learning, ~10ms (only if needed)
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize production decision engine.
        
        Args:
            config: Configuration dictionary with thresholds
        """
        self.config = config or {}
        
        # Initialize all detection layers
        print("[DecisionEngine] Initializing production engine...")
        
        # Layer 0: Whitelist (check before all other layers)
        print("[DecisionEngine] Loading whitelist...")
        self.whitelist = WhitelistDB()
        
        # Layer 1: Hash Database
        print("[DecisionEngine] Loading hash database...")
        self.hash_db = HashDatabase()
        
        # Layer 2: YARA Engine
        print("[DecisionEngine] Loading YARA rules...")
        self.yara = YARAEngine()
        
        # Layer 3: Heuristic Engine
        print("[DecisionEngine] Loading heuristic engine...")
        self.heuristics = EnhancedHeuristicEngine()
        
        # Layer 4: ML Model (optional - will train later)
        self.ml_model = None
        self.ml_available = False
        
        # Try to load existing model
        self._try_load_ml_model()
        
        # Thresholds
        self.confidence_threshold = self.config.get('confidence_threshold', 0.85)
        self.yara_confidence_threshold = self.config.get('yara_confidence_threshold', 0.9)
        self.heuristic_high_threshold = self.config.get('heuristic_high_threshold', 75)
        self.heuristic_medium_threshold = self.config.get('heuristic_medium_threshold', 40)
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'hash_hits': 0,
            'yara_hits': 0,
            'heuristic_hits': 0,
            'ml_hits': 0,
            'clean': 0,
            'errors': 0
        }
        
        print("[DecisionEngine] Initialization complete!")
        whitelist_stats = self.whitelist.get_stats()
        print(f"[DecisionEngine] Whitelist: {whitelist_stats['total_entries']} entries")
        print(f"[DecisionEngine] Hash DB: {self.hash_db.stats['total_hashes']} hashes")
        print(f"[DecisionEngine] YARA: {len(self.yara.rule_files)} rule files")
        print(f"[DecisionEngine] Heuristics: {len(self.heuristics.rules)} rules")
        print(f"[DecisionEngine] ML Model: {'Available' if self.ml_available else 'Not Available'}")
    
    def _try_load_ml_model(self):
        """Try to load ML model if available."""
        # Check for existing LightAV model
        existing_model_paths = [
            "ai_engine/lightgbm_static.onnx",
            "production/ai_engine/models/lightgbm_custom_v1.onnx",
            "ml_models/lightgbm_static.onnx"
        ]
        
        for model_path in existing_model_paths:
            if Path(model_path).exists():
                try:
                    from ai_engine.model_infer import StaticONNXModel
                    self.ml_model = StaticONNXModel(model_path)
                    self.ml_available = True
                    print(f"[DecisionEngine] Loaded ML model: {model_path}")
                    return
                except Exception as e:
                    print(f"[DecisionEngine] Failed to load model {model_path}: {e}")
        
        print("[DecisionEngine] No ML model available (will use heuristics only)")
    
    def decide(self, file_path: str, file_hash: str, 
               cached_verdict: Optional[int] = None) -> DetectionResult:
        """
        Main decision function - 4-layer detection with early exit.
        
        Args:
            file_path: Path to file being scanned
            file_hash: SHA256 hash of file
            cached_verdict: Optional cached verdict from previous scan
            
        Returns:
            DetectionResult with verdict and details
        """
        import time
        start_time = time.time()
        
        self.stats['total_scans'] += 1
        
        try:
            # Check cache first
            if cached_verdict is not None:
                return DetectionResult(
                    verdict=Verdict(cached_verdict),
                    source="cache",
                    confidence=1.0,
                    details={'cached': True},
                    scan_time_ms=(time.time() - start_time) * 1000
                )
            
            # Layer 0: Whitelist Check (before malware detection)
            if self.whitelist.is_whitelisted(file_hash):
                whitelist_info = self.whitelist.get_whitelist_info(file_hash)
                return DetectionResult(
                    verdict=Verdict.BENIGN,
                    source="whitelist",
                    confidence=whitelist_info.get('confidence', 1.0) if whitelist_info else 1.0,
                    details={'layer': 0, 'whitelist_info': whitelist_info},
                    scan_time_ms=(time.time() - start_time) * 1000
                )
            
            # Layer 1: Hash Database (fastest, O(1))
            if self.hash_db.contains(file_hash):
                self.stats['hash_hits'] += 1
                details = self.hash_db.lookup_details(file_hash) or {}
                return DetectionResult(
                    verdict=Verdict.MALICIOUS,
                    source="hash_db",
                    confidence=1.0,
                    details={**details, 'layer': 1},
                    scan_time_ms=(time.time() - start_time) * 1000
                )
            
            # Layer 2: YARA Rules
            yara_matches = self.yara.scan(file_path)
            if yara_matches:
                yara_confidence = self.yara.get_confidence(yara_matches)
                if yara_confidence >= self.yara_confidence_threshold:
                    self.stats['yara_hits'] += 1
                    return DetectionResult(
                        verdict=Verdict.MALICIOUS,
                        source="yara",
                        confidence=yara_confidence,
                        details={
                            'layer': 2,
                            'matches': self.yara.get_match_details(yara_matches)
                        },
                        scan_time_ms=(time.time() - start_time) * 1000
                    )
            
            # Layer 3: Heuristic Analysis
            features = extract_features(file_path)
            heuristic_result = self.heuristics.analyze(file_path, features)
            
            if heuristic_result.score >= self.heuristic_high_threshold:
                self.stats['heuristic_hits'] += 1
                return DetectionResult(
                    verdict=Verdict.MALICIOUS,
                    source="heuristic",
                    confidence=heuristic_result.confidence,
                    details={
                        'layer': 3,
                        'score': heuristic_result.score,
                        'triggers': heuristic_result.triggers
                    },
                    scan_time_ms=(time.time() - start_time) * 1000
                )
            
            # Layer 4: ML Model (only if medium suspicion and ML available)
            if (heuristic_result.score >= self.heuristic_medium_threshold and 
                self.ml_available and self.ml_model):
                
                ml_prediction = self._run_ml_model(file_path, features)
                if ml_prediction >= self.confidence_threshold:
                    self.stats['ml_hits'] += 1
                    return DetectionResult(
                        verdict=Verdict.MALICIOUS,
                        source="ml",
                        confidence=ml_prediction,
                        details={
                            'layer': 4,
                            'heuristic_score': heuristic_result.score,
                            'ml_confidence': ml_prediction
                        },
                        scan_time_ms=(time.time() - start_time) * 1000
                    )
            
            # File is clean
            self.stats['clean'] += 1
            return DetectionResult(
                verdict=Verdict.BENIGN,
                source="clean",
                confidence=1.0,
                details={
                    'heuristic_score': heuristic_result.score if 'heuristic_result' in locals() else 0,
                    'yara_matches': len(yara_matches) if 'yara_matches' in locals() else 0
                },
                scan_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            self.stats['errors'] += 1
            return DetectionResult(
                verdict=Verdict.BENIGN,  # Fail safe
                source="error",
                confidence=0.0,
                details={'error': str(e)},
                scan_time_ms=(time.time() - start_time) * 1000
            )
    
    def _run_ml_model(self, file_path: str, features: np.ndarray) -> float:
        """
        Run ML model prediction.
        
        Args:
            file_path: Path to file
            features: Feature vector
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not self.ml_available:
            return 0.0
        
        try:
            # Prepare features for model
            # Model expects 10 features from LightAV
            if len(features) >= 10:
                model_input = features[:10].reshape(1, -1).astype(np.float32)
                prediction = self.ml_model.predict(model_input)
                # Return probability of malware (class 1)
                return float(prediction[0]) if prediction[0] > 0 else 0.5
        except Exception as e:
            print(f"[DecisionEngine] ML prediction error: {e}")
        
        return 0.0
    
    def get_stats(self) -> Dict:
        """Return comprehensive engine statistics."""
        total = self.stats['total_scans']
        if total == 0:
            return self.stats
        
        return {
            **self.stats,
            'detection_rate': (self.stats['hash_hits'] + self.stats['yara_hits'] + 
                              self.stats['heuristic_hits'] + self.stats['ml_hits']) / total,
            'hash_rate': self.stats['hash_hits'] / total,
            'yara_rate': self.stats['yara_hits'] / total,
            'heuristic_rate': self.stats['heuristic_hits'] / total,
            'ml_rate': self.stats['ml_hits'] / total,
            'clean_rate': self.stats['clean'] / total,
            'error_rate': self.stats['errors'] / total
        }
    
    def reset_stats(self):
        """Reset statistics."""
        for key in self.stats:
            self.stats[key] = 0
    
    def get_layer_info(self) -> Dict:
        """Get information about each detection layer."""
        return {
            'layer_1_hash_db': {
                'name': 'Hash Database',
                'description': 'O(1) lookup of known malware hashes',
                'speed': 'instant',
                'status': 'active',
                'size': self.hash_db.stats['total_hashes']
            },
            'layer_2_yara': {
                'name': 'YARA Rules',
                'description': 'Pattern-based detection',
                'speed': '~50ms',
                'status': 'active' if self.yara.rules else 'inactive',
                'rules': len(self.yara.rule_files)
            },
            'layer_3_heuristic': {
                'name': 'Heuristic Analysis',
                'description': 'Static PE analysis',
                'speed': '~100ms',
                'status': 'active',
                'rules': len(self.heuristics.rules)
            },
            'layer_4_ml': {
                'name': 'ML Model',
                'description': 'Machine learning classification',
                'speed': '~10ms',
                'status': 'active' if self.ml_available else 'inactive',
                'model': 'LightGBM' if self.ml_available else 'none'
            }
        }


def quick_scan(file_path: str) -> Tuple[bool, str, float]:
    """
    Quick scan function for simple usage.
    
    Args:
        file_path: Path to file to scan
        
    Returns:
        Tuple of (is_malicious, source, confidence)
    """
    import hashlib
    
    # Calculate hash
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Create engine and scan
    engine = ProductionDecisionEngine()
    result = engine.decide(file_path, file_hash)
    
    is_malicious = result.verdict == Verdict.MALICIOUS
    return is_malicious, result.source, result.confidence


if __name__ == "__main__":
    # Test the decision engine
    print("=" * 60)
    print("Production Decision Engine Test")
    print("=" * 60)
    print()
    
    engine = ProductionDecisionEngine()
    print()
    
    # Show layer info
    print("Detection Layers:")
    for layer_id, layer_info in engine.get_layer_info().items():
        print(f"  {layer_info['name']}: {layer_info['status']} ({layer_info.get('size') or layer_info.get('rules', 'N/A')})")
    print()
    
    # Test on files
    test_cases = [
        ("EICAR Test", "44d88612fea8a8f36de82e1278abb02f", None),
    ]
    
    print("Test Results:")
    for name, file_hash, file_path in test_cases:
        result = engine.decide(file_path or "test.exe", file_hash)
        print(f"  {name}: {result.verdict.name} (source: {result.source}, confidence: {result.confidence:.2f})")
    
    print()
    print("Stats:", engine.get_stats())
