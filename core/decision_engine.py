"""
Production Decision Engine
4-layer detection: Hash → YARA → Heuristic → ML (with early exit)
"""

import logging
import math
from collections import Counter

# Structured security logger for fail-closed error events
_security_logger = logging.getLogger("lightav.decision_engine")
if not _security_logger.handlers:
    import os
    from pathlib import Path as _LogPath
    _log_dir = _LogPath(__file__).parent.parent / "logs"
    _log_dir.mkdir(exist_ok=True)
    _handler = logging.FileHandler(_log_dir / "decision_errors.log", encoding="utf-8")
    _handler.setFormatter(logging.Formatter('%(message)s'))
    _security_logger.addHandler(_handler)
    _security_logger.setLevel(logging.WARNING)

import numpy as np
from pathlib import Path
from typing import Tuple, Optional, Dict
from dataclasses import dataclass

from core.hash_database import HashDatabase
from core.yara_engine import YARAEngine
from core.heuristic_engine import EnhancedHeuristicEngine
from core.whitelist import WhitelistDB
from core.decision_types import Verdict
from ai.feature_extractor import extract_features
from ai.production_extractor import extract_production_features


@dataclass
class DetectionResult:
    """Complete detection result with all details."""
    verdict: Verdict
    source: str
    confidence: float
    details: Dict
    scan_time_ms: float


class _LayerTracker:
    """
    Lightweight in-memory tracker for per-layer detection statistics.

    Records two things:
      1. Aggregate counters per layer (O(1) per scan, no disk I/O).
      2. Per-file structured log entries (capped at MAX_FILE_LOG entries
         to bound memory; oldest entries are discarded when full).

    Flushes both to ``results/layer_stats.json`` on demand or every
    ``flush_interval`` scans.
    """

    # Upper bound on in-memory per-file log to prevent unbounded growth
    MAX_FILE_LOG = 10_000

    # Human-readable layer names for the per-file log
    _LAYER_NAMES = {
        -1: "cache",
        0: "whitelist",
        1: "hash_db",
        2: "yara",
        3: "heuristic",
        4: "ml",
    }

    def __init__(self, output_path: str = None, flush_interval: int = 100):
        from pathlib import Path as _P
        self._output_path = output_path or str(
            _P(__file__).parent.parent / "results" / "layer_stats.json"
        )
        self._flush_interval = flush_interval
        self._scan_count = 0
        self._stats = {
            "layer_0_whitelist": 0,
            "layer_1_hash": 0,
            "layer_2_yara": 0,
            "layer_3_heuristic": 0,
            "layer_4_ml": 0,
            "clean": 0,
            "error": 0,
            "cache": 0,
        }
        # Per-layer confidence accumulators (for average calculation)
        self._confidence_sums = {k: 0.0 for k in self._stats}
        # Per-file structured log
        self._file_log: list = []

    def record(self, layer: int, confidence: float, verdict_name: str,
               source: str, file_path: str = ""):
        """Record one detection event. O(1), no disk I/O."""
        key = self._layer_key(layer, source)
        self._stats[key] = self._stats.get(key, 0) + 1
        self._confidence_sums[key] = self._confidence_sums.get(key, 0.0) + confidence
        self._scan_count += 1

        # Per-file entry (bounded list)
        if len(self._file_log) < self.MAX_FILE_LOG:
            import os as _os
            self._file_log.append({
                "file": _os.path.basename(file_path) if file_path else "",
                "layer": self._LAYER_NAMES.get(layer, source),
                "confidence": round(confidence, 4),
                "verdict": verdict_name.lower(),
            })

        # Auto-flush periodically (lightweight: only every N scans)
        if self._scan_count % self._flush_interval == 0:
            self.flush()

    def _layer_key(self, layer: int, source: str) -> str:
        if source == "cache":
            return "cache"
        if source == "error":
            return "error"
        mapping = {
            0: "layer_0_whitelist",
            1: "layer_1_hash",
            2: "layer_2_yara",
            3: "layer_3_heuristic",
            4: "layer_4_ml",
        }
        return mapping.get(layer, "clean")

    def get_stats(self) -> Dict:
        """Return current layer statistics with average confidence."""
        result = dict(self._stats)
        result["total_scanned"] = self._scan_count
        # Compute average confidence per layer
        avg_conf = {}
        for k, total in self._stats.items():
            if total > 0:
                avg_conf[k] = round(self._confidence_sums[k] / total, 4)
            else:
                avg_conf[k] = 0.0
        result["avg_confidence"] = avg_conf
        return result

    def get_file_log(self) -> list:
        """Return the per-file structured log entries."""
        return list(self._file_log)

    def flush(self):
        """Write aggregate stats and per-file log to JSON file."""
        import json as _json
        import os as _os
        _os.makedirs(_os.path.dirname(self._output_path) or ".", exist_ok=True)
        output = {
            "summary": self.get_stats(),
            "file_log": self._file_log,
        }
        with open(self._output_path, "w", encoding="utf-8") as f:
            _json.dump(output, f, indent=2)

    def reset(self):
        """Reset all counters and per-file log."""
        for k in self._stats:
            self._stats[k] = 0
            self._confidence_sums[k] = 0.0
        self._scan_count = 0
        self._file_log.clear()


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

        # Lightweight layer-level detection tracker
        self._layer_tracker = _LayerTracker()
        
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
        # Decision thresholds - matched to realistic max possible normalized scores
        self.heuristic_low_threshold = 15
        self.heuristic_medium_threshold = 25
        self.heuristic_high_threshold = 45
        
        # Entropy pre-filter thresholds
        self.entropy_suspicious_threshold = self.config.get('entropy_suspicious_threshold', 7.0)
        self.entropy_high_threshold = self.config.get('entropy_high_threshold', 7.5)
        self.entropy_yara_reduction = self.config.get('entropy_yara_reduction', 0.15)
        self.entropy_heuristic_boost = self.config.get('entropy_heuristic_boost', 15)
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'hash_hits': 0,
            'yara_hits': 0,
            'heuristic_hits': 0,
            'ml_hits': 0,
            'clean': 0,
            'errors': 0,
            'entropy_boosts': 0
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
            "data/models/lightgbm_static.onnx",
            "data/models/lightgbm_custom_v1.onnx",
        ]
        
        # Load scaler
        self.scaler = None
        scaler_path = "data/models/scaler.pkl"
        if Path(scaler_path).exists():
            import joblib
            try:
                self.scaler = joblib.load(scaler_path)
                print(f"[DecisionEngine] Loaded feature scaler: {scaler_path}")
            except Exception as e:
                print(f"[DecisionEngine] Failed to load scaler: {e}")
        
        for model_path in existing_model_paths:
            if Path(model_path).exists():
                try:
                    from ai.model_infer import StaticONNXModel
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
                self._layer_tracker.record(-1, 1.0, Verdict(cached_verdict).name, "cache", file_path)
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
                wl_conf = whitelist_info.get('confidence', 1.0) if whitelist_info else 1.0
                self._layer_tracker.record(0, wl_conf, "BENIGN", "whitelist", file_path)
                return DetectionResult(
                    verdict=Verdict.BENIGN,
                    source="whitelist",
                    confidence=wl_conf,
                    details={'layer': 0, 'whitelist_info': whitelist_info},
                    scan_time_ms=(time.time() - start_time) * 1000
                )
            
            # Layer 1: Hash Database (fastest, O(1))
            if self.hash_db.contains(file_hash):
                self.stats['hash_hits'] += 1
                details = self.hash_db.lookup_details(file_hash) or {}
                self._layer_tracker.record(1, 1.0, "MALICIOUS", "hash_db", file_path)
                return DetectionResult(
                    verdict=Verdict.MALICIOUS,
                    source="hash_db",
                    confidence=1.0,
                    details={**details, 'layer': 1},
                    scan_time_ms=(time.time() - start_time) * 1000
                )
            
            # Entropy pre-filter (between Layer 1 and Layer 2)
            # Computes whole-file Shannon entropy once. High entropy
            # (> 7.0) indicates packed, compressed, or encrypted content.
            # This does NOT add a detection layer — it biases the YARA and
            # heuristic thresholds so subsequent layers are more sensitive
            # to high-entropy files.
            file_entropy = 0.0
            entropy_boost = 0
            effective_yara_threshold = self.yara_confidence_threshold
            try:
                with open(file_path, 'rb') as f:
                    raw_bytes = f.read()
                if raw_bytes:
                    byte_counts = Counter(raw_bytes)
                    length = len(raw_bytes)
                    file_entropy = -sum(
                        (c / length) * math.log2(c / length)
                        for c in byte_counts.values() if c > 0
                    )
                
                if file_entropy >= self.entropy_high_threshold:
                    # Very high entropy: strong packing/encryption signal
                    entropy_boost = self.entropy_heuristic_boost
                    effective_yara_threshold = max(
                        0.5, self.yara_confidence_threshold - self.entropy_yara_reduction
                    )
                    self.stats['entropy_boosts'] += 1
                elif file_entropy >= self.entropy_suspicious_threshold:
                    # Moderately high entropy: mild suspicion signal
                    entropy_boost = self.entropy_heuristic_boost // 2
                    effective_yara_threshold = max(
                        0.6, self.yara_confidence_threshold - (self.entropy_yara_reduction / 2)
                    )
                    self.stats['entropy_boosts'] += 1
            except (OSError, PermissionError):
                pass  # Cannot read file; proceed with default thresholds
            
            # Layer 2: YARA Rules
            yara_matches = self.yara.scan(file_path)
            if yara_matches:
                yara_confidence = self.yara.get_confidence(yara_matches)
                if yara_confidence >= effective_yara_threshold:
                    self.stats['yara_hits'] += 1
                    self._layer_tracker.record(2, yara_confidence, "MALICIOUS", "yara", file_path)
                    return DetectionResult(
                        verdict=Verdict.MALICIOUS,
                        source="yara",
                        confidence=yara_confidence,
                        details={
                            'layer': 2,
                            'matches': self.yara.get_match_details(yara_matches),
                            'file_entropy': round(file_entropy, 3),
                            'entropy_boosted': entropy_boost > 0
                        },
                        scan_time_ms=(time.time() - start_time) * 1000
                    )
            
            # Layer 3: Heuristic Analysis
            features = extract_features(file_path)
            heuristic_result = self.heuristics.analyze(file_path, features)
            
            # Apply entropy boost to heuristic score
            boosted_score = heuristic_result.score + entropy_boost
            
            if boosted_score >= self.heuristic_high_threshold:
                self.stats['heuristic_hits'] += 1
                self._layer_tracker.record(3, heuristic_result.confidence, "MALICIOUS", "heuristic", file_path)
                return DetectionResult(
                    verdict=Verdict.MALICIOUS,
                    source="heuristic",
                    confidence=heuristic_result.confidence,
                    details={
                        'layer': 3,
                        'score': heuristic_result.score,
                        'entropy_boost': entropy_boost,
                        'boosted_score': boosted_score,
                        'file_entropy': round(file_entropy, 3),
                        'triggers': heuristic_result.triggers
                    },
                    scan_time_ms=(time.time() - start_time) * 1000
                )
            
            # Layer 4: ML Model (only if medium suspicion and ML available)
            # Uses boosted_score so high-entropy files are more likely to reach ML
            if (boosted_score >= self.heuristic_medium_threshold and 
                self.ml_available and self.ml_model):
                
                ml_prediction = self._run_ml_model(file_path, features)
                if ml_prediction >= self.confidence_threshold:
                    self.stats['ml_hits'] += 1
                    self._layer_tracker.record(4, ml_prediction, "MALICIOUS", "ml", file_path)
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
            self._layer_tracker.record(-1, 1.0, "BENIGN", "clean", file_path)
            return DetectionResult(
                verdict=Verdict.BENIGN,
                source="clean",
                confidence=1.0,
                details={
                    'heuristic_score': heuristic_result.score if 'heuristic_result' in locals() else 0,
                    'boosted_score': boosted_score if 'boosted_score' in locals() else 0,
                    'file_entropy': round(file_entropy, 3) if 'file_entropy' in locals() else 0,
                    'yara_matches': len(yara_matches) if 'yara_matches' in locals() else 0
                },
                scan_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            self.stats['errors'] += 1

            # --- FAIL-CLOSED: treat any scan error as suspicious ---
            # Determine which detection layer was active when the failure occurred
            if 'heuristic_result' in locals():
                failed_layer = "ml (layer 4)"
            elif 'features' in locals():
                failed_layer = "heuristic (layer 3)"
            elif 'yara_matches' in locals():
                failed_layer = "heuristic/yara-post (layer 2-3)"
            else:
                failed_layer = "hash/yara (layer 1-2)"

            # Structured security log
            import json as _json
            _security_logger.warning(_json.dumps({
                "event": "fail_closed_triggered",
                "file_path": str(file_path),
                "error_type": type(e).__name__,
                "error_message": str(e),
                "failed_layer": failed_layer,
                "verdict": "SUSPICIOUS",
                "confidence": 0.6,
                "quarantine": True
            }))

            self._layer_tracker.record(-1, 0.6, "SUSPICIOUS", "error", file_path)
            return DetectionResult(
                verdict=Verdict.SUSPICIOUS,  # Fail-CLOSED
                source="error",
                confidence=0.6,
                details={
                    'error': str(e),
                    'error_type': type(e).__name__,
                    'failed_layer': failed_layer,
                    'quarantine': True
                },
                scan_time_ms=(time.time() - start_time) * 1000
            )
    
    def _run_ml_model(self, file_path: str, features: np.ndarray) -> float:
        """
        Run ML model prediction using 77 production features and scaler.
        """
        if not self.ml_available:
            return 0.0
        
        try:
            # Extract full 77 production features
            prod_features = extract_production_features(file_path)
            if prod_features is None:
                # Feature extraction returned None — default to safe score
                return 0.0
                
            # Prepare features
            feat_array = prod_features.reshape(1, -1)
            
            # Apply scaler if available
            if self.scaler:
                feat_array = self.scaler.transform(feat_array)
            
            # Model inference
            model_input = feat_array.astype(np.float32)
            
            # Use predict_proba to get raw confidence score, instead of predict which returns 0/1
            prediction = self.ml_model.predict_proba(model_input)[0]
            
            # Class 1 probability (malware)
            return float(prediction)
        except Exception as e:
            # Let the error propagate to the main fail-closed handler
            raise RuntimeError(f"ML prediction failed: {e}") from e
    
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
        self._layer_tracker.reset()

    def get_layer_stats(self) -> Dict:
        """Return per-layer detection counts and average confidence."""
        return self._layer_tracker.get_stats()

    def save_layer_stats(self):
        """Flush current layer stats to results/layer_stats.json."""
        self._layer_tracker.flush()
    
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
    print()
    print("Stats:", engine.get_stats())


# ── Module-level helpers (replaces old agent/decision_engine.py shim) ──

_engine_singleton: Optional[ProductionDecisionEngine] = None


def get_engine() -> ProductionDecisionEngine:
    """Return (and lazily create) the singleton ProductionDecisionEngine."""
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = ProductionDecisionEngine()
    return _engine_singleton


def decide(file_path: str) -> Verdict:
    """
    Convenience wrapper: scan *file_path* and return a Verdict.

    Reuses the module-level engine singleton so callers don't need to
    manage engine lifecycle.
    """
    import hashlib
    engine = get_engine()
    with open(file_path, "rb") as fh:
        file_hash = hashlib.sha256(fh.read()).hexdigest()
    result = engine.decide(file_path, file_hash)
    return result.verdict
