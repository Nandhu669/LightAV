"""
ONNX inference wrapper for LightAV static analysis model.

The model is a binary LGBMClassifier (n_classes_=1) converted via onnxmltools.
ONNX outputs:
  - out[0]: 'label'         — has a shape bug from onnxmltools, DO NOT USE
  - out[1]: 'probabilities' — list of {class_id: raw_logit} dicts

Since the model is binary with a single logit output, we apply sigmoid to get
the malware probability, then threshold at 0.5.

Prediction rule:  malware_prob = sigmoid(logit)
                  label = 1 (malware) if malware_prob >= threshold else 0 (benign)
"""

import os
import numpy as np
import onnxruntime as ort
import joblib


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x.astype(np.float64)))


class StaticONNXModel:
    def __init__(self, model_path: str, scaler_path: str = None, threshold: float = 0.5):
        """
        Args:
            model_path:  Absolute path to the .onnx model file.
            scaler_path: Path to companion _scaler.pkl. Auto-detected if None.
            threshold:   Malware probability threshold (default 0.5).
        """
        self.session      = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
        self.input_name   = self.session.get_inputs()[0].name
        self.feature_count = self.session.get_inputs()[0].shape[1]
        self.threshold    = threshold

        # Auto-detect companion scaler
        if scaler_path is None:
            scaler_path = model_path.replace(".onnx", "_scaler.pkl")
        self.scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None

    def _scale(self, features: np.ndarray) -> np.ndarray:
        if self.scaler is not None:
            return self.scaler.transform(features).astype(np.float32)
        return features.astype(np.float32)

    def predict(self, features: np.ndarray) -> np.ndarray:
        """
        Predict class labels.

        Args:
            features: Raw (unscaled) numpy array of shape (N, feature_count)
                      OR (feature_count,) for a single sample.
        Returns:
            int ndarray of shape (N,) with values 0 (benign) or 1 (malware).
        """
        return (self.predict_proba(features) >= self.threshold).astype(int)

    def predict_proba(self, features: np.ndarray) -> np.ndarray:
        """
        Return malware probability for each sample.

        Args:
            features: Raw (unscaled) numpy array of shape (N, feature_count).
        Returns:
            float32 array of shape (N,) — P(malware) for each sample.
        """
        if features.ndim == 1:
            features = features.reshape(1, -1)
        if features.shape[1] != self.feature_count:
            raise ValueError(
                f"Feature mismatch: expected {self.feature_count}, got {features.shape[1]}"
            )
        scaled  = self._scale(features)
        outputs = self.session.run(None, {self.input_name: scaled})

        # out[1] = list of {class_id: logit}  (binary model → single logit key)
        prob_dicts = outputs[1]
        logits = np.array([list(d.values())[0] for d in prob_dicts], dtype=np.float64)
        return _sigmoid(logits).astype(np.float32)
