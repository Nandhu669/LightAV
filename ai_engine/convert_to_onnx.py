"""
Convert LightGBM model to ONNX format for LightAV.

This module converts the trained LightGBM model to ONNX
for faster inference and cross-platform compatibility.
"""

import joblib
import numpy as np
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType
import onnxruntime as ort


def convert_to_onnx(model_path: str = "lightgbm_static_balanced.pkl",
                    output_path: str = "lightgbm_static.onnx",
                    num_features: int = 77):
    """
    Convert LightGBM model to ONNX format.
    
    Args:
        model_path: Path to the trained LightGBM model (.pkl).
        output_path: Path to save the ONNX model.
        num_features: Number of input features.
    """
    # Load the model
    model = joblib.load(model_path)
    print(f"[OK] Loaded model from {model_path}")
    
    # Define input type
    initial_type = [('float_input', FloatTensorType([None, num_features]))]
    
    # Convert to ONNX using onnxmltools
    onnx_model = convert_lightgbm(
        model,
        initial_types=initial_type,
        target_opset=12
    )
    
    # Save the ONNX model
    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    
    print(f"[OK] Saved ONNX model to {output_path}")
    
    return onnx_model


def verify_onnx_model(onnx_path: str = "lightgbm_static.onnx",
                      pkl_path: str = "lightgbm_static_balanced.pkl"):
    """
    Verify ONNX model produces same results as original.
    
    Args:
        onnx_path: Path to the ONNX model.
        pkl_path: Path to the original model.
    """
    # Load test data
    X = np.load("X_balanced.npy")
    X_sample = X[:10].astype(np.float32)
    
    # Original model prediction
    original_model = joblib.load(pkl_path)
    original_pred = original_model.predict(X_sample)
    
    # ONNX model prediction
    sess = ort.InferenceSession(onnx_path)
    input_name = sess.get_inputs()[0].name
    onnx_pred = sess.run(None, {input_name: X_sample})[0]
    
    # Compare
    match = np.array_equal(original_pred, onnx_pred)
    print(f"\nVerification:")
    print(f"  Original predictions: {original_pred}")
    print(f"  ONNX predictions:     {onnx_pred}")
    print(f"  [{'OK' if match else 'FAIL'}] Predictions {'match' if match else 'do not match'}!")
    
    return match


if __name__ == "__main__":
    convert_to_onnx()
    verify_onnx_model()
