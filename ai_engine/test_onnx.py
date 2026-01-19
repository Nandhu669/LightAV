"""
Test ONNX model inference for LightAV.

This module tests the ONNX model with sample data
and measures inference performance.
"""

import numpy as np
import onnxruntime as ort
import time


def load_onnx_model(model_path: str = "lightgbm_static.onnx"):
    """Load the ONNX model."""
    session = ort.InferenceSession(model_path)
    print(f"[OK] Loaded ONNX model from {model_path}")
    return session


def predict(session, X: np.ndarray):
    """Run prediction using ONNX model."""
    input_name = session.get_inputs()[0].name
    X = X.astype(np.float32)
    result = session.run(None, {input_name: X})
    return result[0]  # Return predictions


def test_single_sample():
    """Test with a single sample."""
    print("\n" + "=" * 50)
    print("SINGLE SAMPLE TEST")
    print("=" * 50)
    
    session = load_onnx_model()
    X = np.load("X_balanced.npy")
    y = np.load("y_balanced.npy")
    
    # Test with single sample
    sample = X[0:1]
    pred = predict(session, sample)
    
    print(f"Input shape: {sample.shape}")
    print(f"Prediction: {pred[0]}")
    print(f"Actual label: {y[0]}")
    print(f"[{'OK' if pred[0] == y[0] else 'FAIL'}] Prediction correct!")


def test_batch():
    """Test with batch of samples."""
    print("\n" + "=" * 50)
    print("BATCH TEST")
    print("=" * 50)
    
    session = load_onnx_model()
    X = np.load("X_balanced.npy")
    y = np.load("y_balanced.npy")
    
    # Test with 100 samples
    batch = X[:100]
    labels = y[:100]
    
    pred = predict(session, batch)
    accuracy = (pred == labels).mean()
    
    print(f"Batch size: {len(batch)}")
    print(f"Accuracy: {accuracy * 100:.2f}%")


def benchmark_inference():
    """Benchmark inference speed."""
    print("\n" + "=" * 50)
    print("INFERENCE BENCHMARK")
    print("=" * 50)
    
    session = load_onnx_model()
    X = np.load("X_balanced.npy")
    
    # Warmup
    _ = predict(session, X[:10])
    
    # Single sample benchmark
    sample = X[0:1]
    times = []
    for _ in range(100):
        start = time.perf_counter()
        _ = predict(session, sample)
        times.append(time.perf_counter() - start)
    
    avg_single = np.mean(times) * 1000
    print(f"Single sample inference: {avg_single:.3f} ms")
    
    # Batch benchmark
    batch = X[:100]
    times = []
    for _ in range(20):
        start = time.perf_counter()
        _ = predict(session, batch)
        times.append(time.perf_counter() - start)
    
    avg_batch = np.mean(times) * 1000
    print(f"Batch (100 samples) inference: {avg_batch:.3f} ms")
    print(f"Per sample in batch: {avg_batch / 100:.3f} ms")


def test_all():
    """Run all tests."""
    test_single_sample()
    test_batch()
    benchmark_inference()
    print("\n[OK] All tests completed!")


if __name__ == "__main__":
    test_all()
