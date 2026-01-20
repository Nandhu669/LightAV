import numpy as np
import os

def load_dataset(data_dir=None):
    """
    Load dataset from .npy files.
    
    Args:
        data_dir: Optional directory path. If None, uses project root.
    
    Returns:
        X: Feature array
        y: Label array
    """
    if data_dir is None:
        # Default to project root (LightAV-Python)
        data_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    X_path = os.path.join(data_dir, "X_balanced.npy")
    y_path = os.path.join(data_dir, "y_balanced.npy")
    
    # Fall back to non-balanced if balanced doesn't exist
    if not os.path.exists(X_path):
        X_path = os.path.join(data_dir, "X.npy")
        y_path = os.path.join(data_dir, "y.npy")
    
    X = np.load(X_path)
    y = np.load(y_path)
    
    X = X.astype("float32")
    y = y.astype("float32")
    
    print(f"[OK] Loaded dataset: X shape = {X.shape}, y shape = {y.shape}")
    
    return X, y
