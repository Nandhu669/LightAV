"""
Dataset balancing utilities for LightAV.

This module provides functions to balance the dataset
to address class imbalance in malware detection.
"""

import numpy as np
from collections import Counter


def load_data():
    """Load the numpy arrays created by load_dataset.py"""
    X = np.load("X.npy")
    y = np.load("y.npy")
    return X, y


def undersample(X, y):
    """
    Undersample the majority class to balance the dataset.
    
    Args:
        X: Features array.
        y: Labels array.
        
    Returns:
        Tuple of (X_balanced, y_balanced).
    """
    # Find minority and majority classes
    class_counts = Counter(y)
    minority_class = min(class_counts, key=class_counts.get)
    majority_class = max(class_counts, key=class_counts.get)
    minority_count = class_counts[minority_class]
    
    # Get indices for each class
    minority_indices = np.where(y == minority_class)[0]
    majority_indices = np.where(y == majority_class)[0]
    
    # Randomly sample from majority class
    np.random.seed(42)
    sampled_majority_indices = np.random.choice(
        majority_indices, size=minority_count, replace=False
    )
    
    # Combine indices
    balanced_indices = np.concatenate([minority_indices, sampled_majority_indices])
    np.random.shuffle(balanced_indices)
    
    return X[balanced_indices], y[balanced_indices]


def balance_dataset():
    """Main function to balance and save the dataset."""
    X, y = load_data()
    
    print("Before balancing:")
    print(f"  X shape: {X.shape}")
    print(f"  y shape: {y.shape}")
    print(f"  Class distribution: {Counter(y)}")
    print(f"  Malware ratio: {y.mean():.4f}")
    
    X_balanced, y_balanced = undersample(X, y)
    
    print("\nAfter balancing (undersampling):")
    print(f"  X shape: {X_balanced.shape}")
    print(f"  y shape: {y_balanced.shape}")
    print(f"  Class distribution: {Counter(y_balanced)}")
    print(f"  Malware ratio: {y_balanced.mean():.4f}")
    
    # Save balanced dataset
    np.save("X_balanced.npy", X_balanced)
    np.save("y_balanced.npy", y_balanced)
    print("\n[OK] Saved X_balanced.npy and y_balanced.npy")
    
    return X_balanced, y_balanced


if __name__ == "__main__":
    balance_dataset()
