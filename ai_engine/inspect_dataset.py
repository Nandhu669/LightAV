"""
Dataset inspection utilities for LightAV.

This module provides functions to inspect and analyze dataset contents
for the malware detection engine.
"""

import pandas as pd


def inspect_dataset():
    """Inspect and analyze the dataset."""
    df = pd.read_csv("data/static_dataset.csv")
    
    print("=" * 60)
    print("DATASET INSPECTION REPORT")
    print("=" * 60)
    
    print(f"\nShape: {df.shape}")
    print(f"Columns:\n{df.columns.tolist()}")
    
    # Check for label column
    print("\n" + "=" * 60)
    print("LABEL COLUMN IDENTIFICATION")
    print("=" * 60)
    
    label_candidates = ['label', 'class', 'malware', 'target', 'Label', 'Class', 'Malware', 'Target']
    found_labels = [col for col in df.columns if col in label_candidates]
    
    if found_labels:
        print(f"\n[OK] Found label column(s): {found_labels}")
        for label_col in found_labels:
            print(f"\n  '{label_col}' unique values: {df[label_col].unique()}")
            print(f"  '{label_col}' value counts:")
            print(df[label_col].value_counts())
    else:
        print("\n[FAIL] No obvious label column found!")
        print("  Columns available:", df.columns.tolist())
    
    # Check if all other columns are numeric
    print("\n" + "=" * 60)
    print("DATA TYPE CHECK")
    print("=" * 60)
    
    non_numeric_cols = []
    numeric_cols = []
    
    for col in df.columns:
        if col in found_labels:
            continue
        if pd.api.types.is_numeric_dtype(df[col]):
            numeric_cols.append(col)
        else:
            non_numeric_cols.append(col)
    
    print(f"\n[OK] Numeric columns (excluding label): {len(numeric_cols)}")
    
    if non_numeric_cols:
        print(f"\n[WARN] Non-numeric columns found: {non_numeric_cols}")
        for col in non_numeric_cols:
            print(f"\n  '{col}' dtype: {df[col].dtype}")
            print(f"  '{col}' sample values: {df[col].head().tolist()}")
    else:
        print("\n[OK] All feature columns are numeric!")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if found_labels and not non_numeric_cols:
        print("\n[OK] Dataset is ready for ML training!")
        print(f"  Label column: {found_labels[0]}")
        print(f"  Number of features: {len(numeric_cols)}")
    else:
        print("\n[WARN] Dataset needs attention before training.")


def clean_dataset():
    """Remove non-feature columns and save cleaned dataset."""
    df = pd.read_csv("data/static_dataset.csv")
    
    print(f"Original shape: {df.shape}")
    print(f"Original columns: {len(df.columns)}")
    
    # Remove Hash_md5_Name column
    if 'Hash_md5_Name' in df.columns:
        df = df.drop(columns=['Hash_md5_Name'])
        print("\n[OK] Removed 'Hash_md5_Name' column")
    else:
        print("\n[INFO] 'Hash_md5_Name' column not found")
    
    print(f"\nNew shape: {df.shape}")
    print(f"New columns: {len(df.columns)}")
    
    # Save cleaned dataset
    df.to_csv("data/static_dataset.csv", index=False)
    print("\n[OK] Saved cleaned dataset to data/static_dataset.csv")
    
    return df


if __name__ == "__main__":
    clean_dataset()
    print("\n" + "=" * 60)
    print("Running inspection on cleaned dataset...")
    print("=" * 60 + "\n")
    inspect_dataset()