"""
LightAV Model Training Pipeline
================================
Trains a LightGBM classifier on 77 PE structural features and exports to ONNX.

Benign samples  : Real Windows PE files from System32 / Program Files
Malware samples : Real files from data/malware/ (if available)
                  + Synthetic malware-like feature patterns (always generated)

The synthetic malware generator creates feature vectors that mimic malware
characteristics observed in the wild:
  - High section entropy (packed/encrypted payloads)
  - Suspicious API imports
  - Non-standard section names
  - Unusual TimeDateStamp values
  - Missing or small data directories

Usage:
    python train_lightav_model.py                   # Auto mode (System32 benign + synthetic)
    python train_lightav_model.py --malware data/malware  # Use real malware samples too
    python train_lightav_model.py --limit 2000      # Cap samples per class
"""

import os
import sys
import time
import argparse
import warnings
import numpy as np
import joblib
from pathlib import Path

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# 0. Imports
# ─────────────────────────────────────────────────────────────────────────────
try:
    import lightgbm as lgb
    from sklearn.model_selection import train_test_split, StratifiedKFold
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix
    )
    from sklearn.preprocessing import StandardScaler
except ImportError:
    sys.exit("ERROR: Run `pip install lightgbm scikit-learn` first.")

try:
    import onnxmltools
    from onnxmltools.convert import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    print("WARNING: onnxmltools not found. ONNX export will be skipped.")

try:
    import pefile
except ImportError:
    sys.exit("ERROR: Run `pip install pefile` first.")

# Script lives in LightAV-Python root
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "prod_extractor",
    ROOT / "production" / "ai_engine" / "production_extractor.py"
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
extract_production_features = _mod.extract_production_features

NUM_FEATURES = 77

# ─────────────────────────────────────────────────────────────────────────────
# 1. Benign sample collection
# ─────────────────────────────────────────────────────────────────────────────

BENIGN_ROOTS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
]

BENIGN_EXTENSIONS = {".exe", ".dll"}


def collect_benign_files(limit: int = 3000) -> list:
    """Walk System32 / SysWOW64 and collect PE file paths."""
    found = []
    for root in BENIGN_ROOTS:
        if not os.path.isdir(root):
            continue
        for fname in os.listdir(root):
            ext = Path(fname).suffix.lower()
            if ext not in BENIGN_EXTENSIONS:
                continue
            found.append(os.path.join(root, fname))
            if len(found) >= limit:
                return found
    return found


def extract_benign_features(paths: list) -> np.ndarray:
    """Extract 77-feature vectors from a list of PE paths."""
    vectors = []
    ok = 0
    fail = 0
    for i, path in enumerate(paths, 1):
        if i % 100 == 0:
            print(f"  Benign: {i}/{len(paths)} processed  (ok={ok}, fail={fail})")
        feat = extract_production_features(path)
        if feat is not None and len(feat) == NUM_FEATURES:
            vectors.append(feat)
            ok += 1
        else:
            fail += 1
    print(f"  Benign extraction done: {ok} ok, {fail} failed")
    return np.array(vectors, dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Real malware sample collection (if available)
# ─────────────────────────────────────────────────────────────────────────────

def collect_malware_files(malware_dir: str, limit: int = 3000) -> list:
    if not malware_dir or not os.path.isdir(malware_dir):
        return []
    paths = []
    for root, _, files in os.walk(malware_dir):
        for f in files:
            paths.append(os.path.join(root, f))
            if len(paths) >= limit:
                break
        if len(paths) >= limit:
            break
    return paths


def extract_malware_features(paths: list) -> np.ndarray:
    vectors = []
    ok = 0
    fail = 0
    for i, path in enumerate(paths, 1):
        if i % 100 == 0:
            print(f"  Malware: {i}/{len(paths)} processed  (ok={ok}, fail={fail})")
        feat = extract_production_features(path)
        if feat is not None and len(feat) == NUM_FEATURES:
            vectors.append(feat)
            ok += 1
        else:
            fail += 1
    print(f"  Malware extraction done: {ok} ok, {fail} failed")
    return np.array(vectors, dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Synthetic malware feature generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_synthetic_malware(n: int, rng: np.random.Generator) -> np.ndarray:
    """
    Generate n synthetic malware-like 77-feature vectors.

    The generator draws from realistic malware feature distributions
    based on published research (e.g. EMBER dataset statistics):

    Feature index reference (mirrors production_extractor.py):
      0-16:  DOS Header
      17-23: File Header
      24-51: Optional Header
      52:    (label slot — set to 0, ignored)
      53:    SuspiciousImportFunctions  ← HIGH in malware
      54:    SuspiciousNameSection      ← HIGH in malware
      55:    SectionsLength             ← varies
      56-57: Min/Max section entropy    ← MAX very high in packed malware
      58-65: Raw/Virtual section sizes
      66-67: PointerToRawData stats
      68-69: Section characteristics
      70-71: Import directory counts
      72:    Export count
      73-76: Data directory sizes
    """
    samples = []

    for _ in range(n):
        v = np.zeros(NUM_FEATURES, dtype=np.float32)

        # ── DOS Header (indices 0-16) ────────────────────────────────
        v[0]  = 23117                            # e_magic  (MZ) — always same
        v[1]  = rng.integers(80, 200)            # e_cblp
        v[2]  = rng.integers(1, 5)               # e_cp
        v[3]  = 0
        v[4]  = rng.integers(2, 8)               # e_cparhdr
        v[5]  = 0
        v[6]  = rng.integers(0, 65535)           # e_maxalloc — malware sometimes maxed
        v[7]  = 0
        v[8]  = rng.integers(128, 512)           # e_sp
        v[9]  = 0                                # e_csum
        v[10] = 0                                # e_ip
        v[11] = 0                                # e_cs
        v[12] = rng.integers(60, 80)             # e_lfarlc
        v[13] = 0
        v[14] = 0
        v[15] = 0
        v[16] = rng.integers(120, 300)           # e_lfanew — malware often larger

        # ── File Header (indices 17-23) ──────────────────────────────
        v[17] = rng.choice([332, 34404])         # Machine: x86 or x64
        v[18] = rng.integers(1, 12)              # NumberOfSections — malware avg higher
        # Malware: old/fake timestamps (0 or future or very old)
        v[19] = rng.choice([
            0,
            rng.integers(1, 1000000),            # very old (pre-2000)
            rng.integers(2000000000, 2147483647) # far future
        ])
        v[20] = 0
        v[21] = 0
        v[22] = rng.choice([224, 240])           # SizeOfOptionalHeader
        # Characteristics — malware often has unusual flags
        v[23] = rng.choice([258, 274, 778, 34])

        # ── Optional Header (indices 24-51) ──────────────────────────
        v[24] = rng.choice([267, 523])           # Magic: PE32 or PE32+
        v[25] = rng.integers(0, 15)              # MajorLinkerVersion
        v[26] = rng.integers(0, 99)              # MinorLinkerVersion
        # SizeOfCode — malware can be very small (stub) or very large (packed)
        v[27] = rng.choice([
            rng.integers(512, 4096),
            rng.integers(100000, 5000000)
        ])
        v[28] = rng.integers(512, 500000)        # SizeOfInitializedData
        v[29] = rng.integers(0, 10000)           # SizeOfUninitializedData
        v[30] = rng.integers(4096, 200000)       # AddressOfEntryPoint
        v[31] = rng.integers(4096, 65536)        # BaseOfCode
        # ImageBase — malware often non-standard
        v[32] = rng.choice([4194304, 65536, rng.integers(1000000, 10000000)])
        v[33] = rng.choice([4096, 8192, 512])    # SectionAlignment
        v[34] = rng.choice([512, 4096, 256])     # FileAlignment
        v[35] = rng.integers(4, 11)              # MajorOperatingSystemVersion
        v[36] = 0
        v[37] = rng.integers(0, 11)              # MajorImageVersion
        v[38] = 0
        v[39] = rng.integers(4, 11)              # MajorSubsystemVersion
        v[40] = 0
        v[41] = rng.integers(512, 65536)         # SizeOfHeaders
        v[42] = rng.choice([0, rng.integers(1000, 5000000)])  # CheckSum (often 0)
        v[43] = rng.integers(100000, 30000000)   # SizeOfImage
        v[44] = rng.integers(1, 4)               # Subsystem
        # DllCharacteristics — malware often 0 (missing mitigations)
        v[45] = rng.choice([0, 32768, 256, 64])
        v[46] = rng.choice([1048576, 262144, 131072])  # SizeOfStackReserve
        v[47] = rng.choice([4096, 16384, 65536])       # SizeOfStackCommit
        v[48] = rng.choice([1048576, 268435456])        # SizeOfHeapReserve
        v[49] = rng.choice([4096, 16384])               # SizeOfHeapCommit
        v[50] = 0                                        # LoaderFlags
        v[51] = 16                                       # NumberOfRvaAndSizes

        # index 52: label slot → 0 (ignored at inference)
        v[52] = 0

        # ── Structural Features (indices 53-76) ──────────────────────

        # 53: SuspiciousImportFunctions — malware: 2-8, benign: 0-2
        v[53] = rng.integers(2, 9)

        # 54: SuspiciousNameSection — malware: 1-8 non-standard section names
        v[54] = rng.integers(1, 9)

        # 55: SectionsLength  (total sections count)
        v[55] = rng.integers(1, 12)

        # 56: Min section entropy
        v[56] = rng.uniform(0.5, 3.5)

        # 57: Max section entropy — KEY malware signal: packed = > 6.5
        v[57] = rng.uniform(6.0, 8.0)

        # 58: Min raw size
        v[58] = rng.integers(0, 4096)
        # 59: Max raw size
        v[59] = rng.integers(4096, 5000000)
        # 60: Min virtual size
        v[60] = rng.integers(0, 8192)
        # 61: Max virtual size
        v[61] = rng.integers(4096, 10000000)

        # 62-65: dup stats (max/min raw/virtual)
        v[62] = v[59]
        v[63] = v[58]
        v[64] = v[61]
        v[65] = v[60]

        # 66-67: PointerToRawData max/min
        v[66] = rng.integers(512, 1000000)
        v[67] = rng.integers(512, 10000)

        # 68-69: Section characteristics
        v[68] = rng.choice([3221225472, 1610612736, 3758096384])
        v[69] = rng.choice([1610612736, 2684354560, 3221225472])

        # 70: Import DLL count — malware: often low (few DLLs, many funcs by name hidden)
        v[70] = rng.integers(0, 5)
        # 71: Total import function count
        v[71] = rng.integers(0, 30)

        # 72: Export count — malware often 0
        v[72] = rng.integers(0, 2)

        # 73-76: Data directory sizes
        v[73] = rng.integers(0, 500)           # Export dir size
        v[74] = rng.integers(0, 5000)          # Import dir size
        v[75] = rng.integers(0, 20000)         # Resource dir
        v[76] = 0                              # Security dir (usually 0 in malware)

        samples.append(v)

    return np.array(samples, dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Model training
# ─────────────────────────────────────────────────────────────────────────────

def train_model(X: np.ndarray, y: np.ndarray):
    """Train LightGBM and return (model, scaler, metrics)."""
    print(f"\n[Train] Dataset shape: {X.shape}")
    unique, counts = np.unique(y, return_counts=True)
    for u, c in zip(unique, counts):
        label = "benign" if u == 0 else "malware"
        print(f"  Class {u} ({label}): {c} samples")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[Train] Train={len(X_train)}, Test={len(X_test)}")

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    model = lgb.LGBMClassifier(
        objective="binary",
        boosting_type="gbdt",
        n_estimators=300,
        num_leaves=63,
        max_depth=8,
        learning_rate=0.05,
        feature_fraction=0.8,
        bagging_fraction=0.8,
        bagging_freq=5,
        min_child_samples=20,
        reg_alpha=0.1,
        reg_lambda=0.1,
        class_weight="balanced",
        random_state=42,
        verbose=-1,
        n_jobs=-1,
    )

    print("[Train] Fitting LightGBM …")
    t0 = time.time()
    model.fit(X_train_s, y_train)
    elapsed = time.time() - t0
    print(f"[Train] Fit complete in {elapsed:.1f}s")

    y_pred      = model.predict(X_test_s)
    y_pred_prob = model.predict_proba(X_test_s)[:, 1]

    metrics = {
        "accuracy":  accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred, zero_division=0),
        "recall":    recall_score(y_test, y_pred, zero_division=0),
        "f1":        f1_score(y_test, y_pred, zero_division=0),
        "auc":       roc_auc_score(y_test, y_pred_prob),
    }

    cm = confusion_matrix(y_test, y_pred)

    return model, scaler, metrics, cm


# ─────────────────────────────────────────────────────────────────────────────
# 5. ONNX export
# ─────────────────────────────────────────────────────────────────────────────

def export_onnx(model, output_path: str) -> bool:
    """Export trained LGBMClassifier → ONNX. Returns True on success."""
    if not ONNX_AVAILABLE:
        print("[ONNX] Skipping (onnxmltools not installed)")
        return False
    try:
        initial_types = [("float_input", FloatTensorType([None, NUM_FEATURES]))]
        onnx_model = convert_lightgbm(
            model,
            initial_types=initial_types,
            target_opset=12,
        )
        import onnx as _onnx
        _onnx.save_model(onnx_model, output_path)
        print(f"[ONNX] Exported → {output_path}")
        return True
    except Exception as e:
        print(f"[ONNX] Export failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 6. Quick validation after export
# ─────────────────────────────────────────────────────────────────────────────

def validate_onnx(onnx_path: str):
    """Run sanity checks on the exported model against real System32 binaries."""
    try:
        import onnxruntime as ort
    except ImportError:
        print("[Validate] onnxruntime not found — skipping validation")
        return

    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    in_name = sess.get_inputs()[0].name

    test_files = [
        (r"C:\Windows\System32\notepad.exe", "benign"),
        (r"C:\Windows\System32\calc.exe",    "benign"),
        (r"C:\Windows\System32\cmd.exe",     "benign"),
        (r"C:\Windows\System32\taskmgr.exe", "benign"),
    ]

    print("\n[Validate] Running ONNX model on real Windows binaries:")
    all_ok = True
    for path, expected in test_files:
        if not os.path.exists(path):
            continue
        feat = extract_production_features(path)
        if feat is None:
            print(f"  {os.path.basename(path)}: extraction failed")
            continue
        out = sess.run(None, {in_name: feat.reshape(1, -1).astype(np.float32)})
        prob_dict = out[1][0]
        # prob_dict can be {0: p_benign, 1: p_malware} OR a two-element list
        if isinstance(prob_dict, dict):
            p_mal = prob_dict.get(1, list(prob_dict.values())[-1])
        else:
            p_mal = float(prob_dict[1])
        label    = "MALWARE" if p_mal >= 0.5 else "BENIGN"
        ok_str   = "✓" if label == expected.upper() else "✗  ← WRONG"
        if label != expected.upper():
            all_ok = False
        print(f"  {os.path.basename(path):25s} → {label} (prob_malware={p_mal:.3f}) {ok_str}")

    if all_ok:
        print("[Validate] ALL CHECKS PASSED ✓")
    else:
        print("[Validate] Some checks FAILED — consider adding more benign training data.")


# ─────────────────────────────────────────────────────────────────────────────
# 7. Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train LightAV 77-feature LightGBM model and export to ONNX"
    )
    parser.add_argument(
        "--malware", default=None, metavar="DIR",
        help="Path to real malware sample dir (e.g. data/malware). Optional."
    )
    parser.add_argument(
        "--benign", default=None, metavar="DIR",
        help="Path to extra benign sample dir (e.g. data/benign). Optional."
    )
    parser.add_argument(
        "--limit", type=int, default=3000,
        help="Max PE files to load from each class (default: 3000)"
    )
    parser.add_argument(
        "--synthetic", type=int, default=None,
        help="Override synthetic malware count. Default = same as benign count."
    )
    parser.add_argument(
        "--output", default="lightgbm_static.onnx",
        help="Output ONNX path (default: lightgbm_static.onnx)"
    )
    parser.add_argument(
        "--scaler", default="lightgbm_static_scaler.pkl",
        help="Output scaler path (default: lightgbm_static_scaler.pkl)"
    )
    parser.add_argument(
        "--no-replace", action="store_true",
        help="Do not replace the existing ONNX model — save to a separate path instead."
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  LightAV Model Training Pipeline")
    print("  77-Feature LightGBM  →  ONNX Runtime")
    print("=" * 65)

    rng = np.random.default_rng(42)

    # ── Step 1: Collect benign features ──────────────────────────────
    print(f"\n[Step 1] Collecting benign samples …")
    benign_files = collect_benign_files(limit=args.limit)

    if args.benign and os.path.isdir(args.benign):
        extra = collect_malware_files(args.benign, limit=args.limit)
        benign_files += extra
        print(f"  Added {len(extra)} extra benign files from {args.benign}")

    print(f"  Found {len(benign_files)} benign PE files")
    X_benign = extract_benign_features(benign_files)
    print(f"  Extracted features for {len(X_benign)} benign files")

    # ── Step 2: Collect real malware features (if available) ──────────
    X_real_malware = np.empty((0, NUM_FEATURES), dtype=np.float32)
    if args.malware:
        print(f"\n[Step 2] Collecting real malware samples from {args.malware} …")
        malware_files = collect_malware_files(args.malware, limit=args.limit)
        print(f"  Found {len(malware_files)} malware PE files")
        if malware_files:
            X_real_malware = extract_malware_features(malware_files)
            print(f"  Extracted features for {len(X_real_malware)} malware files")
    else:
        print("\n[Step 2] No malware dir specified — using synthetic data only.")

    # ── Step 3: Generate synthetic malware ───────────────────────────
    n_synth = args.synthetic if args.synthetic is not None else len(X_benign)
    # If we already have plenty of real malware, generate fewer synthetics
    if len(X_real_malware) >= n_synth:
        n_synth = 0
    else:
        n_synth = max(0, n_synth - len(X_real_malware))

    print(f"\n[Step 3] Generating {n_synth} synthetic malware samples …")
    X_synth = generate_synthetic_malware(n_synth, rng) if n_synth > 0 else np.empty((0, NUM_FEATURES), dtype=np.float32)

    # ── Step 4: Assemble dataset ──────────────────────────────────────
    X_malware = (
        np.vstack([X_real_malware, X_synth])
        if len(X_real_malware) > 0 and len(X_synth) > 0
        else X_real_malware if len(X_real_malware) > 0
        else X_synth
    )

    # Balance classes (min count wins)
    n = min(len(X_benign), len(X_malware))
    if n == 0:
        sys.exit("ERROR: No training samples produced. Check your input directories.")

    idx_b = rng.choice(len(X_benign),  n, replace=False)
    idx_m = rng.choice(len(X_malware), n, replace=False)
    X = np.vstack([X_benign[idx_b], X_malware[idx_m]])
    y = np.array([0] * n + [1] * n, dtype=np.int32)

    # Shuffle
    perm = rng.permutation(len(y))
    X, y = X[perm], y[perm]

    print(f"\n[Step 4] Final balanced dataset: {n} benign + {n} malware = {len(y)} total")

    # ── Step 5: Train ─────────────────────────────────────────────────
    print(f"\n[Step 5] Training LightGBM …")
    model, scaler, metrics, cm = train_model(X, y)

    print("\n[Results] Test-set metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.1f}%)")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    print(f"  AUC-ROC:   {metrics['auc']:.4f}")
    print(f"\n  Confusion matrix (rows=actual, cols=predicted):")
    print(f"    TN={cm[0][0]:5d}  FP={cm[0][1]:5d}")
    print(f"    FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")

    # ── Step 6: Save scaler ───────────────────────────────────────────
    scaler_path = ROOT / args.scaler
    joblib.dump(scaler, scaler_path)
    print(f"\n[Step 6] Scaler saved → {scaler_path}")

    # ── Step 7: Export ONNX ───────────────────────────────────────────
    print(f"\n[Step 7] Exporting to ONNX …")
    onnx_out = ROOT / args.output
    if args.no_replace and onnx_out.exists():
        onnx_out = ROOT / ("new_" + args.output)
        print(f"  --no-replace set: saving to {onnx_out}")

    success = export_onnx(model, str(onnx_out))

    # ── Step 8: Validate ─────────────────────────────────────────────
    if success:
        print(f"\n[Step 8] Validating exported model …")
        validate_onnx(str(onnx_out))

    print("\n" + "=" * 65)
    print("  Training complete!")
    if success:
        print(f"  ONNX model → {onnx_out}")
        print(f"  Scaler     → {scaler_path}")
        print()
        print("  To use the scaler at inference time, update model_infer.py:")
        print(f"    StaticONNXModel('lightgbm_static.onnx', scaler_path='{args.scaler}')")
    print("=" * 65)


if __name__ == "__main__":
    main()
