"""
LightAV Model Training Pipeline
================================
Trains a LightGBM classifier on 77 PE structural features and exports to ONNX.

Malware sample sources (all handled safely):
  1. ZIP archives  — extracted to memory ONLY, never written to disk
                     Supports MalwareBazaar password: "infected"  (default)
                     Supports custom password via --zip-password flag
  2. Raw PE files  — read from disk (data/malware/*.exe etc.)
  3. Synthetic     — generated programmatically (always included if needed)

Benign samples:
  - Real Windows PE files from System32 / SysWOW64 (always collected)
  - Optional extra benign dir via --benign flag

Why in-memory extraction is safe:
  pefile.PE(data=raw_bytes) parses the PE structure in RAM.
  Windows Defender cannot scan BytesIO/bytes objects — only file paths.
  The bytes are never written to disk and are garbage-collected immediately.

Usage:
  # Synthetic only (no malware needed):
  python train_lightav_model.py --limit 2000

  # With real malware ZIPs (MalwareBazaar default password):
  python train_lightav_model.py --malware data/malware --limit 5000

  # With custom ZIP password:
  python train_lightav_model.py --malware data/malware --zip-password mypass

  # With raw PE files (unzipped, Defender excluded first):
  python train_lightav_model.py --malware data/malware --limit 5000
"""

import os
import sys
import io
import time
import zipfile
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
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix,
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
    print("WARNING: onnxmltools not found — ONNX export will be skipped.")

try:
    import pefile
except ImportError:
    sys.exit("ERROR: Run `pip install pefile` first.")

# Add project root to path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# Load production extractor (supports both path and bytes)
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "prod_extractor",
    ROOT / "production" / "ai_engine" / "production_extractor.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
extract_production_features          = _mod.extract_production_features
extract_production_features_from_bytes = _mod.extract_production_features_from_bytes

NUM_FEATURES = 77

# ─────────────────────────────────────────────────────────────────────────────
# 1. Benign sample collection (from disk — always safe)
# ─────────────────────────────────────────────────────────────────────────────

BENIGN_ROOTS      = [r"C:\Windows\System32", r"C:\Windows\SysWOW64"]
BENIGN_EXTENSIONS = {".exe", ".dll"}


def collect_benign_files(limit: int = 3000) -> list:
    found = []
    for root in BENIGN_ROOTS:
        if not os.path.isdir(root):
            continue
        for fname in os.listdir(root):
            if Path(fname).suffix.lower() in BENIGN_EXTENSIONS:
                found.append(os.path.join(root, fname))
                if len(found) >= limit:
                    return found
    return found


def extract_benign_features(paths: list) -> np.ndarray:
    vectors, ok, fail = [], 0, 0
    for i, path in enumerate(paths, 1):
        if i % 200 == 0:
            print(f"  Benign: {i}/{len(paths)}  (ok={ok}, fail={fail})")
        feat = extract_production_features(path)
        if feat is not None and len(feat) == NUM_FEATURES:
            vectors.append(feat)
            ok += 1
        else:
            fail += 1
    print(f"  Benign done: {ok} extracted, {fail} failed")
    return np.array(vectors, dtype=np.float32) if vectors else np.empty((0, NUM_FEATURES), dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Malware sample collection — ZIP (in-memory) and raw PE
# ─────────────────────────────────────────────────────────────────────────────

# MalwareBazaar ships samples with this password
MALWAREBAZAAR_ZIP_PASSWORD = b"infected"

# File extensions considered PE files inside ZIPs
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".drv"}


def _is_pe_bytes(data: bytes) -> bool:
    """Quick check: does the buffer start with MZ magic?"""
    return len(data) >= 2 and data[:2] == b"MZ"


def _extract_zip_in_memory(
    zip_path: str,
    password: bytes,
    limit: int,
    vectors: list,
    ok_ref: list,
    fail_ref: list,
    skip_ref: list,
) -> None:
    """
    Open a zip file and extract each member to RAM only.
    Passes raw bytes directly to pefile — nothing written to disk.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = zf.namelist()
            for member in members:
                if len(vectors) >= limit:
                    break

                # Filter to likely PE extensions
                member_ext = Path(member).suffix.lower()
                if member_ext and member_ext not in PE_EXTENSIONS:
                    skip_ref[0] += 1
                    continue

                try:
                    raw = zf.read(member, pwd=password)
                except RuntimeError:
                    # Try no password
                    try:
                        raw = zf.read(member)
                    except Exception:
                        fail_ref[0] += 1
                        continue
                except Exception:
                    fail_ref[0] += 1
                    continue

                # MZ magic check
                if not _is_pe_bytes(raw):
                    skip_ref[0] += 1
                    continue

                # Extract features from bytes (never touches disk)
                feat = extract_production_features_from_bytes(raw)
                del raw  # free memory immediately

                if feat is not None and len(feat) == NUM_FEATURES:
                    vectors.append(feat)
                    ok_ref[0] += 1
                else:
                    fail_ref[0] += 1

    except zipfile.BadZipFile:
        fail_ref[0] += 1
    except Exception:
        fail_ref[0] += 1


def extract_malware_features(malware_dir: str, limit: int, zip_password: bytes) -> np.ndarray:
    """
    Walk malware_dir and extract features from:
      - .zip files  → in-memory extraction (safe from Defender)
      - raw PE files → read from disk

    Returns float32 array of shape (N, 77).
    """
    if not malware_dir or not os.path.isdir(malware_dir):
        return np.empty((0, NUM_FEATURES), dtype=np.float32)

    vectors = []
    ok      = [0]   # mutable reference for nested functions
    fail    = [0]
    skip    = [0]

    zip_files = []
    raw_files = []

    for root, _, files in os.walk(malware_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname.lower().endswith(".zip"):
                zip_files.append(fpath)
            elif Path(fname).suffix.lower() in PE_EXTENSIONS:
                raw_files.append(fpath)

    total_zips = len(zip_files)
    total_raw  = len(raw_files)
    print(f"  Found {total_zips} zip archive(s), {total_raw} raw PE file(s)")

    # ── Process ZIPs (in-memory, Defender-safe) ───────────────────────
    for i, zpath in enumerate(zip_files, 1):
        if len(vectors) >= limit:
            break
        if i % 10 == 0 or i == 1:
            print(f"  [ZIP {i}/{total_zips}] {os.path.basename(zpath)}  "
                  f"(ok={ok[0]}, fail={fail[0]}, skip={skip[0]})")
        _extract_zip_in_memory(
            zpath, zip_password, limit,
            vectors, ok, fail, skip,
        )

    # ── Process raw PEs (from disk) ───────────────────────────────────
    if len(vectors) < limit and raw_files:
        print(f"  Processing {len(raw_files)} raw PE files …")
        for i, fpath in enumerate(raw_files, 1):
            if len(vectors) >= limit:
                break
            if i % 200 == 0:
                print(f"  [Raw {i}/{total_raw}]  ok={ok[0]}, fail={fail[0]}")
            feat = extract_production_features(fpath)
            if feat is not None and len(feat) == NUM_FEATURES:
                vectors.append(feat)
                ok[0] += 1
            else:
                fail[0] += 1

    print(f"  Malware done: {ok[0]} extracted, {fail[0]} failed, {skip[0]} skipped (non-PE)")
    return np.array(vectors, dtype=np.float32) if vectors else np.empty((0, NUM_FEATURES), dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Synthetic malware feature generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_synthetic_malware(n: int, rng: np.random.Generator) -> np.ndarray:
    """
    Generate realistic synthetic malware-like 77-feature vectors.
    Based on published EMBER dataset malware statistics.

    Key malware signals injected:
      - High max-section entropy (> 6.5) — packed/encrypted payload
      - Suspicious import function names
      - Non-standard section names
      - Unusual / zeroed TimeDateStamp
      - Missing or mismatched data directories
      - Non-standard DllCharacteristics (no ASLR/DEP/CFG)
    """
    samples = []
    for _ in range(n):
        v = np.zeros(NUM_FEATURES, dtype=np.float32)

        # DOS Header (0-16)
        v[0]  = 23117                              # e_magic (MZ)
        v[1]  = rng.integers(80, 200)
        v[2]  = rng.integers(1, 5)
        v[3]  = 0
        v[4]  = rng.integers(2, 8)
        v[5]  = 0
        v[6]  = rng.integers(0, 65535)             # e_maxalloc — malware often max
        v[7]  = 0
        v[8]  = rng.integers(128, 512)
        v[9]  = 0
        v[10] = 0
        v[11] = 0
        v[12] = rng.integers(60, 80)
        v[13] = 0
        v[14] = 0
        v[15] = 0
        v[16] = rng.integers(120, 300)             # e_lfanew — larger in malware stubs

        # File Header (17-23)
        v[17] = rng.choice([332, 34404])           # Machine: x86 / x64
        v[18] = rng.integers(1, 12)                # NumberOfSections
        # Timestamp — 0 (stripped), very old, or far-future (fake)
        v[19] = rng.choice([
            0,
            int(rng.integers(1, 999_999)),
            int(rng.integers(2_000_000_000, 2_147_483_647)),
        ])
        v[20] = 0
        v[21] = 0
        v[22] = rng.choice([224, 240])
        v[23] = rng.choice([258, 274, 778, 34])    # Characteristics

        # Optional Header (24-51)
        v[24] = rng.choice([267, 523])             # Magic: PE32 / PE32+
        v[25] = rng.integers(0, 15)
        v[26] = rng.integers(0, 99)
        # SizeOfCode: malware either tiny stub or huge packed blob
        v[27] = rng.choice([
            int(rng.integers(512, 4_096)),
            int(rng.integers(100_000, 5_000_000)),
        ])
        v[28] = int(rng.integers(512, 500_000))
        v[29] = int(rng.integers(0, 10_000))
        v[30] = int(rng.integers(4_096, 200_000))
        v[31] = int(rng.integers(4_096, 65_536))
        # ImageBase: non-standard values
        v[32] = rng.choice([
            4_194_304, 65_536,
            int(rng.integers(1_000_000, 10_000_000)),
        ])
        v[33] = rng.choice([4096, 8192, 512])
        v[34] = rng.choice([512, 4096, 256])
        v[35] = int(rng.integers(4, 11))
        v[36] = 0
        v[37] = int(rng.integers(0, 11))
        v[38] = 0
        v[39] = int(rng.integers(4, 11))
        v[40] = 0
        v[41] = int(rng.integers(512, 65_536))
        v[42] = rng.choice([0, int(rng.integers(1_000, 5_000_000))])
        v[43] = int(rng.integers(100_000, 30_000_000))
        v[44] = int(rng.integers(1, 4))
        # DllCharacteristics: 0 = no mitigations (common in malware)
        v[45] = rng.choice([0, 32768, 256, 64])
        v[46] = rng.choice([1_048_576, 262_144, 131_072])
        v[47] = rng.choice([4_096, 16_384, 65_536])
        v[48] = rng.choice([1_048_576, 268_435_456])
        v[49] = rng.choice([4_096, 16_384])
        v[50] = 0
        v[51] = 16
        v[52] = 0   # label slot

        # Structural features (53-76)
        v[53] = float(rng.integers(2, 9))          # SuspiciousImportFunctions
        v[54] = float(rng.integers(1, 9))          # SuspiciousNameSection
        v[55] = float(rng.integers(1, 12))         # SectionsLength
        v[56] = float(rng.uniform(0.5, 3.5))       # Min entropy
        v[57] = float(rng.uniform(6.0, 8.0))       # Max entropy — KEY malware signal
        v[58] = float(rng.integers(0, 4_096))
        v[59] = float(rng.integers(4_096, 5_000_000))
        v[60] = float(rng.integers(0, 8_192))
        v[61] = float(rng.integers(4_096, 10_000_000))
        v[62] = v[59]; v[63] = v[58]               # dup
        v[64] = v[61]; v[65] = v[60]               # dup
        v[66] = float(rng.integers(512, 1_000_000))
        v[67] = float(rng.integers(512, 10_000))
        v[68] = rng.choice([3_221_225_472, 1_610_612_736, 3_758_096_384])
        v[69] = rng.choice([1_610_612_736, 2_684_354_560, 3_221_225_472])
        v[70] = float(rng.integers(0, 5))          # Import DLL count (low in malware)
        v[71] = float(rng.integers(0, 30))
        v[72] = float(rng.integers(0, 2))          # Exports (usually 0 in malware)
        v[73] = float(rng.integers(0, 500))
        v[74] = float(rng.integers(0, 5_000))
        v[75] = float(rng.integers(0, 20_000))
        v[76] = 0                                  # Security dir (0 = unsigned)

        samples.append(v)

    return np.array(samples, dtype=np.float32)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Model training
# ─────────────────────────────────────────────────────────────────────────────

def train_model(X: np.ndarray, y: np.ndarray):
    print(f"\n[Train] Dataset: {X.shape[0]} samples × {X.shape[1]} features")
    unique, counts = np.unique(y, return_counts=True)
    for u, c in zip(unique, counts):
        print(f"  class {u} ({'benign' if u==0 else 'malware'}): {c}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[Train] Train={len(X_train)}, Test={len(X_test)}")

    scaler      = StandardScaler()
    X_train_s   = scaler.fit_transform(X_train)
    X_test_s    = scaler.transform(X_test)

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
    print(f"[Train] Done in {time.time()-t0:.1f}s")

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
    if not ONNX_AVAILABLE:
        print("[ONNX] Skipping — onnxmltools not installed")
        return False
    try:
        initial_types = [("float_input", FloatTensorType([None, NUM_FEATURES]))]
        onnx_model = convert_lightgbm(model, initial_types=initial_types, target_opset=12)
        import onnx as _onnx
        _onnx.save_model(onnx_model, output_path)
        print(f"[ONNX] Saved → {output_path}")
        return True
    except Exception as e:
        print(f"[ONNX] Export failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 6. Validation
# ─────────────────────────────────────────────────────────────────────────────

def validate_onnx(onnx_path: str):
    try:
        import onnxruntime as ort
    except ImportError:
        print("[Validate] onnxruntime not found — skipping")
        return

    sess    = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    in_name = sess.get_inputs()[0].name

    test_files = [
        (r"C:\Windows\System32\notepad.exe", "benign"),
        (r"C:\Windows\System32\calc.exe",    "benign"),
        (r"C:\Windows\System32\cmd.exe",     "benign"),
        (r"C:\Windows\System32\taskmgr.exe", "benign"),
        (r"C:\Windows\System32\mspaint.exe", "benign"),
    ]

    print("\n[Validate] Spot-checking ONNX model on Windows system binaries:")
    all_ok = True
    for path, expected in test_files:
        if not os.path.exists(path):
            continue
        feat = extract_production_features(path)
        if feat is None:
            print(f"  {os.path.basename(path):25s} → extraction failed")
            continue
        out    = sess.run(None, {in_name: feat.reshape(1, -1).astype(np.float32)})
        pd     = out[1][0]
        p_mal  = pd[1] if isinstance(pd, dict) else float(pd[1])
        label  = "MALWARE" if p_mal >= 0.5 else "BENIGN"
        ok_str = "✓" if label == expected.upper() else "✗ WRONG"
        if label != expected.upper():
            all_ok = False
        print(f"  {os.path.basename(path):25s}  {label}  (prob={p_mal:.3f})  {ok_str}")

    print("[Validate] " + ("ALL CHECKS PASSED ✓" if all_ok else
                           "Some checks FAILED — add more benign training data."))


# ─────────────────────────────────────────────────────────────────────────────
# 7. Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train LightAV 77-feature LightGBM → ONNX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Synthetic only (fastest, no malware needed):
  python train_lightav_model.py --limit 2000

  # With MalwareBazaar ZIPs (default password 'infected'):
  python train_lightav_model.py --malware data/malware --limit 5000

  # With custom ZIP password:
  python train_lightav_model.py --malware data/malware --zip-password mysecret

  # Only use ZIPs (skip raw PEs in the malware folder):
  python train_lightav_model.py --malware data/malware --zips-only

  # Save to a different output (keep existing model):
  python train_lightav_model.py --output models/v2.onnx --no-replace
""",
    )
    parser.add_argument("--malware",      default=None, metavar="DIR",
                        help="Malware sample dir (ZIPs and/or raw PEs). Optional.")
    parser.add_argument("--benign",       default=None, metavar="DIR",
                        help="Extra benign sample dir. Optional.")
    parser.add_argument("--limit",        type=int, default=3000,
                        help="Max samples per class (default: 3000).")
    parser.add_argument("--synthetic",    type=int, default=None,
                        help="Force synthetic malware count (default: same as benign).")
    parser.add_argument("--zip-password", default="infected", metavar="PWD",
                        help="Password for encrypted ZIPs (default: 'infected' for MalwareBazaar).")
    parser.add_argument("--zips-only",    action="store_true",
                        help="Only process ZIP archives in the malware dir; ignore raw PEs.")
    parser.add_argument("--output",       default="lightgbm_static.onnx",
                        help="Output ONNX file (default: lightgbm_static.onnx).")
    parser.add_argument("--scaler",       default="lightgbm_static_scaler.pkl",
                        help="Output scaler file (default: lightgbm_static_scaler.pkl).")
    parser.add_argument("--no-replace",   action="store_true",
                        help="Do not overwrite existing ONNX — prefix output with 'new_'.")
    args = parser.parse_args()

    zip_password = args.zip_password.encode() if args.zip_password else b"infected"

    print("=" * 65)
    print("  LightAV Model Training Pipeline")
    print("  77-Feature LightGBM  →  ONNX Runtime")
    print("=" * 65)

    rng = np.random.default_rng(42)

    # ── Step 1: Benign ────────────────────────────────────────────────
    print(f"\n[Step 1] Collecting benign samples (limit={args.limit}) …")
    benign_paths = collect_benign_files(limit=args.limit)
    if args.benign and os.path.isdir(args.benign):
        extra = [
            os.path.join(args.benign, f)
            for f in os.listdir(args.benign)
            if Path(f).suffix.lower() in BENIGN_EXTENSIONS
        ]
        benign_paths += extra[: max(0, args.limit - len(benign_paths))]
        print(f"  Added {len(extra)} extra benign files from {args.benign}")
    print(f"  Total benign paths: {len(benign_paths)}")
    X_benign = extract_benign_features(benign_paths)

    # ── Step 2: Real malware ──────────────────────────────────────────
    X_real_malware = np.empty((0, NUM_FEATURES), dtype=np.float32)
    if args.malware:
        print(f"\n[Step 2] Collecting malware samples from: {args.malware}")
        print(f"  ZIP password: '{args.zip_password}'  |  zips-only: {args.zips_only}")

        if args.zips_only:
            # Temporarily rename raw PEs so extractor ignores them —
            # actually just override: pass an empty raw_files list by
            # creating a wrapper directory listing that only shows ZIPs.
            # Simpler: we call extract_malware_features with a subfolder
            # that only has the ZIPs... but cleanest is just to handle in
            # extract_malware_features. We'll pass a flag via the limit
            # mechanic: pass an extra arg:
            X_real_malware = _extract_zips_only(
                args.malware, args.limit, zip_password
            )
        else:
            X_real_malware = extract_malware_features(
                args.malware, args.limit, zip_password
            )
        print(f"  Real malware features extracted: {len(X_real_malware)}")
    else:
        print("\n[Step 2] No --malware dir given — will use synthetic data.")

    # ── Step 3: Synthetic malware ─────────────────────────────────────
    n_real = len(X_real_malware)
    n_benign = len(X_benign)
    # Fill up to match benign count if real malware is insufficient
    n_synth = max(0, (args.synthetic if args.synthetic is not None else n_benign) - n_real)
    print(f"\n[Step 3] Generating {n_synth} synthetic malware vectors …")
    X_synth = (
        generate_synthetic_malware(n_synth, rng)
        if n_synth > 0
        else np.empty((0, NUM_FEATURES), dtype=np.float32)
    )

    # ── Step 4: Assemble + balance ────────────────────────────────────
    parts = [p for p in [X_real_malware, X_synth] if len(p) > 0]
    X_malware = np.vstack(parts) if parts else np.empty((0, NUM_FEATURES), dtype=np.float32)

    n = min(len(X_benign), len(X_malware))
    if n == 0:
        sys.exit("ERROR: No training samples — check directories and try again.")

    idx_b = rng.choice(len(X_benign),  n, replace=False)
    idx_m = rng.choice(len(X_malware), n, replace=False)
    X = np.vstack([X_benign[idx_b], X_malware[idx_m]])
    y = np.array([0] * n + [1] * n, dtype=np.int32)
    perm = rng.permutation(len(y))
    X, y = X[perm], y[perm]

    print(f"\n[Step 4] Final dataset: {n} benign + {n} malware = {len(y)} total")
    real_m_used = min(n, len(X_real_malware))
    synth_used  = n - real_m_used
    if real_m_used > 0:
        print(f"  Malware breakdown: {real_m_used} real  + {synth_used} synthetic")
    else:
        print(f"  Malware breakdown: {synth_used} synthetic only")

    # ── Step 5: Train ─────────────────────────────────────────────────
    print(f"\n[Step 5] Training …")
    model, scaler, metrics, cm = train_model(X, y)

    print("\n[Results]")
    print(f"  Accuracy : {metrics['accuracy']:.4f}  ({metrics['accuracy']*100:.1f}%)")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall   : {metrics['recall']:.4f}")
    print(f"  F1 Score : {metrics['f1']:.4f}")
    print(f"  AUC-ROC  : {metrics['auc']:.4f}")
    print(f"\n  Confusion matrix (rows=actual, cols=predicted):")
    print(f"    TN={cm[0][0]:5d}  FP={cm[0][1]:5d}  (false alarms on benign)")
    print(f"    FN={cm[1][0]:5d}  TP={cm[1][1]:5d}  (missed malware)")

    # ── Step 6: Save scaler ───────────────────────────────────────────
    scaler_path = ROOT / args.scaler
    joblib.dump(scaler, scaler_path)
    print(f"\n[Step 6] Scaler saved → {scaler_path}")

    # ── Step 7: Export ONNX ───────────────────────────────────────────
    onnx_out = ROOT / args.output
    if args.no_replace and onnx_out.exists():
        onnx_out = ROOT / ("new_" + args.output)
        print(f"  --no-replace: saving to {onnx_out}")
    print(f"\n[Step 7] Exporting ONNX …")
    success = export_onnx(model, str(onnx_out))

    # ── Step 8: Validate ─────────────────────────────────────────────
    if success:
        print(f"\n[Step 8] Validating …")
        validate_onnx(str(onnx_out))

    print("\n" + "=" * 65)
    print("  Training complete!")
    if success:
        print(f"  Model  → {onnx_out}")
        print(f"  Scaler → {scaler_path}")
    print("=" * 65)


def _extract_zips_only(malware_dir: str, limit: int, zip_password: bytes) -> np.ndarray:
    """Variant that only processes ZIP archives — skips raw PE files on disk."""
    vectors, ok, fail, skip = [], [0], [0], [0]
    for fname in os.listdir(malware_dir):
        if not fname.lower().endswith(".zip"):
            continue
        if len(vectors) >= limit:
            break
        zpath = os.path.join(malware_dir, fname)
        print(f"  [ZIP] {fname}")
        _extract_zip_in_memory(zpath, zip_password, limit, vectors, ok, fail, skip)
    print(f"  ZIP-only done: {ok[0]} ok, {fail[0]} fail, {skip[0]} skipped")
    return np.array(vectors, dtype=np.float32) if vectors else np.empty((0, NUM_FEATURES), dtype=np.float32)


if __name__ == "__main__":
    main()
