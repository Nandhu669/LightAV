#!/usr/bin/env python3
"""
LightAV Evaluation Runner
--------------------------
Measures real detection performance against labelled sample directories.

Usage:
    python evaluation_runner.py --malware malware_samples --benign benign_samples
    python evaluation_runner.py --malware malware_samples --benign benign_samples --output results/eval.json

The script reuses the existing LightAV scanner API (agent.scanner.process_file)
and does NOT modify any detection logic.
"""

import argparse
import json
import os
import sys
import time
import zipfile
import tempfile
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Result data structures
# ---------------------------------------------------------------------------

@dataclass
class FileScanResult:
    """Result of scanning a single file."""
    path: str
    expected: str          # "malware" or "benign"
    verdict: str           # "BENIGN", "MALICIOUS", "SUSPICIOUS"
    correct: bool
    scan_time_ms: float
    error: str = ""


@dataclass
class EvaluationReport:
    """Aggregate evaluation metrics."""
    total_files: int = 0
    malware_samples: int = 0
    benign_samples: int = 0
    malware_detected: int = 0
    malware_missed: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    suspicious_count: int = 0
    errors: int = 0
    detection_rate: float = 0.0
    false_positive_rate: float = 0.0
    avg_scan_time_ms: float = 0.0
    total_scan_time_ms: float = 0.0
    file_results: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core evaluation logic
# ---------------------------------------------------------------------------

def _is_pe_file(filepath: str) -> bool:
    """Check if a file starts with the PE/MZ magic bytes."""
    try:
        with open(filepath, 'rb') as f:
            return f.read(2) == b'MZ'
    except Exception:
        return False


def _rename_extensionless_executables(temp_dir: str) -> int:
    """
    Walk the temp directory and rename extensionless files to .exe
    if they have a valid PE header. Returns the count of renamed files.
    """
    renamed = 0
    for root, _, filenames in os.walk(temp_dir):
        for fname in filenames:
            fpath = os.path.join(root, fname)
            _, ext = os.path.splitext(fname)
            if not ext and _is_pe_file(fpath):
                new_path = fpath + '.exe'
                os.rename(fpath, new_path)
                renamed += 1
    return renamed


def _safe_extract_zip(zip_path: str, dest_dir: str) -> bool:
    """
    Safely extract a single zip file into dest_dir with Zip Bomb protection.
    Returns True if extraction succeeded, False otherwise.
    """
    MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB max per file
    MAX_FILES = 200                           # Max 200 files per zip
    PASSWORDS = [b'infected', b'password', b'1234', b'malware', None]

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for pwd in PASSWORDS:
                try:
                    zf.setpassword(pwd)
                    infos = zf.infolist()

                    if len(infos) > MAX_FILES:
                        print(f"    [!] Skipping {os.path.basename(zip_path)}: "
                              f"Exceeds {MAX_FILES} file limit (Zip Bomb Protection).")
                        return True  # Intentional skip, not a failure

                    for info in infos:
                        if info.is_dir():
                            continue
                        if info.file_size > MAX_UNCOMPRESSED_SIZE:
                            print(f"    [!] Skipping {info.filename}: Exceeds 50MB size limit.")
                            continue
                        zf.extract(info, path=dest_dir)

                    return True
                except RuntimeError as e:
                    if 'password' in str(e).lower() or 'bad password' in str(e).lower():
                        continue
                    break
                except Exception:
                    continue
    except Exception as e:
        print(f"    [!] Error opening zip {os.path.basename(zip_path)}: {e}")
        return False

    return False


def collect_files(directory: str, extract_zips: bool = False,
                  temp_dir: str = None) -> List[str]:
    """
    Recursively collect all scannable files from a directory.

    Args:
        directory:    Root directory to walk.
        extract_zips: If True, extract .zip files into temp_dir for scanning.
        temp_dir:     Destination for extracted zip contents (required when extract_zips=True).

    Returns:
        Sorted list of absolute file paths.
    """
    files = []
    for root, _, filenames in os.walk(directory):
        for fname in filenames:
            file_path = os.path.join(root, fname)

            if fname.lower().endswith('.zip') and extract_zips and temp_dir:
                print(f"[!] Safely extracting {fname} for scanning...")
                success = _safe_extract_zip(file_path, temp_dir)
                if not success:
                    print(f"    [!] Failed to extract {fname} (unknown password or corrupted)")
            else:
                files.append(file_path)

    # Collect extracted files from the temp directory
    if temp_dir and extract_zips:
        # Rename extensionless PE files so the scanner recognises them
        renamed = _rename_extensionless_executables(temp_dir)
        if renamed:
            print(f"[*] Renamed {renamed} extensionless PE files to .exe for scanning.")

        for root, _, filenames in os.walk(temp_dir):
            for fname in filenames:
                files.append(os.path.join(root, fname))

    return sorted(files)


def scan_single_file(filepath: str, expected_label: str) -> FileScanResult:
    """
    Scan one file using the existing LightAV pipeline and record the result.
    
    Args:
        filepath:       Absolute path to the sample file.
        expected_label: "malware" or "benign".
    
    Returns:
        FileScanResult with timing and correctness info.
    """
    from core.scanner import scan_file as process_file
    from core.decision_types import Verdict

    start = time.perf_counter()
    try:
        verdict = process_file(filepath)
        elapsed_ms = (time.perf_counter() - start) * 1000

        verdict_name = verdict.name  # "BENIGN", "MALICIOUS", "SUSPICIOUS"

        # Determine correctness
        if expected_label == "malware":
            # MALICIOUS or SUSPICIOUS counts as detected
            correct = verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
        else:
            correct = verdict == Verdict.BENIGN

        return FileScanResult(
            path=filepath,
            expected=expected_label,
            verdict=verdict_name,
            correct=correct,
            scan_time_ms=elapsed_ms,
        )

    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return FileScanResult(
            path=filepath,
            expected=expected_label,
            verdict="ERROR",
            correct=False,
            scan_time_ms=elapsed_ms,
            error=str(e),
        )


def run_evaluation(malware_dir: str, benign_dir: str) -> EvaluationReport:
    """
    Run the full evaluation suite.
    
    Args:
        malware_dir: Directory containing known-malware samples.
        benign_dir:  Directory containing known-benign samples.
    
    Returns:
        EvaluationReport with all metrics.
    """
    report = EvaluationReport()

    # Create an ISOLATED temp directory only for malware zip extraction
    malware_temp_dir = tempfile.TemporaryDirectory(prefix="lightav_eval_mal_")

    # Malware: extract zips into isolated temp dir
    malware_files = collect_files(
        malware_dir, extract_zips=True, temp_dir=malware_temp_dir.name
    ) if os.path.isdir(malware_dir) else []

    # Benign: never extract zips (benign samples are already raw files)
    benign_files = collect_files(
        benign_dir, extract_zips=False
    ) if os.path.isdir(benign_dir) else []

    report.malware_samples = len(malware_files)
    report.benign_samples  = len(benign_files)
    report.total_files     = report.malware_samples + report.benign_samples

    if report.total_files == 0:
        print("[!] No sample files found. Check your directory paths.")
        return report

    print(f"\n{'=' * 60}")
    print(f"  LightAV Evaluation Runner")
    print(f"{'=' * 60}")
    print(f"  Malware samples : {report.malware_samples}  ({malware_dir})")
    print(f"  Benign samples  : {report.benign_samples}  ({benign_dir})")
    print(f"  Total files     : {report.total_files}")
    print(f"{'=' * 60}\n")

    all_results: List[FileScanResult] = []
    total_time_ms = 0.0

    # --- Scan malware samples ---
    if malware_files:
        print(f"[*] Scanning {report.malware_samples} malware samples...")
        for i, fpath in enumerate(malware_files, 1):
            result = scan_single_file(fpath, "malware")
            all_results.append(result)
            total_time_ms += result.scan_time_ms

            if result.error:
                report.errors += 1
            elif result.verdict == "SUSPICIOUS":
                report.suspicious_count += 1

            # Progress indicator every 50 files
            if i % 50 == 0 or i == report.malware_samples:
                print(f"    [{i}/{report.malware_samples}] "
                      f"Last: {Path(fpath).name} -> {result.verdict} "
                      f"({result.scan_time_ms:.1f}ms)")

    # --- Scan benign samples ---
    if benign_files:
        print(f"\n[*] Scanning {report.benign_samples} benign samples...")
        for i, fpath in enumerate(benign_files, 1):
            result = scan_single_file(fpath, "benign")
            all_results.append(result)
            total_time_ms += result.scan_time_ms

            if result.error:
                report.errors += 1

            if i % 50 == 0 or i == report.benign_samples:
                print(f"    [{i}/{report.benign_samples}] "
                      f"Last: {Path(fpath).name} -> {result.verdict} "
                      f"({result.scan_time_ms:.1f}ms)")

    # --- Compute metrics ---
    report.total_scan_time_ms = total_time_ms
    report.avg_scan_time_ms = total_time_ms / report.total_files if report.total_files else 0.0

    for r in all_results:
        if r.expected == "malware" and r.verdict in ("MALICIOUS", "SUSPICIOUS"):
            report.malware_detected += 1
        elif r.expected == "malware" and r.verdict not in ("MALICIOUS", "SUSPICIOUS"):
            report.malware_missed += 1
        elif r.expected == "benign" and r.verdict in ("MALICIOUS", "SUSPICIOUS"):
            report.false_positives += 1
        elif r.expected == "benign" and r.verdict == "BENIGN":
            report.true_negatives += 1

    report.detection_rate = (
        (report.malware_detected / report.malware_samples * 100)
        if report.malware_samples > 0 else 0.0
    )
    report.false_positive_rate = (
        (report.false_positives / report.benign_samples * 100)
        if report.benign_samples > 0 else 0.0
    )

    # Attach per-file results (without bloating the summary)
    report.file_results = [
        {
            "path": r.path,
            "expected": r.expected,
            "verdict": r.verdict,
            "correct": r.correct,
            "scan_time_ms": round(r.scan_time_ms, 2),
            **({"error": r.error} if r.error else {}),
        }
        for r in all_results
    ]

    # Flush per-file layer visibility log (results/layer_stats.json)
    try:
        from core.decision_engine import get_engine
        engine = get_engine()
        engine.save_layer_stats()
        print("[*] Layer stats saved to results/layer_stats.json")
    except Exception as e:
        print(f"[!] Warning: Could not save layer stats: {e}")

    # Clean up the malware temporary directory now that scanning is done
    try:
        malware_temp_dir.cleanup()
        print("[*] Secure malware temp directory wiped automatically.")
    except Exception as e:
        print(f"[!] Warning: Could not fully clean temp directory: {e}")

    return report


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_report(report: EvaluationReport) -> None:
    """Print a human-readable summary to stdout."""
    print(f"\n{'=' * 60}")
    print(f"  EVALUATION RESULTS")
    print(f"{'=' * 60}")
    print(f"  Total files scanned   : {report.total_files}")
    print(f"  Malware samples       : {report.malware_samples}")
    print(f"  Benign samples        : {report.benign_samples}")
    print(f"{'-' * 60}")
    print(f"  Malware detected (TP) : {report.malware_detected}")
    print(f"  Malware missed   (FN) : {report.malware_missed}")
    print(f"  False positives  (FP) : {report.false_positives}")
    print(f"  True negatives   (TN) : {report.true_negatives}")
    print(f"  Suspicious verdicts   : {report.suspicious_count}")
    print(f"  Errors                : {report.errors}")
    print(f"{'-' * 60}")
    print(f"  Detection rate        : {report.detection_rate:.2f}%")
    print(f"  False positive rate   : {report.false_positive_rate:.2f}%")
    print(f"  Avg scan time         : {report.avg_scan_time_ms:.2f} ms/file")
    print(f"  Total scan time       : {report.total_scan_time_ms:.0f} ms")
    print(f"{'=' * 60}\n")

    # Highlight misses and false positives
    misses = [r for r in report.file_results if r["expected"] == "malware" and r["verdict"] not in ("MALICIOUS", "SUSPICIOUS")]
    fps    = [r for r in report.file_results if r["expected"] == "benign"  and r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]

    if misses:
        print(f"  [!] Missed malware ({len(misses)}):")
        for m in misses[:20]:
            print(f"     - {m['path']}  (verdict: {m['verdict']})")
        if len(misses) > 20:
            print(f"     ... and {len(misses) - 20} more")

    if fps:
        print(f"\n  [!] False positives ({len(fps)}):")
        for fp in fps[:20]:
            print(f"     - {fp['path']}  (verdict: {fp['verdict']})")
        if len(fps) > 20:
            print(f"     ... and {len(fps) - 20} more")


def save_report(report: EvaluationReport, output_path: str) -> None:
    """Save the evaluation report as JSON."""
    # Build the JSON-friendly summary (matches the spec exactly)
    summary = {
        "total_files": report.total_files,
        "malware_detected": report.malware_detected,
        "false_positives": report.false_positives,
        "detection_rate": round(report.detection_rate, 4),
        "false_positive_rate": round(report.false_positive_rate, 4),
        "avg_scan_time_ms": round(report.avg_scan_time_ms, 2),
    }

    # Extended data alongside the required fields
    full_report = {
        **summary,
        "malware_samples": report.malware_samples,
        "benign_samples": report.benign_samples,
        "malware_missed": report.malware_missed,
        "true_negatives": report.true_negatives,
        "suspicious_count": report.suspicious_count,
        "errors": report.errors,
        "total_scan_time_ms": round(report.total_scan_time_ms, 2),
        "file_results": report.file_results,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(full_report, f, indent=2)

    print(f"  [+] Report saved to: {output_path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LightAV Evaluation Runner — measure detection performance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python evaluation_runner.py --malware malware_samples --benign benign_samples
  python evaluation_runner.py --malware data/malware --benign data/benign -o results/eval.json
  python evaluation_runner.py --malware C:\\Samples\\malware --benign C:\\Samples\\clean
        """,
    )
    parser.add_argument(
        "--malware", "-m",
        required=True,
        help="Directory containing known-malware samples",
    )
    parser.add_argument(
        "--benign", "-b",
        required=True,
        help="Directory containing known-benign samples",
    )
    parser.add_argument(
        "--output", "-o",
        default="results/evaluation_report.json",
        help="Output JSON file path (default: results/evaluation_report.json)",
    )

    args = parser.parse_args()

    # Validate inputs
    if not os.path.isdir(args.malware):
        print(f"[ERROR] Malware directory not found: {args.malware}")
        sys.exit(1)
    if not os.path.isdir(args.benign):
        print(f"[ERROR] Benign directory not found: {args.benign}")
        sys.exit(1)

    # Run evaluation
    report = run_evaluation(args.malware, args.benign)
    print_report(report)
    save_report(report, args.output)


if __name__ == "__main__":
    main()
