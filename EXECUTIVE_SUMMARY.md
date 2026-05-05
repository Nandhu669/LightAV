# Executive Summary — LightAV

**Project**: LightAV — A Research Prototype for Resource-Aware Static Malware Detection  
**Type**: Final Year Project / Research-Grade Prototype  
**Platform**: Windows (user-space, Python 3.10+)  
**Date**: May 2026

---

## Overview

LightAV is a Python-based antivirus engine prototype that implements a five-layer static analysis pipeline for Windows PE files. The project explores two architectural questions: (1) whether a sequentially ordered, early-exit detection pipeline can achieve acceptable scan throughput under strict resource constraints, and (2) whether adaptive resource governance can allow a background scanning process to coexist with user workloads without OS-level scheduling support.

The system operates entirely in user space. It performs static analysis only — no files are executed, sandboxed, or monitored at runtime. It has no kernel-level access and does not intercept system calls or hook APIs. It is not a production security product and does not provide real-world endpoint protection.

---

## Detection Architecture

The detection pipeline processes files through five sequential layers, ordered by computational cost:

| Layer | Technique | Time | Exit Condition |
|---|---|---|---|
| 0 — Whitelist | SHA-256 lookup against known-good hashes | < 1 ms | Match → BENIGN |
| 1 — Hash DB | Bloom filter pre-check + SQLite confirmation (60,011 hashes) | < 1 ms | Match → MALICIOUS |
| 2 — YARA | 7 compiled rule files (packers, imports, entropy, persistence, C2) | ~50 ms | Confidence > 0.9 → MALICIOUS |
| 3 — Heuristic | 20 PE structural rules across 4 severity tiers | ~100 ms | Score > 75 → MALICIOUS |
| 4 — ML | LightGBM (77 features, ONNX Runtime inference) | ~10 ms | Probability > 0.85 → MALICIOUS |

Early-exit optimization ensures that the majority of benign files terminate at Layer 0 or 1, avoiding the cost of YARA, heuristic, and ML analysis.

---

## Design Contributions

1. **Multi-layer detection pipeline**: Five independent detection techniques composed into a single sequential pipeline with per-layer confidence scoring and threshold-based exit points.

2. **Early-exit optimization**: Cost-ordered layer sequencing ensures cheap deterministic checks execute before expensive analysis. Files matching the whitelist or hash database bypass all subsequent layers.

3. **Resource governor**: A five-state finite state machine (IDLE, NORMAL, BUSY, GAMING, CRITICAL) that monitors CPU and RAM at 2-second intervals and dynamically adjusts scanning throughput. Includes gaming process detection (15+ known executables) with automatic state recovery.

4. **Bloom filter optimization**: Two-stage hash lookup combining an in-memory Bloom filter (~2 MB, 0.1% false-positive rate) with a disk-backed SQLite database, converting the common-case lookup from O(log n) disk I/O to O(1) memory access.

---

## Resource Profile

| Metric | Measured |
|---|---|
| CPU usage (scanning) | 5–30% adaptive |
| Memory footprint | < 100 MB |
| Per-file scan (whitelist hit) | < 1 ms |
| Per-file scan (full pipeline) | < 200 ms |
| Hash database | 21 MB |

---

## Scope Boundaries

- Static analysis only — no behavioral or runtime monitoring
- User-space only — no kernel-level access
- Windows PE files only — no script or document analysis via heuristic/ML layers
- Offline only — no cloud intelligence or automatic signature updates
- Not adversarially tested — no evaluation against evasion techniques

---

## Technology Stack

Python 3.10+, LightGBM, ONNX Runtime, YARA, pefile, pybloom-live, psutil, FastAPI, React, PyQt6, SQLite.

---

## Conclusion

LightAV demonstrates that a multi-layer static detection pipeline with adaptive resource governance is architecturally feasible within the constraints of a Python user-space application. The design contributions — pipeline ordering, early-exit logic, Bloom filter optimization, and finite-state resource control — are the primary outcomes of this work. The prototype is not suitable for deployment as a security product; it is intended as a foundation for further research into lightweight, resource-aware malware detection architectures.
