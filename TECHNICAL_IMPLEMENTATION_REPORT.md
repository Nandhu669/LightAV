# Technical Implementation Report

**Project Name:** LightAV — Resource-Aware Static Malware Detection Prototype  
**Version:** 1.0.0  
**Date:** May 2026  
**Classification:** Research-Grade Prototype

---

## 1. Project Overview

LightAV is a research prototype of a lightweight antivirus engine for Windows, implemented in Python. It combines five independent static analysis layers — whitelist pre-filter, hash-based lookup, YARA pattern matching, heuristic PE analysis, and machine learning classification — into a single resource-aware scanning pipeline.

The project investigates architectural approaches to multi-layer static detection and adaptive resource management. It operates entirely in user space, performs static analysis only, and has no kernel-level access or behavioral monitoring capability. It is not intended for deployment as a security product.

---

## 2. System Architecture

### 2.1 Architecture Overview
LightAV is organized into three functional layers:

- **Detection Engine:** 5-layer static analysis pipeline with early-exit optimization
- **Resource Management:** Adaptive CPU/RAM control via a 5-state finite state machine
- **User Interface:** React web dashboard + PyQt6 desktop GUI + FastAPI backend

### 2.2 Detection Pipeline
Each file is processed through five sequential layers, ordered by computational cost:

1. **Layer 0: Whitelist Pre-filter** — O(1) lookup, eliminates known-good files
2. **Layer 1: Hash Database** — O(1) via Bloom filter + SQLite (60,011 hashes)
3. **Layer 2: YARA Rules** — 7 rule files, ~50ms per file
4. **Layer 3: Heuristic Engine** — 20 PE analysis rules, ~100ms per file
5. **Layer 4: ML Classification** — LightGBM ONNX model, ~10ms per file

### 2.3 Resource Governor
Five-state finite state machine:
- **IDLE:** 30% CPU, 100 MB RAM
- **NORMAL:** 20% CPU, 80 MB RAM
- **BUSY:** 10% CPU, 60 MB RAM
- **GAMING:** 5% CPU, 50 MB RAM (detects 15+ gaming processes)
- **CRITICAL:** 0% CPU, 40 MB RAM (scanning paused)

---

## 3. Implementation Status

### 3.1 Detection Layers

#### Layer 0: Whitelist
- **Status:** Implemented
- **Entries:** 4,053 (Microsoft-signed binaries)
- **Lookup Time:** O(1)

#### Layer 1: Hash Database
- **Status:** Implemented
- **Hashes:** 60,011 malware hashes
- **Bloom Filter:** ~2 MB in memory, 0.1% false-positive rate

#### Layer 2: YARA Engine
- **Status:** Implemented
- **Rule Files:** 7 (high_entropy, suspicious_imports, common_packers, suspicious_strings, persistence, network, anti_analysis)
- **Scan Time:** ~50 ms per file

#### Layer 3: Heuristic Engine
- **Status:** Implemented
- **Rules:** 20 static analysis rules across 4 severity tiers
- **Scan Time:** ~100 ms per file

#### Layer 4: ML Classifier
- **Status:** Implemented
- **Model:** LightGBM exported to ONNX (209 KB)
- **Features:** 77 PE structural features
- **Inference Time:** ~10 ms per file

### 3.2 Resource Management
- **Resource Governor:** Implemented (5-state FSM, 2-second polling interval)
- **Gaming Mode:** Implemented (15+ monitored processes, 30-second recovery)
- **CPU Throttling:** Proportional control algorithm

### 3.3 User Interface
- **Web Dashboard:** React frontend + FastAPI backend (12 REST endpoints)
- **Desktop GUI:** PyQt6 with WebEngine integration

### 3.4 Supporting Systems
- **Quarantine:** Isolated storage with metadata and restore capability
- **Logging:** Structured JSON format
- **Hash Cache:** 10,000 entries, 24-hour expiration

---

## 4. Self-Test Results

| Test | Result |
|------|--------|
| Hash Database | PASS (60,011 hashes loaded) |
| YARA Engine | PASS (7 rule files compiled) |
| Heuristic Engine | PASS (20 rules loaded) |
| Decision Engine | PASS (all layers initialized) |
| Scanner | PASS (ready to scan) |

---

## 5. Observed Performance

| Metric | Measured |
|--------|----------|
| Hash lookup | < 1 ms (Bloom filter) |
| YARA scan | ~50 ms per file |
| Heuristic analysis | ~100 ms per file |
| ML inference | ~10 ms per file |
| CPU usage (scanning) | 5–30% adaptive |
| Memory footprint | < 100 MB |
| Hash database | 21 MB (60,011 entries) |

Note: All measurements were taken on a single development machine. Controlled benchmarking across diverse hardware has not been performed.

---

## 6. Limitations

1. **Static analysis only.** No execution, sandboxing, or runtime behavior monitoring.
2. **No kernel-level access.** Operates entirely in user space.
3. **No behavioral monitoring.** Cannot observe process execution, registry changes, or network activity in real time.
4. **Limited ML training data.** Detection rate depends on training dataset size; the current pre-trained model was trained on a small sample set.
5. **Windows PE files only.** Script-based threats are partially covered by YARA string rules only.
6. **No adversarial robustness evaluation.** Evasion techniques have not been tested against the system.
7. **Offline only.** No cloud threat intelligence or automatic signature updates.

---

## 7. Conclusion

LightAV demonstrates the feasibility of a multi-layer static detection pipeline with adaptive resource governance within a Python user-space application. The design contributions — early-exit pipeline optimization, Bloom filter hash lookup, and finite-state resource control — are the primary technical outcomes.

This is a research prototype. It is suitable for architectural study and further development, not for deployment as endpoint protection.

---

**Report Classification:** Research Prototype  
**Last Updated:** May 2026
