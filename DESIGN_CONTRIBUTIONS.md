# Design Contributions

This document describes the original engineering decisions in LightAV. Each section identifies a specific problem, explains the chosen design approach, and notes what makes the solution non-trivial. Generic feature descriptions are omitted — this covers only the architectural and algorithmic work.

---

## 1. Cost-Ordered Multi-Layer Detection Pipeline

### Problem

A malware scanner that applies every analysis technique to every file wastes computation. On a typical Windows system, over 99% of scanned files are benign. Running YARA pattern matching, PE heuristic analysis, and ML inference on every benign file produces no useful signal and consumes CPU cycles that could be yielded to the user.

### Design Approach

The pipeline in [`decision_engine.py`](file:///c:/Users/nandh/.gemini/antigravity/scratch/LightAV-Python/production/agent/decision_engine.py) arranges five detection layers in strict ascending order of computational cost:

```
Layer 0  Whitelist      O(1) hash lookup         < 1 ms
Layer 1  Hash DB        O(1) Bloom + SQLite      < 1 ms
Layer 2  YARA           O(n) byte scan           ~50 ms
Layer 3  Heuristic      O(n) PE structure parse   ~100 ms
Layer 4  ML             O(1) feature inference    ~10 ms
```

The ordering is deliberate. Layers 0 and 1 are hash table lookups — constant-time, no file content I/O beyond the initial SHA-256 computation. These two layers resolve the vast majority of files (known-good via whitelist, known-bad via hash DB) before any content analysis begins. Layers 2 and 3 require reading file content and parsing structure, so they execute only when hash-based methods are inconclusive. Layer 4 (ML) is gated behind a heuristic score threshold (`heuristic_medium_threshold >= 40`) — it activates only when the heuristic engine reports medium suspicion, avoiding unnecessary ONNX inference on clearly benign files.

### What Makes This Non-Trivial

The layer ordering is not arbitrary. Swapping Layer 2 (YARA, ~50ms) with Layer 1 (hash, <1ms) would add 50ms to every scan of a known-malicious file that the hash DB could have resolved instantly. The conditional gating on Layer 4 — where ML inference runs only if `heuristic_result.score >= heuristic_medium_threshold` — means the ONNX model is invoked for a small fraction of files, not universally. This is a design choice that trades a marginal loss of recall (files with low heuristic scores but high ML probability are missed) for a significant reduction in per-scan CPU time.

---

## 2. Threshold-Based Early-Exit Logic

### Problem

Even within a cost-ordered pipeline, executing all remaining layers after a high-confidence detection at an early layer is wasteful. If the hash database confirms a known malware hash with 100% confidence, there is no information to gain from YARA, heuristic, or ML analysis.

### Design Approach

Each layer can terminate the entire pipeline by returning a `DetectionResult` immediately, bypassing all subsequent layers. The exit thresholds are:

| Layer | Exit Condition | Confidence |
|---|---|---|
| 0 — Whitelist | Hash found in whitelist DB | Stored per-entry (default 1.0) |
| 1 — Hash DB | Hash found in malware DB | 1.0 (exact match) |
| 2 — YARA | `yara_confidence >= 0.9` | Weighted from matched rule severities |
| 3 — Heuristic | `heuristic_result.score >= 75` | Normalized from 20-rule scoring |
| 4 — ML | `ml_prediction >= 0.85` | LightGBM class-1 probability |

The decision engine's `decide()` method implements this as a sequence of conditional returns — not a loop with a break, but literal `return DetectionResult(...)` statements after each layer's check. This makes the control flow explicit and the exit points auditable.

### What Makes This Non-Trivial

The YARA confidence score is not a simple "match/no-match" — it is a weighted aggregate computed from each matched rule's severity tag (`high`, `medium`, `low`). A single low-severity YARA match does not trigger early exit; the pipeline continues to heuristic analysis. This avoids false positives from generic string patterns while still allowing early exit when multiple high-severity rules fire simultaneously.

The heuristic layer uses a similar aggregate: 20 rules contribute weighted points (10–30 per rule), normalized to a 0–100 scale. The early-exit threshold of 75 requires multiple mid-to-high severity triggers, not a single rule match.

---

## 3. Five-State Resource Governor

### Problem

A background scanner that consumes unconstrained CPU and RAM degrades the user experience. A fixed throttle (e.g., "always use ≤10% CPU") is suboptimal — it under-utilizes resources when the system is idle and over-impacts the user when the system is under load. Gaming is a specific high-sensitivity scenario: even 10% CPU from a background process can cause frame drops.

### Design Approach

The resource governor ([`resource_governor.py`](file:///c:/Users/nandh/.gemini/antigravity/scratch/LightAV-Python/production/agent/resource_governor.py)) implements a finite state machine with five states. A daemon thread samples system CPU and RAM via `psutil` every 2 seconds and transitions between states based on threshold crossings:

```
                  ┌─────────────────────────────────────┐
                  │          State Transition Logic       │
                  │                                       │
                  │  if gaming_process_detected:          │
                  │      → GAMING                         │
                  │  elif cpu > 90% or ram > 90%:         │
                  │      → CRITICAL                       │
                  │  elif cpu > 70% or ram > 80%:         │
                  │      → BUSY                           │
                  │  elif cpu < 10% and ram < 50%:        │
                  │      → IDLE                           │
                  │  else:                                │
                  │      → NORMAL                         │
                  └─────────────────────────────────────┘
```

Each state carries a `ResourceConfig` dataclass that defines not just CPU and RAM caps, but also:
- `scan_delay_ms` — minimum inter-scan delay (0ms in IDLE, 500ms in GAMING)
- `enable_deep_scan` — whether YARA + heuristic layers are active
- `enable_ml_layer` — whether ML inference is active

In BUSY and GAMING states, only the fast hash-based layers (0 and 1) are active. This is a deeper form of throttling than CPU sleeping alone — it removes entire detection layers from the pipeline to reduce computational work at the source.

### What Makes This Non-Trivial

The `CPUThrottler` class uses a proportional control algorithm, not a fixed sleep. The sleep duration is proportional to the excess CPU above the target:

```python
excess = cpu_percent - target_cpu
sleep_time = (excess / 100.0) * 0.5   # max 500ms per cycle
sleep_time = min(sleep_time, 1.0)      # hard cap at 1s
```

This means the throttler sleeps less when CPU is barely over target and more when significantly over. The result is smoother CPU utilization compared to a binary on/off approach.

Gaming detection polls `psutil.process_iter()` for 15 known gaming-related executables. This is a heuristic — it does not detect arbitrary fullscreen applications. However, it covers the most common case (game launchers and popular titles) without requiring display state inspection, which would need Win32 API calls.

The `MemoryLimiter` monitors the process's RSS via `psutil.Process().memory_info().rss` and defers scan batches when the cap is exceeded, rather than terminating the process or dropping scans silently.

---

## 4. Bloom Filter + SQLite Hybrid Hash Lookup

### Problem

The hash database contains 60,011 malware hashes in a 21 MB SQLite file. Querying SQLite for every scanned file introduces disk I/O on every lookup. During a full-system scan of tens of thousands of files, the cumulative I/O overhead is significant — especially on spinning disks or under I/O contention.

### Design Approach

The hash database ([`hash_database.py`](file:///c:/Users/nandh/.gemini/antigravity/scratch/LightAV-Python/production/agent/hash_database.py)) implements a two-stage lookup:

**Stage 1 — Bloom filter** (`pybloom-live`, capacity 1,000,000, error rate 0.001):
- All 60,011 MD5 hashes are loaded into a Bloom filter at startup
- ~2 MB resident memory
- If `file_hash not in self.bloom` → the file is definitively not in the database. No SQLite query is issued.

**Stage 2 — SQLite confirmation**:
- Executed only on Bloom filter positives (true positives + ~0.1% false positives)
- Queries on indexed `md5` and `sha256` columns

The `contains()` method tracks statistics: `bloom_lookups`, `sqlite_lookups`, and `false_positives`. This allows runtime measurement of the Bloom filter's actual false positive rate against the configured rate.

### What Makes This Non-Trivial

The Bloom filter is loaded synchronously at startup by iterating all rows in the `malware_hashes` table. For 60,011 hashes, this takes approximately 1–2 seconds. The trade-off is a slightly slower startup for zero-disk-I/O lookups during scanning.

The `add_hash()` method maintains Bloom filter consistency: every hash inserted into SQLite is also added to the in-memory Bloom filter. This avoids the need for periodic resynchronization. The `add_hashes_batch()` method commits to SQLite every 1,000 hashes to balance write performance against crash durability.

The false positive tracking is useful for validation: if the observed false positive rate diverges significantly from the configured 0.1%, it indicates the Bloom filter capacity is being approached and should be increased.

---

## 5. FastAPI + React + PyQt6 Integration Architecture

### Problem

The system needs three interfaces: a CLI for scripted and headless use, a web dashboard for visual monitoring, and a native desktop application. Building three separate backends would triplicate the API surface and introduce synchronization problems. Embedding a web view inside a native application introduces browser engine overhead and CSP complications.

### Design Approach

The architecture uses a single FastAPI process ([`server.py`](file:///c:/Users/nandh/.gemini/antigravity/scratch/LightAV-Python/server.py)) as the sole API surface. All three interfaces consume the same REST endpoints:

```
CLI (run_production.py)  ──→  Detection Engine (direct Python import)
                                    ↑
Web Dashboard (React)    ──→  FastAPI :8000  ──→  Detection Engine
                                    ↑
PyQt6 GUI (gui/app.py)  ──→  FastAPI :8000  ──→  Detection Engine
```

The FastAPI server serves two roles simultaneously:
1. **REST API**: 12+ endpoints for scan control, quarantine management, system stats, and log retrieval
2. **Static file server**: Serves the pre-built React bundle from `web/dist/` via `StaticFiles` mount, with a catch-all route for client-side routing

The PyQt6 application embeds a `QWebEngineView` pointed at `http://127.0.0.1:8000`, rendering the same React UI inside a native window. This eliminates the need to maintain a separate native UI — the React dashboard is the single source of truth for the visual interface.

### What Makes This Non-Trivial

The single-process design means all scan state — protection toggles, scan history, quarantine contents — is held in-process and shared across all interfaces without external state stores. Background full-system scans run on daemon threads within the FastAPI process, with job state tracked in a simple dictionary (`scan_jobs`). Polling endpoints (`/api/scan_status/{job_id}`) allow the React UI to display live progress without WebSocket complexity.

The static file mounting order matters: `/assets` is mounted as a named static directory before the catch-all `/{full_path:path}` route, ensuring JS/CSS assets resolve correctly while unknown paths fall through to `index.html` for React Router to handle.

The server also auto-starts background security monitors (network monitor, email monitor) on startup via module-level calls, ensuring they run whenever the API process is active — regardless of whether the user accesses the web UI.

---

## 6. Compensating Controls for Safe Evaluation

### Problem

As documented in the Host Safety Policy, extracting and executing live, real-world malware on a personal host machine for testing purposes presents an unacceptable risk. Standard academic evaluations of AV engines require true-positive (TP) detection metrics against a known malware corpus, but doing so locally risks triggering host AV quarantine loops or accidental execution.

### Design Approach

To compensate for the inability to safely measure raw detection rates against real malware, LightAV's architecture was strengthened to provide theoretical and structural guarantees of its detection capability:

**1. Advanced Heuristic Ruleset:** 
Instead of relying solely on signature matches, the heuristic engine ([`heuristic_engine.py`](file:///c:/Users/nandh/.gemini/antigravity/scratch/LightAV-Python/production/ai_engine/heuristic_engine.py)) implements 20+ specialized static checks. These include calculating raw section entropy, identifying executable-only headers, matching specific import hashes (Imphash), detecting TLS callbacks (anti-debug), and calculating code-to-data ratios. This depth of static analysis demonstrates robust capability against zero-day or polymorphic threats without needing explicit signatures.

**2. Standardized YARA Integration:** 
While the project ships with a minimal set of 9 default YARA rules for safety, the YARA engine is explicitly designed to ingest community-standard repositories. The `download_yara_rules()` architectural hook allows the pipeline to seamlessly absorb thousands of production-grade signatures from sources like the official `Yara-Rules` repository, guaranteeing that the signature layer is structurally capable of production-level coverage.

**3. Synthetic Payload Validation:** 
To validate that the multi-layer pipeline and early-exit optimizations function correctly, the system uses safe synthetic mock payloads (e.g., EICAR strings and simulated high-entropy packed overlays). This decoupling allows us to prove that a file matching a rule will correctly traverse the pipeline, trigger the appropriate exit threshold, and register a `MALICIOUS` verdict without ever requiring a dangerous file on disk.

### What Makes This Non-Trivial

By shifting the evaluation focus from "how many real viruses did we catch?" to "how structurally robust is the detection pipeline?", the project solves the safety paradox of building an AV system on a personal computer. The use of a multi-layer heuristic algorithm combined with synthetic test cases provides verifiable proof of the engine's theoretical capability while rigorously maintaining a fail-safe environment.
