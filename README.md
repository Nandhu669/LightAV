# LightAV

A lightweight, rule-based antivirus system for Windows designed for educational and research purposes.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## Overview

LightAV is a static analysis-based antivirus system that detects malicious files using hash verification and rule-based analysis. The system prioritizes low resource usage, offline operation, and transparent decision-making.

**Key Characteristics:**
- No internet dependency (fully offline operation)
- No kernel hooks or real-time file interception
- Low CPU and memory footprint
- Transparent rule-based detection
- Educational and research-focused design

---

## Features

| Feature | Description |
|---------|-------------|
| Static File Scanning | Analyzes files without execution |
| SHA-256 Hashing | Cryptographic file identification |
| Cache-Based Detection | Fast lookup for previously scanned files |
| Rule-Based Analysis | Configurable detection rules |
| Quarantine System | Isolates malicious files safely |
| Restore Functionality | Recover quarantined files when needed |
| Audit Logging | Complete scan and action history |
| GUI Dashboard | PyQt-based control interface |
| System Monitoring | CPU and RAM usage display |
| Windows Service | Background operation support |
| Performance-Aware | Pauses on high CPU usage |

---

## Architecture

```
LightAV-Python/
├── agent/                  # Core scanning engine
│   ├── scanner.py          # File scanning logic
│   ├── decision_engine.py  # Verdict determination
│   ├── quarantine.py       # File isolation
│   ├── hash_cache.py       # Hash caching system
│   ├── logger.py           # Audit logging
│   ├── log_reader.py       # Log retrieval
│   ├── restore.py          # File restoration
│   ├── runtime_state.py    # Scanner state management
│   └── main_agent.py       # Agent entry point
├── ai_engine/              # ML components (future)
│   ├── feature_extractor.py
│   └── model_infer.py
├── gui/                    # User interface
│   └── app.py              # PyQt dashboard
├── service/                # Windows service
│   └── service_runner.py
├── config.yaml             # Configuration file
├── logs/                   # Log output directory
├── quarantine/             # Isolated files
│   └── files/
└── requirements.txt
```

### Module Descriptions

**agent/** - Core scanning engine containing the file scanner, decision engine, quarantine manager, and logging system.

**ai_engine/** - Reserved for machine learning components including feature extraction and model inference.

**gui/** - PyQt6-based graphical interface for user interaction and system monitoring.

**service/** - Windows service wrapper for background operation.

---

## Detection Workflow

```
┌─────────────┐
│ File Input  │
└──────┬──────┘
       ▼
┌─────────────┐
│ Hash (SHA-256)│
└──────┬──────┘
       ▼
┌─────────────┐     ┌─────────────┐
│ Cache Check │────▶│ Return Cached│
└──────┬──────┘     │   Verdict   │
       │ miss      └─────────────┘
       ▼
┌─────────────┐
│Static Analysis│
└──────┬──────┘
       ▼
┌─────────────┐
│Decision Engine│
└──────┬──────┘
       ▼
┌─────────────┐
│   Verdict   │
└──────┬──────┘
       │
   ┌───┴───┐
   ▼       ▼
┌─────┐ ┌─────────┐
│Safe │ │Malicious│
└─────┘ └────┬────┘
             ▼
       ┌──────────┐
       │Quarantine│
       └──────────┘
             ▼
       ┌──────────┐
       │   Log    │
       └──────────┘
```

**Step-by-Step Process:**

1. **File Input** - File path received via GUI, drag-drop, or folder scan
2. **Hash Calculation** - SHA-256 hash computed for file identification
3. **Cache Lookup** - Check if file was previously scanned
4. **Static Analysis** - Analyze file structure and properties
5. **Decision Engine** - Apply rules to determine verdict
6. **Quarantine** - Isolate file if malicious
7. **Logging** - Record action for audit trail

---

## GUI Dashboard

The graphical interface provides:

| Function | Description |
|----------|-------------|
| Status Display | Current scanner state (Running/Paused) |
| Pause/Resume | Toggle scanner operation |
| Select File | Scan individual files |
| Scan Folder | Scan all files in a directory |
| Drag & Drop | Drop files onto window to scan |
| Scan Results | Visual feedback with threat status |
| Scan History | Last 5 scan results with timestamps |
| Quarantine Viewer | List of isolated files |
| Restore | Recover quarantined files |
| Live Logs | Real-time log display |
| System Stats | CPU and RAM usage monitoring |

**Keyboard Shortcuts:**
- `Ctrl+O` - Select file to scan
- `Ctrl+D` - Select folder to scan
- `Ctrl+Q` - Quit application

---

## Installation

### Requirements

- Python 3.10 or higher
- Windows 10/11
- 50 MB disk space

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/LightAV-Python.git
cd LightAV-Python
```

2. **Create virtual environment**
```bash
python -m venv venv
venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Verify installation**
```bash
python -c "from agent.scanner import process_file; print('OK')"
```

### Dependencies

```
PyQt6>=6.4.0
psutil>=5.9.0
PyYAML>=6.0
plyer>=2.1.0
```

---

## Usage

### Running the GUI

```bash
# From project root
set PYTHONPATH=.
python gui/app.py
```

Or using PowerShell:
```powershell
$env:PYTHONPATH = "."; python gui/app.py
```

### Scanning Files

**Method 1: File Picker**
1. Click "Select File (Ctrl+O)"
2. Choose file in dialog
3. View result in Scan Results panel

**Method 2: Folder Scan**
1. Click "Scan Folder (Ctrl+D)"
2. Select directory
3. Progress bar shows scan status
4. Summary displayed on completion

**Method 3: Drag and Drop**
1. Drag file onto application window
2. Result displayed immediately

### Quarantine

Quarantined files are moved to `quarantine/files/` with the following naming:
```
{timestamp}_{original_hash}_{filename}
```

**To restore a file:**
1. Select file in Quarantine list
2. Click "Restore Selected File"
3. File restored to `restored/` directory

### Viewing Logs

Logs are stored in `logs/` directory and displayed in the GUI's Live Logs panel.

Log format:
```
YYYY-MM-DD HH:MM:SS | file: {path} | hash: {sha256} | verdict: {result}
```

---

## Configuration

Edit `config.yaml` to modify behavior:

```yaml
scanner:
  scan_interval: 5          # Seconds between scans
  max_file_size: 104857600  # 100 MB limit
  pause_on_high_cpu: true
  cpu_threshold: 80         # Pause if CPU > 80%

quarantine:
  path: "quarantine/files"
  max_age_days: 30

logging:
  level: INFO
  max_log_size: 10485760    # 10 MB
```

---

## Performance Design

LightAV is designed for minimal system impact:

| Aspect | Design Choice |
|--------|---------------|
| Scanning | On-demand only, no file system hooks |
| Detection | Static analysis, no behavioral monitoring |
| Caching | Hash-based cache reduces repeat scans |
| CPU | Automatic pause on high system load |
| Memory | Minimal footprint, no large signatures |
| Disk | Small log files with rotation |

**What LightAV Does NOT Do:**
- Real-time file interception
- Kernel-level monitoring
- Background file watching
- Network traffic analysis
- Process injection detection

---

## Limitations

| Limitation | Reason |
|------------|--------|
| No behavioral analysis | Static analysis only |
| No real-time protection | On-demand scanning |
| No cloud detection | Fully offline operation |
| No runtime ML inference | Performance priority |
| No packed file analysis | Simplified detection |
| No memory scanning | File-based only |

---

## Future Enhancements

- [ ] Behavioral analysis engine
- [ ] Offline ML-based detection
- [ ] Signature update system
- [ ] Advanced PE file analysis
- [ ] Scheduled scanning
- [ ] Email notifications
- [ ] System tray integration
- [ ] Multi-language support

---

## Project Structure

```
Component           Technology      Purpose
─────────────────────────────────────────────────
Scanner Engine      Python          File analysis
Decision Engine     Rule-based      Verdict logic
Cache System        SQLite          Hash caching
GUI                 PyQt6           User interface
Logging             Python logging  Audit trail
Service             pywin32         Background ops
Configuration       YAML            Settings
```

---

## Testing

Run the scanner on test files:

```bash
# Scan a single file
python -c "from agent.scanner import process_file; print(process_file('test.exe'))"

# Run GUI
$env:PYTHONPATH = "."; python gui/app.py
```

---

## License

This project is licensed under the MIT License.

---

## Disclaimer

LightAV is designed for **educational and research purposes only**. It is not intended to replace production antivirus software. The detection capabilities are limited to static analysis and rule-based matching. Do not rely on this software for protection against real-world malware threats.

---

## Author

Developed as a final year cybersecurity project.

---

## Acknowledgments

- PyQt6 for the GUI framework
- Python community for security libraries
- Open-source antivirus research
