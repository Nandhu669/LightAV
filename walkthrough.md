# LightAV Startup Walkthrough

## 1. Fixing the Entry Point
The application failed to launch due to an incorrect import in `run_lightav.py`.
- **Issue**: Attempted to import from `gui.main_window`, which did not exist as the primary entry point.
- **Fix**: Updated `run_lightav.py` to import `main` from `gui.app`.
- **Verification**: Launched the app using `python run_lightav.py`, which successfully initialized the PyQt6 container and mounted the React-based dashboard.

## 2. Environment Verification
The project uses a hybrid architecture:
- **Backend**: FastAPI (Python)
- **Frontend**: React (Vite-built)
- **Container**: PyQt6 with QWebEngine

We verified communication between the JS frontend and Python backend via the `QWebChannel` and REST API. 
- API Status Check: `GET /api/status` -> `{"running": true}`
- Sample File Scan: `POST /api/scan {"path": "README.md"}` -> `{"success": true, "verdict": "CLEAN"}`
- Sample Folder Scan: `POST /api/scan_folder {"path": "ai_engine"}` -> `{"success": true, "threats_found": 0}`

## 3. Project Cleanup and Optimization
To optimize the project size and remove clutter:
- **Cache Removal**: Removed `__pycache__` directories.
- **Redundancy Cleanup**: Legitimate cleanup of legacy backup files (`.bak`, `.old`, etc.).
- **Dependency Optimization**: Identified and uninstalled redundant `PyQt5` packages from the main `.venv`, saving ~140MB as the application now correctly uses `PyQt6`.
- **Requirements Update**: Updated `requirements.txt` to strictly pin current environment versions and reflect the shift to `PyQt6`.
- **Storage Profile**: Verified that active components in `node_modules` (e.g., Lucide, Recharts) are necessary for the UI and that `installer/lightav_env` is maintained at a reasonable size (~440MB).

## 4. Troubleshooting
### Browser Subagent Failures
If the browser subagent fails to launch due to environment issues (e.g., missing Playwright), verification was performed using PowerShell `Invoke-RestMethod` to test API endpoints directly and confirm backend health.

