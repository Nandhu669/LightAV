from pathlib import Path

# Get project root (parent of agent directory)
PROJECT_ROOT = Path(__file__).parent.parent
LOG_FILE = PROJECT_ROOT / "logs" / "decisions.log"

def read_last_lines(n=50):
    if not LOG_FILE.exists():
        return []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return lines[-n:]
