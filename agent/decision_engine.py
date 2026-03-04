from agent.decision_types import Verdict
from production.agent.decision_engine import ProductionDecisionEngine
import hashlib

# Singleton instance of the new ML pipeline to persist across UI scans
_production_engine = None

def decide(path, cached_verdict=None):
    global _production_engine
    
    if cached_verdict is not None:
        return Verdict(cached_verdict), "cache"

    # Initialize the 4-layer AI engine on first scan
    if _production_engine is None:
        _production_engine = ProductionDecisionEngine()

    # Get file hash for the new engine
    with open(path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # Run the production decision pipeline!
    result = _production_engine.decide(path, file_hash)
    
    return result.verdict, result.source
