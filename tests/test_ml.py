import numpy as np
from production.agent.decision_engine import ProductionDecisionEngine

engine = ProductionDecisionEngine()
print("ML Available:", engine.ml_available)

# Dummy features: 77 floats
dummy_features = np.random.rand(77)

try:
    score = engine._run_ml_model("dummy.exe", dummy_features)
    print("Test prediction passed! Score:", score)
except Exception as e:
    print("Error:", e)
