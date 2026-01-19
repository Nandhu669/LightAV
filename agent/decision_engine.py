from agent.decision_types import Verdict
from agent.static_rules import rule_based_static_decision
from ai_engine.feature_extractor import extract_features

def decide(path, cached_verdict=None):
    if cached_verdict is not None:
        return Verdict(cached_verdict), "cache"

    features = extract_features(path)
    rule_verdict = rule_based_static_decision(features)
    if rule_verdict is not None:
        return rule_verdict, "rules"

    return Verdict.BENIGN, "default"
