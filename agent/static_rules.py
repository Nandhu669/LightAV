from agent.decision_types import Verdict
from agent.thresholds import (
    MAX_ENTROPY_THRESHOLD,
    MIN_SECTION_COUNT,
    MAX_SECTION_COUNT
)

def rule_based_static_decision(features):
    """
    features: numpy array of length 10
    Returns:
        Verdict or None
    """

    (
        file_size_kb,
        section_count,
        mean_entropy,
        max_entropy,
        dll_count,
        api_count,
        has_signature,
        entry_point,
        code_size,
        data_size
    ) = features

    # Rule 1: Extremely high entropy + unsigned
    if max_entropy > MAX_ENTROPY_THRESHOLD and has_signature == 0:
        return Verdict.MALICIOUS

    # Rule 2: Abnormal section count
    if section_count < MIN_SECTION_COUNT or section_count > MAX_SECTION_COUNT:
        return Verdict.MALICIOUS

    return None  # inconclusive
