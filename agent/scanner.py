from agent.hash_cache import (
    compute_hash,
    get_cached_verdict,
    store_verdict
)
from agent.decision_engine import decide
from agent.decision_types import Verdict
from agent.logger import log_decision, log_quarantine
from agent.quarantine import quarantine_file
from agent.timer import Timer

def process_file(path):
    file_hash = compute_hash(path)
    cached = get_cached_verdict(file_hash)

    with Timer() as t:
        verdict, source = decide(path, cached)

    store_verdict(file_hash, int(verdict))
    log_decision(
        file_path=path,
        file_hash=file_hash,
        source=source,
        verdict=verdict,
        elapsed_ms=t.ms,
    )

    if verdict == Verdict.MALICIOUS:
        q_path = quarantine_file(path, file_hash)
        log_quarantine(path, q_path)

    return verdict

