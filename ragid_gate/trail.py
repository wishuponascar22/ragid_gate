import json
import hashlib
import time
from ragid_gate.gate import GateResult

# In-memory chain state — replaced by TrailStax integration in production
_last_hash = "0" * 64

def _compute_hash(entry: dict) -> str:
    encoded = json.dumps(entry, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()

def commit_gate_result(result: GateResult, retain_days: int = 365, erasure_eligible: bool = False) -> bool:
    global _last_hash

    try:
        retain_until = time.strftime(
            "%Y-%m-%d",
            time.gmtime(time.time() + (retain_days * 86400))
        )

        entry = {
            "previous_hash": _last_hash,
            "timestamp": result.timestamp,
            "agent_id": result.agent_id,
            "requested_gate": result.requested_gate,
            "decision": result.decision,
            "reason": result.reason,
            "retain_until": retain_until,
            "erasure_eligible": erasure_eligible,
        }

        current_hash = _compute_hash(entry)
        entry["hash"] = current_hash
        _last_hash = current_hash

        print(json.dumps(entry, indent=2))
        return True

    except Exception as e:
        print(f"Trail commit failed: {e}")
        return False

def commit_tombstone(original_hash: str, reason: str = "gdpr_erasure_request") -> bool:
    global _last_hash

    try:
        entry = {
            "previous_hash": _last_hash,
            "timestamp": int(time.time()),
            "entry": "ERASED",
            "original_hash": original_hash,
            "reason": reason,
        }

        current_hash = _compute_hash(entry)
        entry["hash"] = current_hash
        _last_hash = current_hash

        print(json.dumps(entry, indent=2))
        return True

    except Exception as e:
        print(f"Tombstone commit failed: {e}")
        return False

def purge_eligible_entries(get_entries: callable, delete_entry: callable) -> int:
    """
    Purges entries past their retain_until date.
    Replaces each with a tombstone.
    Returns count of purged entries.
    """
    today = time.strftime("%Y-%m-%d", time.gmtime())
    purged = 0

    entries = get_entries()
    for entry in entries:
        if entry.get("erasure_eligible") and entry.get("retain_until", "9999-12-31") <= today:
            delete_entry(entry["hash"])
            commit_tombstone(entry["hash"])
            purged += 1

    return purged
