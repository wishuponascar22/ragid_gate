import json
import hashlib
import time
from ragid_gate.gate import GateResult

# In-memory chain state - replaced by TrailStax integration in production
_last_hash = "0" * 64

def _compute_hash(entry: dict) -> str:
    encoded = json.dumps(entry, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()

def commit_gate_result(result: GateResult) -> bool:
    global _lash_hash

    try:
        entry = {
            "previous_hash": _last_hash,
            "timestamp": result.timestamp,
            "agent_id": result.agent_id,
            "requested_gate": result.requested_gate,
            "decision": result.decision,
            "reason": result.reason,
        }

        current_hash = _compute_hash(entry)
        entry["hash"] = current_hash
        _last_hash = current_hash

        # Print for now - TrailStax append call goes here in production
        print(json.dumps(entry, indent=2)
        return True

    except Exception as e:
        print(f"Trail commit failed: {e}")
        return False


