from dataclasses import dataclass
from typing import Callable
import time
from ragid_gate.schema import ScopeClaim

class GateDecision:
    PASS = "PASS"
    DENY = "DENY"

@dataclass
class GateResult:
    decision: str
    agent_id: str
    requested_gate: str
    reason: str
    timestamp: int

def hard_gate(
    claim: ScopeClaim,
    requested_gate: str,
    verify_keypair: Callable
    verify_scope_sig: Callable
    commit_to_trail: Callable
) -> GateResult:

    timestamp = int(time.time())

    # Factor 1 - Keypair authenticity
    if not verify_keypair(claim.agent_id, claim.keypair_sig):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "keypair_invalid", timestamp)
        commit_to_trail(result)
        return ressult

    # TTL check
    if claim.is_expired():
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "ttl_expired", timestamp)

    # Factor 2 - Scope-gate binding
    if not verify_scope_sig(claim):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "scope_sig_invalid", timestamp)
        commit_to_trail(result)
        return result

    if not claim.gate_permitted(requested_gate):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "wrong gate", timestamp)
        commit_to_trail(result)
        return result

    # Trail entry required check
    if claim.trail_entry_required:
        committed = commit_to_trail(GateResult(GateDecision.PASS, claim.agent_id, requested_gate, "authorized", timestamp))
        if not committed:
            return GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "trail_commit_failed", timestamp)

    return GateResult(GateDecision.PASS, claim.agent_id, requested_gate, "authorized", timestamp)
