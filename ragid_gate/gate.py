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

def check_clock_skew(
    issued_at: int,
    max_skew_seconds: int = 30
) -> bool:
    """
    Returns True if issued_at is within acceptable skew window of server time.
    Returns False if timestamp is too far in the past or future - indicates clock manipulation.
    """
    server_time = int(time.time())
    skew = abs(server_time - issued_at)
    return skew <= max_skew_seconds

def check_rate_limit(
    agent_id: str,
    get_attempts: Callable,
    increment_attempts: Callable,
    max_attempts: int = 10,
    window_seconds: int = 60
) -> bool:
    """
    Returns True if agent is within rate limit.
    Returns False if agent has exceeded max_attempts within the window and should be denied.
    """
    current = get_attempts(agent_id)
    if current is None:
        increment_attempts(agent_id, window_seconds)
        return True
    if int(current) >= max_attempts:
        return False
    increment_attempts(agent_id, window_seconds)
    return True


def _external_deny(agent_id: str, requested_gate: str, timestamp: int) -> GateResult:
    return GateResult(GateDecision.DENY, agent_id, requested_gate, "unauthorized", timestamp)

def hard_gate(
    claim: ScopeClaim,
    requested_gate: str,
    verify_keypair: Callable
    verify_scope_sig: Callable
    commit_to_trail: Callable
    check_and_store_nonce: Callable
    get_attempts: Callable,
    increment_attempts: Callable
    max_skew_seconds: int = 30
) -> GateResult:

    timestamp = int(time.time())

    # Rate limit check
    if not check_rate_limit(claim.agent_id, get_attempts, increment_attempts):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "rate_limited", timestamp)
        commit_to_trail(result)
        return _external_deny(claim.agent_id, requested_gate, timestamp)

    # Clock skew check
    if not check_clock_skew(claim.issued_at, max_skew_seconds):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "clock_skew_detected", timestamp)
        commit_to_trail(result)
        return _external_deny(claim.agent_id, requested_gate, timestamp)

    # Factor 1 - Keypair authenticity
    if not verify_keypair(claim.agent_id, claim.keypair_sig):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "keypair_invalid", timestamp)
        commit_to_trail(result)
        return _external_deny(claim.agent_id, requested_gate, timestamp)

    # TTL check
    if claim.is_expired():
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "ttl_expired", timestamp)
        commit_to_trail(result)
        return _external_deny(claim.agent_id, requested_gate, timestamp)

    # Factor 2 - Scope-gate binding
    if not verify_scope_sig(claim):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "scope_sig_invalid", timestamp)
        commit_to_trail(result)
        return _external_deny(claim.agent_id, requested_gate, timestamp)

    # Nonce check - replay attack prevention
    if not check_and_store_nonce(claim.nonce):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "nonce_replayed", timestamp)
        commit_to_trail(result)
        return _external_deny(claim.agent_id, requested_gate, timestamp)

    if not claim.gate_permitted(requested_gate):
        result = GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "wrong gate", timestamp)
        commit_to_trail(result)
        return _external_deny(claim.agent_id, requested_gate, timestamp)

    # Trail entry required check
    if claim.trail_entry_required:
        committed = commit_to_trail(GateResult(GateDecision.PASS, claim.agent_id, requested_gate, "authorized", timestamp))
        if not committed:
            return GateResult(GateDecision.DENY, claim.agent_id, requested_gate, "trail_commit_failed", timestamp)

    return GateResult(GateDecision.PASS, claim.agent_id, requested_gate, "authorized", timestamp)
