from dataclasses import dataclass, field
from typing import List
import time

@dataclass
class ScopeClaim:
    agent_id: str
    keypair_sig: str
    issued_at: int
    ttl: int
    gate: str
    role: str
    resource: str
    task_id: str
    permitted_gates: List[str]
    denied_gates: List[str]
    scope_sig: str
    nonce: str
    trail_entry_required: bool = True

    def is_expired(self) -> bool:
        return(time.time() - self.issued_at) > self.ttl

    def gate_permitted(self, requested_gate: str) -> bool:
        if requested_gate in self.denied_gates:
            return False
        return requested_gate in self.permitted_gates
