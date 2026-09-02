"""Fresh-process certifier used by the P7 restart-durability check.

The parent executes an authorization instance to completion and then runs this module in
a NEW interpreter with the same AAL_LEDGER_PATH. Nothing is inherited except the on-disk
ledger, so a certificate issued here would mean the consumed instance came back to life.
The verifier is built through the deployment constructor, i.e. the same call the hardware
stack makes -- the durability property is checked on the deployed configuration, not on a
ledger hand-wired for the test.

Usage:  python -m aal.restart_probe '<json spec>'   ->  one JSON line on stdout
"""
from __future__ import annotations

import json
import sys

from .types import Clock, Capability, ActionRequest, WorldState, Evidence, Certificate
from .authority import make_order, ProtocolEngine
from .verifier import AALVerifier


def probe(spec: dict) -> dict:
    clock = Clock(spec["now_ms"])
    verifier = AALVerifier.for_deployment(clock)
    capability = Capability(spec["capability"])
    order = make_order(spec["order_id"], capability, spec["target"],
                       protocol_sequence=tuple(spec["protocol_sequence"]),
                       room=spec["room"])
    protocol = ProtocolEngine()
    protocol.set_state(order, spec["step"], tuple(spec["completed"]))
    request = ActionRequest(capability, spec["target"], room=spec["room"],
                            protocol_step=spec["step"], params=spec["params"])
    evidence = [Evidence(kind, spec["target"], conf, clock.now())
                for kind, conf in spec["evidence"]]
    world = WorldState(spec["room"], spec["target"], workspace_clear=True)
    out = verifier.certify(request, world, evidence, order, protocol)
    issued = isinstance(out, Certificate)
    return {"issued": issued,
            "reason": "" if issued else out.reason,
            "ledger_durable": verifier.ledger.is_durable,
            "ledger_path": verifier.ledger.persist_path}


if __name__ == "__main__":
    print(json.dumps(probe(json.loads(sys.argv[1]))))
