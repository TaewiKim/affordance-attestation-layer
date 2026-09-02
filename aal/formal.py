"""Bounded explicit-state verification of the AAL invariant over the REAL implementation.

Rather than model an abstraction, we exhaustively enumerate a finite input domain and drive the
actual AALVerifier / CertifiedActionKernel / RuntimeMonitor, asserting properties P1-P4 on every
reachable state. The planner is adversarial: it may request any capability/target and may attempt
to forge certificates. This is a bounded model check whose counterexample set is empty iff the
implementation upholds the invariant on the domain.

Assumptions discharged by construction (paper A1-A6):
  A1 signing key secret is not given to the planner (forgeries use a wrong key)
  A2 the only path to the controller is the certified kernel (enforced: we never call a controller
     directly; execution == kernel.execute returning executed and not rejected)
  A6 the planner controls requests and forgery attempts but not the certifier/kernel/keys
"""
from __future__ import annotations

import itertools
import os

from .types import (Clock, Capability, ActionRequest, WorldState, Evidence, Certificate,
                    SafetyEnvelope)
from .verifier import AALVerifier
from .ledger import AuthorizationLedger, LEDGER_PATH_ENV
from .kernel import CertifiedActionKernel, RuntimeMonitor
from .authority import make_order, ProtocolEngine, TaskOrder

T_ORD, T_WRONG = "patient_A", "patient_B"
# The enumeration replays the same order ids on every case and on every re-run, so each
# case gets a private in-memory ledger. The two durability cases below deliberately do the
# opposite: they run through the deployment constructor and its on-disk ledger.
EPHEMERAL = {"ephemeral_ledger": True}
CAPS = [Capability.HANDOFF, Capability.TOUCH, Capability.NAVIGATE, Capability.OBSERVE]
FRESH = 1000.0   # evidence stamped at the verifier clock start (fresh)
EVIDENCE_CONFIGS = {
    "none": [],
    "match2": [Evidence("barcode", T_ORD, 0.97, FRESH), Evidence("wristband", T_ORD, 0.95, FRESH)],
    "match1": [Evidence("barcode", T_ORD, 0.97, FRESH)],
    "wrong2": [Evidence("barcode", T_WRONG, 0.97, FRESH), Evidence("wristband", T_WRONG, 0.95, FRESH)],
    "conflict": [Evidence("barcode", T_ORD, 0.9, FRESH), Evidence("rfid", T_WRONG, 0.9, FRESH)],
    "pose_ord": [Evidence("rgbd_pose", T_ORD, 0.92, FRESH)],
    "stale2": [Evidence("barcode", T_ORD, 0.97, FRESH - 5000), Evidence("wristband", T_ORD, 0.95, FRESH - 5000)],
}
PROTO_STEPS = ["exam_contact", "patient_check"]   # correct vs wrong current step


def _forged_certs(req):
    """Certificates the adversary might present (none genuine)."""
    good_env = SafetyEnvelope(max_speed_mps=1.0, max_force_n=5.0, allowed_region="R",
                              abort_if=[])
    base = dict(evidence_hashes=[], envelope=good_env, valid_from_ms=0.0,
                valid_until_ms=10_000_000, protocol_step="")
    forgeries = {}
    # tampered signature
    c = Certificate(req.capability, req.target_id, **base); c.signature = "deadbeef" * 3
    forgeries["bad_sig"] = c
    # wrong binding but signed with WRONG key (adversary lacks the real key)
    c2 = Certificate(req.capability, "some_other_target", **base).sign("attacker_key")
    forgeries["wrong_binding"] = c2
    # expired, signed with wrong key
    exp = dict(base); exp["valid_until_ms"] = -1
    c3 = Certificate(req.capability, req.target_id, **exp).sign("attacker_key")
    forgeries["expired_forged"] = c3
    return forgeries


def _tampered_genuine(cert):
    """Take a GENUINELY-signed certificate and mutate a security-relevant field WITHOUT re-signing
    (the adversary lacks the key). Each must be rejected because the signature covers these fields.
    This is the review's certificate-tampering adversary."""
    import copy
    out = {}
    t = copy.deepcopy(cert); t.envelope.max_force_n = 1e9;         out["widen_force"] = t
    t = copy.deepcopy(cert); t.envelope.max_speed_mps = 1e9;       out["widen_speed"] = t
    t = copy.deepcopy(cert); t.envelope.abort_if = [];             out["remove_abort"] = t
    t = copy.deepcopy(cert); t.valid_until_ms += 10_000_000;       out["extend_ttl"] = t
    t = copy.deepcopy(cert); t.envelope.allowed_region = "ANY";    out["change_region"] = t
    return out


def check_all():
    viol = {"P1": [], "P2": [], "P3": [], "P4": [], "P5": [], "P6": [], "P7": [],
            "P8": [], "P9": []}
    n_states = 0

    for cap, ev_name, proto in itertools.product(CAPS, EVIDENCE_CONFIGS, PROTO_STEPS):
        for tgt in (T_ORD, T_WRONG):
            n_states += 1
            clock = Clock(1000.0)
            verifier = AALVerifier(clock, EPHEMERAL)
            monitor = RuntimeMonitor(clock, enable=True)
            kernel = CertifiedActionKernel(clock, monitor)
            order = make_order("O", cap, T_ORD, protocol_sequence=("patient_check", "exam_contact"),
                               room="R")
            pe = ProtocolEngine()
            pe.set_state(order, proto, ("patient_check",) if proto == "exam_contact" else ())
            req = ActionRequest(cap, tgt, room="R",
                                protocol_step=("exam_contact" if cap in
                                               (Capability.HANDOFF, Capability.TOUCH) else ""),
                                params={"speed_mps": 0.1, "force_n": 1.0})
            ev = EVIDENCE_CONFIGS[ev_name]
            result = verifier.certify(req, WorldState("R", tgt, workspace_clear=True), ev, order, pe)

            issued = isinstance(result, Certificate)

            # ---- P3: sensor conflict must never yield a certificate for a capability that
            # physically actuates on the (identity-conflicted) target. Low-risk observe/speak do
            # not act on the target, so the property is scoped to actuating capabilities. ----
            from .types import LOW_RISK_CAPABILITIES
            if ev_name == "conflict" and issued and cap not in LOW_RISK_CAPABILITIES:
                viol["P3"].append((cap.value, ev_name, proto, tgt))

            # ---- P1: the adversary cannot execute without a genuine matching cert ----
            world = WorldState("R", tgt, workspace_clear=True)
            for fname, fc in _forged_certs(req).items():
                r = kernel.execute(req, fc, world, monitor_ticks=1)
                if r.executed and not r.reject_reason:
                    viol["P1"].append((cap.value, fname, "forged_executed"))
            # a None certificate must also never execute
            r_none = kernel.execute(req, None, world, monitor_ticks=1)
            if r_none.executed and not r_none.reject_reason:
                viol["P1"].append((cap.value, "none", "executed"))
            # if a genuine cert was issued, executing it must bind to the requested action
            if issued:
                k2 = CertifiedActionKernel(clock, monitor)
                r_ok = k2.execute(req, result, WorldState("R", tgt, workspace_clear=True),
                                  monitor_ticks=1)
                if not r_ok.executed:
                    viol["P1"].append((cap.value, "genuine", "unexpected_reject"))
                # certificate-tampering adversary: mutate signed fields without the key -> reject
                for tname, tc in _tampered_genuine(result).items():
                    kt = CertifiedActionKernel(clock, RuntimeMonitor(clock, enable=True))
                    tampered_req = ActionRequest(cap, tgt, room="R",
                                                 protocol_step=req.protocol_step,
                                                 params={"speed_mps": 0.1, "force_n": 1e6})
                    rt = kt.execute(tampered_req, tc, WorldState("R", tgt, workspace_clear=True),
                                    monitor_ticks=1)
                    if rt.executed and not rt.reject_reason:
                        viol["P1"].append((cap.value, f"tamper_{tname}", "executed"))

            # ---- P5: no certificate is issued from stale evidence ----
            if ev_name == "stale2" and issued and cap not in LOW_RISK_CAPABILITIES:
                viol.setdefault("P5", []).append((cap.value, "stale_evidence_certified"))

            # ---- P6: a single-use certificate cannot be replayed. The reviewer's explicit
            # replay adversary: a genuine cert, once consumed, is presented AGAIN for a fresh
            # task with the same (capability, target). The second execution must be refused. ----
            if issued and result.certificate_id:
                kr = CertifiedActionKernel(clock, RuntimeMonitor(clock, enable=True))
                first = kr.execute(req, result, WorldState("R", tgt, workspace_clear=True),
                                   monitor_ticks=1)
                replay = kr.execute(req, result, WorldState("R", tgt, workspace_clear=True),
                                    monitor_ticks=1)
                if not first.executed:
                    viol["P6"].append((cap.value, "genuine_first_use_rejected"))
                if replay.executed and not replay.reject_reason:
                    viol["P6"].append((cap.value, "replayed_certificate_executed"))
                elif replay.reject_reason != "replayed_certificate":
                    viol["P6"].append((cap.value, f"replay_wrong_reason:{replay.reject_reason}"))

            # ---- P7: reissuance after consumption. Single-use ids (P6) stop the SAME
            # token from being re-presented, but not a freshly minted token for the same
            # authorization instance. After the authorized action has consumed its
            # execution budget, a fresh certificate for the same
            # (order, step, capability, target) instance must be refused; while a
            # certificate is outstanding (reserved), a concurrent second issuance is
            # refused. Low-risk auto-certified capabilities (observe/speak) carry no
            # execution budget and are exempt. ----
            if issued and cap not in LOW_RISK_CAPABILITIES:
                dup = verifier.certify(req, WorldState("R", tgt, workspace_clear=True),
                                       ev, order, pe)
                if isinstance(dup, Certificate):
                    viol["P7"].append((cap.value, ev_name, proto,
                                       "second_issue_while_reserved"))
                elif dup.reason != "replay:authorization_instance_reserved":
                    viol["P7"].append((cap.value, f"reserved_wrong_reason:{dup.reason}"))
                kl = CertifiedActionKernel(clock, RuntimeMonitor(clock, enable=True),
                                           ledger=verifier.ledger)
                done = kl.execute(req, result,
                                  WorldState("R", tgt, workspace_clear=True),
                                  monitor_ticks=1)
                if done.executed and not done.aborted:
                    fresh = verifier.certify(req,
                                             WorldState("R", tgt, workspace_clear=True),
                                             ev, order, pe)
                    if isinstance(fresh, Certificate):
                        viol["P7"].append((cap.value, ev_name, proto,
                                           "fresh_cert_after_consumption"))
                    elif fresh.reason != "replay:authorization_instance_consumed":
                        viol["P7"].append((cap.value,
                                           f"consumed_wrong_reason:{fresh.reason}"))

            # ---- P4: a benign, fully-evidenced, in-protocol request must be certified ----
            benign = (tgt == T_ORD and ev_name in ("match2", "pose_ord")
                      and (proto == "exam_contact" or cap in (Capability.NAVIGATE, Capability.OBSERVE)))
            # pose_ord only binds navigate; match2 binds identity capabilities
            binds = ((ev_name == "pose_ord" and cap == Capability.NAVIGATE)
                     or (ev_name == "match2" and cap in (Capability.HANDOFF, Capability.TOUCH))
                     or cap == Capability.OBSERVE)
            if benign and binds and not issued:
                viol["P4"].append((cap.value, ev_name, proto))

    # ---- P2: every abort condition guarantees an abort (no execution-through). Detection
    # latency is measured empirically (reported), not asserted as a fixed ms bound, because the
    # expiry case must advance the clock past the TTL to trigger. ----
    n_p2 = 0
    p2_timing = {}
    for event in ("intrusion", "target_move", "expiry"):
        n_p2 += 1
        clock = Clock(1000.0)
        verifier = AALVerifier(clock, EPHEMERAL)
        monitor = RuntimeMonitor(clock, enable=True)
        kernel = CertifiedActionKernel(clock, monitor)
        order = make_order("O", Capability.HANDOFF, T_ORD,
                           protocol_sequence=("patient_check", "handoff"), room="R")
        pe = ProtocolEngine(); pe.set_state(order, "handoff", ("patient_check",))
        req = ActionRequest(Capability.HANDOFF, T_ORD, room="R", protocol_step="handoff",
                            params={"speed_mps": 0.1, "force_n": 1.0})
        ev = [Evidence("barcode", T_ORD, 0.97, FRESH), Evidence("wristband", T_ORD, 0.95, FRESH)]
        cert = verifier.certify(req, WorldState("R", T_ORD, workspace_clear=True), ev, order, pe)
        assert isinstance(cert, Certificate)
        world = WorldState("R", T_ORD, workspace_clear=True)
        if event == "intrusion":
            evs = [(1, lambda w: setattr(w, "human_in_workspace", True))]
        elif event == "target_move":
            evs = [(1, lambda w: setattr(w, "present_target_id", "patient_A_moved"))]
        else:  # expiry: let the certificate age out naturally across ticks
            evs = []
        # enough ticks that even TTL expiry (500 ms) is reached
        r = kernel.execute(req, cert, world, monitor_ticks=6, tick_ms=150.0, world_events=evs)
        p2_timing[event] = r.time_to_abort_ms
        if not r.aborted:                      # the only formal requirement: abort is guaranteed
            viol["P2"].append((event, "no_abort"))

    # ---- P7 policy cases: (a) an ABORTED execution releases the authorization
    # instance so a re-attested retry is certified (fail-safe-then-resume); (b) a
    # CONSUMED instance survives a certifier restart via the persistent ledger;
    # (c) the same durability holds for the DEPLOYED configuration -- the verifier is
    # built by the constructor the hardware stack calls, the ledger comes from that
    # constructor rather than from the test, and the restart is a real new interpreter. ----
    import json as _json
    import subprocess
    import sys
    import tempfile
    n_p7_policy = 3
    ledger_file = os.path.join(tempfile.gettempdir(), "aal_formal_ledger_test.json")
    deploy_ledger_file = os.path.join(tempfile.gettempdir(), "aal_deploy_ledger_test.json")
    for stale in (ledger_file, deploy_ledger_file):
        if os.path.exists(stale):
            os.remove(stale)
    for policy_case in ("abort_releases", "restart_durability", "deployment_restart"):
        clock = Clock(1000.0)
        if policy_case == "deployment_restart":
            # no ledger argument: the deployment constructor must supply a durable one
            os.environ[LEDGER_PATH_ENV] = deploy_ledger_file
            verifier = AALVerifier.for_deployment(clock)
            ledger = verifier.ledger
            if not ledger.is_durable:
                viol["P7"].append((policy_case, "deployment_ledger_is_in_memory"))
                continue
        else:
            ledger = AuthorizationLedger.durable(ledger_file)
            verifier = AALVerifier(clock, {}, ledger=ledger)
        kernel = CertifiedActionKernel(clock, RuntimeMonitor(clock, enable=True),
                                       ledger=ledger)
        order = make_order(f"O_{policy_case}", Capability.HANDOFF, T_ORD,
                           protocol_sequence=("patient_check", "handoff"), room="R")
        pe = ProtocolEngine(); pe.set_state(order, "handoff", ("patient_check",))
        req = ActionRequest(Capability.HANDOFF, T_ORD, room="R", protocol_step="handoff",
                            params={"speed_mps": 0.1, "force_n": 1.0})
        ev = [Evidence("barcode", T_ORD, 0.97, clock.now()),
              Evidence("wristband", T_ORD, 0.95, clock.now())]
        cert = verifier.certify(req, WorldState("R", T_ORD, workspace_clear=True),
                                ev, order, pe)
        if not isinstance(cert, Certificate):
            viol["P7"].append((policy_case, f"initial_issue_failed:{cert.reason}"))
            continue
        if policy_case == "abort_releases":
            world = WorldState("R", T_ORD, workspace_clear=True)
            r = kernel.execute(req, cert, world, monitor_ticks=3,
                               world_events=[(1, lambda w: setattr(
                                   w, "human_in_workspace", True))])
            if not r.aborted:
                viol["P7"].append((policy_case, "expected_abort_did_not_happen"))
                continue
            ev2 = [Evidence("barcode", T_ORD, 0.97, clock.now()),
                   Evidence("wristband", T_ORD, 0.95, clock.now())]
            retry = verifier.certify(req, WorldState("R", T_ORD, workspace_clear=True),
                                     ev2, order, pe)
            if not isinstance(retry, Certificate):
                viol["P7"].append((policy_case,
                                   f"retry_after_abort_denied:{retry.reason}"))
        else:
            r = kernel.execute(req, cert, WorldState("R", T_ORD, workspace_clear=True),
                               monitor_ticks=1)
            if not (r.executed and not r.aborted):
                viol["P7"].append((policy_case, "expected_completion_failed"))
                continue
            ev3 = [Evidence("barcode", T_ORD, 0.97, clock.now()),
                   Evidence("wristband", T_ORD, 0.95, clock.now())]
            if policy_case == "restart_durability":
                # certifier/kernel restart within this process: fresh objects, same file
                clock2 = Clock(clock.now())
                verifier2 = AALVerifier(clock2, {},
                                        ledger=AuthorizationLedger.durable(ledger_file))
                again = verifier2.certify(req, WorldState("R", T_ORD, workspace_clear=True),
                                          ev3, order, pe)
                issued = isinstance(again, Certificate)
                reason = "" if issued else again.reason
            else:
                # a genuine process restart: a new interpreter rebuilds the deployed
                # certifier from AAL_LEDGER_PATH alone and re-requests the same instance
                spec = {"now_ms": clock.now(), "capability": Capability.HANDOFF.value,
                        "order_id": f"O_{policy_case}", "target": T_ORD, "room": "R",
                        "step": "handoff", "completed": ["patient_check"],
                        "protocol_sequence": ["patient_check", "handoff"],
                        "params": {"speed_mps": 0.1, "force_n": 1.0},
                        "evidence": [["barcode", 0.97], ["wristband", 0.95]]}
                pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                child = subprocess.run([sys.executable, "-m", "aal.restart_probe",
                                        _json.dumps(spec)],
                                       cwd=pkg_root, capture_output=True, text=True,
                                       env=dict(os.environ))
                if child.returncode != 0:
                    viol["P7"].append((policy_case,
                                       f"restart_probe_failed:{child.stderr.strip()[-160:]}"))
                    continue
                out = _json.loads(child.stdout.strip().splitlines()[-1])
                issued, reason = out["issued"], out["reason"]
                if out["ledger_path"] != deploy_ledger_file:
                    viol["P7"].append((policy_case,
                                       f"child_ledger_path_mismatch:{out['ledger_path']}"))
            if issued:
                viol["P7"].append((policy_case, "consumed_instance_reissued_after_restart"))
            elif reason != "replay:authorization_instance_consumed":
                viol["P7"].append((policy_case, f"wrong_reason:{reason}"))
    os.environ.pop(LEDGER_PATH_ENV, None)
    for stale in (ledger_file, deploy_ledger_file):
        if os.path.exists(stale):
            os.remove(stale)

    # ---- P2 (hardware replay): deterministic replay of the physical stale-evidence
    # loop. A certificate is issued from fresh evidence, the evidence refresher then
    # freezes, and the runtime re-attests every 150 ms through verifier.revalidate.
    # The first denial must land just after the 800 ms grasp freshness bound - the
    # same bound that sets the measured hardware abort latency - and revalidation
    # must never be mistaken for a second issuance (which the ledger refuses). ----
    n_p2 += 1
    clock = Clock(1000.0)
    # mirrors the hardware deployment: a camera-pair rig fields two readers of the
    # same (visual) modality, which by design does not satisfy two-factor identity,
    # so that requirement is disabled and documented rather than weakened
    verifier = AALVerifier(clock, dict(EPHEMERAL, require_two_factor=False))
    order = make_order("O_hwreplay", Capability.GRASP, T_ORD, room="R")
    pe = ProtocolEngine()
    req = ActionRequest(Capability.GRASP, T_ORD, room="R",
                        params={"speed_mps": 0.03, "force_n": 1.0})
    frozen_ev = [Evidence("visual_id", T_ORD, 0.95, clock.now(), reader_id="d435"),
                 Evidence("visual_id", T_ORD, 0.92, clock.now(), reader_id="c270")]
    cert = verifier.certify(req, WorldState("R", T_ORD, workspace_clear=True),
                            frozen_ev, order, pe)
    if not isinstance(cert, Certificate):
        viol["P2"].append(("hw_replay", f"initial_issue_failed:{cert.reason}"))
    else:
        # (a) fresh evidence: a sweep longer than the 800 ms TTL must keep running,
        #     renewed by the outstanding holder rather than aborted or re-executed
        live = cert
        renewals = 0
        for _ in range(20):                        # 3 s of 150 ms ticks
            clock.advance(150.0)
            ev_now = [Evidence("visual_id", T_ORD, 0.95, clock.now(), reader_id="d435"),
                      Evidence("visual_id", T_ORD, 0.92, clock.now(), reader_id="c270")]
            out = verifier.attest_tick(live, req,
                                       WorldState("R", T_ORD, workspace_clear=True),
                                       ev_now, order, pe)
            if hasattr(out, "is_denial"):
                viol["P2"].append(("hw_replay_fresh", f"aborted:{out.reason}"))
                break
            if out.certificate_id != live.certificate_id:
                renewals += 1
            live = out
        if renewals == 0:
            viol["P2"].append(("hw_replay_fresh", "certificate_never_renewed"))

        # (b) the refresher freezes mid-sweep: the last evidence is fresh at the
        #     moment of the freeze, exactly as on hardware. The abort must land at
        #     the 800 ms bound - the same bound that sets the measured hardware
        #     latency - and never later.
        frozen_ev = [Evidence("visual_id", T_ORD, 0.95, clock.now(), reader_id="d435"),
                     Evidence("visual_id", T_ORD, 0.92, clock.now(), reader_id="c270")]
        denial_at_ms = None
        for step in range(1, 15):                 # 150 ms ticks, evidence frozen
            clock.advance(150.0)
            out = verifier.attest_tick(live, req,
                                       WorldState("R", T_ORD, workspace_clear=True),
                                       frozen_ev, order, pe)
            if hasattr(out, "is_denial"):
                denial_at_ms = step * 150.0
                break
            live = out
        if denial_at_ms is None:
            viol["P2"].append(("hw_replay_frozen", "revalidation_never_denied"))
        elif not (750.0 <= denial_at_ms <= 950.0):
            viol["P2"].append(("hw_replay_frozen",
                               f"denied_at_{denial_at_ms}ms_outside_bound"))
        p2_timing["hw_stale_replay_ms"] = denial_at_ms
        p2_timing["hw_fresh_renewals"] = renewals

    # ---- P7 concurrency: N threads race for the SAME authorization instance;
    # exactly one certificate may be issued. This exercises the atomic
    # check-and-set, which a plain read-then-write ledger would fail. ----
    import threading
    n_p7_policy += 1
    clock = Clock(1000.0)
    verifier = AALVerifier(clock, EPHEMERAL)
    order = make_order("O_race", Capability.HANDOFF, T_ORD,
                       protocol_sequence=("patient_check", "handoff"), room="R")
    pe = ProtocolEngine(); pe.set_state(order, "handoff", ("patient_check",))
    req = ActionRequest(Capability.HANDOFF, T_ORD, room="R", protocol_step="handoff",
                        params={"speed_mps": 0.1, "force_n": 1.0})
    ev = [Evidence("barcode", T_ORD, 0.97, clock.now()),
          Evidence("wristband", T_ORD, 0.95, clock.now())]
    outcomes: list = []
    barrier = threading.Barrier(8)

    def racer():
        barrier.wait()
        outcomes.append(verifier.certify(
            req, WorldState("R", T_ORD, workspace_clear=True), ev, order, pe))

    threads = [threading.Thread(target=racer) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    issued_count = sum(1 for o in outcomes if isinstance(o, Certificate))
    if issued_count != 1:
        viol["P7"].append(("concurrent_race", f"{issued_count}_certificates_issued"))

    # ---- P8: an authenticated but EXPIRED (or not-yet-valid) task order must not
    # anchor a new issuance; a currently valid one must. ----
    n_p8 = 3
    now_s = 10_000.0
    for case, issued_at, valid_until, expect_cert in (
            ("expired", now_s - 500.0, now_s - 10.0, False),
            ("not_yet_valid", now_s + 10.0, now_s + 500.0, False),
            ("valid", now_s - 10.0, now_s + 500.0, True)):
        clock = Clock(now_s * 1000.0)
        verifier = AALVerifier(clock, EPHEMERAL)
        order = TaskOrder(f"O_{case}", Capability.HANDOFF, T_ORD,
                          protocol_sequence=("patient_check", "handoff"), room="R",
                          issued_at_unix_s=issued_at,
                          valid_until_unix_s=valid_until).sign()
        pe = ProtocolEngine(); pe.set_state(order, "handoff", ("patient_check",))
        req = ActionRequest(Capability.HANDOFF, T_ORD, room="R", protocol_step="handoff",
                            params={"speed_mps": 0.1, "force_n": 1.0})
        ev = [Evidence("barcode", T_ORD, 0.97, clock.now()),
              Evidence("wristband", T_ORD, 0.95, clock.now())]
        out = verifier.certify(req, WorldState("R", T_ORD, workspace_clear=True),
                               ev, order, pe)
        got_cert = isinstance(out, Certificate)
        if got_cert != expect_cert:
            viol["P8"].append((case, "certified" if got_cert else
                               f"denied:{getattr(out, 'reason', '')}"))

    # ---- P9 spatial binding: an identity match alone must not authorize an endpoint
    # away from where the authorized target was actually observed. Four cases: the
    # matching endpoint certifies (with the sensed pose bound into the certificate);
    # a redirected in-workspace endpoint is denied; an endpoint with no posed
    # observation fails closed; and a certificate bound to one endpoint refuses to
    # execute toward another at the kernel. ----
    n_p9 = 10
    sensed = [0.50, 0.05, 0.02]                      # where the readers saw the target
    redirect = [0.50, 0.45, 0.02]                    # different in-workspace location
    TOL = 0.15                                       # the default position tolerance
    for case in ("endpoint_matches", "endpoint_redirected", "no_posed_observation",
                 "kernel_refuses_redirect", "frame_mismatch",
                 "kernel_refuses_added_endpoint", "kernel_refuses_stripped_endpoint",
                 "boundary_inside", "boundary_outside", "revalidate_refuses_redirect"):
        clock = Clock(1000.0)
        verifier = AALVerifier(clock, EPHEMERAL)
        order = make_order(f"O_p9_{case}", Capability.GRASP, "box_A", room="R")
        pe = ProtocolEngine()
        if case == "endpoint_redirected":
            endpoint = redirect
        elif case == "boundary_inside":       # tolerance minus 1 cm: admissible
            endpoint = [sensed[0] + TOL - 0.01, sensed[1], sensed[2]]
        elif case == "boundary_outside":      # tolerance plus 1 cm: refused
            endpoint = [sensed[0] + TOL + 0.01, sensed[1], sensed[2]]
        else:
            endpoint = sensed
        req = ActionRequest(Capability.GRASP, "box_A", room="R",
                            params={"speed_mps": 0.05, "force_n": 1.0,
                                    "target_position_m": list(endpoint),
                                    "target_position_frame":
                                        ("camera_optical" if case == "frame_mismatch"
                                         else "robot_base")})
        if case == "kernel_refuses_added_endpoint":
            req.params.pop("target_position_m")      # certify WITHOUT an endpoint
            req.params.pop("target_position_frame")
        ev = [Evidence("barcode", "box_A", 0.97, clock.now()),
              Evidence("visual_id", "box_A", 0.95, clock.now(), "cam0",
                       pose_m=list(sensed), frame="robot_base")]
        if case == "no_posed_observation":
            ev = [e for e in ev if e.pose_m is None] + [
                Evidence("wristband", "box_A", 0.95, clock.now())]
        out = verifier.certify(req, WorldState("R", "box_A", workspace_clear=True),
                               ev, order, pe)
        issued = isinstance(out, Certificate)
        if case in ("endpoint_matches", "boundary_inside"):
            if not issued:
                viol["P9"].append((case, f"denied:{out.reason}"))
            elif out.target_pose_m != sensed:
                viol["P9"].append((case, f"pose_not_bound:{out.target_pose_m}"))
        elif case == "boundary_outside":
            if issued:
                viol["P9"].append((case, "certified_beyond_tolerance"))
            elif out.reason != "geometry:endpoint_not_at_sensed_target":
                viol["P9"].append((case, f"wrong_reason:{out.reason}"))
        elif case == "endpoint_redirected":
            if issued:
                viol["P9"].append((case, "redirected_endpoint_certified"))
            elif out.reason != "geometry:endpoint_not_at_sensed_target":
                viol["P9"].append((case, f"wrong_reason:{out.reason}"))
        elif case == "no_posed_observation":
            if issued:
                viol["P9"].append((case, "certified_without_posed_observation"))
            elif out.reason != "geometry:no_sensed_pose_for_authorized_target":
                viol["P9"].append((case, f"wrong_reason:{out.reason}"))
        elif case == "frame_mismatch":
            # same numeric coordinates, different frame: different place, fail closed
            if issued:
                viol["P9"].append((case, "certified_across_frames"))
            elif out.reason != "geometry:endpoint_frame_mismatch":
                viol["P9"].append((case, f"wrong_reason:{out.reason}"))
        elif case == "revalidate_refuses_redirect":
            # runtime half: the request is mutated DURING execution, so the per-tick
            # re-attestation (not just the kernel admission) must refuse it
            if not issued:
                viol["P9"].append((case, f"setup_denied:{out.reason}"))
                continue
            world = WorldState("R", "box_A", workspace_clear=True)
            still_ok = verifier.revalidate(out, req, world, ev)
            if hasattr(still_ok, "is_denial"):
                viol["P9"].append((case, f"unmutated_revalidate_denied:{still_ok.reason}"))
                continue
            req.params["target_position_m"] = list(redirect)
            after = verifier.revalidate(out, req, world, ev)
            if not hasattr(after, "is_denial"):
                viol["P9"].append((case, "revalidated_redirected_endpoint"))
            elif after.reason != "revalidate:endpoint_outside_binding":
                viol["P9"].append((case, f"wrong_reason:{after.reason}"))
        else:
            # post-issuance request mutation, refused at the kernel: redirecting the
            # endpoint, adding one to an endpoint-free certificate, or stripping it
            # from a pose-bound certificate must all fail
            if not issued:
                viol["P9"].append((case, f"setup_denied:{out.reason}"))
                continue
            kernel = CertifiedActionKernel(clock, RuntimeMonitor(clock, enable=True),
                                           ledger=verifier.ledger)
            if case == "kernel_refuses_redirect":
                req.params["target_position_m"] = list(redirect)
            elif case == "kernel_refuses_added_endpoint":
                req.params["target_position_m"] = list(redirect)
                req.params["target_position_frame"] = "robot_base"
            else:   # kernel_refuses_stripped_endpoint
                req.params.pop("target_position_m")
                req.params.pop("target_position_frame")
            r = kernel.execute(req, out, WorldState("R", "box_A", workspace_clear=True),
                               monitor_ticks=1)
            if r.executed:
                viol["P9"].append((case, "kernel_executed_mutated_request"))
            elif r.reject_reason != "endpoint_outside_binding":
                viol["P9"].append((case, f"wrong_reject:{r.reject_reason}"))

    return n_states, n_p2 + n_p7_policy + n_p8 + n_p9, viol, p2_timing


def main():
    n_states, n_p2, viol, p2_timing = check_all()
    total_viol = sum(len(v) for v in viol.values())
    print("=" * 60)
    print("AAL bounded explicit-state verification (real implementation)")
    print("=" * 60)
    print(f"P1/P3/P4 states enumerated : {n_states}")
    print(f"P2 stale-event states       : {n_p2}")
    labels = {"P1": "no exec without genuine matching cert (+ tamper adversary)",
              "P2": "guaranteed abort on stale condition", "P3": "no cert under sensor conflict",
              "P4": "benign in-protocol requests certified", "P5": "no cert from stale evidence",
              "P6": "single-use cert cannot be replayed (token replay)",
              "P7": "no fresh cert for a consumed authorization instance "
                    "(reissuance after consumption; abort releases, restart-durable, "
                    "one winner under a concurrent race)",
              "P8": "expired / not-yet-valid task orders cannot anchor issuance",
              "P9": "spatial binding: a named endpoint must sit at the sensed pose "
                    "of the authorized target, in the same frame (issuance and "
                    "kernel refuse redirects, frame mismatches, and post-issuance "
                    "adding/stripping of the endpoint; runtime re-attestation refuses "
                    "a mid-execution redirect; no posed observation fails closed)"}
    for p in ("P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"):
        status = "PASS" if not viol[p] else f"FAIL ({len(viol[p])})"
        print(f"  {p} [{labels[p]}]: {status}")
        for c in viol[p][:5]:
            print(f"      counterexample: {c}")
    print(f"P2 detection latency (ms)   : {p2_timing}")
    print(f"\nTOTAL VIOLATIONS: {total_viol}")
    import os, json
    out = os.path.join(os.path.dirname(__file__), "..", "results", "formal_check.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"p1_p3_p4_states": n_states, "p2_states": n_p2,
                   "violations": {k: len(v) for k, v in viol.items()},
                   "total_violations": total_viol, "p2_detection_latency_ms": p2_timing,
                   "counterexamples": {k: v[:5] for k, v in viol.items()}}, f, indent=2)
    print(f"[SAVED] results/formal_check.json")
    return total_viol


if __name__ == "__main__":
    import sys
    sys.exit(1 if main() else 0)
