"""Durable per-authorization-instance consumption state (reissuance after consumption).

Single-use certificate ids stop the SAME token from being presented twice, but they do
not stop an adversarial planner from requesting a FRESH token for the same still-valid
task order after the first one was consumed. The ledger closes that
gap: every issued certificate is bound to an authorization instance

    (order_id, protocol_step, capability, target_id)

with an execution budget of one, tracked through

    UNUSED -> RESERVED (certificate issued, execution pending)
           -> CONSUMED (execution completed; further issuance denied)

Retry policy, stated explicitly: an ABORTED execution releases the reservation, so a
re-attested retry of the same authorized action is permitted (fail-safe-then-resume);
a COMPLETED execution consumes the instance permanently. A reservation whose
certificate expired without executing lapses back to UNUSED so an unexecuted issuance
cannot deadlock the instance.

Scope of the guarantee, stated precisely: the ledger prevents a fresh certificate from
being issued for an instance that a previous execution already consumed. It does not
provide exactly-once physical effect. An execution that is aborted part-way may already
have produced a partial physical effect (an object grasped, a container tilted), and the
released instance is then re-certifiable, so the same physical action can be re-attempted.
Exactly-once effect would additionally require an in-flight/committed distinction and
resume-only recovery; see the discussion in the paper.

Persistence is explicit at every construction site: `AuthorizationLedger.durable(path)`
writes through to disk so consumption survives a certifier/kernel restart, and
`AuthorizationLedger.ephemeral()` keeps state in memory only. Deployment constructors use
the durable form; evaluation harnesses use the ephemeral form so that measurements of one
run never inherit consumption state from another.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time

RESERVED = "RESERVED"
CONSUMED = "CONSUMED"
UNUSED = "UNUSED"

# Deployments override the ledger location with this variable; the default keeps the
# state next to the implementation so a restarted certifier finds it without configuration.
LEDGER_PATH_ENV = "AAL_LEDGER_PATH"


def default_ledger_path() -> str:
    override = os.environ.get(LEDGER_PATH_ENV)
    if override:
        return override
    pkg = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(pkg, "var", "authorization_ledger.json")


def instance_key(order_id: str, protocol_step: str, capability_value: str,
                 target_id: str) -> str:
    return f"{order_id}|{protocol_step}|{capability_value}|{target_id}"


class AuthorizationLedger:
    @staticmethod
    def _read_state_file(path: str, timeout_s: float = 2.0, poll_s: float = 0.002) -> dict:
        """Read the persisted state, retrying a transient Windows denial.

        The state file is replaced atomically, but on Windows the target is
        briefly inaccessible while a concurrent replace lands, so an unlocked
        reader -- construction, in particular -- can see PermissionError where
        POSIX simply reads the old or the new file. Because the replacement is
        atomic, retrying observes one whole version or the other, never a torn
        one.
        """
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                with open(path, encoding="utf-8") as handle:
                    return json.load(handle)
            except FileNotFoundError:
                return {}
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(poll_s)

    #: `persist_path` is REQUIRED, with no default. A silent in-memory default is exactly
    #: the failure this class exists to prevent: it looks durable and replays after a
    #: restart. Construct through `durable()` or `ephemeral()` so the intent is on record.
    def __init__(self, persist_path: str | None):
        self._persist_path = persist_path
        self._state: dict[str, dict] = {}
        # check-and-set must be atomic, or two concurrent requests for the same
        # instance can both observe UNUSED and both be issued. Within a process the
        # lock serializes it; across processes the O_EXCL lock file below does.
        self._mutex = threading.RLock()
        if persist_path and os.path.exists(persist_path):
            self._state = self._read_state_file(persist_path)

    @classmethod
    def durable(cls, persist_path: str | None = None) -> "AuthorizationLedger":
        """Deployment form: consumption is written through to disk and survives a restart."""
        path = persist_path or default_ledger_path()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        return cls(path)

    @classmethod
    def ephemeral(cls) -> "AuthorizationLedger":
        """Evaluation form: in-memory only, so one measurement run cannot inherit
        consumption state from an earlier one. Not for deployment."""
        return cls(None)

    @property
    def is_durable(self) -> bool:
        return self._persist_path is not None

    @property
    def persist_path(self) -> str | None:
        return self._persist_path

    @staticmethod
    def _atomic_replace(tmp: str, target: str,
                        timeout_s: float = 2.0, poll_s: float = 0.002) -> None:
        """os.replace, retried while Windows reports the target as in use.

        Replacement is atomic on both platforms, but Windows refuses it while
        any handle on the target is open, including the short-lived ones other
        certifiers and background file scanners take. POSIX has no such
        restriction. Retrying preserves atomicity -- each attempt either
        replaces the file completely or does nothing -- and only widens the
        window in which the rename is allowed to land.
        """
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                os.replace(tmp, target)
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(poll_s)

    def _save(self) -> None:
        if not self._persist_path:
            return
        tmp = self._persist_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self._state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        self._atomic_replace(tmp, self._persist_path)
        # Persist the directory entry where the platform supports directory fsync.
        parent = os.path.dirname(os.path.abspath(self._persist_path))
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        try:
            fd = os.open(parent, os.O_RDONLY | directory_flag)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def status(self, key: str, now_ms: float) -> str:
        with self._mutex:
            entry = self._state.get(key)
            if entry is None:
                return UNUSED
            if entry["state"] == RESERVED and now_ms > entry.get("valid_until_ms", 0.0):
                return UNUSED       # unexecuted issuance lapsed with its certificate
            return entry["state"]

    @staticmethod
    def _process_start_token(pid: int) -> str:
        """Best-effort process-birth token used to distinguish PID reuse on Linux."""
        try:
            text = open(f"/proc/{pid}/stat", encoding="utf-8").read()
            fields = text.rsplit(")", 1)[1].split()
            return fields[19]  # field 22 (starttime); fields begin at process state
        except (OSError, IndexError):
            return ""

    @staticmethod
    def _pid_is_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True

    def _try_reclaim_orphan_lock(self, path: str, *, metadata_grace_s: float = 0.25) -> bool:
        """Remove a lock whose owning process has exited.

        The lock file records host, PID, and (where available) Linux process
        start time. An unreadable just-created file is given a short grace period
        because another process may be between O_EXCL creation and metadata fsync.
        Locks owned by another host are never reclaimed automatically.
        """
        try:
            age_s = max(0.0, time.time() - os.path.getmtime(path))
        except FileNotFoundError:
            return True
        try:
            with open(path, encoding="utf-8") as handle:
                metadata = json.load(handle)
        except (OSError, ValueError, TypeError):
            if age_s < metadata_grace_s:
                return False
            metadata = {}

        host = str(metadata.get("host", ""))
        if host and host != socket.gethostname():
            return False
        try:
            pid = int(metadata.get("pid", -1))
        except (TypeError, ValueError):
            pid = -1
        recorded_start = str(metadata.get("process_start", ""))
        alive = self._pid_is_alive(pid)
        current_start = self._process_start_token(pid) if alive else ""
        same_process = alive and (
            not recorded_start or not current_start or recorded_start == current_start
        )
        if same_process:
            return False
        try:
            os.remove(path)
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def _cross_process_lock(self, timeout_s: float = 5.0, poll_s: float = 0.005):
        """Inter-process mutex with bounded waiting and orphan recovery.

        A tight fixed-iteration loop caused false availability failures under
        normal contention. A bare O_EXCL file also survives an abrupt process
        exit and can deadlock every restarted certifier. The lock now records its
        owner, waits against a monotonic deadline, yields between attempts, and
        reclaims a lock only when that recorded process is no longer alive.
        """
        if not self._persist_path:
            return None
        path = self._persist_path + ".lock"
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                metadata = json.dumps({
                    "host": socket.gethostname(),
                    "pid": os.getpid(),
                    "process_start": self._process_start_token(os.getpid()),
                    "created_wall_s": time.time(),
                }).encode("utf-8")
                os.write(handle, metadata)
                os.fsync(handle)
                return handle
            except (FileExistsError, PermissionError):
                # Windows reports a lock that exists, is held open by a waiter's
                # orphan check, or is pending deletion as PermissionError rather
                # than FileExistsError. All three mean "not acquirable yet", so
                # both are contention, not a fatal error. A genuine permission
                # fault still surfaces, as the wait then reaches the deadline.
                if self._try_reclaim_orphan_lock(path):
                    continue
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"authorization ledger lock is stuck: {path}")
                time.sleep(poll_s)

    def _release_lock(self, handle, timeout_s: float = 2.0, poll_s: float = 0.002) -> None:
        """Close and remove the lock file, retrying a transient sharing failure.

        A waiter inspecting the lock for orphan recovery holds a read handle on
        it for the duration of a small json.load. On Windows a file with any
        open handle cannot be unlinked, so the owner's removal can fail with a
        sharing violation. Discarding that failure strands the lock: its
        recorded owner is still alive, so no waiter is permitted to reclaim it
        and every later acquisition times out. POSIX unlinks regardless of open
        handles, which is why this only appears on Windows. The competing read
        is microseconds long, so a bounded retry clears it.
        """
        if handle is None:
            return
        os.close(handle)
        path = self._persist_path + ".lock"
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                os.remove(path)
                return
            except FileNotFoundError:
                return
            except OSError:
                if time.monotonic() >= deadline:
                    return
                time.sleep(poll_s)

    def reserve_if_unused(self, key: str, certificate_id: str, valid_until_ms: float,
                          now_ms: float) -> bool:
        """Atomically claim the instance. Returns False if it is already
        RESERVED or CONSUMED, so exactly one of N concurrent requests wins."""
        with self._mutex:
            handle = self._cross_process_lock()
            try:
                if self._persist_path and os.path.exists(self._persist_path):
                    self._state = self._read_state_file(self._persist_path)   # re-read: another process may have won
                if self.status(key, now_ms) != UNUSED:
                    return False
                self._state[key] = {"state": RESERVED, "certificate_id": certificate_id,
                                    "valid_until_ms": valid_until_ms}
                self._save()
                return True
            finally:
                self._release_lock(handle)

    def _mutate(self, change) -> None:
        """Read-modify-write the persisted state under both locks, so a writer never
        overwrites an entry another process created since this one last read the file."""
        with self._mutex:
            handle = self._cross_process_lock()
            try:
                if self._persist_path and os.path.exists(self._persist_path):
                    self._state = self._read_state_file(self._persist_path)
                change(self._state)
                self._save()
            finally:
                self._release_lock(handle)

    def reserve(self, key: str, certificate_id: str, valid_until_ms: float) -> None:
        self._mutate(lambda state: state.__setitem__(
            key, {"state": RESERVED, "certificate_id": certificate_id,
                  "valid_until_ms": valid_until_ms}))

    def consume(self, key: str) -> None:
        self._mutate(lambda state: state.__setitem__(key, {"state": CONSUMED}))

    # --- execution lifecycle, shared by the kernel and every hardware adapter -------
    # A physical adapter that certifies and then streams the controller itself (rather
    # than going through CertifiedActionKernel.execute) MUST call these at its own
    # completion/abort points, or consumption never happens on hardware and a consumed
    # instance could be reissued after the fact.

    def complete_execution(self, certificate) -> None:
        """A certified execution ran to completion: consume its instance for good."""
        if getattr(certificate, "authorization_instance", ""):
            self.consume(certificate.authorization_instance)

    def abort_execution(self, certificate) -> None:
        """A certified execution aborted safely: release the reservation so a
        re-attested retry can certify (fail-safe-then-resume)."""
        if getattr(certificate, "authorization_instance", ""):
            self.release(certificate.authorization_instance)

    def release(self, key: str) -> None:
        def _drop(state):
            entry = state.get(key)
            if entry is not None and entry["state"] == RESERVED:
                del state[key]
        self._mutate(_drop)
