#!/usr/bin/python3
"""Does PTRACE_ATTACH report its stop to the tracer?

The in-tree strace smoke covers TRACEME + exec, where the tracee is the
tracer's own child and the initial stop comes from the exec path. `strace -p`
uses the other door: PTRACE_ATTACH raises SIGSTOP at an already-running task,
which must then enter a ptrace-stop and have it reported to the tracer's
`wait4`. This probe exercises that door in the two shapes that matter, each
bounded so a missing report reads as a timeout instead of hanging the caller.
"""
import ctypes
import os
import signal
import sys
import time

PTRACE_CONT = 7
PTRACE_TRACEME = 0
PTRACE_GETREGS = 12
PTRACE_SYSCALL = 24
# x86_64 `struct user_regs_struct` is 27 unsigned longs; these are the two
# slots a syscall-stop is about (arch/x86/include/asm/user_64.h).
REG_RAX = 10
REG_ORIG_RAX = 15
SYS_GETPID = 39
ENOSYS = 38
PTRACE_DETACH = 17
PTRACE_ATTACH = 16
__WALL = 0x40000000

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]


def ptrace(request, pid, addr=0, data=0):
    ctypes.set_errno(0)
    rc = libc.ptrace(request, pid, ctypes.c_void_p(addr), ctypes.c_void_p(data))
    return rc, ctypes.get_errno()


def spin_victim():
    """A child that stays runnable: a stop has to interrupt live execution."""
    while True:
        os.getpid()


def idle_victim():
    """A child parked in a blocking syscall, like a daemon in its event loop."""
    while True:
        time.sleep(0.05)


def await_stop(pid, budget=8.0):
    """Poll for a ptrace-stop report, bounded. Returns a short verdict."""
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        try:
            got, status = os.waitpid(pid, os.WNOHANG | __WALL)
        except ChildProcessError:
            return "ECHILD"
        except OSError as err:
            return f"errno {err.errno}"
        if got > 0 and (pid < 0 or got == pid):
            if os.WIFSTOPPED(status):
                return f"stopped sig={os.WSTOPSIG(status)}"
            if os.WIFEXITED(status):
                return f"exited {os.WEXITSTATUS(status)}"
            if os.WIFSIGNALED(status):
                return f"killed sig={os.WTERMSIG(status)}"
            return f"status {status:#x}"
        time.sleep(0.05)
    return "NO REPORT (timed out)"


def case(name, body):
    pid = os.fork()
    if pid == 0:
        try:
            body()
        finally:
            os._exit(0)
    time.sleep(0.3)  # let it reach its steady state
    rc, err = ptrace(PTRACE_ATTACH, pid)
    if rc != 0:
        verdict = f"attach failed errno {err}"
    else:
        verdict = await_stop(pid)
        ptrace(PTRACE_CONT, pid)
        ptrace(PTRACE_DETACH, pid)
    os.kill(pid, signal.SIGKILL)
    try:
        os.waitpid(pid, __WALL)
    except OSError:
        pass
    return f"{name}={verdict}"


def sibling_case(name, body, wait_for_any):
    """Attach from a task that did NOT fork the tracee.

    `strace -p` always looks like this: the tracer is a sibling (or unrelated
    entirely) and its `wait4` has to find the tracee by walking the tracer's
    ptraced list rather than its children. The tracer runs in its own child so
    the victim really is a non-descendant of it; the verdict comes back over a
    pipe because the tracer cannot return a value to us.
    """
    rfd, wfd = os.pipe()
    victim = os.fork()
    if victim == 0:
        os.close(rfd)
        os.close(wfd)
        try:
            body()
        finally:
            os._exit(0)

    tracer = os.fork()
    if tracer == 0:
        os.close(rfd)
        try:
            rc, err = ptrace(PTRACE_ATTACH, victim)
            if rc != 0:
                verdict = f"attach failed errno {err}"
            else:
                verdict = await_stop(-1 if wait_for_any else victim)
                ptrace(PTRACE_CONT, victim)
                ptrace(PTRACE_DETACH, victim)
            os.write(wfd, verdict.encode())
        finally:
            os._exit(0)

    os.close(wfd)
    # The tracer writes once and exits; a tracer wedged in wait4 writes
    # nothing, so a short read deadline is the same observation as its own
    # timeout without inheriting its hang.
    verdict = "NO VERDICT (tracer never reported)"
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            got, _ = os.waitpid(tracer, os.WNOHANG)
        except OSError:
            break
        if got == tracer:
            data = os.read(rfd, 256)
            if data:
                verdict = data.decode()
            break
        time.sleep(0.05)
    os.close(rfd)
    for pid in (victim, tracer):
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, __WALL)
        except OSError:
            pass
    return f"{name}={verdict}"


def threaded_victim():
    """A thread group, like any real daemon: a main thread plus workers."""
    import threading

    def worker():
        while True:
            time.sleep(0.05)

    for _ in range(2):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
    while True:
        time.sleep(0.05)


def thread_state(pid, tid):
    """The scheduler state letter from /proc/<pid>/task/<tid>/stat.

    't' is tracing-stop. It separates the two ways a missing report can
    happen: the thread stopped and the report was lost, or the thread never
    took the signal at all.
    """
    try:
        with open(f"/proc/{pid}/task/{tid}/stat", "rb") as fh:
            raw = fh.read().decode("latin-1")
    except OSError as err:
        return f"stat-errno{err.errno}"
    # comm is parenthesised and may contain spaces; state is the field after it.
    return raw[raw.rfind(")") + 2 :].split(" ")[0]


def thread_group_case(name):
    """Attach to EVERY thread of a non-child thread group, as strace does.

    `strace -p` enumerates /proc/<pid>/task and attaches to each tid, then
    expects one stop report per thread from `wait4(-1, ..., __WALL)`. A tracee
    identified by tid rather than tgid is the one shape the single-threaded
    cases above cannot distinguish, and it is the shape every real `strace -p`
    target has.
    """
    rfd, wfd = os.pipe()
    victim = os.fork()
    if victim == 0:
        os.close(rfd)
        os.close(wfd)
        try:
            threaded_victim()
        finally:
            os._exit(0)

    tracer = os.fork()
    if tracer == 0:
        os.close(rfd)
        try:
            time.sleep(1.0)  # let the workers exist
            try:
                tids = sorted(int(t) for t in os.listdir(f"/proc/{victim}/task"))
            except OSError as err:
                tids = []
                verdict = f"task dir unreadable errno {err.errno}"
            if tids:
                failed = []
                for tid in tids:
                    rc, err = ptrace(PTRACE_ATTACH, tid)
                    if rc != 0:
                        failed.append(f"{tid}:errno{err}")
                # Wait per tid rather than for any tid: which THREADS report
                # is the whole question, and wait-for-any cannot tell us.
                per_tid = [
                    f"{tid}:{await_stop(tid, budget=6.0)}"
                    f"/state={thread_state(victim, tid)}"
                    for tid in tids
                ]
                stops = [v for v in per_tid if "stopped sig=" in v]
                verdict = f"tids={len(tids)} stops={len(stops)} [{' '.join(per_tid)}]"
                if failed:
                    verdict += f" attach-failed={','.join(failed)}"
                if len(stops) != len(tids):
                    verdict += " NO REPORT for every thread"
                for tid in tids:
                    ptrace(PTRACE_CONT, tid)
                    ptrace(PTRACE_DETACH, tid)
            os.write(wfd, verdict.encode())
        finally:
            os._exit(0)

    os.close(wfd)
    verdict = "NO VERDICT (tracer never reported)"
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            got, _ = os.waitpid(tracer, os.WNOHANG)
        except OSError:
            break
        if got == tracer:
            data = os.read(rfd, 512)
            if data:
                verdict = data.decode()
            break
        time.sleep(0.05)
    os.close(rfd)
    for pid in (victim, tracer):
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, __WALL)
        except OSError:
            pass
    return f"{name}={verdict}"


def syscall_stop_case(name, use_attach=False):
    """What a tracer sees in rax at a syscall-entry and a syscall-exit stop.

    Linux stamps the two stops differently, and `entry_64.S` is explicit about
    it:

        pushq   %rax                    /* pt_regs->orig_ax */
        PUSH_AND_CLEAR_REGS rax=$-ENOSYS

    so from the instant of entry `orig_ax` holds the syscall number and `ax`
    holds -ENOSYS; the syscall's real result only lands in `ax` on the way
    out. An ATTACHING tracer cannot know whether the first syscall-stop it
    sees is an entry or an exit, and `rax == -ENOSYS` is how it tells — get
    this wrong and strace pairs the stops off by one and prints the syscall
    NUMBER where the return value belongs.

    Stepped with PTRACE_SYSCALL until an entry stop for a syscall whose answer
    we already know: getpid, whose return value is the tracee's own pid.
    """
    # Two ways in, because they are different code paths and the difference is
    # diagnostic: TRACEME + raise(SIGSTOP) is what `strace <cmd>` does, while
    # PTRACE_ATTACH is what `strace -p` does. If stepping works from one and not
    # the other, the fault is in how that one registers the tracee, not in the
    # syscall-stop machinery.
    child = os.fork()
    if child == 0:
        try:
            if not use_attach:
                ptrace(PTRACE_TRACEME, 0)
                os.kill(os.getpid(), signal.SIGSTOP)
            # Raw syscalls, so nothing in libc can answer from a cache.
            for _ in range(4000 if not use_attach else 2_000_000):
                libc.syscall(SYS_GETPID)
        finally:
            os._exit(0)
    if use_attach:
        time.sleep(0.3)
        rc, err = ptrace(PTRACE_ATTACH, child)
        if rc != 0:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, __WALL)
            return f"{name}=attach failed errno {err}"

    regs = (ctypes.c_ulong * 27)()

    def getregs():
        rc, err = ptrace(PTRACE_GETREGS, child, 0, ctypes.addressof(regs))
        return None if rc != 0 else (regs[REG_ORIG_RAX], regs[REG_RAX], err)

    notes = []
    try:
        got, status = os.waitpid(child, 0)
        if not os.WIFSTOPPED(status):
            return f"{name}=tracee never stopped (status {status:#x})"

        # Step to an entry stop for getpid.
        entry = None
        for _ in range(6000):
            if ptrace(PTRACE_SYSCALL, child)[0] != 0:
                return f"{name}=PTRACE_SYSCALL rejected"
            _, status = os.waitpid(child, 0)
            if not os.WIFSTOPPED(status):
                return f"{name}=tracee left the stop (status {status:#x})"
            seen = getregs()
            if seen is None:
                return f"{name}=PTRACE_GETREGS rejected"
            if seen[0] == SYS_GETPID:
                entry = seen
                break
        if entry is None:
            return f"{name}=no getpid entry-stop in 6000 steps"

        orig, rax, _ = entry
        # -ENOSYS as an unsigned 64-bit register value.
        notes.append(f"entry:orig_rax={orig} rax={ctypes.c_long(rax).value}")
        if ctypes.c_long(rax).value != -ENOSYS:
            notes.append("ENTRY RAX NOT -ENOSYS")

        # One more step lands on the matching exit stop.
        if ptrace(PTRACE_SYSCALL, child)[0] != 0:
            return f"{name}=PTRACE_SYSCALL rejected before the exit stop"
        _, status = os.waitpid(child, 0)
        if not os.WIFSTOPPED(status):
            return f"{name}=tracee left the exit stop (status {status:#x})"
        seen = getregs()
        if seen is None:
            return f"{name}=PTRACE_GETREGS rejected at the exit stop"
        orig, rax, _ = seen
        notes.append(f"exit:orig_rax={orig} rax={ctypes.c_long(rax).value}")
        if orig != SYS_GETPID:
            notes.append("EXIT ORIG_RAX LOST THE SYSCALL NUMBER")
        if rax != child:
            notes.append(f"EXIT RAX NOT THE RETURN VALUE (want {child})")

        # While parked in a ptrace-stop, /proc must say so: 't' is
        # tracing-stop. `ps` and every monitor reads this.
        for path in (f"/proc/{child}/stat", f"/proc/{child}/task/{child}/stat"):
            state = proc_state(path)
            notes.append(f"{'pid' if 'task' not in path else 'tid'}-state={state}")
            if state != "t":
                notes.append(f"STATE NOT 't' IN {path}")
    finally:
        ptrace(PTRACE_DETACH, child)
        try:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, __WALL)
        except OSError:
            pass
    return f"{name}=" + " ".join(notes)


def strace_return_case(name, flags=(), budget=60):
    """Does `strace` print RESULTS where results belong?

    RECORDED, not asserted — see `main`. `strace <cmd>` does not work yet for a
    reason this probe cannot fix and that is separate from everything above: a
    traced `execve` reports nothing to the tracer. Linux gives two things here,
    and NARF gives neither — the exec report itself (`ptrace_event(
    PTRACE_EVENT_EXEC)`, or for a tracer that did not ask for the event the
    legacy `send_sig(SIGTRAP)`), and the execve syscall-EXIT stop, which on
    Linux is what prints `execve(...) = 0` and which NARF skips because the
    exec path DIVERGES into the new image instead of returning through the
    syscall exit. They have to land together: adding only the SIGTRAP was
    measured, and it turned the hang into something worse — strace, still
    waiting for the exit stop, took the report for a real signal and injected
    it, so `/bin/echo` died of SIGTRAP (`rc=-5`).

    `strace -p` is unaffected and works: it attaches to a process that has
    already exec'd, so it never needs either of them.

    The register case above pins the contract strace reads; this is the same
    thing end to end through the real tool, because that is what anyone
    debugging on this kernel actually runs.

    The assertion is SELF-CHECKING rather than a hardcoded number: a successful
    `write` returns the count it was given, so the result strace prints must
    equal the length in the same line. That holds whatever libc does with
    buffering, and it needs no oracle — which matters, because strace is not
    installed on the build host, so this case cannot be answered there. A
    kernel reporting rax as the syscall NUMBER printed `= 1` here, which is
    `__NR_write`.
    """
    import re
    import subprocess

    out = "/tmp/narf-strace-echo"
    argv = ["strace", *flags, "-o", out, "-e", "trace=write", "/bin/echo", "narf"]
    try:
        proc = subprocess.run(argv, timeout=budget, capture_output=True)
    except FileNotFoundError:
        # Not an error: the build host has no strace, and this case is about
        # the tool, not the kernel. Skipping must not read as a failure.
        return f"{name}=skipped (no strace)"
    except OSError as err:
        return f"{name}=strace did not run (errno {err.errno})"
    except subprocess.TimeoutExpired:
        # Distinguish slow from stuck: strace writes the trace as it goes, so a
        # file that has grown means it was still stepping when the budget ran
        # out, while an empty one means it never got past the exec.
        try:
            with open(out, "r", errors="replace") as fh:
                partial = fh.read().splitlines()
        except OSError:
            partial = []
        tail = partial[-1].strip()[:80] if partial else ""
        return (
            f"{name}=strace did not finish in {budget}s"
            f" (trace lines={len(partial)} last=[{tail}])"
        )
    try:
        with open(out, "r", errors="replace") as fh:
            trace = fh.read()
    except OSError as err:
        return f"{name}=trace unreadable errno {err.errno}"
    hit = next(
        (
            m
            for m in (
                re.search(r"write\(1,.*?, (\d+)\)\s*=\s*(-?\d+)", ln)
                for ln in trace.splitlines()
            )
            if m
        ),
        None,
    )
    if hit is None:
        return f"{name}=no write(1,...) line in the trace rc={proc.returncode}"
    asked, got = int(hit.group(1)), int(hit.group(2))
    verdict = "ok" if asked == got else f"NOT the return (asked {asked}, printed {got})"
    return f"{name}={verdict} write={asked}->{got} rc={proc.returncode}"


def proc_state(path):
    """The state letter from a /proc stat line (the field after `(comm)`)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read().decode("latin-1")
    except OSError as err:
        return f"errno{err.errno}"
    return raw[raw.rfind(")") + 2 :].split(" ")[0]


def main():
    # ASSERTED: every one of these is a contract this kernel meets, checked
    # against the same run on the build host.
    results = [
        case("attach-spinning", spin_victim),
        case("attach-idle", idle_victim),
        sibling_case("sibling-waitany", idle_victim, wait_for_any=True),
        sibling_case("sibling-waitpid", idle_victim, wait_for_any=False),
        thread_group_case("sibling-threadgroup"),
        syscall_stop_case("sysstop-traceme"),
        syscall_stop_case("sysstop-attach", use_attach=True),
    ]
    # RECORDED, not asserted: the traced-execve gap above. Reported on every
    # run so it stays visible — and so that the day it starts working, it says
    # so — but not failing, because failing here would hide the contracts this
    # probe exists to prove. `-f` adds
    # PTRACE_O_TRACECLONE/TRACEFORK/TRACEVFORK, a different path from a bare
    # TRACEME+exec, so both are run.
    observations = [
        strace_return_case("strace-plain"),
        strace_return_case("strace-follow", flags=("-f",)),
    ]
    # Every failure mode this probe can report says so in words: a missing
    # report, a missing verdict, or an attach that errored.
    bad = [
        r
        for r in results
        if "NO " in r
        or "failed" in r
        or "unreadable" in r
        or "NOT " in r
        or "rejected" in r
        or "LOST " in r
        or "never" in r
        or "did not" in r
        or "timed out" in r
    ]
    print("PTRACE-PROBE:", "FAIL" if bad else "OK", " ".join(results + observations))
    sys.stdout.flush()


main()
