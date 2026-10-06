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


def main():
    results = [
        case("attach-spinning", spin_victim),
        case("attach-idle", idle_victim),
        sibling_case("sibling-waitany", idle_victim, wait_for_any=True),
        sibling_case("sibling-waitpid", idle_victim, wait_for_any=False),
        thread_group_case("sibling-threadgroup"),
    ]
    # Every failure mode this probe can report says so in words: a missing
    # report, a missing verdict, or an attach that errored.
    bad = [r for r in results if "NO " in r or "failed" in r or "unreadable" in r]
    print("PTRACE-PROBE:", "FAIL" if bad else "OK", " ".join(results))
    sys.stdout.flush()


main()
