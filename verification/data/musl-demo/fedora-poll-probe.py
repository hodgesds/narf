#!/usr/bin/python3
"""Does a blocking wait actually block?

WirePlumber's main loop is GLib's, and GLib polls PipeWire's loop by putting
its EPOLL fd into a `poll(2)` set. If any of these waits returns immediately
instead of blocking for its timeout, that loop spins at 100% of a CPU while
still behaving correctly — which is exactly the shape to look for. Everything
here is deliberately IDLE: nothing is ever ready, so every wait must consume
its full timeout.
"""
import ctypes
import os
import select
import signal
import socket
import time

TIMEOUT_MS = 500
TOLERANCE = 0.4  # seconds; emulation is slow, but never faster than the clock


def took(fn):
    start = time.monotonic()
    ready = fn()
    return time.monotonic() - start, ready


# GLib's main loop does not call poll(2). `g_poll` calls PPOLL where it is
# available, with a NULL timeout whenever it has no timeout source to serve,
# and Python's `select` module exposes no ppoll — so every case above tests a
# syscall GLib never issues. A traced WirePlumber showed its main thread in
# ppoll 1.65 MILLION times in 35 seconds, so ppoll is the one that has to be
# measured directly.
class Pollfd(ctypes.Structure):
    _fields_ = [
        ("fd", ctypes.c_int),
        ("events", ctypes.c_short),
        ("revents", ctypes.c_short),
    ]


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


_libc = ctypes.CDLL("libc.so.6", use_errno=True)
# glibc's wrapper takes four arguments and supplies sigsetsize itself, which is
# where the `8` in a traced `ppoll(..., NULL, NULL, 8)` comes from.
_libc.ppoll.restype = ctypes.c_int
_libc.ppoll.argtypes = [
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_void_p,
]


def _ppoll(fds, timeout_ts):
    arr = (Pollfd * len(fds))()
    for i, (fd, events) in enumerate(fds):
        arr[i].fd = fd
        arr[i].events = events
    ctypes.set_errno(0)
    start = time.monotonic()
    rc = _libc.ppoll(
        ctypes.byref(arr),
        len(fds),
        None if timeout_ts is None else ctypes.byref(timeout_ts),
        None,
    )
    elapsed = time.monotonic() - start
    err = ctypes.get_errno()
    if rc < 0:
        return elapsed, [f"rc=-1 errno={err}"]
    if rc > len(fds):
        # Impossible by construction: ppoll returns how many entries have a
        # non-zero revents, so it can never exceed nfds. Say so loudly rather
        # than letting it read as "lots of fds were ready".
        return elapsed, [f"rc={rc} EXCEEDS nfds={len(fds)}"]
    return elapsed, [f"revents={arr[i].revents:#x}" for i in range(rc)]


def ppoll_timed(fds, seconds):
    """ppoll with a real timeout: must consume it and report nothing ready."""
    ts = Timespec()
    ts.tv_sec = int(seconds)
    ts.tv_nsec = int((seconds - int(seconds)) * 1_000_000_000)
    return _ppoll(fds, ts)


_libc.poll.restype = ctypes.c_int
_libc.poll.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int]


def _poll(fds, timeout_ms):
    arr = (Pollfd * len(fds))()
    for i, (fd, events) in enumerate(fds):
        arr[i].fd = fd
        arr[i].events = events
    ctypes.set_errno(0)
    start = time.monotonic()
    rc = _libc.poll(ctypes.byref(arr), len(fds), timeout_ms)
    elapsed = time.monotonic() - start
    err = ctypes.get_errno()
    if rc < 0:
        return elapsed, [f"rc=-1 errno={err}"]
    if rc > len(fds):
        return elapsed, [f"rc={rc} EXCEEDS nfds={len(fds)}"]
    return elapsed, [f"revents={arr[i].revents:#x}" for i in range(rc)]


def _bounded(bound, call):
    """Run an INDEFINITE wait with SIGALRM as the only way out.

    Every case above passed a 500 ms timeout, so the infinite wait — the one
    an idle GLib loop actually makes — was never measured. It goes through
    ctypes rather than `select`, because PEP 475 makes Python retry an
    EINTR'd syscall transparently: a `select.poll().poll()` with no timeout
    would restart after the handler and block forever instead of reporting.
    """
    previous = signal.signal(signal.SIGALRM, lambda *_: None)
    signal.setitimer(signal.ITIMER_REAL, bound)
    try:
        return call()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def poll_blocking(fds, bound):
    """poll(2) with timeout -1: block until an fd is ready, so forever here."""
    return _bounded(bound, lambda: _poll(fds, -1))


def ppoll_blocking(fds, bound):
    """ppoll with a NULL timeout — the call GLib makes when it has nothing
    scheduled. It must block until an fd is ready, i.e. forever here, so the
    only way out is a signal. SIGALRM bounds it; returning BEFORE the alarm is
    the defect."""
    return _bounded(bound, lambda: _ppoll(fds, None))


def main() -> None:
    results = []

    # 1. poll(2) with no descriptors at all: a pure timeout.
    results.append(("poll-empty", took(lambda: select.poll().poll(TIMEOUT_MS))))

    # 2. poll(2) on an idle eventfd.
    efd = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
    p = select.poll()
    p.register(efd, select.POLLIN)
    results.append(("poll-eventfd", took(lambda: p.poll(TIMEOUT_MS))))

    # 3. epoll_wait on an idle eventfd.
    ep = select.epoll()
    ep.register(efd, select.EPOLLIN)
    results.append(("epoll-wait", took(lambda: ep.poll(TIMEOUT_MS / 1000.0))))

    # 4. The shape that matters: poll(2) over an EPOLL fd whose only member is
    #    idle. This is GLib polling PipeWire's loop fd.
    pe = select.poll()
    pe.register(ep.fileno(), select.POLLIN)
    results.append(("poll-of-epoll", took(lambda: pe.poll(TIMEOUT_MS))))

    # 5. Same, with an idle timerfd in the epoll set, as the ALSA node has.
    tfd = os.timerfd_create(time.CLOCK_MONOTONIC, flags=os.TFD_NONBLOCK | os.TFD_CLOEXEC)
    os.timerfd_settime(tfd, initial=30.0, interval=0.0)
    ep.register(tfd, select.EPOLLIN)
    results.append(("poll-of-epoll+timerfd", took(lambda: pe.poll(TIMEOUT_MS))))

    # 6. GLib's EXACT mask. `g_source_add_unix_fd` registers
    #    G_IO_IN|G_IO_ERR|G_IO_HUP, and WirePlumber registers PipeWire's loop
    #    fd that way (lib/wp/core.c:wp_loop_source_new). POLLERR and POLLHUP
    #    are OUTPUT-ONLY in poll(2): the kernel ignores them in `events` and
    #    only ever reports them in `revents`. A kernel that treats them as
    #    requested returns immediately every time, and since GLib counts
    #    G_IO_ERR as "ready" the loop dispatches, finds nothing, and spins -
    #    silently, because nothing is actually wrong with any fd.
    glib_mask = select.POLLIN | select.POLLERR | select.POLLHUP
    pg = select.poll()
    pg.register(efd, glib_mask)
    results.append(("poll-eventfd-glibmask", took(lambda: pg.poll(TIMEOUT_MS))))

    pge = select.poll()
    pge.register(ep.fileno(), glib_mask)
    results.append(("poll-of-epoll-glibmask", took(lambda: pge.poll(TIMEOUT_MS))))

    # 7. CONSUME, then wait. The waits above were all on objects that were
    #    never signalled; this is the other half, and the one that matches a
    #    loop which dispatches forever without logging: a level that is raised,
    #    consumed, and never lowered. `pw_loop` signals itself with an eventfd
    #    (`spa_loop_utils_add_event`, `pw_loop_invoke`) and talks to the daemon
    #    over a Unix socket, so both must go quiet once drained.
    os.eventfd_write(efd, 7)
    assert os.eventfd_read(efd) == 7
    results.append(("eventfd-after-read", took(lambda: p.poll(TIMEOUT_MS))))

    a, b = socket.socketpair()
    a.setblocking(False)
    b.setblocking(False)
    b.send(b"x" * 16)
    assert a.recv(64) == b"x" * 16
    ps = select.poll()
    ps.register(a.fileno(), glib_mask)
    results.append(("socketpair-after-read", took(lambda: ps.poll(TIMEOUT_MS))))

    # An expired timerfd that has been read must go quiet until it is re-armed.
    t2 = os.timerfd_create(time.CLOCK_MONOTONIC, flags=os.TFD_NONBLOCK | os.TFD_CLOEXEC)
    os.timerfd_settime(t2, initial=0.05, interval=0.0)
    time.sleep(0.15)
    os.read(t2, 8)
    pt = select.poll()
    pt.register(t2, glib_mask)
    results.append(("timerfd-after-read", took(lambda: pt.poll(TIMEOUT_MS))))

    # And the whole shape at once: those three inside an epoll, polled the way
    # GLib polls PipeWire's loop.
    ep2 = select.epoll()
    ep2.register(efd, select.EPOLLIN)
    ep2.register(a.fileno(), select.EPOLLIN)
    ep2.register(t2, select.EPOLLIN)
    pq = select.poll()
    pq.register(ep2.fileno(), glib_mask)
    results.append(("drained-epoll-glibmask", took(lambda: pq.poll(TIMEOUT_MS))))
    ep2.close()
    a.close()
    b.close()
    os.close(t2)

    # 8. The one fd in a session manager's loop that is not generic: an ALSA
    #    CONTROL descriptor with mixer events subscribed. ACP keeps one open
    #    per card and polls it for the whole life of the session, so a control
    #    fd that reports readable with no event queued spins that loop.
    #    SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS = _IOWR('U', 0x16, int).
    import fcntl
    import struct

    SUBSCRIBE_EVENTS = 0xC0045516
    for card in ("/dev/snd/controlC0", "/dev/snd/controlC1"):
        try:
            cfd = os.open(card, os.O_RDONLY)
        except OSError as err:
            results.append((f"ctl{card[-1]}-open", (TOLERANCE, [f"errno {err.errno}"])))
            continue
        pc = select.poll()
        pc.register(cfd, select.POLLIN)
        results.append((f"ctl{card[-1]}-idle", took(lambda: pc.poll(TIMEOUT_MS))))
        try:
            fcntl.ioctl(cfd, SUBSCRIBE_EVENTS, struct.pack("i", 1), True)
        except OSError as err:
            results.append((f"ctl{card[-1]}-subscribe", (TOLERANCE, [f"errno {err.errno}"])))
            os.close(cfd)
            continue
        results.append((f"ctl{card[-1]}-subscribed", took(lambda: pc.poll(TIMEOUT_MS))))
        os.close(cfd)

    # 9. ppoll(2), the syscall GLib actually waits in. Same idle objects, and
    #    GLib's exact mask, in both shapes it uses: a bounded timeout and the
    #    indefinite NULL-timeout wait.
    glib_fds = [
        (efd, glib_mask),
        (ep.fileno(), glib_mask),
        (tfd, glib_mask),
    ]
    results.append(("ppoll-timeout", ppoll_timed(glib_fds, TIMEOUT_MS / 1000.0)))
    results.append(("ppoll-null", ppoll_blocking(glib_fds, TIMEOUT_MS / 1000.0)))
    # And the degenerate set, which isolates the wait itself from any fd:
    results.append(("ppoll-empty-timeout", ppoll_timed([], TIMEOUT_MS / 1000.0)))
    results.append(("ppoll-empty-null", ppoll_blocking([], TIMEOUT_MS / 1000.0)))
    # The same two through poll(2) with timeout -1. If BOTH poll and ppoll
    # return early it is the indefinite-wait path, not ppoll; if only ppoll
    # does, it is ppoll's own.
    results.append(("poll-infinite", poll_blocking(glib_fds, TIMEOUT_MS / 1000.0)))
    results.append(("poll-empty-infinite", poll_blocking([], TIMEOUT_MS / 1000.0)))
    # Bisect the set one fd at a time. An early return with nothing ready
    # means some fd claims readiness through a channel that its own level
    # then denies, and naming that fd is the difference between fixing the
    # fd and fixing the poll return path.
    for label, one in (("efd", efd), ("epoll", ep.fileno()), ("timerfd", tfd)):
        results.append(
            (f"poll-inf-{label}", poll_blocking([(one, glib_mask)], TIMEOUT_MS / 1000.0))
        )
        results.append(
            (f"ppoll-t-{label}", ppoll_timed([(one, glib_mask)], TIMEOUT_MS / 1000.0))
        )

    bad = []
    out = []
    for name, (elapsed, ready) in results:
        out.append(f"{name}={elapsed:.3f}s/{len(ready)}")
        if elapsed < TOLERANCE:
            bad.append(f"{name} returned after {elapsed:.3f}s with {ready!r}")

    print("POLL-PROBE:", "FAIL" if bad else "OK", " ".join(out))
    for line in bad:
        print("POLL-PROBE:  ", line)

    os.close(tfd)
    ep.close()
    os.close(efd)


main()
