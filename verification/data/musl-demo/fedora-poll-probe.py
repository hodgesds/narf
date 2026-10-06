#!/usr/bin/python3
"""Does a blocking wait actually block?

WirePlumber's main loop is GLib's, and GLib polls PipeWire's loop by putting
its EPOLL fd into a `poll(2)` set. If any of these waits returns immediately
instead of blocking for its timeout, that loop spins at 100% of a CPU while
still behaving correctly — which is exactly the shape to look for. Everything
here is deliberately IDLE: nothing is ever ready, so every wait must consume
its full timeout.
"""
import os
import select
import socket
import time

TIMEOUT_MS = 500
TOLERANCE = 0.4  # seconds; emulation is slow, but never faster than the clock


def took(fn):
    start = time.monotonic()
    ready = fn()
    return time.monotonic() - start, ready


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
