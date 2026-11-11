#!/usr/bin/python3
"""Guest-side load pieces for the QEMU soak that need sockets, ptys or timers.

Each subcommand is one loop the shell orchestrator (soak-guest.sh) runs as a
worker. A worker reports progress by rewriting its heartbeat file and exits
non-zero with one line on stderr when something that must work did not.
"""
import errno
import mmap
import os
import pty
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time

BLOCK = os.urandom(1 << 20)


def beat(path, value):
    try:
        with open(path, "w") as f:
            f.write(f"{value}\n")
    except OSError:
        pass


def connect(host, port, tls, timeout=30):
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname="narf-soak")
    return sock


def read_reply(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            raise OSError("connection closed before the reply header")
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    status = int(head.split(b" ", 2)[1])
    return status, length, body


def upload(host, port, tls, mib):
    """One large request body, the way an HTTPS client uploads a file."""
    sock = connect(host, port, tls)
    total = mib << 20
    sock.sendall(f"PUT /up HTTP/1.1\r\nHost: soak\r\nContent-Length: {total}\r\n\r\n".encode())
    sent = 0
    while sent < total:
        sock.sendall(BLOCK)
        sent += len(BLOCK)
    status, length, body = read_reply(sock)
    while len(body) < length:
        body += sock.recv(65536)
    sock.close()
    if status != 200 or int(body.split()[1]) != total:
        raise OSError(f"upload of {total} bytes answered {status} {body[:40]!r}")
    return total


def download(host, port, tls, mib):
    sock = connect(host, port, tls)
    sock.sendall(f"GET /down?mb={mib} HTTP/1.1\r\nHost: soak\r\n\r\n".encode())
    status, length, body = read_reply(sock)
    got = len(body)
    while got < length:
        chunk = sock.recv(1 << 20)
        if not chunk:
            break
        got += len(chunk)
    sock.close()
    if status != 200 or got != mib << 20:
        raise OSError(f"download of {mib} MiB answered {status}, {got} bytes")
    return got


def cmd_tcp(hb, host, port, tls, mib, secs):
    """Alternate uploads and downloads, with a burst of short requests between."""
    end = time.monotonic() + secs
    done = 0
    while time.monotonic() < end:
        done += upload(host, port, tls, mib)
        beat(hb, done >> 20)
        done += download(host, port, tls, mib)
        beat(hb, done >> 20)
        for _ in range(20):
            sock = connect(host, port, tls)
            sock.sendall(b"GET /ping HTTP/1.1\r\nHost: soak\r\n\r\n")
            read_reply(sock)
            sock.close()


def cmd_listen(hb, port):
    """Guest-side server for the host's connections through the port forward.

    `S <bytes>` makes the guest send that many bytes; `R <bytes>` makes it
    read them and answer with the count.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    served = [0]

    def serve(conn):
        try:
            conn.settimeout(60)
            line = b""
            while not line.endswith(b"\n"):
                byte = conn.recv(1)
                if not byte:
                    return
                line += byte
            op, count = line.split()
            count = int(count)
            if op == b"S":
                left = count
                while left > 0:
                    conn.sendall(BLOCK[: min(left, len(BLOCK))])
                    left -= min(left, len(BLOCK))
            else:
                got = 0
                while got < count:
                    chunk = conn.recv(1 << 20)
                    if not chunk:
                        break
                    got += len(chunk)
                conn.sendall(f"{got}\n".encode())
            served[0] += count >> 20
            beat(hb, served[0])
        except OSError:
            pass
        finally:
            conn.close()

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


def cmd_udp(hb, host, port, secs):
    """Datagram echo through the NIC, and a loopback pair beside it."""
    out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out.settimeout(1.0)
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.bind(("127.0.0.1", 0))
    b.bind(("127.0.0.1", 0))
    b.settimeout(1.0)
    end = time.monotonic() + secs
    sent = lost = 0
    while time.monotonic() < end:
        payload = struct.pack("!Q", sent) + BLOCK[: 64 + sent % 1200]
        out.sendto(payload, (host, port))
        try:
            reply, _ = out.recvfrom(4096)
            if reply != payload:
                lost += 1
        except socket.timeout:
            lost += 1
        a.sendto(payload, b.getsockname())
        if b.recvfrom(4096)[0] != payload:
            raise OSError("loopback datagram came back different")
        sent += 1
        if sent % 50 == 0:
            beat(hb, f"{sent} lost={lost}")
            time.sleep(0.01)
    if sent and lost * 2 > sent:
        raise OSError(f"{lost} of {sent} datagrams to {host}:{port} were not echoed")


def cmd_unix(hb, secs):
    """AF_UNIX stream traffic with descriptor passing, as desktop IPC does."""
    end = time.monotonic() + secs
    rounds = 0
    while time.monotonic() < end:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        pid = os.fork()
        if pid == 0:
            parent.close()
            try:
                while True:
                    msg, fds, _, _ = socket.recv_fds(child, 65536, 4)
                    if not msg:
                        break
                    total = 0
                    for fd in fds:
                        size = os.fstat(fd).st_size
                        with mmap.mmap(fd, size, prot=mmap.PROT_READ) as view:
                            total += view[0] + view[size - 1]
                        os.close(fd)
                    child.sendall(struct.pack("!I", total) + msg[:16])
            finally:
                os._exit(0)
        child.close()
        poller = select.epoll()
        poller.register(parent, select.EPOLLIN)
        for i in range(200):
            fd = os.memfd_create("soak")
            size = 4096 * (1 + i % 64)
            os.ftruncate(fd, size)
            with mmap.mmap(fd, size) as view:
                view[0] = i % 251
                view[size - 1] = 7
            socket.send_fds(parent, [BLOCK[: 256 + i]], [fd])
            os.close(fd)
            if not poller.poll(30):
                raise OSError("no reply on the unix socket within 30 s")
            reply = parent.recv(64)
            if struct.unpack("!I", reply[:4])[0] != i % 251 + 7:
                raise OSError("a passed memfd read back different contents")
        poller.close()
        parent.close()
        os.waitpid(pid, 0)
        rounds += 1
        beat(hb, rounds)


def cmd_timers(hb, secs):
    """Interval timer signals, sleeping threads and stop/continue."""
    ticks = [0]
    signal.signal(signal.SIGALRM, lambda *_: ticks.__setitem__(0, ticks[0] + 1))
    signal.setitimer(signal.ITIMER_REAL, 0.002, 0.002)
    stop = threading.Event()

    def sleeper(period):
        while not stop.is_set():
            time.sleep(period)

    threads = [threading.Thread(target=sleeper, args=(0.001 * (i + 1),)) for i in range(8)]
    for t in threads:
        t.start()
    end = time.monotonic() + secs
    rounds = 0
    while time.monotonic() < end:
        pid = os.fork()
        if pid == 0:
            signal.setitimer(signal.ITIMER_REAL, 0, 0)
            while True:
                time.sleep(0.001)
        for _ in range(20):
            os.kill(pid, signal.SIGSTOP)
            os.kill(pid, signal.SIGCONT)
        os.kill(pid, signal.SIGTERM)
        os.waitpid(pid, 0)
        try:
            select.select([], [], [], 0.05)
        except InterruptedError:
            pass
        rounds += 1
        if rounds % 10 == 0:
            beat(hb, f"{rounds} ticks={ticks[0]}")
    stop.set()
    signal.setitimer(signal.ITIMER_REAL, 0, 0)
    for t in threads:
        t.join()
    if ticks[0] == 0:
        raise OSError("the interval timer never delivered SIGALRM")


def cmd_pty(hb, secs):
    """A shell on a pty, typed at and read from, as a terminal emulator does."""
    end = time.monotonic() + secs
    rounds = 0
    while time.monotonic() < end:
        pid, fd = pty.fork()
        if pid == 0:
            os.execv("/usr/bin/bash", ["bash", "--norc", "--noprofile", "-i"])
        want = b"SOAK-PTY-%d-DONE" % rounds
        os.write(fd, b"stty -echo; ls -la /usr/bin | tail -n 400; stty -a; tty\n")
        os.write(fd, b"echo SOAK-PTY-" + str(rounds).encode() + b"-DONE\n")
        seen = b""
        deadline = time.monotonic() + 60
        while want not in seen:
            ready, _, _ = select.select([fd], [], [], 1.0)
            if ready:
                try:
                    seen = (seen + os.read(fd, 65536))[-4096:]
                except OSError as e:
                    if e.errno == errno.EIO:
                        break
                    raise
            if time.monotonic() > deadline:
                raise OSError("the pty shell did not answer within 60 s")
        os.write(fd, b"exit\n")
        os.close(fd)
        os.waitpid(pid, 0)
        rounds += 1
        beat(hb, rounds)


def cmd_fsio(hb, directory, secs):
    """Save-by-rename, an fsynced append log and random writes with fdatasync."""
    os.makedirs(directory, exist_ok=True)
    end = time.monotonic() + secs
    rounds = 0
    log = os.open(os.path.join(directory, "wal.log"), os.O_CREAT | os.O_WRONLY | os.O_APPEND)
    db = os.open(os.path.join(directory, "data.db"), os.O_CREAT | os.O_RDWR)
    os.ftruncate(db, 32 << 20)
    dirfd = os.open(directory, os.O_RDONLY)
    while time.monotonic() < end:
        name = os.path.join(directory, f"state-{rounds % 50}.json")
        tmp = name + ".tmp"
        with open(tmp, "wb") as f:
            f.write(BLOCK[: 2000 + (rounds * 37) % 60000])
            f.flush()
            os.fsync(f.fileno())
        os.rename(tmp, name)
        os.fsync(dirfd)
        os.write(log, BLOCK[: 300 + rounds % 3000])
        os.fsync(log)
        os.pwrite(db, BLOCK[:8192], (rounds * 8192 * 131) % (32 << 20))
        os.fdatasync(db)
        with open(name, "rb") as f:
            if f.read(16) != BLOCK[:16]:
                raise OSError(f"{name} read back different after rename")
        if os.fstat(log).st_size > (64 << 20):
            os.ftruncate(log, 0)
        rounds += 1
        if rounds % 5 == 0:
            beat(hb, rounds)


def cmd_bigwrite(path, chunk_mib, count, sync):
    """Write <count> chunks of <chunk_mib> MiB, one write() each, and time
    every call; then, on request, one fsync."""
    chunk = BLOCK * chunk_mib
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    times = []
    for _ in range(count):
        t = time.monotonic()
        done = 0
        while done < len(chunk):
            done += os.write(fd, chunk[done:])
        times.append((time.monotonic() - t) * 1000)
    total = sum(times) / 1000
    line = (f"bigwrite: {count} x {chunk_mib} MiB write(): min {min(times):.0f} ms, "
            f"avg {sum(times) / len(times):.0f} ms, max {max(times):.0f} ms, "
            f"{count * chunk_mib / total:.1f} MiB/s")
    if sync == "fsync":
        t = time.monotonic()
        os.fsync(fd)
        line += f"; fsync {(time.monotonic() - t) * 1000:.0f} ms"
    os.close(fd)
    print(line)


def cmd_crash(mib):
    """Die of SIGSEGV with <mib> MiB of touched heap, for a core dump."""
    heap = bytearray(mib << 20)
    for off in range(0, len(heap), 4096):
        heap[off] = 1
    import ctypes

    ctypes.string_at(0)


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    try:
        if cmd == "tcp":
            cmd_tcp(args[0], args[1], int(args[2]), args[3] == "tls", int(args[4]), int(args[5]))
        elif cmd == "listen":
            cmd_listen(args[0], int(args[1]))
        elif cmd == "udp":
            cmd_udp(args[0], args[1], int(args[2]), int(args[3]))
        elif cmd == "unix":
            cmd_unix(args[0], int(args[1]))
        elif cmd == "timers":
            cmd_timers(args[0], int(args[1]))
        elif cmd == "pty":
            cmd_pty(args[0], int(args[1]))
        elif cmd == "fsio":
            cmd_fsio(args[0], args[1], int(args[2]))
        elif cmd == "bigwrite":
            cmd_bigwrite(args[0], int(args[1]), int(args[2]), args[3])
        elif cmd == "crash":
            cmd_crash(int(args[0]))
        else:
            sys.exit(f"soak-guest.py: unknown command {cmd}")
    except Exception as e:  # one line for the serial log, then a failing exit
        sys.stderr.write(f"{cmd}: {type(e).__name__}: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
