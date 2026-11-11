#!/usr/bin/python3
"""Host side of the QEMU soak (run-soak.sh).

Everything listens on 127.0.0.1 only; the guest reaches it through QEMU's
user-mode network (10.0.2.2 / 10.0.3.2) and the host reaches the guest
through localhost port forwards.

* An HTTP and an HTTPS server the guest uploads to and downloads from, and a
  UDP echo.
* SSH sessions into the guest: a pty session that starts tmux and runs an
  HTTPS upload in it (what was running on the hardware when it hung), short
  logins in a loop, and bulk data over ssh in both directions.
* Bulk TCP into a listener in the guest.
* A watch on the serial log. `SOAK-PULSE` lines stopping for --stall seconds
  is a stall: every vCPU's registers are dumped through QMP several times
  (the instruction pointers say where each CPU is stuck), the kernel's
  lockup detector gets --linger seconds to report, and QEMU is quit. The
  registers are also sampled every few seconds during the run.
"""
import argparse
import http.server
import json
import os
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse

BLOCK = os.urandom(1 << 20)
KERNEL_LINES = re.compile(
    r"watchdog:|nvme:|btrfs:|oom:|Out of memory|KERNEL PANIC|CPU EXCEPTION|panicked at|"
    r"READ-ONLY|GateTimeout|SOAK-ERR|SOAK-PHASE|SOAK-START|SOAK-END|SOAK-NET|UNKILLABLE|"
    r"STUCK|BUSY-STREAK|SOAK-BASELINE|SOAK-FINAL|SOAK-ERRCOUNT|SOAK-OUT|SOAK-EXITWB|"
    r"SOAK-FORKFLUSH|SOAK-DIRTYEXIT|SOAK-EPISODE|SOAK-NOTE"
)


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = {}

    def add(self, key, n=1):
        with self.lock:
            self.counts[key] = self.counts.get(key, 0) + n


STATS = Stats()
T0 = time.monotonic()
LOG_LOCK = threading.Lock()
EVENTS = None


def event(text):
    line = f"[host +{time.monotonic() - T0:7.1f}s] {text}"
    with LOG_LOCK:
        print(line, flush=True)
        if EVENTS:
            EVENTS.write(line + "\n")
            EVENTS.flush()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, body):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path != "/down":
            return self.reply(b"pong\n")
        mib = int(parse_qs(url.query).get("mb", ["1"])[0])
        self.send_response(200)
        self.send_header("Content-Length", str(mib << 20))
        self.end_headers()
        for _ in range(mib):
            self.wfile.write(BLOCK)
        STATS.add("served_down_mib", mib)

    def do_PUT(self):
        left = int(self.headers.get("Content-Length", "0"))
        got = 0
        while left > 0:
            chunk = self.rfile.read(min(left, 1 << 20))
            if not chunk:
                break
            got += len(chunk)
            left -= len(chunk)
        STATS.add("served_up_mib", got >> 20)
        self.reply(f"OK {got}\n".encode())

    do_POST = do_PUT


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


def serve_http(port, cert=None):
    srv = Server(("127.0.0.1", port), Handler)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert + ".crt", cert + ".key")
        # The handshake runs in the connection's own thread, on first read.
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def serve_udp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))

    def loop():
        while True:
            data, peer = sock.recvfrom(65536)
            sock.sendto(data, peer)
            STATS.add("udp_echoed")

    threading.Thread(target=loop, daemon=True).start()


class Qmp:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def command(self, execute, **arguments):
        with self.lock:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect(self.path)
            f = sock.makefile("rw")
            f.readline()
            for cmd in ({"execute": "qmp_capabilities"}, {"execute": execute, "arguments": arguments}):
                f.write(json.dumps(cmd) + "\n")
                f.flush()
                while True:
                    reply = json.loads(f.readline())
                    if "return" in reply or "error" in reply:
                        break
            sock.close()
            return reply.get("return")

    def hmp(self, line):
        return self.command("human-monitor-command", **{"command-line": line}) or ""

    def quit(self):
        try:
            self.command("quit")
        except (OSError, ValueError):
            pass


def cpu_summary(registers):
    """`cpu:rip:cs[:hlt]` for each vCPU of an `info registers -a` dump."""
    out = []
    for block in re.split(r"(?m)^CPU#", registers)[1:]:
        cpu = block.split("\n", 1)[0].strip()
        rip = re.search(r"RIP=([0-9a-f]+)", block)
        cs = re.search(r"CS =([0-9a-f]+)", block)
        hlt = " hlt" if re.search(r"HLT=1", block) else ""
        out.append(f"{cpu}:{rip.group(1) if rip else '?'}:cs{cs.group(1) if cs else '?'}{hlt}")
    return " ".join(out)


class Serial:
    """Follows the serial log the xtask writes."""

    def __init__(self, path):
        self.path = path
        self.started = self.ended = self.panicked = False
        self.heavy = False
        self.last_pulse = None
        self.last_pulse_line = ""
        self.last_up = "?"
        self.lines = 0
        threading.Thread(target=self.follow, daemon=True).start()

    def follow(self):
        while not os.path.exists(self.path):
            time.sleep(0.5)
        with open(self.path, "rb") as f:
            tail = b""
            while True:
                chunk = f.read(65536)
                if not chunk:
                    time.sleep(0.2)
                    continue
                tail += chunk
                *lines, tail = tail.split(b"\n")
                for raw in lines:
                    self.line(raw.decode("utf-8", "replace").rstrip("\r"))

    def line(self, text):
        self.lines += 1
        if "SOAK-PULSE" in text:
            self.last_pulse = time.monotonic()
            self.last_pulse_line = text
            m = re.search(r"up=([0-9.]+)", text)
            if m:
                self.last_up = m.group(1)
            return
        if "SOAK-START" in text:
            self.started = True
            self.last_pulse = time.monotonic()
        if "SOAK-PHASE heavy" in text:
            self.heavy = True
        if "SOAK-END" in text:
            self.ended = True
        if "KERNEL PANIC" in text or "CPU EXCEPTION" in text or "panicked at" in text:
            self.panicked = True
        if KERNEL_LINES.search(text) and "SOAK-PROBE" not in text and "SOAK-CPU" not in text:
            event("serial: " + text[:400])
        elif "STUCK" in text or "BUSY-STREAK" in text:
            event("serial: " + text[:400])


def ssh_base(key, port, user):
    return [
        "ssh", "-F", "/dev/null", "-i", key, "-p", str(port),
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=20",
        "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=6",
        f"{user}@127.0.0.1",
    ]  # fmt: skip


def ssh_env():
    env = dict(os.environ)
    env["TERM"] = "xterm-256color"
    return env


def ssh_tmux(args, port, guest_host, stop, tag):
    """A pty login that starts tmux and runs an HTTPS upload loop in a pane."""
    while not stop.is_set():
        cmd = ssh_base(args.key, port, "narf") + ["-tt", "tmux new-session -A -s soak"]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=ssh_env())
        got = [0]

        def drain(out=proc.stdout, got=got):
            while True:
                chunk = out.read1(65536)
                if not chunk:
                    break
                got[0] += len(chunk)

        threading.Thread(target=drain, daemon=True).start()
        try:
            time.sleep(3)
            upload = (f"python3 /run/narf-soak/soak-guest.py tcp /tmp/soak-ssh-{tag} "
                      f"{guest_host} {args.tls_port} tls {args.xfer_mb} 50\n")
            proc.stdin.write(upload.encode())
            proc.stdin.flush()
            for i in range(25):
                if stop.wait(2) or proc.poll() is not None:
                    break
                if i == 2:
                    # A second pane with a chatty program, then back.
                    proc.stdin.write(b'\x02"')
                    proc.stdin.write(b"while :; do ls -la /usr/lib | tail -n 40; sleep 0.3; done\n")
                proc.stdin.flush()
            proc.stdin.write(b"\x03")
            proc.stdin.flush()
        except OSError:
            pass
        subprocess.run(ssh_base(args.key, port, "narf") + ["tmux kill-server"],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=120, check=False)
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            STATS.add(f"ssh_tmux_{tag}_hung")
            event(f"ssh tmux session {tag} did not end within 60 s of tmux kill-server")
        STATS.add(f"ssh_tmux_{tag}_rounds")
        STATS.add(f"ssh_tmux_{tag}_bytes", got[0])
        if got[0] == 0:
            STATS.add(f"ssh_tmux_{tag}_silent")
            stop.wait(5)


def ssh_logins(args, port, stop, tag):
    while not stop.is_set():
        try:
            out = subprocess.run(
                ssh_base(args.key, port, "narf") + ["uname -s; id -u; ls /usr/bin | wc -l"],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=False)
            ok = out.returncode == 0 and b"1000" in out.stdout
        except subprocess.TimeoutExpired:
            ok = False
        STATS.add(f"ssh_login_{tag}_{'ok' if ok else 'failed'}")
        stop.wait(2)


def ssh_bulk(args, port, stop, tag):
    payload = BLOCK * args.xfer_mb
    while not stop.is_set():
        try:
            up = subprocess.run(ssh_base(args.key, port, "root") + ["wc -c"], input=payload,
                                capture_output=True, timeout=600, check=False)
            down = subprocess.run(
                ssh_base(args.key, port, "root") + [f"head -c {len(payload)} /dev/zero"],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=600, check=False)
            ok = up.stdout.strip() == str(len(payload)).encode() and len(down.stdout) == len(payload)
        except subprocess.TimeoutExpired:
            ok = False
        STATS.add(f"ssh_bulk_{tag}_{'ok' if ok else 'failed'}")
        stop.wait(1 if ok else 5)


def inbound(args, port, stop, tag):
    """Bulk TCP into the guest's listener, both directions."""
    total = args.xfer_mb << 20
    while not stop.is_set():
        try:
            for op in (b"R", b"S"):
                sock = socket.create_connection(("127.0.0.1", port), timeout=30)
                sock.settimeout(120)
                sock.sendall(op + b" %d\n" % total)
                if op == b"R":
                    for _ in range(args.xfer_mb):
                        sock.sendall(BLOCK)
                    ok = sock.makefile().readline().strip() == str(total)
                else:
                    got = 0
                    while got < total:
                        chunk = sock.recv(1 << 20)
                        if not chunk:
                            break
                        got += len(chunk)
                    ok = got == total
                sock.close()
                STATS.add(f"inbound_{tag}_{'ok' if ok else 'failed'}")
        except OSError:
            STATS.add(f"inbound_{tag}_failed")
            stop.wait(5)


def main():
    global EVENTS
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial-log", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--qmp", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--cert", required=True, help="path prefix of the TLS .crt/.key")
    ap.add_argument("--http-port", type=int, default=42080)
    ap.add_argument("--tls-port", type=int, default=42443)
    ap.add_argument("--udp-port", type=int, default=42053)
    ap.add_argument("--ssh", type=int, action="append", default=[],
                    help="forwarded sshd port; give one per guest NIC")
    ap.add_argument("--inbound", type=int, action="append", default=[],
                    help="forwarded port of the guest's listener; one per guest NIC")
    ap.add_argument("--guest-host", action="append", default=[],
                    help="the host's address as each guest NIC sees it")
    ap.add_argument("--xfer-mb", type=int, default=100)
    ap.add_argument("--boot-secs", type=int, default=420,
                    help="seconds allowed before SOAK-START")
    ap.add_argument("--deadline", type=int, required=True,
                    help="seconds after which QEMU is quit regardless")
    ap.add_argument("--stall", type=int, default=30)
    ap.add_argument("--linger", type=int, default=60)
    ap.add_argument("--rip-every", type=float, default=5.0)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    EVENTS = open(os.path.join(args.out_dir, "host-events.log"), "w")
    serve_http(args.http_port)
    serve_http(args.tls_port, args.cert)
    serve_udp(args.udp_port)
    serial = Serial(args.serial_log)
    qmp = Qmp(args.qmp)
    stop = threading.Event()
    rips = open(os.path.join(args.out_dir, "vcpu-rip-samples.log"), "w")
    event(f"servers on 127.0.0.1: http {args.http_port}, https {args.tls_port}, udp {args.udp_port}")

    def registers(label):
        try:
            dump = qmp.hmp("info registers -a")
        except (OSError, ValueError) as e:
            event(f"QMP register dump failed: {e}")
            return
        path = os.path.join(args.out_dir, f"registers-{label}.txt")
        with open(path, "w") as f:
            f.write(dump)
        event(f"{label}: {cpu_summary(dump)}")

    load_started = False
    verdict = "deadline"
    next_rip = 0.0
    booted = None
    while True:
        time.sleep(0.5)
        now = time.monotonic()
        if booted is None:
            # Nothing is timed until QEMU prints: the build and the wait for
            # a build slot come first and can take any amount of time.
            if serial.lines == 0:
                continue
            booted = now
            event("QEMU started (first serial output)")
        if serial.heavy and not load_started:
            load_started = True
            for i, port in enumerate(args.ssh):
                host = args.guest_host[i] if i < len(args.guest_host) else "10.0.2.2"
                for target, extra in ((ssh_tmux, (host,)), (ssh_logins, ()), (ssh_bulk, ())):
                    threading.Thread(target=target, args=(args, port, *extra, stop, f"nic{i}"),
                                     daemon=True).start()
            for i, port in enumerate(args.inbound):
                threading.Thread(target=inbound, args=(args, port, stop, f"nic{i}"),
                                 daemon=True).start()
            event("host load started (ssh sessions, inbound TCP)")
        if serial.started and now >= next_rip and not serial.ended:
            next_rip = now + args.rip_every
            try:
                rips.write(f"{now - T0:.1f} up={serial.last_up} "
                           f"{cpu_summary(qmp.hmp('info registers -a'))}\n")
                rips.flush()
            except (OSError, ValueError):
                if now - booted > 30:
                    verdict = "qemu-exited"
                    break
        if serial.panicked:
            event("kernel panic marker on the serial console")
            time.sleep(5)
            registers("panic")
            verdict = "panic"
            break
        if serial.ended:
            event("guest finished the soak; waiting for it to power off")
            stop.set()
            end = time.monotonic() + 180
            while time.monotonic() < end:
                try:
                    qmp.hmp("info status")
                except (OSError, ValueError):
                    break
                time.sleep(2)
            verdict = "completed"
            break
        if serial.started and serial.last_pulse and now - serial.last_pulse > args.stall:
            event(f"STALL: no SOAK-PULSE for {args.stall} s; last: {serial.last_pulse_line}")
            for i in range(5):
                registers(f"stall-{i}")
                time.sleep(1)
            event(f"waiting {args.linger} s for the lockup detector to report")
            time.sleep(args.linger)
            registers("stall-final")
            verdict = "stall"
            break
        if not serial.started and now - booted > args.boot_secs:
            event(f"the guest did not start the soak within {args.boot_secs} s")
            registers("no-start")
            verdict = "no-start"
            break
        if now - booted > args.deadline:
            event("hard deadline reached")
            registers("deadline")
            break
    stop.set()
    qmp.quit()
    with open(os.path.join(args.out_dir, "host-summary.txt"), "w") as f:
        f.write(f"verdict: {verdict}\n")
        for key in sorted(STATS.counts):
            f.write(f"{key}: {STATS.counts[key]}\n")
    event(f"verdict: {verdict}; " + ", ".join(f"{k}={v}" for k, v in sorted(STATS.counts.items())))
    sys.exit(0 if verdict == "completed" else 1)


if __name__ == "__main__":
    main()
