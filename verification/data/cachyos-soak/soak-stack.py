#!/usr/bin/python3
"""Kernel stacks of the running soak guest's busy vCPUs, through QMP.

  soak-stack.py <run-dir> [words]

For every vCPU that is in kernel mode and not halted, reads <words> stack
words (default 1024) above its stack pointer and prints the ones that are
return addresses into the kernel's text, symbolized against the kernel ELF
in the run directory. The lockup detector's own backtrace keeps twenty
frames; a deep filesystem path uses those up before it reaches whoever
called it, and this goes on until the stack ends.

It is a scan, not an unwind: stale words left by earlier calls show up too.
Read it from the bottom (the outermost caller) upwards.
"""
import bisect
import importlib.util
import json
import os
import re
import socket
import sys
import time


def load_report():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location("soak_report", os.path.join(here, "soak-report.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hmp(path, line):
    for _ in range(40):
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(20)
            sock.connect(path)
            f = sock.makefile("rw")
            f.readline()
            reply = {}
            for cmd in ({"execute": "qmp_capabilities"},
                        {"execute": "human-monitor-command", "arguments": {"command-line": line}}):
                f.write(json.dumps(cmd) + "\n")
                f.flush()
                while True:
                    reply = json.loads(f.readline())
                    if "return" in reply or "error" in reply:
                        break
            sock.close()
            return reply.get("return") or ""
        except (OSError, ValueError):
            # The soak's own driver holds the monitor for a moment at a time.
            time.sleep(0.25)
    raise SystemExit("could not reach the QMP socket")


def main():
    run = sys.argv[1]
    words = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
    report = load_report()
    slide = 0
    with open(os.path.join(run, "serial.log"), "rb") as f:
        m = re.search(rb"kernel image slide (0x[0-9a-f]+)", f.read())
        if m:
            slide = int(m.group(1), 16)
    syms = report.Symbols(os.path.join(run, "narf-frame"), slide)
    lo, hi = syms.addrs[0] + slide, syms.addrs[-1] + slide
    qmp = os.path.join(run, "qmp.sock")
    registers = hmp(qmp, "info registers -a")
    for block in re.split(r"(?m)^CPU#", registers)[1:]:
        cpu = block.split("\n", 1)[0].strip()
        rip = int(re.search(r"RIP=([0-9a-f]+)", block).group(1), 16)
        rsp = int(re.search(r"RSP=([0-9a-f]+)", block).group(1), 16)
        cs = int(re.search(r"CS =([0-9a-f]+)", block).group(1), 16)
        if "HLT=1" in block or cs & 3:
            continue
        print(f"== cpu {cpu}: rip {rip:#x} {syms.name(rip) or ''}  rsp {rsp:#x}")
        # One command per CPU: `cpu N` selects whose address space `x` reads.
        hmp(qmp, f"cpu {cpu}")
        dump = hmp(qmp, f"x /{words}gx {rsp:#x}")
        last = None
        for line in dump.splitlines():
            addr, _, values = line.partition(":")
            for i, value in enumerate(values.split()):
                value = int(value, 16)
                if not lo <= value <= hi:
                    continue
                name = syms.name(value)
                if not name:
                    continue
                short = name.rsplit("+", 1)[0]
                if short != last:
                    print(f"   [{addr.strip()}+{i * 8:#x}] {name[:170]}")
                last = short


if __name__ == "__main__":
    main()
