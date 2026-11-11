#!/usr/bin/python3
"""Summarise one soak run directory (target/soak/<name>) from its serial log.

  soak-report.py <run-dir>               the summary
  soak-report.py <run-dir> --addr X...   symbolize kernel addresses

Memory over time, busy CPUs, probe latencies, worker progress, every kernel
line worth reading (watchdog:, nvme:, btrfs:, oom:, panics) and, when the
run directory holds the kernel ELF, the functions behind the addresses in
lockup reports and in the vCPU register dumps of a stall.
"""
import bisect
import os
import re
import subprocess
import sys

KERNEL = re.compile(
    r"watchdog:|nvme:.*(gate|stall|timeout|Timeout)|btrfs:.*(READ-ONLY|abort|error|corrupt)|"
    r"oom:|Out of memory|KERNEL PANIC|CPU EXCEPTION|panicked at|GateTimeout|coredump:",
    re.I,
)
ESC = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")


class Symbols:
    def __init__(self, elf, slide):
        self.slide = slide
        self.addrs, self.names = [], []
        out = subprocess.run(["nm", "-n", "-C", elf], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split(" ", 2)
            if len(parts) == 3 and parts[1] in "tTwW":
                self.addrs.append(int(parts[0], 16))
                self.names.append(parts[2])

    def name(self, addr):
        addr -= self.slide
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i < 0 or addr - self.addrs[i] > 0x40000:
            return None
        return f"{self.names[i]}+{addr - self.addrs[i]:#x}"


def load(run):
    with open(os.path.join(run, "serial.log"), "rb") as f:
        text = f.read().decode("utf-8", "replace")
    return [ESC.sub("", line) for line in text.split("\n")]


def kv(line):
    return dict(m.groups() for m in re.finditer(r"(\S+?)=(\S+)", line))


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))] if values else 0


def lockup_reports(block, syms):
    """Condense the lockup detector's lines of one stretch of the log.

    Returns printable lines: each distinct soft/hard lockup (task, longest
    duration, symbolized stack), and each stranded task with its longest wait
    and how many other CPUs were idle in that report.
    """
    out = []
    lockups = {}
    stranded = {}
    i = 0
    while i < len(block):
        line = block[i]
        m = re.search(r"watchdog: (soft|hard) lockup - CPU#(\d+) .*?(\d+)s.*?\[([^\]]*)\]", line)
        if m:
            kind, cpu, secs, task = m.group(1), m.group(2), int(m.group(3)), m.group(4)
            stack = []
            j = i + 1
            while j < len(block) and re.search(r"watchdog:\s+CPU#", block[j]):
                a = re.search(r"0x(ffff[0-9a-f]{12})", block[j])
                if a and syms and "backtrace" not in block[j]:
                    name = syms.name(int(a.group(1), 16))
                    if name:
                        name = name.rsplit("+", 1)[0]
                        if not stack or stack[-1] != name:
                            stack.append(name)
                j += 1
            # One entry per task. The stack scan keeps a fixed number of
            # frames, so a deep filesystem path cuts off before its caller;
            # keep the report whose stack reaches furthest out (the most
            # frames outside the filesystem and the block layer).
            def reach(frames):
                return sum(1 for f in frames if "narf_userspace" in f or "narf_scheduler" in f
                           or "syscall" in f or "narf_memory::address_space" in f)

            best = lockups.setdefault((kind, task), [0, set(), stack, line])
            best[0] = max(best[0], secs)
            best[1].add(cpu)
            if reach(stack) > reach(best[2]):
                best[2], best[3] = stack, line
            i = j
            continue
        m = re.search(r"watchdog:\s+starved \[([^\]]*)\] cpu=(\d+) wait=([0-9.]+)s held_in=(\S+)", line)
        if m:
            task, cpu, wait, where = m.group(1), m.group(2), float(m.group(3)), m.group(4)
            # The per-CPU lines that follow this report say how many CPUs
            # had nothing to do while the task waited.
            idle = 0
            for follow in block[i + 1:i + 40]:
                if re.search(r"watchdog:\s+cpu=\d+ idle", follow):
                    idle += 1
                elif "runnable task(s)" in follow or "lockup -" in follow:
                    break
            best = stranded.setdefault((task, cpu, where), [0.0, 0])
            if wait >= best[0]:
                best[0], best[1] = wait, idle
        i += 1
    for (kind, task), (secs, cpus, stack, line) in lockups.items():
        out.append(f"{kind} lockup, CPU {'/'.join(sorted(cpus))}, up to {secs} s without scheduling: [{task}]")
        out.append("    " + line[line.index("watchdog:"):][:230])
        for name in stack:
            out.append("      " + name[:150])
    for (task, cpu, where), (wait, idle) in sorted(stranded.items(), key=lambda kv: -kv[1][0]):
        out.append(f"stranded on cpu {cpu} ({where}) for up to {wait:.1f} s while {idle} CPUs were idle: [{task}]")
    return out


def episodes(lines, syms):
    """Per-episode table for the directed part of a run."""
    found, cur = [], None
    for line in lines:
        m = re.search(r"SOAK-EPISODE (begin|returned|end|out) (\S+?):? (.*)", line)
        if m:
            what, name, rest = m.groups()
            if what == "begin":
                cur = {"name": name, "ms": None, "rc": "?", "after": None, "out": [],
                       "probes": {}, "streak": {}, "best": (0, "-"), "log": []}
                found.append(cur)
            elif cur and what == "returned":
                d = kv(rest)
                cur["ms"], cur["rc"] = int(d.get("ms", 0)), d.get("rc", "?")
            elif cur and what == "out":
                cur["out"].append(rest)
            elif cur and what == "end":
                cur["after"] = int(kv(rest).get("busy_after_return_ms", 0))
                cur = None
            continue
        if cur is None:
            continue
        if "SOAK-PROBE" in line:
            for name, value in re.findall(r" (\w+)=(STUCK\(\d+s\)|\d+)", line.split("ms:", 1)[-1]):
                ms = int(re.search(r"\d+", value).group()) * (1000 if "STUCK" in value else 1)
                cur["probes"][name] = max(cur["probes"].get(name, 0), ms)
        elif "SOAK-CPU" in line:
            for cpu, cell in re.findall(r" (\d+):(f|\d+/\d+)", line):
                full = cell != "f" and int(cell.split("/")[0]) >= 99
                cur["streak"][cpu] = cur["streak"].get(cpu, 0) + 1 if full else 0
                if cur["streak"][cpu] * 2 > cur["best"][0]:
                    cur["best"] = (cur["streak"][cpu] * 2, cpu)
        elif "watchdog:" in line:
            cur["log"].append(line)
    if not found:
        return
    print("\n-- directed episodes: one operation at a time on the idle system")
    print("   (ms = the command; after = seconds some CPU stayed busy once it had returned;")
    print("    100% = longest run of samples with one CPU fully busy; probe columns = worst ms)")
    print(f"   {'episode':24s} {'ms':>7s} {'after':>6s} {'100%':>9s} "
          f"{'logind':>7s} {'busctl':>7s} {'fsync':>7s} {'exec':>6s} {'read':>6s}  detector")
    for e in found:
        soft = sum("lockup -" in l for l in e["log"])
        starved = len({re.search(r"starved \[([^\]]*)\]", l).group(1) for l in e["log"] if "starved [" in l})
        streak = f"{e['best'][0]}s@{e['best'][1]}" if e["best"][0] else "-"
        after = "?" if e["after"] is None else f"{max(e['after'], 0) / 1000:.0f}"
        pr = e["probes"]
        print(f"   {e['name']:24s} {e['ms'] if e['ms'] is not None else '?':>7} {after:>6s} {streak:>9s} "
              f"{pr.get('loginctl', 0):7d} {pr.get('busctl', 0):7d} {pr.get('fsync', 0):7d} "
              f"{pr.get('exec', 0):6d} {pr.get('coldread', 0):6d}  "
              f"{f'{soft} lockup report(s), {starved} stranded task(s)' if soft or starved else '-'}")
    for e in found:
        for text in e["out"]:
            print(f"   {e['name']}: {text[:260]}")
    for e in found:
        reports = lockup_reports(e["log"], syms)
        if reports:
            print(f"\n   detector during {e['name']}:")
            for text in reports:
                print("     " + text)


def main():
    run = sys.argv[1]
    lines = load(run)
    slide = 0
    for line in lines:
        m = re.search(r"kernel image slide (0x[0-9a-f]+)", line)
        if m:
            slide = int(m.group(1), 16)
            break
    elf = os.path.join(run, "narf-frame")
    syms = Symbols(elf, slide) if os.path.exists(elf) else None
    if "--addr" in sys.argv:
        for a in sys.argv[sys.argv.index("--addr") + 1:]:
            print(a, syms.name(int(a, 16)) if syms else "(no kernel ELF in the run directory)")
        return

    def symbolize(text):
        if not syms:
            return ""
        names = []
        for a in re.findall(r"\b(?:0x)?(ffff[0-9a-f]{12})\b", text):
            n = syms.name(int(a, 16))
            if n:
                names.append(f"{a[-9:]}={n}")
        return ("\n        " + "\n        ".join(names)) if names else ""

    print(f"== {run} (kernel slide {slide:#x})")
    for line in lines:
        if re.search(r"SOAK-(START|CMDLINE|NET|NOTE|PHASE|BASELINE|FINAL|END|ERRCOUNT|OUT|EXITWB|"
                     r"FORKFLUSH|SHMAP|SAMPLER|DIRTYEXIT)\b", line):
            print("  " + line[line.index("SOAK-"):][:300])

    episodes(lines, syms)

    pulses = []
    for line in lines:
        if "SOAK-PULSE" in line:
            d = kv(line)
            try:
                pulses.append((float(d["up"]), int(d["free_kb"]), int(d["avail_kb"]),
                               d.get("load", "")))
            except (KeyError, ValueError):
                pass
    if pulses:
        print(f"\n-- memory (guest uptime s, MiB) from {len(pulses)} pulses")
        print("     up    free   avail  load1")
        step = max(1, len(pulses) // 30)
        for up, free, avail, load1 in pulses[::step] + [pulses[-1]]:
            print(f"  {up:7.1f} {free >> 10:7d} {avail >> 10:7d}  {load1}")
        low = min(pulses, key=lambda p: p[1])
        print(f"  lowest free {low[1] >> 10} MiB at {low[0]:.1f} s; last pulse at {pulses[-1][0]:.1f} s")
        gaps = [(b[0] - a[0], a[0]) for a, b in zip(pulses, pulses[1:]) if b[0] - a[0] > 5]
        for gap, at in sorted(gaps, reverse=True)[:10]:
            print(f"  PULSE GAP {gap:.1f} s after up={at:.1f}")

    samples = [kv(line) for line in lines if "SOAK-SAMPLE" in line]
    if samples:
        keys = [k for k in ("Cached", "Buffers", "AnonPages", "Shmem", "Slab", "SUnreclaim",
                            "KernelStack", "PageTables", "Dirty", "Writeback") if k in samples[0]]
        print("\n-- meminfo fields (MiB) at 0/25/50/75/100% of the run")
        for k in keys:
            picks = [samples[min(len(samples) - 1, len(samples) * q // 4)] for q in range(5)]
            print(f"  {k:12s} " + " ".join(f"{int(p.get(k, 0)) >> 10:7d}" for p in picks))

    busy, frozen, bound = [], {}, []
    for line in lines:
        if "SOAK-CPU" not in line:
            continue
        up = float(kv(line).get("up", 0))
        cells = re.findall(r" (\d+):(f|\d+/\d+)", line)
        total = 0
        for cpu, cell in cells:
            if cell == "f":
                frozen[cpu] = frozen.get(cpu, 0) + 1
            else:
                total += int(cell.split("/")[0])
        busy.append((up, total / 100))
        if "BUSY-STREAK" in line:
            bound.append(line[line.index("SOAK-CPU"):][:200])
    if busy:
        print(f"\n-- busy CPUs (mean per tenth of the run, of {len(cells)})")
        n = max(1, len(busy) // 10)
        print("  " + " ".join(
            f"{sum(b for _, b in busy[i:i + n]) / len(busy[i:i + n]):.1f}"
            for i in range(0, len(busy), n)))
        if frozen:
            print(f"  samples in which a CPU's counters did not advance: {frozen}")
        for line in bound[:10]:
            print("  " + line)
        if len(bound) > 10:
            print(f"  ... {len(bound)} BUSY-STREAK samples in total")

    probes, stuck = {}, []
    for line in lines:
        if "SOAK-PROBE" not in line:
            continue
        for name, value in re.findall(r" (\w+)=(STUCK\(\d+s\)|\d+)", line.split("ms:", 1)[-1]):
            if value.startswith("STUCK"):
                stuck.append((kv(line).get("up"), name, value))
            else:
                probes.setdefault(name, []).append(int(value))
    if probes:
        print("\n-- probes (ms): median / p95 / max / count")
        for name, values in probes.items():
            print(f"  {name:10s} {pct(values, 0.5):6d} {pct(values, 0.95):6d} {max(values):6d} {len(values):5d}")
        for up, name, value in stuck[:20]:
            print(f"  STUCK up={up} {name} {value}")
        if len(stuck) > 20:
            print(f"  ... {len(stuck)} stuck probe samples in total")

    hbs = [(kv(line)) for line in lines if "SOAK-HB" in line]
    if hbs:
        print("\n-- worker progress (first -> last heartbeat; longest run of unchanged samples)")
        names = sorted({k for h in hbs for k in h if k != "n"})
        for name in names:
            series = [h[name] for h in hbs if name in h]
            longest = cur = 0
            for a, b in zip(series, series[1:]):
                cur = cur + 1 if a == b else 0
                longest = max(longest, cur)
            print(f"  {name:14s} {series[0][:40]:>40s} -> {series[-1][:60]}  (flat {longest * 5} s)")

    tasks = [line for line in lines if "SOAK-TASKS" in line]
    if tasks:
        print("\n-- task states and waits, last sample")
        print("  " + tasks[-1][tasks[-1].index("SOAK-TASKS"):][:900])
    blocked = [line for line in lines if "SOAK-BLOCKED" in line]
    if blocked:
        print(f"-- {len(blocked)} samples listed tasks in state D; last:")
        print("  " + blocked[-1][blocked[-1].index("SOAK-BLOCKED"):][:600])

    errs = [line for line in lines if "SOAK-ERR " in line or "UNKILLABLE" in line]
    print(f"\n-- workload errors: {len(errs)}")
    for line in errs[:40]:
        print("  " + line[:300])

    watchdog = [line for line in lines if "watchdog:" in line and "detector on" not in line]
    print(f"\n-- lockup detector, whole run: {len(watchdog)} lines")
    for text in lockup_reports(watchdog, syms):
        print("  " + text)
    kernel = [line for line in lines
              if KERNEL.search(line) and "SOAK-" not in line and "watchdog:" not in line]
    print(f"\n-- other kernel lines of interest: {len(kernel)}")
    for line in kernel[:60]:
        print("  " + line[:400] + symbolize(line))
    if len(kernel) > 60:
        print(f"  ... {len(kernel) - 60} more")

    for name in sorted(os.listdir(run)):
        if name.startswith("registers-") and syms:
            with open(os.path.join(run, name)) as f:
                dump = f.read()
            print(f"\n-- {name}")
            for block in re.split(r"(?m)^CPU#", dump)[1:]:
                cpu = block.split("\n", 1)[0].strip()
                rip = re.search(r"RIP=([0-9a-f]+)", block)
                cs = re.search(r"CS =([0-9a-f]+)", block)
                where = syms.name(int(rip.group(1), 16)) if rip else None
                print(f"  cpu{cpu} cs={cs.group(1) if cs else '?'} rip={rip.group(1) if rip else '?'}"
                      f" {where or ''}{' (halted)' if 'HLT=1' in block else ''}")
    rips = os.path.join(run, "vcpu-rip-samples.log")
    if os.path.exists(rips) and syms:
        # Every sample is one instruction pointer per vCPU: a coarse profile
        # of where the kernel spends its time, by phase of the run.
        phases = []
        for line in lines:
            m = re.search(r"SOAK-PHASE (\S+) up=([0-9.]+)", line)
            if m:
                phases.append((float(m.group(2)), m.group(1)))
        hist, totals = {}, {}
        with open(rips) as f:
            for line in f:
                m = re.search(r"up=([0-9.]+)", line)
                up = float(m.group(1)) if m else 0.0
                phase = "boot"
                for start, name in phases:
                    if up >= start:
                        phase = name
                for cpu, rip, cs, hlt in re.findall(r"(\d+):([0-9a-f]+):cs([0-9a-f]+)( hlt)?", line):
                    totals[phase] = totals.get(phase, 0) + 1
                    if hlt:
                        key = "(halted)"
                    elif int(cs, 16) & 3:
                        key = "(user mode)"
                    else:
                        key = (syms.name(int(rip, 16)) or rip).split("+")[0]
                    hist.setdefault(phase, {})
                    hist[phase][key] = hist[phase].get(key, 0) + 1
        print("\n-- where the vCPUs were (instruction-pointer samples, percent of the phase)")
        for phase, counts in hist.items():
            top = sorted(counts.items(), key=lambda kv: -kv[1])[:9]
            print(f"  {phase} ({totals[phase]} samples):")
            for key, n in top:
                print(f"    {100 * n / totals[phase]:5.1f}%  {key[:150]}")
    summary = os.path.join(run, "host-summary.txt")
    if os.path.exists(summary):
        print("\n-- host side")
        with open(summary) as f:
            print("  " + f.read().replace("\n", "\n  ").rstrip())


if __name__ == "__main__":
    main()
