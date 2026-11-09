#!/usr/bin/env python3
"""Reserve a complete LLC for a sweep; restore host controls on every exit.

The cgroup partition follows docs.kernel.org/admin-guide/cgroup-v2.html.
No host-wide ASLR change is needed: both benchmark guests opt out per process.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CPU_ROOT = Path("/sys/devices/system/cpu")


def read(path):
    return Path(path).read_text().strip()


def cpu_list(value):
    result = set()
    for group in value.split(","):
        if not group: continue
        edges = group.split("-")
        result.update(range(int(edges[0]), int(edges[-1]) + 1))
    return result


def temperatures(state):
    values = {name: int(read(path)) for name, path in state["sensors"].items()}
    for name, value in values.items():
        if value >= state["limits"][name]: raise RuntimeError(f"PreconditionFailed: thermal tripwire {name}={value}")
    if read(state["storage_alarm"]) != "0": raise RuntimeError("PreconditionFailed: benchmark NVMe alarm")
    return values


def verify(state):
    if read(CPU_ROOT / "smt/active") != "0" or read(CPU_ROOT / "cpufreq/boost") != "0":
        raise RuntimeError("PreconditionFailed: SMT/boost changed")
    for cpu in state["cpus"]:
        base = CPU_ROOT / f"cpu{cpu}/cpufreq"
        if (read(base / "scaling_governor") != "performance" or
            int(read(base / "scaling_min_freq")) != state["frequency_khz"] or
            int(read(base / "scaling_max_freq")) != state["frequency_khz"]):
            raise RuntimeError(f"PreconditionFailed: frequency policy changed on CPU {cpu}")
    group = Path(state["cgroup"])
    if read(group / "cpuset.cpus.partition") != "isolated":
        raise RuntimeError("PreconditionFailed: CPU partition no longer isolated")
    if cpu_list(read(group / "cpuset.cpus.effective")) != set(state["cpus"]):
        raise RuntimeError("PreconditionFailed: effective CPU partition changed")
    online = cpu_list(read(CPU_ROOT / "online"))
    llc = cpu_list(read(CPU_ROOT / f"cpu{state['cpus'][0]}/cache/index3/shared_cpu_list")) & online
    if llc != set(state["cpus"]): raise RuntimeError("PreconditionFailed: LLC is shared outside partition")
    return temperatures(state)


def cpu_times():
    rows = {}
    for line in read("/proc/stat").splitlines():
        parts = line.split()
        if parts and parts[0].startswith("cpu") and parts[0][3:].isdigit():
            v = list(map(int, parts[1:9])) # guest time is already included in user
            rows[int(parts[0][3:])] = (sum(v), v[3] + v[4])
    return rows


def restore_policy(base, original):
    """Allow expansion of either bound before restoring the original interval."""
    base = Path(base)
    (base / "scaling_governor").write_text(original["scaling_governor"] + "\n")
    minimum = min(int(original["scaling_min_freq"]), int(read(base / "scaling_min_freq")), int(original["scaling_max_freq"]))
    (base / "scaling_min_freq").write_text(str(minimum) + "\n")
    (base / "scaling_max_freq").write_text(original["scaling_max_freq"] + "\n")
    (base / "scaling_min_freq").write_text(original["scaling_min_freq"] + "\n")
    (base / "energy_performance_preference").write_text(original["energy_performance_preference"] + "\n")
    deadline = time.monotonic() + 5
    while any(read(base / name) != value for name, value in original.items()) and time.monotonic() < deadline:
        time.sleep(0.1)
    if any(read(base / name) != value for name, value in original.items()):
        raise RuntimeError(f"restoration verification failed for {base}")


def remove_partition(group):
    group = Path(group)
    if not group.exists(): return
    if read(group / "cgroup.procs"): raise RuntimeError("temporary cgroup still populated")
    (group / "cpuset.cpus.partition").write_text("member\n")
    (group / "cpuset.cpus.exclusive").write_text("\n")
    until = time.monotonic() + 15
    while True:
        try: group.rmdir(); return
        except OSError as error:
            if error.errno != errno.EBUSY or time.monotonic() >= until: raise
            time.sleep(0.1)


def initial_window(state, seconds=30):
    before = cpu_times()
    history = []
    for _ in range(seconds):
        history.append(dict(monotonic=time.monotonic(), temperatures=verify(state)))
        time.sleep(1)
    after = cpu_times()
    busy = {}
    for cpu in state["cpus"]:
        total = after[cpu][0] - before[cpu][0]
        idle = after[cpu][1] - before[cpu][1]
        busy[cpu] = 1 - idle / total if total else 1
    if max(busy.values()) > 0.05:
        raise RuntimeError("PreconditionFailed: initial LLC CPU load exceeds 0.05: " + str(busy))
    return dict(thermal_history=history, llc_busy_fraction=busy, duration_seconds=seconds)


def plan():
    model = next(line.split(":", 1)[1].strip() for line in read("/proc/cpuinfo").splitlines() if line.startswith("model name"))
    if "AMD Ryzen 9 7940HX" not in model:
        raise RuntimeError("PreconditionFailed: unreviewed CPU/thermal profile")
    cpus = list(range(8, 16))
    nominal = {int(read(CPU_ROOT / f"cpu{c}/acpi_cppc/nominal_freq")) * 1000 for c in cpus}
    if len(nominal) != 1: raise RuntimeError("different nominal frequencies in benchmark LLC")
    cpu_sensor = next((p for p in Path("/sys/class/hwmon").glob("*") if read(p / "name") == "k10temp"), None)
    if cpu_sensor is None: raise RuntimeError("PreconditionFailed: CPU temperature monitor unavailable")
    # /tmp is backed by nvme0n1p3 on this runner. Require that topology explicitly.
    disk = json.loads(subprocess.check_output(["findmnt", "-J", "-T", "/tmp"], text=True))["filesystems"][0]
    if disk["source"] != "/dev/nvme0n1p3": raise RuntimeError("unreviewed benchmark storage topology")
    sensor = next(p for p in Path("/sys/class/hwmon").glob("*")
                  if read(p / "name") == "nvme" and (p / "device").resolve().name == "nvme0")
    warning = int(read(sensor / "temp1_max")) if (sensor / "temp1_max").exists() else int(read(sensor / "temp1_crit"))
    return dict(cpu_model=model, cpus=cpus, frequency_khz=nominal.pop(), cgroup=f"/sys/fs/cgroup/narf-fs-bench-{os.getpid()}",
                sensors={"cpu": str(cpu_sensor / "temp1_input"), "nvme": str(sensor / "temp1_input")},
                # AMD specifies Tjmax=100 C for the Ryzen 9 7940HX; retain
                # a 15 C margin instead of treating ordinary 70 C as a throttle.
                limits={"cpu": 85000, "nvme": min(warning, int(read(sensor / "temp1_crit"))) - 5000},
                storage_alarm=str(sensor / "temp1_alarm"), storage=disk)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--restore-existing", action="store_true")
    p.add_argument("--workdir", type=Path, required=True)
    p.add_argument("--narf-kernel", type=Path, required=True)
    p.add_argument("--linux-kernel", type=Path, required=True)
    p.add_argument("--samples", type=int, default=100)
    args = p.parse_args()
    if args.restore_existing:
        state = json.loads((args.workdir / "host-controls.json").read_text())
        if state.get("cgroup_created", False):
            remove_partition(Path(state["cgroup"]))
        for name, original in [("cpufreq/boost", state["boost_original"]), ("smt/control", state["smt_original"])]:
            (CPU_ROOT / name).write_text(original + "\n")
        for directory, original in state["policies_original"].items(): restore_policy(directory, original)
        (args.workdir / "host-restoration.json").write_text(json.dumps(dict(errors=[], restored=True, recovery=True)) + "\n")
        return 0
    state = plan()
    if not args.apply:
        print(json.dumps(state, indent=2)); return 0
    args.workdir.mkdir(parents=True, exist_ok=False)
    group = Path(state["cgroup"])
    group_created = False
    state["cgroup_created"] = False
    child = None
    errors = []
    state["originals"] = {}
    def write(path, value):
        path = Path(path)
        original = read(path)
        state["originals"].setdefault(str(path), original)
        path.write_text(str(value) + "\n")
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    state_path = args.workdir / "host-controls.json"
    original_policies = {
        str(p): {name: read(p / name) for name in ["scaling_governor", "scaling_min_freq", "scaling_max_freq", "energy_performance_preference"]}
        for p in (CPU_ROOT / "cpufreq").glob("policy*")
    }
    state["policies_original"] = original_policies
    state["smt_original"] = read(CPU_ROOT / "smt/control")
    state["boost_original"] = read(CPU_ROOT / "cpufreq/boost")
    state_path.write_text(json.dumps(state, indent=2) + "\n")
    try:
        write(CPU_ROOT / "smt/control", "off")
        write(CPU_ROOT / "cpufreq/boost", "0")
        for cpu in state["cpus"]:
            base = CPU_ROOT / f"cpu{cpu}/cpufreq"
            write(base / "scaling_governor", "performance")
            write(base / "scaling_min_freq", state["frequency_khz"])
            write(base / "scaling_max_freq", state["frequency_khz"])
        group.mkdir()
        group_created = True
        state["cgroup_created"] = True
        state_path.write_text(json.dumps(state, indent=2) + "\n")
        (group / "cpuset.mems").write_text(read("/sys/fs/cgroup/cpuset.mems.effective") + "\n")
        (group / "cpuset.cpus").write_text("8-15\n")
        (group / "cpuset.cpus.exclusive").write_text("8-15\n")
        (group / "cpuset.cpus.partition").write_text("isolated\n")
        verify(state)
        state_path.write_text(json.dumps(state, indent=2) + "\n")
        def enter():
            (group / "cgroup.procs").write_text(str(os.getpid()) + "\n")
            os.sched_setaffinity(0, {10})
        command = ["setarch", "x86_64", "-R", sys.executable, str(Path(__file__).with_name("measure.py")),
                   "--workdir", str(args.workdir), "--prepared-directory", "--samples", str(args.samples),
                   "--narf-kernel", str(args.narf_kernel.resolve()), "--linux-kernel", str(args.linux_kernel.resolve())]
        env = dict(os.environ, NARF_FS_HOST_STATE=str(state_path))
        child = subprocess.Popen(command, env=env, preexec_fn=enter, start_new_session=True)
        code = child.wait()
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try: child.wait(timeout=10)
            except subprocess.TimeoutExpired: os.killpg(child.pid, signal.SIGKILL); child.wait()
        if group_created and group.exists():
            try:
                # Children use separate process sessions. Kill remaining members
                # before returning this temporary partition's CPUs to the host.
                for pid in read(group / "cgroup.procs").split():
                    try: os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError: pass
                until = time.monotonic() + 5
                while read(group / "cgroup.procs") and time.monotonic() < until: time.sleep(0.05)
                remove_partition(group)
            except (OSError, RuntimeError) as e: errors.append(str(e))
        # Restore global capabilities before their per-policy limits. Boost and
        # CPU hotplug may themselves change the visible policy bounds.
        for path, original in [(CPU_ROOT / "cpufreq/boost", state["boost_original"]),
                               (CPU_ROOT / "smt/control", state["smt_original"])]:
            try: path.write_text(original + "\n")
            except OSError as e: errors.append(f"restore {path}: {e}")
        for directory, original in original_policies.items():
            base = Path(directory)
            try:
                restore_policy(base, original)
            except (OSError, RuntimeError) as e: errors.append(f"restore policy {directory}: {e}")
        for path, original in [(CPU_ROOT / "cpufreq/boost", state["boost_original"]),
                               (CPU_ROOT / "smt/control", state["smt_original"])]:
            if read(path) != original: errors.append(f"restoration verification failed for {path}")
        (args.workdir / "host-restoration.json").write_text(json.dumps(dict(errors=errors, restored=not errors), indent=2) + "\n")
        if errors: raise RuntimeError("host restoration failed: " + repr(errors))
    return code


if __name__ == "__main__":
    sys.exit(main())
