#!/usr/bin/env python3
"""Matched KVM filesystem sweep. Full runs require verified host controls."""
import argparse
import json
import os
from pathlib import Path
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

import controlled_host as host
import run as diagnostics

ROOT = diagnostics.ROOT
HERE = Path(__file__).resolve().parent
SIZE = 8 * 1024 * 1024
CONTRACT = {
    "first-read-64k": (SIZE, "bytes"), "cached-read-64k": (16 * SIZE, "bytes"),
    "cached-random-read-4k": (4096 * 4096, "bytes"),
    "sequential-write-64k-fsync": (SIZE, "bytes"),
    "random-overwrite-4k-fsync": (4096 * 4096, "bytes"),
    "append-64k-fsync": (65536, "bytes"), "write-4k-fsync-each": (64, "operations"),
    "cached-stat": (16384, "operations"), "readdir": (32768, "entries"),
    "create-directory-fsync": (128, "operations"), "rename-directory-fsync": (128, "operations"),
}


def pattern():
    return bytes((i * 17 + (i >> 8) * 31 + 91) & 255 for i in range(65536)) * (SIZE // 65536)


def validate_log(path, code, side):
    text = path.read_text(errors="replace").replace("\r", "")
    env = re.findall(r"^FSBENCH_ENV native=0 no_randomize=1 file_bytes=8388608 random_ops=4096 names=1024$", text, re.M)
    found = re.findall(r"^FSBENCH name=(\S+) cycles=(\d+) work=(\d+) unit=(\S+)$", text, re.M)
    rows = [dict(name=n, cycles=int(c), work=int(w), unit=u) for n, c, w, u in found]
    valid = (code == 0 and len(env) == 1 and len(found) == len(CONTRACT)
             and [r["name"] for r in rows] == list(CONTRACT)
             and len(re.findall(r"^FSBENCH_DONE cases=11$", text, re.M)) == 1
             and "FSBENCH_FAIL" not in text
             and all(r["cycles"] > 0 and (r["work"], r["unit"]) == CONTRACT[r["name"]] for r in rows))
    if side == "linux": valid = valid and re.findall(r"^FSRUN-RC=(\d+)$", text, re.M) == ["0"]
    return dict(valid=valid, cases=rows, returncode=code, log=str(path))


def persistent_check(work, image, fs, tag):
    log = work / f"{tag}-check.log"
    checker = (["btrfs", "check", "--readonly", "--check-data-csum", str(image)] if fs == "btrfs"
               else ["e2fsck", "-f", "-n", str(image)])
    code = diagnostics.run_logged(checker, log, timeout=120)
    bad = [s for s in log.read_text(errors="replace").lower().splitlines()
           if s.startswith("error") or ("errors found" in s and "no error found" not in s)]
    tree = work / "restore"
    tree.mkdir()
    command = (["btrfs", "restore", str(image), str(tree)] if fs == "btrfs"
               else ["debugfs", "-R", f'rdump / "{tree}"', str(image)])
    restore_code = diagnostics.run_logged(command, work / f"{tag}-restore.log", timeout=120)
    original = pattern()
    xor = lambda data, salt: data.translate(bytes(i ^ salt for i in range(256)))
    expected = {"seed.bin": original, "overwrite.bin": xor(original, 0xa5),
                "append.bin": original + xor(original[:65536], 0x5a),
                "out-sequential": xor(original, 0xa5), "out-fsync-each": xor(original[:64 * 4096], 0x3c),
                "warmup0": bytes(4096), "warmup1": bytes(4096)}
    expected.update({f"lookup/n{i:04d}": b"x" for i in range(1024)})
    expected.update({f"renamed{i:04d}": b"" for i in range(128)})
    errors = []
    for name, data in expected.items():
        try:
            if (tree / name).read_bytes() != data: errors.append("content:" + name)
        except OSError: errors.append("missing:" + name)
    errors += [f"old-name:created{i:04d}" for i in range(128) if (tree / f"created{i:04d}").exists()]
    passed = code == 0 and not bad and restore_code == 0 and not errors
    if passed: shutil.rmtree(tree)
    return dict(passed=passed, checker_returncode=code, checker_markers=bad,
                restore_returncode=restore_code, content_errors=errors, checked_files=len(expected), log=str(log))


class Qmp:
    def __init__(self, path, proc):
        self.sock = socket.socket(socket.AF_UNIX)
        until = time.monotonic() + 30
        while True:
            try: self.sock.connect(str(path)); break
            except (FileNotFoundError, ConnectionRefusedError):
                if proc.poll() is not None or time.monotonic() > until: raise
                time.sleep(0.05)
        self.sock.settimeout(30)
        self.stream = self.sock.makefile("rwb", buffering=0)
        json.loads(self.stream.readline())
        self.ident = 0
        self.command("qmp_capabilities")

    def command(self, name):
        self.ident += 1
        self.stream.write((json.dumps(dict(execute=name, id=self.ident)) + "\n").encode())
        while True:
            row = json.loads(self.stream.readline())
            if row.get("id") == self.ident:
                if "error" in row: raise RuntimeError(str(row))
                return row["return"]

    def close(self):
        self.stream.close(); self.sock.close()


def guest(command, env, log, qmp_path, controls, argv_record):
    before = host.verify(controls) if controls else None
    with log.open("w") as output:
        proc = subprocess.Popen(["setarch", "x86_64", "-R"] + command, cwd=ROOT, env=env,
                                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        qmp = None
        try:
            qmp = Qmp(qmp_path, proc)
            cpus = qmp.command("query-cpus-fast")
            if len(cpus) != 2: raise RuntimeError("expected exactly two guest vCPUs")
            placement = []
            for cpu in cpus:
                target = 8 + cpu["cpu-index"]
                os.sched_setaffinity(cpu["thread-id"], {target})
                if os.sched_getaffinity(cpu["thread-id"]) != {target}: raise RuntimeError("vCPU pin failed")
                placement.append(dict(guest_cpu=cpu["cpu-index"], host_cpu=target, thread_id=cpu["thread-id"]))
            tgid = next(line.split()[1] for line in Path(f"/proc/{cpus[0]['thread-id']}/status").read_text().splitlines() if line.startswith("Tgid:"))
            actual = Path(f"/proc/{tgid}/cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
            if int(Path(f"/proc/{tgid}/personality").read_text(), 16) & 0x40000 == 0:
                raise RuntimeError("PreconditionFailed: QEMU ASLR still enabled")
            argv_record.write_text(json.dumps(actual, indent=2) + "\n")
            qmp.command("cont")
            until = time.monotonic() + 240
            history = []
            next_monitor = 0
            while proc.poll() is None:
                if controls and time.monotonic() >= next_monitor:
                    history.append(dict(monotonic=time.monotonic(), temperatures=host.verify(controls)))
                    next_monitor = time.monotonic() + 0.5
                if "FSBENCH_FAIL" in log.read_text(errors="replace"):
                    raise RuntimeError("guest workload failed: " + str(log))
                if time.monotonic() > until: raise RuntimeError("guest timeout: " + str(log))
                time.sleep(0.05)
            return proc.returncode, dict(placement=placement, qemu_argv=actual, thermal_before=before, thermal_history=history)
        finally:
            if qmp: qmp.close()
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: os.killpg(proc.pid, signal.SIGKILL); proc.wait()
            if qmp_path.exists(): qmp_path.unlink()


def qemu_wrapper(work):
    directory = work / "qemu-bin"
    directory.mkdir()
    path = directory / "qemu-system-x86_64"
    path.write_text('''#!/usr/bin/python3
import os,sys
args=sys.argv[1:]
for i,word in enumerate(args[:-1]):
 if word=='-drive':
  parts=args[i+1].split(',')
  if 'id=vblk0' in parts:
   parts=[p for p in parts if not p.startswith('cache=')]+['cache=writeback']
  else:
   parts=[p for p in parts if not p.startswith(('file=','readonly=','snapshot='))]+['file='+os.environ['FSBENCH_AUX_IMAGE'],'snapshot=on']
  args[i+1]=','.join(parts)
os.execv('/usr/bin/qemu-system-x86_64',['/usr/bin/qemu-system-x86_64']+args)
''')
    path.chmod(0o755)
    return directory


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workdir", type=Path, required=True)
    p.add_argument("--prepared-directory", action="store_true")
    p.add_argument("--narf-kernel", type=Path, required=True)
    p.add_argument("--linux-kernel", type=Path, required=True)
    p.add_argument("--samples", type=int, default=100)
    p.add_argument("--pilot", action="store_true")
    p.add_argument("--filesystems", nargs="+", choices=["ext2", "ext4", "btrfs"], default=["ext2", "ext4", "btrfs"])
    args = p.parse_args()
    if not args.pilot and args.samples < 100: p.error("full sweeps require 100 independent boots per side/format")
    controls = json.loads(Path(os.environ["NARF_FS_HOST_STATE"]).read_text()) if "NARF_FS_HOST_STATE" in os.environ else None
    if not controls and not args.pilot:
        print(json.dumps(dict(status="PreconditionFailed", failed=["no-controlled-host-session"]))); return 2
    work = args.workdir.resolve()
    if not str(work).startswith("/tmp/"): p.error("benchmark workdir must use the monitored /tmp NVMe filesystem")
    work.mkdir(parents=True, exist_ok=args.prepared_directory)
    binary = work / "fs-bench"
    subprocess.run(["musl-gcc", "-O2", "-static", "-no-pie", "-std=c11", "-Wall", "-Wextra", "-Werror", str(HERE / "bench.c"), "-o", str(binary)], check=True)
    analyzer = work / "analyze"
    subprocess.run(["rustc", "--edition=2021", "-O", str(HERE / "analyze.rs"), "-o", str(analyzer)], check=True)
    seed = work / "seed"
    (seed / "lookup").mkdir(parents=True)
    for name in ["seed.bin", "overwrite.bin", "append.bin"]: (seed / name).write_bytes(pattern())
    for i in range(1024): (seed / "lookup" / f"n{i:04d}").write_bytes(b"x")
    bases = {fs: diagnostics.make_image(work, seed, fs) for fs in args.filesystems}
    initrds = {fs: diagnostics.initrd(work, binary, fs) for fs in args.filesystems}
    hashes = {fs: diagnostics.sha256(image) for fs, image in bases.items()}
    aux = work / "auxiliary.img"
    with aux.open("xb") as stream: stream.truncate(8 * 1024 * 1024)
    wrapper = qemu_wrapper(work)
    kernels = {}
    for side in ["narf", "linux"]:
        source = getattr(args, side + "_kernel").resolve()
        target = work / ("narf-frame" if side == "narf" else "linux-vmlinuz")
        subprocess.run(["cp", "--reflink=auto", str(source), str(target)], check=True)
        kernels[side] = target
    report = dict(classification="PilotOnly" if args.pilot else "Collecting", performance_record=False,
                  source_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  source_sha256={str(path.relative_to(ROOT)): diagnostics.sha256(path) for path in [HERE / "bench.c", HERE / "measure.py", HERE / "controlled_host.py", HERE / "analyze.rs", ROOT / "build/xtask/src/bench_stats.rs"]},
                  kernel_sha256={k: diagnostics.sha256(v) for k, v in kernels.items()}, base_hashes=hashes,
                  host_controls=controls, cases=CONTRACT, samples=[], complete=False,
                  metric="elapsed invariant TSC cycles; lower is better", warmup="two 4 KiB create/fsyncs, cached read/stat warmups; first-read has no file-data warmup",
                  directory_policy="create/rename keep files linked; unlink integrity failures remain in the diagnostic sweep")
    report["tool_versions"] = {tool: subprocess.run(command, capture_output=True, text=True).stdout.splitlines()[:2]
        for tool, command in {"qemu": ["qemu-system-x86_64", "--version"], "rustc": ["rustc", "--version"],
                              "musl-gcc": ["musl-gcc", "--version"], "btrfs": ["btrfs", "version"]}.items()}
    report["linux_reference"] = dict(path="/usr/src/linux",
        commit=subprocess.check_output(["git", "-C", "/usr/src/linux", "rev-parse", "HEAD"], text=True).strip(),
        status=subprocess.check_output(["git", "-C", "/usr/src/linux", "status", "--short"], text=True),
        binary_build_provenance="existing /boot image; correspondence to reference source is unverified")
    for path in [HERE / "bench.c", HERE / "measure.py", HERE / "controlled_host.py", HERE / "analyze.rs"]:
        shutil.copy2(path, work / path.name)
    def save(): (work / "samples.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    if controls:
        print("Verifying 30-second thermal and idle-LLC window", flush=True)
        report["initial_window"] = host.initial_window(controls)
    os.sched_setaffinity(0, {11})
    template = None
    rng = random.Random(1729)
    total = 1 if args.pilot else args.samples
    for sample in range(total):
        filesystems = list(args.filesystems); rng.shuffle(filesystems)
        for fs in filesystems:
            sides = ["narf", "linux"]
            if template and rng.randrange(2): sides.reverse()
            for side in sides:
                tag = f"{sample:03d}-{fs}-{side}"
                image = work / "guest.img"
                subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(bases[fs]), str(image)], check=True)
                sock = Path(f"/tmp/narf-fsb-{os.getpid()}.qmp")
                env = os.environ.copy()
                if side == "narf":
                    for key in list(env):
                        if key.startswith(("NARF_QEMU_", "XTASK_QEMU_", "XTASK_STAGE_", "NARF_VBLK_")): del env[key]
                    env.update(NARF_VBLK_IMG=str(image), NARF_QEMU_MEM_MB="2048", NARF_QEMU_SMP="2",
                               NARF_QEMU_CPU="host,phys-bits=40", XTASK_QEMU_ACCEL="kvm", XTASK_QEMU_QMP=str(sock),
                               NARF_QEMU_EXTRA="-S", XTASK_STAGE_BIN=str(binary) + ":usr/bin/fs-bench",
                               XTASK_RI_PROMPT_TIMEOUT_SECS="180", XTASK_RI_ECHO_TIMEOUT_SECS="180",
                               CARGO_MANIFEST_DIR=str(ROOT / "build/xtask"), FSBENCH_AUX_IMAGE=str(aux), PATH=str(wrapper) + ":" + env["PATH"])
                    command = [str(ROOT / "target/debug/xtask"), "run-interactive", "--prebuilt", str(kernels[side]),
                               "--cmd", f"/usr/bin/fs-bench /dev/vblk0 {fs} " + ("/mnt" if fs.startswith("ext") else "/tmp/fs-sweep"),
                               "--expect", "FSBENCH_DONE cases=11"]
                else:
                    command = list(template)
                    for flag, value in [("-kernel", str(kernels[side])), ("-initrd", str(initrds[fs])),
                                        ("-append", "console=ttyS0 panic=-1 quiet"), ("-qmp", f"unix:{sock},server=on,wait=off")]:
                        if flag in command: command[command.index(flag) + 1] = value
                        else: command += [flag, value]
                print("START", tag, flush=True)
                code, context = guest(command, env, work / f"{tag}.log", sock, controls, work / f"{tag}-qemu.json")
                if side == "narf": template = context["qemu_argv"]
                row = validate_log(work / f"{tag}.log", code, side) | dict(side=side, fs=fs, sample=sample, context=context)
                row["integrity"] = persistent_check(work, image, fs, tag)
                report["samples"].append(row); save()
                if not row["valid"] or not row["integrity"]["passed"]:
                    raise RuntimeError("invalid sample, retained image: " + tag)
                image.unlink()
                print("DONE", tag, "all cases and integrity checks pass", flush=True)
    if not all(diagnostics.sha256(path) == hashes[fs] for fs, path in bases.items()):
        raise RuntimeError("immutable base image changed")
    if any(diagnostics.sha256(ROOT / path) != digest for path, digest in report["source_sha256"].items()):
        raise RuntimeError("benchmark source changed during collection")
    if any(diagnostics.sha256(path) != report["kernel_sha256"][side] for side, path in kernels.items()):
        raise RuntimeError("kernel image changed during collection")
    report["complete"] = True
    report["classification"] = "PilotOnly" if args.pilot else "ValidatedPerformance"
    report["performance_record"] = not args.pilot
    if not args.pilot:
        host.verify(controls)
        data = "".join(f"{r['fs']}\t{c['name']}\t{r['side']}\t{c['cycles']}\t{c['work']}\t{c['unit']}\n" for r in report["samples"] for c in r["cases"])
        result = subprocess.run([str(analyzer)], input=data, text=True, capture_output=True, check=True)
        analysis = json.loads(result.stdout)
        if not analysis["sample_size_sufficient"]: raise RuntimeError("insufficient independent samples")
        (work / "statistics.json").write_text(json.dumps(analysis, indent=2) + "\n")
    save()
    print("SWEEP-COMPLETE", report["classification"], flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
