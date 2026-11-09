#!/usr/bin/env python3
"""Disposable-image filesystem diagnostics. Never emits a performance record."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CASES = ["seq-read-first", "seq-read-warm", "random-read", "stat", "readdir",
         "seq-write-sync", "random-overwrite-sync", "append-sync", "fsync-each",
         "create-unlink", "rename-unlink"]
UNITS = [1048576, 1048576, 524288, 512, 64, 1048576, 524288, 65536, 32768, 16, 16]


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def host_checks():
    def read(path):
        try:
            return Path(path).read_text().strip()
        except OSError:
            return None
    cpus = sorted(os.sched_getaffinity(0))
    governors = {read(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor") for cpu in cpus}
    boost = read("/sys/devices/system/cpu/cpufreq/boost")
    no_turbo = read("/sys/devices/system/cpu/intel_pstate/no_turbo")
    checks = {
        "governors": sorted(str(x) for x in governors),
        "boost": boost, "intel_no_turbo": no_turbo,
        "smt_active": read("/sys/devices/system/cpu/smt/active"),
        "host_aslr": read("/proc/sys/kernel/randomize_va_space"),
        "affinity": cpus,
        "kvm_accessible": os.access("/dev/kvm", os.R_OK | os.W_OK),
    }
    failed = []
    if governors != {"performance"}: failed.append("governor_not_performance")
    if boost != "0" and no_turbo != "1": failed.append("boost_not_verified_disabled")
    if checks["smt_active"] != "0": failed.append("smt_not_verified_disabled")
    if checks["host_aslr"] != "0": failed.append("host_aslr_enabled")
    if not checks["kvm_accessible"]: failed.append("kvm_unavailable")
    # This screening harness does not implement the full controlled-run protocol.
    failed.extend(["fixed_frequency_unverified", "dedicated_cores_unverified",
                   "thermal_history_30s_unverified", "llc_sibling_load_unverified",
                   "guest_process_aslr_unverified"])
    return {"status": "PreconditionFailed", "failed": failed, "observed": checks}


def run_logged(command, path, *, env=None, timeout=300):
    with path.open("w") as output:
        proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return proc.wait(timeout=timeout)
        except BaseException as error:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            if isinstance(error, subprocess.TimeoutExpired): return 124
            raise


def prepare(work):
    binary = work / "fs-probe"
    subprocess.run(["musl-gcc", "-std=c11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
                    str(HERE / "probe.c"), "-o", str(binary)], check=True)
    seed = work / "seed"
    (seed / "lookup").mkdir(parents=True)
    data = bytes((i * 17 + (i >> 8) * 31 + 91) & 255 for i in range(1048576))
    for name in ["seed.bin", "overwrite.bin", "append.bin"]: (seed / name).write_bytes(data)
    for i in range(64): (seed / "lookup" / f"n{i:04d}").write_bytes(b"x")
    return seed, binary


def make_image(work, seed, fs, btrfs_features=None):
    image = work / f"base-{fs}.img"
    with image.open("xb") as stream: stream.truncate(512 * 1024 * 1024)
    if fs == "btrfs":
        command = ["mkfs.btrfs", "-f", "-n", "16384", "-s", "4096", "--rootdir", str(seed), str(image)]
        if btrfs_features:
            command[1:1] = ["-O", btrfs_features]
    else:
        command = ["mke2fs", "-F", "-t", fs, "-b", "4096", "-d", str(seed), str(image)]
    if run_logged(command, work / f"mkfs-{fs}.log"):
        raise RuntimeError(f"mkfs failed: {fs}")
    return image


def initrd(work, binary, fs):
    stage = work / f"init-{fs}"
    for directory in ["bin", "dev", "proc", "sys", "tmp"]: (stage / directory).mkdir(parents=True)
    shutil.copy2(ROOT / "verification/data/musl-demo/busybox_static_x86_64", stage / "bin/busybox")
    shutil.copy2(binary, stage / "probe")
    script = stage / "init"
    script.write_text(f"""#!/bin/busybox sh
/bin/busybox mount -t devtmpfs dev /dev
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/probe /dev/vda {fs} /tmp/fs-sweep
rc=$?
/bin/busybox echo FSRUN-RC=$rc
/bin/busybox poweroff -f
""")
    script.chmod(0o755)
    target = work / f"init-{fs}.cpio"
    # Input list is generated without a shell or host mounts.
    names = ".\n" + "\n".join(str(p.relative_to(stage)) for p in sorted(stage.rglob("*"))) + "\n"
    with target.open("wb") as output:
        subprocess.run(["cpio", "-o", "-H", "newc"], input=names.encode(), cwd=stage,
                       stdout=output, stderr=subprocess.DEVNULL, check=True)
    return target


def parse_log(log, code, side, fs):
    text = log.read_text(errors="replace").replace("\r", "")
    found = re.findall(r"^FSCASE name=(\S+) status=(ok|error) errno=(\d+) step=(\S+) units=(\d+) ns=(\d+)$", text, re.M)
    rows = [dict(name=name, status=status, errno=int(err), step=step, units=int(units),
                 diagnostic_ns=int(ns)) for name, status, err, step, units, ns in found]
    done = re.findall(r"^FSDONE cases=(\d+) failed=(\d+)$", text, re.M)
    device = "/dev/vda" if side == "linux" else "/dev/vblk0"
    existing = side == "narf" and fs.startswith("ext")
    mount = bool(re.search(rf"^FSMOUNT status=ok device={device} fs={fs} existing={int(existing)} ", text, re.M))
    if existing:
        mount = mount and bool(re.search(r'^  mnt-mount-ext2: ext on vblk0 mounted at "/mnt"$', text, re.M))
    sync = bool(re.search(r"^FSSYNC status=ok errno=0 unmount=0 retained_boot_mount=[01]$", text, re.M))
    complete = (mount and [row["name"] for row in rows] == CASES and len(done) == 1
                and len(re.findall(r"^FS-SWEEP-END$", text, re.M)) == 1)
    if complete:
        complete = (int(done[0][0]) == len(CASES) and int(done[0][1]) == sum(r["status"] != "ok" for r in rows)
                    and all(r["status"] != "ok" or (r["units"] == units and r["errno"] == 0 and r["diagnostic_ns"] > 0)
                            for r, units in zip(rows, UNITS)))
    valid_exit = code == 0 and (side != "linux" or re.findall(r"^FSRUN-RC=(\d+)$", text, re.M) == ["0"])
    return dict(log=str(log), returncode=code, complete=complete, mounted=mount,
                synced_unmounted=sync, valid_exit=valid_exit, cases=rows,
                passed=complete and sync and valid_exit and all(r["status"] == "ok" for r in rows))


def verify_restored(tree, cases):
    """Compare independently extracted persistent data to the workload contract."""
    original = bytes((i * 17 + (i >> 8) * 31 + 91) & 255 for i in range(1048576))
    expected = {"seed.bin": original}
    statuses = {case["name"]: case["status"] for case in cases}
    if statuses.get("random-overwrite-sync") == "ok":
        data = bytearray(original)
        for i in range(128):
            start = ((i * 97) % 256) * 4096
            data[start:start + 4096] = bytes(b ^ 0xa5 for b in data[start:start + 4096])
        expected["overwrite.bin"] = bytes(data)
    # A failed write may have made partial progress; it remains a failed case.
    if statuses.get("append-sync") == "ok":
        tail = bytes(((i * 17 + (i >> 8) * 31 + 91) & 255) ^ 0xa5 for i in range(1048576, 1114112))
        expected["append.bin"] = original + tail
    for name, size in [("seq-write-sync", 1048576), ("fsync-each", 32768)]:
        if statuses.get(name) == "ok": expected[name] = bytes(b ^ 0xa5 for b in original[:size])
    expected.update({f"lookup/n{i:04d}": b"x" for i in range(64)})
    errors = []
    for name, data in expected.items():
        try:
            if (tree / name).read_bytes() != data: errors.append(f"content_mismatch:{name}")
        except OSError:
            errors.append(f"missing_or_unreadable:{name}")
    for case in ["create-unlink", "rename-unlink"]:
        if statuses.get(case) == "ok":
            for i in range(16):
                names = [f"{case}{i:04d}"]
                if case == "rename-unlink": names.append(f"renamed{i:04d}")
                for name in names:
                    if (tree / name).exists(): errors.append(f"unexpected_file:{name}")
    return dict(passed=not errors, checked_files=len(expected), errors=errors)


def check_image(work, image, side, fs, cases, timeout):
    checker = (["btrfs", "check", "--readonly", "--check-data-csum", str(image)] if fs == "btrfs"
               else ["e2fsck", "-f", "-n", str(image)])
    log = work / f"{side}-{fs}-check.log"
    code = run_logged(checker, log, timeout=timeout)
    bad_markers = [line for line in log.read_text(errors="replace").lower().splitlines()
                   if line.startswith("error") or ("errors found" in line and "no error found" not in line)]
    tree = work / f"{side}-{fs}-restored"
    tree.mkdir()
    restore = (["btrfs", "restore", str(image), str(tree)] if fs == "btrfs"
               else ["debugfs", "-R", f'rdump / "{tree}"', str(image)])
    restore_log = work / f"{side}-{fs}-restore.log"
    restore_code = run_logged(restore, restore_log, timeout=timeout)
    content = verify_restored(tree, cases)
    return dict(fsck_log=str(log), fsck_returncode=code, fsck_bad_markers=bad_markers,
                restore_log=str(restore_log), restore_returncode=restore_code, persistent_content=content,
                image_checks_passed=code == 0 and not bad_markers and restore_code == 0 and content["passed"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnostic", action="store_true", help="explicitly allow functional runs; no performance claims")
    parser.add_argument("--workdir", type=Path, help="new directory for disposable images and logs")
    parser.add_argument("--narf-kernel", type=Path)
    parser.add_argument("--linux-kernel", type=Path)
    parser.add_argument("--filesystems", nargs="+", choices=["ext2", "ext4", "btrfs"], default=["ext2", "ext4", "btrfs"])
    parser.add_argument("--sides", nargs="+", choices=["narf", "linux"], default=["narf", "linux"])
    parser.add_argument("--accel", choices=["kvm", "tcg"], default="kvm")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--cpus", type=int, default=2)
    parser.add_argument("--memory-mb", type=int, default=2048)
    parser.add_argument("--btrfs-features", help="explicit mkfs.btrfs -O list; default uses installed mkfs defaults")
    args = parser.parse_args()
    checks = host_checks()
    if not args.diagnostic:
        print(json.dumps(checks, indent=2))
        return 2
    if not args.workdir or ("narf" in args.sides and not args.narf_kernel) or ("linux" in args.sides and not args.linux_kernel):
        parser.error("--diagnostic requires --workdir and a kernel for every requested side")
    if args.cpus < 1 or args.memory_mb < 512 or args.memory_mb % 2 or args.timeout < 1:
        parser.error("positive CPUs/timeout and even memory >=512 MiB are required")
    if len(set(args.filesystems)) != len(args.filesystems) or len(set(args.sides)) != len(args.sides):
        parser.error("duplicate filesystems or sides are not allowed")
    work = args.workdir.resolve()
    if any(char in str(work) for char in '\n\r"\\,:'):
        parser.error("workdir cannot contain QEMU/debugfs separator characters")
    work.mkdir(parents=True, exist_ok=False)
    report = dict(classification="DiagnosticOnly", performance_record=False, host_checks=checks,
                  source_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                  source_dirty=bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                  source_sha256={str(p.relative_to(ROOT)): sha256(p) for p in [HERE / "probe.c", HERE / "run.py"]},
                  config=vars(args) | {"workdir": str(work)}, runs=[])
    report["config"] = {k: str(v) if isinstance(v, Path) else v for k, v in report["config"].items()}
    def save():
        (work / "diagnostics.json").write_text(json.dumps(report, indent=2) + "\n")
    save()
    seed, binary = prepare(work)
    for path in [HERE / "probe.c", HERE / "run.py"]: shutil.copy2(path, work / path.name)
    report["tools"] = {}
    for command in [["qemu-system-x86_64", "--version"], ["btrfs", "--version"], ["mke2fs", "-V"], ["musl-gcc", "--version"]]:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        report["tools"][command[0]] = result.stdout.strip()
    report["probe_sha256"] = sha256(binary)
    for side in args.sides:
        kernel = getattr(args, side + "_kernel").resolve()
        report[side + "_kernel_sha256"] = sha256(kernel)
        local_kernel = work / ("narf-frame" if side == "narf" else "linux-vmlinuz")
        subprocess.run(["cp", "--reflink=auto", str(kernel), str(local_kernel)], check=True)
        setattr(args, side + "_kernel", local_kernel)
    bases = {fs: make_image(work, seed, fs, args.btrfs_features) for fs in args.filesystems}
    report["base_image_sha256"] = {fs: sha256(image) for fs, image in bases.items()}
    save()
    for fs, base in bases.items():
        for side in args.sides:
            image = work / f"{side}-{fs}.img"
            subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(base), str(image)], check=True)
            log = work / f"{side}-{fs}.log"
            env = os.environ.copy()
            if side == "linux":
                command = ["qemu-system-x86_64", "-machine", "q35", "-cpu", "max,phys-bits=40",
                           "-accel", args.accel, "-smp", str(args.cpus), "-m", str(args.memory_mb),
                           "-display", "none", "-serial", "stdio", "-no-reboot", "-monitor", "none",
                           "-kernel", str(args.linux_kernel.resolve()), "-initrd", str(initrd(work, binary, fs)),
                           "-append", "console=ttyS0 panic=-1 quiet",
                           "-drive", f"if=none,id=vblk0,format=raw,cache=writeback,file={image}",
                           "-device", "virtio-blk-pci,drive=vblk0,disable-legacy=on,disable-modern=off"]
            else:
                # Remove inherited sweep/debug switches which could change storage semantics.
                for key in list(env):
                    if key.startswith(("NARF_QEMU_", "XTASK_QEMU_", "XTASK_STAGE_", "NARF_VBLK_")):
                        del env[key]
                env.update(NARF_VBLK_IMG=str(image), XTASK_STAGE_BIN=str(binary) + ":usr/bin/fs-probe",
                           NARF_QEMU_MEM_MB=str(args.memory_mb), NARF_QEMU_SMP=str(args.cpus),
                           XTASK_QEMU_ACCEL=args.accel, XTASK_RI_PROMPT_TIMEOUT_SECS=str(args.timeout),
                           XTASK_RI_ECHO_TIMEOUT_SECS=str(args.timeout),
                           CARGO_MANIFEST_DIR=str(ROOT / "build/xtask"))
                command = [str(ROOT / "target/debug/xtask"), "run-interactive", "--prebuilt", str(args.narf_kernel.resolve()),
                           "--cmd", f"/usr/bin/fs-probe /dev/vblk0 {fs} " + ("/mnt" if fs.startswith("ext") else "/tmp/fs-sweep"),
                           "--expect", "FS-SWEEP-END"]
            print(f"START {side} {fs}", flush=True)
            code = run_logged(command, log, env=env, timeout=args.timeout)
            row = parse_log(log, code, side, fs) | dict(side=side, fs=fs, command=command)
            row.update(check_image(work, image, side, fs, row["cases"], args.timeout))
            row["passed"] = row["passed"] and row["image_checks_passed"]
            report["runs"].append(row)
            save()
            print(f"DONE {side} {fs}: complete={row['complete']} passed={row['passed']} fsck={row['fsck_returncode']}", flush=True)
    report["base_images_unchanged"] = all(sha256(path) == report["base_image_sha256"][fs] for fs, path in bases.items())
    save()
    return 0 if report["base_images_unchanged"] and all(row["passed"] for row in report["runs"]) else 1


if __name__ == "__main__":
    sys.exit(main())
