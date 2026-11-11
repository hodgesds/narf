#!/usr/bin/python3
"""Check a soak run's disk image from the host, after QEMU has exited.

  soak-verify.py <run-dir> <image>

* Extracts the btrfs root partition of <image> (a reflinked range, so it
  costs nothing) and runs `btrfs check --readonly` on it.
* Restores /narf-soak-data from subvolume @ with `btrfs restore` (both
  unprivileged, on a regular file) and checks what the guest wrote there
  against what its serial log says it wrote:
    - `durable: <file> <mode> done seed=<s> mib=<m>`: the file must hold the
      pattern of <s> for <m> MiB;
    - `INTEGRITY-FINAL <file> len=<n> fnv=<h>`: the file must be <n> bytes
      with FNV-1a hash <h>.
Prints one line per check and a summary to stdout, and keeps the logs in
<run-dir>/verify/.
"""
import os
import re
import struct
import subprocess
import sys

ROOT_OFFSET = (2048 + 512 * 2048) * 512   # after the 1 MiB gap and the 512 MiB ESP
MASK = (1 << 64) - 1


def pattern_word(seed, off):
    x = ((seed * 0x9E3779B97F4A7C15) & MASK) ^ off
    x ^= x >> 33
    x = (x * 0xff51afd7ed558ccd) & MASK
    x ^= x >> 33
    x = (x * 0xc4ceb9fe1a85ec53) & MASK
    x ^= x >> 33
    return x


def fnv1a(data):
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & MASK
    return h


def extract(image, out):
    size = os.path.getsize(image) - ROOT_OFFSET - 2048 * 512
    if os.path.exists(out):
        os.unlink(out)
    with open(image, "rb") as src, open(out, "wb") as dst:
        left, off = size, ROOT_OFFSET
        while left > 0:
            n = os.copy_file_range(src.fileno(), dst.fileno(), min(left, 1 << 30), off)
            if n <= 0:
                raise OSError("copy_file_range stopped")
            off += n
            left -= n


def subvol_id(part, name="@"):
    out = subprocess.run(["btrfs", "inspect-internal", "dump-tree", "-t", "root", part],
                         capture_output=True, text=True).stdout
    pending = None
    for line in out.splitlines():
        m = re.search(r"ROOT_REF (\d+)", line)
        if m:
            pending = int(m.group(1))
            continue
        m = re.search(r" name (\S+)$", line)
        if m and pending is not None:
            if m.group(1) == name:
                return pending
            pending = None
    raise SystemExit("subvolume @ not found")


def check_durable(path, seed, mib):
    try:
        data = open(path, "rb").read()
    except OSError:
        return "MISSING"
    want = mib << 20
    if len(data) != want:
        tail = f", length {len(data)} of {want}"
    else:
        tail = ""
    bad = first = 0
    first = -1
    for i in range(0, min(len(data), want) // 8):
        (w,) = struct.unpack_from("<Q", data, i * 8)
        if w != pattern_word(seed, i * 8):
            bad += 1
            if first < 0:
                first = i * 8
    zero = data.count(0) == len(data)
    if bad == 0 and not tail:
        return "ok"
    return (f"BAD: {bad} of {want // 8} words differ (first at {first})"
            f"{' - the file is all zeroes' if zero else ''}{tail}")


def main():
    run, image = sys.argv[1], sys.argv[2]
    vdir = os.path.join(run, "verify")
    os.makedirs(vdir, exist_ok=True)
    part = os.path.join(vdir, "root.btrfs")
    extract(image, part)
    out = subprocess.run(["btrfs", "check", "--readonly", part], capture_output=True, text=True)
    text = out.stdout + out.stderr
    open(os.path.join(vdir, "btrfs-check.log"), "w").write(text)
    errors = [l for l in text.splitlines() if "ERROR" in l or re.search(r"\berrors? found\b", l) and "no error" not in l]
    verdict = "clean" if out.returncode == 0 and not errors else f"FAILED (rc {out.returncode})"
    print(f"btrfs check --readonly: {verdict}")
    for line in (errors or text.strip().splitlines()[-3:])[:12]:
        print(f"  {line}")

    serial = open(os.path.join(run, "serial.log"), "rb").read().decode("utf-8", "replace")
    durable = re.findall(r"durable: (/narf-soak-data/\S+) (\w+) done seed=(\d+) mib=(\d+)", serial)
    integ = {}
    for path, length, h in re.findall(r"INTEGRITY-FINAL (/narf-soak-data/\S+) len=(\d+) fnv=([0-9a-f]+)",
                                      serial):
        integ[path] = (int(length), int(h, 16))
    if not durable and not integ:
        print("no data written under /narf-soak-data to check")
        os.unlink(part)
        return
    restore = os.path.join(vdir, "restore")
    subprocess.run(["rm", "-rf", restore])
    os.makedirs(restore)
    r = subprocess.run(["btrfs", "restore", "-r", str(subvol_id(part)), "--path-regex",
                        r"^/(|narf-soak-data(|/.*))$", part, restore], capture_output=True, text=True)
    open(os.path.join(vdir, "restore.log"), "w").write(r.stdout + r.stderr)
    failed = 0
    for path, mode, seed, mib in durable:
        result = check_durable(restore + path, int(seed), int(mib))
        # `nosync` is written just before the hard stop: Linux may lose it
        # too, so it is reported, not judged.
        if mode == "nosync":
            print(f"durable {mode:6s} {path}: {result} (informational)")
            continue
        failed += result != "ok"
        print(f"durable {mode:6s} {path}: {result}")
    for path, (length, h) in sorted(integ.items()):
        try:
            data = open(restore + path, "rb").read()
            if len(data) != length:
                result = f"BAD: length {len(data)}, guest said {length}"
            elif fnv1a(data) != h:
                result = "BAD: contents differ from what the guest verified"
            else:
                result = "ok"
        except OSError:
            result = "MISSING"
        failed += result != "ok"
        print(f"integrity {path}: {result}")
    judged = len([d for d in durable if d[1] != "nosync"]) + len(integ)
    print(f"data checks: {judged - failed} ok, {failed} not")
    os.unlink(part)


if __name__ == "__main__":
    main()
