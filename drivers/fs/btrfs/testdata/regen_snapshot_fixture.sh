#!/usr/bin/env bash
# Regenerate fixture-snapshots.img.sparse: a btrfs whose subvolume trees are
# shared with Linux-made snapshots — the shape of an installed CachyOS root
# under snapper (`@`, a nested `@/.snapshots` subvolume holding numbered
# snapshots of `@`, a top-level snapshot beside it, `@home` snapshotted too),
# with writes between the snapshots (so interior blocks are shared AND some
# are already COWed), a reflinked file, and a metadata + data balance on top
# (relocation leaves FULL_BACKREF blocks and shared-block/shared-data refs).
#
# Snapshots need a real kernel. This boots the host's own Linux kernel under
# QEMU with a throwaway initramfs (bash, coreutils, util-linux mount and
# btrfs-progs from the host, plus their libraries), attaches the image as a
# virtio disk and runs `snapshot-workload.sh` below. Unprivileged: no loop
# device, no host mount, no host block device. The output is checked with
# `btrfs check --readonly --check-data-csum`.
#
#   LINUX_KERNEL=/boot/vmlinuz-linux-cachyos (default)
#   SNAPSHOT_FIXTURE_KEEP=<path>      also keep the full raw image
#   SNAPSHOT_FIXTURE_MANIFEST=<path>  write a per-subvolume sha256 manifest
set -euo pipefail

cd "$(dirname "$0")"
KERNEL="${LINUX_KERNEL:-/boot/vmlinuz-linux-cachyos}"
WORK="$(mktemp -d)"
# SNAPSHOT_FIXTURE_KEEP=<path>: also keep the full raw image there.
trap '[ -n "${SNAPSHOT_FIXTURE_KEEP:-}" ] && cp --sparse=always "$IMG" "$SNAPSHOT_FIXTURE_KEEP"; rm -rf "$WORK"' EXIT
IMG="$WORK/snap.img"
UUID=c4c405ee-0000-4a11-9e57-00000005a95f

truncate -s 256M "$IMG"
mkfs.btrfs -q -f -U "$UUID" -L snapfixture -n 4096 -s 4096 --csum crc32c -m single \
    -O block-group-tree,free-space-tree,no-holes "$IMG"

# ── initramfs ──────────────────────────────────────────────────────────
ROOT="$WORK/initramfs"
mkdir -p "$ROOT"/{bin,dev,proc,sys,mnt,tmp,lib,lib64,usr/lib}
TOOLS="bash sh mount umount btrfs mkdir cp rm dd sync sha256sum cat seq head mv ln gzip
truncate ls sleep printf find sort xargs echo chmod tr fstrim"
for t in $TOOLS; do
    p="$(type -P "$t")" || continue
    cp -L "$p" "$ROOT/bin/$t"
    ldd "$p" 2>/dev/null | grep -o '/[^ ]*' | while read -r lib; do
        mkdir -p "$ROOT$(dirname "$lib")"
        cp -Ln "$lib" "$ROOT$lib" 2>/dev/null || true
    done
done
cat > "$ROOT/init" <<'INIT'
#!/bin/bash
export PATH=/bin
mount -t devtmpfs dev /dev
mount -t proc proc /proc
mount -t sysfs sys /sys
if bash -ex /snapshot-workload.sh > /dev/console 2>&1; then
    echo "SNAPSHOT-FIXTURE: OK" > /dev/console
else
    echo "SNAPSHOT-FIXTURE: FAIL" > /dev/console
fi
sync
echo o > /proc/sysrq-trigger
sleep 10
INIT
chmod +x "$ROOT/init"
cat > "$ROOT/snapshot-workload.sh" <<'WORK'
M=/mnt
mount -o compress=zstd:1 /dev/vda $M
btrfs subvolume create $M/@
btrfs subvolume create $M/@home
mkdir -p $M/@/etc $M/@/usr/lib/pkg $M/@/var/lib/pacman/local $M/@home/narf
# Many small (inline) files: a multi-level fs tree on 4 KiB nodes.
for i in $(seq 0 899); do printf 'file %d of the root\n' "$i" > $M/@/usr/lib/pkg/f$i; done
# Compressible regular extents.
for i in $(seq 0 39); do
    for j in $(seq 1 300); do echo "line $j of data file $i"; done > $M/@/usr/lib/data$i.txt
done
# Incompressible data and a reflink of it (data shared within one tree).
dd if=/dev/urandom of=$M/@/usr/lib/blob.bin bs=64k count=4 status=none
cp --reflink=always $M/@/usr/lib/blob.bin $M/@/usr/lib/blob-reflink.bin
for i in $(seq 0 199); do echo "home $i" > $M/@home/narf/h$i; done
sync

# snapper: a nested .snapshots subvolume, numbered read-only snapshots.
btrfs subvolume create $M/@/.snapshots
mkdir $M/@/.snapshots/1
btrfs subvolume snapshot -r $M/@ $M/@/.snapshots/1/snapshot
btrfs subvolume snapshot -r $M/@home $M/@home/.snap-home
sync

# Round 2: diverge (COWs some shared blocks, leaves the rest shared).
for i in $(seq 0 7 899); do echo "round2 $i" >> $M/@/usr/lib/pkg/f$i; done
rm -f $M/@/usr/lib/pkg/f1[0-9][0-9]
for i in $(seq 0 99); do echo "new $i" > $M/@/etc/new$i; done
dd if=/dev/urandom of=$M/@/usr/lib/data3.txt bs=4k count=3 conv=notrunc status=none
for i in $(seq 0 49); do echo "home2 $i" >> $M/@home/narf/h$i; done
sync
mkdir $M/@/.snapshots/2
btrfs subvolume snapshot -r $M/@ $M/@/.snapshots/2/snapshot
sync

# Round 3: more divergence, a writable snapshot written after creation, and
# a top-level snapshot (NARF's `.narf-pre-rw-@`).
for i in $(seq 3 11 899); do echo "round3 $i" > $M/@/usr/lib/pkg/f$i; done
truncate -s 1000 $M/@/usr/lib/data7.txt
mkdir $M/@/.snapshots/3
btrfs subvolume snapshot $M/@ $M/@/.snapshots/3/snapshot
echo "written after the snapshot" > $M/@/.snapshots/3/snapshot/etc/after-snap
btrfs subvolume snapshot -r $M/@ $M/.narf-pre-rw-@
for i in $(seq 0 9); do echo "round4 $i" >> $M/@/etc/new$i; done
sync

# Relocation: FULL_BACKREF blocks, shared-block and shared-data refs.
btrfs balance start -m $M
btrfs balance start -d $M
sync
btrfs subvolume list $M
fstrim -v $M
umount $M
WORK

(cd "$ROOT" && find . | cpio -o -H newc --quiet) | gzip -1 > "$WORK/initramfs.gz"

qemu-system-x86_64 -machine q35 -m 1024M -smp 2 -nographic -no-reboot \
    -accel kvm -cpu host \
    -kernel "$KERNEL" -initrd "$WORK/initramfs.gz" \
    -append "console=ttyS0 rdinit=/init panic=-1 loglevel=4" \
    -drive "if=virtio,format=raw,discard=unmap,file=$IMG" | tee "$WORK/console.log"
grep -q "SNAPSHOT-FIXTURE: OK" "$WORK/console.log"

btrfs check --readonly --check-data-csum "$IMG"

# SNAPSHOT_FIXTURE_MANIFEST=<path>: every subvolume's files (sha256), by
# subvolume id, as `btrfs restore` extracts them (not committed: the kernel
# tests compare snapshots before and after writing themselves).
if [ -n "${SNAPSHOT_FIXTURE_MANIFEST:-}" ]; then
MAN="$SNAPSHOT_FIXTURE_MANIFEST"
: > "$MAN"
for id in $(btrfs inspect-internal dump-tree -t 1 "$IMG" |
            sed -n 's/.*key (\([0-9]*\) ROOT_ITEM .*/\1/p' | sort -un); do
    [ "$id" = 5 ] || [ "$id" -ge 256 ] || continue
    out="$WORK/restore-$id"
    mkdir -p "$out"
    btrfs restore -r "$id" "$IMG" "$out" >/dev/null 2>&1 || true
    (cd "$out" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum) |
        sed "s|^|$id |" >> "$MAN"
done
fi

python3 - "$IMG" fixture-snapshots.img.sparse <<'PY'
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src, 'rb').read()
runs, blk, i, n = [], 4096, 0, len(data)
while i < n:
    if data[i:i+blk].count(0) == len(data[i:i+blk]):
        i += blk
        continue
    j = i
    while j < n and data[j:j+blk].count(0) != len(data[j:j+blk]):
        j += blk
    runs.append((i, data[i:j]))
    i = j
with open(dst, 'wb') as f:
    f.write(b'NARFBTR1' + struct.pack('<QI', n, len(runs)))
    for off, b in runs:
        f.write(struct.pack('<QQ', off, len(b)) + b)
PY
echo "wrote fixture-snapshots.img.sparse ($(stat -c %s fixture-snapshots.img.sparse) bytes)"
