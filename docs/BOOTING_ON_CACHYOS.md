# Booting NARF from CachyOS

This guide covers testing NARF on an x86_64 machine that normally runs
CachyOS. Keep the CachyOS kernel installed and selected by default. NARF is an
additional boot target, not currently a drop-in replacement for
`linux-cachyos`.

## What works today

| Goal | Status |
| --- | --- |
| Build and boot NARF under QEMU on a CachyOS host | Supported |
| Boot the NARF ISO or a NARF USB image on a spare machine | Supported, hardware coverage varies |
| Install the native Arch package on a legacy-BIOS GRUB system | Implemented; GRUB searches for the kernel on either common `/boot` layout |
| Install the native Arch package on a UEFI GRUB system | Implemented through a package-owned Limine EFI payload |
| Boot the installed CachyOS root and its systemd/KDE session under NARF | Not yet a supported workflow |
| Boot an encrypted CachyOS root | Not yet supported by the native-package workflow |
| Use CachyOS Limine, systemd-boot, or rEFInd | Implemented through native registration, BLS, or EFI discovery |
| Boot a signed native package with Secure Boot enabled | Implemented; the enforced chain and tamper rejection are OVMF-gated, while physical firmware still needs validation |

The distinction matters. NARF can run unmodified musl and glibc programs and
has booted a generated Fedora image with systemd as PID 1 in QEMU. The native
package currently boots NARF's built-in userspace, however; it does not reuse
the CachyOS initramfs, Linux modules, or installed root filesystem.

CachyOS currently offers GRUB, Limine, systemd-boot, and rEFInd. NARF's native
package installs an isolated Limine application, kernel, and configuration
under `/EFI/NARF` on the ESP. UEFI GRUB chainloads it, systemd-boot uses its
Boot Loader Specification entry, rEFInd discovers it, and CachyOS Limine is
registered through `limine-entry-tool`. Legacy-BIOS GRUB continues to load the
Multiboot2 kernel directly. See the CachyOS
[boot-manager overview](https://wiki.cachyos.org/installation/boot_managers/)
before changing an installed machine.

In this guide, **supported** means the exact workflow has a repeatable
end-to-end acceptance test. **Implemented** means the relevant code exists and
has narrower tests; it does not imply that a particular physical machine has
passed. **Experimental** means the path is useful for development but still
has an important integration or hardware-validation gap.

## Safety checklist

Before a bare-metal test:

1. Keep `linux-cachyos` installed and configured as the default entry.
2. Have a CachyOS live USB or another known-good recovery path.
3. Back up important data. Do not use an experimental kernel boot as a backup
   test.
4. For unsigned release media, disable Secure Boot for the NARF attempt. For a
   native package, either do that or sign its bound loader with the machine's
   existing enrolled `sbctl` policy as described below.
5. Start with QEMU, then a dedicated NARF USB, and only then add a native boot
   entry.

Confirm the machine and boot layout without changing anything:

```sh
uname -m
if test -d /sys/firmware/efi; then echo UEFI; else echo "legacy BIOS"; fi
findmnt /boot /boot/efi
test -f /boot/grub/grub.cfg && echo "GRUB configuration found"
sbctl status 2>/dev/null || true
```

The CachyOS native package path uses `x86_64`. It supports the boot
managers above but does not change UEFI NVRAM, replace the active manager, or
make NARF the default. The cross-distribution packager also emits native
aarch64 UEFI packages, but CachyOS itself is an x86_64 distribution.

## Recommended first test: QEMU

Install the build and virtualization prerequisites listed in
[Running on Linux](RUNNING_ON_LINUX.md). On CachyOS these are available through
`pacman`; package names can change, but the required tools include the base
build toolchain, Rustup, QEMU x86_64, `libisoburn`/`xorriso`, `mtools`, OVMF,
and GRUB utilities.

From a NARF checkout:

```sh
cargo xtask host-test
cargo xtask run --arch=x86_64
cargo xtask boot-smoke --arch=x86_64
cargo xtask test --arch=x86_64
```

The first Rust command installs the repository-pinned toolchain through
Rustup when it is not already present. `/dev/kvm` is used automatically when
the current user can access it; otherwise QEMU falls back to slower software
emulation.

Exercise the same x86_64 UEFI/Limine image layout used for release media:

```sh
cargo xtask iso-boot --arch=x86_64
```

This is the most useful first compatibility report because failure leaves the
host boot configuration untouched. When reporting a problem, include the
QEMU command, serial log, CPU model, and the final test summary.

Before testing networking on hardware, run both end-to-end virtual paths:

```sh
cargo xtask net-smoke --arch=x86_64
cargo xtask e1000-module-net-smoke --arch=x86_64
```

Both require successful host-to-guest TCP and UDP exchanges plus a guest DNS
lookup. The second additionally proves that the e1000 driver was built,
ABI-stamped, loaded before PCI probing, and used as the exclusive owner of the
emulated NIC.

## Standalone ISO or USB test

Build the release image:

```sh
cargo xtask image --arch=x86_64
sha256sum target/narf-x86_64.iso
```

The ISO boots through Limine's removable-media UEFI path and requires Secure
Boot to be disabled. It is independent of the boot manager installed by
CachyOS.

For a dedicated USB device, first identify the exact target:

```sh
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS
```

Then write it with the guarded xtask command:

```sh
sudo cargo xtask disk-write --device=/dev/sdX
sync
sudo eject /dev/sdX
```

`disk-write` is destructive to the selected device and refuses a target that
is not USB-attached. Replace `/dev/sdX` only after checking its model and size.
Do not select the CachyOS system disk.

On first real-hardware attempts, capture the serial console if the platform
exposes one and record the exact CPU, motherboard/laptop, storage controller,
GPU, network adapter, and boot result. Stage 5 silicon validation remains in
progress, so a successful QEMU boot does not imply every physical driver is
ready.

### Disposable partitioned ext4 USB

After the live ISO boots, the next storage test is a dedicated partitioned
USB. This exercises GPT discovery, a FAT32 ESP, root-device selection, and an
ext4 root without touching the CachyOS disk:

```sh
cargo xtask image --arch=x86_64
cargo xtask disk-write-partitioned \
  --device=/dev/sdX \
  --root-fs=ext4 \
  --root-label=NARF_ROOT
```

The second command displays the target and asks for confirmation before using
`sudo` to repartition it. It destroys every existing partition and byte of
data on the selected USB device. Check its transport, model, and size with
`lsblk` immediately before answering the prompt.

This creates a NARF development root containing the in-tree init and shell; it
does not copy or convert the installed CachyOS system. ext4 is the default
because it is the most exercised persistent-root path. Use this only after the
non-partitioned ISO has established that the machine reaches NARF at all.

## RX 6750 XT bring-up boot

Recipe for the Navi22 (RX 6750 XT, `03:00.0`) bring-up on the Gigabyte B650I
AORUS ULTRA (BIOS F41). The console lives on the Raphael iGPU (`12:00.0`); the
6750 XT is a secondary GPU whose cold boot cannot take the screen away. The
stick saves the NARF kernel log to itself, so a failed boot can be read back
under CachyOS. The stick boots with `narf.disks=boot-only`, which keeps the
internal disks read-only; see
[Internal-disk safety](#internal-disk-safety-narfdisksboot-only) for exactly
what that guarantees.

**Build** (no device access; the importer copies only the Navi22 blobs):

```sh
cargo xtask import-firmware --source /usr/lib/firmware \
  --vendor amdgpu/navy_flounder --skip-existing
cargo xtask usb-image --initramfs-firmware "amdgpu/navy_flounder*"
```

This writes `target/narf-x86_64-usb.img`: an MBR disk with one FAT32 ESP
(label `NARFBOOT`) holding Limine, the kernel, an initramfs with the
`navy_flounder` firmware (the Navi22 initcall runs before any root mount) and
`/NARFLOG.ID`. The kernel command line gets `narf.disks=boot-only
narf.bootlog=<random token> log_buf_len=8M` and no `quiet`. Add arguments with `--cmdline <arg>`
(repeatable); build without the log with `--no-bootlog`. Adding `--qemu` also
boots a copy of the image under OVMF as QEMU USB storage and prints the logs
it wrote; those boots also attach decoy internal disks (an NVMe with a GPT
ESP, an ext4 marked `needs_recovery` and a btrfs, plus a whole-disk ext4 on
SATA) and fail unless their SHA-256 is unchanged afterwards.

**BIOS settings:**

- *Settings → IO Ports → Initial Display Output*: **IGD Video**, so the UEFI
  GOP, Limine and the NARF console are on the motherboard HDMI.
- *Settings → IO Ports → Integrated Graphics*: **Enabled** (Auto can disable
  the iGPU while a discrete card is installed).
- *Boot → CSM Support*: **Disabled** (the stick is UEFI-only).
- *Boot → Secure Boot*: **disabled** for this test, because the stick is
  unsigned (see [UEFI Secure Boot](SECURE_BOOT.md)). This host currently
  reports it disabled: `od -An -t u1
  /sys/firmware/efi/efivars/SecureBoot-*` ends in `0`.
- Choose the stick once from the boot menu (F12) instead of changing the boot
  order, so CachyOS stays the default.

**Cabling:** connect the monitor to the **motherboard HDMI**. A second cable
from the monitor to the 6750 XT's HDMI is optional and matters only once
native modeset lands. Attach a USB keyboard for the NARF shell.

**Write the stick.** Identify it first. It must show `TRAN usb`:

```sh
lsblk -o NAME,SIZE,MODEL,TRAN,MOUNTPOINTS
cargo xtask disk-write --iso target/narf-x86_64-usb.img \
  --device /dev/sdX --fast-wipe
```

`disk-write` refuses non-USB targets, asks for confirmation, and verifies the
written bytes after a replug. On this host the internal disks are the two
NVMe drives (the Sabrent data disk at `04:00.0` and the WD SN770 CachyOS disk
at `07:00.0`; Linux names them `nvme0n1` / `nvme1n1` in either order, varying
per boot) and the SATA disk `sda`. None of them is ever a valid `--device`.

**What to expect on screen.** While the card boots, every Navi22 stage prints
`start`, then `complete` or `failed <error>`. The cold boot ends with
`amdgpu: navi22 stage summary (N/M ok):` followed by one line per
stage, then the connector (EDID/HPD), media and thermal notes. If the screen stops changing, photograph it; the last `start` line
names the stage that hung. Shortly after the shell appears, the console shows
`bootlog: saving the kernel log to usb-msc0p1:/narf-boot-<n>.log`. To finish,
log in (`root` / `narf`) and type `reboot` (or `poweroff`) in the NARF
shell, which flushes the log one last time.
Otherwise wait at least five seconds after the last line before powering off.

**Retrieve the log** after booting back into CachyOS:

```sh
lsblk -o NAME,SIZE,TRAN,LABEL      # the NARFBOOT partition, e.g. sdX1
udisksctl mount -b /dev/sdX1
cp /run/media/$USER/NARFBOOT/narf-boot-*.log .
udisksctl unmount -b /dev/sdX1
```

Each boot creates the next `narf-boot-<n>.log`, up to 32 files of at most
4 MiB each; delete old ones to continue. Each line is prefixed with seconds
since boot, as in `dmesg`. The kernel writes only to a USB FAT volume whose
`/NARFLOG.ID` matches the token on its command line. To keep the stick
read-only for one boot, press `e` in the Limine menu and change the argument
to `narf.bootlog=off`.

An unexpected power-off during bring-up is most likely the Navi22 thermal
protection (SMU CTF or software-shutdown temperature), which calls the ACPI S5
power-off on purpose. That path runs the same final flush as `reboot`, so the
log should end with the `amdgpu: navi22 thermal ...` or `EMERGENCY` line that
caused it, followed by `[bootlog: final flush before reboot/power-off]`.

Limits: the stick becomes writable only once the USB stack runs, which is
after the last boot initcall, including the 6750 XT cold boot. Lines logged
before then are saved retroactively, but a hang *before* that point leaves
only the screen. A kernel panic is appended in a final flush bounded at 3 s.
A fatal CPU exception is not saved.

### Internal-disk safety (`narf.disks=boot-only`)

`cargo xtask usb-image` puts `narf.disks=boot-only` on the command line
(`--allow-all-disks` leaves it off; never use that on this machine). With it:

- **Every block device is read-only until it is identified as the stick.**
  The block registry wraps each disk and partition (NVMe, SATA, USB, SD) in a
  guard that passes reads and refuses writes with an error. The first refusal
  per device is logged as `disks: refused write to <dev> ...`. The console
  states the policy at boot:
  `disks: narf.disks=boot-only: every disk is read-only until identified as
  the boot medium`.
- **Only the stick becomes writable.** A USB mass-storage FAT volume whose
  `/NARFLOG.ID` matches the `narf.bootlog=` token is identified
  (`disks: usb-msc0p1: identified as the boot medium`). From then on, that
  stick's partitions are writable, and nothing else is. A device that later
  appears under the same name starts read-only again. With
  `narf.bootlog=off`, or a `--no-bootlog` image, nothing is ever identified,
  so every disk stays read-only, the stick included.
- **No automatic mount of anything else.** These boot steps skip every
  unidentified disk and log the skip:
  - `root-mount-auto`, including an explicit `root=`, which is refused with
    `BootOnly` (`/` comes from the initramfs);
  - `efi-system-partition-mount`, which therefore never mounts the CachyOS ESP
    at `/boot`;
  - `mnt-mount-ext2`, which never mounts an internal ext4 (such as the
    Sabrent `nvme0n1p2`) at `/mnt`.

  The btrfs member discovery skips unidentified disks too. The btrfs disk
  smokes additionally need `narf.btrfs_smoke`, which only xtask's own test
  run passes.
- **Read-only mounts do not write.** An ext2/3/4 or btrfs volume on a
  read-only device is mounted read-only without a single write:
  - **ext:** the stale `needs_recovery` superblock repair is skipped. A dirty
    journal is replayed into memory only.
  - **btrfs:** a pending fsync log tree refuses the mount instead of being
    replayed. No commit timer starts.
  - **FAT:** a mount never writes (there is no dirty-bit or FSInfo update at
    mount). Writes happen only through file operations, which the guard
    refuses.
- **The NVMe passthrough is closed.** On every controller node `/dev/nvme<C>`,
  admin and I/O passthrough ioctls (Format, Sanitize, firmware commit, raw
  writes) and writes are refused unless every namespace of that controller is
  the stick. Only the namespace-id query is answered.

Limits. Exactly what this does and does not cover:

- **Scope.** The guarantee covers what NARF does after the kernel starts.
  - The UEFI firmware and Limine run first, and they are outside it. Limine
    only reads.
  - Under QEMU, OVMF without a writable variable store writes `\NvVars` to
    the first ESP it finds. `--qemu` gives it one, so the check measures
    NARF alone.
- **Which writes are guarded.** The guard sees every write that goes through
  the block registry: all filesystems, the `/dev/<disk>` block nodes, the
  boot log and the partition/LUKS layers. A driver writing through a private
  controller handle would bypass it. An audit of the in-tree storage drivers
  found no such write on a non-test boot.
  - NVMe, AHCI, virtio-blk and USB MSC probes only read: IDENTIFY and the
    partition table. Controller setup (queue creation, feature negotiation,
    HBA and link resets) does not change media.
  - Format/Sanitize/firmware/security commands have no in-kernel caller.
  - Test-only writes exist only in `kernel-test` builds, which usb-image does
    not use.
- **Command-line errors.** A misspelled `narf.disks=` value fails closed to
  `boot-only`. Removing the argument (Limine `e` editor) removes the
  guarantee.
- **Reads stay allowed.** The internal disks can still be enumerated,
  partition-scanned and read, including from the root shell.
- **Explicit `ro` on the stick.** A userspace `mount -o ro` of the
  identified stick sets only the VFS read-only flag. ext's mount-time
  superblock repair would still run there. On every other disk the device
  itself is read-only, so this does not arise.
- **Current hardware coverage on this host.**
  - NVMe: NARF drives every NVMe controller, numbered in PCI order: on this
    host `nvme0` is `04:00.0` (Sabrent data disk) and `nvme1` is `07:00.0`
    (WD SN770, the CachyOS disk). Every active namespace is registered as
    `nvme<C>n<N>` and partition-scanned, so `nvme0n1p1`, `nvme0n1p2` (ext4
    data), `nvme1n1p1` (the ESP) and `nvme1n1p2` (btrfs root) are all
    registered, read-only.
  - **Names are not identity.** A controller that fails to probe, a moved
    drive or a firmware that enumerates differently shifts every later name.
    Identify disks by filesystem UUID or PARTUUID (`/dev/disk/by-uuid`,
    `/dev/disk/by-partuuid`) or by hardware identity (`/dev/disk/by-id/
    nvme-<model>_<serial>`, `nvme-<wwid>`, `/dev/disk/by-path/
    pci-0000:07:00.0-nvme-1`); the boot log prints each namespace's PCI
    address, model, serial and WWID (`nvme: nvme1 (0000:07:00.0, ...)`).
  - SATA: the AHCI driver binds any AHCI-class controller (`01:06:01`), as
    Linux does, so the AMD 600-series controller (`1022:43f6`) and `sda`
    are driven as `sata0`, with any partitions as `sata0p<n>`, all
    read-only. The AMD controller has not been tested: QEMU emulates only
    Intel ICH9.
  - Probing these disks only reads. Controller setup (NVMe queue creation,
    the AHCI HBA reset and SATA link reset) does not change media.
  - On reboot and power-off NARF sends every NVMe controller a Flush (when
    it has a volatile write cache) and then the CC.SHN normal-shutdown
    notification, as Linux does (`nvme: nvme<C>: flushed ... CC.SHN normal
    shutdown: Complete`). Neither carries data or changes media contents.
- **Testing.** This is validated in QEMU (block-layer model tests, a
  two-controller NVMe model and a two-controller QEMU run, ext and btrfs
  read-only mount tests, and the `usb-image --qemu` decoy hashes with two
  NVMe decoys and a SATA decoy). It has
  not been validated on hardware.

### Booting the installed root (`narf.disks=root-ro` / `root-rw`)

Two more policies boot the host's own CachyOS root (systemd as PID 1)
instead of NARF's userspace. Both name the root only by filesystem UUID, never
by a device name:

```sh
# Read-only root, writable tmpfs overlay (nothing on any disk is written):
cargo xtask grub-image --root-policy root-ro \
  --root-uuid 653602c3-cd42-420e-95ef-4c4033d17b56
# Real read-write to the btrfs root ONLY:
cargo xtask grub-image --root-policy root-rw \
  --root-uuid 653602c3-cd42-420e-95ef-4c4033d17b56
```

Each command emits `narf.disks=<mode> root=UUID=<uuid> rootflags=subvol=/@
systemd_pid1` (`--rootflags` changes the subvolume). Without `--root-policy`,
grub-image still writes `boot-only`. `--bootlog-token <token>` adds
`narf.bootlog=<token>` (8-64 characters of `[A-Za-z0-9_-]`) for the
persistent boot log described below.

- **Nothing is writable until the root is designated.** Root mounting
  matches `root=UUID=` and calls `designate_root` before the filesystem is
  built. The designation re-reads the UUID from the partition's own
  superblock and requires exactly one `root=` on the command line. It is
  refused for a UUID carried by two devices (a cloned disk, a multi-device
  btrfs), a whole disk, an ESP or vfat partition and, under `root-rw`,
  anything that is not btrfs. It can happen once per boot. If the root device
  is removed or re-registered, or a second device with its UUID appears, the
  designation is revoked and every disk stays read-only for the rest of the
  boot.
- **Banners.** At policy resolution:
  `disks: POLICY narf.disks=root-rw: ONLY the partition whose filesystem UUID
  matches root=UUID=... will be WRITABLE; every other disk and partition (its
  ESP included) is read-only`. At designation:
  `disks: WRITABLE: <dev> (btrfs UUID ...) is the ONLY writable device`.
  Under `root-ro` the second banner says `designated READ-ONLY ... NOTHING is
  writable`.
- **`root-rw` writes exactly one partition.** Only the designated root
  partition's block-layer guard passes writes. Every other disk and
  partition is refused: the SN770's whole-disk device and its ESP
  (`6D89-28C5`, which may be mounted read-only), the Sabrent, `sda`, and the
  `/dev/nvme<C>` passthrough nodes. vfat filesystems also report themselves
  read-only to the VFS under both root policies, so they mount `ro`.
- **The boot-log stick is the one exception, under both policies.** With
  `narf.bootlog=<token>`, the USB mass-storage FAT partition whose
  `/NARFLOG.ID` first line is the token becomes writable, and nothing else on
  that stick or any other disk does. A stick on the root's own disk is never
  accepted. The console then prints `disks: WRITABLE (log stick):
  usb-msc0p1 ...`. A failed root-ro/root-rw boot still leaves its log. Under
  the root policies the log probes the stick only after root mounting has
  finished, so the stick's I/O never delays the root. Lines from before then
  are saved retroactively.
- **The boot stops visibly, never degrades.** A failed `root=` mount under
  either root policy prints `root-mount: narf.disks=... ROOT MOUNT FAILED:
  <reason>; NOT falling back` plus the btrfs refusal line. It does not fall
  back to the initramfs or another disk.
- **btrfs write-safety gate.** This mirrors Linux `open_ctree` /
  `btrfs_check_features`. Before anything can write (log replay included),
  a read-write btrfs mount is refused and logged as
  `btrfs <uuid>: REFUSING read-write mount: <reason>` when any of these hold:
  - an incompat or compat_ro bit outside what the writer maintains;
  - a free-space tree without its valid bit (or BGT without FST);
  - no free-space tree on non-mixed block groups;
  - `BTRFS_SUPER_FLAG_ERROR` or any superblock flag besides `WRITTEN`
    (seeding, metadump, fsid or csum change in progress);
  - generation 0;
  - a balance item, reloc roots, or a started or suspended device replace.

  Under `root-rw` the gate also requires one device, crc32c, 4 KiB sectors,
  a power-of-two nodesize of 4–64 KiB, a valid free-space tree and an empty
  log tree (`log_root == 0`; mount once on Linux to replay a dirty log). Its
  incompat set is limited to `MIXED_BACKREF DEFAULT_SUBVOL COMPRESS_LZO
  COMPRESS_ZSTD BIG_METADATA EXTENDED_IREF SKINNY_METADATA NO_HOLES` and its
  compat_ro set to `FREE_SPACE_TREE FREE_SPACE_TREE_VALID BLOCK_GROUP_TREE`.
- **One writer per filesystem.** Every btrfs mount of an fsid is a view of
  one shared core: one transaction, one allocator, one superblock commit. So
  under `root-rw` all seven fstab subvolumes (`/`, `/home`, `/root`, `/srv`,
  `/var/cache`, `/var/tmp`, `/var/log`) are writable together. The gate
  runs once per core. A read-write mount of a refused core fails with `EROFS`,
  which `mount(8)` retries read-only. Every other fsid and device stays
  read-only at the block layer.
- **Status on this host.** The CachyOS root has compat_ro `0xb`
  (`FREE_SPACE_TREE FREE_SPACE_TREE_VALID BLOCK_GROUP_TREE`) and incompat
  `0x371`, and the writer maintains all of it, block-group tree included, so
  `root-rw` writes it. The gate refuses only if the superblock read at boot
  shows a pending log tree (an unclean Linux shutdown), an error flag, or a
  running balance or replace. Compare with the real superblock using `sudo
  btrfs inspect-internal dump-super
  /dev/disk/by-uuid/653602c3-cd42-420e-95ef-4c4033d17b56`.
- **What the writer does to a CachyOS volume.**
  - New data is written uncompressed, which is valid under
    `compress=zstd:1`.
  - Touched zstd/LZO extents are rewritten uncompressed.
  - `chattr +C` journals (`NODATASUM`) get no checksums.
  - Freed extents' checksums are removed from Linux's merged csum items.
  - Data goes to DATA block groups and tree blocks to METADATA ones.
  - The free-space tree is maintained.
  - The v1 space cache is invalidated by the generation bump.
  - `discard=async` is accepted and ignored (NARF never discards).
  - Options that would change unmaintained state (`clear_cache`,
    `space_cache=v1`, `nodatasum`, `rescue=`, `degraded`, `device=`) are
    refused.
- **Interop test.** `cargo xtask btrfs-rootrw-interop` builds a CachyOS-shaped
  image unprivileged and boots it under `root-rw`. The image has GPT, an ESP,
  btrfs with nodesize 16K, crc32c, FST, no-holes, `--compress zstd:1`, the
  seven `@` subvolumes and `+C` journals. It is built twice, with the host's
  exact flags (block-group tree) and without them. Each image gets four
  boots:
  - `@`: pacman db add and remove, `/etc/hostname` replace, a zstd-file
    overwrite, an unlink;
  - `@home`;
  - `@log`: journal append, rotate and vacuum;
  - `fstab`: all six other subvolumes mounted rw through the shared core and
    written.

  After each boot the test requires host `btrfs check --readonly
  --check-data-csum` to be clean and the GPT and ESP to be byte-identical. At
  the end, `btrfs restore` content must match in all seven subvolumes.
  `--bgt=refused` checks the opposite case (a writer without BGT support).
  `cargo xtask btrfs-crash-smoke [--bgt]` checks fsync durability across a
  SIGKILL. A host `mount -o loop,ro` runs only with passwordless sudo.
- **Before a real `root-rw` boot**, take a read-only snapshot on CachyOS
  (`sudo btrfs subvolume snapshot -r / /.snapshots/pre-narf`) and keep a
  backup of `/home`. Shut NARF down cleanly (`sync`, then power off). Back on
  CachyOS, run `sudo btrfs scrub start -B /` and check `dmesg` for btrfs
  errors.

## Storage encryption and LUKS

NARF has a real encrypted-block implementation, but that does not yet make an
ordinary encrypted CachyOS installation bootable through the native package.

| Capability | Current status |
| --- | --- |
| Open common LUKS1 volumes | Implemented for AES-XTS/`plain64` with bounded PBKDF2 profiles |
| Open common LUKS2 volumes | Implemented for one normal AES-XTS/`plain64` crypt segment with bounded PBKDF2 or Argon2i/Argon2id keyslots |
| Read and write the unlocked payload | Implemented; LUKS metadata itself is opened read-only |
| Supply a key from a measured NARF initramfs | Implemented with `rd.luks.key=/path` and optional `rd.luks.uuid=<uuid>` |
| Prompt interactively for a passphrase during boot | Not implemented |
| Format LUKS, edit keyslots, repair metadata, use integrity profiles, or resume reencryption | Not implemented |
| Unlock an installed CachyOS root from the current Arch package entry | Not integrated or accepted as a supported workflow |

The keyfile path names a file *inside the staged NARF initramfs*, not a path on
the still-locked root filesystem. The current Arch package boots built-in
userspace and does not build or attach a CachyOS-specific NARF initramfs, add
the required kernel arguments, or offer an unlock prompt. A typical encrypted
CachyOS root therefore remains unavailable even when its particular LUKS
header and cipher profile are understood by the block layer.

For now, leave an encrypted production installation unchanged. Test storage
with a disposable unencrypted ext4 image or disk, or build a dedicated NARF
initramfs containing a test keyfile. Never copy a production passphrase into a
development image, and do not remove encryption from the CachyOS installation
just to test NARF.

The exact accepted profiles and work limits are documented in the
[encrypted-block specification](../block/specification/encrypted.md).

## Filesystem status

CachyOS offers Btrfs, XFS, ext4, F2FS, and ZFS. Its default Btrfs layout uses
multiple subvolumes and Zstd compression. NARF's most supported and recommended
root filesystem for current installation experiments is **ext4**.

| Filesystem | NARF status | CachyOS testing guidance |
| --- | --- | --- |
| ext4 | Read/write; the default and most exercised NARF partitioned-install path | Recommended for a disposable NARF root. Unsupported features, a dirty journal, or damaged metadata can still force read-only operation or rejection. |
| ext2/ext3 | Supported by the shared ext-family driver, with feature-dependent write limits | Useful for fixtures and simple images; prefer ext4 for a new test root. |
| Btrfs | Broad read/write, compression, subvolume, snapshot, multi-device, and checksum support exists | Do not point NARF at the production CachyOS root yet. The CachyOS `@` layout, fstab, boot orchestration, and distro-PID1 path lack an end-to-end acceptance gate. |
| FAT12/16/32 | Read/write | Suitable for EFI/removable-media data, not a CachyOS root filesystem. |
| exFAT | Mount, directory walk, and reads work; full VFS mutation is incomplete | Treat as read-mostly removable media, not a root filesystem. |
| SquashFS, ISO 9660, UDF, MINIX | Read-only implementations, with format-specific limits | Suitable only for supported image or media use cases. |
| XFS, F2FS, ZFS | No NARF filesystem driver | Unsupported. CachyOS's Linux ZFS module cannot be loaded by NARF. |

Filesystem support is not permission to experiment on the only copy of a
volume. Use a clone or a disposable image until the exact NARF driver, mount
options, userspace, and shutdown path have passed an end-to-end test.

## Driver readiness

A driver being present in the source tree does not mean every device ID,
firmware revision, interrupt topology, and laptop wiring has passed on real
hardware. Start from the proven QEMU devices and treat physical hardware as a
bring-up target.

| Area | Best-tested path | Current physical-hardware caveat |
| --- | --- | --- |
| Storage | QEMU virtio-blk and NVMe | NVMe, AHCI, USB mass-storage, and other transports are in-tree, but machine-specific silicon coverage varies. Do not continue toward a root mount if the controller or disk did not bind cleanly. |
| Wired networking | QEMU e1000; its live acceptance test covers TCP, UDP, and DNS, including the loadable-module path | e1000/e1000e, igc, Realtek, ixgbe, mlx5, and other drivers have different maturity levels. Match the exact PCI ID; use QEMU e1000 or a known supported wired adapter when the onboard NIC is not ready. |
| Wi-Fi | Software and protocol tests | iwlwifi's AX210+/Sc/BE211 path still needs silicon validation and real-supplicant acceptance; ath11k and rtw88 are earlier bring-up. Do not depend on Wi-Fi for the first boot. |
| Graphics | QEMU Bochs and virtio-gpu framebuffer/DRM paths | Native AMDGPU work targets specific Phoenix/HawkPoint and Navi22 hardware but has not completed the silicon gate. CachyOS NVIDIA modules are Linux modules and cannot be reused. Use serial or the boot framebuffer first. |
| Input and USB | QEMU input plus xHCI USB HID paths | xHCI, USB keyboard/mouse, i8042, and I2C-HID foundations exist, but laptop touchpads and platform wiring still need machine-specific validation. Keep a USB keyboard and serial fallback. |
| Audio, power, suspend, and thermal | QEMU or software tests for individual pieces | Not first-boot acceptance criteria. Avoid suspend/resume during initial hardware testing. |

Devices that require firmware must use firmware staged and authorized for
NARF. Installed Linux modules, DKMS output, and a Linux driver's private
firmware-loading path are not interchangeable with a NARF module or driver.
Distribution maintainers can package an out-of-tree NARF driver as a built-in
or runtime module without editing this repository; see
[external kernel composition](extending/composition.md) and the
[runtime-module guide](extending/modules.md).

### Firmware for a hardware-specific test image

CachyOS normally stores device firmware under `/usr/lib/firmware` (with
`/lib/firmware` resolving to the same hierarchy). NARF's importer can copy a
single vendor subtree into the ignored `target/firmware` staging area,
decompress Arch-style `.zst` entries, and wrap each blob in the NARF firmware
format:

```sh
cargo xtask import-firmware \
  --source /usr/lib/firmware \
  --vendor iwlwifi \
  --skip-existing
cargo xtask image --arch=x86_64
```

With a partitioned root, firmware not selected for the initramfs is staged at
`/lib/firmware` on that root. Firmware needed before the root can mount must be
selected explicitly, for example with `--initramfs-firmware "vendor/*"` on
the `image` command. Import only the vendor required for the test; a complete
host firmware tree can make the image unnecessarily large.

The normal development image enables the explicit unsigned-firmware bring-up
policy and logs each unsigned handout. A distribution build must instead sign
the wrapped payloads and embed the authorized public keys as described in the
[firmware specification](../firmware/specification/spec.md). Never treat a
blob's presence in CachyOS as proof that the matching NARF driver is complete.

## CPU and isolation status

NARF selects its x86_64 domain backend at boot. It uses PKS when exposed by
the CPU and otherwise attempts the PCID page-table backend used by current AMD
laptops and many older Intel machines. The selected backend is printed in the
boot log.

PKS has suitable QEMU fault coverage. The PCID policy has structural tests,
but the enforcement path has not yet executed on the project's available
hardware runners. If neither PKS nor PCID is available, boot can continue
without a domain enforcer. Such a boot may still help driver bring-up, but it
must not be reported as proving NARF's cross-domain security properties. See
[Domain backends](DOMAIN_BACKENDS.md) for the exact boundary.

## Native Arch package on UEFI or legacy BIOS

A release may provide an Arch package named like:

```text
narf-kernel-<version>-1-x86_64.pkg.tar.zst
```

Inspect it before installation:

```sh
pacman -Qip ./narf-kernel-<version>-1-x86_64.pkg.tar.zst
pacman -Qlp ./narf-kernel-<version>-1-x86_64.pkg.tar.zst
```

Install it as an additional kernel target:

```sh
sudo pacman -U ./narf-kernel-<version>-1-x86_64.pkg.tar.zst
```

Developers can build the same package locally:

```sh
cargo install --path build/cargo-narf
cargo narf detect
cargo narf install --version 0.5.0 \
  --limine-efi /usr/share/limine/BOOTX64.EFI \
  --dry-run
cargo narf install --version 0.5.0 \
  --limine-efi /usr/share/limine/BOOTX64.EFI
```

Use the path from CachyOS's `limine` package. If the machine does not use
Limine as its primary manager, installing that package supplies build input;
it does not by itself change the active boot manager or firmware default.

The package installs `/boot/narf-kernel-<version>`, the package-owned UEFI
source payload under `/usr/lib/narf/uefi`, the `narf-uefi` administrator tool,
and `/etc/grub.d/42_narf`. When a FAT ESP is mounted at `/efi`, `/boot`, or
`/boot/efi`, its package hook also installs:

```text
/EFI/NARF/narf.efi
/EFI/NARF/narf-frame
/EFI/NARF/limine.conf
/boot/limine/limine.conf
/loader/entries/narf.conf
```

These are ESP-relative paths. For example, when the ESP itself is mounted at
`/boot`, its ESP-relative `/boot/limine/limine.conf` appears on the host as
`/boot/boot/limine/limine.conf`.

The `/boot/limine/limine.conf` copy is a marked GRUB-chainload fallback. The
installer does not overwrite an unrelated file at that path. It also skips
that fallback when another Limine EFI application is already present, then
reports a warning so that installation's existing Limine policy can remain in
control.

It does not replace or remove any CachyOS kernel, write UEFI NVRAM variables,
or change the default entry.

Before rebooting, verify the package and ESP payload:

```sh
pacman -Ql narf-kernel
grub-file --is-x86-multiboot2 /boot/narf-kernel-<version>
sudo narf-uefi status
```

If CachyOS already manages an enrolled Secure Boot policy with `sbctl`, sign
the NARF loader after package installation. This explicit choice persists and
future package upgrades re-sign the replacement loader:

```sh
sudo sbctl status
sudo narf-uefi install --sign-with-sbctl
sudo narf-uefi status
sudo sbctl verify /boot/EFI/NARF/narf.efi
```

Adjust the final path to the actual ESP mount point. Do not create or enroll
keys solely for this test without first accounting for CachyOS, Windows,
firmware updates, and option ROM trust. NARF never changes PK, KEK, `db`, MOK,
or the firmware Secure Boot setting. See
[UEFI Secure Boot](SECURE_BOOT.md) for the trust-chain and recovery model.

If `status` says no ESP is mounted, identify and mount the actual ESP, then
install explicitly. Do not substitute the root or data partition:

```sh
findmnt -t vfat
sudo narf-uefi install --esp /boot
sudo narf-uefi status --esp /boot
```

Replace `/boot` with the mount point reported on the machine. On UEFI GRUB,
regenerate `/boot/grub/grub.cfg` after a manual install and verify that the
NARF entry contains `chainloader`:

```sh
sudo grub-mkconfig -o /boot/grub/grub.cfg
grep -n -A12 -B1 "NARF <version>" /boot/grub/grub.cfg
```

On legacy BIOS the same generator searches first for
`/narf-kernel-<version>` and then `/boot/narf-kernel-<version>`, selecting the
filesystem that actually owns the file before issuing `multiboot2`.

No manual menu edit is needed for systemd-boot: it reads
`/loader/entries/narf.conf`. rEFInd discovers `/EFI/NARF/narf.efi`. On a
CachyOS Limine installation, the hook asks `limine-entry-tool` to register the
same EFI application; if the tool reports a warning, reinstall it explicitly
with `narf-uefi install` after confirming the ESP and active manager.

Installing a newer `narf-kernel` package upgrades the same package name,
removes the previous package-owned NARF image, and regenerates GRUB. It does
not retain an automatic older-NARF rollback entry. The separately installed
`linux-cachyos` package remains the recovery path and should stay the default.

At the GRUB menu, leave CachyOS as the default and select the NARF entry only
for the test. The current entry boots NARF's built-in userspace and does not
need a CachyOS-generated initramfs.

To remove the package and regenerate GRUB entries:

```sh
sudo pacman -R narf-kernel
```

Package removal invokes `narf-uefi remove` and regenerates GRUB when present.
The ESP must be mounted during removal. If it is currently unmounted, mount it
and run `sudo narf-uefi remove --esp <mount-point>` *before* `pacman -R`; the
package cannot clean an unmounted filesystem after its helper has been removed.

## Pre-hardware validation gate

Run `cargo xtask cachyos-gate` before booting the installed CachyOS root
under NARF on the real machine, and again after every change to storage,
btrfs, the disk policy or the systemd path. It boots the same
`cargo xtask grub-image` bundle that goes on the host's ESP, against disk
images that have the host's shape, and prints one PASS/FAIL row per check.
It exits nonzero if any row fails. It never opens a host block device.
Everything it writes is a regular file under `target/cachyos-gate/` (or
`--work-dir`).

```sh
cargo xtask cachyos-gate                       # full matrix (Gates A/B)
cargo xtask cachyos-gate --cases ro,rw         # a subset, in matrix order
cargo xtask cachyos-gate --crash-runs 3 --cycles 3 --seed 42
cargo xtask cachyos-gate --skip-build --cases linux   # reuse the staged bundles
cargo xtask cachyos-gate --real-root /mnt/sabrent/narf-gatec/cachyos-root-copy.img \
  --work-dir /mnt/sabrent/narf-gatec/work      # Gate C (see below)
```

### What it boots

| Piece | Gate | Host |
| --- | --- | --- |
| Machine | QEMU q35, OVMF (split CODE + a private VARS copy, so OVMF never writes `\NvVars` to an ESP), 4 vCPUs, 4 GiB, KVM when `/dev/kvm` is usable | B650I, UEFI |
| NVMe controller 1 (`00:04.0`) | Decoy GPT disk: vfat p1 (1 MiB) + ext4 p2 (64 MiB, one file), like the Sabrent | Sabrent Rocket 4.0 (`04:00.0`) |
| NVMe controller 2 (`00:07.0`) | Root disk: GPT vfat ESP p1 + btrfs p2, `boot` device | WD SN770 (`07:00.0`) |
| USB stick | MBR FAT32 with `/NARFLOG.ID` for `narf.bootlog=` | The bring-up stick |
| Boot chain | OVMF -> GRUB -> the bundle's `grub.cfg` stanza -> Limine (`/EFI/NARF/BOOTX64.EFI`) -> NARF | CachyOS GRUB -> the same stanza |

The root disk is the `cachyos-root-smoke` image
(`verification/data/cachyos-root/REGEN_cachyos_root_image.sh`, built
unprivileged on first use): the real CachyOS `base` userspace, `mkfs.btrfs -O
block-group-tree,free-space-tree,no-holes`, crc32c, 16 KiB nodes, 4 KiB
sectors, zstd, the subvolumes `@ @home @root @srv @cache @tmp @log`, and the
host's fstab with the image's own UUIDs. Its superblock carries the host's
feature flags exactly (compat_ro 0xb, incompat 0x371). The gate works on a
reflinked copy, `target/cachyos-gate/root.img`.

GRUB is a `grub-mkstandalone` x86_64-efi image placed at
`\EFI\BOOT\BOOTX64.EFI` on the root disk's ESP. Its embedded `grub.cfg` is
`set timeout=0` plus the bundle's own `grub.cfg` stanza, unchanged, so the
`search --file /EFI/NARF/BOOTX64.EFI` + `chainloader` path that runs on the
host is the path tested. The bundle's `esp/` tree is copied onto the same
ESP, as on the host. The gate builds two bundles:

```sh
cargo xtask grub-image --features cgroup-all,container \
  --root-policy root-ro --root-uuid <image fsid>      # and --root-policy root-rw
```

`--features cgroup-all,container` (plus the `boot-init` and
`firmware-allow-unsigned` that `grub-image` always adds) is the systemd PID 1
configuration that `systemd-pid1` uses. Build the hardware bundle the same
way. The gate appends `narf.bootlog=<token>` to the staged `limine.conf`
because `grub-image` has no option for it yet. The resulting command line is
printed in the `topology` row, for example:

```
narf.disks=root-rw root=UUID=<fsid> rootflags=subvol=/@ systemd_pid1 narf.bootlog=gate...
```

Each boot logs in on the serial console (`root` / `narf`, the image's test
credentials) and drives the guest from a shell. The write workload writes
under `/narf-gate` on `@`:

- 400 small files, 50 of them fsynced one at a time;
- 100 renames and 100 unlinks;
- a 100 MiB file written through a temporary name, fsynced, then renamed;
- a `TAG` file;
- a file in `/home` if `/home` is writable;
- a journald message, then `journalctl --flush`.

It reports `home=rw|ro`, `journal=persistent|volatile` and the mount options
of `/`, `/home` and `/var/log`. All content is deterministic, so the host can
verify it byte for byte.

### The rows

| Row | Passes when |
| --- | --- |
| `topology` | Both bundles built; the root image's fsid and ESP serial differ from every host disk (the constants above plus `findmnt -no UUID` of `/`, `/boot/efi` and `/home`); its `/etc/fstab` (read with `btrfs restore`) names only the image's own btrfs and ESP UUIDs; no log tree. |
| `1 root-ro` | The getty login prompt is reached and the workload runs on the tmpfs overlay. Afterwards the SHA-256 of the whole root disk and of the decoy is unchanged, and so is the btrfs superblock generation. |
| `2 root-rw` | Login is reached with `/` mounted `rw`, and the workload and a clean `systemctl poweroff` complete. On the host, `btrfs check --readonly` and `btrfs check --readonly --check-data-csum` are clean, and `btrfs restore -r <id of @>` (unprivileged, on the extracted partition file) yields exactly the expected files and content. `log_root` is 0. Every byte outside the btrfs partition (GPT, ESP, slack) and the whole decoy are unchanged. |
| `3 crash xN` | N times, QEMU is SIGKILLed at a uniformly random point (5-95%) of the workload, using the duration measured by row 2 (30 s if row 2 did not run). `btrfs check --readonly` must be clean after each kill. The next NARF root-rw boot must either mount `/` read-write (only allowed when `log_root` is 0), or refuse read-write with the `non-empty fsync log tree` reason while leaving the root partition's hash unchanged. A refusal is followed by one Linux boot, which replays the log, and the runs continue. A final boot judges the last kill. |
| `4 cycles xN` | N consecutive root-rw boot -> workload -> poweroff cycles, each followed by the row 2 host checks: check, check-data-csum, restore, outside-bytes and decoy unchanged, `log_root` 0. |
| `5 linux interop` | The host's own kernel (`/boot/vmlinuz-linux-cachyos`, copied) boots the post-NARF image with systemd, mounts `/` rw, reads the files of the last NARF round (SHA-256 of `big.dat`, a small file), and runs the workload. `btrfs scrub start -B /` must find no errors, and the host checks must then be clean. NARF then boots the image root-rw again, reads the Linux-written files, writes a new round and powers off, and the host checks are clean again (round trip). |
| `boot chain` | Summary of every boot. Each NARF boot must show GRUB's `Booting 'NARF'` within 120 s, NARF's first console line within 180 s more, and its `disks: POLICY` line within 240 s after that. A boot that hangs before the kernel runs (firmware, GRUB or Limine) is killed and retried once, and is listed here. A second hang fails the row that was booting. |

The Linux boot needs no initramfs. The CachyOS kernel has btrfs and
virtio-blk built in (NVMe is a module), so the gate attaches both images as
virtio-blk disks and boots `root=PARTUUID=<p2> rootflags=subvol=/@ rw
console=ttyS0`. vfat is a module too, so it adds `systemd.mask=boot-efi.mount`.
The image has no Linux modules, so the ESP cannot be mounted. Add arguments
with `CACHYOS_GATE_LINUX_APPEND`.

### Reading the output

The run ends with a table:

```
cachyos-gate results
row              result  detail
---------------  ------  ----------------------------------------
topology         PASS    q35+OVMF; OVMF -> GRUB (...) -> Limine -> NARF
                         ...
1 root-ro        PASS    login 41s; / rw (overlay); ...; root+decoy sha256 unchanged; gen 9 unchanged; ...
2 root-rw        FAIL    / is not mounted read-write under root-rw: btrfs ...: REFUSING read-write mount: ...
```

- A row's detail starts with the first failure. The last lines of the guest
  console follow, and then the serial log's path, so a FAIL can be read
  without rerunning.
- `target/cachyos-gate/logs/NN-<label>.serial.log` holds the full serial
  console of boot `NN`: firmware, GRUB, Limine, the NARF kernel log, systemd
  and the shell session.
- `target/cachyos-gate/check/<label>.check.log` and `.check-csum.log` hold the
  host `btrfs check` output. `<label>.restore.log` and `restore-<label>/` hold
  what `btrfs restore` extracted.
- `REFUSING read-write mount: <reason>` lines in a detail come from NARF's
  read-write safety gate. Under `root-rw`, the gate turns the volume
  read-only and names the reason, such as an unsupported feature bit or a log
  tree.
- `home=ro` or `journal=volatile` in a PASS row is information, not a
  failure. The workload writes to `@` only. Whether the other fstab
  subvolumes come up writable depends on the btrfs one-writer-per-fsid rule.
- The crash row prints its seed. Rerun it with the same `--seed` to repeat
  the same kill points.
- `bootlog saved|not saved` in row 1 shows whether the kernel log reached the
  USB stick under that policy.

Do not boot the installed root on hardware until every row passes on the
current tree, first against the generated image (Gates A/B) and then against
a real copy of the host root (Gate C).

### Gate C: a real copy of the host root

Gate C runs the same matrix against a byte-level copy of the host's own `@`
(and optionally `@home`). Build the copy once, on the Sabrent's ext4 data
partition (`/mnt/sabrent`, about 519 GB free). These are the only commands
in this workflow that need `sudo`. They read the live root through read-only
snapshots and write only the image file through a loop device. The copy gets
a new fsid, a new ESP serial and an fstab that names only those, so it can
never be confused with the host root.

```sh
set -eu
SAB=/mnt/sabrent
DIR=$SAB/narf-gatec
IMG=$DIR/cachyos-root-copy.img
HOST_FSID=653602c3-cd42-420e-95ef-4c4033d17b56   # live root; never reused
HOST_ESP=6D89-28C5
sudo mkdir -p "$DIR" && sudo chown "$USER": "$DIR"

# 1. A sparse GPT disk: 512 MiB ESP + btrfs sized for the root's data + 40 GiB.
USED=$(sudo btrfs filesystem usage -b / | awk '/^ *Used:/ {print $2; exit}')
truncate -s $(( USED / 1024 / 1024 / 1024 + 41 ))G "$IMG"
sfdisk "$IMG" <<'SFDISK'
label: gpt
start=2048, size=1048576, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI system partition"
start=1050624, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="root"
SFDISK

# 2. Filesystems with fresh identities and the host root's mkfs features.
LOOP=$(sudo losetup --find --show --partscan "$IMG")
NEW_FSID=$(uuidgen)
sudo mkfs.fat -F 32 -n EFI "${LOOP}p1"
sudo mkfs.btrfs -U "$NEW_FSID" -L cachyos-gatec --csum crc32c -n 16384 -s 4096 \
  -O block-group-tree,free-space-tree,no-holes "${LOOP}p2"
NEW_ESP=$(sudo blkid -s UUID -o value "${LOOP}p1")
sudo mkdir -p /mnt/narf-gatec /mnt/narf-hosttop
sudo mount -o noatime,compress=zstd:1 "${LOOP}p2" /mnt/narf-gatec

# 3. Read-only snapshots of the live subvolumes, sent into the copy.
sudo mount -o subvolid=5 UUID=$HOST_FSID /mnt/narf-hosttop
sudo btrfs subvolume snapshot -r /mnt/narf-hosttop/@ /mnt/narf-hosttop/@narf-gatec-root
sudo btrfs send /mnt/narf-hosttop/@narf-gatec-root | sudo btrfs receive /mnt/narf-gatec/
# Optional: also copy @home.
sudo btrfs subvolume snapshot -r /mnt/narf-hosttop/@home /mnt/narf-hosttop/@narf-gatec-home
sudo btrfs send /mnt/narf-hosttop/@narf-gatec-home | sudo btrfs receive /mnt/narf-gatec/

# 4. Writable @ (and @home) in the copy, plus the remaining CachyOS subvolumes.
sudo btrfs subvolume snapshot /mnt/narf-gatec/@narf-gatec-root /mnt/narf-gatec/@
sudo btrfs subvolume snapshot /mnt/narf-gatec/@narf-gatec-home /mnt/narf-gatec/@home \
  || sudo btrfs subvolume create /mnt/narf-gatec/@home
for s in @root @srv @cache @tmp @log; do sudo btrfs subvolume create /mnt/narf-gatec/$s; done
sudo btrfs subvolume delete /mnt/narf-gatec/@narf-gatec-root
sudo btrfs subvolume delete /mnt/narf-gatec/@narf-gatec-home 2>/dev/null || true

# 5. Inside the COPY only: fstab names the copy's UUIDs; every other UUID line
#    (the Sabrent, other disks) is commented out. Gate login root/narf.
F=/mnt/narf-gatec/@/etc/fstab
sudo sed -i -e "s/$HOST_FSID/$NEW_FSID/g" -e "s/$HOST_ESP/$NEW_ESP/g" "$F"
sudo awk -v a="UUID=$NEW_FSID" -v b="UUID=$NEW_ESP" \
  '/^[[:space:]]*UUID=/ && $1 != a && $1 != b { print "#narf-gatec# " $0; next } { print }' \
  "$F" | sudo tee "$F.new" >/dev/null && sudo mv "$F.new" "$F"
echo 'root:narf' | sudo chpasswd -R /mnt/narf-gatec/@
grep -v '^#' "$F"                           # review: only $NEW_FSID / $NEW_ESP

# 6. Clean up: the host's temporary snapshots, the mounts, the loop device.
sudo umount /mnt/narf-gatec
sudo btrfs subvolume delete /mnt/narf-hosttop/@narf-gatec-root /mnt/narf-hosttop/@narf-gatec-home
sudo umount /mnt/narf-hosttop
sudo losetup -d "$LOOP"
sudo chown "$USER": "$IMG"
```

Then, unprivileged:

```sh
cargo xtask cachyos-gate --real-root /mnt/sabrent/narf-gatec/cachyos-root-copy.img \
  --work-dir /mnt/sabrent/narf-gatec/work
```

The gate refuses an image whose fsid or ESP serial matches a host disk, or
whose fstab names any other UUID. ext4 has no reflinks, so the gate first
makes a full copy of the image in `--work-dir`, and the host checks extract
the btrfs partition to a file again after each boot. Expect a run to take
hours for a large root. Add `--in-place` to boot the given image itself and
skip the first copy; Gate C is then single-use until the copy is rebuilt. The
copy keeps the host's machine-id and enabled units. If the graphical target
gets in the way of the serial login, run `sudo ln -sfn
/usr/lib/systemd/system/multi-user.target
/mnt/narf-gatec/@/etc/systemd/system/default.target` in step 5.

## Why the installed CachyOS root is not ready yet

CachyOS recommends Btrfs and normally uses an `@` root subvolume plus separate
subvolumes for `/home`, `/root`, `/srv`, and parts of `/var`; it also enables
Zstd compression by default. See the CachyOS
[filesystem layout](https://wiki.cachyos.org/installation/filesystem/).
NARF has Btrfs read/write and compressed-extent coverage, but the supported
distro-PID1 gate currently uses a purpose-built ext-family Fedora image mounted
at `/mnt`. It is not yet wired to CachyOS's Btrfs subvolume/fstab layout.

Other blockers to a drop-in `linux-cachyos` replacement are:

- the release package is not built with and configured for the full
  `boot-init`/systemd/cgroup distro path;
- CachyOS's mkinitcpio image is a Linux boot artifact and cannot simply be
  handed to NARF as a replacement driver environment;
- Linux DKMS and prebuilt modules, including CachyOS's NVIDIA and ZFS modules,
  do not use NARF's module ABI;
- the stock CachyOS rootfs has no dedicated NARF acceptance gate yet;
- native GPU, Wi-Fi, input, NVMe, suspend/resume, and platform support still
  need machine-specific silicon validation.

The minimum credible “CachyOS under NARF” gate is a disposable CachyOS image
booted in QEMU with systemd as PID 1, networking, persistent storage, udev,
login, and a clean shutdown marker. Bare-metal testing should follow only
after that gate passes and the target machine's drivers are validated.

## Open implementation work

The UEFI packaging path is now implemented, but these deployment items remain:

| Item | Needed before calling it supported |
| --- | --- |
| CachyOS root acceptance | Build a disposable CachyOS image and gate systemd PID 1, udev, networking, persistent writes, login, and clean shutdown in QEMU. |
| Encrypted root boot | Build/stage a NARF initramfs, add credential policy and kernel arguments, and provide an interactive or distribution-managed unlock path. |
| CachyOS Btrfs layout | Gate the default `@` subvolume layout, Zstd, fstab-generated mounts, snapshots, and shutdown/recovery behavior. |
| Secure Boot key lifecycle | A deploying distribution or administrator must own enrollment, rotation, revocation, recovery, and signing-key custody; NARF deliberately does not automate firmware key changes. |
| Hardware support matrix | Run repeatable silicon tests keyed by PCI/USB/ACPI IDs, firmware versions, and machine models instead of inferring support from in-tree code. |

Those changes should use focused follow-up branches because they change boot
policy, test infrastructure, filesystems, or drivers.

## If something is not supported

Do not try to make NARF the default kernel or repair the production
installation from the failed NARF boot. Reboot the existing `linux-cachyos`
entry, then choose the narrow fallback for the missing layer:

1. If `narf-uefi status` fails, mount the ESP and rerun `narf-uefi install`
   with an explicit `--esp`. If the active manager still has no NARF entry,
   use QEMU or the standalone NARF ISO/USB image and report the manager and
   ESP layout.
2. If the root is encrypted, keep it locked and use a disposable unencrypted
   ext4 test image. The measured-initramfs keyfile flow is for intentionally
   constructed test images, not an automatic CachyOS unlock replacement.
3. If the filesystem is XFS, F2FS, or ZFS, do not mount it through NARF. Clone
   the workload onto a disposable ext4 image instead. Treat an existing Btrfs
   CachyOS root the same way until its full boot layout has an acceptance test.
4. If storage does not bind, stop before mounting or writing. Reproduce with a
   QEMU virtio-blk or NVMe device and report the physical controller's PCI ID.
5. If networking is missing, collect logs offline and reproduce with QEMU
   e1000. Prefer a known supported wired device over Wi-Fi for bare-metal
   bring-up.
6. If graphics or input fails, use serial output, the boot framebuffer, and a
   USB keyboard. A graphical desktop is not the first proof of a sound boot.
7. If implementing the missing support, keep it in an external crate and add
   it through a composition first. Record the exact PCI/USB/ACPI identity and
   firmware requirements before choosing built-in versus runtime-module form.

From CachyOS, collect read-only inventory before filing a report:

```sh
uname -a
lspci -nnk
lsusb
lsblk -f
findmnt -no SOURCE,FSTYPE,OPTIONS /
findmnt /boot /boot/efi
```

Include that inventory, the exact NARF commit, how the image was built, the
boot method, kernel arguments, and the complete serial log. If the failure is
device-specific, identify the vendor/device ID and firmware revision rather
than only the product name.

For the authoritative implementation status, see [STATUS.md](../STATUS.md),
the [desktop compatibility track](DESKTOP_LINUX_PLAN.md), and the
[release-packaging guide](../packaging/README.md).
