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
| Boot NARF with Secure Boot enabled | Not yet supported |

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
4. Disable Secure Boot for the NARF attempt. NARF release media and native
   packages do not yet participate in CachyOS's `sbctl` signing flow.
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

The native package path currently requires `x86_64`. It supports the boot
managers above but does not change UEFI NVRAM, replace the active manager, or
make NARF the default. Native aarch64 package installation and Secure Boot are
still outside this workflow.

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
- Secure Boot signing and key enrollment are not implemented for native
  packages;
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
| Secure Boot | Sign the EFI loader and kernel artifacts and integrate with a documented key-enrollment policy. |
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
