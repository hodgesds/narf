# Build, run, and install a self-contained NARF EFI image

The x86_64 source-build path produces `target/narf-x86_64.efi`: one PE/COFF
application containing NARF's EFI entry code, kernel ELF, uncompressed CPIO
initramfs, and kernel command line. UEFI firmware can execute this file
directly. No Limine executable, configuration, kernel sidecar, or initramfs
sidecar is needed on the EFI System Partition (ESP).

Native x86 distribution packages and `cargo narf install` use this path by
default. `image`, `iso-boot`, `grub-image`, and `usb-image` retain their existing
media layouts. `--limine-efi` explicitly selects legacy x86 packages. aarch64 continues to use
`cargo xtask image --arch=aarch64` and its kernel-bound EFI loader.

## Prerequisites

Use the nightly toolchain pinned in `rust-toolchain.toml`, with `rust-src`
and `llvm-tools` installed. Run Cargo through rustup so the pinned toolchain
is selected. Initial builds need access to crates.io.

For QEMU, install `qemu-system-x86_64` and OVMF. Set `OVMF_CODE` to the
firmware CODE image if it is not in one of xtask's standard locations.
The new run path uses QEMU's read-only virtual FAT backend and needs neither
Limine, xorriso, nor mtools.

## Build and run

From the repository root:

```sh
# Build the self-contained application, init/shell, and coreutils.
cargo xtask efi-image

# Build and boot it through OVMF; serial input/output uses this terminal.
cargo xtask efi-image --run

# Use the graphical QEMU window for login; retain serial boot diagnostics.
cargo xtask efi-image --run --display=gtk \
  --cmdline 'narf.disks=boot-only console=ttyS0 console=tty0'

# Build a separate smoke image, require the clean-exit marker and ACPI S5.
cargo xtask efi-image --smoke
```

The default build enables `boot-init`. It embeds the in-tree init, shell,
and `echo`, `pwd`, `cat`, `ls`, and `ps` executables in a CPIO archive.
The existing kernel boot path mounts that archive. The smoke image enables
`boot-smoke` and shuts down automatically; it is written separately as
`target/narf-x86_64-smoke.efi`.

The in-tree getty uses login `root` and password `narf` for development. At
the `narf>` prompt, try `echo hello world`. These are the existing development
credentials described in [Running on Linux](RUNNING_ON_LINUX.md#3-boot-it--log-in).

`XTASK_MEM` (default `4096M`), `XTASK_SMP` (default `2`), `XTASK_CPU`, and
`XTASK_QEMU_ACCEL` configure QEMU. `XTASK_BOOT_SMOKE_TIMEOUT_SECS` sets the
smoke timeout (default 180). OVMF loads the complete EFI application before
the loader copies the kernel and initramfs, so allow memory for both copies.

The ESP staging directory is
`target/native-uefi-x86_64/esp/EFI/BOOT/BOOTX64.EFI` (with a separate
`native-uefi-x86_64-smoke` directory for smoke boots). Only the EFI file is
inside the staged ESP. QEMU's virtual FAT backend has its own size limits;
large firmware bundles may require a real FAT image for manual QEMU testing.

To reuse an exact kernel or supply a complete archive:

```sh
cargo xtask efi-image --prebuilt /absolute/path/narf-frame \
  --initramfs /absolute/path/initramfs.cpio --output target/my-narf.efi
```

`--prebuilt` reports the selected kernel path and SHA-256 and does not rebuild
it or add Cargo features to it. A prebuilt kernel used with `--smoke` must
already contain `boot-smoke`; an interactive kernel needs `boot-init`.
The supplied archive must be uncompressed CPIO `newc` (`070701`), containing
the files your kernel needs. Supplying `--initramfs` replaces the complete
generated archive; it cannot be combined with firmware globs or composed
modules. The canonical ELF remains available for debugging; the embedded
copy has non-loadable symbol/debug sections stripped.

## Boot configuration and firmware

The default embedded command line is `narf.disks=boot-only`. To select an
installed root for the existing kernel root-mount path, build a separate image:

```sh
cargo xtask efi-image --output target/narf-installed.efi \
  --cmdline 'root=UUID=YOUR-FILESYSTEM-UUID systemd_pid1 narf.disks=root-ro'
```

Use the actual filesystem UUID and a root filesystem supported by NARF. This
preserves the existing installed-root compatibility limits. See
[Booting NARF from CachyOS](BOOTING_ON_CACHYOS.md) for the root policy and
distro-userspace prerequisites. To attach a regular raw disk image in QEMU,
add `--run --root-image /absolute/path/root.img`. The disk uses a disposable
snapshot; writes do not modify the source image. Host block devices are refused.

Configuration is bound at build time. EFI shell arguments, firmware load
options, and boot-manager `options` lines do not override it. Rebuild and
replace the EFI file when changing the command line or initramfs.

Firmware is included from the existing `target/firmware/` inventory using
repeatable globs:

```sh
cargo xtask efi-image --initramfs-firmware 'iwlwifi/*'
```

Only matching blobs are added, under the existing `firmware/` archive prefix;
an unmatched selection is an error. Existing NRFW signature and trusted-key
policy still applies. Importing firmware and qualifying its hardware support
are separate steps. Firmware not selected for the archive is not copied to
an installed root by this command.

## Package installation

```sh
cargo narf package --version 0.5.0 --formats auto
cargo narf install --version 0.5.0 --dry-run
# After installing a distribution package, check the mounted ESP:
sudo narf-uefi status
```

The package helper manages `/EFI/NARF/narf.efi`, its BLS entry, and upgrade
signing. It validates the embedded bundle before publishing the new image.
See [packaging](../packaging/README.md) for custom command lines, signed
packages, and migration of an adopted host Limine menu. The manual workflow
below uses a separate directory so it can coexist with a package installation.

## Install on an existing ESP

For a laptop or desktop, select the framebuffer terminal as the preferred
console (`console=tty0` last). The default command line prefers serial for
the headless development workflow. Then copy the image into its own directory
on an already-mounted ESP. These commands are performed by the administrator,
not by `efi-image`:

```sh
cargo xtask efi-image --cmdline 'narf.disks=boot-only console=ttyS0 console=tty0'

ESP=/boot/efi                 # use your mounted ESP's actual path
sudo install -D -m 0644 target/narf-x86_64.efi \
  "$ESP/EFI/NARF-NATIVE/narf.efi"
```

Select that file in the firmware's one-time boot-from-file menu, or execute
`fs0:\EFI\NARF-NATIVE\narf.efi` in a UEFI shell (the ESP may be `fs1:`).
An existing UEFI GRUB installation can chainload it with a custom menu entry:

```grub
menuentry 'NARF native EFI' {
    search --no-floppy --file --set=narf_esp /EFI/NARF-NATIVE/narf.efi
    chainloader ($narf_esp)/EFI/NARF-NATIVE/narf.efi
    boot
}
```

For systemd-boot, create an administrator-managed Type #1 entry on the ESP:

```ini
title NARF native EFI
efi /EFI/NARF-NATIVE/narf.efi
```

For removable media, copy the image to `EFI/BOOT/BOOTX64.EFI` on that medium's
FAT ESP. On each update, rebuild and replace the same EFI file. Remove the
custom boot-manager entry and `EFI/NARF-NATIVE/narf.efi` to uninstall this
manual installation. The existing `narf-uefi` package helper manages its own
package payload, not this separate directory. This workflow does not change
UEFI NVRAM or the host's default boot entry.

## Signing and current limits

All embedded payload bytes are ordinary PE image data. Sign the completed
EFI file after building, using a key trusted by your firmware:

```sh
sbsign --key db.key --cert db.crt --output target/narf-signed.efi \
  target/narf-x86_64.efi
sbverify --cert db.crt target/narf-signed.efi
```

Install the signed output. A later rebuild needs signing again. Secure Boot
firmware enforcement is tested by `packaging/test-secure-boot.sh`; physical
laptop acceptance remains a separate gate. See [Secure Boot](SECURE_BOOT.md) for existing key-management policy.

The first native implementation uses the ELF's fixed physical load range
and rejects a firmware allocation collision. It keeps the loaded EFI image,
initramfs, handoff and EFI boot-services pages reserved for the kernel lifetime;
firmware configuration tables can still refer into the latter. It bounds the
EFI map to 1024 descriptors and the coalesced kernel map to 64 regions; excess
entries fail instead of being dropped. BGRX GOP framebuffers are passed to
the existing kernel framebuffer ABI; other layouts use serial output.

The EFI entry prints the firmware's `SecureBoot` and `SetupMode` variables
before ExitBootServices. This is the enforcement-state evidence used by the
acceptance test. The kernel's separate Secure Boot variable cache is not yet
populated by this handoff; a later kernel-cache report does not substitute for
firmware authentication or this test.

## Encrypted root and initramfs policy

The EFI loader passes the archive to the kernel and never acquires a
credential or decrypts a disk. At Early init, the initramfs crate installs one
explicit credential policy. Late root mounting unlocks the selected LUKS
container, detects its inner filesystem, and exposes `/dev/cryptroot` before
applying `ro`, `rootflags=`, and the root overlay policy.

For serial unlock, use the **outer LUKS container UUID** for both selectors:

```sh
cargo xtask efi-image --output target/narf-encrypted.efi \
  --cmdline 'narf.disks=root-ro root=UUID=YOUR-LUKS-UUID rd.luks.uuid=YOUR-LUKS-UUID rd.luks.prompt=serial console=ttyS0'
```

Replace the UUIDs with `cryptsetup luksUUID` output. The prompt accepts up to
512 printable ASCII bytes, never echoes, supports backspace, and cancels on
Ctrl-C/Escape. `rd.luks.tries=3` (1–5) and `rd.luks.timeout=90` (1–300 seconds
per prompt) bound retries and waiting. Wrong passphrases retry; cancellation,
metadata errors, unsupported KDF parameters, or exhausted attempts stop boot.
A required encrypted root never falls back to the development initramfs login.
The prompt consumes raw serial input; USB keyboard and graphical password
entry require a later early-userspace design and are not available here.

`narf.disks=root-ro` preserves all media and can supply the existing RAM-backed
overlay to `systemd_pid1`. `root-rw` additionally requires btrfs inside the
container and its existing write-safety gate; only the designated container
partition and its decrypted view gain write permission. Other partitions and
the whole-disk device remain read-only. Removing/replacing that registration
revokes retained decrypted handles. UUID selection is deliberately the outer
container in these policies, so boot does not ask for credentials on every
unrelated encrypted disk. NARF's existing LUKS algorithm/KDF/resource limits
still apply; this does not add Linux device-mapper, LVM, or multi-device LUKS.

Noninteractive `rd.luks.key=/path` reads exact bytes from a complete supplied
CPIO archive, with optional `rd.luks.uuid=` restriction and a 64-KiB cap.
It cannot be combined with the serial prompt. **An embedded keyfile is readable
on the ESP and remains in the permanently staged archive**; signing provides
integrity, not key confidentiality. Never put a production passphrase in the
command line. TPM-backed unlock, early-userspace root switching, and reclaimable
archive ownership remain separate design work.

## Validation

The native path has booted through OVMF with release and debug kernels and
passed the clean-shutdown gate. A production-init build has also logged in
over serial and executed `echo hello world` from the shell. The diskless QEMU
fixture exposed an existing NVMe AER-supervisor busy loop when its controller
registry was empty; the supervisor now parks between discovery attempts.
Its regression runs with
`cargo xtask test --arch=x86_64 --hw-profile=minimal --subsystem drivers/nvme`.
The encrypted btrfs write fixture also exposed a virtio sync adapter which
rejected multi-sector writes; it now sends every sector and preserves flush
semantics. This matters for both ordinary btrfs metadata and encrypted views.

Run the focused acceptance gates with the pinned toolchain on PATH:

```sh
packaging/test-packaging.sh
packaging/test-secure-boot.sh
# Build a current production boot-init image first (without --smoke):
cargo xtask efi-image
python3 packaging/test-native-luks.py \
  --kernel target/native-uefi-x86_64/kernel.elf \
  --initramfs target/native-uefi-x86_64/initramfs.cpio
```

The LUKS fixture test needs `cryptsetup`, `mke2fs`, `sfdisk`, QEMU/OVMF, and
Python `cryptography`, `cc`, `btrfs`, and `qemu-img`. It constructs/encrypts only
temporary regular files,
uses QEMU snapshots/overlays, and verifies the source-image hashes. Its writable
btrfs case fsyncs a test file, decrypts the resulting overlay, runs
`btrfs check --readonly`, and recovers the file with `btrfs restore` without
mounting it on the host.
Secure Boot tests additionally need `sbsign`, `sbverify`, `virt-fw-vars`,
`openssl`, and `qemu-img`. Generated keys are disposable test keys, never
release keys. See [hardware acceptance](NATIVE_UEFI_HARDWARE.md) before testing
on a physical machine.
