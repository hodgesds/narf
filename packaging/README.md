# NARF release packaging

`build-release.sh` turns a canonical x86_64 or aarch64 kernel ELF and its
architecture-matching EFI loader into installable distribution packages.
Packages own these source artifacts:

- `/boot/narf-kernel-<version>` as the versioned host-side copy, also used by
  x86_64 legacy-BIOS GRUB;
- `/usr/lib/narf/uefi/` with the bound loader, kernel, architecture, version,
  integrity metadata, and the x86_64 Limine configuration;
- `/usr/bin/narf-uefi` for ESP installation, verification, and removal; and
- `/etc/grub.d/42_narf` for GRUB on both firmware types.

The package hook copies the loader/NARF payload to `/EFI/NARF` on the mounted
EFI System Partition and writes a Boot Loader Specification Type #1 entry at
`/loader/entries/narf.conf`. When no existing Limine installation owns the
ESP-wide policy, it also writes the same marked configuration at
`/boot/limine/limine.conf`: Limine uses this documented fallback when GRUB's
`chainloader` cannot supply the EFI application's original file path. An
unrelated existing file at that location is never overwritten, and an
existing Limine EFI application suppresses the fallback so its primary menu
continues to own policy. UEFI GRUB chainloads the payload, systemd-boot
consumes the BLS entry, rEFInd discovers `narf.efi`, and CachyOS Limine is
registered through `limine-entry-tool` when it is present. Legacy-BIOS GRUB
still loads the kernel directly through Multiboot2. These slash-prefixed EFI
paths are relative to the ESP root, not necessarily the Linux host's `/`.

On x86_64 the loader is Limine and the package binds both its configuration and
kernel digest. On aarch64 it is NARF's EFI loader, with the exact kernel digest
bound into the PE/COFF image. The aarch64 loader checks that digest before it
parses the ELF. Signing either bound loader therefore authenticates the whole
loader-to-kernel chain.

When Limine's host utility is available, the builder uses its `enroll-config`
command and independently verifies the resulting embedded digest. Otherwise it
applies the same upstream marker format directly. `--limine-tool FILE` selects
a reviewed host utility explicitly.

The release workflow also publishes `narf-x86_64.iso` and
`narf-aarch64-uefi.img` plus SHA-256 sidecars after booting both through
OVMF/AAVMF. Distribution packages do not embed those media images or their
external initramfs; the installed kernel uses its built-in userspace.

Published media and native release packages are integrity-bound but unsigned:
the project does not possess an administrator's or distribution's private key.
Native packages can be signed during their build, or the installed loader can
be signed with an existing `sbctl` policy. See
[UEFI Secure Boot](../docs/SECURE_BOOT.md).

## Install and verify the UEFI payload

`narf-uefi` automatically recognizes a mounted FAT ESP at `/efi`, `/boot`, or
`/boot/efi`. A package install succeeds without modifying firmware state when
no ESP is mounted, so verify it before rebooting:

```sh
sudo narf-uefi status
```

For a nonstandard mount point, install explicitly and then regenerate a GRUB
configuration if GRUB is the active manager:

```sh
sudo narf-uefi install --esp /path/to/esp
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

For a machine whose Secure Boot keys are already managed by `sbctl`, opt into
local signing once. The helper remembers that policy and re-signs upgrades:

```sh
sudo narf-uefi install --sign-with-sbctl
sudo narf-uefi status
```

The helper never changes UEFI NVRAM or the firmware's default boot entry. It
adds only `/EFI/NARF`, its marked `/boot/limine/limine.conf` fallback, the
`narf.conf` BLS entry, its saved ESP path, and an optional CachyOS Limine menu
entry. `sudo narf-uefi remove` removes only files carrying NARF's marker or
known package paths, plus that registration. Native package removal invokes
the same operation; mount the recorded ESP before removing the package so it
can be cleaned.

Supported outputs:

- Debian and Ubuntu: `.deb`
- Fedora and other RPM distributions: `.rpm`
- Arch Linux: `.pkg.tar.zst`
- Gentoo: versioned source archive plus an overlay-ready `.ebuild`
- Distribution-independent: `.tar.gz`

## Cargo frontend

Developers working from a source checkout may install the optional Cargo
subcommand:

```sh
cargo install --path build/cargo-narf
cargo narf detect
cargo narf package --version 0.5.0 --formats auto
```

`auto` reads `/etc/os-release`. The wrapper locates the checkout and calls the
same reproducible `build-release.sh` path used by release CI; it does not carry
a second package implementation.

For a local installation, the explicit `install` command builds one native
artifact and delegates it to the host package manager. Point it at the
distribution's reviewed Limine EFI executable unless one of the automatic
locations described below already exists:

```sh
cargo narf install --version 0.5.0 \
  --limine-efi /usr/share/limine/BOOTX64.EFI
# Inspect the final privileged command without executing it:
cargo narf install --version 0.5.0 \
  --limine-efi /usr/share/limine/BOOTX64.EFI --dry-run
```

Debian-family systems use apt/dpkg, RPM-family systems use dnf/rpm, and Arch
systems use pacman. Gentoo remains generation-only because registering an
overlay is a separate administrator policy decision. The wrapper never copies
files into `/boot` itself: package ownership, upgrade ordering and removal stay
with the native distribution database. End users installing release `.deb`,
`.rpm`, or `.pkg.tar.zst` artifacts do not need Cargo or a Rust toolchain.

Build every format available on the current host. Supply the reviewed Limine
EFI executable explicitly, set `LIMINE_PATH` to its directory, or first build
an x86_64 image so the packager can reuse its loader:

```sh
packaging/build-release.sh --version 0.5.0 --formats all \
  --limine-efi /usr/share/limine/BOOTX64.EFI
# Equivalent Cargo frontend option:
cargo narf package --version 0.5.0 --formats all \
  --limine-efi /usr/share/limine/BOOTX64.EFI
```

For aarch64, `--arch aarch64` builds and binds NARF's own UEFI loader. An
already-built loader can be supplied explicitly:

```sh
cargo xtask image --arch=aarch64
cargo narf package --version 0.5.0 --arch aarch64 --formats all \
  --uefi-loader target/narf-uefi-aarch64/narf.efi
```

The x86_64 path builds `target/x86_64-unknown-none/release/narf-frame`; the
aarch64 path builds the canonical kernel, a stripped ESP copy, and the UEFI
loader. `--skip-build` requires those architecture-specific artifacts to exist.
Native package tools are intentionally used, so unavailable formats are
reported and skipped for `--formats all`; an explicitly requested unavailable
format is an error. Release outputs, `SHA256SUMS`, and `release-manifest.json`
land in `target/release-assets/<version>/`.

The x86_64 UEFI payload deliberately uses packaged Limine rather than asking
systemd-boot or UEFI GRUB to execute the Multiboot2 ELF directly. aarch64 uses
NARF's native UEFI loader because its kernel follows the Linux-compatible FDT
entry ABI rather than Multiboot2.

Distributions may pass `--secure-boot-key` and `--secure-boot-cert`; the builder
signs with `sbsign` and verifies the result with `sbverify`. Both arguments are
also available through `cargo narf package` and `cargo narf install`. Keys are
inputs only and are never copied into staging or release assets.

To test packaging without compiling the kernel, provide that canonical kernel
artifact and use `--skip-build`:

```sh
packaging/build-release.sh --version 0.5.0 --skip-build \
  --limine-efi /path/to/BOOTX64.EFI
```

## Tagging

`prepare-tag.sh 0.5.0` validates the version, clean tree, current branch, and
release commit. It prints the signed-tag command by default. A human maintainer
may pass `--create` to create the signed `v0.5.0` tag locally, then push it
after review. The tool never pushes and AI agents must never create or sign a
release tag.

The GitHub release workflow validates an existing signed `v*` tag,
boots the ISO through OVMF, rebuilds the publishable non-smoke ISO,
and builds packages in distribution containers. It uploads the ISO,
its checksum, and packages only after all jobs succeed.

The ordinary package test verifies the isolated ESP layout and native package
hooks on both architectures. `packaging/test-uefi-boot.sh` adds the end-to-end x86_64 acceptance
path: OVMF launches an installed-style GRUB build, the generated NARF stanza
chainloads the package's `/EFI/NARF/narf.efi`, Limine reads the adjacent
configuration or the package-managed ESP fallback, and the packaged kernel
must print its clean-exit marker with no panic. CI runs that gate after the
removable-media UEFI boot.

`packaging/test-aarch64-package-boot.sh` boots the native aarch64 package under
AAVMF and requires a one-byte kernel modification to be rejected.
`packaging/test-secure-boot.sh` enrolls an ephemeral certificate into a
disposable OVMF variable store, boots the signed x86_64 chain with Secure Boot
enforced, and likewise requires a tampered kernel to fail. CI retains none of
the generated private-key material.
