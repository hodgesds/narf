# NARF release packaging

`build-release.sh` turns the canonical kernel ELF and Limine's x86_64 EFI
application into installable distribution packages. Packages own these source
artifacts:

- `/boot/narf-kernel-<version>` for legacy-BIOS GRUB;
- `/usr/lib/narf/uefi/{narf.efi,narf-frame,version}` for UEFI installation;
- `/usr/bin/narf-uefi` for ESP installation, verification, and removal; and
- `/etc/grub.d/42_narf` for GRUB on both firmware types.

The package hook copies the Limine/NARF payload to `/EFI/NARF` on the mounted
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

The release workflow also publishes `narf-x86_64.iso` and its SHA-256
sidecar after booting the same image layout through OVMF. Distribution
packages do not embed that ISO or its external initramfs; the installed
kernel uses its built-in userspace.

The ISO uses the standard removable-media path
`EFI/BOOT/BOOTX64.EFI` through Limine. It currently requires Secure
Boot to be disabled; signed-loader/shim enrollment is not part of the
release process yet. The installed UEFI payload has the same limitation.

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

The script builds `target/x86_64-unknown-none/release/narf-frame` through
`cargo xtask build --arch=x86_64` unless `--skip-build` is passed.
Native package tools are intentionally used, so unavailable formats are
reported and skipped for `--formats all`; an explicitly requested unavailable
format is an error. Release outputs, `SHA256SUMS`, and `release-manifest.json`
land in `target/release-assets/<version>/`.

Native packages target x86_64. The UEFI payload deliberately uses a packaged
Limine application rather than asking systemd-boot or UEFI GRUB to execute the
Multiboot2 ELF directly. Native aarch64 packages and Secure Boot signing remain
separate work; the release continues to provide tested aarch64 UEFI media.

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
hooks. `packaging/test-uefi-boot.sh` adds the end-to-end x86_64 acceptance
path: OVMF launches an installed-style GRUB build, the generated NARF stanza
chainloads the package's `/EFI/NARF/narf.efi`, Limine reads the adjacent
configuration or the package-managed ESP fallback, and the packaged kernel
must print its clean-exit marker with no panic. CI runs that gate after the
removable-media UEFI boot.
