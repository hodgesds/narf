# NARF release packaging

The default x86_64 payload is a self-contained native NARF EFI application.
`cargo xtask efi-image` builds it without Limine; `cargo narf package` and
`cargo narf install` use that same build path. See [native EFI](../docs/NATIVE_UEFI.md)
for source builds, firmware selection, encrypted root, and manual installation.

Packages own `/boot/narf-kernel-<version>` (including the legacy-BIOS GRUB
copy), `/usr/lib/narf/uefi/` (EFI image, matching extracted kernel, version,
architecture, hashes and bundle manifest), `/usr/bin/narf-uefi`, and
`/etc/grub.d/42_narf`. The x86 EFI image embeds the exact stripped kernel,
CPIO archive, and command line in a versioned `.narf` section. The builder and
installer verify all three SHA-256 hashes; `native-efi.py` can inspect/extract
that section without executing the image. A PE signature authenticates the
complete embedded boot configuration.

The install hook publishes `/EFI/NARF/narf.efi` on the mounted ESP and a
Type #1 `/loader/entries/narf.conf` entry. UEFI GRUB chainloads that image,
systemd-boot consumes the BLS entry, rEFInd discovers it, and an installed
CachyOS Limine manager can chainload it through `limine-entry-tool`. No kernel,
archive, or Limine configuration sidecars are needed on the x86 ESP. These
paths are relative to the ESP, not necessarily the host root. BIOS GRUB keeps
its Multiboot2 path. aarch64 retains its existing separate, digest-bound kernel
and NARF EFI loader.

`--limine-efi FILE` explicitly selects legacy x86 packaging, with the existing
config/kernel digest binding. Only that layout installs `limine.conf` and its
marked GRUB fallback. Native upgrades remove those obsolete managed sidecars
after publishing the complete new image; unrelated host files are preserved.
An adopted host Multiboot entry must be migrated explicitly as described below.
Existing ISO, GRUB-image, and USB-image commands retain their layouts.

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
adds `/EFI/NARF`, the legacy-only marked `/boot/limine/limine.conf` fallback, the
`narf.conf` BLS entry, its saved ESP path, and an optional CachyOS Limine menu
entry. `sudo narf-uefi remove` removes only files carrying NARF's marker or
known package paths, plus that registration. Native package removal invokes
the same operation; mount the recorded ESP before removing the package so it
can be cleaned.

With explicit legacy Limine packages, an existing NARF hardware-test entry can still load `boot():/boot/narf-frame`
from an older `grub-image` bundle. Package installation normally updates
`/EFI/NARF/narf-frame`, so that older entry otherwise keeps booting its previous
kernel. Adopt its existing menu explicitly:

```sh
sudo narf-uefi install --esp /boot/efi \
  --limine-config /boot/efi/boot/limine/limine.conf
sudo narf-uefi status --esp /boot/efi
```

The config must be on the selected ESP and contain exactly one NARF
Multiboot2 entry using `boot():/boot/narf-frame` or
`boot():/EFI/NARF/narf-frame`. The helper copies the packaged kernel to that
entry's existing location and saves the config path for subsequent upgrades.
It preserves the menu, root policy, command line, firmware initramfs, and EFI
application. Before replacing a legacy kernel, it saves the original at
`/var/lib/narf/limine-kernel-before-package` on the host root. Kernel updates
are staged one at a time so they fit alongside the firmware initramfs on a
512-MiB ESP. Status also checks the selected kernel
against the package; a stale or moved entry fails verification. An entry with
a kernel digest must already name the packaged digest. Removal keeps the
pre-existing menu, legacy kernel, and backup, and forgets the adoption state.

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

For a local installation, build one native artifact and delegate installation
to the host package manager:

```sh
cargo narf install --version 0.5.0
# Inspect the final privileged command without executing it:
cargo narf install --version 0.5.0 --dry-run
# Embed an installed-root policy in the image being packaged:
cargo narf package --version 0.5.0 --formats tar \
  --cmdline 'root=UUID=YOUR-ROOT-UUID narf.disks=root-ro'
```

`--cmdline` and `--initramfs` apply to a new native x86 build and cannot be
combined with `--skip-build`. With `--skip-build`, `--uefi-loader FILE` selects
an already complete native image; the kernel is extracted from it, preventing
packaging a stale or different kernel sidecar.

Debian-family systems use apt/dpkg, RPM-family systems use dnf/rpm, and Arch
systems use pacman. Gentoo remains generation-only because registering an
overlay is a separate administrator policy decision. The wrapper never copies
files into `/boot` itself: package ownership, upgrade ordering and removal stay
with the native distribution database. End users installing release `.deb`,
`.rpm`, or `.pkg.tar.zst` artifacts do not need Cargo or a Rust toolchain.

Build every format available on the current host:

```sh
packaging/build-release.sh --version 0.5.0 --formats all
cargo narf package --version 0.5.0 --formats all
```

For aarch64, `--arch aarch64` builds and binds NARF's own UEFI loader. An
already-built loader can be supplied explicitly:

```sh
cargo xtask image --arch=aarch64
cargo narf package --version 0.5.0 --arch aarch64 --formats all \
  --uefi-loader target/narf-uefi-aarch64/narf.efi
```

The x86_64 path builds `target/narf-x86_64.efi`; aarch64 builds its canonical
kernel, stripped ESP copy, and separate loader. `--skip-build` requires those
architecture-specific artifacts. Unavailable formats are skipped with `all`;
an explicitly requested unavailable format is an error. Outputs, `SHA256SUMS`,
and `release-manifest.json` land in `target/release-assets/<version>/`.

To migrate a saved host Limine adoption, first rebuild a native image containing
the old entry's root policy and selected firmware. Change that NARF menu entry
to an EFI chainload of `/EFI/NARF/narf.efi`; retain any fallback entry needed
for recovery. Then remove only `/var/lib/narf/limine-config` (the adoption
record), install the native package, and run `narf-uefi status`. The installer
refuses to discard this record automatically because an older external command
line or firmware archive cannot be inferred from the new embedded policy.

Distributions may pass `--secure-boot-key` and `--secure-boot-cert`; the builder
signs with `sbsign` and verifies the result with `sbverify`. Both arguments are
also available through `cargo narf package` and `cargo narf install`. Keys are
inputs only and are never copied into staging or release assets.

To package an existing complete image without compiling:

```sh
packaging/build-release.sh --version 0.5.0 --skip-build \
  --uefi-loader target/narf-x86_64.efi
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

## Crate version pull requests

Crate versions are independent from the kernel/package release version. A
crate opts into automated version preparation only when its manifest has both
an explicit version and:

```toml
[package.metadata.narf]
release-managed = true
```

Workspace-inherited versions are intentionally ignored. Prepare one or more
point releases locally with:

```sh
cargo xtask crate-release bump --package narf-tpm --package narf-i3c
cargo xtask crate-release check --package narf-tpm --package narf-i3c
```

Use `--set narf-tpm=0.2.0` when an exact non-patch version is required. The
bump updates registry requirements for internal path dependencies and may add
a release-managed dependent only if its existing requirement no longer accepts
the new version. It does not commit, tag, push, or publish.

The `Crate version pull request` workflow exposes the same package and exact
version selections through manual dispatch. Its monthly run uses publication
tags named `crate/NAME/vVERSION` and opens a PR only for crates with owned-file
changes since that tag. A crate with no matching tag is skipped, which keeps
unpublished crates held back while desktop support is still incomplete. Set
the repository variable `NARF_MONTHLY_CRATE_BUMPS=true` only when periodic PRs
should begin. The workflow deliberately has no crates.io token and cannot
publish; publication will be a separate maintainer-approved gate. After it
opens the PR, it explicitly dispatches the normal CI workflow on the new head
because GitHub suppresses recursive pull-request events from `GITHUB_TOKEN`.

The separate `Distribution packaging readiness` workflow builds both kernel
architectures each week, then constructs packages in Debian, Ubuntu, Fedora,
Arch, and Gentoo containers. Native x86_64 packages are installed, queried,
and removed inside their disposable container; cross-architecture and Gentoo
outputs receive structural checks. It uploads short-lived Actions artifacts,
not release assets. Manual dispatch is always available. Scheduled runs remain
dormant until `NARF_DISTRO_READINESS=true`, so the matrix can be enabled after
the remaining distro fixes land without changing the workflow again.

The ordinary package test verifies the isolated ESP layout and native package
hooks on both architectures. `packaging/test-uefi-boot.sh` adds the end-to-end x86_64 acceptance
path: OVMF launches an installed-style GRUB build, the generated NARF stanza
chainloads the package's self-contained `/EFI/NARF/narf.efi`, and the embedded kernel
must print its clean-exit marker with no panic. CI runs that gate after the
removable-media UEFI boot.

`packaging/test-aarch64-package-boot.sh` boots the native aarch64 package under
AAVMF and requires a one-byte kernel modification to be rejected.
`packaging/test-secure-boot.sh` enrolls an ephemeral certificate into a
disposable OVMF variable store, boots the signed x86_64 chain with Secure Boot
enforced, and requires firmware authentication rejection of unsigned images and
separate kernel, initramfs, and command-line modifications. A timeout alone is
not a passing rejection. Logs and a JSON report remain under
`target/secure-boot-native/`; ephemeral private keys are removed. Use
`packaging/test-secure-boot.sh --limine` for the legacy binding gate.
`packaging/test-native-luks.py` boots real cryptsetup-generated LUKS1/LUKS2
regular-file fixtures, including serial unlock/retry/cancel/timeout; see the
native EFI guide for invocation and physical-machine acceptance.
