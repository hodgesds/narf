# NARF release packaging

`build-release.sh` turns the canonical kernel ELF into installable
distribution packages. Packages install `/boot/narf-kernel-<version>` and a
GRUB generator at `/etc/grub.d/42_narf`. The generator uses GRUB's
`multiboot2` command, matching the header already emitted by
`frame/src/x86_64/boot.S`.

The release workflow also publishes `narf-x86_64.iso` and its SHA-256
sidecar after booting the same image layout through OVMF. Distribution
packages do not embed that ISO or its external initramfs; the installed
kernel uses its built-in userspace.

The ISO uses the standard removable-media path
`EFI/BOOT/BOOTX64.EFI` through Limine. It currently requires Secure
Boot to be disabled; signed-loader/shim enrollment is not part of the
release process yet.

Supported outputs:

- Debian and Ubuntu: `.deb`
- Fedora and other RPM distributions: `.rpm`
- Arch Linux: `.pkg.tar.zst`
- Gentoo: versioned source archive plus an overlay-ready `.ebuild`
- Distribution-independent: `.tar.gz`

Build every format available on the current host:

```sh
packaging/build-release.sh --version 0.5.0 --formats all
```

The script builds `target/x86_64-unknown-none/release/narf-frame` through
`cargo xtask build --arch=x86_64` unless `--skip-build` is passed.
Native package tools are intentionally used, so unavailable formats are
reported and skipped for `--formats all`; an explicitly requested unavailable
format is an error. Release outputs, `SHA256SUMS`, and `release-manifest.json`
land in `target/release-assets/<version>/`.

To test packaging without compiling the kernel, provide that canonical kernel
artifact and use `--skip-build`:

```sh
packaging/build-release.sh --version 0.5.0 --skip-build
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
