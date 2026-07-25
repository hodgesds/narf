# NARF release packaging

`build-release.sh` turns the canonical kernel ELF into installable
distribution packages. Packages install `/boot/narf-frame-<version>` and a
GRUB generator at `/etc/grub.d/42_narf`. The generator uses GRUB's
`multiboot2` command, matching the header already emitted by
`frame/src/x86_64/boot.S`.

The ISO and its external initramfs are not packaged; they remain test artifacts
produced by `xtask image`. The installed kernel uses its built-in userspace.

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

The GitHub release workflow validates an existing signed `v*` tag and builds
packages in distribution containers. It uploads artifacts to the GitHub
release only after all packaging jobs succeed.
