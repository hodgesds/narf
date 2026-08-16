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

## Cargo frontend

Developers working from a source checkout may install the optional Cargo
subcommand:

```sh
cargo install cargo-narf
cargo narf detect
cargo narf package --version 0.1.0 --formats auto
```

`auto` reads `/etc/os-release`. The wrapper locates the checkout and calls the
same reproducible `build-release.sh` path used by release CI; it does not carry
a second package implementation. Run it inside a NARF checkout or pass
`--repo /path/to/narf` explicitly.

For a local installation, the explicit `install` command builds one native
artifact and delegates it to the host package manager:

```sh
cargo narf install --version 0.1.0
# Inspect the final privileged command without executing it:
cargo narf install --version 0.1.0 --dry-run
```

Debian-family systems use apt/dpkg, RPM-family systems use dnf/rpm, and Arch
systems use pacman. Gentoo remains generation-only because registering an
overlay is a separate administrator policy decision. The wrapper never copies
files into `/boot` itself: package ownership, upgrade ordering and removal stay
with the native distribution database. End users installing release `.deb`,
`.rpm`, or `.pkg.tar.zst` artifacts do not need Cargo or a Rust toolchain.

## Crates.io SDK release

Reusable workspace components and `cargo-narf` are published at one
synchronized version so custom kernels can consume a coherent dependency graph.
In-tree manifests retain `path` dependencies for development and also specify
the matching registry version used outside the repository. The separately
rooted `narf-libc` is injected into the release graph after
`narf-user-runtime`; repository-only `xtask` and validation/boot helpers remain
private.

Inspect the deterministic dependency order or package-check the complete
release without uploading:

```sh
packaging/publish-crates.sh --version 0.1.0 --plan
packaging/publish-crates.sh --version 0.1.0 --check
```

The release workflow runs the same preflight and invokes `--execute` only from
the matching clean, annotated, maintainer-signed tag. It requires the scoped
`CRATES_IO_TOKEN` repository secret. Uploads are dependency ordered and
resumable: an exact crate version already visible on crates.io is skipped. A
human maintainer must create and sign the release tag; AI agents may not do so.

Build every format available on the current host:

```sh
packaging/build-release.sh --version 0.1.0 --formats all
```

The script builds `target/x86_64-unknown-none/release/narf-frame` through
`cargo xtask build --arch=x86_64` unless `--skip-build` is passed.
Native package tools are intentionally used, so unavailable formats are
reported and skipped for `--formats all`; an explicitly requested unavailable
format is an error. Release outputs, `SHA256SUMS`, and `release-manifest.json`
land in `target/release-assets/<version>/`.

Current native packages target x86_64 GRUB and its `multiboot2` command. A
systemd `kernel-install`/Boot Loader Specification path needs a versioned NARF
UEFI executable because systemd-boot cannot directly launch a Multiboot2 ELF;
that work is intentionally not hidden behind the Cargo frontend.

To test packaging without compiling the kernel, provide that canonical kernel
artifact and use `--skip-build`:

```sh
packaging/build-release.sh --version 0.1.0 --skip-build
```

## Tagging

`prepare-tag.sh 0.1.0` validates the version, clean tree, current branch, and
release commit. It prints the signed-tag command by default. A human maintainer
may pass `--create` to create the signed `v0.1.0` tag locally, then push it
after review. The tool never pushes and AI agents must never create or sign a
release tag.

The GitHub release workflow validates an existing signed `v*` tag,
boots the ISO through OVMF, rebuilds the publishable non-smoke ISO,
and builds packages in distribution containers. It uploads the ISO,
its checksum, and packages only after all jobs succeed.
