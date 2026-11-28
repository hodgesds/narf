# build/cargo-narf — `cargo narf` frontend

`cargo narf` (cargo alias `narf`, binary `cargo-narf`) is the single
developer frontend for NARF: the build / run / test orchestrator and the
native distribution packager in one crate. The developer commands nest
under groups — `build`, `test`, `run`, `smoke`, `bench`, `firmware`,
`pkg`, `ci`, `disk` — so the build is `cargo narf build build`, the QEMU
test suite is `cargo narf test test`, and native packaging is
`cargo narf pkg package`. The old flat `cargo xtask <command>` alias keeps
working as a deprecated shim: it prints a notice and forwards to the
nested form.

`cargo narf build efi-image` builds an opt-in, self-contained x86_64 EFI application
at `target/narf-x86_64.efi`. `--run` boots it through OVMF; `--smoke` builds a
separate smoke image and requires the kernel's clean shutdown. It needs no
Limine or ISO/FAT image utilities. See [native EFI](../../docs/NATIVE_UEFI.md)
for building, configuration, installation, and current limits. Existing
`image`, `iso-boot`, and package commands retain their previous behavior.

`cargo narf` is the primary developer entrypoint for NARF. It is a
workspace-local binary invoked as `cargo narf <group> <command>`, and it owns
everything between a source checkout and a kernel running under QEMU or
on real hardware: cross-compilation, QEMU boot, the test gates, bootable
media, firmware staging, and the performance benchmarks. Treating the
build pipeline as a Rust program rather than a web of shell scripts keeps
the cross-compilation flags, linker-script selection, QEMU topology, and
serial-marker parsing in one typed, reviewable place.

## What it does

Commands nest under groups: `build` is `cargo narf build build`,
`host-test` is `cargo narf test host-test`, `package` is
`cargo narf pkg package`. The leaf names below are the group members.

The command surface groups into a few concerns:

**Build and boot.** `build` cross-compiles the kernel for a chosen
architecture (`x86_64`, `aarch64`); `run` builds and boots it under QEMU;
`image` and `iso-boot` produce bootable UEFI media and boot it under
OVMF/AAVMF. `demo` boots graphically with the user-mode testbin.

An x86_64 QEMU boot can attach host PCI functions directly through VFIO:

```sh
cargo narf run run --arch=x86_64 \
  --passthrough-device 03:00.0 \
  --passthrough-device 03:00.1
```

The option is repeatable so a multifunction device (typically a GPU plus its
HD-audio function) can be assigned together. Before QEMU starts, cargo narf runs
the same KVM, IOMMU-group, `vfio-pci`, and BAR-window checks exposed by
`cargo narf run passthrough -d 03:00.0 -d 03:00.1`. It does not detach a device
from its Linux driver; host binding remains an explicit administrator action.
The BDF becomes a QEMU `vfio-pci,host=` device, after which NARF discovers it
through its ordinary PCIe enumeration path.

**Test gates.** `host-test` is the fast, hardware-independent unit-test
gate — it deliberately runs an allowlist of crates that need neither the
kernel linker script, privileged instructions, nor QEMU. `test` boots
under QEMU and runs the in-kernel test suite (the one built on
`verification/kernel-test`), optionally narrowed to a single subsystem.
`boot-smoke` performs a real init pass with no test feature and parses
serial output for panic and success markers, catching full-boot
regressions that isolated smokes miss. `run-interactive` drives the
serial port programmatically to prove the keystroke-to-UART interactive
loop, and `musl-demo` verifies the linux-compat demo binaries boot and
run through the real shell, execve, and ELF loader. Set
`XTASK_QEMU_SERIAL_TEE=1` to mirror captured kernel-test and boot-smoke serial
to stdout in real time; CI enables it so long guest phases remain observable.

**Change-based CI.** `affected` parses `cargo metadata` to build the
workspace reverse-dependency closure and, from a git diff against a base
ref, computes exactly which CI jobs and kernel-test subsystems a change
can touch — emitting JSON or GitHub Actions outputs. Hub-crate,
build-infrastructure, or unknown-path changes (and push-to-main / nightly
events) force a full run. Its pure core is unit-tested.

**Networking and server smokes.** `net-smoke`, `e1000-module-net-smoke`, and
`redis-smoke` boot with
QEMU user-networking and a host-forwarded port, then open a real TCP
socket *from the host* to a guest server (NARF's `netserve`, or an
unmodified `redis-server`) and round-trip traffic — proving a guest
daemon is reachable off-box. Both network-stack smokes check TCP, UDP, and a
guest DNS query through SLIRP. The e1000 variant additionally builds and
ABI-stamps `e1000.ko`, autoloads it in an operator-selected driver frame before
PCI probing, disables the built-in e1000 claimant for that boot, and requires
the module-owned NIC to carry every live exchange. `systemd-pid1` boots a
mounted distro rootfs's `/lib/systemd/systemd` as real PID 1 with the
QEMU user-network configuration, optionally asserting the network works
end-to-end through SLIRP.

**Benchmarks.** `redis-bench`, `stress-bench`, `mt-echo-bench`, and
`bpf-bench` measure NARF against a Linux baseline under an identical QEMU
configuration. These gate nothing and assert nothing; they answer "where
does NARF stand" and "what does this cost." The benchmark statistics
(median, bootstrap CIs, Welch's t and Mann-Whitney U, Benjamini-Hochberg
correction — the `verification/` §8 protocol) live in a unit-tested
module so a wrong distribution tail can't silently invalidate every
number.

**Modules.** `build-module` cross-compiles a kernel-module crate (such as
`modules/test-module`) into a single relocatable object — NARF's
equivalent of a `.ko` — and `attach-module-signature` appends a verified
Ed25519 trailer to a built module image. The e1000 module smoke derives the
running kernel ABI hash from the canonical `kernel_abi!` declaration with
Rust's own token stringification before staging the image.

**External composition.** The common build arguments accept
`--composition FILE`, repeatable `--builtin-crate MANIFEST`, and repeatable
`--module-crate MANIFEST`. A composition resolves crates from any Cargo
workspace, generates a frame manifest/registrar below `target/` for built-ins,
and builds, ABI-stamps, stages, and autoloads `.ko` components. No external or
NARF source manifest is rewritten. `build-module --manifest-path FILE`
provides the lower-level out-of-tree module path. The full schema is in
[`docs/extending/composition.md`](../../docs/extending/composition.md).

**Firmware.** `pack-firmware` wraps a raw firmware payload in the NARF
trailer (optionally with a detached Ed25519 signature), and
`import-firmware` bulk-imports a firmware tree, decompressing Arch's
zstd-shipped blobs on the fly. `image` then splits staged firmware
between the initramfs CPIO and the root partition's `/lib/firmware/`,
mirroring Linux's hybrid model.

**Media and KASLR.** `disk-write` and `disk-write-partitioned` burn a USB
stick (the partitioned variant lays out a GPT with a FAT32 ESP and a
labelled ext4 root). `relocs` extracts the kernel's relocation table and
reports what a boot-time KASLR slide would have to patch.

`grub-image --arch=x86_64` produces `target/grub-x86_64/`: a direct-GRUB
Multiboot2 kernel, its initramfs, and a `grub.cfg` stanza. It retains NARF's
compact loadable KASLR table while removing the non-loadable linker
relocation sections that GRUB refuses. On BIOS, copy `boot/` into the host's
`/boot` and GRUB loads that artifact directly. On x86_64 UEFI, copy `esp/` to
the root of the ESP as well: the generated stanza chainloads the bundled
Limine EFI app, which loads the canonical kernel and initramfs from that ESP.
The EFI app must be trusted by the active Secure Boot policy (or Secure Boot
must be disabled); `grub-image` does not sign it.

The aarch64 image path binds the exact stripped kernel's BLAKE2b-512 digest
into `BOOTAA64.EFI`. The loader fails closed while that placeholder is unbound
and verifies the full kernel before parsing any ELF header. Native package
signing and local `sbctl` policy are documented in
[`docs/SECURE_BOOT.md`](../../docs/SECURE_BOOT.md).

## Native packaging (`pkg` group)

`cargo narf pkg package` drives reproducible native package generation
(`.deb`, `.rpm`, Arch, Gentoo, or tarball) from a built kernel;
`cargo narf pkg install` hands the resulting artifact to the host's native
package tool (apt/dpkg, dnf/rpm, or pacman) rather than writing `/boot` or
the ESP directly; `cargo narf pkg detect` reads `os-release` to report
which package format the current host wants. The `auto` format resolves to
the host's native format so the same invocation produces the right
artifact on each distro, and a reproducible-build timestamp can be pinned
so artifacts are byte-stable.

This crate is deliberately thin: it shells out to the real build (or
packages an already-built canonical kernel artifact) and to the system
package manager rather than reimplementing either. The packaging half is
not part of the inner development loop — day-to-day work goes through the
`build` / `test` / `run` groups — and exists so NARF can be delivered
through the same channels a distribution kernel would be.

## Relationships

`cargo narf` sits above essentially every other workspace crate: it is how the
kernel, the modules, the userspace runtimes, and the verification harness
are built and exercised. `test` drives the suite registered through
`verification/kernel-test`; `build-module` is what turns
`modules/test-module` into a loadable object; the firmware commands
produce the NRFW blobs the kernel's firmware subsystem consumes.

- Spec: [`build/specification/spec.md`](../specification/spec.md)

The native EFI QEMU launcher accepts `--root-image FILE` with `--run` or
`--smoke`, attaching a regular raw image through modern virtio-blk and a
disposable snapshot. Snapshot scratch storage remains under the staging
folder. See the native EFI guide for serial LUKS policy and fixture tests.
