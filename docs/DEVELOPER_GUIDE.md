# Developer guide

This guide is the short, current route from a fresh checkout to a reviewed
NARF change. See [Running on Linux](RUNNING_ON_LINUX.md) for a longer QEMU
walkthrough and [TESTING.md](../TESTING.md) for the complete test surface.

## Set up the checkout

NARF pins Rust in [`rust-toolchain.toml`](../rust-toolchain.toml), including
`rust-src`, `llvm-tools`, `clippy`, and `rustfmt`. Let `rustup` select that
toolchain; do not add an arbitrary `+nightly` override.

The common Ubuntu host dependencies are QEMU for both architectures, OVMF and
AAVMF firmware, FAT/ISO and filesystem utilities, plus the C toolchains used by
Linux-compatibility fixtures:

```sh
sudo apt-get install qemu-system-x86 qemu-system-arm qemu-efi-aarch64 \
  ovmf cpio mtools dosfstools e2fsprogs xorriso \
  musl-tools clang lld linux-libc-dev
```

Not every package is needed for a kernel-only build. The detailed purpose of
each dependency is in [Running on Linux](RUNNING_ON_LINUX.md#1-prerequisites).

## Build, boot, and test

The `xtask` command is the supported front end. Optimized (`release`) builds
are the default; pass `--debug` when debug assertions or debug symbols matter.

```sh
cargo xtask build --arch=x86_64
cargo xtask build --arch=aarch64
cargo xtask run --arch=x86_64
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
```

Use `--features a,b`, `--hw-profile full|minimal|virtio-only|legacy-only`, and
`--package <crate>` where appropriate. `--kasan` is x86_64-only. The
interactive Linux userspace and network/application smokes are currently
x86_64-only:

```sh
cargo xtask run-interactive --arch=x86_64 \
  --cmd "echo hello world" --expect "hello world"
cargo xtask net-smoke --arch=x86_64
```

For a faster focused cycle, kernel test names are prefix-filtered:

```sh
cargo xtask test --arch=x86_64 --subsystem net --kernel-tests-only
```

Before review, run the checks relevant to the changed crates and both kernel
targets. The repository-wide baseline is:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo xtask host-test
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
git diff --check
```

Some target-specific crates need `--target x86_64-unknown-none` or
`aarch64-unknown-none` when invoked directly. Prefer `cargo xtask` for kernel
builds and tests because it supplies the build-std flags and linker settings.

## Navigate the workspace

The root `Cargo.toml` is a single workspace. Kernel mechanism is split into
small `no_std` crates: `frame/`, `memory/`, `scheduler/`, `capabilities/`,
`ipc/`, `io/`, `net/`, `filesystem/`, `userspace/`, and the driver crates under
`drivers/`. `build/xtask/` owns build and QEMU orchestration. Consult the repo
map in [AGENTS.md](../AGENTS.md) and the current progress in
[STATUS.md](../STATUS.md).

Subsystem contracts normally live in `<subsystem>/specification/spec.md`;
where a directory instead names a canonical design document, follow its
README. Read the owning contract before changing the subsystem. An interface
change must update section 3 of the specification in the same change. TCB
files have the higher review and safety-argument rules in the
[process specification](../process/specification/spec.md).

## Add or extend a subsystem or driver

Start at the [extension guide](extending/README.md). It links the actual traits
and registration hooks for filesystems, memory, scheduling, IPC,
capabilities, syscalls, buses, and device classes. Use an existing small
driver as the structural reference and add tests at the lowest useful layer,
then an in-kernel smoke for cross-crate or hardware-facing behavior.

Built-in drivers are ordinary workspace dependencies. They register their
initcalls and bus matches during boot and may use the kernel's Rust crate APIs.
The kernel-side aggregator still has to retain the crate so its registration
code is linked. Runtime-loadable drivers instead use the deliberately small C
module ABI described below; a loadable object cannot link Rust kernel crates.

## Build a runtime module

The canonical instructions are [Writing a NARF kernel module](../modules/MODULE_AUTHORING.md)
and the [module design](../modules/DESIGN.md). The shorter
[runtime-module guide](extending/modules.md) explains the operational flow.

A standalone module is a `#![no_std]` Cargo crate built as a `staticlib`, with
`narf_module_init` and optionally `narf_module_exit`. It declares the primitive
`extern "C"` KSYMTAB functions it calls and must not depend on kernel crates.
Rust layouts and trait objects are not a stable cross-build ABI.

A dual-build driver keeps the kernel dependencies optional:

```toml
[features]
default = ["builtin"]
builtin = ["dep:narf-net", "dep:narf-bus"]
module = []
```

The built-in configuration can assign its isolation domain as a compile-time
constant. The module configuration drops the default feature and has its
domain chosen by the loader:

```sh
cat /sys/kernel/abi_hash
cargo xtask build-module --package narf-drivers-net-e1000 \
  --no-default-features --features module \
  --arch x86_64 --kernel-abi 0x1f3a90c2
```

`drivers/net/e1000/` is the current reference dual-build consumer. Its
built-in path uses `DomainId::DRIVER_0`; its `.ko` manifest defaults to
`target_domain=net`, which an authorized loader may override with, for
example, `domain=driver3`.

The module manifest declares identity, ABI hash, dependencies, required
capabilities, and the default target domain. Build-time `.narf_kparams` entries
are exposed under `/sys/module/<name>/parameters/`. Dependencies must already
be loaded; NARF does not currently autoload them. Production module images
must be signed after their final raw or compressed bytes are built. Never ship
the developer-only `module-allow-unsigned` feature.

## Keep evidence with the change

Tests and documentation should establish the claim being changed. Do not
report performance from a single run: use the sample size, confidence
intervals, and statistical gates in
[verification/specification/spec.md](../verification/specification/spec.md).
For Linux ABI work, update the appropriate executable smoke and keep
[Linux compatibility](LINUX_COMPAT.md) consistent with the implementation.
