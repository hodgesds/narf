# Building and loading runtime modules

NARF has two distinct driver integration paths. A **built-in** driver is a
normal workspace crate linked into the kernel and can use Rust kernel APIs. A
runtime **module** is a separately compiled relocatable ELF object (`.ko`) and
can call only the curated kernel symbol table. The canonical and complete
references are [MODULE_AUTHORING.md](../../modules/MODULE_AUTHORING.md), the
[module design](../../modules/DESIGN.md), and the owning subsystem
specifications linked from those documents.

## Crate and feature shape

A module-only crate is `#![no_std]`, produces a `staticlib`, exports
`narf_module_init` and optionally `narf_module_exit`, and declares the kernel
functions it uses in `unsafe extern "C"` blocks. It must not depend on kernel
crates: that would compile another copy of kernel state into the object.

A driver that also builds into the kernel uses mutually exclusive Cargo
configurations. Keep every real kernel dependency optional and activate it
only from the default `builtin` feature. The `module` feature must leave those
dependencies out of the graph:

```toml
[features]
default = ["builtin"]
builtin = ["dep:narf-bus", "dep:narf-net"]
module = []

[dependencies]
narf-bus = { path = "../../../bus", optional = true }
narf-net = { path = "../../../net", optional = true }
```

Small proc-macro/declarative-macro dependencies are possible only when they
contribute no runtime object code. `drivers/net/e1000/` is the reference: its
built-in configuration uses the full Rust PCI/DMA/network path, while the
module configuration uses the copy-mode C KABI.

## Build both forms

The ordinary workspace build selects `builtin` and links the driver into the
kernel. Its isolation domain is a compile-time constant (e1000 currently uses
`DomainId::DRIVER_0`). Build the loadable form by dropping defaults:

```sh
cat /sys/kernel/abi_hash
cargo xtask build-module --package narf-drivers-net-e1000 \
  --no-default-features --features module \
  --arch x86_64 --kernel-abi 0x1f3a90c2
```

`build-module` forces a `staticlib`, extracts that crate's object members, and
links them into one relocatable object. It works for x86_64 and aarch64. The
ABI hash is derived from the target kernel's export table, so it must come from
that kernel rather than being guessed when the crate is written.

An out-of-tree crate is accepted directly:

```sh
cargo xtask build-module --manifest-path ../acme/Cargo.toml \
  --package acme-driver --no-default-features --features module \
  --arch x86_64 --kernel-abi 0x1f3a90c2
```

For a complete image, [external composition](composition.md) performs the
kernel build, ABI stamp, module build, initramfs staging, and boot arguments as
one operation without adding either crate to the NARF workspace.

## Manifest, parameters, and dependencies

The `.modinfo` manifest names the module and may declare `version`, `license`,
`author`, `description`, `depends`, `required_caps`, `target_domain`, and
`kernel_abi`. The loader enforces the ABI hash, checks that dependencies are
already loaded, and refuses cap-gated imports that were not declared in
`required_caps`. It records dependency references so a live provider cannot
be unloaded. It does not autoload dependencies.

Initial string parameters can be embedded in `.narf_kparams` and appear under
`/sys/module/<name>/parameters/`. The syscall boundary accepts a Linux-shaped
load-argument string, but the loader currently consumes only the special
`domain=<name>` placement override; other words are ignored. Do not promise
module-specific runtime parsing without a corresponding KABI or loader change.

`target_domain=net` is e1000's author default. An authorized runtime load may
override it with names such as `domain=driver3` or `domain=scratch`; a module
can never select `FRAME`. A built-in driver's static domain is not affected by
load parameters.

## Stable ABI rule

Rust has no stable binary ABI. Module exports therefore use `extern "C"` with
integer/pointer primitives and explicitly `repr(C)` records only. Do not pass
Rust trait objects, references whose validity is not bounded by the call, or
`repr(Rust)` structures across the boundary. Per-symbol signature CRCs and the
whole export-table hash detect mismatches, but they do not make an unstable
layout safe.

The current device subset includes PCI enable/registration, bounded BAR MMIO,
coherent DMA via opaque handles, MSI-X/deferred callbacks, responsive waits,
pollers, and copy-mode network registration/RX. E1000 is the current reference
consumer. Consult `modules/src/kabi.rs` and the canonical authoring guide for
the exact exported symbols; do not infer an export from an internal Rust API.

## Sign, compress, load, and unload

`--compress` writes a bounded LZ4 `.ko.lz4` envelope. Production kernels embed
trusted Ed25519 public keys from the absolute build-time
`NARF_MODULE_TRUSTED_KEYS` path. Sign the exact final raw or compressed bytes,
then attach the signature:

```sh
cargo xtask build-module --package <crate> --arch x86_64 \
  --kernel-abi 0x1f3a90c2 --compress --out module.ko.lz4
cargo xtask attach-module-signature --module module.ko.lz4 \
  --signature module.sig --public-key module.pub
```

The first command can also take `--signature` and `--public-key` together.
Unsigned modules require the explicit developer/CI
`module-allow-unsigned` kernel feature.

Userspace loads memory images through `init_module`, file-descriptor images
through `finit_module`, and unloads through `delete_module`. These operations
require module authority. Live modules appear in `/proc/modules` and
`/sys/module/<name>/`; unload is refused while reference or dependency pins
remain. There is no complete `modprobe`-style dependency/alias manager yet,
and the current lack of a full SMP text-unmap grace period makes production
unload experimental. See the design document's live limitations before
depending on unload in an availability-sensitive system.

Boot-time loading is available for drivers that must register a match before
the ordinary device probe. Put ABI-stamped images in the initramfs and select
them from the trusted kernel command line:

```text
modules_load=lib/modules/e1000.ko modules_domain=driver2
```

Paths are comma-separated. The optional domain is an operator override applied
to each listed image; normal signature, ABI, dependency, capability, and
non-`FRAME` placement checks still run. This is an explicit image list, not a
dependency or PCI-alias autoloader.

When listed modules need different placements, use
`modules_domains=path=domain,...`; a matching path overrides the global
`modules_domain` fallback.
