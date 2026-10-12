# narf-modules

Runtime-loadable kernel module subsystem for NARF.

This crate provides:

  * ELF64 parsing for relocatable kernel-module objects.
  * Per-arch relocation (x86_64 + aarch64).
  * Manifest parser (`.modinfo` k=v).
  * Kernel symbol table with cap-typed exports + per-symbol CRC.
  * A curated `extern "C"` ABI surface modules may call (`kabi.rs`).
  * aarch64 PLT veneers for calls beyond `CALL26`'s ±128 MiB (`plt.rs`).
  * Module-state machine, reference counting, and link-time pinning of
    every module a load resolves symbols from.
  * `/proc/modules` and `/sys/module/<name>/` adapters.
  * `init_module` / `finit_module` / `delete_module` syscall bodies.
  * Ed25519-over-BLAKE3 signatures with a build-time trusted-key store.
  * Bounded LZ4 module envelopes, authenticated before decompression.

Module images are mapped by `narf_memory::module_text` into a dedicated
kernel VA window with per-region W^X — text RX, rodata RO, data RW — and
the writable linear-map alias of the text closed. The window sits within
the arch's call range of kernel text, which is what lets rustc's
PC-relative call relocations resolve; see that module's docs.

The aarch64 relocator accepts the page-relative address pairs emitted by
rustc/LLVM for module globals, including 32-bit and 64-bit scaled load/store
low-12 relocations. Real driver fixtures exercise these forms in addition to
the minimal reference module's branch relocations.

`target_domain=` is the author's default placement hint. A holder of module
load authority may override it with the `domain=<name>` parameter to
`init_module` / `finit_module`; the effective domain is recorded on the
module and `FRAME` is always rejected for runtime-loaded text. On x86_64,
image pages carry the selected protection key and entry/callback dispatches
through the active PKS or PCID backend. On MTE-capable aarch64, module-owned
heap allocations are tagged and checked while the scope is active; the
executable image itself is plain Normal memory because PC-relative
code/rodata references cannot carry allocation tags. Statically linked
drivers retain their compile-time Frame placement. See DESIGN.md §2.

The loadable-driver datapath covers PCI command control, bounded BAR MMIO,
responsive register waits, coherent DMA through opaque owner-scoped handles,
MSI-X/deferred callbacks, periodic polling, and copy-mode network-interface
registration. DMA CPU pointers never cross into module code; bounded copy
exports move descriptor and payload bytes, and unload unregisters interfaces,
quiesces IRQs, then revokes every retained DMA capability after disabling bus
mastering.

See:

  * [DESIGN.md](./DESIGN.md) — architecture + rationale for divergence
    from Linux's `.ko` model, and an up-front list of what does and does
    not work yet.
  * [MODULE_AUTHORING.md](./MODULE_AUTHORING.md) — how to write a NARF
    module.
  * [`test-module/`](./test-module) — the worked example, and a module
    in the shape every out-of-tree one takes: no dependencies, its two
    lifecycle symbols written directly, and the kernel functions it calls
    declared in an `extern "C"` block. Because it calls `narf_printk`,
    the object it builds to carries a genuine undefined symbol the
    relocator has to resolve — `R_X86_64_PLT32` on x86_64,
    `R_AARCH64_CALL26` (veneered) on aarch64.

Boot integration: `frame/src/bare_main.rs` calls
`narf_modules::register_initcalls()`, which contributes three initcalls:

  * `modules-abi` at `Stage::Subsys` — registers the driver-domain name
    aliases, registers the kernel ABI surface with KSYMTAB, derives and
    publishes the kernel ABI hash from that surface, and installs the
    fail-closed Ed25519 verifier and build-time trust roots.
  * `modules-initramfs-autoload` immediately after `modules-abi` — when the
    bootloader-supplied command line contains `modules_load=`, loads those
    comma-separated initramfs paths before `Stage::Device` probes hardware.
    `modules_domains=path=domain,...` applies per-image placement;
    `modules_domain=<name>` is the fallback for unmatched images. Signature,
    ABI, capability, and non-`FRAME` checks are the same as for
    `init_module(2)`; without `modules_load=` this is a no-op. `cargo xtask
    run --composition FILE` generates and stages this list for external module
    crates.
  * `modules-sysfs` at `Stage::Fs` — installs `/proc/modules` and
    `/sys/kernel/abi_hash`.

Order inside `modules-abi` matters: the ABI hash is *derived from* the
export table, so the exports have to be registered first. That is the
point of deriving it rather than accepting one — it cannot drift from the
surface it describes.

The symbols a module may call live in `kabi.rs`, declared through one
`kernel_abi!` invocation that also generates their registration and
computes each one's CRC from its signature at compile time. That surface
is deliberately small — Rust has no stable ABI, so only `extern "C"` over
primitives and `repr(C)` can safely cross into a separately compiled
module, and every addition is a promise.

The device-datapath subset now also covers unload-safe network registration and
full copy-mode e1000 RX/TX rings. Rich Rust objects stay in kernel-owned device
contexts; probe, deferred IRQ, poller, and TX callbacks all run through the
lifecycle/domain gate, never directly in hard-IRQ context. The e1000 `.ko`
uses only this primitive C ABI to reset the NIC, allocate/program rings,
transmit a real frame, and deliver completed RX descriptors into the network
stack. Zero-copy module DMA remains a later IOMMU-backed optimization.

Subsystems needing an export outside that surface call `narf_export!`:

```rust
use narf_modules::narf_export;
use narf_capabilities::CapKind;

narf_export!("narf_io_alloc_coherent",
    narf_io::alloc_coherent as usize, 0xABCDEF12);

narf_export!("narf_block_register_block_device",
    narf_block::register_block_device as usize, 0x12345678,
    CapKind::BlockDevice);   // cap-gated
```

Modules then resolve these by name during their relocation pass.

Building a module:

```sh
cat /sys/kernel/abi_hash                       # e.g. 0x1f3a90c2
cargo xtask build-module --package <crate> \
      --arch x86_64 --kernel-abi 0x1f3a90c2
```

This compiles the crate, takes its own object members out of the
`staticlib` archive, and `ld -r`s them into the single relocatable object
the loader wants — merging the per-static `.modinfo` sections in the
process. `cargo xtask test` stages the reference object in the initramfs and
loads, executes, and unloads it on both architecture paths when QEMU is
available.

Add `--compress` to wrap the ABI-stamped ELF in a versioned `.ko.lz4`
envelope. The loader caps both compressed and decompressed lengths at 32 MiB.

Production kernels read trusted raw Ed25519 public keys from the absolute
path in `NARF_MODULE_TRUSTED_KEYS` at build time. Build the final raw or
compressed bytes, sign `BLAKE3(the complete file)`, then attach the detached
64-byte signature and its 32-byte raw public key:

```sh
cargo xtask build-module --package <crate> --arch x86_64 \
  --kernel-abi 0x1f3a90c2 --compress --out module.ko.lz4
# Produce module.sig over BLAKE3(module.ko.lz4) with the release signer.
cargo xtask attach-module-signature --module module.ko.lz4 \
  --signature module.sig --public-key module.pub
```

Unsigned modules fail closed unless the developer/CI-only
`module-allow-unsigned` feature is explicit. For compressed modules the fixed
`NRFM` trailer authenticates the `NRFCMOD` header and compressed bytes before
the bounded LZ4 decoder runs.
