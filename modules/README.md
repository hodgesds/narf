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

`target_domain=` is enforced at module entry. On x86_64, image pages carry
the selected protection key and entry dispatches through the active PKS or
PCID backend. On MTE-capable aarch64, module-owned heap allocations are
tagged and checked while the scope is active; the executable image itself is
plain Normal memory because PC-relative code/rodata references cannot carry
allocation tags. Kernel core remains reachable so exported calls work; see
DESIGN.md §2 for the exact boundary.

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
`narf_modules::register_initcalls()`, which contributes two initcalls:

  * `modules-abi` at `Stage::Subsys` — registers the driver-domain name
    aliases, registers the kernel ABI surface with KSYMTAB, derives and
    publishes the kernel ABI hash from that surface, and installs the
    fail-closed Ed25519 verifier and build-time trust roots.
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
