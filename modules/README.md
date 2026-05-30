# narf-modules

Runtime-loadable kernel module subsystem for NARF.

This crate provides:

  * ELF64 parsing for relocatable kernel-module objects.
  * Per-arch relocation (x86_64 + aarch64).
  * Manifest parser (`.modinfo` k=v).
  * Kernel symbol table with cap-typed exports + per-symbol CRC.
  * Module-state machine + reference counting.
  * Domain placement against the PKS-isolated driver-domain set.
  * `/proc/modules` and `/sys/module/<name>/` adapters.
  * `init_module` / `finit_module` / `delete_module` syscall bodies.
  * Cap-gated signature-verification hook.

See:

  * [DESIGN.md](./DESIGN.md) — architecture + rationale for divergence
    from Linux's `.ko` model.
  * [MODULE_AUTHORING.md](./MODULE_AUTHORING.md) — how to write a NARF
    module.

Boot integration: call `narf_modules::boot_init(kernel_abi_hash)` from
the kernel's Stage::Subsys initcall once the heap is up. That call:

  1. Sets the kernel ABI hash that modules must match.
  2. Installs the default no-op signature verifier.
  3. Registers the standard driver-domain name aliases.
  4. Installs `/proc/modules`.

Subsystems that want to export symbols call `narf_export!` at boot:

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
