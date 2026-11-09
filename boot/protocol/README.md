# narf-boot-protocol

Allocation-free, `no_std` ELF64 validation, bounded memory-map normalization,
and Multiboot2 handoff construction shared by host packaging and NARF's native
x86_64 EFI loader. The crate has no kernel or EFI dependencies and performs no
unsafe operations. See [specification/spec.md](specification/spec.md) for its
wire and ownership contracts and [native EFI instructions](../../docs/NATIVE_UEFI.md)
for building, running, and installing the complete boot artifact.
