# efi — UEFI Runtime Services Codecs

`narf-efi` holds the data-structure codecs the kernel uses to talk to
UEFI firmware after `ExitBootServices`. It is a clean-room implementation
derived solely from the public Unified Extensible Firmware Interface
(UEFI) Specification, Version 2.10 — no GPL or Linux source was consulted
for the wire layouts, though the Linux runtime wrappers and efivarfs were
referenced for serialization conventions, status mapping, and
enumeration bounds.

The crate is deliberately transport-neutral: every type here describes a
*wire* layout, the exact byte shape firmware and kernel exchange. The
architecture-specific glue that actually issues an indirect call through
the Runtime Services function-pointer table — after pinning the
firmware's page tables — lives in `arch/`, not here. Keeping the codecs
separate from the call mechanism means the parsing and validation logic
is testable in isolation and shared across x86_64 and aarch64.

The covered surface tracks the parts of the UEFI spec the kernel needs
post-boot. System-table decoding (§4) reads the EFI System Table and
table-header layout, verifies signatures, and checks the CRC32 that
firmware stamps across the header. The time module (§8.3) decodes
`EFI_TIME` and `EFI_TIME_CAPABILITIES`. The variable module (§8.2, §32.4)
handles variable attributes, the well-known variable GUIDs, the UCS-2
wide-string encoding of variable names, and the `EFI_SIGNATURE_LIST`
walker used to read the Secure Boot databases (PK, KEK, db, dbx). The
reset module (§8.5) carries the reset-type enum and EFI status codes. A
runtime dispatch layer ties these together into a validated,
allocation-bounded call surface for GetTime, the variable services, and
ResetSystem.

That dispatch surface is currently dormant in production: no supported
boot path yet preserves the runtime-services table and its memory
descriptors across `ExitBootServices`, and `SetVirtualAddressMap` plus
the per-architecture page-table pinning are out of scope until the boot
ABI can carry the final EFI memory map without breaking the aarch64
`x0 = dtb` entry contract. BootServices is not modeled at all — it is not
callable after `ExitBootServices` and the kernel does not use it.

This crate is `no_std`. Its only dependency is the kernel test harness;
the `kernel-test` feature gates in-kernel test hooks.

- Spec: [`specification/spec.md`](./specification/spec.md)
