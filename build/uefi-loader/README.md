# NARF UEFI loader

The x86_64 build is a self-contained EFI application with embedded kernel,
initramfs, and command line. Build it with `cargo xtask efi-image`, run it
through OVMF with `--run`, or require a clean shutdown with `--smoke`.
See [build, install, and run instructions](../../docs/NATIVE_UEFI.md).
Its `.narf` PE section contains a versioned payload manifest; the loader
checks each SHA-256 before parsing the ELF. It reports firmware SecureBoot/
SetupMode while services are live. It uses `narf-boot-protocol` to validate the ELF and emit Multiboot2, then a
position-independent mode bridge enters the existing 32-bit kernel stub.
EFI loader/runtime/boot-services allocations and the complete final descriptor
map are retained; a fixed-address kernel allocation collision fails visibly.

## aarch64

This `aarch64-unknown-uefi` application is staged as the standard
`EFI/BOOT/BOOTAA64.EFI` removable-media loader by `cargo xtask image
--arch=aarch64`. It loads the NARF ELF from the native-package path
`EFI/NARF/narf-frame`, falling back to `boot/narf-frame` for removable
media. It validates and loads the ELF at its physical `PT_LOAD` addresses,
obtains the standard EFI devicetree configuration table, exits Boot Services,
and enters the kernel with the Linux `x0 = dtb` ABI. The DTB is
header-validated and bounded to 4 MiB, covering the expanded tree published by
current ArmVirt EDK2 firmware.

The linked loader is intentionally unbootable until
`packaging/bind-aarch64-uefi.py` replaces its retained digest placeholder with
the BLAKE2b-512 digest of the exact kernel ELF. The loader verifies that digest
before parsing or loading any segment. Signing the bound PE/COFF image therefore
extends UEFI Secure Boot authentication through the non-PE kernel payload.
