# NARF aarch64 UEFI loader

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
