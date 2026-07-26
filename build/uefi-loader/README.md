# NARF aarch64 UEFI loader

This `aarch64-unknown-uefi` application is staged as the standard
`EFI/BOOT/BOOTAA64.EFI` removable-media loader by `cargo xtask image
--arch=aarch64`. It validates and loads the NARF ELF at its physical
`PT_LOAD` addresses, obtains the standard EFI devicetree configuration
table, exits Boot Services, and enters the kernel with the Linux
`x0 = dtb` ABI. The DTB is header-validated and bounded to 4 MiB,
covering the expanded tree published by current ArmVirt EDK2 firmware.
