# Boot protocol references

- Multiboot2 specification, information structure and tags 1/3/6/8/12–17:
  the existing NARF kernel parser is the consumer of the emitted bytes.
- Local Linux reference tree `/usr/src/linux`, inspected for this change:
  `drivers/firmware/efi/libstub/efi-stub-entry.c` (EFI entry and load options),
  `efi-stub-helper.c::efi_exit_boot_services` (final map and map-key retry),
  `arch/x86/boot/header.S` and `drivers/firmware/efi/libstub/x86-stub.c`
  (PE entry versus kernel entry), and `init/initramfs.c` (kernel-owned archive
  unpacking). Linux source is reference material, not a build dependency.
  `drivers/firmware/efi/libstub/secureboot.c` and
  `include/linux/efi.h::efi_get_secureboot_mode` guide the pre-exit
  SecureBoot/SetupMode diagnostic; `init/do_mounts_initrd.c` distinguishes
  legacy initrd loading from kernel-owned initramfs unpacking/root policy.
- `build/uefi-loader/src/aarch64.rs`: existing firmware reservation and
  kernel-integrity handling retained by the aarch64 build.
