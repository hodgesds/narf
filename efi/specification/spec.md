# narf-efi

UEFI Runtime Services + variable + time codecs.

## Sources (public only)

- **Unified Extensible Firmware Interface (UEFI) Specification,
  Version 2.10**, August 2022 — UEFI Forum.
  <https://uefi.org/specs/UEFI/2.10/>
  - §4 — EFI System Table layout, table-header signatures + CRC.
  - §8.2 — Variable Services (GetVariable / SetVariable /
    GetNextVariableName / QueryVariableInfo) + variable Attributes.
  - §8.3 — `EFI_TIME` and `EFI_TIME_CAPABILITIES`.
  - §8.5 — `ResetSystem` + `EFI_RESET_TYPE`.
  - §32.4.1 — `EFI_SIGNATURE_LIST` (Secure Boot db / dbx).

- Linux `/usr/src/linux/drivers/firmware/efi/runtime-wrappers.c`,
  `/usr/src/linux/drivers/firmware/efi/vars.c`, and
  `/usr/src/linux/fs/efivarfs/` for runtime serialization, status mapping,
  enumeration bounds, and the filesystem-visible variable ABI.

## Surface

- `time::EfiTime` / `EfiTimeCapabilities` decoders.
- `reset::EfiResetType` enum + EFI_STATUS constants.
- `variable::{attr, encode_name, encode_name_ucs2, decode_name,
  decode_name_ucs2, parse_signature_list,
  Guid, EFI_GLOBAL_VARIABLE, EFI_IMAGE_SECURITY_DATABASE_GUID,
  EFI_CERT_X509_GUID, EFI_CERT_SHA256_GUID}`.
- `system_table::{TableHeader, signature::*, crc32_ieee,
  decode_configuration_table}`.
- `runtime::{install, is_available, get_time, get_variable,
  get_variable_with_attributes, get_next_variable, list_variables,
  set_variable, query_variable_info, reset_system}` provides the validated
  and allocation-bounded dispatch surface.
  It is currently dormant in production: no supported boot path preserves
  and installs the runtime-services table plus its memory descriptors.

## Out of scope

- `SetVirtualAddressMap` and architecture page-table pinning for EFI
  runtime code/data. Enabling the dispatch surface requires a boot-ABI
  extension carrying the final EFI memory map without violating the
  aarch64 Linux `x0 = dtb` entry contract.
- BootServices — not callable post-`ExitBootServices`, not used by
  the kernel.
