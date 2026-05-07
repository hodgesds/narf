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

No GPL / Linux source consulted.

## Surface

- `time::EfiTime` / `EfiTimeCapabilities` decoders.
- `reset::EfiResetType` enum + EFI_STATUS constants.
- `variable::{attr, encode_name, decode_name, parse_signature_list,
  Guid, EFI_GLOBAL_VARIABLE, EFI_IMAGE_SECURITY_DATABASE_GUID,
  EFI_CERT_X509_GUID, EFI_CERT_SHA256_GUID}`.
- `system_table::{TableHeader, signature::*, crc32_ieee,
  decode_configuration_table}`.

## Out of scope

- Indirect-call dispatch through the live RT-services function-
  pointer table — that's arch-specific glue (page-table pinning,
  EFI calling convention, error-status decoding) that lives in
  `arch/`.
- BootServices — not callable post-`ExitBootServices`, not used by
  the kernel.
