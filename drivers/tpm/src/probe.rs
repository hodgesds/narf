//! ACPI-based TPM identification — `MSFT0101` device matching.
//!
//! ## Parser ownership (composition, #934)
//!
//! This module used to carry a second TPM2 ACPI table parser
//! (`parse_tpm2_table`). It had no production caller and duplicated
//! the parser that is actually wired: `narf_acpi::parse_tpm2` /
//! `narf_acpi::tpm2_info()` in the ACPI crate, which walks the
//! XSDT, verifies the table checksum, and extracts the same
//! `platform_class` / `control_address` / `start_method` fields at
//! the same offsets. The duplicate is deleted; TPM2-table parsing
//! has exactly one owner, `narf-acpi`. Production discovery (the
//! platform transport, #939) consumes `narf_acpi::tpm2_info()`.
//!
//! What remains here is the ACPI *device* identification half:
//! the `MSFT0101` / `PNP0C31` HID matching and the TPM2 start-method
//! constants. The `MSFT0101` `_CRS` enumeration that consumes the
//! HID matching is a separable follow-up (it is not implemented by
//! pretending the table parser still lives here).
//!
//! ## Reference
//!
//! - Linux `drivers/char/tpm/tpm_crb.c` `crb_acpi_add()` /
//!   `crb_acpi_ids` (`{"MSFT0101", 0}`).
//! - Linux `include/acpi/actbl3.h` `struct acpi_table_tpm2`
//!   (start-method values).
//! - TCG ACPI Specification Family "1.2" and "2.0", Rev 1.00.

// ── ACPI HID string ──────────────────────────────────────────────────

/// ACPI `_HID` for TPM 2.0 CRB / firmware-TPM devices.
/// Linux tpm_crb.c: `{"MSFT0101", 0}` in the id table (line 917).
pub const ACPI_HID_TPM2: &str = "MSFT0101";

/// Alternative ACPI `_CID` for some platforms.
pub const ACPI_CID_TPM2: &str = "PNP0C31";

// ── Start-method constants ────────────────────────────────────────────
// Linux include/acpi/actbl3.h lines 456–470. The values are decoded
// from the TPM2 table by `narf_acpi` (the parser owner, above); they
// are kept here as the named vocabulary for classifying a decoded
// `start_method`.

pub const ACPI_TPM2_NOT_ALLOWED: u32 = 0;
pub const ACPI_TPM2_START_METHOD: u32 = 2;
pub const ACPI_TPM2_MEMORY_MAPPED: u32 = 6;
pub const ACPI_TPM2_COMMAND_BUFFER: u32 = 7;
pub const ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD: u32 = 8;
pub const ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC: u32 = 11;
pub const ACPI_TPM2_COMMAND_BUFFER_WITH_PLUTON: u32 = 13;
pub const ACPI_TPM2_CRB_WITH_ARM_FFA: u32 = 15;

/// Returns `true` when a TPM2-table `start_method` (as decoded by
/// `narf_acpi::tpm2_info()`) designates a CRB interface
/// (command-buffer path).
pub fn start_method_is_crb(start_method: u32) -> bool {
    matches!(
        start_method,
        ACPI_TPM2_COMMAND_BUFFER
            | ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD
            | ACPI_TPM2_MEMORY_MAPPED
    )
}

// ── ACPI device matching ─────────────────────────────────────────────

/// Returns `true` if the given ACPI `_HID` string matches a TPM 2.0
/// CRB device. We accept both `MSFT0101` (fTPM on AMD/Intel) and
/// the legacy `PNP0C31` compatible ID.
///
/// Linux tpm_crb.c: `{"MSFT0101", 0}` in `crb_acpi_ids` (line 917).
pub fn matches_tpm2_hid(hid: &str) -> bool {
    hid == ACPI_HID_TPM2 || hid == ACPI_CID_TPM2
}
