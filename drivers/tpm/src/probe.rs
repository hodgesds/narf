//! ACPI-based TPM probe — `MSFT0101` device + TPM2 ACPI table parser.
//!
//! Two discovery paths exist for CRB TPMs:
//!
//! 1. **ACPI device `MSFT0101`** — the OEM declares a device node
//!    under `\_SB` with `_HID = "MSFT0101"` (or compatible ID) and
//!    `_CRS` providing the CRB MMIO resource. This is the path used
//!    by AMD fTPM on Zen 2 / Zen 4.
//!
//! 2. **TPM2 ACPI table** (`ACPI_SIG_TPM2 = "TPM2"`) — a fixed ACPI
//!    table at the root of the ACPI tables array. Offset 0x24 contains
//!    `control_address` (64-bit physical address of the CRB control
//!    area) and offset 0x2C contains `start_method` (u32 interface
//!    selector). Linux reads this table in `tpm_crb.c:798`.
//!
//! ## Start-method values
//!
//! | Value | Name                                    |
//! |-------|-----------------------------------------|
//! | 2     | ACPI_TPM2_START_METHOD                  |
//! | 6     | ACPI_TPM2_MEMORY_MAPPED                 |
//! | 7     | ACPI_TPM2_COMMAND_BUFFER (CRB)          |
//! | 8     | ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD |
//!
//! For AMD fTPM, `start_method == 7` (CRB) is typical.
//!
//! ## Reference
//!
//! - Linux `drivers/char/tpm/tpm_crb.c` `crb_acpi_add()` (line 787).
//! - Linux `include/acpi/actbl3.h` `struct acpi_table_tpm2` (line 437).
//! - TCG ACPI Specification Family "1.2" and "2.0", Rev 1.00.

// ── ACPI HID string ──────────────────────────────────────────────────

/// ACPI `_HID` for TPM 2.0 CRB / firmware-TPM devices.
/// Linux tpm_crb.c: `{"MSFT0101", 0}` in the id table (line 917).
pub const ACPI_HID_TPM2: &str = "MSFT0101";

/// Alternative ACPI `_CID` for some platforms.
pub const ACPI_CID_TPM2: &str = "PNP0C31";

/// ACPI signature for the TPM2 system description table.
/// Linux tpm_crb.c: `#define ACPI_SIG_TPM2 "TPM2"` (line 25).
pub const ACPI_SIG_TPM2: &[u8; 4] = b"TPM2";

// ── Start-method constants ────────────────────────────────────────────
// Linux include/acpi/actbl3.h lines 456–470.

pub const ACPI_TPM2_NOT_ALLOWED: u32 = 0;
pub const ACPI_TPM2_START_METHOD: u32 = 2;
pub const ACPI_TPM2_MEMORY_MAPPED: u32 = 6;
pub const ACPI_TPM2_COMMAND_BUFFER: u32 = 7;
pub const ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD: u32 = 8;
pub const ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC: u32 = 11;
pub const ACPI_TPM2_COMMAND_BUFFER_WITH_PLUTON: u32 = 13;
pub const ACPI_TPM2_CRB_WITH_ARM_FFA: u32 = 15;

// ── TPM2 ACPI table layout ────────────────────────────────────────────

/// Byte offset of the `platform_class` field (u16) in the TPM2 table.
pub const TPM2_TABLE_OFFSET_PLATFORM_CLASS: usize = 36;
/// Byte offset of `control_address` (u64 LE) in the TPM2 table.
/// This is the physical address of the CRB control area.
/// Linux actbl3.h: `u64 control_address` (offset 40 from table start).
pub const TPM2_TABLE_OFFSET_CONTROL_ADDRESS: usize = 40;
/// Byte offset of `start_method` (u32 LE).
/// Linux actbl3.h: `u32 start_method` (offset 48 from table start).
pub const TPM2_TABLE_OFFSET_START_METHOD: usize = 48;

/// Minimum valid length for a TPM2 ACPI table (header + mandatory fields).
pub const TPM2_TABLE_MIN_LEN: usize = 52;

// ── Parsed TPM2 table ─────────────────────────────────────────────────

/// Contents of the `TPM2` ACPI table, as parsed by `parse_tpm2_table`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tpm2AcpiTable {
    /// Physical address of the CRB control area. The driver maps this
    /// as a 4 KiB MMIO region and uses it with `crb::CrbMmio`.
    pub control_address: u64,
    /// Interface selector; one of the `ACPI_TPM2_*` constants above.
    pub start_method: u32,
}

impl Tpm2AcpiTable {
    /// Returns `true` when `start_method` designates a CRB interface
    /// (command-buffer path). Linux tpm_crb.c checks this before
    /// binding the CRB driver.
    pub fn is_crb(&self) -> bool {
        matches!(
            self.start_method,
            ACPI_TPM2_COMMAND_BUFFER
                | ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD
                | ACPI_TPM2_MEMORY_MAPPED
        )
    }
}

/// Parse a raw TPM2 ACPI table byte slice.
///
/// `table` should be the entire ACPI table buffer beginning at the
/// standard ACPI table header (signature at offset 0, length at
/// offset 4, etc.). The `control_address` and `start_method` fields
/// start after the 36-byte ACPI common header.
///
/// Returns `None` if `table` is shorter than `TPM2_TABLE_MIN_LEN`.
pub fn parse_tpm2_table(table: &[u8]) -> Option<Tpm2AcpiTable> {
    if table.len() < TPM2_TABLE_MIN_LEN {
        return None;
    }
    // Validate the 4-byte signature.
    if &table[0..4] != ACPI_SIG_TPM2 {
        return None;
    }
    let control_address = u64::from_le_bytes(
        table[TPM2_TABLE_OFFSET_CONTROL_ADDRESS
            ..TPM2_TABLE_OFFSET_CONTROL_ADDRESS + 8]
            .try_into()
            .ok()?,
    );
    let start_method = u32::from_le_bytes(
        table[TPM2_TABLE_OFFSET_START_METHOD..TPM2_TABLE_OFFSET_START_METHOD + 4]
            .try_into()
            .ok()?,
    );
    Some(Tpm2AcpiTable {
        control_address,
        start_method,
    })
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
