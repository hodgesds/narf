//! HCI opcode constants — Bluetooth Core Spec 5.3 Vol 4 Part E §7.
//!
//! Opcodes are composed as `(OGF << 10) | OCF`. We define the OGF
//! groups first then the Mandatory commands every controller must
//! implement (Vol 4 Part E §3.1, table 3.1) so the bring-up state
//! machine can issue them without each call site rebuilding the
//! opcode by hand.

use crate::hci::opcode;

// ── OGF (Opcode Group Field, §5.4.1) ───────────────────────────────
pub const OGF_LINK_CONTROL:           u8 = 0x01;
pub const OGF_LINK_POLICY:            u8 = 0x02;
pub const OGF_CONTROLLER_BASEBAND:    u8 = 0x03;
pub const OGF_INFORMATIONAL:          u8 = 0x04;
pub const OGF_STATUS:                 u8 = 0x05;
pub const OGF_TESTING:                u8 = 0x06;
pub const OGF_LE_CONTROLLER:          u8 = 0x08;
pub const OGF_VENDOR:                 u8 = 0x3F;

// ── Mandatory: Controller & Baseband (§7.3) ────────────────────────
/// HCI_Reset (§7.3.2). No parameters; controller returns Command
/// Complete with status.
pub const HCI_RESET: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0003);

/// HCI_Set_Event_Mask (§7.3.1). 8-byte parameter = bitmap of events
/// the controller will deliver.
pub const HCI_SET_EVENT_MASK: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0001);

// ── Mandatory: Informational Parameters (§7.4) ─────────────────────
/// HCI_Read_Local_Version_Information (§7.4.1). Returns
/// HCI_Version, HCI_Revision, LMP_Version, Manufacturer_Name,
/// LMP_Subversion.
pub const HCI_READ_LOCAL_VERSION: u16 = opcode(OGF_INFORMATIONAL, 0x0001);

/// HCI_Read_Local_Supported_Commands (§7.4.2). 64-byte bitmap.
pub const HCI_READ_LOCAL_SUPPORTED_COMMANDS: u16 = opcode(OGF_INFORMATIONAL, 0x0002);

/// HCI_Read_Local_Supported_Features (§7.4.3). 8-byte bitmap.
pub const HCI_READ_LOCAL_SUPPORTED_FEATURES: u16 = opcode(OGF_INFORMATIONAL, 0x0003);

/// HCI_Read_BD_ADDR (§7.4.6). Returns the 6-byte BD_ADDR.
pub const HCI_READ_BD_ADDR: u16 = opcode(OGF_INFORMATIONAL, 0x0009);

/// HCI_Read_Buffer_Size (§7.4.5). Returns ACL/SCO MTU + count.
pub const HCI_READ_BUFFER_SIZE: u16 = opcode(OGF_INFORMATIONAL, 0x0005);

// ── LE basics (§7.8) — needed even for "is BLE here?" probes ───────
pub const HCI_LE_READ_BUFFER_SIZE_V1: u16 = opcode(OGF_LE_CONTROLLER, 0x0002);
pub const HCI_LE_READ_LOCAL_SUPPORTED_FEATURES: u16 = opcode(OGF_LE_CONTROLLER, 0x0003);
pub const HCI_LE_SET_EVENT_MASK: u16 = opcode(OGF_LE_CONTROLLER, 0x0001);

#[cfg(test)]
mod selftest {
    use super::*;
    // Compile-time check: opcode encoding from the spec is exact.
    // §7.3.2: OGF=0x03, OCF=0x0003 → opcode 0x0C03.
    const _: () = assert!(HCI_RESET == 0x0C03);
    // §7.3.1: OGF=0x03, OCF=0x0001 → 0x0C01.
    const _: () = assert!(HCI_SET_EVENT_MASK == 0x0C01);
    // §7.4.1: OGF=0x04, OCF=0x0001 → 0x1001.
    const _: () = assert!(HCI_READ_LOCAL_VERSION == 0x1001);
    // §7.4.6: OGF=0x04, OCF=0x0009 → 0x1009.
    const _: () = assert!(HCI_READ_BD_ADDR == 0x1009);
}
