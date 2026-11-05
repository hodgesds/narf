//! HCI opcode constants — Bluetooth Core Spec 5.3 Vol 4 Part E §7.
//!
//! Opcodes are composed as `(OGF << 10) | OCF`. We define the OGF
//! groups first then the Mandatory commands every controller must
//! implement (Vol 4 Part E §3.1, table 3.1) so the bring-up state
//! machine can issue them without each call site rebuilding the
//! opcode by hand.

use crate::hci::opcode;

// ── OGF (Opcode Group Field, §5.4.1) ───────────────────────────────
pub const OGF_LINK_CONTROL: u8 = 0x01;
pub const OGF_LINK_POLICY: u8 = 0x02;
pub const OGF_CONTROLLER_BASEBAND: u8 = 0x03;
pub const OGF_INFORMATIONAL: u8 = 0x04;
pub const OGF_STATUS: u8 = 0x05;
pub const OGF_TESTING: u8 = 0x06;
pub const OGF_LE_CONTROLLER: u8 = 0x08;
pub const OGF_VENDOR: u8 = 0x3F;

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

/// HCI_Read_Local_Name (§7.4.14). Returns Status (1) + the 248-byte
/// local name (NUL-padded). Read during bring-up so mgmt READ_INFO
/// reports the controller's real name (issue #815).
pub const HCI_READ_LOCAL_NAME: u16 = opcode(OGF_INFORMATIONAL, 0x0014);

/// HCI_Read_Class_Of_Device (§7.4.23). Returns Status (1) + the
/// 3-byte Class of Device. Read during bring-up so mgmt READ_INFO
/// reports the controller's real class (issue #815).
pub const HCI_READ_CLASS_OF_DEVICE: u16 = opcode(OGF_INFORMATIONAL, 0x0023);

/// HCI_Read_Buffer_Size (§7.4.5). Returns ACL/SCO MTU + count.
pub const HCI_READ_BUFFER_SIZE: u16 = opcode(OGF_INFORMATIONAL, 0x0005);

// ── LE basics (§7.8) — needed even for "is BLE here?" probes ───────
pub const HCI_LE_READ_BUFFER_SIZE_V1: u16 = opcode(OGF_LE_CONTROLLER, 0x0002);
pub const HCI_LE_READ_LOCAL_SUPPORTED_FEATURES: u16 = opcode(OGF_LE_CONTROLLER, 0x0003);
pub const HCI_LE_SET_EVENT_MASK: u16 = opcode(OGF_LE_CONTROLLER, 0x0001);

// ── LE Central GAP (§7.8) — scan + connect ────────────────────────
/// HCI_LE_Set_Scan_Parameters (§7.8.10). 7-byte parameter:
/// scan_type (1) + scan_interval (2 LE) + scan_window (2 LE) +
/// own_address_type (1) + scanning_filter_policy (1).
pub const HCI_LE_SET_SCAN_PARAMETERS: u16 = opcode(OGF_LE_CONTROLLER, 0x000B);
/// HCI_LE_Set_Scan_Enable (§7.8.11). 2-byte parameter:
/// scan_enable (1) + filter_duplicates (1).
pub const HCI_LE_SET_SCAN_ENABLE: u16 = opcode(OGF_LE_CONTROLLER, 0x000C);
/// HCI_LE_Create_Connection (§7.8.12). 25-byte parameter block.
/// Returns Command Status (not Command Complete); the connection
/// outcome is signalled by an LE Connection Complete subevent.
pub const HCI_LE_CREATE_CONNECTION: u16 = opcode(OGF_LE_CONTROLLER, 0x000D);
/// HCI_LE_Create_Connection_Cancel (§7.8.13). No parameters.
pub const HCI_LE_CREATE_CONNECTION_CANCEL: u16 = opcode(OGF_LE_CONTROLLER, 0x000E);

// ── Link Control (§7.1) — generic link teardown ───────────────────
/// HCI_Disconnect (§7.1.6). 3-byte parameter:
/// connection_handle (2 LE) + reason (1). Returns Command Status;
/// completion is signalled by Disconnection Complete (§7.7.5).
pub const HCI_DISCONNECT: u16 = opcode(OGF_LINK_CONTROL, 0x0006);

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
    // §7.8.10: OGF=0x08, OCF=0x000B → 0x200B.
    const _: () = assert!(HCI_LE_SET_SCAN_PARAMETERS == 0x200B);
    // §7.8.11: OGF=0x08, OCF=0x000C → 0x200C.
    const _: () = assert!(HCI_LE_SET_SCAN_ENABLE == 0x200C);
    // §7.8.12: OGF=0x08, OCF=0x000D → 0x200D.
    const _: () = assert!(HCI_LE_CREATE_CONNECTION == 0x200D);
    // §7.1.6: OGF=0x01, OCF=0x0006 → 0x0406.
    const _: () = assert!(HCI_DISCONNECT == 0x0406);
}

// ── Classic BR/EDR — Inquiry + Connection (§7.1) ─────────────────
pub const HCI_INQUIRY: u16 = opcode(OGF_LINK_CONTROL, 0x0001);
pub const HCI_INQUIRY_CANCEL: u16 = opcode(OGF_LINK_CONTROL, 0x0002);
pub const HCI_CREATE_CONNECTION: u16 = opcode(OGF_LINK_CONTROL, 0x0005);
/// HCI_Remote_Name_Request (§7.1.19). 10-byte parameter:
/// BD_ADDR (6) + Page_Scan_Repetition_Mode (1) + Reserved (1) +
/// Clock_Offset (2 LE). Returns Command Status; the name arrives
/// in a Remote Name Request Complete event (§7.7.7, code 0x07).
pub const HCI_REMOTE_NAME_REQUEST: u16 = opcode(OGF_LINK_CONTROL, 0x0019);
pub const HCI_ACCEPT_CONNECTION_REQUEST: u16 = opcode(OGF_LINK_CONTROL, 0x0009);
pub const HCI_REJECT_CONNECTION_REQUEST: u16 = opcode(OGF_LINK_CONTROL, 0x000A);
pub const HCI_AUTHENTICATION_REQUESTED: u16 = opcode(OGF_LINK_CONTROL, 0x0011);
pub const HCI_SET_CONNECTION_ENCRYPTION: u16 = opcode(OGF_LINK_CONTROL, 0x0013);
pub const HCI_SETUP_SYNCHRONOUS_CONNECTION: u16 = opcode(OGF_LINK_CONTROL, 0x0028);
pub const HCI_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST: u16 = opcode(OGF_LINK_CONTROL, 0x0029);
pub const HCI_IO_CAPABILITY_REQUEST_REPLY: u16 = opcode(OGF_LINK_CONTROL, 0x002B);
pub const HCI_USER_CONFIRMATION_REQUEST_REPLY: u16 = opcode(OGF_LINK_CONTROL, 0x002C);
pub const HCI_USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY: u16 = opcode(OGF_LINK_CONTROL, 0x002D);
pub const HCI_USER_PASSKEY_REQUEST_REPLY: u16 = opcode(OGF_LINK_CONTROL, 0x002E);
pub const HCI_REMOTE_OOB_DATA_REQUEST_REPLY: u16 = opcode(OGF_LINK_CONTROL, 0x0030);
// ── SSP + Host Config (§7.3) ──────────────────────────────────────
/// HCI_Write_Authentication_Enable (§7.3.31). 1-byte parameter:
/// 0x00 = link security off, 0x01 = on (Security Mode 3). Issued
/// by mgmt SET_LINK_SECURITY (issue #815).
pub const HCI_WRITE_AUTHENTICATION_ENABLE: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0020);
pub const HCI_WRITE_SIMPLE_PAIRING_MODE: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0056);
pub const HCI_WRITE_INQUIRY_MODE: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0045);
pub const HCI_WRITE_PAGE_TIMEOUT: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0018);
pub const HCI_WRITE_SCAN_ENABLE: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x001A);
pub const HCI_WRITE_CLASS_OF_DEVICE: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0024);
pub const HCI_WRITE_LOCAL_NAME: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0013);
/// HCI_Write_Page_Scan_Type (§7.3.44). 1-byte parameter: 0x00 =
/// standard page scan, 0x01 = interlaced (fast connectable).
/// Issued by mgmt SET_FAST_CONNECTABLE (issue #815).
pub const HCI_WRITE_PAGE_SCAN_TYPE: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x0047);
/// HCI_Write_LE_Host_Support (§7.3.66). 2-byte parameter:
/// LE_Host_Supported (1) + Simultaneous_LE_Host_Supported (1,
/// always 0 here). Issued by mgmt SET_LE (issue #815).
pub const HCI_WRITE_LE_HOST_SUPPORT: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x006D);
/// HCI_Write_Secure_Connections_Host_Support (§7.3.76). 1-byte
/// parameter: 0x00 = off, 0x01 = on. Issued by mgmt
/// SET_SECURE_CONN (issue #815).
pub const HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT: u16 = opcode(OGF_CONTROLLER_BASEBAND, 0x007A);

// ── LE Advertising (§7.8.5..7.8.9) ────────────────────────────────
/// HCI_LE_Set_Advertising_Parameters (§7.8.5).
pub const HCI_LE_SET_ADVERTISING_PARAMETERS: u16 = opcode(OGF_LE_CONTROLLER, 0x0006);
/// HCI_LE_Set_Advertising_Data (§7.8.7). 32-byte param: length + 31-byte data.
pub const HCI_LE_SET_ADVERTISING_DATA: u16 = opcode(OGF_LE_CONTROLLER, 0x0008);
/// HCI_LE_Set_Scan_Response_Data (§7.8.8).
pub const HCI_LE_SET_SCAN_RESPONSE_DATA: u16 = opcode(OGF_LE_CONTROLLER, 0x0009);
/// HCI_LE_Set_Advertising_Enable (§7.8.9). 1-byte param.
pub const HCI_LE_SET_ADVERTISING_ENABLE: u16 = opcode(OGF_LE_CONTROLLER, 0x000A);
/// HCI_LE_Set_Random_Address (§7.8.4).
pub const HCI_LE_SET_RANDOM_ADDRESS: u16 = opcode(OGF_LE_CONTROLLER, 0x0005);

// ── LE Periodic Advertising (§7.8.61..63, §7.8.67..69) ─────────────
// OCFs cross-checked against Linux `include/net/bluetooth/hci.h`
// (HCI_OP_LE_SET_PER_ADV_PARAMS 0x203E … HCI_OP_LE_PA_TERM_SYNC
// 0x2046) and the btmon trace in the kernel's PA-sync commit
// history: Set Params plen 7, Set Data plen 7, Enable plen 2,
// Create Sync plen 14, Terminate Sync plen 2. OCF 0x0045 is
// Create Sync Cancel (§7.8.68), not Terminate Sync — the two are
// adjacent and easy to confuse; the kernel header settles it.
//
// LE Periodic Advertising Sync Transfer Received (§7.7.65.21,
// subevent 0x18) is deliberately NOT here: it is the optional
// remainder, tracked separately (see #1560).
/// HCI_LE_Set_Periodic_Advertising_Parameters (§7.8.61). 7-byte
/// parameter: advertising_handle (1) + interval_min (2 LE) +
/// interval_max (2 LE) + properties (2 LE).
pub const HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS: u16 = opcode(OGF_LE_CONTROLLER, 0x003E);
/// HCI_LE_Set_Periodic_Advertising_Data (§7.8.62). Variable
/// parameter: advertising_handle (1) + operation (1) +
/// advertising_data_length (1) + advertising_data (0..=251).
pub const HCI_LE_SET_PERIODIC_ADVERTISING_DATA: u16 = opcode(OGF_LE_CONTROLLER, 0x003F);
/// HCI_LE_Set_Periodic_Advertising_Enable (§7.8.63). 2-byte
/// parameter: enable (1) + advertising_handle (1).
pub const HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE: u16 = opcode(OGF_LE_CONTROLLER, 0x0040);
/// HCI_LE_Periodic_Advertising_Create_Sync (§7.8.67). 14-byte
/// parameter. Returns Command Status; the outcome is signalled by
/// an LE Periodic Advertising Sync Established subevent (§7.7.65.15).
pub const HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC: u16 = opcode(OGF_LE_CONTROLLER, 0x0044);
/// HCI_LE_Periodic_Advertising_Create_Sync_Cancel (§7.8.68). No
/// parameters. Cancels a pending Create Sync.
pub const HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL: u16 = opcode(OGF_LE_CONTROLLER, 0x0045);
/// HCI_LE_Periodic_Advertising_Terminate_Sync (§7.8.69). 2-byte
/// parameter: sync_handle (2 LE).
pub const HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC: u16 = opcode(OGF_LE_CONTROLLER, 0x0046);

// ── LE Filter Accept List (§7.8.14..16) ───────────────────────────
/// HCI_LE_Add_Device_To_Filter_Accept_List (§7.8.16).
/// 7-byte param: address_type (1) + address (6).
pub const HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST: u16 = opcode(OGF_LE_CONTROLLER, 0x0011);
/// HCI_LE_Remove_Device_From_Filter_Accept_List (§7.8.17).
pub const HCI_LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST: u16 = opcode(OGF_LE_CONTROLLER, 0x0012);
/// HCI_LE_Clear_Filter_Accept_List (§7.8.15).
pub const HCI_LE_CLEAR_FILTER_ACCEPT_LIST: u16 = opcode(OGF_LE_CONTROLLER, 0x0010);

// ── LE Crypto helpers (§7.8.22, §7.8.23) ──────────────────────────
/// HCI_LE_Encrypt (§7.8.22). 32-byte param: key (16) + plaintext (16).
/// Returns 16-byte ciphertext via Command Complete.
pub const HCI_LE_ENCRYPT: u16 = opcode(OGF_LE_CONTROLLER, 0x0017);
/// HCI_LE_Rand (§7.8.23). No params. Returns 8 random bytes.
pub const HCI_LE_RAND: u16 = opcode(OGF_LE_CONTROLLER, 0x0018);

// ── LE Start Encryption (§7.8.24) ─────────────────────────────────
/// HCI_LE_Start_Encryption (§7.8.24). 28-byte param.
pub const HCI_LE_START_ENCRYPTION: u16 = opcode(OGF_LE_CONTROLLER, 0x0019);
/// HCI_LE_Long_Term_Key_Request_Reply (§7.8.25).
pub const HCI_LE_LTK_REQUEST_REPLY: u16 = opcode(OGF_LE_CONTROLLER, 0x001A);
/// HCI_LE_Long_Term_Key_Request_Negative_Reply (§7.8.26).
pub const HCI_LE_LTK_REQUEST_NEGATIVE_REPLY: u16 = opcode(OGF_LE_CONTROLLER, 0x001B);

// ── LE Read max data length, used by Data Length Extension (§7.8.46) ─
pub const HCI_LE_READ_MAX_DATA_LENGTH: u16 = opcode(OGF_LE_CONTROLLER, 0x002F);
pub const HCI_LE_SET_DATA_LENGTH: u16 = opcode(OGF_LE_CONTROLLER, 0x0022);

// ── BLE Audio / ISO (§7.8.97..) — for ISO Data Path setup ─────────
/// HCI_LE_Setup_ISO_Data_Path (§7.8.109).
pub const HCI_LE_SETUP_ISO_DATA_PATH: u16 = opcode(OGF_LE_CONTROLLER, 0x006E);
/// HCI_LE_Remove_ISO_Data_Path (§7.8.110).
pub const HCI_LE_REMOVE_ISO_DATA_PATH: u16 = opcode(OGF_LE_CONTROLLER, 0x006F);

#[cfg(test)]
mod selftest_ext {
    use super::*;
    // §7.8.5: OGF=0x08 OCF=0x0006 → 0x2006.
    const _: () = assert!(HCI_LE_SET_ADVERTISING_PARAMETERS == 0x2006);
    // §7.8.7: OGF=0x08 OCF=0x0008 → 0x2008.
    const _: () = assert!(HCI_LE_SET_ADVERTISING_DATA == 0x2008);
    // §7.8.9: OGF=0x08 OCF=0x000A → 0x200A.
    const _: () = assert!(HCI_LE_SET_ADVERTISING_ENABLE == 0x200A);
    // §7.8.16: OGF=0x08 OCF=0x0011 → 0x2011.
    const _: () = assert!(HCI_LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST == 0x2011);
    // §7.8.22: OGF=0x08 OCF=0x0017 → 0x2017.
    const _: () = assert!(HCI_LE_ENCRYPT == 0x2017);
    // §7.8.23: OGF=0x08 OCF=0x0018 → 0x2018.
    const _: () = assert!(HCI_LE_RAND == 0x2018);
    // §7.8.61: OGF=0x08 OCF=0x003E → 0x203E.
    const _: () = assert!(HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS == 0x203E);
    // §7.8.62: OGF=0x08 OCF=0x003F → 0x203F.
    const _: () = assert!(HCI_LE_SET_PERIODIC_ADVERTISING_DATA == 0x203F);
    // §7.8.63: OGF=0x08 OCF=0x0040 → 0x2040.
    const _: () = assert!(HCI_LE_SET_PERIODIC_ADVERTISING_ENABLE == 0x2040);
    // §7.8.67: OGF=0x08 OCF=0x0044 → 0x2044.
    const _: () = assert!(HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC == 0x2044);
    // §7.8.68: OGF=0x08 OCF=0x0045 → 0x2045.
    const _: () = assert!(HCI_LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL == 0x2045);
    // §7.8.69: OGF=0x08 OCF=0x0046 → 0x2046.
    const _: () = assert!(HCI_LE_PERIODIC_ADVERTISING_TERMINATE_SYNC == 0x2046);
    // §7.1.5: OGF=0x01 OCF=0x0005 → 0x0405.
    const _: () = assert!(HCI_CREATE_CONNECTION == 0x0405);
    // §7.1.19: OGF=0x01 OCF=0x0019 → 0x0419.
    const _: () = assert!(HCI_REMOTE_NAME_REQUEST == 0x0419);
    // §7.3.45: OGF=0x03 OCF=0x0045 → 0x0C45.
    const _: () = assert!(HCI_WRITE_INQUIRY_MODE == 0x0C45);
    // §7.4.5: OGF=0x04 OCF=0x0005 → 0x1005.
    const _: () = assert!(HCI_READ_BUFFER_SIZE == 0x1005);
    // §7.4.14: OGF=0x04 OCF=0x0014 → 0x1014.
    const _: () = assert!(HCI_READ_LOCAL_NAME == 0x1014);
    // §7.4.23: OGF=0x04 OCF=0x0023 → 0x1023.
    const _: () = assert!(HCI_READ_CLASS_OF_DEVICE == 0x1023);
    // §7.3.31: OGF=0x03 OCF=0x0020 → 0x0C20.
    const _: () = assert!(HCI_WRITE_AUTHENTICATION_ENABLE == 0x0C20);
    // §7.3.44: OGF=0x03 OCF=0x0047 → 0x0C47.
    const _: () = assert!(HCI_WRITE_PAGE_SCAN_TYPE == 0x0C47);
    // §7.3.66: OGF=0x03 OCF=0x006D → 0x0C6D.
    const _: () = assert!(HCI_WRITE_LE_HOST_SUPPORT == 0x0C6D);
    // §7.3.76: OGF=0x03 OCF=0x007A → 0x0C7A.
    const _: () = assert!(HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT == 0x0C7A);
}
