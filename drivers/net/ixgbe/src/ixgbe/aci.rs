//! ACI (Admin Command Interface) transport for the E610.
//!
//! Grounding: Linux ixgbe @ cbbddb6 (`ixgbe_e610.c`
//! `ixgbe_aci_send_cmd_execute` / `ixgbe_aci_send_cmd` /
//! `ixgbe_aci_get_phy_caps` / `ixgbe_aci_set_phy_cfg` /
//! `ixgbe_aci_set_link_restart_an` /
//! `ixgbe_aci_get_link_info` / `ixgbe_aci_list_caps`,
//! `ixgbe_type_e610.h` register/opcode/flag defines, and
//! `include/linux/net/intel/libie/adminq.h` for the
//! descriptor layout and the capability-element struct).
//! ⚠️ Every address, opcode, and bit below is
//! Linux-transcribed: no public E610 datasheet is
//! available, so the ACI surface cannot be
//! datasheet-grounded. The module says so plainly wherever
//! a value has no datasheet source.
//!
//! The interface is CSR-based, no DMA: the PF writes the
//! 32-byte descriptor to PF_HIDA, the indirect buffer (if
//! any) to PF_HIBA, sets PF_HICR.C, and polls for SV (sync
//! completion) or EV (async/event). The descriptor and the
//! buffer are transferred as dwords; the buffer's byte
//! length is carried in the descriptor's datalen field.
//!
//! Two NARF deviations from Linux, both deliberate:
//! - Timeouts: Linux polls the sync phase for up to 100 s
//!   and the async phase for up to 150 s. This module takes
//!   caller deadlines; the live path uses 10 s / 30 s wedge
//!   thresholds (the firmware normally answers in
//!   milliseconds — the same judgement as the driver's
//!   100 ms CTRL.RST wedge threshold).
//! - Retry restore: Linux's `ixgbe_aci_send_cmd` restores
//!   the buffer from a copy that only ever held its first
//!   byte (`*buf_cpy = *(u8 *)buf`). This module does not
//!   need a restore at all: the EBUSY check happens before
//!   the descriptor or buffer is touched, so a retried
//!   command still holds its original inputs.

use super::queues::RegBank;

/// PF Host Interface Control Register
/// (Linux-transcribed, `ixgbe_type_e610.h`).
pub const REG_PF_HICR: u64 = 0x0008_2048;
/// PF Host Interface Descriptor Array base
/// (Linux-transcribed). 8 dwords: the request descriptor
/// is written here, the sync response read back here.
pub const REG_PF_HIDA_BASE: u64 = 0x0008_5000;
/// PF Host Interface Descriptor Array 2 base
/// (Linux-transcribed). The async/event response is read
/// back here.
pub const REG_PF_HIDA_2_BASE: u64 = 0x0008_5020;
/// PF Host Interface Buffer Array base
/// (Linux-transcribed). The indirect buffer is written
/// here (RD commands) and read back here (responses).
pub const REG_PF_HIBA_BASE: u64 = 0x0008_4000;

/// PF_HICR: the admin-command interface is enabled.
pub const PF_HICR_EN: u32 = 1 << 0;
/// PF_HICR: a command is in flight (set by SW, cleared by
/// FW).
pub const PF_HICR_C: u32 = 1 << 1;
/// PF_HICR: a valid sync response is in PF_HIDA.
pub const PF_HICR_SV: u32 = 1 << 2;
/// PF_HICR: a valid async/event response is in PF_HIDA_2.
pub const PF_HICR_EV: u32 = 1 << 3;

/// Descriptor size in bytes (`libie_aq_desc`, 32 bytes).
pub const ACI_DESC_SIZE: usize = 32;
/// Descriptor size in dwords.
pub const ACI_DESC_DWORDS: usize = 8;
/// Largest indirect buffer (`ixgbe_type_e610.h`
/// IXGBE_ACI_MAX_BUFFER_SIZE).
pub const ACI_MAX_BUFFER_SIZE: usize = 4096;
/// Large-buffer threshold: a rounded buffer over this
/// size sets the LB flag (`libie` LIBIE_AQ_LG_BUF).
pub const ACI_LG_BUF: usize = 512;

/// Send retry budget (`ixgbe_type_e610.h`
/// IXGBE_ACI_SEND_MAX_EXECUTE).
pub const ACI_SEND_MAX_EXECUTE: u32 = 3;
/// Inter-retry wait inside `aci_send_cmd` (Linux sleeps
/// 10 ms; this module polls PF_HICR.C for up to 10 ms and
/// returns early when it clears).
pub const ACI_SEND_DELAY_MS: u64 = 10;

/// ACI opcodes (`ixgbe_type_e610.h`).
pub const ACI_OPC_GET_VER: u16 = 0x0001;
pub const ACI_OPC_DRIVER_VER: u16 = 0x0002;
pub const ACI_OPC_GET_FW_EVENT: u16 = 0x0014;
pub const ACI_OPC_LIST_FUNC_CAPS: u16 = 0x000A;
pub const ACI_OPC_LIST_DEV_CAPS: u16 = 0x000B;
pub const ACI_OPC_GET_PHY_CAPS: u16 = 0x0600;
pub const ACI_OPC_SET_PHY_CFG: u16 = 0x0601;
pub const ACI_OPC_RESTART_AN: u16 = 0x0605;
pub const ACI_OPC_GET_LINK_STATUS: u16 = 0x0607;
pub const ACI_OPC_SET_EVENT_MASK: u16 = 0x0613;

/// Descriptor flags (`libie` LIBIE_AQ_FLAG_*).
pub const ACI_FLAG_DD: u16 = 1 << 0;
pub const ACI_FLAG_CMP: u16 = 1 << 1;
pub const ACI_FLAG_ERR: u16 = 1 << 2;
pub const ACI_FLAG_VFE: u16 = 1 << 3;
pub const ACI_FLAG_LB: u16 = 1 << 9;
pub const ACI_FLAG_RD: u16 = 1 << 10;
pub const ACI_FLAG_VFC: u16 = 1 << 11;
pub const ACI_FLAG_BUF: u16 = 1 << 12;
pub const ACI_FLAG_SI: u16 = 1 << 13;
pub const ACI_FLAG_EI: u16 = 1 << 14;
pub const ACI_FLAG_FE: u16 = 1 << 15;

/// Admin-command return codes (`libie` LIBIE_AQ_RC_*).
pub const ACI_RC_OK: u16 = 0;
pub const ACI_RC_EBUSY: u16 = 12;
pub const ACI_RC_EINVAL: u16 = 14;

/// get_link_status LSE values (`ixgbe_type_e610.h`).
pub const ACI_LSE_NOP: u16 = 0x0;
pub const ACI_LSE_DIS: u16 = 0x2;
pub const ACI_LSE_ENA: u16 = 0x3;
pub const ACI_LSE_IS_ENABLED: u16 = 0x1;

/// restart_an command flags (`ixgbe_type_e610.h`).
pub const ACI_RESTART_AN_LINK_RESTART: u8 = 1 << 1;
pub const ACI_RESTART_AN_LINK_ENABLE: u8 = 1 << 2;

/// get_phy_caps report modes (`ixgbe_type_e610.h`).
pub const ACI_REPORT_TOPO_CAP_NO_MEDIA: u8 = 0;
pub const ACI_REPORT_TOPO_CAP_MEDIA: u8 = 1 << 1;
pub const ACI_REPORT_ACTIVE_CFG: u8 = 1 << 2;
pub const ACI_REPORT_DFLT_CFG: u8 = 1 << 3;
pub const ACI_REPORT_MODE_M: u8 = 0x0E;
/// get_phy_caps RQM bit (`ixgbe_type_e610.h`
/// IXGBE_ACI_GET_PHY_RQM).
pub const ACI_GET_PHY_RQM: u16 = 1 << 0;

/// set_phy_cfg capability mask: only these caps bits may
/// be turned on (`ixgbe_type_e610.h`
/// IXGBE_ACI_PHY_ENA_VALID_MASK).
pub const ACI_PHY_ENA_VALID_MASK: u8 = 0xEF;

/// get_link_status link_info bits
/// (`ixgbe_type_e610.h`, `ixgbe_aci_cmd_get_link_status_data`).
pub const ACI_LINK_UP: u8 = 1 << 0;
pub const ACI_MEDIA_AVAILABLE: u8 = 1 << 6;
/// get_link_status eee_status bits.
pub const ACI_LINK_EEE_ENABLED: u8 = 1 << 2;
pub const ACI_LINK_EEE_ACTIVE: u8 = 1 << 3;

/// Capability-list element id for EEE (`libie`
/// LIBIE_AQC_CAPS_EEE).
pub const ACI_CAPS_EEE: u16 = 0x009B;

/// get_phy_caps_data, in bytes (`ixgbe_type_e610.h`
/// `ixgbe_aci_cmd_get_phy_caps_data`, 560 bytes).
pub const PHY_CAPS_DATA_LEN: usize = 560;
/// get_link_status_data, in bytes (`ixgbe_type_e610.h`
/// `ixgbe_aci_cmd_get_link_status_data`, 32 bytes).
pub const LINK_STATUS_DATA_LEN: usize = 32;
/// set_phy_cfg_data, in bytes (`ixgbe_type_e610.h`
/// `ixgbe_aci_cmd_set_phy_cfg_data`, 26 bytes; 24 without
/// the trailing eee_entry_delay field).
pub const SET_PHY_CFG_DATA_LEN: usize = 26;
pub const SET_PHY_CFG_DATA_LEN_NO_EEE: usize = 24;

/// ACI transport failures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AciError {
    /// Buffer over the 4096-byte cap, or a buffer/length
    /// mismatch (buffer present with length 0, or absent
    /// with a non-zero length).
    BadLength,
    /// PF_HICR.EN clear: the interface is not enabled.
    NotEnabled,
    /// PF_HICR.C set on entry: another command is in
    /// flight (Linux `-EBUSY`).
    Busy,
    /// PF_HICR.C still set after the poll (Linux `-ETIME`).
    Timeout,
    /// Neither SV nor EV set after completion.
    NoStatus,
    /// The response descriptor's opcode is not the
    /// request's (except for get_fw_event 0x0014, whose
    /// async response legitimately carries an event
    /// opcode).
    OpcodeMismatch,
    /// The response descriptor's retval is non-zero
    /// (Linux's `last_status`).
    Firmware,
}

impl AciError {
    /// Static message for the `IxgbeError::Other` mapping.
    pub fn as_str(self) -> &'static str {
        match self {
            AciError::BadLength => "aci bad length",
            AciError::NotEnabled => "aci not enabled",
            AciError::Busy => "aci busy",
            AciError::Timeout => "aci timeout",
            AciError::NoStatus => "aci no status",
            AciError::OpcodeMismatch => "aci opcode mismatch",
            AciError::Firmware => "aci firmware error",
        }
    }
}

/// An indirect ACI buffer: `data[..len]` is transferred
/// via PF_HIBA. `host_to_fw` sets the RD flag (the host
/// writes the buffer to the firmware, as set_phy_cfg
/// does); without it the buffer is firmware-to-host (as
/// get_phy_caps / get_link_status do).
#[derive(Debug)]
pub struct AciBuf<'a> {
    pub data: &'a mut [u8],
    pub len: usize,
    pub host_to_fw: bool,
}

/// Build a fresh direct-command descriptor (Linux
/// `ixgbe_fill_dflt_direct_cmd_desc`): zeroed, opcode in
/// place, SI flag set. Layout (`libie_aq_desc`): flags
/// LE16 @0, opcode LE16 @2, datalen LE16 @4, retval LE16
/// @6, cookie_high LE32 @8, cookie_low LE32 @12, params
/// 16 bytes @16. As dwords: d0 = opcode<<16 | flags,
/// d1 = retval<<16 | datalen, d2/d3 = cookies, d4..d7 =
/// params.
pub fn desc_new(opcode: u16) -> [u32; ACI_DESC_DWORDS] {
    let mut desc = [0u32; ACI_DESC_DWORDS];
    desc[0] = ((opcode as u32) << 16) | (ACI_FLAG_SI as u32);
    desc
}

/// Descriptor opcode field.
pub fn desc_opcode(desc: &[u32; ACI_DESC_DWORDS]) -> u16 {
    (desc[0] >> 16) as u16
}

/// Descriptor flags field.
pub fn desc_flags(desc: &[u32; ACI_DESC_DWORDS]) -> u16 {
    (desc[0] & 0xFFFF) as u16
}

/// Descriptor datalen field (buffer bytes).
pub fn desc_datalen(desc: &[u32; ACI_DESC_DWORDS]) -> u16 {
    (desc[1] & 0xFFFF) as u16
}

/// Descriptor retval field.
pub fn desc_retval(desc: &[u32; ACI_DESC_DWORDS]) -> u16 {
    (desc[1] >> 16) as u16
}

/// Whether `opcode` is one `ixgbe_aci_send_cmd` retries
/// on EBUSY (Linux `ixgbe_should_retry_aci_send_cmd_execute`:
/// get_phy_caps, get_link_status, get_link_topo, and
/// disable_rxen — the last two are not built in this
/// module, so only the first two can occur here).
pub fn should_retry(opcode: u16) -> bool {
    matches!(opcode, ACI_OPC_GET_PHY_CAPS | ACI_OPC_GET_LINK_STATUS)
}

/// Execute one ACI command (Linux
/// `ixgbe_aci_send_cmd_execute`): validate, transfer the
/// buffer (RD only), write the descriptor, set C, poll
/// sync (SV or !C) then async (EV or !C), read the
/// response descriptor back, check opcode + retval, read
/// the response buffer back. The descriptor is updated in
/// place with the response. `buf` may be `None` for
/// direct commands.
pub fn aci_execute<B: RegBank>(
    bank: &mut B,
    desc: &mut [u32; ACI_DESC_DWORDS],
    buf: Option<&mut AciBuf<'_>>,
    sync_deadline: narf_time::Deadline,
    async_deadline: narf_time::Deadline,
) -> Result<(), AciError> {
    let opcode = desc_opcode(desc);
    let hicr = bank.read32(REG_PF_HICR);
    if hicr & PF_HICR_EN == 0 {
        return Err(AciError::NotEnabled);
    }
    if hicr & PF_HICR_C != 0 {
        return Err(AciError::Busy);
    }
    // Validate the buffer before touching any register:
    // a present buffer needs a non-zero length within the
    // cap, and an absent buffer needs length 0. Linux
    // sets the BUF flag from the buffer pointer, then
    // requires the two to agree.
    let (buf_len, host_to_fw) = match &buf {
        Some(b) => {
            if b.len == 0 || b.len > ACI_MAX_BUFFER_SIZE || b.len > b.data.len() {
                return Err(AciError::BadLength);
            }
            (b.len, b.host_to_fw)
        }
        None => (0, false),
    };
    if buf.is_some() {
        desc[0] |= ACI_FLAG_BUF as u32;
    }
    if buf_len > 0 {
        let rounded = buf_len.div_ceil(4) * 4;
        if rounded > ACI_LG_BUF {
            desc[0] |= ACI_FLAG_LB as u32;
        }
        desc[1] = (desc[1] & 0xFFFF_0000) | (buf_len as u32);
        if host_to_fw {
            desc[0] |= ACI_FLAG_RD as u32;
            if let Some(b) = buf.as_ref() {
                write_hiba(bank, &b.data[..buf_len]);
            }
        }
    }
    for (i, word) in desc.iter().enumerate() {
        bank.write32(REG_PF_HIDA_BASE + (i as u64) * 4, *word);
    }
    // Set C, clear SV and EV — this starts the firmware.
    let hicr = (bank.read32(REG_PF_HICR) | PF_HICR_C) & !(PF_HICR_SV | PF_HICR_EV);
    bank.write32(REG_PF_HICR, hicr);
    // Sync poll: SV set or C clear.
    let _ = narf_scheduler::responsive_spin_until(
        || {
            let h = bank.read32(REG_PF_HICR);
            h & PF_HICR_SV != 0 || h & PF_HICR_C == 0
        },
        sync_deadline,
    );
    // Async poll: EV set or C clear. (Runs even after a
    // sync completion, where C-clear exits it at once.)
    let _ = narf_scheduler::responsive_spin_until(
        || {
            let h = bank.read32(REG_PF_HICR);
            h & PF_HICR_EV != 0 || h & PF_HICR_C == 0
        },
        async_deadline,
    );
    let hicr = bank.read32(REG_PF_HICR);
    // The sync response lives in PF_HIDA; an async/event
    // response (EV set, C clear) overwrites it from
    // PF_HIDA_2 — exactly Linux's order.
    if hicr & PF_HICR_SV != 0 {
        for (i, slot) in desc.iter_mut().enumerate() {
            *slot = bank.read32(REG_PF_HIDA_BASE + (i as u64) * 4);
        }
    }
    if hicr & PF_HICR_EV != 0 && hicr & PF_HICR_C == 0 {
        for (i, slot) in desc.iter_mut().enumerate() {
            *slot = bank.read32(REG_PF_HIDA_2_BASE + (i as u64) * 4);
        }
    }
    if hicr & PF_HICR_C != 0 {
        return Err(AciError::Timeout);
    }
    if hicr & PF_HICR_SV == 0 && hicr & PF_HICR_EV == 0 {
        return Err(AciError::NoStatus);
    }
    if desc_opcode(desc) != opcode && opcode != ACI_OPC_GET_FW_EVENT {
        return Err(AciError::OpcodeMismatch);
    }
    if desc_retval(desc) != ACI_RC_OK {
        return Err(AciError::Firmware);
    }
    if let Some(b) = buf {
        read_hiba(bank, &mut b.data[..buf_len]);
    }
    Ok(())
}

/// Write `bytes` to the PF_HIBA registers as LE dwords,
/// with a partial tail dword (Linux's buf_tail handling).
fn write_hiba<B: RegBank>(bank: &mut B, bytes: &[u8]) {
    let full = bytes.len() / 4;
    for i in 0..full {
        bank.write32(
            REG_PF_HIBA_BASE + (i as u64) * 4,
            u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]),
        );
    }
    let tail = bytes.len() % 4;
    if tail > 0 {
        let mut word = [0u8; 4];
        word[..tail].copy_from_slice(&bytes[full * 4..]);
        bank.write32(
            REG_PF_HIBA_BASE + (full as u64) * 4,
            u32::from_le_bytes(word),
        );
    }
}

/// Read `bytes.len()` bytes back from the PF_HIBA
/// registers (LE dwords, partial tail dword).
fn read_hiba<B: RegBank>(bank: &mut B, bytes: &mut [u8]) {
    let full = bytes.len() / 4;
    for i in 0..full {
        let word = bank.read32(REG_PF_HIBA_BASE + (i as u64) * 4);
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let tail = bytes.len() % 4;
    if tail > 0 {
        let word = bank.read32(REG_PF_HIBA_BASE + (full as u64) * 4);
        bytes[full * 4..].copy_from_slice(&word.to_le_bytes()[..tail]);
    }
}

/// Send one ACI command with Linux's EBUSY retry (Linux
/// `ixgbe_aci_send_cmd`): up to `ACI_SEND_MAX_EXECUTE`
/// attempts for retryable opcodes, waiting up to 10 ms
/// for C to clear between attempts. Other errors return
/// at once. The descriptor and buffer are untouched on
/// the EBUSY path (the check precedes any mutation), so
/// no restore is needed between attempts.
pub fn aci_send_cmd<B: RegBank>(
    bank: &mut B,
    desc: &mut [u32; ACI_DESC_DWORDS],
    mut buf: Option<&mut AciBuf<'_>>,
    sync_deadline: narf_time::Deadline,
    async_deadline: narf_time::Deadline,
) -> Result<(), AciError> {
    let opcode = desc_opcode(desc);
    let retryable = should_retry(opcode);
    for _ in 0..ACI_SEND_MAX_EXECUTE {
        // `as_deref_mut` re-borrows the buffer for each
        // attempt; the EBUSY path leaves it untouched, so
        // no restore is needed between attempts.
        match aci_execute(
            bank,
            desc,
            buf.as_deref_mut(),
            sync_deadline,
            async_deadline,
        ) {
            Ok(()) => return Ok(()),
            Err(AciError::Busy) if retryable => {
                let _ = narf_scheduler::responsive_spin_until(
                    || bank.read32(REG_PF_HICR) & PF_HICR_C == 0,
                    narf_time::Deadline::after_ms(ACI_SEND_DELAY_MS),
                );
            }
            Err(e) => return Err(e),
        }
    }
    Err(AciError::Busy)
}

/// get_phy_caps command (Linux `ixgbe_aci_get_phy_caps`):
/// param0 carries RQM (if qualified modules are wanted)
/// and the report mode; lport_num is left 0, as Linux
/// leaves it. Returns the descriptor; the caller supplies
/// the `PHY_CAPS_DATA_LEN`-byte response buffer.
pub fn get_phy_caps_desc(qual_mods: bool, report_mode: u8) -> [u32; ACI_DESC_DWORDS] {
    let mut desc = desc_new(ACI_OPC_GET_PHY_CAPS);
    let mut param0: u16 = (report_mode & ACI_REPORT_MODE_M) as u16;
    if qual_mods {
        param0 |= ACI_GET_PHY_RQM;
    }
    desc[4] = (param0 as u32) << 16;
    desc
}

/// set_phy_cfg command (Linux `ixgbe_aci_set_phy_cfg`):
/// lport_num in byte0, RD flag set; the caller supplies
/// the cfg buffer (`SET_PHY_CFG_DATA_LEN` bytes, or
/// `SET_PHY_CFG_DATA_LEN_NO_EEE` when the firmware lacks
/// EEE support).
pub fn set_phy_cfg_desc(lport: u8) -> [u32; ACI_DESC_DWORDS] {
    let mut desc = desc_new(ACI_OPC_SET_PHY_CFG);
    desc[4] = lport as u32;
    desc
}

/// get_link_status command (Linux
/// `ixgbe_aci_get_link_info`): lport_num in byte0,
/// cmd_flags (LSE_ENA / LSE_DIS) in bytes 2–3.
pub fn get_link_status_desc(ena_lse: bool, lport: u8) -> [u32; ACI_DESC_DWORDS] {
    let mut desc = desc_new(ACI_OPC_GET_LINK_STATUS);
    let flags = if ena_lse { ACI_LSE_ENA } else { ACI_LSE_DIS };
    desc[4] = (lport as u32) | ((flags as u32) << 16);
    desc
}

/// restart_an command (Linux
/// `ixgbe_aci_set_link_restart_an`): lport_num in byte0,
/// cmd_flags in byte2 — LINK_RESTART always, LINK_ENABLE
/// when the link should come up.
pub fn restart_an_desc(ena_link: bool, lport: u8) -> [u32; ACI_DESC_DWORDS] {
    let mut desc = desc_new(ACI_OPC_RESTART_AN);
    let mut flags = ACI_RESTART_AN_LINK_RESTART;
    if ena_link {
        flags |= ACI_RESTART_AN_LINK_ENABLE;
    }
    desc[4] = (lport as u32) | ((flags as u32) << 16);
    desc
}

/// list_dev_caps command (Linux `ixgbe_aci_list_caps`,
/// opcode 0x000B): no parameters; the caller supplies the
/// `ACI_MAX_BUFFER_SIZE`-byte response buffer.
pub fn list_dev_caps_desc() -> [u32; ACI_DESC_DWORDS] {
    desc_new(ACI_OPC_LIST_DEV_CAPS)
}

/// The PHY capabilities Linux's `ixgbe_setup_eee_e610`
/// copies into the set-PHY-config command (plus the EEE
/// fields the status path reports).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PhyCaps {
    pub phy_type_low: u64,
    pub phy_type_high: u64,
    pub caps: u8,
    pub low_power_ctrl_an: u8,
    pub eee_cap: u16,
    pub eeer_value: u16,
    pub link_fec_opt: u8,
    pub module_compliance_enforcement: u8,
    pub eee_entry_delay: u16,
}

/// Parse a get_phy_caps_data buffer (560 bytes; only the
/// first 48 bytes carry the fields this module needs).
/// Layout (`ixgbe_type_e610.h`
/// `ixgbe_aci_cmd_get_phy_caps_data`): phy_type_low LE64
/// @0, phy_type_high LE64 @8, caps u8 @16,
/// low_power_ctrl_an u8 @17, eee_cap LE16 @18, eeer_value
/// LE16 @20, phy_id_oui[4] @22, phy_fw_ver[8] @26,
/// link_fec_options u8 @34, module_compliance_enforcement
/// u8 @35, extended_compliance_code u8 @36, module_type[3]
/// @37, qualified_module_count u8 @40, rsvd2 u8 @41,
/// eee_entry_delay LE16 @42, rsvd3[4] @44,
/// qual_modules[16] @48.
pub fn parse_phy_caps(buf: &[u8]) -> Result<PhyCaps, AciError> {
    if buf.len() < 48 {
        return Err(AciError::BadLength);
    }
    let le64 = |off: usize| u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
    let le16 = |off: usize| u16::from_le_bytes(buf[off..off + 2].try_into().unwrap());
    Ok(PhyCaps {
        phy_type_low: le64(0),
        phy_type_high: le64(8),
        caps: buf[16],
        low_power_ctrl_an: buf[17],
        eee_cap: le16(18),
        eeer_value: le16(20),
        link_fec_opt: buf[34],
        module_compliance_enforcement: buf[35],
        eee_entry_delay: le16(42),
    })
}

/// Build a set_phy_cfg_data buffer from PHY caps (Linux
/// `ixgbe_copy_phy_caps_to_cfg` + `ixgbe_aci_set_phy_cfg`):
/// the copied fields, caps masked to
/// `ACI_PHY_ENA_VALID_MASK` and the LINK + AUTO_LINK_UPDT
/// bits ORed in by the caller via `caps_extra`, eee_cap
/// from the advertised set. Layout (`ixgbe_type_e610.h`
/// `ixgbe_aci_cmd_set_phy_cfg_data`, __packed):
/// phy_type_low LE64 @0, phy_type_high LE64 @8, caps u8
/// @16, low_power_ctrl_an u8 @17, eee_cap LE16 @18,
/// eeer_value LE16 @20, link_fec_opt u8 @22,
/// module_compliance_enforcement u8 @23, eee_entry_delay
/// LE16 @24. When `include_eee_field` is false the buffer
/// is 24 bytes (the trailing field is omitted — the
/// firmware without EEE support expects the short form).
pub fn build_set_phy_cfg(
    caps: &PhyCaps,
    caps_extra: u8,
    eee_cap: u16,
    include_eee_field: bool,
) -> [u8; SET_PHY_CFG_DATA_LEN] {
    let mut buf = [0u8; SET_PHY_CFG_DATA_LEN];
    buf[0..8].copy_from_slice(&caps.phy_type_low.to_le_bytes());
    buf[8..16].copy_from_slice(&caps.phy_type_high.to_le_bytes());
    buf[16] = (caps.caps | caps_extra) & ACI_PHY_ENA_VALID_MASK;
    buf[17] = caps.low_power_ctrl_an;
    buf[18..20].copy_from_slice(&eee_cap.to_le_bytes());
    buf[20..22].copy_from_slice(&caps.eeer_value.to_le_bytes());
    buf[22] = caps.link_fec_opt;
    buf[23] = caps.module_compliance_enforcement;
    if include_eee_field {
        buf[24..26].copy_from_slice(&caps.eee_entry_delay.to_le_bytes());
    }
    buf
}

/// The link status `ixgbe_aci_get_link_info` reports (the
/// fields the EEE path uses; the full 32-byte struct also
/// carries topology, FEC, and PHY-type fields).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkStatus {
    pub link_info: u8,
    pub eee_status: u8,
    pub link_speed: u16,
}

/// Parse a get_link_status_data buffer (32 bytes).
/// Layout (`ixgbe_type_e610.h`
/// `ixgbe_aci_cmd_get_link_status_data`): topo_media_conflict
/// u8 @0, link_cfg_err u8 @1, link_info u8 @2, an_info u8
/// @3, ext_info u8 @4, lb_status u8 @5, max_frame_size
/// LE16 @6, cfg u8 @8, power_desc u8 @9, link_speed LE16
/// @10, reserved3 LE16 @12, eee_status u8 @14, reserved4
/// u8 @15, phy_type_low LE64 @16, phy_type_high LE64 @24.
pub fn parse_link_status(buf: &[u8]) -> Result<LinkStatus, AciError> {
    if buf.len() < LINK_STATUS_DATA_LEN {
        return Err(AciError::BadLength);
    }
    Ok(LinkStatus {
        link_info: buf[2],
        eee_status: buf[14],
        link_speed: u16::from_le_bytes(buf[10..12].try_into().unwrap()),
    })
}

/// Read the device capabilities and report whether the
/// firmware supports EEE (Linux `ixgbe_discover_dev_caps`
/// + `ixgbe_parse_dev_caps`: the list_dev_caps command
///   returns capability elements — 32 bytes each (`libie`
///   `libie_aqc_list_caps_elem`: cap LE16 @0, major_ver u8
///   @2, minor_ver u8 @3, number LE32 @4, logical_id LE32
///   @8, phys_id LE32 @12, rsvd 16 bytes) — and the EEE
///   element (`ACI_CAPS_EEE`) carries eee_support in its
///   number field). `buf` must hold `ACI_MAX_BUFFER_SIZE`
///   bytes; the returned count comes from the response
///   descriptor's params, so a short buffer reports
///   `BadLength` rather than scanning garbage.
pub fn find_dev_cap_eee<B: RegBank>(
    bank: &mut B,
    buf: &mut [u8],
    sync_deadline: narf_time::Deadline,
    async_deadline: narf_time::Deadline,
) -> Result<bool, AciError> {
    if buf.len() < ACI_MAX_BUFFER_SIZE {
        return Err(AciError::BadLength);
    }
    let mut desc = list_dev_caps_desc();
    let mut wrapper = AciBuf {
        data: buf,
        len: ACI_MAX_BUFFER_SIZE,
        host_to_fw: false,
    };
    aci_send_cmd(
        bank,
        &mut desc,
        Some(&mut wrapper),
        sync_deadline,
        async_deadline,
    )?;
    // The element count is the list_caps command's params
    // word 1 (count LE32 at params offset 4).
    let count = desc[5] as usize;
    let max = ACI_MAX_BUFFER_SIZE / 32;
    if count > max {
        return Err(AciError::BadLength);
    }
    for i in 0..count {
        let off = i * 32;
        let cap = u16::from_le_bytes(wrapper.data[off..off + 2].try_into().unwrap());
        if cap == ACI_CAPS_EEE {
            let number = u32::from_le_bytes(wrapper.data[off + 4..off + 8].try_into().unwrap());
            return Ok(number != 0);
        }
    }
    Ok(false)
}
