//! i40e VSI — the switch element a queue set actually belongs to.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 (GPL-2.0; NARF is GPL-2.0-or-later so adaptation
//! is permitted):
//!
//! - `i40e_adminq_cmd.h` — `i40e_aqc_switch_seid`,
//!   `i40e_aqc_get_switch_config_header_resp`,
//!   `i40e_aqc_switch_config_element_resp`,
//!   `i40e_aqc_vsi_properties_data`, `i40e_aqc_macvlan`,
//!   `i40e_aqc_add_macvlan_element_data`.
//! - `i40e_main.c` — `i40e_fetch_switch_configuration` /
//!   `i40e_setup_pf_switch` (how the main VSI's SEID is discovered),
//!   `i40e_add_vsi`'s `I40E_VSI_MAIN` arm.
//! - `i40e_common.c` — `i40e_aq_set_link_restart_an`.
//!
//! ## Why there is no "create VSI" here
//!
//! A PF's main VSI already exists: firmware builds it as part of
//! device initialisation, before the driver is loaded. Linux does
//! **not** call `add_vsi` (0x0210) for it — it walks the switch
//! configuration to find the VSI element, then reads the existing
//! context back with `get_vsi_parameters` (0x0212). This module does
//! the same. `add_vsi` is for the *extra* VSIs a driver creates
//! (VMDq, flow director, SR-IOV VFs), none of which are in scope.
//!
//! The one field the data path genuinely needs out of that read is
//! `qs_handle[0]`: the TX queue context's `rdylist` must name the
//! firmware-allocated arbitration queue set for the traffic class, or
//! the scheduler will not service the queue.

use alloc::vec::Vec;

use super::{AqOpcode, I40eError, I40eNic};

// ── Switch configuration (0x0200) ───────────────────────────────────

/// `struct i40e_aqc_get_switch_config_header_resp` — 16 bytes, then
/// the element array.
pub const SWITCH_CONFIG_HEADER_BYTES: usize = 16;
/// `struct i40e_aqc_switch_config_element_resp` — 16 bytes each.
pub const SWITCH_CONFIG_ELEMENT_BYTES: usize = 16;

/// `I40E_SWITCH_ELEMENT_TYPE_MAC`.
pub const ELEMENT_TYPE_MAC: u8 = 1;
/// `I40E_SWITCH_ELEMENT_TYPE_PF`.
pub const ELEMENT_TYPE_PF: u8 = 2;
/// `I40E_SWITCH_ELEMENT_TYPE_VF`.
pub const ELEMENT_TYPE_VF: u8 = 3;
/// `I40E_SWITCH_ELEMENT_TYPE_VEB`.
pub const ELEMENT_TYPE_VEB: u8 = 17;
/// `I40E_SWITCH_ELEMENT_TYPE_VSI`.
pub const ELEMENT_TYPE_VSI: u8 = 19;

/// One decoded switch element.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SwitchElement {
    /// `I40E_SWITCH_ELEMENT_TYPE_*`.
    pub element_type: u8,
    pub revision: u8,
    /// This element's switch id.
    pub seid: u16,
    /// The element above it.
    pub uplink_seid: u16,
    /// The element below it.
    pub downlink_seid: u16,
    pub connection_type: u8,
    pub element_info: u16,
}

impl SwitchElement {
    /// Decode one 16-byte element.
    ///
    /// Layout: `element_type:u8`, `revision:u8`, `seid:le16`,
    /// `uplink_seid:le16`, `downlink_seid:le16`, `reserved[3]`,
    /// `connection_type:u8`, `scheduler_id:le16`, `element_info:le16`.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < SWITCH_CONFIG_ELEMENT_BYTES {
            return None;
        }
        Some(Self {
            element_type: buf[0],
            revision: buf[1],
            seid: u16::from_le_bytes([buf[2], buf[3]]),
            uplink_seid: u16::from_le_bytes([buf[4], buf[5]]),
            downlink_seid: u16::from_le_bytes([buf[6], buf[7]]),
            connection_type: buf[11],
            element_info: u16::from_le_bytes([buf[14], buf[15]]),
        })
    }
}

/// Decoded switch configuration: the header counts plus the elements.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SwitchConfig {
    /// Elements in this response.
    pub num_reported: u16,
    /// Elements the switch has in total.
    pub num_total: u16,
    pub elements: Vec<SwitchElement>,
}

impl SwitchConfig {
    /// Decode a `get_switch_config` response buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < SWITCH_CONFIG_HEADER_BYTES {
            return None;
        }
        let num_reported = u16::from_le_bytes([buf[0], buf[1]]);
        let num_total = u16::from_le_bytes([buf[2], buf[3]]);
        let mut elements = Vec::with_capacity(num_reported as usize);
        for i in 0..num_reported as usize {
            let off = SWITCH_CONFIG_HEADER_BYTES + i * SWITCH_CONFIG_ELEMENT_BYTES;
            match buf.get(off..off + SWITCH_CONFIG_ELEMENT_BYTES) {
                Some(slice) => match SwitchElement::parse(slice) {
                    Some(e) => elements.push(e),
                    None => break,
                },
                // Firmware reported more elements than it sent. Keep
                // what arrived rather than discarding the response.
                None => break,
            }
        }
        Some(Self {
            num_reported,
            num_total,
            elements,
        })
    }

    /// The PF's main VSI element, if the walk found exactly one.
    ///
    /// Linux only trusts this immediately after a reset, when the
    /// switch holds a single VSI and it must be the PF's. If more
    /// than one is reported, something else has already created VSIs
    /// and picking one would be a guess.
    pub fn main_vsi(&self) -> Option<SwitchElement> {
        let mut found = None;
        for e in &self.elements {
            if e.element_type == ELEMENT_TYPE_VSI {
                if found.is_some() {
                    return None;
                }
                found = Some(*e);
            }
        }
        found
    }
}

// ── VSI properties (0x0212) ─────────────────────────────────────────

/// `struct i40e_aqc_vsi_properties_data` is 128 bytes; the first 96
/// are written by software and the rest is the response section.
pub const VSI_PROPERTIES_BYTES: usize = 128;

/// Byte offset of `valid_sections`.
pub const VSI_OFF_VALID_SECTIONS: usize = 0;
/// Byte offset of `switch_id`.
pub const VSI_OFF_SWITCH_ID: usize = 2;
/// Byte offset of `mapping_flags`.
pub const VSI_OFF_MAPPING_FLAGS: usize = 28;
/// Byte offset of `queue_mapping[0]`.
pub const VSI_OFF_QUEUE_MAPPING: usize = 30;
/// Byte offset of `tc_mapping[0]`.
pub const VSI_OFF_TC_MAPPING: usize = 62;
/// Byte offset of `qs_handle[0]` — start of the response section.
pub const VSI_OFF_QS_HANDLE: usize = 96;
/// Byte offset of `stat_counter_idx`.
pub const VSI_OFF_STAT_COUNTER_IDX: usize = 112;
/// Byte offset of `sched_id`.
pub const VSI_OFF_SCHED_ID: usize = 114;

/// `I40E_AQ_VSI_QUE_MAP_CONTIG` — `queue_mapping[0]` is the first
/// queue and the TC map supplies the count.
pub const VSI_QUE_MAP_CONTIG: u16 = 0x0;
/// `I40E_AQ_VSI_QUE_MAP_NONCONTIG` — each entry names a queue.
pub const VSI_QUE_MAP_NONCONTIG: u16 = 0x1;

/// `I40E_AQ_VSI_TC_QUE_OFFSET_SHIFT`.
pub const VSI_TC_QUE_OFFSET_SHIFT: u16 = 0;
/// `I40E_AQ_VSI_TC_QUE_NUMBER_SHIFT` — log2 of the queue count for
/// the TC, *not* the count itself.
pub const VSI_TC_QUE_NUMBER_SHIFT: u16 = 9;

/// The parts of a VSI's context this driver reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VsiParams {
    /// Switch element id.
    pub seid: u16,
    /// VSI number within the switch.
    pub vsi_number: u16,
    /// `mapping_flags`.
    pub mapping_flags: u16,
    /// `queue_mapping[0]`.
    pub queue_mapping_0: u16,
    /// `tc_mapping[0]`.
    pub tc_mapping_0: u16,
    /// `qs_handle[0]` — the TX arbitration queue set for TC0.
    pub qs_handle_0: u16,
    /// The raw 128-byte context, kept so an update path can modify
    /// one section without inventing the rest.
    pub raw: [u8; VSI_PROPERTIES_BYTES],
}

impl Default for VsiParams {
    // `[u8; 128]` has no `Default` impl (the blanket one stops at 32
    // elements), so the derive cannot be used.
    fn default() -> Self {
        Self {
            seid: 0,
            vsi_number: 0,
            mapping_flags: 0,
            queue_mapping_0: 0,
            tc_mapping_0: 0,
            qs_handle_0: 0,
            raw: [0u8; VSI_PROPERTIES_BYTES],
        }
    }
}

impl VsiParams {
    /// `true` when the VSI uses contiguous queue mapping, which is
    /// what makes `queue_mapping[0]` the base queue.
    pub const fn is_contiguous(&self) -> bool {
        self.mapping_flags & VSI_QUE_MAP_NONCONTIG == 0
    }

    /// First queue of TC0 relative to the VSI's queue base.
    pub const fn tc0_queue_offset(&self) -> u16 {
        (self.tc_mapping_0 >> VSI_TC_QUE_OFFSET_SHIFT) & 0x1FF
    }

    /// Number of queues in TC0. The field stores log2 of the count,
    /// so a stored 0 means one queue, not zero queues.
    pub const fn tc0_queue_count(&self) -> u16 {
        1 << ((self.tc_mapping_0 >> VSI_TC_QUE_NUMBER_SHIFT) & 0x7)
    }
}

// ── MAC filters (0x0250) ────────────────────────────────────────────

/// `I40E_AQC_MACVLAN_ADD_PERFECT_MATCH`.
pub const MACVLAN_ADD_PERFECT_MATCH: u16 = 0x0001;
/// `I40E_AQC_MACVLAN_ADD_IGNORE_VLAN`.
pub const MACVLAN_ADD_IGNORE_VLAN: u16 = 0x0004;
/// `I40E_AQC_MACVLAN_ADD_USE_SHARED_MAC`.
pub const MACVLAN_ADD_USE_SHARED_MAC: u16 = 0x0010;
/// `I40E_AQC_MACVLAN_CMD_SEID_VALID`.
pub const MACVLAN_CMD_SEID_VALID: u16 = 0x8000;
/// `I40E_AQC_MM_ERR_NO_RES` — the match_method firmware returns when
/// it has no filter resources left.
pub const MACVLAN_MM_ERR_NO_RES: u8 = 0xFF;

/// `struct i40e_aqc_add_macvlan_element_data` — 16 bytes.
pub const MACVLAN_ELEMENT_BYTES: usize = 16;

/// Encode one `add_macvlan` element.
///
/// Layout: `mac_addr[6]`, `vlan_tag:le16`, `flags:le16`,
/// `queue_number:le16`, `match_method:u8`, `reserved[3]`. The last
/// four bytes are the response section and are sent as zero.
pub fn encode_macvlan_element(mac: [u8; 6], flags: u16, queue: u16) -> [u8; MACVLAN_ELEMENT_BYTES] {
    let mut e = [0u8; MACVLAN_ELEMENT_BYTES];
    e[0..6].copy_from_slice(&mac);
    // vlan_tag stays 0: with IGNORE_VLAN set firmware does not look
    // at it, and this driver does not do VLAN filtering.
    e[8..10].copy_from_slice(&flags.to_le_bytes());
    e[10..12].copy_from_slice(&queue.to_le_bytes());
    e
}

/// The broadcast address, which needs its own filter — a perfect
/// unicast match does not cover it, and without it ARP never
/// reaches the stack.
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

// ── PHY / link (0x0605) ─────────────────────────────────────────────

/// `I40E_AQ_PHY_RESTART_AN`.
pub const PHY_RESTART_AN: u8 = 0x02;
/// `I40E_AQ_PHY_LINK_ENABLE`.
pub const PHY_LINK_ENABLE: u8 = 0x04;

// ── Driver-side operations ──────────────────────────────────────────

impl I40eNic {
    /// `get_switch_config` (0x0200) — indirect.
    pub fn aq_get_switch_config(&self) -> Result<SwitchConfig, I40eError> {
        // Ask for as much as one AQ data buffer holds. Linux pages
        // through with a start_seid cursor; a freshly reset PF
        // reports a handful of elements, far inside one buffer.
        const RESP_LEN: u16 = 1024;
        let mut params = [0u8; 16];
        // `i40e_aqc_switch_seid.seid` doubles as the start cursor;
        // 0 means "from the beginning".
        params[0..2].copy_from_slice(&0u16.to_le_bytes());
        let (buf, _wb) = self.aq_send(AqOpcode::GetSwitchConfig, params, None, RESP_LEN)?;
        SwitchConfig::parse(&buf).ok_or(I40eError::BadSwitchConfig)
    }

    /// Keep VLAN tags in received/transmitted bytes because the frame-ring
    /// profile does not negotiate hardware tag insertion or stripped tags.
    pub(super) fn aq_keep_vlan_headers(&mut self) -> Result<(), I40eError> {
        let mut properties = self.vsi.raw;
        // Do not override a firmware-assigned port VLAN silently.
        if properties[8..10] != [0, 0] {
            return Err(I40eError::BadVsiParams);
        }
        properties[0..2].copy_from_slice(&4u16.to_le_bytes()); // VLAN_VALID only
        properties[12] = 0x03 | 0x18; // MODE_ALL | EMOD_NOTHING
        let mut params = [0u8; 16];
        params[0..2].copy_from_slice(&self.vsi_seid.to_le_bytes());
        self.aq_send(
            AqOpcode::UpdateVsiParameters,
            params,
            Some(&properties),
            VSI_PROPERTIES_BYTES as u16,
        )?;
        self.vsi.raw = properties;
        Ok(())
    }

    /// `get_vsi_parameters` (0x0212) — indirect.
    pub fn aq_get_vsi_params(&self, seid: u16) -> Result<VsiParams, I40eError> {
        let mut params = [0u8; 16];
        params[0..2].copy_from_slice(&seid.to_le_bytes());
        let (buf, wb) = self.aq_send(
            AqOpcode::GetVsiParameters,
            params,
            None,
            VSI_PROPERTIES_BYTES as u16,
        )?;
        if buf.len() < VSI_PROPERTIES_BYTES {
            return Err(I40eError::BadVsiParams);
        }
        let mut raw = [0u8; VSI_PROPERTIES_BYTES];
        raw.copy_from_slice(&buf[..VSI_PROPERTIES_BYTES]);

        let rd16 = |off: usize| u16::from_le_bytes([raw[off], raw[off + 1]]);
        Ok(VsiParams {
            // The completion descriptor echoes the seid and vsi
            // number in its first two params words.
            seid: u16::from_le_bytes([wb.params[0], wb.params[1]]),
            vsi_number: u16::from_le_bytes([wb.params[2], wb.params[3]]),
            mapping_flags: rd16(VSI_OFF_MAPPING_FLAGS),
            queue_mapping_0: rd16(VSI_OFF_QUEUE_MAPPING),
            tc_mapping_0: rd16(VSI_OFF_TC_MAPPING),
            qs_handle_0: rd16(VSI_OFF_QS_HANDLE),
            raw,
        })
    }

    /// `add_macvlan` (0x0250) — indirect, one element per call.
    pub fn aq_add_macvlan(&self, seid: u16, mac: [u8; 6], flags: u16) -> Result<(), I40eError> {
        let element = encode_macvlan_element(mac, flags, 0);
        let mut params = [0u8; 16];
        // `i40e_aqc_macvlan`: num_addresses:le16, seid[3]:le16.
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[2..4].copy_from_slice(&(seid | MACVLAN_CMD_SEID_VALID).to_le_bytes());
        let (resp, _wb) = self.aq_send(
            AqOpcode::AddMacvlan,
            params,
            Some(&element),
            MACVLAN_ELEMENT_BYTES as u16,
        )?;
        // Firmware writes the per-element result back into the same
        // buffer. A command-level OK with a per-element failure is
        // the case a naive caller misses.
        if resp.len() >= 13 && resp[12] == MACVLAN_MM_ERR_NO_RES {
            return Err(I40eError::MacFilterRejected);
        }
        Ok(())
    }

    /// Add the filters a VSI needs to receive ordinary traffic: an
    /// exact match on its own address and one for broadcast.
    pub fn aq_add_default_mac_filters(&self, seid: u16, mac: [u8; 6]) -> Result<(), I40eError> {
        self.aq_add_macvlan(
            seid,
            mac,
            MACVLAN_ADD_PERFECT_MATCH | MACVLAN_ADD_IGNORE_VLAN,
        )?;
        self.aq_add_macvlan(
            seid,
            BROADCAST_MAC,
            MACVLAN_ADD_PERFECT_MATCH | MACVLAN_ADD_IGNORE_VLAN,
        )
    }

    /// `set_link_restart_an` (0x0605) — enable the link and restart
    /// auto-negotiation.
    pub fn aq_set_link_restart_an(&self, enable_link: bool) -> Result<(), I40eError> {
        let mut params = [0u8; 16];
        let mut command = PHY_RESTART_AN;
        if enable_link {
            command |= PHY_LINK_ENABLE;
        }
        params[0] = command;
        self.aq_send(AqOpcode::SetLinkRestartAn, params, None, 0)?;
        Ok(())
    }
}
