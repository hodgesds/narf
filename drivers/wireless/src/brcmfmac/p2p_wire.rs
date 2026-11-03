// SPDX-License-Identifier: GPL-2.0-or-later
//! brcmfmac P2P wire encodings and action-frame policy (no I/O).
//!
//! Linux 7.3-rc4 sources mirrored here:
//! - `p2p.c` `struct brcmf_p2p_disc_st_le` / `enum brcmf_p2p_disc_state`
//!   (`brcmf_p2p_set_discover_state`, bsscfg iovar `p2p_state`);
//! - `fwil_types.h` `struct brcmf_fil_p2p_if_le` (`p2p_ifadd`/`p2p_ifupd`),
//!   `enum brcmf_fil_p2p_if_types`, `struct brcmf_fil_af_params_le` +
//!   `struct brcmf_fil_action_frame_le` (`actframe`) and
//!   `struct brcmf_rx_mgmt_data` (`BRCMF_E_ACTION_FRAME_RX` payload);
//! - `p2p.c` `brcmf_p2p_generate_bss_mac`, `brcmf_p2p_is_{pub,dpp_pub,p2p,
//!   gas}_action`, `brcmf_p2p_pub_af_tx` and the GAS branch of
//!   `brcmf_p2p_send_action_frame` (dwell/next-subtype/search/mpc policy);
//! - `cfg80211.c` `brcmf_cfg80211_mgmt_tx` (action frame -> `af_params`)
//!   and `brcmf_p2p_notify_action_frame_rx` (event -> 802.11 frame).
//!
//! Nothing here grants RF, channel or transmit authority.
use alloc::vec::Vec;

/// `fweh.h` event codes handled by `p2p.c`.
pub const E_P2P_DISC_LISTEN_COMPLETE: u32 = 55;
pub const E_ACTION_FRAME_COMPLETE: u32 = 60;
pub const E_ACTION_FRAME_OFF_CHAN_COMPLETE: u32 = 70;
pub const E_P2P_PROBEREQ_MSG: u32 = 72;
pub const E_ACTION_FRAME_RX: u32 = 75;
/// The events `cfg80211.c::brcmf_register_event_handlers` registers for
/// P2P; `fweh` enables every registered handler device-wide.
pub const DEVICE_EVENTS: [usize; 5] = [
    E_P2P_DISC_LISTEN_COMPLETE as usize,
    E_ACTION_FRAME_COMPLETE as usize,
    E_ACTION_FRAME_OFF_CHAN_COMPLETE as usize,
    E_P2P_PROBEREQ_MSG as usize,
    E_ACTION_FRAME_RX as usize,
];
/// `BRCMF_E_STATUS_SUCCESS`.
pub const E_STATUS_SUCCESS: u32 = 0;

/// `BRCMF_FIL_ACTION_FRAME_SIZE`.
pub const ACTION_FRAME_SIZE: usize = 1800;
/// `sizeof(struct brcmf_fil_af_params_le)`.
pub const AF_PARAMS_LEN: usize = 28 + ACTION_FRAME_SIZE;
/// `DOT11_MGMT_HDR_LEN`.
pub const MGMT_HDR_LEN: usize = 24;
/// `sizeof(struct brcmf_rx_mgmt_data)`.
pub const RX_MGMT_DATA_LEN: usize = 16;

/// `p2p.c` timing constants (ms).
pub const AF_DWELL_TIME: u32 = 200;
pub const AF_MIN_DWELL_TIME: u32 = 100;
pub const AF_MED_DWELL_TIME: u32 = 400;
pub const AF_LONG_DWELL_TIME: u32 = 1000;
pub const AF_TX_MAX_RETRY: u32 = 5;
pub const AF_MAX_WAIT_TIME_MS: u64 = 2000;
pub const AF_RETRY_DELAY_TIME_MS: u64 = 40;
pub const DISABLE_TIMEOUT_MS: u64 = 500;
/// `BRCMF_SCB_TIMEOUT_VALUE`.
pub const SCB_TIMEOUT_VALUE: u32 = 20;
/// `CUSTOM_RETRY_MASK`.
pub const CUSTOM_RETRY_MASK: u32 = 0xff00_0000;

/// `enum brcmf_p2p_disc_state`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscState {
    Scan = 0,
    Listen = 1,
    Search = 2,
}

/// `struct brcmf_p2p_disc_st_le` (packed: u8 + le16 + le16).
pub fn disc_state(state: DiscState, chanspec: u16, dwell_ms: u16) -> [u8; 5] {
    let mut out = [0; 5];
    out[0] = state as u8;
    out[1..3].copy_from_slice(&chanspec.to_le_bytes());
    out[3..5].copy_from_slice(&dwell_ms.to_le_bytes());
    out
}

/// `enum brcmf_fil_p2p_if_types`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P2pIfType {
    Client = 0,
    Go = 1,
}

/// `struct brcmf_fil_p2p_if_le` (addr, le16 type, le16 chspec).
pub fn p2p_if(addr: [u8; 6], kind: P2pIfType, chanspec: u16) -> [u8; 10] {
    let mut out = [0; 10];
    out[..6].copy_from_slice(&addr);
    out[6..8].copy_from_slice(&(kind as u16).to_le_bytes());
    out[8..10].copy_from_slice(&chanspec.to_le_bytes());
    out
}

/// P2P addresses of `brcmf_p2p_generate_bss_mac`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Addresses {
    pub device: [u8; 6],
    pub connection: [u8; 6],
    pub connection2: [u8; 6],
}

/// `brcmf_p2p_generate_bss_mac`. `random` is the caller's random address
/// used only when Linux would call `eth_random_addr` (no requested address
/// and an already locally administered primary); Linux's random address is
/// unicast and locally administered, so those bits are forced here.
pub fn generate_bss_mac(
    primary: [u8; 6],
    requested: Option<[u8; 6]>,
    random: [u8; 6],
) -> Addresses {
    let device = match requested {
        Some(address) if address != [0; 6] => address,
        _ if primary[0] & 0x02 != 0 => {
            let mut address = random;
            address[0] = (address[0] & 0xfe) | 0x02;
            address
        }
        _ => {
            let mut address = primary;
            address[0] |= 0x02;
            address
        }
    };
    let mut connection = device;
    connection[0] |= 0x02;
    connection[4] ^= 0x80;
    let mut connection2 = device;
    connection2[0] |= 0x02;
    connection2[4] ^= 0x90;
    Addresses {
        device,
        connection,
        connection2,
    }
}

/// Errors of the bounded encoders/decoders.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    /// Not a management action frame, or too short/long.
    Invalid,
}

/// `brcmf_cfg80211_mgmt_tx` action branch: build `brcmf_fil_af_params_le`
/// from an 802.11 management action frame. `channel` is `chan->hw_value`
/// (or the firmware's current channel), `wait_ms` is `params->wait`.
pub fn af_params(
    frame: &[u8],
    channel: u32,
    wait_ms: u32,
    cookie: u64,
) -> Result<Vec<u8>, WireError> {
    if !is_action(frame) || frame.len() > ACTION_FRAME_SIZE + MGMT_HDR_LEN {
        return Err(WireError::Invalid);
    }
    let body = &frame[MGMT_HDR_LEN..];
    let mut out = alloc::vec![0; AF_PARAMS_LEN];
    out[0..4].copy_from_slice(&channel.to_le_bytes());
    out[4..8].copy_from_slice(&wait_ms.to_le_bytes());
    out[8..14].copy_from_slice(&frame[16..22]); // bssid
    out[16..22].copy_from_slice(&frame[4..10]); // da
    out[22..24].copy_from_slice(&(body.len() as u16).to_le_bytes());
    out[24..28].copy_from_slice(&(cookie as u32).to_le_bytes());
    out[28..28 + body.len()].copy_from_slice(body);
    Ok(out)
}

/// Read fields of an encoded `af_params`.
pub fn af_channel(params: &[u8]) -> u32 {
    u32::from_le_bytes([params[0], params[1], params[2], params[3]])
}
pub fn af_dwell(params: &[u8]) -> u32 {
    u32::from_le_bytes([params[4], params[5], params[6], params[7]])
}
pub fn set_af_channel(params: &mut [u8], channel: u32) {
    params[0..4].copy_from_slice(&channel.to_le_bytes());
}
pub fn set_af_dwell(params: &mut [u8], dwell: u32) {
    params[4..8].copy_from_slice(&dwell.to_le_bytes());
}
/// The action body (`action_frame.data[..len]`).
pub fn af_body(params: &[u8]) -> &[u8] {
    let len = usize::from(u16::from_le_bytes([params[22], params[23]])).min(ACTION_FRAME_SIZE);
    &params[28..28 + len]
}
pub fn af_da(params: &[u8]) -> [u8; 6] {
    let mut out = [0; 6];
    out.copy_from_slice(&params[16..22]);
    out
}

/// `ieee80211_is_action`: management type, action subtype.
pub fn is_action(frame: &[u8]) -> bool {
    frame.len() >= MGMT_HDR_LEN && frame[0] & 0xfc == 0xd0
}
/// `ieee80211_is_probe_resp`.
pub fn is_probe_resp(frame: &[u8]) -> bool {
    frame.len() >= MGMT_HDR_LEN && frame[0] & 0xfc == 0x50
}

const WLAN_CATEGORY_PUBLIC: u8 = 4;
const WLAN_PUB_ACTION_VENDOR_SPECIFIC: u8 = 9;
const WLAN_OUI_WFA: [u8; 3] = [0x50, 0x6f, 0x9a];
const WLAN_OUI_TYPE_WFA_P2P: u8 = 9;
const WLAN_OUI_TYPE_WFA_DPP: u8 = 0x1a;
const P2P_AF_CATEGORY: u8 = 0x7f;

/// `brcmf_p2p_is_pub_action` (8-byte fixed part).
pub fn is_pub_action(body: &[u8]) -> bool {
    body.len() >= 8
        && body[0] == WLAN_CATEGORY_PUBLIC
        && body[1] == WLAN_PUB_ACTION_VENDOR_SPECIFIC
        && body[5] == WLAN_OUI_TYPE_WFA_P2P
        && body[2..5] == WLAN_OUI_WFA
}
/// `brcmf_p2p_is_dpp_pub_action` (7 bytes suffice, as in Linux).
pub fn is_dpp_pub_action(body: &[u8]) -> bool {
    body.len() >= 7
        && body[0] == WLAN_CATEGORY_PUBLIC
        && body[1] == WLAN_PUB_ACTION_VENDOR_SPECIFIC
        && body[5] == WLAN_OUI_TYPE_WFA_DPP
        && body[2..5] == WLAN_OUI_WFA
}
/// `brcmf_p2p_is_p2p_action` (7-byte fixed part).
pub fn is_p2p_action(body: &[u8]) -> bool {
    body.len() >= 7
        && body[0] == P2P_AF_CATEGORY
        && body[4] == WLAN_OUI_TYPE_WFA_P2P
        && body[1..4] == WLAN_OUI_WFA
}
/// `P2PSD_ACTION_ID_GAS_*`.
pub const GAS_IREQ: u8 = 0x0a;
pub const GAS_IRESP: u8 = 0x0b;
pub const GAS_CREQ: u8 = 0x0c;
pub const GAS_CRESP: u8 = 0x0d;
/// `brcmf_p2p_is_gas_action` (3-byte fixed part).
pub fn is_gas_action(body: &[u8]) -> bool {
    body.len() >= 3 && body[0] == 0x04 && (GAS_IREQ..=GAS_CRESP).contains(&body[1])
}

/// P2P public action subtypes (`P2P_PAF_*`).
pub const PAF_GON_REQ: u8 = 0;
pub const PAF_GON_RSP: u8 = 1;
pub const PAF_GON_CONF: u8 = 2;
pub const PAF_INVITE_REQ: u8 = 3;
pub const PAF_INVITE_RSP: u8 = 4;
pub const PAF_DEVDIS_REQ: u8 = 5;
pub const PAF_DEVDIS_RSP: u8 = 6;
pub const PAF_PROVDIS_REQ: u8 = 7;
pub const PAF_PROVDIS_RSP: u8 = 8;
pub const PAF_SUBTYPE_INVALID: u8 = 255;

/// `struct brcmf_config_af_params` + the selected dwell and the
/// `next_af_subtype` / GO-negotiation phase transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfPolicy {
    /// `mpc_onoff`: `Some(false)` turns MPC off before TX, `Some(true)`
    /// back on after, `None` leaves it.
    pub mpc: Option<bool>,
    pub search_channel: bool,
    pub extra_listen: bool,
    pub dwell_ms: u32,
    pub next_subtype: u8,
    /// `Some(true)` sets `GO_NEG_PHASE`, `Some(false)` clears it.
    pub go_neg_phase: Option<bool>,
}

/// IEEE 802.11 P2P attribute: Group ID (`IEEE80211_P2P_ATTR_GROUP_ID`).
const P2P_ATTR_GROUP_ID: u8 = 15;

/// `cfg80211_get_p2p_attr` presence check over P2P IE bodies in `ies`.
fn has_p2p_attr(ies: &[u8], attr: u8) -> bool {
    let mut offset = 0;
    while offset + 2 <= ies.len() {
        let id = ies[offset];
        let len = usize::from(ies[offset + 1]);
        let Some(element) = ies.get(offset + 2..offset + 2 + len) else {
            return false;
        };
        if id == 221
            && len >= 4
            && element[..3] == WLAN_OUI_WFA
            && element[3] == WLAN_OUI_TYPE_WFA_P2P
        {
            let mut attrs = &element[4..];
            while attrs.len() >= 3 {
                let attr_len = usize::from(u16::from_le_bytes([attrs[1], attrs[2]]));
                if attrs[0] == attr {
                    return true;
                }
                let Some(rest) = attrs.get(3 + attr_len..) else {
                    break;
                };
                attrs = rest;
            }
        }
        offset += 2 + len;
    }
    false
}

/// `brcmf_p2p_send_action_frame` classification + `brcmf_p2p_pub_af_tx`.
/// `None` is Linux's "Unknown Frame" refusal (`return false`, no TX).
pub fn af_policy(body: &[u8]) -> Option<AfPolicy> {
    let mut policy = AfPolicy {
        mpc: None,
        search_channel: false,
        extra_listen: false,
        dwell_ms: AF_DWELL_TIME,
        next_subtype: PAF_SUBTYPE_INVALID,
        go_neg_phase: None,
    };
    if is_pub_action(body) {
        policy.extra_listen = true;
        let subtype = body[6];
        match subtype {
            PAF_GON_REQ => {
                policy.go_neg_phase = Some(true);
                policy.mpc = Some(false);
                policy.search_channel = true;
                policy.next_subtype = subtype + 1;
                policy.dwell_ms = AF_MED_DWELL_TIME;
            }
            PAF_GON_RSP => {
                policy.next_subtype = subtype + 1;
                policy.dwell_ms = AF_MED_DWELL_TIME;
            }
            PAF_GON_CONF => {
                policy.go_neg_phase = Some(false);
                policy.mpc = Some(true);
                policy.dwell_ms = AF_MIN_DWELL_TIME;
                policy.extra_listen = false;
            }
            PAF_INVITE_REQ => {
                policy.search_channel = true;
                policy.next_subtype = subtype + 1;
                policy.dwell_ms = AF_MED_DWELL_TIME;
            }
            PAF_INVITE_RSP | PAF_DEVDIS_RSP => {
                policy.dwell_ms = AF_MIN_DWELL_TIME;
                policy.extra_listen = false;
            }
            PAF_DEVDIS_REQ => {
                policy.search_channel = true;
                policy.next_subtype = subtype + 1;
                policy.dwell_ms = AF_LONG_DWELL_TIME;
            }
            PAF_PROVDIS_REQ => {
                if !has_p2p_attr(&body[8..], P2P_ATTR_GROUP_ID) {
                    policy.search_channel = true;
                }
                policy.mpc = Some(false);
                policy.next_subtype = subtype + 1;
                policy.dwell_ms = AF_MED_DWELL_TIME;
            }
            PAF_PROVDIS_RSP => {
                policy.next_subtype = PAF_GON_REQ;
                policy.dwell_ms = AF_MED_DWELL_TIME;
                policy.extra_listen = false;
            }
            // Unknown subtype: sent with the defaults set so far.
            _ => {}
        }
        Some(policy)
    } else if is_gas_action(body) {
        let action = body[1];
        if action == GAS_IREQ || action == GAS_CREQ {
            policy.search_channel = true;
            policy.next_subtype = action + 1;
            policy.dwell_ms = AF_MED_DWELL_TIME;
        } else {
            policy.dwell_ms = AF_MIN_DWELL_TIME;
        }
        Some(policy)
    } else if is_p2p_action(body) || is_dpp_pub_action(body) {
        Some(policy)
    } else {
        None
    }
}

/// The receive-side subtype `brcmf_p2p_notify_action_frame_rx` compares
/// against `next_af_subtype`.
pub fn rx_subtype(body: &[u8]) -> u8 {
    if is_pub_action(body) {
        body[6]
    } else if is_gas_action(body) {
        body[1]
    } else {
        PAF_SUBTYPE_INVALID
    }
}

/// Decoded `BRCMF_E_ACTION_FRAME_RX` payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RxAction {
    /// `be16 chanspec` of `struct brcmf_rx_mgmt_data`.
    pub chanspec: u16,
    /// The action body following the fixed header.
    pub body: Vec<u8>,
}

/// Strict decode of `struct brcmf_rx_mgmt_data` + body. Linux reads
/// `e->datalen - sizeof(*rxframe)` bytes; an undersized or truncated event
/// is refused instead of read.
pub fn parse_rx_action(datalen: u32, payload: &[u8]) -> Result<RxAction, WireError> {
    let datalen = datalen as usize;
    if datalen < RX_MGMT_DATA_LEN || payload.len() < datalen {
        return Err(WireError::Invalid);
    }
    Ok(RxAction {
        chanspec: u16::from_be_bytes([payload[2], payload[3]]),
        body: payload[RX_MGMT_DATA_LEN..datalen].to_vec(),
    })
}

/// `brcmf_p2p_notify_action_frame_rx` frame reconstruction:
/// `da` = the interface address, `sa` = event source, `bssid` = the
/// firmware `BRCMF_C_GET_BSSID` reply, frame control = action.
pub fn rx_frame(da: [u8; 6], sa: [u8; 6], bssid: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0; MGMT_HDR_LEN + body.len()];
    out[0] = 0xd0;
    out[4..10].copy_from_slice(&da);
    out[10..16].copy_from_slice(&sa);
    out[16..22].copy_from_slice(&bssid);
    out[MGMT_HDR_LEN..].copy_from_slice(body);
    out
}

/// D11AC 20 MHz chanspec of `channel` (`brcmu_d11ac_encchspec`, BW_20,
/// band from the channel number).
pub fn chanspec20(channel: u8) -> Option<u16> {
    match channel {
        1..=14 => Some(0x1000 | u16::from(channel)),
        15..=200 => Some(0xd000 | u16::from(channel)),
        _ => None,
    }
}
/// Control channel and frequency of a received chanspec
/// (`decchspec` + `ieee80211_channel_to_frequency`), 20 MHz part only.
pub fn chanspec_frequency(chanspec: u16) -> Option<u32> {
    let channel = u32::from(chanspec & 0xff);
    match chanspec & 0xc000 {
        0x0000 if (1..=13).contains(&channel) => Some(2407 + 5 * channel),
        0x0000 if channel == 14 => Some(2484),
        0xc000 if channel > 14 => Some(5000 + 5 * channel),
        _ => None,
    }
}
/// `ieee80211_frequency_to_channel` for 2.4/5 GHz.
pub fn frequency_channel(mhz: u32) -> Option<u8> {
    let channel = match mhz {
        2484 => 14,
        2412..=2472 => (mhz - 2407) / 5,
        5000..=5900 => (mhz - 5000) / 5,
        _ => return None,
    };
    u8::try_from(channel).ok()
}
