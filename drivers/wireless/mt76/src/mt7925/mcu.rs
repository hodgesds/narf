//! MT7925 (CONNAC3) UNI MCU command framing + station/BSS builders.
//!
//! Byte encoders only: they build the exact messages Linux sends to
//! the MT7925 firmware, but they do not dispatch anything — there is
//! no live MCU send path in the tree yet (the transport `submit`
//! in `mt7921::firmware_transport_hw` owns the WM/FWDL rings; the UNI
//! send path will post on TX MCU_WM, `regs::MT7925_TXQ_MCU_WM` = 15,
//! and read responses on RX MCU_WM, `regs::MT7925_RXQ_MCU_WM` = 0).
//!
//! ## Wire rules (all from upstream, cited per item)
//!
//! - A UNI command word packs the command id into bits[7:0] with the
//!   UNI bit (17) set; the WM bit (20) selects the WM firmware, the
//!   QUERY bit (16) selects a query. `mt76_connac_mcu.h:1216-1254`.
//! - Every TLV is `{ tag: u16 LE, len: u16 LE, body }` where `len` is
//!   the **total** TLV size including the 4-byte header
//!   (`mt76_connac_mcu_add_nested_tlv`, `mt76_connac_mcu.c`).
//! - A station request opens with `sta_req_hdr` (8 bytes):
//!   `bss_idx`, `wlan_idx_lo`, `tlv_num: u16 LE`, `is_tlv_append = 1`,
//!   `muar_idx` (the vif's OMAC index, `0xe` for the vif's own BMC
//!   WCID), `wlan_idx_hi`, reserved. `mt76_connac_mcu.c:319-340`.
//! - A BSS request opens with `bss_req_hdr` (4 bytes): `bss_idx` +
//!   3 reserved bytes. `mt7925/mcu.c:2589-2603`.
//! - BA state is programmed **per link**: `mt7925_mcu_uni_tx_ba` /
//!   `mt7925_mcu_uni_rx_ba` iterate the station's active links and
//!   send one `STA_REC_UPDATE` carrying a single `STA_REC_BA` TLV per
//!   link. `mt7925/mcu.c:761-824`.
//! - The MLD TLV always lists the primary (deflink) first, then the
//!   secondary links, at most 2 links total (`link[2]`).
//!   `mt7925/mcu.c:2066-2140`. It is emitted on every non-NONE
//!   station update, MLD vif or not: a non-MLD vif sends it with
//!   `link_num = 0` (v7.0-rc7 `mt7925/mcu.c:1913-1944, 1995-1998`).
//! - The EHT MLD TLV is emitted only for an MLD vif
//!   (`ieee80211_vif_is_mld`); `mld_type = 0xff` always.
//!   `mt7925/mcu.c:2028-2062`.
//! - Station remove is `STA_REC_REMOVE` (action 0) followed by a bare
//!   `STA_REC_MLD_OFF` TLV. `mt7925/mcu.c:2144-2156, 2237-2244`.
//! - BSS info TLV order is fixed: BASIC, SEC, RATE, QoS, MLD, IFS,
//!   then HE + BSS_COLOR when the BSS supports HE, then RLM + MBSSID
//!   when enabling. `mt7925/mcu.c:3102-3142`.
//! - The BSS EHT TLV is a **separate** `BSS_INFO_UPDATE` carrying
//!   only that TLV (`mt7925_mcu_set_eht_pp`, `mt7925/mcu.c:2623-2637`);
//!   it is not part of the `add_bss_info_sta` stream.
//!
//! ## Boundaries
//!
//! - EHT capability **values** (STA_REC_EHT mac/phy caps + MCS maps,
//!   BSS HE `max_nss_mcs`, BSS EHT op fields) are plain inputs here.
//!   Slice 7 (`mt7921::he`, `iface.rs`) computes them from the AP's
//!   EHT IEs; this module only lays out their bytes.
//! - The station update follows `mt7925_mcu_sta_cmd` (Linux v7.0-rc7
//!   `mt7925/mcu.c:1958-2010`): BASIC, PHY, HT, VHT, (UAPSD — AP vifs
//!   only), HW_AMSDU, HE_V2, HE_6G, EHT, RA, STATE_V2, then MLD (+
//!   EHT MLD for an MLD vif) once the state is not NONE, then
//!   HDR_TRANS. The fixed records (PHY, RA, STATE_V2, HDR_TRANS) take
//!   structured inputs; `cap_tlvs` is the caller-supplied run of the
//!   capability-gated ones (HT..EHT). `mt7921::association`
//!   (`JoinPlan::uni_sta_caps`) fills both from the negotiated
//!   profiles; the builder itself only lays out the bytes. Only
//!   `STA_REC_HE_V2` carries HE: `mt7925_mcu_sta_he_tlv` never sends
//!   the CONNAC2 `STA_REC_HE`.
//! - 320 MHz stays refused (`association.rs:1296`): the RLM encoder
//!   accepts the upstream `CMD_CBW_320MHZ` value but no caller in
//!   this slice passes it.
//! - `MT7925_STA_UPDATE_MAX_SIZE` / `MT7925_BSS_UPDATE_MAX_SIZE`
//!   from upstream (`mt7925/mcu.h:505-524` in v7.0-rc7) are **not**
//!   reproduced: they sum TLV structs this module does not encode
//!   (BF, BFEE, RA_FIXED, ...). The `UNI_*_UPDATE_BOUND` consts below
//!   bound only what this module emits, for the future send path's
//!   static buffers.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::mt7921::regs::MAC_ADDR_LEN;

// ── UNI command words ────────────────────────────────────────────
//
// mt76_connac_mcu.h:1208-1254:
//   __MCU_CMD_FIELD_ID    GENMASK(7, 0)
//   __MCU_CMD_FIELD_QUERY BIT(16)
//   __MCU_CMD_FIELD_UNI   BIT(17)
//   __MCU_CMD_FIELD_WM    BIT(20)
//   MCU_UNI_CMD(_t)            = UNI | id
//   MCU_WM_UNI_CMD(_t)         = UNI | WM | id
//   MCU_WM_UNI_CMD_QUERY(_t)   = UNI | QUERY | WM | id

/// UNI bit (17) of a UNI command word.
pub const MCU_CMD_FIELD_UNI: u32 = 1 << 17;
/// QUERY bit (16) of a UNI command word.
pub const MCU_CMD_FIELD_QUERY: u32 = 1 << 16;
/// WM bit (20) of a UNI command word.
pub const MCU_CMD_FIELD_WM: u32 = 1 << 20;

/// `MCU_UNI_CMD(id)`: plain UNI command word.
pub const fn mcu_uni_cmd(id: u8) -> u32 {
    MCU_CMD_FIELD_UNI | id as u32
}

/// `MCU_WM_UNI_CMD(id)`: UNI command word addressed to the WM firmware.
pub const fn mcu_wm_uni_cmd(id: u8) -> u32 {
    MCU_CMD_FIELD_UNI | MCU_CMD_FIELD_WM | id as u32
}

/// `MCU_WM_UNI_CMD_QUERY(id)`: UNI query word addressed to the WM firmware.
pub const fn mcu_wm_uni_cmd_query(id: u8) -> u32 {
    MCU_CMD_FIELD_UNI | MCU_CMD_FIELD_QUERY | MCU_CMD_FIELD_WM | id as u32
}

/// UNI command ids (`mt76_connac_mcu.h:1315-1364`, enum `mt76_mcu_uni_cmd`).
pub const UNI_CMD_DEV_INFO_UPDATE: u8 = 0x01;
pub const UNI_CMD_BSS_INFO_UPDATE: u8 = 0x02;
pub const UNI_CMD_STA_REC_UPDATE: u8 = 0x03;
/// `MCU_UNI_CMD_EFUSE_CTRL = 0x2d` (`mt76_connac_mcu.h:1342`).
pub const UNI_CMD_EFUSE_CTRL: u8 = 0x2d;

/// `MCU_UNI_CMD(STA_REC_UPDATE)` — the word every station message carries.
pub const UNI_STA_REC_UPDATE_CMD: u32 = mcu_uni_cmd(UNI_CMD_STA_REC_UPDATE);
/// `MCU_UNI_CMD(BSS_INFO_UPDATE)` — the word every BSS-info message carries.
pub const UNI_BSS_INFO_UPDATE_CMD: u32 = mcu_uni_cmd(UNI_CMD_BSS_INFO_UPDATE);

/// `MCU_UNI_CMD(EFUSE_CTRL)` — what `mt7925_mcu_set_eeprom` sends
/// (`mt7925/mcu.c:1629`). Note the asymmetry: the set path uses the
/// plain UNI word (no WM, no QUERY), while the read path uses the
/// WM query word below.
pub const UNI_EFUSE_CTRL_CMD: u32 = mcu_uni_cmd(UNI_CMD_EFUSE_CTRL);
/// `MCU_WM_UNI_CMD_QUERY(EFUSE_CTRL)` — what `mt7925_mcu_read_eeprom`
/// sends (`mt7925/mcu.c:861`).
pub const UNI_EFUSE_CTRL_QUERY_CMD: u32 = mcu_wm_uni_cmd_query(UNI_CMD_EFUSE_CTRL);

// ── MCU RXD (event header) ───────────────────────────────────────
//
// struct mt7925_mcu_rxd (mt7925/mcu.h:26-43), 44 bytes:
//   rxd[8]: u32 LE x8
//   len: u16 LE, pkt_type_id: u16 LE
//   eid, seq, option, __rsv
//   ext_eid, __rsv1[2], s2d_index
//   tlv[]

/// Size of `struct mt7925_mcu_rxd` (44 bytes).
pub const MCU_RXD_SIZE: usize = 44;
/// `MCU_UNI_CMD_EVENT` — option bit 1 (`mt76_connac_mcu.h:1113`).
pub const MCU_RXD_OPT_EVENT: u8 = 1 << 1;
/// `MCU_UNI_CMD_UNSOLICITED_EVENT` — option bit 2 (`mt76_connac_mcu.h:1114`).
pub const MCU_RXD_OPT_UNSOLICITED_EVENT: u8 = 1 << 2;

/// Parsed `mt7925_mcu_rxd` header (the TLV payload follows it).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct McuRxd {
    /// RXD word 0..8 (TXD/RXD descriptor words, LE).
    pub rxd: [u32; 8],
    /// Length of the payload after the header.
    pub len: u16,
    /// Packet-type id.
    pub pkt_type_id: u16,
    /// Event id.
    pub eid: u8,
    /// Sequence number.
    pub seq: u8,
    /// Option bits (`MCU_RXD_OPT_*`).
    pub option: u8,
    /// Extended event id.
    pub ext_eid: u8,
    /// S2D index.
    pub s2d_index: u8,
}

impl McuRxd {
    /// `true` when the event is solicited (a command response).
    pub const fn is_event(self) -> bool {
        self.option & MCU_RXD_OPT_EVENT != 0
    }
    /// `true` when the event is unsolicited (firmware-initiated).
    pub const fn is_unsolicited(self) -> bool {
        self.option & MCU_RXD_OPT_UNSOLICITED_EVENT != 0
    }
}

/// Parse an `mt7925_mcu_rxd` header. `None` when the buffer is
/// shorter than the 44-byte header.
pub fn parse_mcu_rxd(bytes: &[u8]) -> Option<McuRxd> {
    let b = bytes.get(..MCU_RXD_SIZE)?;
    let mut rxd = [0u32; 8];
    for (i, w) in rxd.iter_mut().enumerate() {
        *w = u32::from_le_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
    }
    Some(McuRxd {
        rxd,
        len: u16::from_le_bytes([b[32], b[33]]),
        pkt_type_id: u16::from_le_bytes([b[34], b[35]]),
        eid: b[36],
        seq: b[37],
        option: b[38],
        ext_eid: b[40],
        s2d_index: b[43],
    })
}

// ── TLV + request-header helpers ─────────────────────────────────

/// One TLV header: `{ tag: u16 LE, len: u16 LE }`. `len` always
/// includes these 4 bytes.
pub const TLV_HDR_SIZE: usize = 4;

/// Append a TLV (`tag`, `body`) to `out`, with `len` = total TLV size.
/// Returns the offset of the TLV header.
pub fn append_tlv(out: &mut Vec<u8>, tag: u16, body: &[u8]) -> usize {
    let offset = out.len();
    let total = TLV_HDR_SIZE + body.len();
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&(total as u16).to_le_bytes());
    out.extend_from_slice(body);
    offset
}

/// `sta_req_hdr` size (8 bytes).
pub const STA_REQ_HDR_SIZE: usize = 8;
/// `bss_req_hdr` size (4 bytes).
pub const BSS_REQ_HDR_SIZE: usize = 4;

/// Encode `sta_req_hdr` (`mt76_connac_mcu.c:319-340`):
/// `{ bss_idx, wlan_idx_lo, tlv_num = 0, is_tlv_append = 1, muar_idx,
///    wlan_idx_hi, rsv }`. The caller patches `tlv_num` with
/// [`set_sta_req_tlv_count`] once the TLVs are appended.
pub fn encode_sta_req_hdr(bss_idx: u8, wcid_idx: u16, muar_idx: u8, out: &mut [u8]) -> Option<()> {
    let hdr = out.get_mut(..STA_REQ_HDR_SIZE)?;
    hdr[0] = bss_idx;
    hdr[1] = (wcid_idx & 0xff) as u8;
    hdr[2] = 0; // tlv_num lo — patched by set_sta_req_tlv_count
    hdr[3] = 0; // tlv_num hi
    hdr[4] = 1; // is_tlv_append
    hdr[5] = muar_idx;
    hdr[6] = (wcid_idx >> 8) as u8;
    hdr[7] = 0;
    Some(())
}

/// Patch the `tlv_num` field (bytes 2..4, LE) of a `sta_req_hdr`.
/// Upstream increments it once per `mt76_connac_mcu_add_tlv` call.
pub fn set_sta_req_tlv_count(hdr: &mut [u8], count: u16) {
    if let Some(h) = hdr.get_mut(..STA_REQ_HDR_SIZE) {
        h[2..4].copy_from_slice(&count.to_le_bytes());
    }
}

/// Encode `bss_req_hdr` (`mt7925/mcu.c:2589-2603`):
/// `{ bss_idx, rsv[3] }`.
pub fn encode_bss_req_hdr(bss_idx: u8, out: &mut [u8]) -> Option<()> {
    let hdr = out.get_mut(..BSS_REQ_HDR_SIZE)?;
    hdr[0] = bss_idx;
    hdr[1] = 0;
    hdr[2] = 0;
    hdr[3] = 0;
    Some(())
}

// ── STA_REC tags ─────────────────────────────────────────────────
//
// mt76_connac_mcu.h:836-871 (enum, STA_REC_*). Only the tags this
// module emits are listed.

/// `STA_REC_BASIC` = 0.
pub const STA_REC_BASIC: u16 = 0;
/// `STA_REC_RA` = 1 (`struct sta_rec_ra_info`).
pub const STA_REC_RA: u16 = 1;
/// `STA_REC_BA` = 6.
pub const STA_REC_BA: u16 = 6;
/// `STA_REC_STATE` = 7. CONNAC3 sends `struct sta_rec_state_v2`
/// under this same tag (`mt7925_mcu_sta_state_v2_tlv`).
pub const STA_REC_STATE: u16 = 7;
/// `STA_REC_HT` = 9.
pub const STA_REC_HT: u16 = 9;
/// `STA_REC_VHT` = 10.
pub const STA_REC_VHT: u16 = 10;
/// `STA_REC_APPS` = 11 (`struct sta_rec_uapsd`). Listed for the
/// record only: `mt76_connac_mcu_sta_uapsd` (`mt76_connac_mcu.c:434-
/// 464`) returns unless the vif is an AP, so a station never sends it.
pub const STA_REC_APPS: u16 = 11;
/// `STA_REC_HE` = 14 — the CONNAC2 `struct sta_rec_he`. Listed for
/// the record only: `mt7925_mcu_sta_he_tlv` (`mt7925/mcu.c:1636-1642`)
/// sends only `STA_REC_HE_V2`.
pub const STA_REC_HE: u16 = 14;
/// `STA_REC_HW_AMSDU` = 15 (`struct sta_rec_amsdu`).
pub const STA_REC_HW_AMSDU: u16 = 15;
/// `STA_REC_PHY` = 0x15 (`mt76_connac_mcu.h:824`).
pub const STA_REC_PHY: u16 = 0x15;
/// `STA_REC_HE_6G` = 0x17.
pub const STA_REC_HE_6G: u16 = 0x17;
/// `STA_REC_HE_V2` = 0x19.
pub const STA_REC_HE_V2: u16 = 0x19;
/// `STA_REC_MLD` = 0x20.
pub const STA_REC_MLD: u16 = 0x20;
/// `STA_REC_EHT_MLD` = 0x21.
pub const STA_REC_EHT_MLD: u16 = 0x21;
/// `STA_REC_EHT` = 0x22.
pub const STA_REC_EHT: u16 = 0x22;
/// `STA_REC_MLD_OFF` = 0x23.
pub const STA_REC_MLD_OFF: u16 = 0x23;
/// `STA_REC_REMOVE` = 0x25.
pub const STA_REC_REMOVE: u16 = 0x25;
/// `STA_REC_KEY_V3` = 0x27 (`mt76_connac_mcu.h:866`) — the CONNAC3
/// key record (`struct sta_rec_sec_uni`, `mt7925/mcu.h`), used by
/// `mt7925_mcu_sta_key_tlv` (`mt7925/mcu.c:1320-1401`) for pairwise,
/// group and IGTK installs alike. The CONNAC2 `STA_REC_KEY_V2` (17)
/// has no UNI counterpart: a 7925 key goes in its own
/// `STA_REC_UPDATE` carrying only this TLV (`mt7925_mcu_add_key`,
/// `mt7925/mcu.c:1403-1423`).
pub const STA_REC_KEY_V3: u16 = 0x27;
/// `STA_REC_HDR_TRANS` = 0x2B (`mt76_connac_mcu.h:835`).
pub const STA_REC_HDR_TRANS: u16 = 0x2b;

/// CONNAC3 cipher ids (`mt7925/mcu.h:165-175`, enum):
/// NONE = 0, WEP40 = 1, TKIP = 2, AES_CCMP = 4, WEP104 = 5,
/// BIP_CMAC_128 = 6, WEP128 = 7, WAPI = 8, CCMP_256 = 10,
/// GCMP = 11, GCMP_256 = 12. The mapping from an 802.11 suite to
/// these bytes is `mt7925_mcu_get_cipher` (`mt7925/mcu.c:679-698`);
/// the NARF-side mapping lives in `mt7921::association`
/// (`connac3_cipher_for_suite`), next to the CONNAC2 one.
pub const CONNAC3_CIPHER_NONE: u8 = 0;
pub const CONNAC3_CIPHER_WEP40: u8 = 1;
pub const CONNAC3_CIPHER_TKIP: u8 = 2;
pub const CONNAC3_CIPHER_AES_CCMP: u8 = 4;
pub const CONNAC3_CIPHER_WEP104: u8 = 5;
pub const CONNAC3_CIPHER_BIP_CMAC_128: u8 = 6;
pub const CONNAC3_CIPHER_WEP128: u8 = 7;
pub const CONNAC3_CIPHER_WAPI: u8 = 8;
pub const CONNAC3_CIPHER_CCMP_256: u8 = 10;
pub const CONNAC3_CIPHER_GCMP: u8 = 11;
pub const CONNAC3_CIPHER_GCMP_256: u8 = 12;

// ── UNI BSS_INFO tags ────────────────────────────────────────────
//
// mt76_connac_mcu.h:1419-1443 (enum, UNI_BSS_INFO_*).

/// `UNI_BSS_INFO_BASIC` = 0.
pub const UNI_BSS_INFO_BASIC: u16 = 0;
/// `UNI_BSS_INFO_RLM` = 2.
pub const UNI_BSS_INFO_RLM: u16 = 2;
/// `UNI_BSS_INFO_BSS_COLOR` = 4.
pub const UNI_BSS_INFO_BSS_COLOR: u16 = 4;
/// `UNI_BSS_INFO_HE_BASIC` = 5.
pub const UNI_BSS_INFO_HE_BASIC: u16 = 5;
/// `UNI_BSS_INFO_11V_MBSSID` = 6.
pub const UNI_BSS_INFO_11V_MBSSID: u16 = 6;
/// `UNI_BSS_INFO_RATE` = 11.
pub const UNI_BSS_INFO_RATE: u16 = 11;
/// `UNI_BSS_INFO_QBSS` = 15.
pub const UNI_BSS_INFO_QBSS: u16 = 15;
/// `UNI_BSS_INFO_SEC` = 16.
pub const UNI_BSS_INFO_SEC: u16 = 16;
/// `UNI_BSS_INFO_IFS_TIME` = 23.
pub const UNI_BSS_INFO_IFS_TIME: u16 = 23;
/// `UNI_BSS_INFO_MLD` = 26.
pub const UNI_BSS_INFO_MLD: u16 = 26;
/// `UNI_BSS_INFO_EHT` = 30.
pub const UNI_BSS_INFO_EHT: u16 = 30;

// ── Connection types ─────────────────────────────────────────────
//
// mt76_connac_mcu.h:895-915:
//   STA_TYPE_STA = BIT(0), STA_TYPE_AP = BIT(1), STA_TYPE_ADHOC = BIT(2)
//   NETWORK_INFRA = BIT(16), NETWORK_P2P = BIT(17), NETWORK_IBSS = BIT(18)
//   CONNECTION_INFRA_STA = STA_TYPE_STA | NETWORK_INFRA, ...

/// Station in an infrastructure BSS (`0x10001`).
pub const CONN_TYPE_INFRA_STA: u32 = (1 << 0) | (1 << 16);
/// AP in an infrastructure BSS (`0x10002`).
pub const CONN_TYPE_INFRA_AP: u32 = (1 << 1) | (1 << 16);
/// P2P group client (`0x20001`).
pub const CONN_TYPE_P2P_GC: u32 = (1 << 0) | (1 << 17);
/// P2P group owner (`0x20002`).
pub const CONN_TYPE_P2P_GO: u32 = (1 << 1) | (1 << 17);
/// IBSS/adhoc (`0x40004`).
pub const CONN_TYPE_IBSS_ADHOC: u32 = (1 << 2) | (1 << 18);

/// `CONN_STATE_DISCONNECT` = 0 (`cmd.rs`, `mt76_connac_mcu.h`).
pub const CONN_STATE_DISCONNECT: u8 = 0x00;
/// `CONN_STATE_PORT_SECURE` = 2 (`cmd.rs`, `mt76_connac_mcu.h`).
pub const CONN_STATE_PORT_SECURE: u8 = 0x02;

/// `MT76_STA_INFO_STATE_*` (`mt76_connac_mcu.h:1821-1825`).
pub const STA_STATE_NONE: u8 = 0;
pub const STA_STATE_AUTH: u8 = 1;
pub const STA_STATE_ASSOC: u8 = 2;

/// `EXTRA_INFO_VER` = BIT(0), `EXTRA_INFO_NEW` = BIT(1)
/// (`mt76_connac_mcu.h`, `struct sta_rec_basic`).
pub const STA_EXTRA_INFO_VER: u16 = 1;
pub const STA_EXTRA_INFO_NEW: u16 = 2;

// ── Station TLV encoders ─────────────────────────────────────────

/// `sta_rec_basic` total size: tag+len (4) + conn_type (4) +
/// conn_state (1) + qos (1) + aid (2) + peer_addr (6) + extra_info (2).
pub const STA_REC_BASIC_TLV_SIZE: usize = 20;
/// `sta_rec_state_v2` total size (`mt7925/mcu.c:1815-1824`, local to
/// `mt7925_mcu_sta_state_v2_tlv`): tag+len (4) + state (1) + rsv[3] +
/// flags (4) + vht_opmode (1) + action (1) + rsv2[2]. Not the CONNAC2
/// 12-byte `sta_rec_state`, whose `state` byte sits at offset 8.
pub const STA_REC_STATE_V2_TLV_SIZE: usize = 16;
/// `sta_rec_phy` total size (`mt76_connac_mcu.h:405-415`): tag+len
/// (4), basic_rate (2), then phy_type, ampdu, rts_policy, rcpi,
/// max_ampdu_len (connac3) and rsv (6).
pub const STA_REC_PHY_TLV_SIZE: usize = 12;
/// `sta_rec_ra_info` total size (`mt76_connac_mcu.h:398-403`):
/// tag+len (4) + legacy (2) + rx_mcs_bitmask[HT_MCS_MASK_NUM = 10].
pub const STA_REC_RA_TLV_SIZE: usize = 16;
/// `sta_rec_ht` total size (`mt76_connac_mcu.h:302-307`).
pub const STA_REC_HT_TLV_SIZE: usize = 8;
/// `sta_rec_vht` total size (`mt76_connac_mcu.h:309-318`): the full
/// struct, `rts_bw_sig` tail included — `mt7925_mcu_sta_vht_tlv`
/// adds `sizeof(*vht)` (`mt7925/mcu.c:1713`).
pub const STA_REC_VHT_TLV_SIZE: usize = 16;
/// `sta_rec_amsdu` total size (`mt76_connac_mcu.h:376-383`).
pub const STA_REC_HW_AMSDU_TLV_SIZE: usize = 8;
/// `sta_rec_he_v2` total size (`mt76_connac_mcu.h:366-374`): tag+len
/// (4) + he_mac_cap[6] + he_phy_cap[11] + pkt_ext (1) +
/// max_nss_mcs[3] (6). The bytes come from the shared
/// `mt7921::he::Profile::sta_v2` builder (same struct on both
/// generations).
pub const STA_REC_HE_V2_TLV_SIZE: usize = 28;
/// `sta_rec_he_6g_capa` total size (`mt76_connac_mcu.h:417-422`).
pub const STA_REC_HE_6G_TLV_SIZE: usize = 8;
/// `sta_rec_hdr_trans` total size (`mt7925/mcu.h:438-445`).
pub const STA_REC_HDR_TRANS_TLV_SIZE: usize = 8;
/// `sta_rec_ba_uni` total size (`mt7925/mcu.h:414-425`).
pub const STA_REC_BA_UNI_TLV_SIZE: usize = 16;
/// `sta_rec_mld` total size (`mt7925/mcu.h:469-483`): header + mac +
/// ids + link[2].
pub const STA_REC_MLD_TLV_SIZE: usize = 28;
/// `sta_rec_eht_mld` total size (`mt7925/mcu.h:485-493`).
pub const STA_REC_EHT_MLD_TLV_SIZE: usize = 16;
/// `sta_rec_eht` total size (`mt7925/mcu.h:427-443`).
pub const STA_REC_EHT_TLV_SIZE: usize = 40;
/// `sta_rec_remove` total size (`mt76_connac_mcu.h:578-582`).
pub const STA_REC_REMOVE_TLV_SIZE: usize = 8;
/// `sta_rec_sec_uni` total size (`mt7925/mcu.h`, `struct
/// sta_rec_sec_uni`): tag+len (4) + add/tx_key/key_type/
/// is_authenticator (4) + peer_addr (6) + bss_idx/cipher_id/key_id/
/// key_len/wlan_idx/mgmt_prot (6) + key (32) + key_rsc (16).
pub const STA_REC_KEY_V3_TLV_SIZE: usize = 68;
/// Maximum key bytes a `sta_rec_sec_uni` carries (`key[32]`).
pub const STA_REC_KEY_V3_MAX_KEY_LEN: usize = 32;

/// BA types (`mt76_connac_mcu.h:1034-1037`, enum):
/// `MT_BA_TYPE_INVALID` = 0, `MT_BA_TYPE_ORIGINATOR` = 1,
/// `MT_BA_TYPE_RECIPIENT` = 2.
pub const BA_TYPE_ORIGINATOR: u8 = 1;
pub const BA_TYPE_RECIPIENT: u8 = 2;

/// Encode `sta_rec_basic` (`mt76_connac_mcu.c:424-433`,
/// `mt76_connac_mcu_sta_basic_tlv`): `{ conn_type: u32 LE,
/// conn_state, qos, aid: u16 LE, peer_addr[6], extra_info: u16 LE }`.
/// `extra_info` carries `EXTRA_INFO_VER` always and `EXTRA_INFO_NEW`
/// when `newly` (upstream: `newly && conn_state != DISCONNECT`).
#[allow(clippy::too_many_arguments)]
pub fn encode_sta_rec_basic_tlv(
    conn_type: u32,
    conn_state: u8,
    aid: u16,
    peer_addr: [u8; MAC_ADDR_LEN],
    qos: bool,
    newly: bool,
    out: &mut [u8],
) -> Option<()> {
    let body = out.get_mut(..STA_REC_BASIC_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_BASIC.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_BASIC_TLV_SIZE as u16).to_le_bytes());
    body[4..8].copy_from_slice(&conn_type.to_le_bytes());
    body[8] = conn_state;
    body[9] = qos as u8;
    body[10..12].copy_from_slice(&aid.to_le_bytes());
    body[12..18].copy_from_slice(&peer_addr);
    let mut extra = STA_EXTRA_INFO_VER;
    if newly && conn_state != CONN_STATE_DISCONNECT {
        extra |= STA_EXTRA_INFO_NEW;
    }
    body[18..20].copy_from_slice(&extra.to_le_bytes());
    Some(())
}

/// Encode `sta_rec_state_v2` (`mt7925_mcu_sta_state_v2_tlv`,
/// `mt7925/mcu.c:1810-1836`): `{ state, rsv[3], flags: u32 LE = 0,
/// vht_opmode, action = 0, rsv2[2] }` under tag `STA_REC_STATE`. The
/// `rcpi` the upstream function takes is unused. `vht_opmode` is
/// [`sta_state_v2_vht_opmode`] for a VHT peer and 0 otherwise.
pub fn encode_sta_rec_state_v2_tlv(state: u8, vht_opmode: u8, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_STATE_V2_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_STATE.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_STATE_V2_TLV_SIZE as u16).to_le_bytes());
    body[4] = state;
    body[12] = vht_opmode;
    Some(())
}

/// `sta_rec_state_v2.vht_opmode` for a VHT peer
/// (`mt7925/mcu.c:1831-1835`): the `IEEE80211_STA_RX_BW_*` value in
/// the low bits and `rx_nss << IEEE80211_OPMODE_NOTIF_RX_NSS_SHIFT`
/// (4). Upstream shifts `rx_nss` itself, NOT `rx_nss - 1` as the
/// CONNAC2 `mt76_connac_mcu_sta_tlv` does (`mt76_connac_mcu.c:940-
/// 944`); this mirrors the CONNAC3 code as written.
pub const fn sta_state_v2_vht_opmode(bandwidth: u8, rx_nss: u8) -> u8 {
    bandwidth | (rx_nss << 4)
}

/// `PHY_TYPE_BIT_*` (`mt76_connac_mcu.h:950-971`): the
/// `sta_rec_phy.phy_type` bits `mt76_connac_get_phy_mode_v2`
/// (`mt76_connac_mcu.c:791-845`) sets — HR_DSSS | ERP on 2.4 GHz,
/// OFDM on 5/6 GHz, plus HT / VHT (5/6 GHz only) / HE / BE for the
/// peer's capabilities.
pub const PHY_TYPE_BIT_HR_DSSS: u8 = 1 << 0;
pub const PHY_TYPE_BIT_ERP: u8 = 1 << 1;
pub const PHY_TYPE_BIT_OFDM: u8 = 1 << 3;
pub const PHY_TYPE_BIT_HT: u8 = 1 << 4;
pub const PHY_TYPE_BIT_VHT: u8 = 1 << 5;
pub const PHY_TYPE_BIT_HE: u8 = 1 << 6;
pub const PHY_TYPE_BIT_BE: u8 = 1 << 7;

/// `sta_rec_phy` inputs (`mt7925_mcu_sta_phy_tlv`,
/// `mt7925/mcu.c:1762-1807`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UniStaPhy {
    /// `link_conf->basic_rates` truncated to u16: a bitmap over the
    /// band's sband bitrate table (12 entries on 2.4 GHz, the 8 OFDM
    /// entries on 5/6 GHz).
    pub basic_rate: u16,
    /// `mt76_connac_get_phy_mode_v2(.., link_sta)`: `PHY_TYPE_BIT_*`.
    pub phy_type: u8,
    /// A-MPDU length exponent `af`: the HT factor, raised to the VHT
    /// `MAX_A_MPDU_LENGTH_EXPONENT` when larger, replaced by the 6 GHz
    /// band capability's exponent when that capability is present.
    /// Full width (0..=7): `max_ampdu_len` carries it as is, while
    /// `ampdu` keeps only the 2-bit HT factor field.
    pub ampdu_factor: u8,
    /// Minimum MPDU start spacing `mm` (`IEEE80211_HT_AMPDU_PARM_DENSITY`
    /// encoding): the HT density, or the 6 GHz capability's.
    pub density: u8,
}

/// Encode `sta_rec_phy` (`mt7925_mcu_sta_phy_tlv`): `{ basic_rate: u16
/// LE, phy_type, ampdu, rts_policy = 0, rcpi = 0, max_ampdu_len, rsv }`.
/// `ampdu = FIELD_PREP(IEEE80211_HT_AMPDU_PARM_FACTOR, af) |
/// FIELD_PREP(IEEE80211_HT_AMPDU_PARM_DENSITY, mm)` — `FIELD_PREP`
/// masks, so a VHT exponent above 3 survives only in `max_ampdu_len`.
/// The CONNAC3 builder never sets `rcpi` (the CONNAC2 one does).
pub fn encode_sta_rec_phy_tlv(phy: &UniStaPhy, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_PHY_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_PHY.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_PHY_TLV_SIZE as u16).to_le_bytes());
    body[4..6].copy_from_slice(&phy.basic_rate.to_le_bytes());
    body[6] = phy.phy_type;
    body[7] = (phy.ampdu_factor & 0x03) | ((phy.density << 2) & 0x1c);
    body[10] = phy.ampdu_factor;
    Some(())
}

/// `RA_LEGACY_OFDM` = GENMASK(13, 6), `RA_LEGACY_CCK` = GENMASK(3, 0)
/// (`mt76_connac_mcu.h:395-396`).
pub const RA_LEGACY_OFDM: u16 = 0x3fc0;
pub const RA_LEGACY_CCK: u16 = 0x000f;

/// `sta_rec_ra_info.legacy` from `link_sta->supp_rates[band]`
/// (`mt7925_mcu_sta_rate_ctrl_tlv`, `mt7925/mcu.c:1861-1868`).
/// `supp_rates` indexes the band's sband table: on 2.4 GHz entries
/// 0..3 are CCK and 4..11 OFDM, so the OFDM half moves to bits 6..13
/// and CCK stays in 0..3; on 5/6 GHz the table is the 8 OFDM rates.
pub const fn ra_legacy(supp_rates: u16, two_ghz: bool) -> u16 {
    if two_ghz {
        (((supp_rates >> 4) << 6) & RA_LEGACY_OFDM) | (supp_rates & RA_LEGACY_CCK)
    } else {
        (supp_rates << 6) & RA_LEGACY_OFDM
    }
}

/// `sta_rec_ra_info` inputs (`mt7925_mcu_sta_rate_ctrl_tlv`,
/// `mt7925/mcu.c:1839-1874`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UniStaRa {
    /// [`ra_legacy`] of the peer's supported legacy rates.
    pub legacy: u16,
    /// `link_sta->ht_cap.mcs.rx_mask` for an HT peer, zero otherwise.
    pub rx_mcs_bitmask: [u8; 10],
}

/// Encode `sta_rec_ra_info` (tag `STA_REC_RA`): `{ legacy: u16 LE,
/// rx_mcs_bitmask[10] }`.
pub fn encode_sta_rec_ra_tlv(ra: &UniStaRa, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_RA_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_RA.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_RA_TLV_SIZE as u16).to_le_bytes());
    body[4..6].copy_from_slice(&ra.legacy.to_le_bytes());
    body[6..16].copy_from_slice(&ra.rx_mcs_bitmask);
    Some(())
}

/// `sta_rec_hdr_trans` inputs (`mt7925_mcu_sta_hdr_trans_tlv`,
/// `mt7925/mcu.c:1067-1103`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UniStaHdrTrans {
    /// Set for a non-station vif, or a 4-address WCID.
    pub from_ds: bool,
    /// Set for a station vif, or a 4-address WCID.
    pub to_ds: bool,
    /// `!test_bit(MT_WCID_FLAG_HDR_TRANS)`: RX 802.3 decap offload off.
    pub dis_rx_hdr_tran: bool,
}

impl UniStaHdrTrans {
    /// A 3-address station vif without RX decap offload: `to_ds = 1`,
    /// `from_ds = 0`, `dis_rx_hdr_tran = 1`. NARF never enables RX
    /// decap offload (`mt7925_sta_set_decap_offload`,
    /// `mt7925/main.c:1552`, is what sets `MT_WCID_FLAG_HDR_TRANS`;
    /// NARF's RX path parses 802.11 headers, as the CONNAC2
    /// WTBL_HDR_TRANS "no RX translation" byte already says) and has
    /// no 4-address mode, so both WCID flags are clear — upstream's
    /// values for a station without either feature.
    pub const STATION: Self = Self {
        from_ds: false,
        to_ds: true,
        dis_rx_hdr_tran: true,
    };
}

/// Encode `sta_rec_hdr_trans` (`mt7925/mcu.h:438-445`): `{ from_ds,
/// to_ds, dis_rx_hdr_tran, rsv }`.
pub fn encode_sta_rec_hdr_trans_tlv(hdr: &UniStaHdrTrans, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_HDR_TRANS_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_HDR_TRANS.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_HDR_TRANS_TLV_SIZE as u16).to_le_bytes());
    body[4] = u8::from(hdr.from_ds);
    body[5] = u8::from(hdr.to_ds);
    body[6] = u8::from(hdr.dis_rx_hdr_tran);
    Some(())
}

/// Encode `sta_rec_ht` (`mt7925_mcu_sta_ht_tlv`, `mt7925/mcu.c:1689-
/// 1701`): `{ ht_cap: u16 LE = link_sta->ht_cap.cap, rsv }`.
pub fn encode_sta_rec_ht_tlv(ht_cap: u16, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_HT_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_HT.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_HT_TLV_SIZE as u16).to_le_bytes());
    body[4..6].copy_from_slice(&ht_cap.to_le_bytes());
    Some(())
}

/// Encode `sta_rec_vht` (`mt7925_mcu_sta_vht_tlv`, `mt7925/mcu.c:1704-
/// 1719`): `{ vht_cap: u32 LE, vht_rx_mcs_map: u16 LE, vht_tx_mcs_map:
/// u16 LE, rts_bw_sig = 0, rsv[3] }`. Upstream sends it for a VHT peer
/// AND for any peer with a 6 GHz band capability ("necessary to let hw
/// work normally"), where `link_sta->vht_cap` is all zero
/// (`ieee80211_vht_cap_ie_to_sta_vht_cap` memsets it and returns
/// without an HT capability).
pub fn encode_sta_rec_vht_tlv(
    cap: u32,
    rx_mcs_map: u16,
    tx_mcs_map: u16,
    out: &mut [u8],
) -> Option<()> {
    let body = out.get_mut(..STA_REC_VHT_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_VHT.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_VHT_TLV_SIZE as u16).to_le_bytes());
    body[4..8].copy_from_slice(&cap.to_le_bytes());
    body[8..10].copy_from_slice(&rx_mcs_map.to_le_bytes());
    body[10..12].copy_from_slice(&tx_mcs_map.to_le_bytes());
    Some(())
}

/// `IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_{3895,7991,11454}` = 0, 1, 2:
/// the `sta_rec_amsdu.max_mpdu_size` values CONNAC3 sends.
pub const AMSDU_MAX_MPDU_3895: u8 = 0;
pub const AMSDU_MAX_MPDU_7991: u8 = 1;
pub const AMSDU_MAX_MPDU_11454: u8 = 2;

/// `sta_rec_amsdu.max_mpdu_size` from `link_sta->agg.max_amsdu_len`
/// (`mt7925_mcu_sta_amsdu_tlv`, `mt7925/mcu.c:1746-1758`): 11454 → 2,
/// 7935 (HT) or 7991 → 1, anything else → 0. CONNAC2 sends the 0/1
/// flag `max_amsdu_len >= 7991` instead (`mt76_connac_mcu.c:615-616`),
/// so the two generations part at 11454.
pub const fn amsdu_max_mpdu_size(max_amsdu_len: u16) -> u8 {
    match max_amsdu_len {
        11454 => AMSDU_MAX_MPDU_11454,
        7935 | 7991 => AMSDU_MAX_MPDU_7991,
        _ => AMSDU_MAX_MPDU_3895,
    }
}

/// Encode `sta_rec_amsdu` (`mt7925_mcu_sta_amsdu_tlv`, tag
/// `STA_REC_HW_AMSDU`): `{ max_amsdu_num = 8, max_mpdu_size,
/// amsdu_en = 1, rsv }`. Sent for a station/AP vif whenever
/// `agg.max_amsdu_len` is non-zero — mac80211 sets it from the HT,
/// VHT, 6 GHz band or (2.4 GHz) EHT capability, so never for a
/// legacy peer.
pub fn encode_sta_rec_amsdu_tlv(max_mpdu_size: u8, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_HW_AMSDU_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_HW_AMSDU.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_HW_AMSDU_TLV_SIZE as u16).to_le_bytes());
    body[4] = 8;
    body[5] = max_mpdu_size;
    body[6] = 1;
    Some(())
}

/// Encode `sta_rec_he_6g_capa` (`mt7925_mcu_sta_he_6g_tlv`,
/// `mt7925/mcu.c:1645-1658`): `{ capa: u16 LE, rsv[2] }`. Upstream
/// sends it whenever `link_sta->he_6ghz_capa.capa` is non-zero — no
/// band/state gate, unlike CONNAC2's `band == 6GHZ && state == ASSOC`
/// (`mt76_connac_mcu.c:898-906`).
pub fn encode_sta_rec_he_6g_tlv(capa: u16, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_HE_6G_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_HE_6G.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_HE_6G_TLV_SIZE as u16).to_le_bytes());
    body[4..6].copy_from_slice(&capa.to_le_bytes());
    Some(())
}

/// Encode `sta_rec_ba_uni` (`mt7925/mcu.c:731-759`,
/// `mt7925_mcu_sta_ba`): `{ tid, ba_type, amsdu, ba_en, ssn: u16 LE,
/// winsize: u16 LE, ba_rdd_rro = 0, rsv[3] }`.
/// `ba_type` is `BA_TYPE_ORIGINATOR` for TX BA, `BA_TYPE_RECIPIENT`
/// for RX BA. `ba_en` is the enable bit shifted by `tid` — upstream
/// writes `enable << params->tid` into the u8 field, so `tid` must
/// be < 8.
pub fn encode_sta_rec_ba_uni_tlv(
    tid: u8,
    tx: bool,
    amsdu: bool,
    enable: bool,
    ssn: u16,
    winsize: u16,
    out: &mut [u8],
) -> Option<()> {
    if tid >= 8 {
        return None;
    }
    let body = out.get_mut(..STA_REC_BA_UNI_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_BA.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_BA_UNI_TLV_SIZE as u16).to_le_bytes());
    body[4] = tid;
    body[5] = if tx {
        BA_TYPE_ORIGINATOR
    } else {
        BA_TYPE_RECIPIENT
    };
    body[6] = amsdu as u8;
    body[7] = u8::from(enable) << tid;
    body[8..10].copy_from_slice(&ssn.to_le_bytes());
    body[10..12].copy_from_slice(&winsize.to_le_bytes());
    Some(())
}

/// One link of an MLD station: its WCID index and its BSS index.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MldLink {
    /// WCID index of this link's station record.
    pub wcid_idx: u16,
    /// BSS index of this link's BSS record.
    pub bss_idx: u8,
}

/// The MLD links of one station, primary first.
/// Upstream (`mt7925/mcu.c:2066-2140`) always encodes the primary
/// (deflink) first, then at most one secondary link (`link[2]`);
/// `primary_id`/`wlan_id` are the deflink WCID and `secondary_id`
/// is the secondary WCID (0 when there is none).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MldLinks {
    /// The station's own MAC (the MLD MAC). Upstream's `sta_rec_mld`
    /// writes `sta->addr` here — the peer AP MLD's address
    /// (`mt7925/mcu.c:1927`); NARF does not parse that address from
    /// the Basic Multi-Link element yet, so the `MldStation` path (no
    /// live callers) keeps the own MLD MAC until it does.
    pub own_mac: [u8; MAC_ADDR_LEN],
    /// Primary (deflink) link.
    pub primary: MldLink,
    /// Secondary link, if the station has a second active link.
    pub secondary: Option<MldLink>,
    /// Masked EML capabilities for the EHT MLD TLV: the vif's
    /// `eml_cap` masked to EMLSR-supp + transition timeout, plus the
    /// wiphy ext-capa EML padding/transition delay bits
    /// (`mt7925/mcu.c:2052-2058`). Computed by the caller from
    /// `mt7921::mlo::EmlCaps::advertised()` — NARF models neither
    /// input (no vif cfg, no wiphy iftype ext capa), so the
    /// fail-closed value is 0 with `emlsr = false` (the EHT MLD
    /// TLV then carries `str_cap[0] = BIT(1)`). See `mlo.rs` for
    /// the full provenance; never fill this from the negotiated
    /// EHT caps — upstream does not source EML there.
    pub eml_cap: u16,
    /// `true` when EMLSR is supported (selects the `eml_cap` bytes;
    /// otherwise `str_cap[0] = BIT(1)`).
    pub emlsr: bool,
}

/// Encode `sta_rec_mld` (`mt7925/mcu.c:2066-2140`): `{ mac_addr[6],
/// primary_id: u16 LE, secondary_id: u16 LE, wlan_id: u16 LE,
/// link_num, rsv[3], link[2] of { wlan_id: u16 LE, bss_idx, rsv } }`.
pub fn encode_sta_rec_mld_tlv(links: &MldLinks, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_MLD_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_MLD.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_MLD_TLV_SIZE as u16).to_le_bytes());
    body[4..10].copy_from_slice(&links.own_mac);
    body[10..12].copy_from_slice(&links.primary.wcid_idx.to_le_bytes());
    let secondary_id = links.secondary.map_or(0, |s| s.wcid_idx);
    body[12..14].copy_from_slice(&secondary_id.to_le_bytes());
    body[14..16].copy_from_slice(&links.primary.wcid_idx.to_le_bytes());
    // link[0]: primary first.
    let mut link_num = 1u8;
    body[20..22].copy_from_slice(&links.primary.wcid_idx.to_le_bytes());
    body[22] = links.primary.bss_idx;
    if let Some(secondary) = links.secondary {
        link_num = 2;
        body[24..26].copy_from_slice(&secondary.wcid_idx.to_le_bytes());
        body[26] = secondary.bss_idx;
    }
    body[16] = link_num;
    Some(())
}

/// Encode `sta_rec_mld` for a station on a non-MLD vif
/// (`mt7925_mcu_sta_mld_tlv`, `mt7925/mcu.c:1913-1944`, which has no
/// MLD gate of its own): `mac_addr = sta->addr` (the peer), `primary_id
/// = wlan_id = deflink wcid`, `secondary_id = 0`, and `link_num =
/// min(hweight16(mvif->valid_links), 2)` = 0 because a non-MLD vif has
/// no valid links (`mvif->valid_links` is only written by
/// `mt7925_change_vif_links`, `mt7925/main.c:2039`), so `link[]` stays
/// zero.
pub fn encode_sta_rec_mld_tlv_non_mld(
    peer_addr: [u8; MAC_ADDR_LEN],
    wcid_idx: u16,
    out: &mut [u8],
) -> Option<()> {
    let body = out.get_mut(..STA_REC_MLD_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_MLD.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_MLD_TLV_SIZE as u16).to_le_bytes());
    body[4..10].copy_from_slice(&peer_addr);
    body[10..12].copy_from_slice(&wcid_idx.to_le_bytes());
    body[14..16].copy_from_slice(&wcid_idx.to_le_bytes());
    Some(())
}

/// Encode `sta_rec_eht_mld` (`mt7925/mcu.c:2028-2062`): `{ nsep = 0,
/// mld_type = 0xff, rsv1 = 0, str_cap[3], eml_cap[3], rsv2[3] }`.
/// With EMLSR the low two bytes of `eml_cap` go into `eml_cap[0..2]`;
/// without it `str_cap[0] = BIT(1)`.
pub fn encode_sta_rec_eht_mld_tlv(links: &MldLinks, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_EHT_MLD_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_EHT_MLD.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_EHT_MLD_TLV_SIZE as u16).to_le_bytes());
    body[5] = 0xff; // mld_type
    if links.emlsr {
        // eml_cap[0] at offset 10, eml_cap[1] at offset 11.
        body[10] = (links.eml_cap & 0xff) as u8;
        body[11] = (links.eml_cap >> 8) as u8;
    } else {
        // str_cap[0] at offset 7.
        body[7] = 1 << 1; // str_cap[0] = BIT(1)
    }
    Some(())
}

/// EHT capability values for `sta_rec_eht` (`mt7925/mcu.h:427-443`).
/// All fields are plain inputs: slice 7 computes them from the AP's
/// EHT IEs; this struct only carries them to the wire.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StaEhtCaps {
    /// TID bitmap.
    pub tid_bitmap: u8,
    /// EHT MAC capabilities.
    pub mac_cap: u16,
    /// EHT PHY capabilities.
    pub phy_cap: u64,
    /// EHT PHY capabilities, extended.
    pub phy_cap_ext: u64,
    /// MCS map, 20 MHz (4 bytes).
    pub mcs_map_bw20: [u8; 4],
    /// MCS map, 80 MHz (3 bytes).
    pub mcs_map_bw80: [u8; 3],
    /// MCS map, 160 MHz (3 bytes).
    pub mcs_map_bw160: [u8; 3],
    /// MCS map, 320 MHz (3 bytes). Present in the struct even though
    /// 320 MHz stays refused — the firmware layout is fixed.
    pub mcs_map_bw320: [u8; 3],
}

/// Encode `sta_rec_eht` (`mt7925/mcu.c:1800-1818`,
/// `mt7925_mcu_sta_eht_tlv`): `{ tid_bitmap, _rsv, mac_cap: u16 LE,
/// phy_cap: u64 LE, phy_cap_ext: u64 LE, mcs_map_bw20[4],
/// mcs_map_bw80[3], mcs_map_bw160[3], mcs_map_bw320[3], _rsv2[3] }`.
pub fn encode_sta_rec_eht_tlv(caps: &StaEhtCaps, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_EHT_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_EHT.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_EHT_TLV_SIZE as u16).to_le_bytes());
    body[4] = caps.tid_bitmap;
    body[6..8].copy_from_slice(&caps.mac_cap.to_le_bytes());
    body[8..16].copy_from_slice(&caps.phy_cap.to_le_bytes());
    body[16..24].copy_from_slice(&caps.phy_cap_ext.to_le_bytes());
    body[24..28].copy_from_slice(&caps.mcs_map_bw20);
    body[28..31].copy_from_slice(&caps.mcs_map_bw80);
    body[31..34].copy_from_slice(&caps.mcs_map_bw160);
    body[34..37].copy_from_slice(&caps.mcs_map_bw320);
    Some(())
}

/// Encode `sta_rec_remove` (`mt7925/mcu.c:2144-2156`): `{ action = 0,
/// pad[3] }`.
pub fn encode_sta_rec_remove_tlv(out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..STA_REC_REMOVE_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_REMOVE.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_REMOVE_TLV_SIZE as u16).to_le_bytes());
    Some(())
}

// ── Station builders ─────────────────────────────────────────────

/// Parameters for one link's UNI station update
/// (`mt7925_mcu_sta_cmd`, `mt7925/mcu.c:1958-2010`, the
/// `info->enable && info->link_sta` branch).
#[derive(Clone, Debug)]
pub struct UniStaParams<'a> {
    /// BSS index of this link (`mvif->idx`).
    pub bss_idx: u8,
    /// WCID index of this link's station record.
    pub wcid_idx: u16,
    /// OMAC index of the vif (`muar_idx`).
    pub omac_idx: u8,
    /// Connection type (`CONN_TYPE_*`).
    pub conn_type: u32,
    /// Connection state (`CONN_STATE_*`).
    pub conn_state: u8,
    /// Association id (0 before association).
    pub aid: u16,
    /// Peer (AP) address.
    pub peer_addr: [u8; MAC_ADDR_LEN],
    /// QoS (WMM) negotiated.
    pub qos: bool,
    /// `true` when this is a newly-added station
    /// (upstream: `state != MT76_STA_INFO_STATE_ASSOC`).
    pub newly: bool,
    /// Station info state (`STA_STATE_*`).
    pub state: u8,
    /// `STA_REC_PHY` inputs.
    pub phy: UniStaPhy,
    /// Caller-supplied capability TLV stream, appended verbatim
    /// between PHY and RA in upstream order: HT, VHT, (UAPSD: AP vifs
    /// only, never here), HW_AMSDU, HE_V2, HE_6G, EHT — each present
    /// only when the peer has the capability. Filled by
    /// `mt7921::association::JoinPlan::uni_sta_caps` from the
    /// negotiated profiles.
    pub cap_tlvs: &'a [u8],
    /// `STA_REC_RA` inputs.
    pub ra: UniStaRa,
    /// `sta_rec_state_v2.vht_opmode` (0 for a non-VHT peer).
    pub vht_opmode: u8,
    /// `STA_REC_HDR_TRANS` inputs.
    pub hdr_trans: UniStaHdrTrans,
    /// MLD links, when the vif is an MLD vif. Once the state is not
    /// NONE the MLD TLV follows STATE for every station (built from
    /// these links, or the non-MLD form with `link_num = 0` when
    /// `None`), and the EHT MLD TLV follows it only for an MLD vif
    /// (`mt7925_mcu_sta_eht_mld_tlv` returns unless
    /// `ieee80211_vif_is_mld`).
    pub mld: Option<MldLinks>,
}

/// Upper bound on what [`build_uni_sta_update_req`] emits for one
/// link with no capability TLVs, in state NONE: hdr (8), BASIC (20),
/// PHY (12), RA (16), STATE_V2 (16) and HDR_TRANS (8). A non-NONE
/// state adds MLD (28), an MLD vif EHT MLD (16) on top; capability
/// TLVs add their own length. This is a NARF-side bound for the TLVs
/// this module emits, not upstream's `MT7925_STA_UPDATE_MAX_SIZE`.
pub const UNI_STA_UPDATE_BOUND: usize = STA_REQ_HDR_SIZE
    + STA_REC_BASIC_TLV_SIZE
    + STA_REC_PHY_TLV_SIZE
    + STA_REC_RA_TLV_SIZE
    + STA_REC_STATE_V2_TLV_SIZE
    + STA_REC_HDR_TRANS_TLV_SIZE;

/// Build one link's UNI station-update body
/// (`MCU_UNI_CMD(STA_REC_UPDATE)`, `mt7925_mcu_sta_cmd` with
/// `enable` and a `link_sta`, `mt7925/mcu.c:1977-2007`):
/// `sta_req_hdr` + BASIC + PHY + `cap_tlvs` (HT, VHT, HW_AMSDU,
/// HE_V2, HE_6G, EHT) + RA + STATE_V2 [+ MLD [+ EHT MLD]] +
/// HDR_TRANS. HDR_TRANS is the enable branch's tail
/// (`mt7925/mcu.c:2005-2007`); the disable branch is
/// [`build_uni_sta_remove_req`]. The caller sends one such message
/// per active link, primary first (`mt7925_mcu_sta_update` per
/// `mlink`).
pub fn build_uni_sta_update_req(params: &UniStaParams<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(UNI_STA_UPDATE_BOUND + params.cap_tlvs.len() + 44);
    out.resize(STA_REQ_HDR_SIZE, 0);
    let _ = encode_sta_req_hdr(params.bss_idx, params.wcid_idx, params.omac_idx, &mut out);
    let mut tlv_count: u16 = 0;

    let mut basic = [0u8; STA_REC_BASIC_TLV_SIZE];
    let _ = encode_sta_rec_basic_tlv(
        params.conn_type,
        params.conn_state,
        params.aid,
        params.peer_addr,
        params.qos,
        params.newly,
        &mut basic,
    );
    out.extend_from_slice(&basic);
    tlv_count += 1;

    let mut phy = [0u8; STA_REC_PHY_TLV_SIZE];
    let _ = encode_sta_rec_phy_tlv(&params.phy, &mut phy);
    out.extend_from_slice(&phy);
    tlv_count += 1;

    out.extend_from_slice(params.cap_tlvs);
    // Capability TLVs arrive pre-counted by the caller: each is a
    // 4-byte-header TLV, so count them by walking their lengths.
    let mut rest = params.cap_tlvs;
    while rest.len() >= TLV_HDR_SIZE {
        let len = u16::from_le_bytes([rest[2], rest[3]]) as usize;
        if len < TLV_HDR_SIZE || len > rest.len() {
            break;
        }
        tlv_count += 1;
        rest = &rest[len..];
    }

    let mut ra = [0u8; STA_REC_RA_TLV_SIZE];
    let _ = encode_sta_rec_ra_tlv(&params.ra, &mut ra);
    out.extend_from_slice(&ra);
    tlv_count += 1;

    let mut state = [0u8; STA_REC_STATE_V2_TLV_SIZE];
    let _ = encode_sta_rec_state_v2_tlv(params.state, params.vht_opmode, &mut state);
    out.extend_from_slice(&state);
    tlv_count += 1;

    if params.state != STA_STATE_NONE {
        let mut mld = [0u8; STA_REC_MLD_TLV_SIZE];
        let _ = match params.mld {
            Some(links) => encode_sta_rec_mld_tlv(&links, &mut mld),
            None => encode_sta_rec_mld_tlv_non_mld(params.peer_addr, params.wcid_idx, &mut mld),
        };
        out.extend_from_slice(&mld);
        tlv_count += 1;
        if let Some(links) = params.mld {
            let mut eht_mld = [0u8; STA_REC_EHT_MLD_TLV_SIZE];
            let _ = encode_sta_rec_eht_mld_tlv(&links, &mut eht_mld);
            out.extend_from_slice(&eht_mld);
            tlv_count += 1;
        }
    }

    let mut hdr_trans = [0u8; STA_REC_HDR_TRANS_TLV_SIZE];
    let _ = encode_sta_rec_hdr_trans_tlv(&params.hdr_trans, &mut hdr_trans);
    out.extend_from_slice(&hdr_trans);
    tlv_count += 1;

    set_sta_req_tlv_count(&mut out, tlv_count);
    out
}

/// Build one link's UNI TX-BA message (`mt7925/mcu.c:761-793`,
/// `mt7925_mcu_uni_tx_ba` via `mt7925_mcu_sta_ba`): `sta_req_hdr` +
/// a single `STA_REC_BA` TLV. One message per active link; the
/// caller loops the links. `enable && !amsdu` also clears the
/// link's AMSDU flag in upstream — the caller's station state owns
/// that, not this encoder.
#[allow(clippy::too_many_arguments)] // wide hw ABI: 8 BA fields mirror the on-wire TLV
pub fn build_uni_tx_ba_req(
    bss_idx: u8,
    wcid_idx: u16,
    omac_idx: u8,
    tid: u8,
    amsdu: bool,
    enable: bool,
    ssn: u16,
    winsize: u16,
) -> Option<Vec<u8>> {
    build_uni_ba_req(
        bss_idx, wcid_idx, omac_idx, tid, true, amsdu, enable, ssn, winsize,
    )
}

/// Build one link's UNI RX-BA message (`mt7925/mcu.c:795-824`,
/// `mt7925_mcu_uni_rx_ba`): `sta_req_hdr` + a single `STA_REC_BA`
/// TLV. One message per active link.
#[allow(clippy::too_many_arguments)] // wide hw ABI: 8 BA fields mirror the on-wire TLV
pub fn build_uni_rx_ba_req(
    bss_idx: u8,
    wcid_idx: u16,
    omac_idx: u8,
    tid: u8,
    amsdu: bool,
    enable: bool,
    ssn: u16,
    winsize: u16,
) -> Option<Vec<u8>> {
    build_uni_ba_req(
        bss_idx, wcid_idx, omac_idx, tid, false, amsdu, enable, ssn, winsize,
    )
}

/// Shared TX/RX BA encoder.
#[allow(clippy::too_many_arguments)] // wide hw ABI: 9 BA fields mirror the on-wire TLV
fn build_uni_ba_req(
    bss_idx: u8,
    wcid_idx: u16,
    omac_idx: u8,
    tid: u8,
    tx: bool,
    amsdu: bool,
    enable: bool,
    ssn: u16,
    winsize: u16,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(STA_REQ_HDR_SIZE + STA_REC_BA_UNI_TLV_SIZE);
    out.resize(STA_REQ_HDR_SIZE, 0);
    encode_sta_req_hdr(bss_idx, wcid_idx, omac_idx, &mut out)?;
    let mut ba = [0u8; STA_REC_BA_UNI_TLV_SIZE];
    encode_sta_rec_ba_uni_tlv(tid, tx, amsdu, enable, ssn, winsize, &mut ba)?;
    out.extend_from_slice(&ba);
    set_sta_req_tlv_count(&mut out, 1);
    Some(out)
}

/// Build one link's UNI station-remove body
/// (`mt7925/mcu.c:2237-2244`): `sta_req_hdr` + `STA_REC_REMOVE` +
/// a bare `STA_REC_MLD_OFF` TLV (tag + len only, 4 bytes).
pub fn build_uni_sta_remove_req(bss_idx: u8, wcid_idx: u16, omac_idx: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(STA_REQ_HDR_SIZE + STA_REC_REMOVE_TLV_SIZE + TLV_HDR_SIZE);
    out.resize(STA_REQ_HDR_SIZE, 0);
    let _ = encode_sta_req_hdr(bss_idx, wcid_idx, omac_idx, &mut out);
    let mut remove = [0u8; STA_REC_REMOVE_TLV_SIZE];
    let _ = encode_sta_rec_remove_tlv(&mut remove);
    out.extend_from_slice(&remove);
    let _ = append_tlv(&mut out, STA_REC_MLD_OFF, &[]);
    set_sta_req_tlv_count(&mut out, 2);
    out
}

/// Parameters for one link's UNI key install/remove
/// (`mt7925_mcu_sta_key_tlv`, `mt7925/mcu.c:1320-1401`).
#[derive(Clone, Debug)]
pub struct UniStaKeyParams<'a> {
    /// BSS index of this link (`mconf->mt76.idx`).
    pub bss_idx: u8,
    /// WCID index of the station record the key belongs to.
    pub wcid_idx: u16,
    /// OMAC index of the vif (`muar_idx`).
    pub omac_idx: u8,
    /// `true` = SET_KEY (`add = 1`), `false` = DISABLE_KEY (`add = 0`).
    pub add: bool,
    /// `true` for a pairwise key (upstream's `sta` branch, which
    /// also sets `key_type = 1`); `false` for a group/IGTK key (the
    /// vif-sta branch, `tx_key = key_type = 0`).
    pub pairwise: bool,
    /// Peer address: the AP address for a pairwise key, the BSSID
    /// for a group/IGTK key (the vif-sta branch copies
    /// `link_conf->bssid`).
    pub peer_addr: [u8; MAC_ADDR_LEN],
    /// CONNAC3 cipher id (`CONNAC3_CIPHER_*`). Ignored (zeroed)
    /// when `add` is false: upstream only consults the cipher on
    /// the SET_KEY path.
    pub cipher_id: u8,
    /// Key index. Ignored (zeroed) when `add` is false, except the
    /// BIP batch, which carries the GTK index here (see
    /// `key` below).
    pub key_id: u8,
    /// Key bytes: at most 32. Empty when `add` is false. For the
    /// BIP batch (`cipher_id == CONNAC3_CIPHER_BIP_CMAC_128`) this
    /// is the 32-byte `key[0] || key[1]` pair — the installed GTK
    /// (16 bytes) followed by the IGTK (16 bytes) — and `key_id`
    /// is the GTK index (`mt7925/mcu.c:1372-1377`).
    pub key: &'a [u8],
}

/// Encode `sta_rec_sec_uni` (`mt7925/mcu.c:1320-1401`,
/// `mt7925/mcu.h`): `{ add, tx_key, key_type, is_authenticator = 0,
/// peer_addr[6], bss_idx, cipher_id, key_id, key_len, wlan_idx,
/// mgmt_prot = 1, key[32], key_rsc[16] = 0 }`. `mgmt_prot` is 1
/// unconditionally upstream ("only used in MLO mode").
/// `is_authenticator` and `key_rsc` are never set by upstream here
/// and stay 0. `None` when `out` is short, the key is over 32
/// bytes, or a remove carries key bytes.
/// TKIP MIC order: upstream swaps the Rx/Tx MIC halves
/// (`mt7925/mcu.c:1384-1388`); this encoder copies `key` verbatim,
/// so callers must not pass a TKIP key — the association layer
/// refuses TKIP key installs (see `connac3_cipher_for_suite`).
pub fn encode_sta_rec_key_v3_tlv(params: &UniStaKeyParams<'_>, out: &mut [u8]) -> Option<()> {
    if params.key.len() > STA_REC_KEY_V3_MAX_KEY_LEN || !params.add && !params.key.is_empty() {
        return None;
    }
    let body = out.get_mut(..STA_REC_KEY_V3_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&STA_REC_KEY_V3.to_le_bytes());
    body[2..4].copy_from_slice(&(STA_REC_KEY_V3_TLV_SIZE as u16).to_le_bytes());
    body[4] = u8::from(params.add);
    body[5] = u8::from(params.pairwise);
    body[6] = u8::from(params.pairwise);
    body[8..14].copy_from_slice(&params.peer_addr);
    body[14] = params.bss_idx;
    if params.add {
        body[15] = params.cipher_id;
        body[16] = params.key_id;
        body[17] = params.key.len() as u8;
        body[20..20 + params.key.len()].copy_from_slice(params.key);
    }
    body[18] = (params.wcid_idx & 0xff) as u8;
    body[19] = 1; // mgmt_prot
    Some(())
}

/// Build one link's UNI key body (`mt7925_mcu_add_key`,
/// `mt7925/mcu.c:1403-1423`): `sta_req_hdr` + a single
/// `STA_REC_KEY_V3` TLV. A key install/remove is its own
/// `STA_REC_UPDATE`, unlike the CONNAC2 secure peer record, which
/// appends `STA_REC_KEY_V2` to the full station record.
pub fn build_uni_sta_key_req(params: &UniStaKeyParams<'_>) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(STA_REQ_HDR_SIZE + STA_REC_KEY_V3_TLV_SIZE);
    out.resize(STA_REQ_HDR_SIZE, 0);
    encode_sta_req_hdr(params.bss_idx, params.wcid_idx, params.omac_idx, &mut out)?;
    let mut key = [0u8; STA_REC_KEY_V3_TLV_SIZE];
    encode_sta_rec_key_v3_tlv(params, &mut key)?;
    out.extend_from_slice(&key);
    set_sta_req_tlv_count(&mut out, 1);
    Some(out)
}

// ── BSS TLV encoders ─────────────────────────────────────────────

/// `mt76_connac_bss_basic_tlv` total size
/// (`mt76_connac_mcu.h:1510-1539`): tag+len (4) + active (1) +
/// omac_idx (1) + hw_bss_idx (1) + band_idx (1) + conn_type (4) +
/// conn_state (1) + wmm_idx (1) + bssid (6) + bmc_tx_wlan_idx (2) +
/// bcn_interval (2) + dtim_period (1) + phymode (1) + sta_idx (2) +
/// nonht_basic_phy (2) + phymode_ext (1) + link_idx (1).
pub const UNI_BSS_BASIC_TLV_SIZE: usize = 32;
/// `bss_sec_tlv` total size (`mt7925/mcu.c:2823-2832`): tag+len (4) +
/// mode (1) + status (1) + cipher (1) + rsv (1).
pub const UNI_BSS_SEC_TLV_SIZE: usize = 8;
/// `bss_rate_tlv` total size (`mt7925/mcu.h:374-385`).
pub const UNI_BSS_RATE_TLV_SIZE: usize = 16;
/// `mt76_connac_bss_qos_tlv` total size
/// (`mt76_connac_mcu.h:1540-1545`).
pub const UNI_BSS_QOS_TLV_SIZE: usize = 8;
/// `bss_mld_tlv` total size (`mt7925/mcu.h:387-399`).
pub const UNI_BSS_MLD_TLV_SIZE: usize = 20;
/// `bss_ifs_time_tlv` total size (`mt7925/mcu.h:495-508`).
pub const UNI_BSS_IFS_TLV_SIZE: usize = 20;
/// `bss_info_uni_he` total size (`mt76_connac_mcu.h:1708-1716`).
pub const UNI_BSS_HE_TLV_SIZE: usize = 16;
/// `bss_info_uni_bss_color` total size
/// (`mt76_connac_mcu.h:1700-1705`).
pub const UNI_BSS_COLOR_TLV_SIZE: usize = 8;
/// `bss_rlm_tlv` total size (`mt7925/mcu.h:510-525`).
pub const UNI_BSS_RLM_TLV_SIZE: usize = 16;
/// `bss_info_uni_mbssid` total size (`mt76_connac_mcu.h:1718-1724`).
pub const UNI_BSS_MBSSID_TLV_SIZE: usize = 8;
/// `bss_eht_tlv` total size (`mt7925/mcu.h:400-412`).
pub const UNI_BSS_EHT_TLV_SIZE: usize = 16;

/// Security modes for the BSS SEC TLV (`mt7925/mcu.h:156-163`, enum).
pub const BSS_SEC_MODE_OPEN: u8 = 0;
pub const BSS_SEC_MODE_SHARED: u8 = 1;
pub const BSS_SEC_MODE_WPA: u8 = 3;
pub const BSS_SEC_MODE_WPA_PSK: u8 = 4;
pub const BSS_SEC_MODE_WPA_NONE: u8 = 5;
pub const BSS_SEC_MODE_WPA2: u8 = 6;
pub const BSS_SEC_MODE_WPA2_PSK: u8 = 7;
pub const BSS_SEC_MODE_WPA3_SAE: u8 = 11;

/// Basic-rate sets for the BSS RATE TLV (`mt7925/mcu.c:2897-2906`,
/// `mt76_connac_mcu.h:999-1000`): 2.4 GHz uses
/// `HR_DSSS_ERP_BASIC_RATE` (GENMASK(3, 0)), 5/6 GHz uses
/// `OFDM_BASIC_RATE` (BIT(6) | BIT(8) | BIT(10)).
pub const BSS_BASIC_RATE_2G: u16 = 0x000f;
pub const BSS_BASIC_RATE_5G: u16 = (1 << 6) | (1 << 8) | (1 << 10);

/// Channel bandwidths for the RLM TLV (`mt76_connac.h:56-64`,
/// `CMD_CBW_*` = `IEEE80211_STA_RX_BW_*` for 20/40/80/160).
pub const RLM_BW_20: u8 = 0;
pub const RLM_BW_40: u8 = 1;
pub const RLM_BW_80: u8 = 2;
pub const RLM_BW_160: u8 = 3;
pub const RLM_BW_10: u8 = 4;
pub const RLM_BW_5: u8 = 5;
pub const RLM_BW_80P80: u8 = 6;
/// 320 MHz. The value exists in the upstream enum; no caller in
/// this slice passes it (320 MHz stays refused).
pub const RLM_BW_320: u8 = 7;

/// RLM band values (`mt7925/mcu.c:2553-2563`): 1 = 2.4 GHz,
/// 2 = 5 GHz, 3 = 6 GHz.
pub const RLM_BAND_2G: u8 = 1;
pub const RLM_BAND_5G: u8 = 2;
pub const RLM_BAND_6G: u8 = 3;

/// Encode the UNI BSS BASIC TLV (`mt7925/mcu.c:2734-2815`,
/// `mt7925_mcu_bss_basic_tlv`). Field order follows
/// `mt76_connac_bss_basic_tlv`; `conn_state` is `!enable` upstream
/// (0 when enabling, 1 when disabling), and `active` is set per
/// iftype by the caller (station: `true`).
#[allow(clippy::too_many_arguments)]
pub fn encode_uni_bss_basic_tlv(
    active: bool,
    omac_idx: u8,
    hw_bss_idx: u8,
    band_idx: u8,
    conn_type: u32,
    conn_state: u8,
    wmm_idx: u8,
    bssid: [u8; MAC_ADDR_LEN],
    bmc_tx_wlan_idx: u16,
    bcn_interval: u16,
    dtim_period: u8,
    phymode: u8,
    sta_idx: u16,
    nonht_basic_phy: u16,
    phymode_ext: u8,
    link_idx: u8,
    out: &mut [u8],
) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_BASIC_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_BASIC.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_BASIC_TLV_SIZE as u16).to_le_bytes());
    body[4] = active as u8;
    body[5] = omac_idx;
    body[6] = hw_bss_idx;
    body[7] = band_idx;
    body[8..12].copy_from_slice(&conn_type.to_le_bytes());
    body[12] = conn_state;
    body[13] = wmm_idx;
    body[14..20].copy_from_slice(&bssid);
    body[20..22].copy_from_slice(&bmc_tx_wlan_idx.to_le_bytes());
    body[22..24].copy_from_slice(&bcn_interval.to_le_bytes());
    body[24] = dtim_period;
    body[25] = phymode;
    body[26..28].copy_from_slice(&sta_idx.to_le_bytes());
    body[28..30].copy_from_slice(&nonht_basic_phy.to_le_bytes());
    body[30] = phymode_ext;
    body[31] = link_idx;
    Some(())
}

/// Encode the UNI BSS SEC TLV (`mt7925/mcu.c:2819-2857`): `{ mode,
/// status, cipher, rsv }`. Mode/status pairs: OPEN (0, 1), WPA2-PSK
/// CCMP (7, 6), WPA3-SAE GCMP (11, 8), TKIP (7, 4), WEP (1, 0).
pub fn encode_uni_bss_sec_tlv(mode: u8, status: u8, cipher: u8, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_SEC_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_SEC.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_SEC_TLV_SIZE as u16).to_le_bytes());
    body[4] = mode;
    body[5] = status;
    body[6] = cipher;
    Some(())
}

/// Encode the UNI BSS RATE TLV (`mt7925/mcu.c:2860-2909`,
/// `mt7925_mcu_bss_bmc_tlv`): `{ rsv1[2] = 0, basic_rate: u16 LE,
/// bc_trans = 0, mc_trans = 0, short_preamble, bc_fixed_rate,
/// mc_fixed_rate, rsv2 = 0 }`. The fixed-rate index is the vif's
/// mcast/basic rates index; 2.4 GHz sets `short_preamble = 1`.
pub fn encode_uni_bss_rate_tlv(
    basic_rate: u16,
    short_preamble: bool,
    fixed_rate_idx: u8,
    out: &mut [u8],
) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_RATE_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_RATE.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_RATE_TLV_SIZE as u16).to_le_bytes());
    body[6..8].copy_from_slice(&basic_rate.to_le_bytes());
    body[12] = short_preamble as u8;
    body[13] = fixed_rate_idx;
    body[14] = fixed_rate_idx;
    Some(())
}

/// Encode the UNI BSS QoS TLV (`mt7925/mcu.c:2931-2941`): `{ qos,
/// pad[3] }`.
pub fn encode_uni_bss_qos_tlv(qos: bool, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_QOS_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_QBSS.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_QOS_TLV_SIZE as u16).to_le_bytes());
    body[4] = qos as u8;
    Some(())
}

/// Per-link MLD identity for one BSS record
/// (`mt7925/mcu.c:2912-2929`, `mt7925_mcu_bss_mld_tlv`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UniBssMld {
    /// `true` when the vif is an MLD vif (or has >1 valid link).
    /// `link_id`/`group_mld_id` are `0xff` when false.
    pub is_mld: bool,
    /// Link id of this BSS record (`link_conf->link_id`).
    pub link_id: u8,
    /// BSS index of the primary link (`mvif->bss_conf.mt76.idx`).
    pub primary_bss_idx: u8,
    /// The vif's own MAC.
    pub own_mac: [u8; MAC_ADDR_LEN],
    /// `true` when EMLSR is enabled on this vif (chip EML capable
    /// and `eml_cap & EMLSR_SUPP`).
    pub eml_enable: bool,
}

/// Encode the UNI BSS MLD TLV (`mt7925/mcu.c:2912-2929`): `{
/// group_mld_id, own_mld_id = bss_idx + 32, mac_addr[6],
/// remap_idx = 0xff, link_id, eml_enable, max_link_num = 0,
/// hybrid_mode = 0, rsv[3] }`. `bss_idx` is this record's BSS
/// index, from the enclosing `bss_req_hdr`.
pub fn encode_uni_bss_mld_tlv(mld: &UniBssMld, bss_idx: u8, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_MLD_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_MLD.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_MLD_TLV_SIZE as u16).to_le_bytes());
    body[4] = if mld.is_mld {
        mld.primary_bss_idx
    } else {
        0xff
    };
    body[5] = bss_idx.wrapping_add(32);
    body[6..12].copy_from_slice(&mld.own_mac);
    body[12] = 0xff; // remap_idx
    body[13] = if mld.is_mld { mld.link_id } else { 0xff };
    body[14] = mld.eml_enable as u8;
    Some(())
}

/// Encode the UNI BSS IFS TLV (`mt7925/mcu.c:2980-2994`): only
/// `slot_valid = 1` and `slot_time` are set; the rest are 0.
pub fn encode_uni_bss_ifs_tlv(slot_time: u16, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_IFS_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_IFS_TIME.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_IFS_TLV_SIZE as u16).to_le_bytes());
    body[4] = 1; // slot_valid
    body[8..10].copy_from_slice(&slot_time.to_le_bytes());
    Some(())
}

/// Encode the UNI BSS HE TLV (`mt7925/mcu.c:2971-2996`,
/// `bss_info_uni_he`): `{ he_rts_thres: u16 LE, he_pe_duration,
/// su_disable = 0, max_nss_mcs[3]: u16 LE each, rsv[2] }`.
/// `max_nss_mcs` is indexed `[BW80, BW160, BW8080]`
/// (`CMD_HE_MCS_BW80 = 0, BW160 = 1, BW8080 = 2`); the values come
/// from the AP's HE caps (slice 7).
pub fn encode_uni_bss_he_tlv(
    he_pe_duration: u8,
    he_rts_thres: u16,
    max_nss_mcs: [u16; 3],
    out: &mut [u8],
) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_HE_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_HE_BASIC.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_HE_TLV_SIZE as u16).to_le_bytes());
    body[4..6].copy_from_slice(&he_rts_thres.to_le_bytes());
    body[6] = he_pe_duration;
    body[8..10].copy_from_slice(&max_nss_mcs[0].to_le_bytes());
    body[10..12].copy_from_slice(&max_nss_mcs[1].to_le_bytes());
    body[12..14].copy_from_slice(&max_nss_mcs[2].to_le_bytes());
    Some(())
}

/// Encode the UNI BSS COLOR TLV (`mt7925/mcu.c:2998-3010`): `{
/// enable, bss_color, rsv[2] }`. Both bytes are 0 when disabling.
pub fn encode_uni_bss_color_tlv(enable: bool, bss_color: u8, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_COLOR_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_BSS_COLOR.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_COLOR_TLV_SIZE as u16).to_le_bytes());
    body[4] = enable as u8;
    body[5] = if enable { bss_color } else { 0 };
    Some(())
}

/// RLM (channel) parameters for one link's BSS record
/// (`mt7925/mcu.c:2506-2586`, `mt7925_mcu_bss_rlm_tlv`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UniBssRlm {
    /// Primary channel number (`hw_value`).
    pub control_channel: u8,
    /// Center channel of the operating bandwidth.
    pub center_chan: u8,
    /// Center channel 2 (80P80 / 320 MHz only, else 0).
    pub center_chan2: u8,
    /// Bandwidth (`RLM_BW_*`).
    pub bw: u8,
    /// Transmit stream count (antenna-mask population).
    pub tx_streams: u8,
    /// Receive stream count (antenna-mask population).
    pub rx_streams: u8,
    /// Band (`RLM_BAND_*`).
    pub band: u8,
}

/// Encode the UNI BSS RLM TLV (`mt7925/mcu.c:2506-2586`): `{
/// control_channel, center_chan, center_chan2, bw, tx_streams,
/// rx_streams, ht_op_info, sco, band, pad[3] }`.
/// `ht_op_info` is 4 ("HT 40M allowed") except at 20 MHz (0);
/// `sco` is 1 (SCA) when control < center, 3 (SCB) when control >
/// center, else 0.
pub fn encode_uni_bss_rlm_tlv(rlm: &UniBssRlm, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_RLM_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_RLM.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_RLM_TLV_SIZE as u16).to_le_bytes());
    body[4] = rlm.control_channel;
    body[5] = rlm.center_chan;
    body[6] = rlm.center_chan2;
    body[7] = rlm.bw;
    body[8] = rlm.tx_streams;
    body[9] = rlm.rx_streams;
    body[10] = if rlm.bw == RLM_BW_20 { 0 } else { 4 };
    body[11] = if rlm.control_channel < rlm.center_chan {
        1
    } else if rlm.control_channel > rlm.center_chan {
        3
    } else {
        0
    };
    body[12] = rlm.band;
    Some(())
}

/// Encode the UNI BSS MBSSID TLV (`mt7925/mcu.c:2943-2969`): `{
/// max_indicator, mbss_idx, tx_bss_omac_idx = 0, rsv }`.
pub fn encode_uni_bss_mbssid_tlv(max_indicator: u8, mbss_idx: u8, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_MBSSID_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_11V_MBSSID.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_MBSSID_TLV_SIZE as u16).to_le_bytes());
    body[4] = max_indicator;
    body[5] = mbss_idx;
    Some(())
}

/// Encode the UNI BSS EHT TLV (`mt7925/mcu.h:400-412`,
/// `mt7925/mcu.c:2606-2621`): only the puncturing fields are set —
/// `is_eth_dscb_present = punctured != 0`,
/// `eht_dis_sub_chan_bitmap = punctured`; the rest are 0.
pub fn encode_uni_bss_eht_tlv(punctured: u16, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..UNI_BSS_EHT_TLV_SIZE)?;
    body.fill(0);
    body[0..2].copy_from_slice(&UNI_BSS_INFO_EHT.to_le_bytes());
    body[2..4].copy_from_slice(&(UNI_BSS_EHT_TLV_SIZE as u16).to_le_bytes());
    body[5] = u8::from(punctured != 0);
    body[10..12].copy_from_slice(&punctured.to_le_bytes());
    Some(())
}

// ── BSS builders ─────────────────────────────────────────────────

/// Security identity for one link's BSS SEC TLV.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UniBssSec {
    /// Security mode (`BSS_SEC_MODE_*`).
    pub mode: u8,
    /// Security status (OPEN 1, WPA2-PSK 6, WPA3-SAE 8, TKIP 4, WEP 0).
    pub status: u8,
    /// Cipher (`CONNAC3_CIPHER_*` byte from the vif).
    pub cipher: u8,
}

/// Parameters for one link's UNI BSS-info station message
/// (`mt7925_mcu_add_bss_info_sta`, `mt7925/mcu.c:3102-3142`).
#[derive(Copy, Clone, Debug)]
pub struct UniBssParams {
    /// BSS index of this link (`mvif->idx`).
    pub bss_idx: u8,
    /// `true` when the BSS is being enabled; `conn_state = !enable`.
    pub enable: bool,
    /// Connection type (`CONN_TYPE_*`).
    pub conn_type: u32,
    /// OMAC index of the vif.
    pub omac_idx: u8,
    /// Hardware BSS index (`omac_idx` when `<= EXT_BSSID_START`,
    /// else `HW_BSSID_0`).
    pub hw_bss_idx: u8,
    /// Band index.
    pub band_idx: u8,
    /// WMM index.
    pub wmm_idx: u8,
    /// BSSID of the AP.
    pub bssid: [u8; MAC_ADDR_LEN],
    /// BMC TX WCID index.
    pub bmc_tx_wlan_idx: u16,
    /// Beacon interval (TU).
    pub bcn_interval: u16,
    /// DTIM period.
    pub dtim_period: u8,
    /// PHY mode (`PHY_MODE_*` bits).
    pub phymode: u8,
    /// Station WCID index.
    pub sta_idx: u16,
    /// Non-HT basic PHY index (`PHY_TYPE_ERP_INDEX` on 2.4 GHz,
    /// `PHY_TYPE_OFDM_INDEX` otherwise).
    pub nonht_basic_phy: u16,
    /// Extended PHY mode (`PHY_MODE_AX_6G` on 6 GHz, ...).
    pub phymode_ext: u8,
    /// Link index (`mvif->idx`).
    pub link_idx: u8,
    /// Security identity (mode/status/cipher).
    pub sec: UniBssSec,
    /// Basic-rate set (`BSS_BASIC_RATE_2G` / `BSS_BASIC_RATE_5G`).
    pub basic_rate: u16,
    /// Short preamble (2.4 GHz only).
    pub short_preamble: bool,
    /// Multicast/broadcast fixed-rate index.
    pub fixed_rate_idx: u8,
    /// QoS enabled on the BSS.
    pub qos: bool,
    /// Per-link MLD identity (always emitted).
    pub mld: UniBssMld,
    /// Slot time (µs) for the IFS TLV.
    pub slot_time: u16,
    /// HE parameters, when the BSS supports HE. Emits the HE + BSS
    /// COLOR TLVs; the values come from the AP's HE caps (slice 7).
    pub he: Option<UniBssHe>,
    /// RLM (channel) parameters, emitted only when enabling.
    pub rlm: Option<UniBssRlm>,
    /// MBSSID `(max_indicator, mbss_idx)`, emitted only when
    /// enabling.
    pub mbssid: Option<(u8, u8)>,
}

/// HE parameters for the BSS HE + COLOR TLVs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UniBssHe {
    /// HE PE duration (defaults to 4 upstream when 0).
    pub pe_duration: u8,
    /// HE RTS threshold (defaults to 1023 upstream when 0).
    pub rts_thres: u16,
    /// Max NSS/MCS per bandwidth, `[BW80, BW160, BW8080]`.
    pub max_nss_mcs: [u16; 3],
    /// BSS color enabled on this BSS.
    pub color_enabled: bool,
    /// BSS color value.
    pub color: u8,
}

/// Upper bound on what [`build_uni_bss_info_sta_req`] emits
/// (hdr 4, BASIC 32, SEC 8, RATE 16, QoS 8, MLD 20, IFS 20,
/// HE 16, COLOR 8, RLM 16, MBSSID 8). A NARF-side bound for the
/// TLVs this module emits, not upstream's `MT7925_BSS_UPDATE_MAX_SIZE`.
pub const UNI_BSS_UPDATE_BOUND: usize = BSS_REQ_HDR_SIZE
    + UNI_BSS_BASIC_TLV_SIZE
    + UNI_BSS_SEC_TLV_SIZE
    + UNI_BSS_RATE_TLV_SIZE
    + UNI_BSS_QOS_TLV_SIZE
    + UNI_BSS_MLD_TLV_SIZE
    + UNI_BSS_IFS_TLV_SIZE
    + UNI_BSS_HE_TLV_SIZE
    + UNI_BSS_COLOR_TLV_SIZE
    + UNI_BSS_RLM_TLV_SIZE
    + UNI_BSS_MBSSID_TLV_SIZE;

/// Build one link's UNI BSS-info message
/// (`MCU_UNI_CMD(BSS_INFO_UPDATE)`, `mt7925/mcu.c:3102-3142`).
/// TLV order is fixed upstream: BASIC (first, always), SEC, RATE,
/// QoS, MLD, IFS, then HE + COLOR when `he` is set, then RLM +
/// MBSSID when `enable`. The caller sends one such message per link
/// (`mt7925_mcu_add_bss_info` resolves the link's BC + station
/// WCIDs and forwards them here).
pub fn build_uni_bss_info_sta_req(params: &UniBssParams) -> Vec<u8> {
    let mut out = Vec::with_capacity(UNI_BSS_UPDATE_BOUND);
    out.resize(BSS_REQ_HDR_SIZE, 0);
    let _ = encode_bss_req_hdr(params.bss_idx, &mut out);

    let mut basic = [0u8; UNI_BSS_BASIC_TLV_SIZE];
    // Station arm (`mt7925/mcu.c:2804-2810`): active is `true`
    // unconditionally; enable/disable rides on conn_state = !enable.
    let _ = encode_uni_bss_basic_tlv(
        true,
        params.omac_idx,
        params.hw_bss_idx,
        params.band_idx,
        params.conn_type,
        u8::from(!params.enable),
        params.wmm_idx,
        params.bssid,
        params.bmc_tx_wlan_idx,
        params.bcn_interval,
        params.dtim_period,
        params.phymode,
        params.sta_idx,
        params.nonht_basic_phy,
        params.phymode_ext,
        params.link_idx,
        &mut basic,
    );
    out.extend_from_slice(&basic);

    let mut sec = [0u8; UNI_BSS_SEC_TLV_SIZE];
    let _ = encode_uni_bss_sec_tlv(
        params.sec.mode,
        params.sec.status,
        params.sec.cipher,
        &mut sec,
    );
    out.extend_from_slice(&sec);

    let mut rate = [0u8; UNI_BSS_RATE_TLV_SIZE];
    let _ = encode_uni_bss_rate_tlv(
        params.basic_rate,
        params.short_preamble,
        params.fixed_rate_idx,
        &mut rate,
    );
    out.extend_from_slice(&rate);

    let mut qos = [0u8; UNI_BSS_QOS_TLV_SIZE];
    let _ = encode_uni_bss_qos_tlv(params.qos, &mut qos);
    out.extend_from_slice(&qos);

    let mut mld = [0u8; UNI_BSS_MLD_TLV_SIZE];
    let _ = encode_uni_bss_mld_tlv(&params.mld, params.bss_idx, &mut mld);
    out.extend_from_slice(&mld);

    let mut ifs = [0u8; UNI_BSS_IFS_TLV_SIZE];
    let _ = encode_uni_bss_ifs_tlv(params.slot_time, &mut ifs);
    out.extend_from_slice(&ifs);

    if let Some(he) = params.he {
        let mut he_tlv = [0u8; UNI_BSS_HE_TLV_SIZE];
        let _ = encode_uni_bss_he_tlv(
            if he.pe_duration == 0 {
                4
            } else {
                he.pe_duration
            },
            if he.rts_thres == 0 {
                1023
            } else {
                he.rts_thres
            },
            he.max_nss_mcs,
            &mut he_tlv,
        );
        out.extend_from_slice(&he_tlv);

        let mut color = [0u8; UNI_BSS_COLOR_TLV_SIZE];
        let _ = encode_uni_bss_color_tlv(he.color_enabled, he.color, &mut color);
        out.extend_from_slice(&color);
    }

    if params.enable {
        if let Some(rlm) = params.rlm {
            let mut rlm_tlv = [0u8; UNI_BSS_RLM_TLV_SIZE];
            let _ = encode_uni_bss_rlm_tlv(&rlm, &mut rlm_tlv);
            out.extend_from_slice(&rlm_tlv);
        }
        if let Some((max_indicator, mbss_idx)) = params.mbssid {
            let mut mbssid = [0u8; UNI_BSS_MBSSID_TLV_SIZE];
            let _ = encode_uni_bss_mbssid_tlv(max_indicator, mbss_idx, &mut mbssid);
            out.extend_from_slice(&mbssid);
        }
    }

    out
}

/// Build the standalone BSS EHT message (`mt7925/mcu.c:2623-2637`,
/// `mt7925_mcu_set_eht_pp`): `bss_req_hdr` + the single EHT TLV.
/// Sent as its own `BSS_INFO_UPDATE`, not inside the
/// `add_bss_info_sta` stream.
pub fn build_uni_bss_eht_req(bss_idx: u8, punctured: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(BSS_REQ_HDR_SIZE + UNI_BSS_EHT_TLV_SIZE);
    out.resize(BSS_REQ_HDR_SIZE, 0);
    let _ = encode_bss_req_hdr(bss_idx, &mut out);
    let mut eht = [0u8; UNI_BSS_EHT_TLV_SIZE];
    let _ = encode_uni_bss_eht_tlv(punctured, &mut eht);
    out.extend_from_slice(&eht);
    out
}

// ── EFUSE over UNI ───────────────────────────────────────────────
//
// The CONNAC3 opcode for EFUSE access is the UNI EFUSE_CTRL command,
// not the CONNAC2 MCU_EXT_CMD_EFUSE_ACCESS that mt7921::mcu cites.
// Read: mt7925_mcu_read_eeprom (mt7925/mcu.c:824-870) sends
// MCU_WM_UNI_CMD_QUERY(EFUSE_CTRL) with tag UNI_EFUSE_ACCESS (1).
// Set: mt7925_mcu_set_eeprom (mt7925/mcu.c:1616-1631) sends
// MCU_UNI_CMD(EFUSE_CTRL) with tag UNI_EFUSE_BUFFER_MODE (2).
// Tags (mt7925/mcu.h:133-137): ACCESS = 1, BUFFER_MODE = 2,
// FREE_BLOCK = 3, BUFFER_RD = 4.
// Modes/formats (mt76_connac_mcu.h:1191-1200): EE_MODE_EFUSE = 0,
// EE_MODE_BUFFER = 1; EE_FORMAT_BIN = 0, EE_FORMAT_WHOLE = 1,
// EE_FORMAT_MULTIPLE = 2.

/// `UNI_EFUSE_ACCESS` tag = 1.
pub const UNI_EFUSE_ACCESS: u16 = 1;
/// `UNI_EFUSE_BUFFER_MODE` tag = 2.
pub const UNI_EFUSE_BUFFER_MODE: u16 = 2;
/// `EE_MODE_EFUSE` = 0.
pub const EE_MODE_EFUSE: u8 = 0;
/// `EE_FORMAT_WHOLE` = 1.
pub const EE_FORMAT_WHOLE: u8 = 1;

/// EFUSE read block size (`MT7925_EEPROM_BLOCK_SIZE`, 16 bytes).
pub const EFUSE_BLOCK_SIZE: usize = 16;

/// EFUSE read-request size: 4 reserved + tag/len (4) + addr (4) +
/// valid (4) + data (16).
pub const EFUSE_READ_REQ_SIZE: usize = 32;
/// EFUSE set-buffer-mode request size: 4 reserved + tag/len (4) +
/// buffer_mode (1) + format (1) + buf_len (2).
pub const EFUSE_SET_REQ_SIZE: usize = 12;
/// EFUSE read-response size: 4 reserved + tag/len (4) + ver (4) +
/// addr (4) + valid (4) + size (4) + magic (4) + type (4) +
/// rsv1[4] (16) + data (32).
pub const EFUSE_READ_RESP_SIZE: usize = 80;

/// Build the UNI EFUSE read request (`mt7925/mcu.c:824-856`):
/// `{ rsv[4] = 0, tag = 1, len = 28, addr = offset rounded down to
/// the 16-byte block, valid = 0, data[16] = 0 }`. The response byte
/// for `offset` is `data[offset % 16]`.
pub fn encode_uni_efuse_read_req(offset: u32, out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..EFUSE_READ_REQ_SIZE)?;
    body.fill(0);
    body[4..6].copy_from_slice(&UNI_EFUSE_ACCESS.to_le_bytes());
    body[6..8].copy_from_slice(&((EFUSE_READ_REQ_SIZE - 4) as u16).to_le_bytes());
    body[8..12].copy_from_slice(&(offset & !15).to_le_bytes());
    Some(())
}

/// Build the UNI EFUSE set-buffer-mode request
/// (`mt7925/mcu.c:1616-1631`): `{ rsv[4] = 0, tag = 2, len = 8,
/// buffer_mode = EE_MODE_EFUSE, format = EE_FORMAT_WHOLE,
/// buf_len = 0 }`. Sent before the MAC init reads EFUSE
/// (`__mt7925_init_hardware` → `mt7925_mcu_set_eeprom`).
pub fn encode_uni_efuse_set_req(out: &mut [u8]) -> Option<()> {
    let body = out.get_mut(..EFUSE_SET_REQ_SIZE)?;
    body.fill(0);
    body[4..6].copy_from_slice(&UNI_EFUSE_BUFFER_MODE.to_le_bytes());
    body[6..8].copy_from_slice(&((EFUSE_SET_REQ_SIZE - 4) as u16).to_le_bytes());
    body[8] = EE_MODE_EFUSE;
    body[9] = EE_FORMAT_WHOLE;
    Some(())
}

/// Parse the UNI EFUSE read response (`mt7925/mcu.c:842-867`) and
/// return the byte at `offset`: `data[offset % 16]` where `data`
/// starts at byte 48. `None` when the buffer is shorter than the
/// 80-byte response or the response address does not cover the
/// requested block.
pub fn parse_uni_efuse_read_resp(bytes: &[u8], offset: u32) -> Option<u8> {
    let b = bytes.get(..EFUSE_READ_RESP_SIZE)?;
    let addr = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    if addr != offset & !15 {
        return None;
    }
    Some(b[48 + (offset as usize & 15)])
}
