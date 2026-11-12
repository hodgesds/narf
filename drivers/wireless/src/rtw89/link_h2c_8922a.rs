// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A MLO link-lifecycle H2C builders (issue #1918).
//!
//! The firmware bodies Linux sends around each link add / assoc /
//! disconnect / remove for one 8922A link (`core.c`
//! `rtw89_core_sta_link_add` / `sta_link_assoc` /
//! `rtw89_core_sta_link_disconnect` / `rtw89_core_sta_link_remove`,
//! torvalds/linux @ cbbddb6 — verified identical in the local
//! `linux-rtw89-src` @ 067c5c2 reference; the only rtw89 diffs
//! between the two trees are unrelated allocator renames):
//!
//! - role-maintain CREATE / REMOVE (`fw.c`
//!   `rtw89_fw_h2c_role_maintain`);
//! - the default DMAC table v2 (`fw.c`
//!   `rtw89_fw_h2c_default_dmac_tbl_v2`, the 8922A chip op at
//!   `rtw8922a.c:3185`);
//! - join-info v1 (`fw.c` `rtw89_fw_h2c_join_info`, BE format with
//!   W1/W2 — including the `IS_MLD` bit, the main MACID, the MLSR
//!   mode and the link ID);
//! - the address-CAM update (`fw.c` `rtw89_fw_h2c_cam`,
//!   `RTW89_ROLE_CON_DISCONN`), built from `cam.c`
//!   `rtw89_cam_fill_addr_cam_info` /
//!   `rtw89_cam_fill_bssid_cam_info` with `addrcam_ver` 0
//!   (`rtw8922a.c:3289`);
//! - the MACID pause (`mac.c` `rtw89_mac_set_macid_pause` / `fw.c`
//!   `rtw89_fw_h2c_macid_pause`), plain and SLEEP variants.
//!
//! Like the station owner, this module builds H2C bodies but never
//! sends them: the caller frames them (`fwcmd_8922a::frame_h2c`,
//! identities in [`LinkCmd`]) and owns the transport. The
//! transition composers ([`link_add_h2cs`], [`link_assoc_h2cs`],
//! [`link_disconnect_h2cs`], [`link_remove_h2cs`]) emit the bodies
//! in Linux's order for one link, from a [`LinkView`] the caller
//! builds from an admitted record plus its VIF-link context.
//!
//! Which transitions send anything depends on the VIF kind —
//! exactly as in Linux:
//!
//! - Station links send nothing on add or remove (`sta_link_add` /
//!   `sta_link_remove` have no H2C for `NL80211_IFTYPE_STATION`);
//!   they send join-info + CAM on assoc and on disconnect.
//! - AP-mode / TDLS links additionally send MACID unpause +
//!   role-maintain CREATE + default DMAC on add, and
//!   role-maintain REMOVE on remove.
//!
//! Deliberate narrowings (all stated, none silent):
//! - The CAM body is the v0 layout (60 bytes) while the firmware
//!   predates 0.35.84.0 (`ADDR_CAM_V0`, `fw.c:1022`), and the
//!   64-byte form with W15 `UPD_MODE` once it does not. The v0
//!   body carries no update-mode field at all, so on old firmware
//!   the assoc/disconnect CAM update is distinguished from the
//!   init only by its sequence and its updated net-type / AID —
//!   the caller must know its firmware version to pick
//!   [`VifLinkCtx::addr_cam_v0`].
//! - The MACID pause is the plain 32-byte body while the
//!   firmware predates 0.34.11.0, and the 256-byte SLEEP body
//!   once it does not (`MACID_PAUSE_SLEEP`, `fw.c:999`) — same
//!   caller-selected switch ([`VifLinkCtx::macid_pause_sleep`]).
//! - The address-CAM / BSSID-CAM entry indices are caller
//!   inputs ([`VifLinkCtx`]): Linux allocates one addr-CAM entry
//!   (128-entry pool, `rtw8922a.c:3283`) and one BSSID-CAM entry
//!   (20-entry pool, `rtw8922a.c:3284`) per VIF link instance at
//!   VIF init (`cam.c` `rtw89_cam_init_addr_cam` /
//!   `rtw89_cam_init_bssid_cam`), and station links share the
//!   VIF link instance's entries (`core.h`
//!   `rtw89_get_addr_cam_of` / `rtw89_get_bssid_cam_of` — only
//!   AP links use the sta link's own addr-CAM entry, only TDLS
//!   links use the sta link's own BSSID-CAM entry). This module
//!   owns no CAM allocator; the Prepared owner must allocate the
//!   per-instance entries before it can emit these bodies.
//! - The per-link own address ([`VifLinkCtx::own`]) is a VIF-link
//!   input, not the station record's `own`: the station owner
//!   holds one factory MAC, while Linux keys each VIF link
//!   instance's CAM SMA by that instance's own link address.
//! - LSIG-TXOP, target-indication and BSS colour are zero: the
//!   8922A station path holds no source for them (the AX codec
//!   does the same), and no security entries are programmed
//!   (host crypto, `RTW89_ADDR_CAM_SEC_NORMAL` with every
//!   security entry / key index 0 — keys arrive via the
//!   separate DCTL security-CAM update).
//! - The join-info v1 `STA_TYPE` follows `fw.c`
//!   `rtw89_fw_get_sta_type` (EHT → BE, HE → AX, else N/AC);
//!   `MLO_MODE` is always MLSR (1) — Linux never programs MLMR
//!   here — and the EMLSR padding / transition delays are the
//!   fixed 256 µs codes (4 / 5, `ieee80211-eht.h:506,518` @
//!   cbbddb6), not negotiated values.

use super::ap_wire::{
    UpdMode, NET_TYPE_AP_MODE, NET_TYPE_NO_LINK, SELF_ROLE_AP_CLIENT, WIFI_ROLE_AP,
};
use super::chip_8922a;
use super::fwcmd_8922a::H2cCmd;
use super::h2c::{
    H2C_CAT_MAC, H2C_CL_MAC_ADDR_CAM_UPDATE, H2C_CL_MAC_FR_EXCHG, H2C_CL_MAC_FW_OFLD,
    H2C_CL_MAC_MEDIA_RPT, H2C_FUNC_MAC_ADDR_CAM_UPD, H2C_FUNC_MAC_DCTLINFO_UD_V2,
    H2C_FUNC_MAC_FWROLE_MAINTAIN, H2C_FUNC_MAC_JOININFO, H2C_FUNC_MAC_MACID_PAUSE,
    H2C_FUNC_MAC_MACID_PAUSE_SLEEP,
};
use super::station_8922a::{LegacyStation, MldLink, MldStation, Station, MAX_LINK_ID};
use alloc::boxed::Box;

/// `enum rtw89_self_role` (`core.h:285`): the station client.
/// (`SELF_ROLE_AP` / `SELF_ROLE_AP_CLIENT` live in `ap_wire.rs`.)
pub(super) const SELF_ROLE_CLIENT: u8 = 0;
/// `enum rtw89_wifi_role` (`core.h:259`): station.
/// (`WIFI_ROLE_AP` lives in `ap_wire.rs`.)
pub(super) const WIFI_ROLE_STATION: u8 = 1;
/// `enum rtw89_net_type` (`core.h:252`): infrastructure (associated).
/// (`NET_TYPE_NO_LINK` / `NET_TYPE_AP_MODE` live in `ap_wire.rs`.)
pub(super) const NET_TYPE_INFRA: u8 = 2;

/// `enum rtw89_fw_sta_type` (`fw.h:1821`): join-info W1 STA_TYPE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum StaType {
    /// Neither EHT nor HE (`RTW89_FW_N_AC_STA`).
    Nac = 0,
    /// HE, no EHT (`RTW89_FW_AX_STA`).
    Ax = 1,
    /// EHT (`RTW89_FW_BE_STA`).
    Be = 2,
}

/// `RTW89_H2C_JOININFO_MLO_MODE_MLSR` (`fw.h:1855`): the only MLO
/// mode Linux programs in join-info W1.
const MLO_MODE_MLSR: u32 = 1;
/// `IEEE80211_EML_CAP_EML_PADDING_DELAY_256US` = 4
/// (`ieee80211-eht.h:506` @ cbbddb6).
const EMLSR_PADDING_256US: u32 = 4;
/// `IEEE80211_EML_CAP_EMLSR_TRANSITION_DELAY_256US` = 5
/// (`ieee80211-eht.h:518` @ cbbddb6). Note the EMLSR transition
/// table has a 16 µs step, so 256 µs is 5 here, not 4.
const EMLSR_TRANS_DELAY_256US: u32 = 5;

/// `RTW89_ADDR_CAM_SEC_NORMAL` = 2 (`core.h:313`).
const ADDR_CAM_SEC_NORMAL: u32 = 2;
/// `RTW89_BSSID_MATCH_ALL` = `GENMASK(5, 0)` (`cam.h:11`).
const BSSID_MATCH_ALL: u32 = 0x3f;
/// `ADDR_CAM_ENT_SHORT_SIZE` = 0x20 (`mac.h:16`): the address-CAM
/// entry length Linux programs for the 8922A (`cam.c`
/// `rtw89_get_addr_cam_entry_size`, default branch). This is
/// NOT the 0x40 the AX codec programs for the 8852 family
/// (`ADDR_CAM_ENT_SIZE`, `mac.h:15`).
const ADDR_CAM_ENT_LEN: u32 = 0x20;
/// `BSSID_CAM_ENT_SIZE` = 0x08 (`mac.h:17`).
const BSSID_CAM_ENT_LEN: u32 = 0x08;

/// Length of the default-DMAC v2 body: `struct
/// rtw89_h2c_dctlinfo_ud_v2` = c0 + w0..w15 + m0..m15, 33 dwords
/// (`cam.h:188`).
pub(super) const DMAC_V2_LEN: usize = 132;
/// Length of the join-info v1 body: `struct rtw89_h2c_join_v1` =
/// W0..W2, 3 dwords (`fw.h:1831`).
pub(super) const JOIN_V1_LEN: usize = 12;
/// Length of the address-CAM v0 body: `struct
/// rtw89_h2c_addr_cam_v0` = W0..W14, 15 dwords (`cam.h:15`).
pub(super) const CAM_V0_LEN: usize = 60;
/// Length of the address-CAM body with the W15 update-mode word:
/// `struct rtw89_h2c_addr_cam` = v0 + W15 (`cam.h:33`).
pub(super) const CAM_V1_LEN: usize = 64;
/// Length of the plain MACID-pause body: `struct
/// rtw89_fw_macid_pause_grp` = pause_grp[4] + mask_grp[4]
/// (`fw.h:315`).
pub(super) const MACID_PAUSE_LEN: usize = 32;
/// Length of the SLEEP MACID-pause body: `struct
/// rtw89_fw_macid_pause_sleep_grp` = 4 × (pause + pause_mask +
/// sleep + sleep_mask, 4 dwords each) (`fw.h:320`).
pub(super) const MACID_PAUSE_SLEEP_LEN: usize = 256;

/// Link-lifecycle failures. Every variant is a refusal, never a
/// fallback: a refused transition produces no bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// MACID outside the chip's 32-slot range.
    MacIdOutOfRange,
    /// MAC index outside 0..=1 (the chip has two MACs; join-info
    /// W0 BAND is a single bit).
    MacIdxOutOfRange,
    /// PHY index outside 0..=1 (CAM BB_SEL is a single bit).
    PhyIdxOutOfRange,
    /// Port outside the 3-bit field.
    PortOutOfRange,
    /// WMM set outside the 2-bit field.
    WmmOutOfRange,
    /// 802.11 link ID above 14.
    LinkIdOutOfRange,
    /// AID above the 12-bit CAM field.
    AidOutOfRange,
    /// Address-CAM index outside the chip's 128-entry pool.
    AddrCamOutOfRange,
    /// BSSID-CAM index outside the chip's 20-entry pool.
    BssidCamOutOfRange,
    /// A role / net-type / wifi-role value outside its H2C
    /// field width (only reachable from a direct builder call;
    /// the transition composers only pass Linux's enum values).
    FieldOutOfRange,
    /// No admitted link has this 802.11 link ID.
    LinkNotFound,
}

/// One H2C identity plus its acknowledgement contract, for
/// framing a link-lifecycle body with `fwcmd_8922a::frame_h2c`.
/// The ack pair is Linux's `rtw89_h2c_pkt_set_hdr(..., rack,
/// dack, len)` for that builder: role-maintain, join-info, CAM
/// and DMAC take DONE_ACK only (`0, 1`); MACID pause takes
/// REC_ACK only (`1, 0`, `fw.c:5618`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LinkCmd {
    /// (category, class, function) address.
    pub(super) cmd: H2cCmd,
    /// Request a receive acknowledgement.
    pub(super) rec_ack: bool,
    /// Request a done acknowledgement.
    pub(super) done_ack: bool,
}

/// Role-maintain: `H2C_CAT_MAC` / `H2C_CL_MAC_MEDIA_RPT` /
/// `H2C_FUNC_MAC_FWROLE_MAINTAIN`, DONE_ACK only.
pub(super) const CMD_ROLE_MAINTAIN: LinkCmd = LinkCmd {
    cmd: H2cCmd {
        cat: H2C_CAT_MAC,
        class: H2C_CL_MAC_MEDIA_RPT,
        func: H2C_FUNC_MAC_FWROLE_MAINTAIN,
    },
    rec_ack: false,
    done_ack: true,
};

/// Join-info: `H2C_CAT_MAC` / `H2C_CL_MAC_MEDIA_RPT` /
/// `H2C_FUNC_MAC_JOININFO`, DONE_ACK only.
pub(super) const CMD_JOIN_INFO: LinkCmd = LinkCmd {
    cmd: H2cCmd {
        cat: H2C_CAT_MAC,
        class: H2C_CL_MAC_MEDIA_RPT,
        func: H2C_FUNC_MAC_JOININFO,
    },
    rec_ack: false,
    done_ack: true,
};

/// Address-CAM update: `H2C_CAT_MAC` /
/// `H2C_CL_MAC_ADDR_CAM_UPDATE` / `H2C_FUNC_MAC_ADDR_CAM_UPD`,
/// DONE_ACK only.
pub(super) const CMD_CAM: LinkCmd = LinkCmd {
    cmd: H2cCmd {
        cat: H2C_CAT_MAC,
        class: H2C_CL_MAC_ADDR_CAM_UPDATE,
        func: H2C_FUNC_MAC_ADDR_CAM_UPD,
    },
    rec_ack: false,
    done_ack: true,
};

/// Default DMAC table v2: `H2C_CAT_MAC` / `H2C_CL_MAC_FR_EXCHG` /
/// `H2C_FUNC_MAC_DCTLINFO_UD_V2`, DONE_ACK only.
pub(super) const CMD_DMAC_V2: LinkCmd = LinkCmd {
    cmd: H2cCmd {
        cat: H2C_CAT_MAC,
        class: H2C_CL_MAC_FR_EXCHG,
        func: H2C_FUNC_MAC_DCTLINFO_UD_V2,
    },
    rec_ack: false,
    done_ack: true,
};

/// MACID pause (plain): `H2C_CAT_MAC` / `H2C_CL_MAC_FW_OFLD` /
/// `H2C_FUNC_MAC_MACID_PAUSE`, REC_ACK only.
pub(super) const CMD_MACID_PAUSE: LinkCmd = LinkCmd {
    cmd: H2cCmd {
        cat: H2C_CAT_MAC,
        class: H2C_CL_MAC_FW_OFLD,
        func: H2C_FUNC_MAC_MACID_PAUSE,
    },
    rec_ack: true,
    done_ack: false,
};

/// MACID pause (SLEEP): `H2C_CAT_MAC` / `H2C_CL_MAC_FW_OFLD` /
/// `H2C_FUNC_MAC_MACID_PAUSE_SLEEP`, REC_ACK only.
pub(super) const CMD_MACID_PAUSE_SLEEP: LinkCmd = LinkCmd {
    cmd: H2cCmd {
        cat: H2C_CAT_MAC,
        class: H2C_CL_MAC_FW_OFLD,
        func: H2C_FUNC_MAC_MACID_PAUSE_SLEEP,
    },
    rec_ack: true,
    done_ack: false,
};

fn check_common(macid: u8, mac_idx: u8, port: u8) -> Result<(), Error> {
    if macid as usize >= chip_8922a::SUPPORT_MACID_NUM {
        return Err(Error::MacIdOutOfRange);
    }
    if mac_idx > 1 {
        return Err(Error::MacIdxOutOfRange);
    }
    if port > 7 {
        return Err(Error::PortOutOfRange);
    }
    Ok(())
}

/// `rtw89_fw_h2c_role_maintain` W0 (`fw.c:5344`,
/// `RTW89_H2C_ROLE_MAINTAIN_W0_*`, `fw.h:1813..1819`):
/// MACID[7:0] | SELF_ROLE[9:8] | UPD_MODE[12:10] |
/// WIFI_ROLE[16:13] | BAND (mac_idx)[18:17] | PORT[21:19].
/// `MACID_EXT`[31:24] stays zero — Linux never encodes it here.
/// `self_role` is the peer role for a peer link on an AP vif
/// (`SELF_ROLE_AP_CLIENT`) and the vif's own role otherwise;
/// `wifi_role` is the vif's role.
pub(super) fn role_maintain(
    macid: u8,
    self_role: u8,
    upd_mode: UpdMode,
    wifi_role: u8,
    mac_idx: u8,
    port: u8,
) -> Result<[u8; 4], Error> {
    check_common(macid, mac_idx, port)?;
    if self_role > 3 || wifi_role > 15 {
        return Err(Error::FieldOutOfRange);
    }
    Ok((u32::from(macid)
        | u32::from(self_role) << 8
        | u32::from(upd_mode as u8) << 10
        | u32::from(wifi_role) << 13
        | u32::from(mac_idx) << 17
        | u32::from(port) << 19)
        .to_le_bytes())
}

/// `rtw89_fw_h2c_default_dmac_tbl_v2` (`fw.c:2671`,
/// `rtw89_h2c_dctlinfo_ud_v2`, `cam.h:188..303`): c0 carries the
/// MACID (`DCTLINFO_V2_C0_MACID`, 7 bits) with OP = 1
/// (`DCTLINFO_V2_C0_OP`, bit 7); the mask words m0..m12 carry
/// their `*_ALL` constants and everything else stays zero (the
/// skb is memset by `rtw89_fw_h2c_alloc_skb_with_hdr`). The
/// non-`ALL` masks: W4 = `GENMASK(31, 5)`, W5 =
/// `GENMASK(31, 8) | GENMASK(3, 0)`, W12 = `GENMASK(15, 0)`;
/// every other m word is `GENMASK(31, 0)`.
pub(super) fn default_dmac_tbl_v2(macid: u8) -> Result<[u8; DMAC_V2_LEN], Error> {
    if macid as usize >= chip_8922a::SUPPORT_MACID_NUM {
        return Err(Error::MacIdOutOfRange);
    }
    let mut body = [0u8; DMAC_V2_LEN];
    // c0 is dword 0; w0..w15 are dwords 1..16; m0..m15 are
    // dwords 17..32.
    let word = |body: &mut [u8; DMAC_V2_LEN], index: usize, value: u32| {
        body[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    };
    word(&mut body, 0, u32::from(macid) | 1 << 7);
    for (m, value) in [
        (0, 0xFFFF_FFFFu32),
        (1, 0xFFFF_FFFF),
        (2, 0xFFFF_FFFF),
        (3, 0xFFFF_FFFF),
        (4, 0xFFFF_FFE0),
        (5, 0xFFFF_FF0F),
        (6, 0xFFFF_FFFF),
        (7, 0xFFFF_FFFF),
        (8, 0xFFFF_FFFF),
        (9, 0xFFFF_FFFF),
        (10, 0xFFFF_FFFF),
        (11, 0xFFFF_FFFF),
        (12, 0x0000_FFFF),
    ] {
        word(&mut body, 17 + m, value);
    }
    Ok(body)
}

/// Inputs to the BE join-info v1 builder (`fw.c:5440`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct JoinV1 {
    /// This link's MACID.
    pub(super) macid: u8,
    /// `dis_conn`: true on disconnect, false on assoc.
    pub(super) dis_conn: bool,
    /// MAC index (0 or 1): W0 BAND is a single bit.
    pub(super) mac_idx: u8,
    /// Hardware EDCA set (0..3).
    pub(super) wmm: u8,
    /// Triggered-uplink capable (the AP's HE support on assoc;
    /// false on disconnect).
    pub(super) trigger: bool,
    /// Shared port id (0..7).
    pub(super) port: u8,
    /// Net type: INFRA on assoc, NO_LINK on disconnect (AP-mode
    /// links report NO_LINK on disconnect too, via the AP branch
    /// of `rtw89_fw_h2c_join_info`).
    pub(super) net_type: u8,
    /// VIF wifi role (STATION for a client, AP for an AP peer).
    pub(super) wifi_role: u8,
    /// Self role (CLIENT for a client, AP_CLIENT for an AP peer).
    pub(super) self_role: u8,
    /// Station type for W1 (`rtw89_fw_get_sta_type`).
    pub(super) sta_type: StaType,
    /// True for MLD links (`ieee80211_vif_is_mld`).
    pub(super) is_mld: bool,
    /// Designated link's MACID (`rtw89_sta_get_main_macid` /
    /// `rtw89_vif_get_main_macid`: `links_inst[0].mac_id`).
    pub(super) main_macid: u8,
    /// True when this link is not the designated VIF link
    /// (`rtwvif_link != rtw89_get_designated_link(...)`).
    pub(super) init_ps: bool,
    /// 802.11 link ID (0..=14).
    pub(super) link_id: u8,
}

/// `rtw89_fw_h2c_join_info` BE format (`fw.c:5440`,
/// `rtw89_h2c_join_v1`, `fw.h:1827..1867`): W0 is the AX word
/// (MACID[7:0] | OP bit 8 | BAND bit 9 | WMM[11:10] | TGR bit 12
/// | PORT[23:21] | NET_TYPE[25:24] | WIFI_ROLE[29:26] |
/// SELF_ROLE[31:30], ISHESTA / DLBW / TF_MAC_PAD / DL_T_PE
/// zero); W1 carries STA_TYPE[2:0] | IS_MLD bit 3 |
/// MAIN_MACID[11:4] | MLO_MODE bit 12 (= MLSR) |
/// INIT_PWR_STATE bit 15 | EMLSR_PADDING[18:16] (= 4, 256 µs) |
/// EMLSR_TRANS_DELAY[21:19] (= 5, 256 µs) | LINK_ID[28:25]
/// (EMLSR_CAB / NSTR_EN / IS_MLD_EXT / SUPPORT_3LINKS /
/// IS_3RD_LINK / UPDATE_MODE zero); W2 is zero (MACID_EXT /
/// MAIN_MACID_EXT).
pub(super) fn join_info_v1(input: &JoinV1) -> Result<[u8; JOIN_V1_LEN], Error> {
    check_common(input.macid, input.mac_idx, input.port)?;
    if input.wmm > 3 {
        return Err(Error::WmmOutOfRange);
    }
    if input.link_id > MAX_LINK_ID {
        return Err(Error::LinkIdOutOfRange);
    }
    if input.main_macid as usize >= chip_8922a::SUPPORT_MACID_NUM {
        return Err(Error::MacIdOutOfRange);
    }
    if input.net_type > 3 || input.wifi_role > 15 || input.self_role > 3 {
        return Err(Error::FieldOutOfRange);
    }
    let w0 = u32::from(input.macid)
        | u32::from(input.dis_conn) << 8
        | u32::from(input.mac_idx & 1) << 9
        | u32::from(input.wmm) << 10
        | u32::from(input.trigger) << 12
        | u32::from(input.port) << 21
        | u32::from(input.net_type) << 24
        | u32::from(input.wifi_role) << 26
        | u32::from(input.self_role) << 30;
    let w1 = u32::from(input.sta_type as u8)
        | u32::from(input.is_mld) << 3
        | u32::from(input.main_macid) << 4
        | MLO_MODE_MLSR << 12
        | u32::from(input.init_ps) << 15
        | EMLSR_PADDING_256US << 16
        | EMLSR_TRANS_DELAY_256US << 19
        | u32::from(input.link_id) << 25;
    let mut body = [0u8; JOIN_V1_LEN];
    body[0..4].copy_from_slice(&w0.to_le_bytes());
    body[4..8].copy_from_slice(&w1.to_le_bytes());
    Ok(body)
}

/// `rtw89_fw_h2c_macid_pause` SLEEP variant (`fw.c:5575`,
/// `struct rtw89_fw_macid_pause_sleep_grp`, `fw.h:320`):
/// only `n[0]` is programmed — `pause_mask_grp[grp]` and
/// `sleep_mask_grp[grp]` carry the bit, and `pause_grp[grp]`
/// / `sleep_grp[grp]` carry it only when pausing — where
/// `grp = macid >> 5`, bit `= macid & 31` (`mac.c:4443`).
/// The plain 32-byte variant is `station_control::codec::
/// pause_at`; this is its firmware-gated sibling (8922A
/// firmware >= 0.34.11.0, `MACID_PAUSE_SLEEP`, `fw.c:999`).
pub(super) fn macid_pause_sleep(
    macid: u8,
    pause: bool,
) -> Result<[u8; MACID_PAUSE_SLEEP_LEN], Error> {
    if macid as usize >= chip_8922a::SUPPORT_MACID_NUM {
        return Err(Error::MacIdOutOfRange);
    }
    let mut body = [0u8; MACID_PAUSE_SLEEP_LEN];
    let group = usize::from(macid >> 5);
    let bit = 1u32 << (macid & 31);
    let word = |body: &mut [u8; MACID_PAUSE_SLEEP_LEN], index: usize, value: u32| {
        body[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    };
    // n[0]: pause_grp[4] at dwords 0..4, pause_mask_grp[4] at
    // 4..8, sleep_grp[4] at 8..12, sleep_mask_grp[4] at 12..16.
    word(&mut body, 4 + group, bit);
    word(&mut body, 12 + group, bit);
    if pause {
        word(&mut body, group, bit);
        word(&mut body, 8 + group, bit);
    }
    Ok(body)
}

/// The MACID pause body: plain (`CMD_MACID_PAUSE`) or SLEEP
/// (`CMD_MACID_PAUSE_SLEEP`), selected by the firmware
/// `MACID_PAUSE_SLEEP` feature. The SLEEP body is boxed: at 256
/// bytes it dwarfs the 32-byte plain body, and a by-value enum
/// would trip `clippy::large_enum_variant` (and copy 257 bytes
/// per value). The enum is therefore `Clone` but not `Copy`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum MacidPause {
    /// Plain 32-byte body.
    Plain([u8; MACID_PAUSE_LEN]),
    /// SLEEP 256-byte body.
    Sleep(Box<[u8; MACID_PAUSE_SLEEP_LEN]>),
}

impl MacidPause {
    /// The H2C identity for this variant.
    pub(super) const fn cmd(&self) -> LinkCmd {
        match self {
            MacidPause::Plain(_) => CMD_MACID_PAUSE,
            MacidPause::Sleep(_) => CMD_MACID_PAUSE_SLEEP,
        }
    }
}

/// Inputs to the address-CAM builders (`cam.c`
/// `rtw89_cam_fill_addr_cam_info` /
/// `rtw89_cam_fill_bssid_cam_info`, `addrcam_ver` 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CamArgs {
    /// This link's MACID (W8).
    pub(super) macid: u8,
    /// Shared port id (W8 PORT_INT and TSF_SYNC).
    pub(super) port: u8,
    /// PHY index (W2 / W13 BB_SEL, one bit each).
    pub(super) phy_idx: u8,
    /// Address-CAM entry index (W1, W3 via the BSSID entry).
    pub(super) addr_cam_idx: u8,
    /// BSSID-CAM entry index (W3, W12).
    pub(super) bssid_cam_idx: u8,
    /// Net type (W2): INFRA on assoc, NO_LINK on a station
    /// disconnect, AP_MODE for AP links.
    pub(super) net_type: u8,
    /// Address-CAM entry valid (W2). Cleared by
    /// `rtw89_cam_deinit_addr_cam` before an AP/TDLS disconnect
    /// CAM; the VIF's entry stays valid for station links.
    pub(super) valid: bool,
    /// BSSID-CAM entry valid (W13).
    pub(super) bssid_valid: bool,
    /// Own (link) address — CAM SMA (W4/W5).
    pub(super) sma: [u8; 6],
    /// Peer (link) address — CAM TMA (W5/W6).
    pub(super) tma: [u8; 6],
    /// BSSID bytes (W13/W14).
    pub(super) bssid: [u8; 6],
    /// AID12 (W9): the shared AID on assoc; 0 on a station
    /// disconnect (the fill only programs an AID for INFRA /
    /// AP_MODE net types).
    pub(super) aid: u16,
    /// Triggered-uplink capable (W8 TF_TRS): the AP's HE support
    /// on assoc, false on disconnect.
    pub(super) trigger: bool,
}

/// `rtw89_fw_h2c_cam` v0 body (`fw.c:2498`, `struct
/// rtw89_h2c_addr_cam_v0`, `cam.h:15`): the 15-dword form the
/// 8922A uses while the firmware predates 0.35.84.0
/// (`ADDR_CAM_V0`). W0 and W7 are never written (zero);
/// W1 = IDX[7:0] | LEN 0x20 [23:16] (offset 0); W2 = VALID |
/// NET_TYPE[2:1] | BB_SEL (phy_idx) bit 7 | SMA_HASH[23:16] |
/// TMA_HASH[31:24] (hit-rule / beacon-hit / mask fields zero,
/// `RTW89_NO_MSK`); W3 = BSSID_CAM_IDX[5:0]; W4..W6 = SMA/TMA
/// bytes; W8 (v0 layout) = MACID[7:0] | PORT_INT[10:8] |
/// TSF_SYNC[13:11] (= port) | TF_TRS bit 14 | (LSIG_TXOP /
/// TGT_IND / FRM_TGT_IND zero); W9 = AID12[11:0] |
/// SEC_ENT_MODE (`NORMAL`, 2) [17:16]; W10/W11 = 0 (no security
/// entries); W12 = BSSID_IDX[7:0] | LEN 0x08 [23:16];
/// W13 = BSSID_VALID | BB_SEL (phy_idx) bit 1 | BSSID_MASK
/// (`MATCH_ALL`, 0x3f) [7:2] | BSSID0[23:16] | BSSID1[31:24];
/// W14 = BSSID2..BSSID5. Hashes are the XOR of the address
/// bytes from the mask start (`cam.c` `rtw89_cam_addr_hash`,
/// start 0 with no mask).
pub(super) fn cam_v0(args: &CamArgs) -> Result<[u8; CAM_V0_LEN], Error> {
    if args.macid as usize >= chip_8922a::SUPPORT_MACID_NUM {
        return Err(Error::MacIdOutOfRange);
    }
    if args.phy_idx > 1 {
        return Err(Error::PhyIdxOutOfRange);
    }
    if args.port > 7 {
        return Err(Error::PortOutOfRange);
    }
    if args.aid > 0xFFF {
        return Err(Error::AidOutOfRange);
    }
    if args.addr_cam_idx as usize >= chip_8922a::ACAM_NUM {
        return Err(Error::AddrCamOutOfRange);
    }
    if args.bssid_cam_idx as usize >= chip_8922a::BCAM_NUM {
        return Err(Error::BssidCamOutOfRange);
    }
    if args.net_type > 3 {
        return Err(Error::FieldOutOfRange);
    }
    let mut body = [0u8; CAM_V0_LEN];
    let word = |body: &mut [u8; CAM_V0_LEN], index: usize, value: u32| {
        body[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    };
    let sma_hash = args.sma.into_iter().fold(0u8, |a, b| a ^ b);
    let tma_hash = args.tma.into_iter().fold(0u8, |a, b| a ^ b);
    word(
        &mut body,
        1,
        u32::from(args.addr_cam_idx) | ADDR_CAM_ENT_LEN << 16,
    );
    word(
        &mut body,
        2,
        u32::from(args.valid)
            | u32::from(args.net_type & 3) << 1
            | u32::from(args.phy_idx) << 7
            | u32::from(sma_hash) << 16
            | u32::from(tma_hash) << 24,
    );
    word(&mut body, 3, u32::from(args.bssid_cam_idx & 0x3f));
    word(
        &mut body,
        4,
        u32::from_le_bytes(args.sma[..4].try_into().unwrap()),
    );
    word(
        &mut body,
        5,
        u32::from_le_bytes([args.sma[4], args.sma[5], args.tma[0], args.tma[1]]),
    );
    word(
        &mut body,
        6,
        u32::from_le_bytes(args.tma[2..].try_into().unwrap()),
    );
    let port = u32::from(args.port & 7);
    word(
        &mut body,
        8,
        u32::from(args.macid) | port << 8 | port << 11 | u32::from(args.trigger) << 14,
    );
    word(
        &mut body,
        9,
        ADDR_CAM_SEC_NORMAL << 16 | u32::from(args.aid & 0xfff),
    );
    word(
        &mut body,
        12,
        u32::from(args.bssid_cam_idx) | BSSID_CAM_ENT_LEN << 16,
    );
    word(
        &mut body,
        13,
        u32::from(args.bssid_valid)
            | u32::from(args.phy_idx) << 1
            | BSSID_MATCH_ALL << 2
            | u32::from(args.bssid[0]) << 16
            | u32::from(args.bssid[1]) << 24,
    );
    word(
        &mut body,
        14,
        u32::from_le_bytes(args.bssid[2..].try_into().unwrap()),
    );
    Ok(body)
}

/// `rtw89_fw_h2c_cam` with the W15 update-mode word (`struct
/// rtw89_h2c_addr_cam`, `cam.h:33`): the 64-byte form the 8922A
/// uses once the firmware is >= 0.35.84.0 (no `ADDR_CAM_V0`
/// feature). W0..W14 are the v0 body; W15 =
/// `UPD_MODE`[2:0] (`ADDR_CAM_W15_UPD_MODE`, `cam.h:150`).
pub(super) fn cam_v1(args: &CamArgs, upd_mode: UpdMode) -> Result<[u8; CAM_V1_LEN], Error> {
    let v0 = cam_v0(args)?;
    let mut body = [0u8; CAM_V1_LEN];
    body[..CAM_V0_LEN].copy_from_slice(&v0);
    body[CAM_V0_LEN..CAM_V1_LEN].copy_from_slice(&(upd_mode as u32).to_le_bytes());
    Ok(body)
}

/// The address-CAM body for a link transition: v0 (60 bytes)
/// or v1 (64 bytes, W15 = CON_DISCONN), selected by the
/// firmware `ADDR_CAM_V0` feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CamBody {
    /// 60-byte v0 body (firmware < 0.35.84.0).
    V0([u8; CAM_V0_LEN]),
    /// 64-byte body with W15 update mode (firmware >= 0.35.84.0).
    V1([u8; CAM_V1_LEN]),
}

/// The VIF-link-instance context a transition needs beyond the
/// admitted link record: the VIF side Linux reads from
/// `rtwvif_link` (port, WMM, trigger, BSSID, CAM indices) plus
/// the two firmware-feature switches. One instance per link:
/// an MLD has one context per link instance (each with its own
/// own-address, CAM indices, MAC/PHY index), a single-link
/// station has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct VifLinkCtx {
    /// This link instance's own MAC address (CAM SMA).
    pub(super) own: [u8; 6],
    /// Shared port id (0..7).
    pub(super) port: u8,
    /// Hardware EDCA set (0..3).
    pub(super) wmm: u8,
    /// The AP's HE support on this link (join TGR / CAM TF_TRS
    /// on assoc; forced false on disconnect).
    pub(super) trigger: bool,
    /// BSSID bytes (CAM BSSID).
    pub(super) bssid: [u8; 6],
    /// This link instance's address-CAM entry index.
    pub(super) addr_cam_idx: u8,
    /// This link instance's BSSID-CAM entry index.
    pub(super) bssid_cam_idx: u8,
    /// BSSID-CAM entry valid (W13). True while the VIF is up
    /// (station links) or after the TDLS BSSID-CAM init.
    pub(super) bssid_valid: bool,
    /// AP-mode vif or TDLS peer: link-add / link-remove H2Cs
    /// apply and the disconnect CAM carries `valid = false`
    /// (deinit first). False for ordinary station links.
    pub(super) ap_or_tdls: bool,
    /// True while the firmware predates 0.35.84.0
    /// (`ADDR_CAM_V0`): 60-byte CAM bodies. False selects the
    /// 64-byte form with W15 `UPD_MODE`.
    pub(super) addr_cam_v0: bool,
    /// True once the firmware is >= 0.34.11.0
    /// (`MACID_PAUSE_SLEEP`): 256-byte SLEEP pause bodies.
    /// False selects the plain 32-byte form.
    pub(super) macid_pause_sleep: bool,
}

/// One link's transition inputs: the admitted record's
/// link-level identity plus its VIF-link context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LinkView {
    /// This link's MACID.
    macid: u8,
    /// MAC index (= instance index).
    mac_idx: u8,
    /// PHY index (= instance index).
    phy_idx: u8,
    /// Peer (link) MAC address — CAM TMA.
    peer: [u8; 6],
    /// Shared AID (12 bits).
    aid: u16,
    /// Station type for join W1.
    sta_type: StaType,
    /// True for MLD links.
    is_mld: bool,
    /// Designated link's MACID.
    main_macid: u8,
    /// 802.11 link ID.
    link_id: u8,
    /// True when this link is not the designated link.
    init_ps: bool,
    /// VIF-link context.
    vif: VifLinkCtx,
}

impl LinkView {
    /// View for one admitted MLD link: MACID / MAC index /
    /// PHY index from the link instance, peer address and AID
    /// from its station record, main MACID from the MLD base
    /// (`links_inst[0].mac_id`), `init_ps` for every link but
    /// the designated one (instance 0). The STA type is BE —
    /// MLD links are admitted through the EHT facet only.
    pub(super) fn for_mld_link(
        mld: &MldStation,
        link: &MldLink,
        vif: &VifLinkCtx,
    ) -> Result<Self, Error> {
        if link.link_id > MAX_LINK_ID {
            return Err(Error::LinkIdOutOfRange);
        }
        Ok(Self {
            macid: link.macid(),
            mac_idx: link.mac_idx(),
            phy_idx: link.mac_idx(),
            peer: link.station.peer,
            aid: mld.aid,
            sta_type: StaType::Be,
            is_mld: true,
            main_macid: mld.base_macid,
            link_id: link.link_id,
            init_ps: link.index != 0,
            vif: *vif,
        })
    }

    /// View for one admitted single-link EHT station: not MLD,
    /// designated by construction, main MACID is its own.
    pub(super) fn for_station(station: &Station, vif: &VifLinkCtx) -> Self {
        Self {
            macid: station.macid,
            mac_idx: 0,
            phy_idx: 0,
            peer: station.peer,
            aid: station.aid,
            sta_type: StaType::Be,
            is_mld: false,
            main_macid: station.macid,
            link_id: 0,
            init_ps: false,
            vif: *vif,
        }
    }

    /// View for one admitted single-link legacy-mode station:
    /// STA type from the negotiated mode (HE → AX, else N/AC),
    /// following `fw.c` `rtw89_fw_get_sta_type`.
    pub(super) fn for_legacy_station(station: &LegacyStation, vif: &VifLinkCtx) -> Self {
        let sta_type = match station.mode() {
            super::station_8922a::LegacyMode::He => StaType::Ax,
            _ => StaType::Nac,
        };
        Self {
            macid: station.macid,
            mac_idx: 0,
            phy_idx: 0,
            peer: station.peer,
            aid: station.aid,
            sta_type,
            is_mld: false,
            main_macid: station.macid,
            link_id: 0,
            init_ps: false,
            vif: *vif,
        }
    }

    fn self_role(&self) -> u8 {
        if self.vif.ap_or_tdls {
            SELF_ROLE_AP_CLIENT
        } else {
            SELF_ROLE_CLIENT
        }
    }

    fn wifi_role(&self) -> u8 {
        if self.vif.ap_or_tdls {
            WIFI_ROLE_AP
        } else {
            WIFI_ROLE_STATION
        }
    }

    fn net_type_assoc(&self) -> u8 {
        if self.vif.ap_or_tdls {
            NET_TYPE_AP_MODE
        } else {
            NET_TYPE_INFRA
        }
    }

    fn join_v1(&self, dis_conn: bool) -> Result<[u8; JOIN_V1_LEN], Error> {
        // `rtw89_vif_type_mapping(link, assoc)`: a station link
        // reports NO_LINK and trigger=false on disconnect; an AP
        // link keeps AP_MODE in the VIF record but join-info's AP
        // branch reports NO_LINK on disconnect anyway.
        let (net_type, trigger) = if dis_conn {
            (NET_TYPE_NO_LINK, false)
        } else {
            (self.net_type_assoc(), self.vif.trigger)
        };
        join_info_v1(&JoinV1 {
            macid: self.macid,
            dis_conn,
            mac_idx: self.mac_idx,
            wmm: self.vif.wmm,
            trigger,
            port: self.vif.port,
            net_type,
            wifi_role: self.wifi_role(),
            self_role: self.self_role(),
            sta_type: self.sta_type,
            is_mld: self.is_mld,
            main_macid: self.main_macid,
            init_ps: self.init_ps,
            link_id: self.link_id,
        })
    }

    fn cam(&self, dis_conn: bool) -> Result<CamBody, Error> {
        // Station disconnect: `rtw89_vif_type_mapping(link,
        // false)` already set NO_LINK, and the fill programs no
        // AID outside INFRA / AP_MODE. AP/TDLS disconnect: the
        // entry was de-initialised first, so `valid` is false
        // and the net type / AID stay AP_MODE / peer AID.
        let (net_type, aid, valid) = if dis_conn {
            if self.vif.ap_or_tdls {
                (NET_TYPE_AP_MODE, self.aid, false)
            } else {
                (NET_TYPE_NO_LINK, 0, true)
            }
        } else {
            (self.net_type_assoc(), self.aid, true)
        };
        let args = CamArgs {
            macid: self.macid,
            port: self.vif.port,
            phy_idx: self.phy_idx,
            addr_cam_idx: self.vif.addr_cam_idx,
            bssid_cam_idx: self.vif.bssid_cam_idx,
            net_type,
            valid,
            bssid_valid: self.vif.bssid_valid,
            sma: self.vif.own,
            tma: self.peer,
            bssid: self.vif.bssid,
            aid,
            trigger: if dis_conn { false } else { self.vif.trigger },
        };
        if self.vif.addr_cam_v0 {
            cam_v0(&args).map(CamBody::V0)
        } else {
            cam_v1(&args, UpdMode::ConDisconn).map(CamBody::V1)
        }
    }
}

/// The `sta_link_add` bodies for one link, in Linux's send
/// order: MACID unpause, role-maintain CREATE, then (already
/// built by admission) the default CMAC table, then the default
/// DMAC table. Station links send nothing here — every field
/// is `None` — and the caller must not send the default CMAC
/// twice. Not `Copy`: `pause` may hold the boxed 256-byte SLEEP
/// body (see [`MacidPause`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LinkAdd {
    /// MACID unpause (AP/TDLS only).
    pub(super) pause: Option<MacidPause>,
    /// Role-maintain CREATE (AP/TDLS only).
    pub(super) role: Option<[u8; 4]>,
    /// Default DMAC table v2 (AP/TDLS only).
    pub(super) dmac: Option<[u8; DMAC_V2_LEN]>,
}

/// The `sta_link_assoc` / `sta_link_disconnect` bodies for one
/// link, in Linux's send order: (already built by admission)
/// the assoc CMAC table, then join-info, then the CAM update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LinkConn {
    /// Join-info v1: `dis_conn = false` on assoc, `true` on
    /// disconnect.
    pub(super) join: [u8; JOIN_V1_LEN],
    /// CAM update (`CON_DISCONN`): v0 or v1 by firmware.
    pub(super) cam: CamBody,
}

/// `rtw89_core_sta_link_add` H2Cs for one link. Station links
/// produce an all-`None` [`LinkAdd`]; AP/TDLS links produce the
/// pause (unpause) + role CREATE + default DMAC triple. The
/// default CMAC table between role and DMAC is admission's
/// (`cctl_g7::build_default`, already on the station record),
/// not rebuilt here.
pub(super) fn link_add_h2cs(view: &LinkView) -> Result<LinkAdd, Error> {
    if !view.vif.ap_or_tdls {
        return Ok(LinkAdd {
            pause: None,
            role: None,
            dmac: None,
        });
    }
    let pause = if view.vif.macid_pause_sleep {
        MacidPause::Sleep(Box::new(macid_pause_sleep(view.macid, false)?))
    } else {
        MacidPause::Plain(super::station_control::codec::pause_at(view.macid, false))
    };
    let role = role_maintain(
        view.macid,
        view.self_role(),
        UpdMode::Create,
        view.wifi_role(),
        view.mac_idx,
        view.vif.port,
    )?;
    let dmac = default_dmac_tbl_v2(view.macid)?;
    Ok(LinkAdd {
        pause: Some(pause),
        role: Some(role),
        dmac: Some(dmac),
    })
}

/// `rtw89_core_sta_link_assoc` H2Cs for one link: join-info
/// (connected) + CAM update (`CON_DISCONN`, AID + net type).
/// The assoc CMAC table sent first is admission's
/// (`Station::assoc_cctl` / per-link assoc CCTL), not rebuilt
/// here.
pub(super) fn link_assoc_h2cs(view: &LinkView) -> Result<LinkConn, Error> {
    Ok(LinkConn {
        join: view.join_v1(false)?,
        cam: view.cam(false)?,
    })
}

/// `rtw89_core_sta_link_disconnect` H2Cs for one link:
/// join-info (disconnect) + CAM update (`CON_DISCONN`,
/// net-type NO_LINK / AID 0 for station links). The assoc CMAC
/// table sent first is admission's, not rebuilt here.
pub(super) fn link_disconnect_h2cs(view: &LinkView) -> Result<LinkConn, Error> {
    Ok(LinkConn {
        join: view.join_v1(true)?,
        cam: view.cam(true)?,
    })
}

/// `rtw89_core_sta_link_remove` H2C for one link:
/// role-maintain REMOVE for AP/TDLS links, nothing for station
/// links.
pub(super) fn link_remove_h2cs(view: &LinkView) -> Result<Option<[u8; 4]>, Error> {
    if !view.vif.ap_or_tdls {
        return Ok(None);
    }
    role_maintain(
        view.macid,
        view.self_role(),
        UpdMode::Remove,
        view.wifi_role(),
        view.mac_idx,
        view.vif.port,
    )
    .map(Some)
}

/// `sta_link_add` bodies for one MLD link, by 802.11 link ID.
pub(super) fn mld_link_add_h2cs(
    mld: &MldStation,
    link_id: u8,
    vif: &VifLinkCtx,
) -> Result<LinkAdd, Error> {
    let link = mld.link(link_id).ok_or(Error::LinkNotFound)?;
    link_add_h2cs(&LinkView::for_mld_link(mld, link, vif)?)
}

/// `sta_link_assoc` bodies for one MLD link, by 802.11 link ID.
pub(super) fn mld_link_assoc_h2cs(
    mld: &MldStation,
    link_id: u8,
    vif: &VifLinkCtx,
) -> Result<LinkConn, Error> {
    let link = mld.link(link_id).ok_or(Error::LinkNotFound)?;
    link_assoc_h2cs(&LinkView::for_mld_link(mld, link, vif)?)
}

/// `sta_link_disconnect` bodies for one MLD link, by 802.11
/// link ID.
pub(super) fn mld_link_disconnect_h2cs(
    mld: &MldStation,
    link_id: u8,
    vif: &VifLinkCtx,
) -> Result<LinkConn, Error> {
    let link = mld.link(link_id).ok_or(Error::LinkNotFound)?;
    link_disconnect_h2cs(&LinkView::for_mld_link(mld, link, vif)?)
}

/// `sta_link_remove` body for one MLD link, by 802.11 link ID.
pub(super) fn mld_link_remove_h2cs(
    mld: &MldStation,
    link_id: u8,
    vif: &VifLinkCtx,
) -> Result<Option<[u8; 4]>, Error> {
    let link = mld.link(link_id).ok_or(Error::LinkNotFound)?;
    link_remove_h2cs(&LinkView::for_mld_link(mld, link, vif)?)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "link_h2c_8922a_tests.rs"]
mod tests;
