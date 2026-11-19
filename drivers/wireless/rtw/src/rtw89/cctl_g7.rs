// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! G7 CCTL (CMAC table) default builder — 8922A station admission.
//!
//! Mirrors Linux `rtw89/fw.c`
//! `rtw89_fw_h2c_default_cmac_tbl_g7` (torvalds/linux @
//! 05441d6 — the sparse-clone reference; the flat cbbddb6
//! clone has no `fw.c`). 8922A selects this builder via
//! `h2c_cctl_func_id = H2C_FUNC_MAC_CCTLINFO_UD_G7`
//! (`rtw8922a.c:3324` in the same tree). Struct and masks:
//! `fw.h:1404..1545`.
//!
//! The H2C payload is c0 + w0..w15 + m0..m15. Each m-word is
//! the update mask for its w-word; words the default builder
//! never touches stay zero with a zero mask, EXCEPT w2/w3/w8,
//! whose values stay zero while their masks are ALL —
//! Linux's literal behavior, replicated here (the mask tells
//! firmware "update these words", and the value is zero).
//! Untouched pairs (w9..w13, m9..m13) are zero on both sides.
//!
//! Default values (`fw.c:4060`): c0 = MACID | OP(1);
//! w0 = DATARATE 4 | MGQ_RPT_EN(tx_rpt_enabled);
//! w1 = DATA_RTY_LOWEST_RATE 4 | RTSRATE 0xa |
//! RTS_RTY_LOWEST_RATE 4; w4 = ACT_SUBCH_CBW 0xFFFF;
//! w5 = NOMINAL_PKT_PADDING 2 on all five subfields;
//! w6 = RESP_REF_RATE 0xb; w7 = NC 1 | NR 1 | CB 1 |
//! CSI_PARA_EN 1 | CSI_FIX_RATE 0xb; w14/w15 current-rate
//! fields all zero. DATARATE 4, RTSRATE 0xa, and the retry
//! rates are Linux literals, not decoded rate codes.
//!
//! Deliberate difference from Linux: a MAC ID above 127 is
//! REJECTED instead of truncated (C0_MACID is 7 bits);
//! Linux's `le32_encode_bits` would silently drop bit 7
//! into the OP bit.

/// Default CMAC table payload: c0 + w0..w15 + m0..m15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DefaultCmac {
    /// c0: MACID bits 6:0, OP bit 7.
    pub c0: u32,
    /// Value words w0..w15.
    pub w: [u32; 16],
    /// Mask words m0..m15.
    pub m: [u32; 16],
}

/// Errors from the CMAC builders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// MAC ID exceeds the 7-bit C0_MACID field.
    BadMacId,
    /// An assoc field exceeds its bitfield width (port, AID, padding).
    BadValue,
}

/// `CCTLINFO_G7_C0_MACID` GENMASK(6, 0) + `C0_OP` BIT(7)
/// (`fw.h:1440,1441`).
const C0_OP: u32 = 1 << 7;
/// `CCTLINFO_G7_W0_DATARATE` GENMASK(11, 0) (`fw.h:1443`).
const W0_DATARATE_MASK: u32 = 0xFFF;
/// `CCTLINFO_G7_W0_DATA_GI_LTF` GENMASK(14, 12) (`fw.h:1444`).
/// Untouched by the default builder (value 0, and bit 19 is
/// excluded from W0_ALL — see below).
const W0_ALL: u32 = 0xFFF0_0000 | 0x0007_FFFF;
/// `CCTLINFO_G7_W0_MGQ_RPT_EN` BIT(21) (`fw.h:1449`).
const W0_MGQ_RPT_EN: u32 = 1 << 21;
/// `CCTLINFO_G7_W1_DATA_RTY_LOWEST_RATE` GENMASK(11, 0)
/// (`fw.h:1458`).
const W1_DATA_RTY_LOWEST_RATE_MASK: u32 = 0xFFF;
/// `CCTLINFO_G7_W1_RTSRATE` GENMASK(27, 16) (`fw.h:1460`).
const W1_RTSRATE_MASK: u32 = 0x0FFF_0000;
/// `CCTLINFO_G7_W1_RTS_RTY_LOWEST_RATE` GENMASK(31, 28)
/// (`fw.h:1461`).
const W1_RTS_RTY_LOWEST_RATE_MASK: u32 = 0xF000_0000;
/// `CCTLINFO_G7_W1_ALL` (`fw.h:1462`).
const W1_ALL: u32 = 0xFFFF_FFFF;
/// `CCTLINFO_G7_W2_ALL` (`fw.h:1475`).
const W2_ALL: u32 = 0xFFFF_FFFF;
/// `CCTLINFO_G7_W3_ALL` (`fw.h:1489`).
const W3_ALL: u32 = 0xFFFF_FFFF;
/// `CCTLINFO_G7_W4_ACT_SUBCH_CBW` GENMASK(31, 16)
/// (`fw.h:1500`).
const W4_ACT_SUBCH_CBW_MASK: u32 = 0xFFFF_0000;
/// `CCTLINFO_G7_W4_ALL` (`fw.h:1501`).
const W4_ALL: u32 = 0xFFFF_C000 | 0x0000_1FFF;
/// `CCTLINFO_G7_W5_NOMINAL_PKT_PADDING0..4`
/// (`fw.h:1502..1506`).
const W5_PADDING_MASK: u32 = 0x3FF;
/// `CCTLINFO_G7_W5_ALL` (`fw.h:1510`).
const W5_ALL: u32 = 0xFFFF_0000 | 0x0000_7FFF;
/// `CCTLINFO_G7_W6_RESP_REF_RATE` GENMASK(23, 12)
/// (`fw.h:1512`).
const W6_RESP_REF_RATE_MASK: u32 = 0x00FF_F000;
/// `CCTLINFO_G7_W6_ALL` (`fw.h:1514`).
const W6_ALL: u32 = 0x8000_0000 | 0x00FF_FFFF;
/// `CCTLINFO_G7_W7_NC` GENMASK(2, 0) (`fw.h:1515`).
const W7_NC_MASK: u32 = 0x7;
/// `CCTLINFO_G7_W7_NR` GENMASK(5, 3) (`fw.h:1516`).
const W7_NR_MASK: u32 = 0x38;
/// `CCTLINFO_G7_W7_CB` GENMASK(9, 8) (`fw.h:1518`).
const W7_CB_MASK: u32 = 0x300;
/// `CCTLINFO_G7_W7_CSI_PARA_EN` BIT(15) (`fw.h:1522`).
const W7_CSI_PARA_EN: u32 = 1 << 15;
/// `CCTLINFO_G7_W7_CSI_FIX_RATE` GENMASK(27, 16)
/// (`fw.h:1523`).
const W7_CSI_FIX_RATE_MASK: u32 = 0x0FFF_0000;
/// `CCTLINFO_G7_W7_ALL` (`fw.h:1525`).
const W7_ALL: u32 = 0xE000_0000 | 0x0FFF_E000 | 0x0000_0FFF;
/// `CCTLINFO_G7_W8_ALL` GENMASK(15, 0) (`fw.h:1536`).
const W8_ALL: u32 = 0xFFFF;
/// `CCTLINFO_G7_W14_ALL` (`fw.h:1541`).
const W14_ALL: u32 = 0xFFFF_FFFF;
/// `CCTLINFO_G7_W15_ALL` (`fw.h:1545`).
const W15_ALL: u32 = 0x0FFF_FFFF;
/// `CCTLINFO_G7_W0_DISRTSFB` BIT(25) (`fw.h:1453`).
const W0_DISRTSFB: u32 = 1 << 25;
/// `CCTLINFO_G7_W0_DISDATAFB` BIT(26) (`fw.h:1454`).
const W0_DISDATAFB: u32 = 1 << 26;
/// `CCTLINFO_G7_W2_DATA_TXCNT_LMT_SEL` BIT(6) (`fw.h:1464`).
const W2_DATA_TXCNT_LMT_SEL: u32 = 1 << 6;
/// `CCTLINFO_G7_W3_RTS_TXCNT_LMT_SEL` BIT(30) (`fw.h:1487`).
const W3_RTS_TXCNT_LMT_SEL: u32 = 1 << 30;
/// `CCTLINFO_G7_W4_MULTI_PORT_ID` GENMASK(2, 0) (`fw.h:1490`).
const W4_MULTI_PORT_ID_MASK: u32 = 0x7;
/// `CCTLINFO_G7_W4_DATA_DCM` BIT(8) (`fw.h:1493`).
const W4_DATA_DCM: u32 = 1 << 8;
/// `CCTLINFO_G7_W6_AID12_PAID` GENMASK(11, 0) (`fw.h:1511`).
const W6_AID12_PAID_MASK: u32 = 0xFFF;
/// `CCTLINFO_G7_W6_ULDL` BIT(31) (`fw.h:1513`).
const W6_ULDL: u32 = 1 << 31;
/// `CCTLINFO_G7_W8_BSR_QUEUE_SIZE_FORMAT` BIT(1) (`fw.h:1527`).
const W8_BSR_QUEUE_SIZE_FORMAT: u32 = 1 << 1;
/// `RTW89_HW_RATE_CCK1` = 0x0 (`core.h:348`).
const HW_RATE_CCK1: u32 = 0x0;
/// `RTW89_HW_RATE_OFDM6` = 0x4 (`core.h:352`).
const HW_RATE_OFDM6: u32 = 0x4;

/// Build the default CMAC table for `macid`.
/// `mgq_rpt_en` is Linux's `rtwdev->hci.tx_rpt_enabled`.
pub(super) fn build_default(macid: u32, mgq_rpt_en: bool) -> Result<DefaultCmac, Error> {
    if macid > 0x7F {
        return Err(Error::BadMacId);
    }
    let mut w = [0u32; 16];
    let mut m = [0u32; 16];
    w[0] = (4 & W0_DATARATE_MASK) | (((mgq_rpt_en as u32) << 21) & W0_MGQ_RPT_EN);
    m[0] = W0_ALL;
    w[1] = (4 & W1_DATA_RTY_LOWEST_RATE_MASK)
        | ((0xA << 16) & W1_RTSRATE_MASK)
        | ((4 << 28) & W1_RTS_RTY_LOWEST_RATE_MASK);
    m[1] = W1_ALL;
    // w2, w3: value zero, mask ALL (Linux literal).
    m[2] = W2_ALL;
    m[3] = W3_ALL;
    w[4] = (0xFFFF << 16) & W4_ACT_SUBCH_CBW_MASK;
    m[4] = W4_ALL;
    w[5] = (2 | (2 << 2) | (2 << 4) | (2 << 6) | (2 << 8)) & W5_PADDING_MASK;
    m[5] = W5_ALL;
    w[6] = (0xB << 12) & W6_RESP_REF_RATE_MASK;
    m[6] = W6_ALL;
    w[7] = (1 & W7_NC_MASK)
        | ((1 << 3) & W7_NR_MASK)
        | ((1 << 8) & W7_CB_MASK)
        | W7_CSI_PARA_EN
        | ((0xB << 16) & W7_CSI_FIX_RATE_MASK);
    m[7] = W7_ALL;
    // w8: value zero, mask ALL (Linux literal).
    m[8] = W8_ALL;
    // w9..w13, m9..m13: untouched, zero on both sides.
    // w14, w15: current-rate fields zero; masks ALL.
    m[14] = W14_ALL;
    m[15] = W15_ALL;
    Ok(DefaultCmac {
        c0: macid | C0_OP,
        w,
        m,
    })
}

/// Build the association CMAC table for `macid`.
///
/// Mirrors Linux `rtw89/fw.c` `rtw89_fw_h2c_assoc_cmac_tbl_g7`
/// (torvalds/linux @ 05441d6). This is a SEPARATE H2C from the
/// default table: only the words below carry masks; every other
/// word/mask pair stays zero, so firmware keeps whatever the
/// default H2C programmed there.
///
/// Field map (Linux order):
/// - w0: DISRTSFB + DISDATAFB; m0: those two bits.
/// - w1: RTS retry lowest rate — CCK1 on 2.4 GHz (non-P2P),
///   OFDM6 otherwise (P2P is always OFDM6); m1: the 4-bit field.
/// - w2/w3: TX-count-limit selectors, both zero; m2/m3: their bits.
/// - w4: multi-port id; m4: the port field, plus DATA_DCM in
///   AP mode (value zero) and ACT_SUBCH_CBW = ~`punctured`
///   when EHT is supported (the default table's all-ones
///   subchannel mask is NOT reused here — Linux writes the
///   live puncturing bitmap instead).
/// - w5: nominal packet padding per width (20/40/80/160/320),
///   2 bits each, supplied by the caller from the peer's PPE
///   thresholds (zero when the peer has neither EHT nor HE caps
///   — Linux memsets the pads and only fills them from EHT/HE
///   caps); m5: all five padding fields. PPE parsing from peer
///   IEs is NOT done here — the 8922A station owner parses the
///   pads (`ppe::parse_assoc_ppe`, issue #1882) and passes them
///   in; this builder only validates their 2-bit range.
/// - w6: AID (12 bits) + ULDL (station mode); m6: both fields.
/// - w8: BSR queue-size format = peer HE support; m8: its bit.
///
/// The returned struct is the same c0+w+m payload shape as
/// [`DefaultCmac`]; the two H2C commands share one wire format.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_assoc(
    macid: u32,
    band_2g: bool,
    p2p: bool,
    port: u32,
    ap_mode: bool,
    eht_support: bool,
    punctured: u16,
    pads: [u8; 5],
    aid: u16,
    station_mode: bool,
    has_he: bool,
) -> Result<DefaultCmac, Error> {
    if macid > 0x7F {
        return Err(Error::BadMacId);
    }
    if port > W4_MULTI_PORT_ID_MASK || aid > W6_AID12_PAID_MASK as u16 {
        return Err(Error::BadValue);
    }
    if pads.iter().any(|p| *p > 3) {
        return Err(Error::BadValue);
    }
    let mut w = [0u32; 16];
    let mut m = [0u32; 16];
    w[0] = W0_DISRTSFB | W0_DISDATAFB;
    m[0] = W0_DISRTSFB | W0_DISDATAFB;
    let lowest_rate = if band_2g && !p2p {
        HW_RATE_CCK1
    } else {
        HW_RATE_OFDM6
    };
    w[1] = (lowest_rate << 28) & W1_RTS_RTY_LOWEST_RATE_MASK;
    m[1] = W1_RTS_RTY_LOWEST_RATE_MASK;
    // w2, w3: selector values zero, masks set (Linux literal).
    m[2] = W2_DATA_TXCNT_LMT_SEL;
    m[3] = W3_RTS_TXCNT_LMT_SEL;
    w[4] = port & W4_MULTI_PORT_ID_MASK;
    m[4] = W4_MULTI_PORT_ID_MASK;
    if ap_mode {
        // DATA_DCM value zero; only its mask bit is set.
        m[4] |= W4_DATA_DCM;
    }
    if eht_support {
        w[4] |= ((!punctured as u32) << 16) & W4_ACT_SUBCH_CBW_MASK;
        m[4] |= W4_ACT_SUBCH_CBW_MASK;
    }
    w[5] = (pads[0] as u32)
        | ((pads[1] as u32) << 2)
        | ((pads[2] as u32) << 4)
        | ((pads[3] as u32) << 6)
        | ((pads[4] as u32) << 8);
    m[5] = W5_PADDING_MASK;
    w[6] = (aid as u32 & W6_AID12_PAID_MASK) | ((station_mode as u32) << 31);
    m[6] = W6_AID12_PAID_MASK | W6_ULDL;
    w[8] = (has_he as u32) << 1;
    m[8] = W8_BSR_QUEUE_SIZE_FORMAT;
    Ok(DefaultCmac {
        c0: macid | C0_OP,
        w,
        m,
    })
}

/// `CCTLINFO_G7_W2_DATA_TX_CNT_LMT` GENMASK(5, 0) (`fw.h:1463`).
const W2_DATA_TX_CNT_LMT_MASK: u32 = 0x3F;
/// `CCTLINFO_G7_W2_AMPDU_MAX_TIME` GENMASK(31, 28) (`fw.h:1474`).
const W2_AMPDU_MAX_TIME_MASK: u32 = 0xF000_0000;
/// `CCTLINFO_G7_W3_BA_BMAP` GENMASK(14, 12) (`fw.h:1479`).
const W3_BA_BMAP_MASK: u32 = 0x7000;
/// `CCTLINFO_G7_W3_AMPDU_TIME_SEL` BIT(28) (`fw.h:1485`).
const W3_AMPDU_TIME_SEL: u32 = 1 << 28;

/// Build the AMPDU update CMAC table for `macid`.
///
/// Mirrors Linux `rtw89/fw.c` `rtw89_fw_h2c_ampdu_cmac_tbl_g7`
/// (torvalds/linux @ 05441d6). Only w3 carries a value+mask;
/// every other word/mask pair stays zero, so firmware keeps
/// whatever the default/assoc H2C programmed there.
///
/// `agg_nums` is the per-TID aggregation count for each TID
/// with an active BlockAck session (Linux iterates the set
/// bits of `ampdu_map`); the update uses the MINIMUM across
/// them. An empty slice means no active session, which Linux
/// reads as `agg_num` 0 — and 0 falls in the first bucket
/// below, so it still programs `ba_bmap` 3.
///
/// Bucket map (Linux thresholds, literal): agg_num <= 0x20
/// → 3; <= 0x40 → 0; <= 0x80 → 1; <= 0x100 → 2; <= 0x200
/// → 4; <= 0x400 → 5; above 0x400 → 0 (Linux leaves
/// `ba_bmap` at its zero initializer).
pub(super) fn build_ampdu(macid: u32, agg_nums: &[u16]) -> Result<DefaultCmac, Error> {
    if macid > 0x7F {
        return Err(Error::BadMacId);
    }
    let agg_num = agg_nums.iter().copied().min().unwrap_or(0);
    let ba_bmap = if agg_num <= 0x20 {
        3
    } else if agg_num <= 0x40 {
        0
    } else if agg_num <= 0x80 {
        1
    } else if agg_num <= 0x100 {
        2
    } else if agg_num <= 0x200 {
        4
    } else if agg_num <= 0x400 {
        5
    } else {
        0
    };
    let mut w = [0u32; 16];
    let mut m = [0u32; 16];
    w[3] = (ba_bmap << 12) & W3_BA_BMAP_MASK;
    m[3] = W3_BA_BMAP_MASK;
    Ok(DefaultCmac {
        c0: macid | C0_OP,
        w,
        m,
    })
}

/// Build the TX-time / TX-retry-limit update CMAC table for
/// `macid`.
///
/// Mirrors Linux `rtw89/fw.c` `rtw89_fw_h2c_txtime_cmac_tbl_g7`
/// (torvalds/linux @ 05441d6). The two Linux boolean gates
/// are `Option` here: `None` means the gate is off and its
/// words stay zero-masked, exactly as Linux leaves them.
///
/// - `Some(ampdu_max_time)`: w3 AMPDU_TIME_SEL set, w2
///   AMPDU_MAX_TIME = the value (4-bit field).
/// - `Some(data_tx_cnt_lmt)`: w2 DATA_TXCNT_LMT_SEL set,
///   w2 DATA_TX_CNT_LMT = the value (6-bit field).
///
/// Out-of-field values are rejected (`BadValue`); Linux
/// would silently truncate them with `le32_encode_bits`.
pub(super) fn build_txtime(
    macid: u32,
    ampdu_max_time: Option<u8>,
    data_tx_cnt_lmt: Option<u8>,
) -> Result<DefaultCmac, Error> {
    if macid > 0x7F {
        return Err(Error::BadMacId);
    }
    if let Some(t) = ampdu_max_time {
        if t as u32 > W2_AMPDU_MAX_TIME_MASK >> 28 {
            return Err(Error::BadValue);
        }
    }
    if let Some(l) = data_tx_cnt_lmt {
        if l as u32 > W2_DATA_TX_CNT_LMT_MASK {
            return Err(Error::BadValue);
        }
    }
    let mut w = [0u32; 16];
    let mut m = [0u32; 16];
    if let Some(t) = ampdu_max_time {
        w[3] |= W3_AMPDU_TIME_SEL;
        m[3] |= W3_AMPDU_TIME_SEL;
        w[2] |= (t as u32) << 28;
        m[2] |= W2_AMPDU_MAX_TIME_MASK;
    }
    if let Some(l) = data_tx_cnt_lmt {
        w[2] |= W2_DATA_TXCNT_LMT_SEL | (l as u32 & W2_DATA_TX_CNT_LMT_MASK);
        m[2] |= W2_DATA_TXCNT_LMT_SEL | W2_DATA_TX_CNT_LMT_MASK;
    }
    Ok(DefaultCmac {
        c0: macid | C0_OP,
        w,
        m,
    })
}

/// Build the punctured-subchannel update CMAC table.
///
/// Mirrors Linux `rtw89/fw.c` `rtw89_fw_h2c_punctured_cmac_tbl_g7`
/// (torvalds/linux @ 05441d6): w4 ACT_SUBCH_CBW = the bitwise
/// NOT of the puncturing bitmap, masked to the 16-bit field;
/// m4 = the field mask; every other pair stays zero.
///
/// NOTE the MAC-ID difference from the other builders: Linux
/// addresses this update by the VIF MAC ID
/// (`rtwvif_link->mac_id`), not the station MACID — so the
/// caller passes the VIF id here.
pub(super) fn build_punctured(macid_vif: u32, punctured: u16) -> Result<DefaultCmac, Error> {
    if macid_vif > 0x7F {
        return Err(Error::BadMacId);
    }
    let mut w = [0u32; 16];
    let mut m = [0u32; 16];
    w[4] = ((!punctured as u32) & 0xFFFF) << 16;
    m[4] = W4_ACT_SUBCH_CBW_MASK;
    Ok(DefaultCmac {
        c0: macid_vif | C0_OP,
        w,
        m,
    })
}
