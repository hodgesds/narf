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

/// Errors from the default CMAC builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// MAC ID exceeds the 7-bit C0_MACID field.
    BadMacId,
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
