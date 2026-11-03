// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B MAC_0/PHY_0 channel MAC and BB programming from the shared B
//! [`operating_channel::Profile`] (rtw8851b.c has the B SCO tables, SCO
//! mapping and 2.4/5GHz 20/40/80MHz support): `rtw8851b_set_channel_mac`,
//! then `rtw8851b_set_channel_bb` in Linux order (`rtw8851b_ctrl_sco_cck`,
//! `rtw8851b_ctrl_ch` with the single-path `rtw8851b_set_gain_error`,
//! `rtw8851b_set_gain_offset` (gain comp + offset with `offset_base` and
//! `rssi_base`) and `rtw8851b_set_rxsc_rpl_comp`, `rtw8851b_ctrl_bw` with
//! the `adc_td` `rtw8851b_bw_setting`, `rtw8851b_ctrl_cck_en`, NBI/CSI spur,
//! 5GHz BT share release, `B_CH_IDX_SEG0`, `rtw8851b_5m_mask`,
//! `rtw8851b_set_cfr`, `rtw8851b_bb_reset_all`), every final bit read back.
//! The RF half is `channel_rf::Channel::prepare_for_channel_51`. No native
//! caller and no admission.
use super::{
    channel_c::{apply, div_round_closest, div_round_down, freq_diff, modify, verify, Field},
    factory_51,
    operating_channel::{Profile, Width},
    power::{self, Io},
    radio_gain::Gain,
};

/// PHY register aperture offset (phy.c `rtw89_phy_write32*`).
const PHY: u32 = 0x10000;

/// `bb_gain_lna[LNA_GAIN_NUM]` path A: (gain_g, gain_a, mask).
const LNA: [(u32, u32, u32); 7] = [
    (0x4678, 0x45dc, 0x00ff_0000),
    (0x4678, 0x45dc, 0xff00_0000),
    (0x467c, 0x4660, 0x0000_00ff),
    (0x467c, 0x4660, 0x0000_ff00),
    (0x467c, 0x4660, 0x00ff_0000),
    (0x467c, 0x4660, 0xff00_0000),
    (0x4680, 0x4664, 0x0000_00ff),
];
/// `bb_gain_tia[TIA_GAIN_NUM]` path A.
const TIA: [(u32, u32, u32); 2] = [(0x4680, 0x4664, 0x00ff_0000), (0x4680, 0x4664, 0xff00_0000)];
/// R_TXFIR0..E (each B_TXFIR_Cxx = GENMASK(23, 0)).
const TXFIR: [u32; 8] = [
    0x2300, 0x2304, 0x2308, 0x230c, 0x2310, 0x2314, 0x2318, 0x231c,
];
/// `rtw8851b_nbi_reg_def`: notch1 / notch2 (idx 0xff, frac 0xc00, en 0x1000).
const NBI: (u32, u32) = (0x46e4, 0x47a4);

/// Inputs the RTL8851B channel program consumes, all retained from
/// completed owners.
#[derive(Clone, Copy)]
pub(super) struct Inputs<'a> {
    /// phy.c `rtw89_phy_config_bb_gain_ax` result for this RTL8851B RFE.
    pub gain: &'a Gain,
    /// `factory_51::Calibration` (`efuse_gain` offset/comp, `adc_td`).
    pub calibration: &'a factory_51::Calibration,
    /// `[efuse_gain.offset_base[PHY_0], efuse_gain.rssi_base[PHY_0]]` from
    /// `radio_init::controls_51`.
    pub bases: [i8; 2],
}

/// `rtw8851b_set_channel_mac(MAC_0)`: (RFMOD, TX sub-carrier word,
/// TXRATE_CHK bits set after clearing BAND_MODE | CHECK_CCK_EN |
/// RTS_LIMIT_IN_OFDM6). `None` for 160MHz (rtw8851b.c
/// `support_bandwidths` has none).
pub(super) fn mac_program(profile: Profile) -> Option<(u8, u32, u8)> {
    let txsc20 = u32::from(profile.txsc(Width::Mhz20));
    let txsc40 = u32::from(profile.txsc(Width::Mhz40));
    let (rf_mod, sub_carrier) = match profile.width() {
        Width::Mhz20 => (0, 0),
        Width::Mhz40 => (1, txsc20),
        Width::Mhz80 => (2, txsc20 | (txsc40 << 4)),
        Width::Mhz160 => return None,
    };
    // channel > 14: BAND_MODE clear, CHECK_CCK_EN | RTS_LIMIT_IN_OFDM6 set;
    // else BAND_MODE set and the other two clear.
    let chk = if profile.is_5ghz() { 0x3 } else { 0x10 };
    Some((rf_mod, sub_carrier, chk))
}

/// `rtw8851b_set_gain_error(subband, RF_PATH_A)`.
fn gain_error(profile: Profile, gain: &Gain, out: &mut alloc::vec::Vec<Field>) {
    let band = profile.gain_band();
    let g2 = profile.subband() == 0;
    let v = |x: i8| x as i32 as u32;
    for (i, &(g, a, mask)) in LNA.iter().enumerate() {
        out.push((PHY + if g2 { g } else { a }, mask, v(gain.lna[band][0][i])));
    }
    for (i, &(g, a, mask)) in TIA.iter().enumerate() {
        out.push((PHY + if g2 { g } else { a }, mask, v(gain.tia[band][0][i])));
    }
}

/// `rtw8851b_set_gain_offset(subband, PHY_0)` (PHY_0: no `_idx` offset).
fn gain_offset(profile: Profile, inputs: &Inputs<'_>, out: &mut alloc::vec::Vec<Field>) {
    let cal = inputs.calibration;
    let subband = usize::from(profile.subband());
    if cal.comp_valid {
        // R_P0_AGC_RSVD MASKBYTE0.
        let tmp = (i32::from(cal.gain_comp[subband]) << 2).clamp(-128, 127);
        out.push((PHY + 0x4acc, 0xff, tmp as u32));
    }
    if !cal.offset_valid {
        return;
    }
    let [offset_base, rssi_base] = inputs.bases.map(i32::from);
    let ofdm = -i32::from(cal.gain_offset[profile.gain_offset_band()]);
    let cck = -i32::from(cal.gain_offset[0]);
    // R_PATH0_G_TIA1_LNA6_OP1DB_V1 B_PATH0_R_G_OFST_MASK.
    let tmp = (-((ofdm << 2) + (offset_base >> 2))).clamp(-128, 127);
    out.push((PHY + 0x4694, 0x00ff_0000, tmp as u32));
    // R_P0_RPL1 / R_P1_RPL1 B_P0_RPL1_BIAS_MASK.
    let tmp = ((ofdm << 4) + offset_base).clamp(-128, 127);
    out.push((PHY + 0x49b0, 0xff, tmp as u32));
    let tmp = ((ofdm << 4) + rssi_base).clamp(-128, 127);
    out.push((PHY + 0x4a00, 0xff, tmp as u32));
    if subband == 0 {
        // R_RX_RPL_OFST B_RX_RPL_OFST_CCK_MASK.
        let tmp = ((cck << 3) + (offset_base >> 1)).clamp(-64, 63);
        out.push((PHY + 0x23ac, 0x7f, tmp as u32));
    }
}

/// `rtw8851b_set_rxsc_rpl_comp(subband)`: path A RPL offsets into the P0
/// and P1 RPL1 (bits [31:8]), RPL2 and RPL3 words.
fn rxsc_rpl_comp(profile: Profile, gain: &Gain, out: &mut alloc::vec::Vec<Field>) {
    let band = profile.gain_band();
    let b = |x: i8, shift: u32| (x as u8 as u32) << shift;
    let r40 = |i: usize| gain.rpl40[band][0][i];
    let r80 = |i: usize| gain.rpl80[band][0][i];
    let rpl1 = b(gain.rpl20[band][0], 8) | b(r40(0), 16) | b(r40(1), 24);
    let rpl2 = b(r40(2), 0) | b(r80(0), 8) | b(r80(1), 16) | b(r80(10), 24);
    let rpl3 = b(r80(2), 0) | b(r80(3), 8) | b(r80(4), 16) | b(r80(9), 24);
    // B_P0_RPL1_MASK = GENMASK(31, 8), written with val >> B_P0_RPL1_SHIFT.
    out.push((PHY + 0x49b0, 0xffff_ff00, rpl1 >> 8));
    out.push((PHY + 0x4a00, 0xffff_ff00, rpl1 >> 8));
    out.push((PHY + 0x49b4, u32::MAX, rpl2));
    out.push((PHY + 0x4a04, u32::MAX, rpl2));
    out.push((PHY + 0x49b8, u32::MAX, rpl3));
    out.push((PHY + 0x4a08, u32::MAX, rpl3));
}

/// `rtw8851b_bw_setting(bw)`: ADC BW select from `efuse->adc_td`, then the
/// per-width CFCH/DCIM/WDADC/ADDCK/RXCK fields.
fn bw_setting(width: Width, adc_td: u8, out: &mut alloc::vec::Vec<Field>) {
    let adc_bw_sel = match adc_td {
        0x11 => 0x5,
        0x9 => 0x3,
        _ => 0x4,
    };
    out.push((PHY + 0xc0d8, 0x1e0, adc_bw_sel));
    out.push((PHY + 0xc0c4, 0x003e_0000, 0xf));
    out.push((PHY + 0xc0e8, 0xffff_0000, 0xa));
    out.push((PHY + 0xc0ec, 0x00ff_0000, 0x3));
    let dcim_fr = match width {
        Width::Mhz80 => 0x0,
        _ => 0x2,
    };
    out.push((PHY + 0xc0d4, 0x780, 0x8));
    out.push((PHY + 0xc0d4, 0x7800, 0x2));
    out.push((PHY + 0xc0d4, 0x0c00_0000, 0x2));
    out.push((PHY + 0xc0ec, 0x6000, dcim_fr));
    out.push((PHY + 0xc0e4, 0x30, 0x2));
    out.push((PHY + 0xc0f0, 1 << 16, 0x0));
    out.push((PHY + 0x12a0, 0xff80_0000, 0x92));
}

/// Field program of `rtw8851b_ctrl_sco_cck` (2.4GHz), `rtw8851b_ctrl_ch`
/// and `rtw8851b_ctrl_bw(pri_ch_idx, bw, PHY_0)`, in Linux order. `None`
/// for 160MHz.
pub(super) fn ctrl_fields(profile: Profile, inputs: &Inputs<'_>) -> Option<alloc::vec::Vec<Field>> {
    let width = profile.width();
    if width == Width::Mhz160 {
        return None;
    }
    let mut out = alloc::vec::Vec::new();
    if profile.cck_enabled() {
        let [barker, cck] = profile.sco();
        out.push((PHY + 0x23b0, 0x7ffff, barker));
        out.push((PHY + 0x23b4, 0x7ffff, cck));
    }
    // rtw8851b_ctrl_ch: R_PATH0_BAND_SEL_V1 BIT(17), R_FC0_BW_V1
    // B_FC0_BW_INV = rtw8851b_sco_mapping(central_ch).
    out.push((PHY + 0x4738, 1 << 17, u32::from(!profile.is_5ghz())));
    out.push((PHY + 0x49c0, 0x7f, profile.sco_compensation()));
    // CCK TXFIR literals (channel 14 or the flat set, 5GHz included); the
    // B words carry identical low 24 bits.
    for (address, value) in TXFIR.into_iter().zip(profile.cck_fir(0)) {
        out.push((PHY + address, 0x00ff_ffff, value & 0x00ff_ffff));
    }
    gain_error(profile, inputs.gain, &mut out);
    gain_offset(profile, inputs, &mut out);
    rxsc_rpl_comp(profile, inputs.gain, &mut out);
    // rtw8851b_ctrl_bw: R_FC0_BW_V1 B_FC0_BW_SET, R_CHBW_MOD_V1 SBW/PRICH.
    let pri = u32::from(profile.pri_ch_idx());
    out.push((PHY + 0x49c0, 0xc000_0000, width as u32));
    out.push((PHY + 0x49c4, 0x3000, 0));
    out.push((PHY + 0x49c4, 0xf00, pri));
    if width == Width::Mhz40 {
        // CCK primary channel: R_RXSC B_RXSC_EN (RTW89_SC_20_UPPER = 1).
        out.push((PHY + 0x237c, 1, u32::from(pri == 1)));
    }
    bw_setting(width, inputs.calibration.adc_td, &mut out);
    Some(out)
}

/// rtw8851b.c `rtw8851b_spur_freq` (MHz; 0 = no spur).
pub(super) fn spur_freq(profile: Profile) -> u32 {
    if !profile.is_5ghz() {
        return 0;
    }
    match profile.center() {
        151 | 153 | 155 | 163 => 5760,
        54 | 58 => 5280,
        _ => 0,
    }
}

/// `rtw8851b_set_nbi_tone_idx(chan)` (no 160MHz notch2 branch: 160MHz is
/// refused before any write).
fn nbi_tone(profile: Profile, out: &mut alloc::vec::Vec<Field>) {
    let (n1, n2) = NBI;
    let spur = spur_freq(profile);
    if spur == 0 {
        out.push((PHY + n1, 0x1000, 0));
        out.push((PHY + n2, 0x1000, 0));
        return;
    }
    let width = profile.width();
    let (nbi_idx, frac) = div_round_down(freq_diff(spur, profile.center_mhz()), 312_500);
    let tone = if width == Width::Mhz20 {
        div_round_down(nbi_idx + 32, 64).1
    } else {
        div_round_down(nbi_idx, if width == Width::Mhz40 { 128 } else { 256 }).1
    };
    let frac_tone = div_round_closest(frac, 78_125);
    out.push((PHY + n1, 0xff, tone as u32));
    out.push((PHY + n1, 0xc00, frac_tone as u32));
    out.push((PHY + n1, 0x1000, 0));
    out.push((PHY + n1, 0x1000, 1));
    out.push((PHY + n2, 0x1000, 0));
}

/// `rtw8851b_set_csi_tone_idx(chan, PHY_0)`.
fn csi_tone(profile: Profile, out: &mut alloc::vec::Vec<Field>) {
    let spur = spur_freq(profile);
    if spur == 0 {
        out.push((PHY + 0x42c8, 1 << 23, 0));
        return;
    }
    let csi = div_round_closest(freq_diff(spur, profile.center_mhz()), 78_125);
    out.push((PHY + 0x42b0, 0x7ff, div_round_down(csi, 2048).1 as u32));
    out.push((PHY + 0x42c8, 1 << 23, 1));
}

/// `rtw8851b_5m_mask(chan, PHY_0)` (path 0 only, threshold 0x5).
fn mask_5m(profile: Profile, out: &mut alloc::vec::Vec<Field>) {
    let pri = profile.pri_ch_idx();
    // RTW89_SC_20_LOWER = 2, UPMOST = 3, LOWEST = 4.
    let (en, low) = match profile.width() {
        Width::Mhz40 => (true, pri == 2),
        Width::Mhz80 => (pri == 3 || pri == 4, pri == 4),
        _ => (false, false),
    };
    if !en {
        out.push((PHY + 0x46f8, 1 << 12, 0));
        out.push((PHY + 0x4440, 1 << 31, 0));
        return;
    }
    out.push((PHY + 0x46f8, 0x3f, 0x5));
    out.push((PHY + 0x46f8, 1 << 12, 1));
    out.push((PHY + 0x46f8, 1 << 8, u32::from(!low)));
    out.push((PHY + 0x46f8, 1 << 6, u32::from(low)));
    out.push((PHY + 0x4440, 1 << 31, 1));
}

/// `rtw8851b_set_cfr(chan)`: (TX_CFR LGC0, LGC1, POLAR_CLIPPING LGC0, LGC1).
fn cfr(profile: Profile, out: &mut alloc::vec::Vec<Field>) {
    let edge =
        !profile.is_5ghz() && profile.width() == Width::Mhz20 && matches!(profile.center(), 1 | 13);
    let (c0, c1, p0, p1) = if edge {
        (0xf8, 0x120, 0x0, 0x3)
    } else {
        (0x120, 0x3ff, 0x3, 0x7)
    };
    out.push((PHY + 0x4b30, 0x3ff, c0));
    out.push((PHY + 0x4b30, 0xffc00, c1));
    out.push((PHY + 0x4b3c, 0xf000, p0));
    out.push((PHY + 0x4b3c, 0xf_0000, p1));
}

/// `rtw8851b_set_channel_bb` after `rtw8851b_ctrl_bw`, up to (not
/// including) `rtw8851b_bb_reset_all`.
pub(super) fn tail_fields(profile: Profile) -> alloc::vec::Vec<Field> {
    let mut out = alloc::vec::Vec::new();
    let cck = profile.cck_enabled();
    // rtw8851b_ctrl_cck_en: R_RXCCA B_RXCCA_DIS, R_PD_ARBITER_OFF,
    // R_UPD_CLK_ADC B_ENABLE_CCK.
    out.push((PHY + 0x2344, 1 << 31, u32::from(!cck)));
    out.push((PHY + 0x0c80, 1 << 31, u32::from(!cck)));
    out.push((PHY + 0x0700, 1 << 5, u32::from(cck)));
    nbi_tone(profile, &mut out);
    csi_tone(profile, &mut out);
    if profile.is_5ghz() {
        for (address, mask) in [
            (0x4738, 1 << 19),     // R_PATH0_BT_SHARE_V1
            (0x4738, 1 << 22),     // R_PATH0_BTG_PATH_V1
            (0x49c4, 1 << 14),     // R_CHBW_MOD_V1 B_BT_SHARE
            (0x49c0, 0x03c0_0000), // R_FC0_BW_V1 B_ANT_RX_BT_SEG0
            (0x4420, 1 << 31),     // R_BT_DYN_DC_EST_EN_V1
            (0x0c6c, 1 << 21),     // R_GNT_BT_WGT_EN
        ] {
            out.push((PHY + address, mask, 0));
        }
    }
    // R_MAC_PIN_SEL B_CH_IDX_SEG0 = rtw89_encode_chan_idx(primary, band).
    out.push((PHY + 0x0734, 0x00ff_0000, u32::from(profile.chan_idx())));
    mask_5m(profile, &mut out);
    cfr(profile, &mut out);
    out
}

/// `rtw8851b_bb_reset_all(PHY_0)`: (before the 1us hold, after it); only
/// the S0 HW-SI trigger.
pub(super) const RESET_ALL: ([Field; 1], [Field; 4]) = (
    [(PHY + 0x1200, 0x7000_0000, 7)],
    [
        (PHY + 0x0704, 1 << 1, 1),
        (PHY + 0x0704, 1 << 1, 0),
        (PHY + 0x1200, 0x7000_0000, 0),
        (PHY + 0x0704, 1 << 1, 1),
    ],
);

/// Program `rtw8851b_set_channel_mac(MAC_0)` and the whole
/// `rtw8851b_set_channel_bb(chan, PHY_0)`, reading every final bit back.
/// 160MHz is refused before any write.
///
/// # Safety
/// Actual RTL8851B MAC_0/PHY_0 with completed RTL8851B tables,
/// `controls_51`, `nctl_51` and RFK init, inside the channel-help window,
/// with exclusive radio ownership and a current channel grant for `profile`.
pub(super) async unsafe fn program(
    io: &mut impl Io,
    profile: Profile,
    inputs: &Inputs<'_>,
) -> Result<(), power::Error> {
    let (Some((rf_mod, sub_carrier, chk)), Some(ctrl)) =
        (mac_program(profile), ctrl_fields(profile, inputs))
    else {
        return Err(power::Error::Unsupported);
    };
    // write8_mask / write8_clr / write8_set on the low bytes; write32.
    let old = io.read8(0xc010)?;
    io.write8(0xc010, (old & !0x3) | rf_mod)?;
    io.write32(0xc088, sub_carrier)?;
    let old = io.read8(0xc628)?;
    io.write8(0xc628, (old & !0x13) | chk)?;
    if io.read32(0xc088)? != sub_carrier
        || io.read8(0xc010)? & 0x3 != rf_mod
        || io.read8(0xc628)? & 0x13 != chk
    {
        return Err(power::Error::Access);
    }
    let mut bb = ctrl;
    bb.extend(tail_fields(profile));
    for &(address, mask, value) in &bb {
        if mask == u32::MAX {
            // rtw89_phy_write32 (RPL2/RPL3 words).
            io.write32(address, value)?;
        } else {
            modify(io, address, mask, value)?;
        }
    }
    verify(io, &bb)?;
    for &(address, mask, value) in &RESET_ALL.0 {
        modify(io, address, mask, value)?;
    }
    io.delay_us(1).await;
    // The trailing writes leave HW-SI 0 and RSTB_ASYNC 1; read both back.
    apply(io, &RESET_ALL.1)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_51/tests.rs"]
mod tests;
