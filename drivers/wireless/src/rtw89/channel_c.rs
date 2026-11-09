// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C MAC_0/PHY_0 (non-DBCC) channel MAC and BB channel-control
//! programming from an [`operating_channel_c::Profile`]: rtw8852c.c
//! `rtw8852c_set_channel_mac`, `rtw8852c_ctrl_sco_cck` and
//! `rtw8852c_ctrl_ch` (`rtw8852c_set_gain_error`,
//! `rtw8852c_set_gain_offset`, band select, SCO FC0, CCK pulse coefficients,
//! `B_CH_IDX_SEG0`) and `rtw8852c_ctrl_bw`, then the rest of
//! `rtw8852c_set_channel_bb` (CCK/CCA/PD arbiter, spur CSI/NBI/notch, BTG
//! BT RX, 5M mask, 160MHz P80 RU, CDD EVM, TXPW RSTB, MUIC,
//! `rtw8852c_ctrl_tx_path_tmac`, `rtw8852c_bb_reset_all`), each read back.
//! No native caller and no admission.
use super::{
    factory_c,
    operating_channel_c::{Band, Profile, Width},
    power::{self, Io},
    radio_gain::Gain,
};

/// PHY register aperture offset (phy.c `rtw89_phy_write32*`).
const PHY: u32 = 0x10000;

/// `bb_gain_lna[LNA_GAIN_NUM]`: (gain_g[A, B], gain_a[A, B], mask).
const LNA: [([u32; 2], [u32; 2], u32); 7] = [
    ([0x4678, 0x475c], [0x45dc, 0x4740], 0x00ff_0000),
    ([0x4678, 0x475c], [0x45dc, 0x4740], 0xff00_0000),
    ([0x467c, 0x4760], [0x4660, 0x4744], 0x0000_00ff),
    ([0x467c, 0x4760], [0x4660, 0x4744], 0x0000_ff00),
    ([0x467c, 0x4760], [0x4660, 0x4744], 0x00ff_0000),
    ([0x467c, 0x4760], [0x4660, 0x4744], 0xff00_0000),
    ([0x4680, 0x4764], [0x4664, 0x4748], 0x0000_00ff),
];
/// `bb_gain_tia[TIA_GAIN_NUM]`.
const TIA: [([u32; 2], [u32; 2], u32); 2] = [
    ([0x4680, 0x4764], [0x4664, 0x4748], 0x00ff_0000),
    ([0x4680, 0x4764], [0x4664, 0x4748], 0xff00_0000),
];
/// `bb_gain_bypass_lna[LNA_GAIN_NUM]`: (gain_g, gain_a, mask_g, mask_a).
const BYPASS: [([u32; 2], [u32; 2], u32, u32); 7] = [
    ([0x4bb8, 0x4c7c], [0x4bb4, 0x4c78], 0xff00_0000, 0xff),
    ([0x4bbc, 0x4c80], [0x4bb4, 0x4c78], 0xff, 0xff00),
    ([0x4bbc, 0x4c80], [0x4bb4, 0x4c78], 0xff00, 0xff_0000),
    ([0x4bbc, 0x4c80], [0x4bb4, 0x4c78], 0xff_0000, 0xff00_0000),
    ([0x4bbc, 0x4c80], [0x4bb8, 0x4c7c], 0xff00_0000, 0xff),
    ([0x4bc0, 0x4c84], [0x4bb8, 0x4c7c], 0xff, 0xff00),
    ([0x4bc0, 0x4c84], [0x4bb8, 0x4c7c], 0xff00, 0xff_0000),
];
/// `bb_gain_op1db_a.reg[]`: (lna[A, B], tia_lna[A, B], mask).
const OP1DB: [([u32; 2], [u32; 2], u32); 7] = [
    ([0x4668, 0x474c], [0x4670, 0x4754], 0xff),
    ([0x4668, 0x474c], [0x4670, 0x4754], 0xff00),
    ([0x4668, 0x474c], [0x4670, 0x4754], 0xff_0000),
    ([0x4668, 0x474c], [0x4670, 0x4754], 0xff00_0000),
    ([0x466c, 0x4750], [0x4674, 0x4758], 0xff),
    ([0x466c, 0x4750], [0x4674, 0x4758], 0xff00),
    ([0x466c, 0x4750], [0x4674, 0x4758], 0xff_0000),
];
/// `bb_gain_op1db_a.reg_tia0_lna6` / `mask_tia0_lna6`.
const TIA0_LNA6: ([u32; 2], u32) = ([0x4674, 0x4758], 0xff00_0000);
/// R_PCOEFF0/2/4/6/8/A/C/E_V1 (each GENMASK(23, 0)).
const PCOEFF: [u32; 8] = [
    0x45bc, 0x45cc, 0x45d0, 0x45d4, 0x45d8, 0x45c0, 0x45c4, 0x45c8,
];

/// One BB/MAC field write: (absolute address, mask, value).
pub(super) type Field = (u32, u32, u32);

/// Inputs the C channel control consumes, all retained from completed owners.
#[derive(Clone, Copy)]
pub(super) struct Inputs<'a> {
    /// phy.c `rtw89_phy_config_bb_gain_ax` result for this C RFE.
    pub gain: &'a Gain,
    /// `rtw8852c_efuse_parsing_gain_offset` (`efuse_gain.offset[]`, valid).
    pub calibration: &'a factory_c::Calibration,
    /// `efuse_gain.offset_base[PHY_0]` from `radio_init::controls_c`.
    pub offset_base: i8,
}

pub(super) fn modify(
    io: &mut impl Io,
    address: u32,
    mask: u32,
    value: u32,
) -> Result<(), power::Error> {
    let old = io.read32(address)?;
    if old == u32::MAX {
        return Err(power::Error::Gone);
    }
    io.write32(
        address,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}
pub(super) fn apply(io: &mut impl Io, fields: &[Field]) -> Result<(), power::Error> {
    for &(address, mask, value) in fields {
        modify(io, address, mask, value)?;
    }
    verify(io, fields)
}
/// Read back the final state of every written bit: the fields are folded in
/// order per address (later and overlapping writes win, as on hardware) and
/// each address is read once.
pub(super) fn verify(io: &mut impl Io, fields: &[Field]) -> Result<(), power::Error> {
    let mut known: alloc::vec::Vec<(u32, u32, u32)> = alloc::vec::Vec::new();
    for &(address, mask, value) in fields {
        let bits = (value << mask.trailing_zeros()) & mask;
        match known.iter_mut().find(|k| k.0 == address) {
            Some(k) => {
                k.1 |= mask;
                k.2 = (k.2 & !mask) | bits;
            }
            None => known.push((address, mask, bits)),
        }
    }
    for (address, mask, expected) in known {
        let value = io.read32(address)?;
        if value == u32::MAX || value & mask != expected {
            return Err(power::Error::Access);
        }
    }
    Ok(())
}

/// rtw8852c.c `rtw8852c_set_gain_error(subband, path)` field writes.
fn gain_error(profile: Profile, gain: &Gain, path: usize, out: &mut alloc::vec::Vec<Field>) {
    let band = profile.gain_band();
    let g2 = profile.subband() == 0;
    let v = |x: i8| x as i32 as u32;
    for (i, &(g, a, mask)) in LNA.iter().enumerate() {
        let reg = if g2 { g[path] } else { a[path] };
        out.push((PHY + reg, mask, v(gain.lna[band][path][i])));
        let (g, a, mask_g, mask_a) = BYPASS[i];
        let (reg, mask) = if g2 {
            (g[path], mask_g)
        } else {
            (a[path], mask_a)
        };
        out.push((PHY + reg, mask, v(gain.bypass[band][path][i])));
        if !g2 {
            let (lna, tia_lna, mask) = OP1DB[i];
            out.push((PHY + lna[path], mask, v(gain.lna_op1db[band][path][i])));
            out.push((PHY + tia_lna[path], mask, v(gain.tia_op1db[band][path][i])));
        }
    }
    if !g2 {
        out.push((
            PHY + TIA0_LNA6.0[path],
            TIA0_LNA6.1,
            v(gain.tia_op1db[band][path][7]),
        ));
    }
    for (i, &(g, a, mask)) in TIA.iter().enumerate() {
        let reg = if g2 { g[path] } else { a[path] };
        out.push((PHY + reg, mask, v(gain.tia[band][path][i])));
    }
}

/// rtw8852c.c `rtw8852c_set_gain_offset(chan, PHY_0, path)` field writes;
/// nothing when `offset_valid` is false.
fn gain_offset(
    profile: Profile,
    inputs: &Inputs<'_>,
    path: usize,
    out: &mut alloc::vec::Vec<Field>,
) {
    let cal = inputs.calibration;
    if !cal.offset_valid {
        return;
    }
    let base = i32::from(inputs.offset_base);
    if profile.band() == Band::Ghz2 {
        // RTW89_GAIN_OFFSET_2G_CCK = 0.
        let q0 = i32::from(cal.gain_offset[path][0]);
        let tmp =
            ((-q0 << 3) + (base >> 1)).clamp(i32::from(i8::MIN) >> 1, i32::from(i8::MAX) >> 1);
        out.push((PHY + 0x2340, 0x7f00, (tmp & 0x7f) as u32));
    }
    let q0 = -i32::from(cal.gain_offset[path][profile.gain_offset_band()]);
    let tmp = (-((q0 << 2) + (base >> 2))).clamp(i32::from(i8::MIN), i32::from(i8::MAX));
    out.push((
        PHY + [0x4694, 0x4778][path],
        0x00ff_0000,
        (tmp & 0xff) as u32,
    ));
    let tmp = (q0 << 4).clamp(i32::from(i8::MIN), i32::from(i8::MAX));
    out.push((
        PHY + 0x4e0c,
        [0xff00, 0x00ff_0000][path],
        (tmp & 0xff) as u32,
    ));
    out.push((PHY + 0x4e2c, [0xff, 0xff00][path], (tmp & 0xff) as u32));
}

/// Field program of `rtw8852c_set_channel_mac(MAC_0)` (byte registers
/// R_AX_WMAC_RFMOD 0xc010 / R_AX_TXRATE_CHK 0xc628 as their 32-bit words).
pub(super) fn mac_fields(profile: Profile) -> [Field; 4] {
    let (rf_mod, sub_carrier, chk) = profile.mac_program();
    [
        (0xc010, 0x3, u32::from(rf_mod)),
        (0xc088, u32::MAX, sub_carrier),
        // write8_clr(BAND_MODE | CHECK_CCK_EN | RTS_LIMIT_IN_OFDM6), then set.
        (0xc628, 0x13, 0),
        (0xc628, u32::from(chk), u32::from(chk)),
    ]
}

/// Field program of `rtw8852c_ctrl_sco_cck` (2.4GHz) followed by
/// `rtw8852c_ctrl_ch(chan, PHY_0)` with `dbcc_en` = 0, in Linux order.
pub(super) fn ctrl_fields(profile: Profile, inputs: &Inputs<'_>) -> alloc::vec::Vec<Field> {
    let mut out = alloc::vec::Vec::new();
    if let Some([barker, cck]) = profile.sco_cck() {
        out.push((PHY + 0x4a1c, 0x7ffff, barker));
        out.push((PHY + 0x4a20, 0x7ffff, cck));
    }
    let g2 = u32::from(profile.band() == Band::Ghz2);
    for (path, band_sel) in [(0, 0x4738), (1, 0x4aa4)] {
        gain_error(profile, inputs.gain, path, &mut out);
        gain_offset(profile, inputs, path, &mut out);
        out.push((PHY + band_sel, 1 << 17, g2));
    }
    out.push((PHY + 0x4970, 1 << 1, 0));
    let (fc, sco) = profile.sco_fc0();
    out.push((PHY + 0x4e30, 0x1fff, fc));
    out.push((PHY + 0x4974, 0x7f, sco));
    if let Some(coefficients) = profile.cck_pcoeff() {
        for (address, value) in PCOEFF.into_iter().zip(coefficients) {
            out.push((PHY + address, 0xff_ffff, value));
        }
    }
    out.push((PHY + 0x0734, 0x00ff_0000, u32::from(profile.chan_idx())));
    ctrl_bw(profile, &mut out);
    out
}

/// rtw8852c.c `rtw8852c_ctrl_bw(chan->pri_ch_idx, bw, PHY_0)` with
/// `dbcc_en` = 0: FC0 BW set, CHBW SBW/primary, per-path sample delay and BW
/// select, BW40 2xFFT / T2F GI combine, `rtw8852c_bw_setting` for A and B,
/// `rtw8852c_edcca_per20_bitmap_sifs`.
fn ctrl_bw(profile: Profile, out: &mut alloc::vec::Vec<Field>) {
    let width = profile.width();
    // Linux `rtw8852c_ctrl_bw` switches on 5/10/20/40/80/160 only; its
    // `default:` arm warns and programs no FC0 BW / CHBW / sample-delay
    // / BW-select field, so a 320MHz profile emits none of those. The
    // BW40 2xFFT / T2F GI combine writes and the per-20 bitmap (the
    // `rtw8852c_edcca_per20_bitmap_sifs` part, which Linux runs for
    // every bandwidth) still apply below.
    let bw = match width {
        Width::Mhz20 => Some((0, 0, 3, 0xf)),
        Width::Mhz40 => Some((1, profile.pri_ch_idx(), 3, 0xf)),
        Width::Mhz80 => Some((2, profile.pri_ch_idx(), 2, 0xd)),
        Width::Mhz160 => Some((3, profile.pri_ch_idx(), 1, 0xb)),
        Width::Mhz320 => None,
    };
    if let Some((set, prich, delay, select)) = bw {
        out.push((PHY + 0x4974, 0xc000_0000, set));
        out.push((PHY + 0x4978, 0x3000, 0));
        out.push((PHY + 0x4978, 0xf00, u32::from(prich)));
        out.push((PHY + 0xc0d4, 0x0c00_0000, delay));
        out.push((PHY + 0xc1d4, 0x0c00_0000, delay));
        out.push((PHY + 0xc0d8, 0x1e0, select));
        out.push((PHY + 0xc1d8, 0x1e0, select));
    }
    let bw40 = u32::from(width == Width::Mhz40);
    out.push((PHY + 0x4e30, 1 << 26, bw40));
    out.push((PHY + 0x4424, 1 << 2, bw40));
    for (adc, wbadc) in [(0xc0ec, 0xc0e4), (0xc1ec, 0xc1e4)] {
        out.push((PHY + adc, 0x6000, 0));
        out.push((PHY + wbadc, 0x30, 2));
    }
    let per20 = if width == Width::Mhz20 { 0xff } else { 0 };
    out.push((PHY + 0x0c9c, 0x000f_f000, per20));
    out.push((PHY + 0x0ca0, 0x000f_f000, 0));
}

/// rtw8852c.c `rtw8852c_spur_freq` (MHz; 0 = no spur).
pub(super) fn spur_freq(profile: Profile) -> u32 {
    let center = profile.center();
    match (profile.band(), profile.width()) {
        (Band::Ghz2, Width::Mhz20) if (5..=8).contains(&center) => 2440,
        (Band::Ghz2, Width::Mhz20) if center == 13 => 2480,
        (Band::Ghz2, Width::Mhz40) if (3..=10).contains(&center) => 2440,
        (Band::Ghz5, _) if matches!(center, 151 | 153 | 155 | 163) => 5760,
        (Band::Ghz6, _) if matches!(center, 195 | 197 | 199 | 207) => 6920,
        _ => 0,
    }
}

/// util.h `s32_div_u32_round_down`: (floor quotient, non-negative remainder).
pub(super) fn div_round_down(dividend: i32, divisor: i32) -> (i32, i32) {
    let (mut q, mut r) = (dividend / divisor, dividend % divisor);
    if r < 0 {
        q -= 1;
        r += divisor;
    }
    (q, r)
}
/// util.h `s32_div_u32_round_closest`.
pub(super) fn div_round_closest(dividend: i32, divisor: i32) -> i32 {
    div_round_down(dividend + divisor / 2, divisor).0
}
/// Linux `(spur_freq - fc) * 1000000` in u32 assigned to s32.
pub(super) fn freq_diff(spur: u32, fc: u32) -> i32 {
    spur.wrapping_sub(fc).wrapping_mul(1_000_000) as i32
}

/// `rtw8852c_nbi_reg_def[path]`: (notch1, notch2) registers; idx 0xff,
/// frac 0xc00, en 0x1000 in each.
const NBI: [(u32, u32); 2] = [(0x4c14, 0x4c20), (0x4cd8, 0x4ce4)];

/// `rtw8852c_set_nbi_tone_idx(chan, path)`.
fn nbi_tone(profile: Profile, path: usize, out: &mut alloc::vec::Vec<Field>) {
    let (n1, n2) = NBI[path];
    let spur = spur_freq(profile);
    if spur == 0 {
        // Linux clears notch1_en twice (notch2 is left alone).
        out.push((PHY + n1, 0x1000, 0));
        out.push((PHY + n1, 0x1000, 0));
        return;
    }
    let width = profile.width();
    let mut fc = profile.center_mhz();
    let mut notch2 = false;
    if width == Width::Mhz160 {
        fc = if spur > fc { fc + 40 } else { fc - 40 };
        let (center, primary) = (profile.center(), profile.primary());
        notch2 = (fc > spur && center < primary) || (fc < spur && center > primary);
    }
    let (nbi_idx, frac) = div_round_down(freq_diff(spur, fc), 312_500);
    let tone = if width == Width::Mhz20 {
        div_round_down(nbi_idx + 32, 64).1
    } else {
        div_round_down(nbi_idx, if width == Width::Mhz40 { 128 } else { 256 }).1
    };
    let frac_tone = div_round_closest(frac, 78_125);
    let (on, off) = if width == Width::Mhz160 && notch2 {
        (n2, n1)
    } else {
        (n1, n2)
    };
    out.push((PHY + on, 0xff, tone as u32));
    out.push((PHY + on, 0xc00, frac_tone as u32));
    out.push((PHY + on, 0x1000, 0));
    out.push((PHY + on, 0x1000, 1));
    out.push((PHY + off, 0x1000, 0));
}

/// `rtw8852c_spur_elimination(chan, pri_ch_idx, PHY_0)` with `dbcc_en` = 0
/// (`rtw8852c_set_csi_tone_idx`, the 160MHz `rtw8852c_spur_notch` for
/// PHY_0 and PHY_1 or `rtw8852c_set_nbi_tone_idx` A and B, PD boost).
fn spur_elimination(profile: Profile, out: &mut alloc::vec::Vec<Field>) {
    let spur = spur_freq(profile);
    if spur == 0 {
        out.push((PHY + 0x42c4, 1 << 23, 0));
    } else {
        let csi = div_round_closest(freq_diff(spur, profile.center_mhz()), 78_125);
        out.push((PHY + 0x42ac, 0x7ff, div_round_down(csi, 2048).1 as u32));
        out.push((PHY + 0x42c4, 1 << 23, 1));
    }
    let pri = profile.pri_ch_idx();
    // RTW89_SC_20_LOWER = 2, UP3X = 7, UPPER = 1, LOW3X = 8.
    let notch = match (profile.width(), pri) {
        (Width::Mhz160, 2 | 7) => Some(0xe7f),
        (Width::Mhz160, 1 | 8) => Some(0x280),
        _ => None,
    };
    match notch {
        Some(value) => {
            for (notch, notch2) in NBI {
                out.push((PHY + notch, 0x1fff, value));
                out.push((PHY + notch, 0x1000, 1));
                out.push((PHY + notch2, 0x1fff, value));
                out.push((PHY + notch2, 0x1000, 1));
            }
        }
        None => {
            nbi_tone(profile, 0, out);
            nbi_tone(profile, 1, out);
        }
    }
    out.push((PHY + 0x49e8, 1 << 7, u32::from(!matches!(pri, 7 | 8))));
}

/// `rtw8852c_ctrl_btg_bt_rx(en, PHY_0)`.
pub(super) fn btg_bt_rx(en: bool, out: &mut alloc::vec::Vec<Field>) {
    let e = u32::from(en);
    out.push((PHY + 0x4738, 1 << 19, e));
    out.push((PHY + 0x4738, 1 << 22, 0));
    out.push((PHY + 0x476c, 0xff00_0000, if en { 0x20 } else { 0x1a }));
    out.push((PHY + 0x4778, 0xff, if en { 0x30 } else { 0x2a }));
    out.push((PHY + 0x4aa4, 1 << 19, e));
    out.push((PHY + 0x4aa4, 1 << 22, e));
    if en {
        out.push((PHY + 0x0980, 0x001e_0000, 0));
    } else {
        out.push((PHY + 0x0980, 0x001e_0000, 0xf));
        out.push((PHY + 0x0980, 0x3c00_0000, 0x4));
    }
    out.push((PHY + 0x4978, 1 << 14, e));
    out.push((PHY + 0x4974, 0x03c0_0000, if en { 2 } else { 0 }));
    out.push((PHY + 0x441c, 1 << 31, e));
    out.push((PHY + 0x0c6c, 1 << 21, e));
}

/// `rtw8852c_5m_mask(chan, PHY_0)`.
fn mask_5m(profile: Profile, out: &mut alloc::vec::Vec<Field>) {
    let pri = profile.pri_ch_idx();
    // RTW89_SC_20_LOWER = 2, UPMOST = 3, LOWEST = 4.
    let (en, low) = match profile.width() {
        Width::Mhz40 => (true, pri == 2),
        Width::Mhz80 => (pri == 3 || pri == 4, pri == 4),
        _ => (false, false),
    };
    if !en {
        out.push((PHY + 0x4c4c, 1 << 12, 0));
        out.push((PHY + 0x4d10, 1 << 12, 0));
        out.push((PHY + 0x4450, 1 << 24, 0));
        return;
    }
    for reg in [0x4c4c, 0x4d10] {
        out.push((PHY + reg, 0x3f, 0x4));
        out.push((PHY + reg, 1 << 12, 1));
        out.push((PHY + reg, 1 << 8, u32::from(!low)));
        out.push((PHY + reg, 1 << 6, u32::from(low)));
    }
    out.push((PHY + 0x4450, 1 << 24, 1));
}

/// reg.h `R_AX_PATH_COM0..11` with `AX_PATH_COMn_DFVAL`.
const PATH_COM: [(u32, u32); 12] = [
    (0xd800, 0),
    (0xd804, 0),
    (0xd808, 0),
    (0xd80c, 0x4924_9249),
    (0xd810, 0x1c9c_9c49),
    (0xd814, 0x3939_3939),
    (0xd818, 0x3939_3939),
    (0xd81c, 0x3939_3939),
    (0xd820, 0),
    (0xd824, 0x0000_07c0),
    (0xd828, 0xe000_0000),
    (0xd82c, 0),
];

/// `rtw8852c_ctrl_tx_path_tmac(tx_path, MAC_0)`; `tx_path` is RF_A (1),
/// RF_B (2) or RF_AB (3).
pub(super) fn tx_path_tmac_fields(tx_path: u8) -> Option<alloc::vec::Vec<Field>> {
    // AX_PATH_COM{0,1,2,7,8}_PATH{A,B,AB}.
    let sel: [u32; 5] = match tx_path {
        1 => [0x0888_9880, 0x1311_1111, 0x0120_9313, 0x3939_3939, 0x3939],
        2 => [0x1111_1900, 0x2322_2222, 0x0120_9323, 0x3938_3939, 0x3938],
        3 => [0x1999_9980, 0x3333_3333, 0x0120_9333, 0x3939_3939, 0x3939],
        _ => return None,
    };
    let mut out = alloc::vec::Vec::new();
    // R_MAC_SEL B_MAC_SEL_MOD for PHY_0 and PHY_1 (no DBCC offset).
    out.push((PHY + 0x09a4, 0x1c, 0));
    out.push((PHY + 0x09a4, 0x1c, 0));
    for address in (0xdc00..=0xddfc).step_by(4) {
        out.push((address, u32::MAX, 0));
    }
    let mut com = PATH_COM;
    for (slot, value) in [0, 1, 2, 7, 8].into_iter().zip(sel) {
        com[slot].1 = value;
    }
    for (address, value) in com {
        out.push((address, u32::MAX, value));
    }
    Some(out)
}

/// `rtw8852c_set_channel_bb` after `rtw8852c_ctrl_bw` for non-DBCC PHY_0
/// with no user `antenna_tx`, up to (not including) `bb_reset_all`. `cav`
/// is `hal.cv == CHIP_CAV`. MAC fields (0xd848, MACID/path tables) carry
/// absolute MAC addresses.
pub(super) fn tail_fields(profile: Profile, cav: bool) -> alloc::vec::Vec<Field> {
    let mut out = alloc::vec::Vec::new();
    let cck = profile.cck_enabled();
    out.push((PHY + 0x0700, 1 << 5, u32::from(cck)));
    out.push((PHY + 0x2320, 1, u32::from(!cck)));
    out.push((PHY + 0x0c80, 1 << 31, u32::from(!cck)));
    spur_elimination(profile, &mut out);
    btg_bt_rx(profile.band() == Band::Ghz2, &mut out);
    mask_5m(profile, &mut out);
    let width = profile.width();
    if width == Width::Mhz160 && !cav {
        let high = u32::from(profile.primary() > profile.center());
        out.push((PHY + 0x09d8, 1 << 26, 0));
        out.push((PHY + 0x2410, 1 << 13, high));
        out.push((0xd848, 1 << 28, high));
    }
    let cdd = u32::from(!(profile.band() == Band::Ghz6 && width == Width::Mhz160));
    out.push((PHY + 0x46c0, 1, cdd));
    for reg in [0x58dc, 0x78dc] {
        out.push((PHY + reg, 0xc000_0000, 1));
        out.push((PHY + reg, 0xc000_0000, 3));
    }
    out.push((PHY + 0x40f8, 1, u32::from(profile.band() == Band::Ghz6)));
    let tx_path = if profile.band() == Band::Ghz6 { 2 } else { 3 };
    if let Some(tmac) = tx_path_tmac_fields(tx_path) {
        out.extend(tmac);
    }
    out
}

/// `rtw8852c_bb_reset_all(PHY_0)`: (before the 1us hold, after it).
pub(super) const RESET_ALL: ([Field; 2], [Field; 5]) = (
    [
        (PHY + 0x1200, 0x7000_0000, 7),
        (PHY + 0x3200, 0x7000_0000, 7),
    ],
    [
        (PHY + 0x0704, 1 << 1, 1),
        (PHY + 0x0704, 1 << 1, 0),
        (PHY + 0x1200, 0x7000_0000, 0),
        (PHY + 0x3200, 0x7000_0000, 0),
        (PHY + 0x0704, 1 << 1, 1),
    ],
);

/// Program the rest of `rtw8852c_set_channel_bb` after [`program`]
/// ([`tail_fields`]) and `rtw8852c_bb_reset_all`, reading back every
/// final bit.
///
/// # Safety
/// Same as [`program`], immediately after it on the same owner.
pub(super) async unsafe fn program_tail(
    io: &mut impl Io,
    profile: Profile,
    cav: bool,
) -> Result<(), power::Error> {
    let tail = tail_fields(profile, cav);
    for &(address, mask, value) in &tail {
        if mask == u32::MAX {
            // rtw89_write32 (MACID antenna / PATH_COM tables).
            io.write32(address, value)?;
        } else {
            modify(io, address, mask, value)?;
        }
    }
    verify(io, &tail)?;
    for &(address, mask, value) in &RESET_ALL.0 {
        modify(io, address, mask, value)?;
    }
    io.delay_us(1).await;
    for &(address, mask, value) in &RESET_ALL.1 {
        modify(io, address, mask, value)?;
    }
    let mut all = RESET_ALL.0.to_vec();
    all.extend_from_slice(&RESET_ALL.1);
    verify(io, &all)
}

/// Program `rtw8852c_set_channel_mac(MAC_0)` then the C BB channel control
/// prefix of `rtw8852c_set_channel_bb` (`ctrl_sco_cck` + `ctrl_ch`),
/// reading every final field back.
///
/// # Safety
/// Actual RTL8852C MAC_0/PHY_0 (non-DBCC) with completed C tables,
/// `controls_c` and `rfk::c` init, inside the channel-help window, with
/// exclusive radio ownership and a current channel grant for `profile`.
pub(super) unsafe fn program(
    io: &mut impl Io,
    profile: Profile,
    inputs: &Inputs<'_>,
) -> Result<(), power::Error> {
    let mac = mac_fields(profile);
    // write8_mask / write8_clr / write8_set on the low byte only.
    for &(address, mask, value) in &mac {
        if address == 0xc088 {
            io.write32(address, value)?;
        } else {
            let old = io.read8(address)?;
            let mask = mask as u8;
            io.write8(address, (old & !mask) | (value as u8 & mask))?;
        }
    }
    if io.read32(0xc088)? != mac[1].2
        || io.read8(0xc010)? & 3 != mac[0].2 as u8
        || io.read8(0xc628)? & 0x13 != mac[3].2 as u8
    {
        return Err(power::Error::Access);
    }
    apply(io, &ctrl_fields(profile, inputs))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_c/tests.rs"]
mod tests;
