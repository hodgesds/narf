// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C MAC_0/PHY_0 (non-DBCC) channel MAC and BB channel-control
//! programming from an [`operating_channel_c::Profile`]: rtw8852c.c
//! `rtw8852c_set_channel_mac`, `rtw8852c_ctrl_sco_cck` and
//! `rtw8852c_ctrl_ch` (`rtw8852c_set_gain_error`,
//! `rtw8852c_set_gain_offset`, band select, SCO FC0, CCK pulse coefficients,
//! `B_CH_IDX_SEG0`) and `rtw8852c_ctrl_bw`, each read back. No native
//! caller and no admission.
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
type Field = (u32, u32, u32);

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

fn modify(io: &mut impl Io, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
    let old = io.read32(address)?;
    if old == u32::MAX {
        return Err(power::Error::Gone);
    }
    io.write32(
        address,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}
fn apply(io: &mut impl Io, fields: &[Field]) -> Result<(), power::Error> {
    for &(address, mask, value) in fields {
        modify(io, address, mask, value)?;
    }
    // Read back the final state of every field (later writes to the same
    // field win, as on hardware).
    for (i, &(address, mask, _)) in fields.iter().enumerate() {
        if fields[i + 1..]
            .iter()
            .any(|f| f.0 == address && f.1 == mask)
        {
            continue;
        }
        let expected = fields[..=i]
            .iter()
            .rev()
            .find(|f| f.0 == address && f.1 == mask)
            .map_or(0, |f| (f.2 << mask.trailing_zeros()) & mask);
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
    let (set, prich, delay, select) = match width {
        Width::Mhz20 => (0, 0, 3, 0xf),
        Width::Mhz40 => (1, profile.pri_ch_idx(), 3, 0xf),
        Width::Mhz80 => (2, profile.pri_ch_idx(), 2, 0xd),
        Width::Mhz160 => (3, profile.pri_ch_idx(), 1, 0xb),
    };
    out.push((PHY + 0x4974, 0xc000_0000, set));
    out.push((PHY + 0x4978, 0x3000, 0));
    out.push((PHY + 0x4978, 0xf00, u32::from(prich)));
    out.push((PHY + 0xc0d4, 0x0c00_0000, delay));
    out.push((PHY + 0xc1d4, 0x0c00_0000, delay));
    out.push((PHY + 0xc0d8, 0x1e0, select));
    out.push((PHY + 0xc1d8, 0x1e0, select));
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
