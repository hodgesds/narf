// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! AR9285 2GHz/full-rate/20MHz channel preparation, from Linux
//! ar5008_phy.c, ar9002_phy.c and hw.c. No PHY/packet engine is activated.
use super::rmw;
use crate::ath9k::{
    channel_width::Geometry,
    identity::{BringUpError, RegisterIo},
    EEPROM_4K_BYTES,
};

pub(super) fn write(
    io: &mut impl RegisterIo,
    register: u64,
    value: u32,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(register, value);
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}
pub(super) fn field(
    io: &mut impl RegisterIo,
    register: u64,
    mask: u32,
    shift: u32,
    value: u32,
) -> Result<(), BringUpError> {
    rmw(io, register, mask, (value << shift) & mask)
}
pub(super) fn slope(coefficient: u32) -> (u32, u32) {
    // ath9k_hw_get_delta_slope_vals, COEF_SCALE_S=24. Admitted 2GHz
    // full-rate coefficients keep every shift within the native u32 range.
    let highest = 31 - coefficient.leading_zeros();
    let exponent = 38 - highest;
    let mantissa = coefficient + (1 << (24 - exponent - 1));
    (mantissa >> (24 - exponent), exponent - 16)
}
/// `ar5008_phy.c::ar5008_hw_cmn_spur_mitigate` (shared by the AR5008 and
/// AR9002 spur paths).
pub(super) fn masks(io: &mut impl RegisterIo, bin: i32) -> Result<(), BringUpError> {
    let mut current = -6000;
    for (pilot, channel, increment) in [
        (0x9980, 0x9998, 0),
        (0x9984, 0x999c, 100),
        (0xa3b0, 0x99d4, 0),
        (0xa3b4, 0x99d8, 0),
    ] {
        let mut mask = 0;
        for bit in 0..30 {
            if current > bin - 100 && current < bin + 100 {
                mask |= 1 << bit;
            }
            current += 100;
        }
        current += increment;
        write(io, pilot, mask)?;
        write(io, channel, mask)?;
    }
    let mut minus = [0u32; 123];
    let mut plus = [0u32; 123];
    for current in (-6100i32..=6100).rev().step_by(100) {
        if current > bin - 120 && current < bin + 120 && (current - bin).abs() < 75 {
            if current < 0 {
                minus[(-current / 100) as usize] = 1;
            } else {
                plus[(current / 100) as usize] = 1;
            }
        }
    }
    // Preserve the native odd/repeated indices in Linux's Viterbi-mask
    // packing. They are hardware layout, not a contiguous Rust bitset.
    type MaskGroup<'a> = (&'a [u32; 123], &'a [usize], u32, u64, u64);
    let groups: [MaskGroup<'_>; 8] = [
        (
            &minus,
            &[
                46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
            ],
            30,
            0x9900,
            0xa3a0,
        ),
        (
            &minus,
            &[31, 32, 33, 34, 35, 36, 37, 48, 39, 40, 41, 42, 43, 44, 45],
            28,
            0x9904,
            0xa3a4,
        ),
        (
            &minus,
            &[
                16, 16, 18, 18, 20, 20, 22, 22, 24, 24, 25, 26, 27, 28, 29, 30,
            ],
            30,
            0x9908,
            0xa3a8,
        ),
        (
            &minus,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            30,
            0x990c,
            0xa3ac,
        ),
        (
            &plus,
            &[15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            28,
            0x9988,
            0xa3b8,
        ),
        (
            &plus,
            &[30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16],
            28,
            0x998c,
            0xa3bc,
        ),
        (
            &plus,
            &[45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31],
            28,
            0x9990,
            0xa3c0,
        ),
        (
            &plus,
            &[
                61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46,
            ],
            30,
            0x9994,
            0xa3c4,
        ),
    ];
    for (source, indices, shift, first, second) in groups {
        let mask = indices.iter().enumerate().fold(0, |word, (i, &index)| {
            word | source[index] << (shift - 2 * i as u32)
        });
        write(io, first, mask)?;
        write(io, second, mask)?;
    }
    Ok(())
}
/// `ar9002_hw_spur_mitigate`: `base` is `AR_BASE_FREQ_2GHZ` (2300) or
/// `AR_BASE_FREQ_5GHZ` (4900) and `denominator` the band's 44/40.
fn spur(
    io: &mut impl RegisterIo,
    image: &[u8],
    spur_chans: usize,
    frequency: u16,
    wide: bool,
    base: i32,
    denominator: i32,
) -> Result<(), BringUpError> {
    let mut selected = None;
    // modalHeader.spurChans: 5x4 bytes at the chip map's offset.
    for index in 0..5 {
        let value = crate::ath9k::identity::eeprom_word(image, spur_chans + index * 4);
        if value == 0x8000 {
            break;
        }
        let offset = i32::from(value / 10) + base - i32::from(frequency);
        if offset.abs() < if wide { 20 } else { 10 } {
            selected = Some(offset);
            break;
        }
    }
    rmw(io, 0xa22c, 0x40, 0)?;
    let Some(offset) = selected else {
        return Ok(());
    };
    rmw(io, 0x9920, 0, 0xf0000000)?;
    write(
        io,
        0x994c,
        (0xff << 18) | 0x20000 | (0xff << 9) | 0x100 | 40,
    )?;
    let phase = ((offset * if wide { 262144 } else { 524288 }) / 10) as u32 & 0xfffff;
    let subchannel = u32::from(wide && offset < 0);
    let adjusted = if wide {
        offset + if offset < 0 { 10 } else { -10 }
    } else {
        offset
    };
    let frequency = ((adjusted * 2048) / denominator) as u32 & 0x3ff;
    write(io, 0x99a0, 0x40000000 | (frequency << 20) | phase)?;
    write(io, 0x99c0, subchannel << 28)?;
    masks(io, offset * 320)
}
pub(super) fn prepare(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    frequency: u16,
) -> Result<(), BringUpError> {
    if !(2412..=2472).contains(&frequency) || (frequency - 2412) % 5 != 0 {
        return Err(BringUpError::BadCalibration);
    }
    prepare_geometry(io, image, Geometry::from_frequency(frequency)?)
}
pub(in crate::ath9k) fn prepare_geometry(
    io: &mut impl RegisterIo,
    image: &[u8; EEPROM_4K_BYTES],
    geometry: Geometry,
) -> Result<(), BringUpError> {
    prepare_chip(io, image, geometry, &AR9285)
}

/// Selects the `[register, value]` CCK FIR INI rows for a frequency.
pub(in crate::ath9k) type CckFir = fn(u16) -> &'static [[u32; 2]];

/// The per-chip differences inside the shared AR9002 channel preparation
/// (`ar5008_hw_override_ini`, `ar5008_hw_init_chain_masks`,
/// `ar9002_hw_set_channel`, `ar9002_hw_spur_mitigate`).
pub(in crate::ath9k) struct ChipChannel {
    /// `AR_PCU_MISC_MODE2` bits cleared: always ADHOC_MCAST_KEYID_ENABLE and
    /// HWWAR1, plus HWWAR2 on `AR_SREV_9287_11_OR_LATER`.
    pub misc_mode2_clear: u32,
    /// Verified factory RX / TX chain masks (`ar5008_hw_init_chain_masks`).
    pub rx_chainmask: u8,
    pub tx_chainmask: u8,
    /// `AR_SREV_9287_11_OR_LATER` writes the CCK FIR INI arrays instead of
    /// toggling `AR_PHY_CCK_TX_CTRL_JAPAN`.
    pub cck_fir: Option<CckFir>,
    /// Byte offset of `modalHeader.spurChans` in the chip's map.
    pub spur_chans: usize,
    /// Byte offset of the 5 GHz `modalHeader[0].spurChans` (dual-band
    /// `ar5416_eeprom_def` maps only).
    pub spur_chans_5g: Option<usize>,
}

/// The tuned channel of the shared AR9002 preparation: a 2.4 GHz
/// [`Geometry`] or, for the dual-band AR9280, a 20 MHz 5 GHz channel. AR9280
/// always has `ATH9K_HW_CAP_FASTCLOCK` (`hw.c::ath9k_hw_fill_cap_info`), so
/// every 5 GHz tune is `IS_CHAN_A_FAST_CLOCK`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Tune {
    Two(Geometry),
    /// `frequency` is the 20 MHz center; `frac_n` is the map's
    /// `EEP_FRAC_N_5G` (`frac_n_5g` from minor 22, otherwise 0).
    Five {
        frequency: u16,
        frac_n: bool,
    },
}

impl Tune {
    pub fn center(self) -> u16 {
        match self {
            Self::Two(geometry) => geometry.center(),
            Self::Five { frequency, .. } => frequency,
        }
    }
    pub fn is_wide(self) -> bool {
        match self {
            Self::Two(geometry) => geometry.is_wide(),
            Self::Five { .. } => false,
        }
    }
    pub fn is_5ghz(self) -> bool {
        matches!(self, Self::Five { .. })
    }
}

/// `ar9002_hw_set_channel`'s `AR_PHY_SYNTH_CONTROL` value for a 5 GHz
/// center (`freq >= 4800`), plus whether the fractional path's
/// `AR_AN_SYNTH9_REFDIVA = 1` analog write precedes it. Integer mode
/// (`EEP_FRAC_N_5G == 0` and a 10/20 MHz-aligned full-rate center) uses
/// `refDivA = 24 >> aModeRefSel`; every other center is 5 MHz-spaced
/// fractional mode with `CHANSEL_5G`.
pub(in crate::ath9k) fn synth_5ghz(frequency: u16, frac_n: bool) -> (u32, bool) {
    let freq = u32::from(frequency);
    let reference = if frac_n {
        0
    } else if freq % 20 == 0 {
        3
    } else if freq % 10 == 0 {
        2
    } else {
        0
    };
    if reference == 0 {
        // fracMode = 1, aModeRefSel = 0, CHANSEL_5G = freq * 0x8000 / 15.
        return ((1 << 28) | (freq * 0x8000 / 15), true);
    }
    let ndiv = (freq * (24 >> reference)) / 60;
    let select = ((ndiv & 0x1ff) << 17) | ((ndiv & 0xffff_fe00) * 2);
    ((reference << 26) | select, false)
}

/// AR9285: one chain; `offsetof(ar5416_eeprom_4k, modalHeader.spurChans)`.
const AR9285: ChipChannel = ChipChannel {
    misc_mode2_clear: 0x40 | 0x100000,
    rx_chainmask: 1,
    tx_chainmask: 1,
    cck_fir: None,
    spur_chans: 100,
    spur_chans_5g: None,
};

pub(in crate::ath9k) fn prepare_chip(
    io: &mut impl RegisterIo,
    image: &[u8],
    geometry: Geometry,
    chip: &ChipChannel,
) -> Result<(), BringUpError> {
    prepare_tune(io, image, Tune::Two(geometry), chip)
}

/// The shared AR9002 channel preparation for either band. 2.4 GHz tunes are
/// byte-identical to the historical [`prepare_chip`] trace.
pub(in crate::ath9k) fn prepare_tune(
    io: &mut impl RegisterIo,
    image: &[u8],
    tune: Tune,
    chip: &ChipChannel,
) -> Result<(), BringUpError> {
    let frequency = tune.center();
    let spur_chans = match tune {
        Tune::Two(_) => chip.spur_chans,
        Tune::Five { .. } => chip.spur_chans_5g.ok_or(BringUpError::Policy)?,
    };
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    // Linux override_ini: keep receive aborted, disable unused multicast
    // key-ID matching and the chip's HWWAR bits, and ignore CFP restrictions.
    rmw(io, 0x8048, 0, 0x02000020)?;
    rmw(io, 0x8344, chip.misc_mode2_clear, 0x80)?;
    let turbo = io.read32(0x9804);
    if turbo == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    // 5 GHz is 20 MHz only: AR_PHY_FC_HT_EN|SHORT_GI_40|SINGLE_HT_LTF1|WALSH.
    let phymode = match tune {
        Tune::Two(geometry) => geometry.turbo(),
        Tune::Five { .. } => 0x3c0,
    };
    write(io, 0x9804, phymode | (turbo & 0x800))?;
    write(io, 0x8318, u32::from(tune.is_wide()))?;
    write(io, 0x64, 25 << 16)?;
    write(io, 0x6c, 15 << 16)?;
    // ar5008_hw_init_chain_masks: RX/CAL chain masks then SELFGEN_MASK; the
    // AR_PHY_SWAP_ALT_CHAIN mask 0x5 cannot pass the two-chain identity.
    write(io, 0x99a4, u32::from(chip.rx_chainmask))?;
    write(io, 0xa39c, u32::from(chip.rx_chainmask))?;
    write(io, 0x832c, u32::from(chip.tx_chainmask))?;
    // ar5008_hw_set_rfmode: 2 GHz DYNAMIC; 5 GHz fast clock OFDM with
    // DYNAMIC | DYN_CCK_DISABLE.
    write(io, 0xa200, if tune.is_5ghz() { 0x104 } else { 4 })?;
    let synth_value = match tune {
        Tune::Two(_) => {
            match chip.cck_fir {
                None => rmw(io, 0xa204, 0x10, 0)?,
                Some(select) => {
                    for row in select(frequency) {
                        write(io, u64::from(row[0]), row[1])?;
                    }
                }
            }
            let synth = io.read32(0x9874);
            if synth == u32::MAX {
                return Err(BringUpError::DeviceGone);
            }
            (synth & 0xc0000000) | 0x30000000 | (u32::from(frequency) * 0x10000 / 15)
        }
        Tune::Five { frac_n, .. } => {
            // Linux reads AR_PHY_SYNTH_CONTROL before the REFDIVA write.
            let synth = io.read32(0x9874);
            if synth == u32::MAX {
                return Err(BringUpError::DeviceGone);
            }
            let (value, refdiva) = synth_5ghz(frequency, frac_n);
            if refdiva {
                // ath9k_hw_analog_shift_rmw(AR_AN_SYNTH9, REFDIVA, 1).
                rmw(io, 0x7868, 0xf800_0000, 1 << 27)?;
                io.delay_us(100);
            }
            (synth & 0xc0000000) | value
        }
    };
    write(io, 0x9874, synth_value)?;
    let coefficient = 0x64000000 / u32::from(frequency);
    let (mantissa, exponent) = slope(coefficient);
    field(io, 0x9814, 0xfffe0000, 17, mantissa)?;
    field(io, 0x9814, 0x1e000, 13, exponent)?;
    let (mantissa, exponent) = slope(9 * coefficient / 10);
    field(io, 0x99d0, 0x7fff0, 4, mantissa)?;
    field(io, 0x99d0, 15, 0, exponent)?;
    let (base, denominator) = if tune.is_5ghz() {
        (4900, 40)
    } else {
        (2300, 44)
    };
    spur(
        io,
        image,
        spur_chans,
        frequency,
        tune.is_wide(),
        base,
        denominator,
    )?;
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
