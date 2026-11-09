use super::super::eeprom::{field as map, modal, Identity};
use super::super::templates::{AR9300_DEFAULT, AR9300_H112, AR9300_H116, AR9300_X112, AR9300_X113};
use super::super::{Chip, Revision};
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Register map with an operation log.
#[derive(Default)]
struct Regs {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
}

impl RegisterIo for Regs {
    fn read32(&mut self, offset: u64) -> u32 {
        self.regs.get(&offset).copied().unwrap_or(0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.writes.push((offset, value));
        self.regs.insert(offset, value);
    }
}

fn fnv(hash: &mut u64, bytes: &[u8]) {
    for &byte in bytes {
        *hash ^= u64::from(byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// The oracle's synthetic per-pier calibration rows.
fn synthetic(image: &mut Image) {
    for a in 0..3usize {
        for p in 0..3usize {
            let at = map::CAL_2G + (a * 3 + p) * 6;
            image[at] = (-3 + a as i32 + 2 * p as i32) as i8 as u8;
            image[at + 1] = 50 + p as u8;
            image[at + 2] = 100 + 10 * p as u8;
            image[at + 3] = (-100 - p as i32) as i8 as u8;
            image[at + 4] = (-90 + a as i32) as i8 as u8;
            image[at + 5] = u8::from(p != 1);
        }
        for p in 0..8usize {
            let at = map::CAL_5G + (a * 8 + p) * 6;
            image[at] = (4 - a as i32 - p as i32) as i8 as u8;
            image[at + 1] = 60 + 2 * p as u8;
            image[at + 2] = 120 - p as u8;
            image[at + 3] = (-110 + p as i32) as i8 as u8;
            image[at + 4] = (-95i32) as i8 as u8;
            image[at + 5] = 1;
        }
    }
}

/// Digest of `targets` + calibration for every template × channel × CTL
/// case in the order of the Linux-function oracle (`ar9003_eeprom.c`
/// target, per-rate CTL and `calibration_apply` code compiled verbatim
/// over the five templates; FCC|11G/11A at 34 and SD_NO_CTL at 60).
fn power_digest(syn: bool) -> Result<u64, BringUpError> {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for template in [
        AR9300_DEFAULT,
        AR9300_X112,
        AR9300_H116,
        AR9300_H112,
        AR9300_X113,
    ] {
        let mut image = template;
        if syn {
            synthetic(&mut image);
        }
        let tx = image[map::TXRX_MASK] >> 4;
        for frequency in [2412, 2437, 2472, 2484, 5180, 5320, 5500, 5745, 5785, 5825] {
            for k in 0..2 {
                let two = frequency < 4000;
                let (ctl, limit) = if k == 1 {
                    (0xe0, 60)
                } else {
                    (0x10 | if two { 2 } else { 0 }, 34)
                };
                let plan = power::plan(&image, frequency, ctl, limit, tx)?;
                fnv(&mut hash, &plan.targets);
                for set in [
                    plan.correction,
                    plan.temperature,
                    plan.voltage,
                    plan.nf_cal,
                    plan.nf_power,
                ] {
                    for value in set {
                        fnv(&mut hash, &value.to_le_bytes());
                    }
                }
            }
        }
    }
    Ok(hash)
}

fn smoke_ath9k_ar9300_txpower_matches_linux_oracle() -> TestResult {
    if power_digest(false) != Ok(0xdf75_75b0_efd7_2031) {
        return TestResult::Fail("plain-template power digest differs from the Linux oracle");
    }
    if power_digest(true) != Ok(0xe886_ec05_2a80_e291) {
        return TestResult::Fail(
            "synthetic-calibration power digest differs from the Linux oracle",
        );
    }
    // One oracle row in clear: h116 5500 MHz, FCC|11A at 34, two chains.
    let Ok(plan) = power::plan(&AR9300_H116, 5500, 0x10, 34, 3) else {
        return TestResult::Fail("h116 5500 MHz plan was refused");
    };
    let mut expected = [0u8; power::RATES];
    expected[..4].copy_from_slice(&[28, 28, 28, 24]);
    expected[8..18].copy_from_slice(&[28, 28, 28, 24, 20, 16, 28, 24, 20, 16]);
    if plan.targets != expected || plan.max_power_level != 28 {
        return TestResult::Fail("h116 5500 MHz targets differ from the oracle row");
    }
    // Ceiling and mask policy.
    if power::plan(&AR9300_DEFAULT, 2412, 0x12, 64, 7) != Err(BringUpError::BadCalibration)
        || power::plan(&AR9300_DEFAULT, 2412, 0x12, 34, 0) != Err(BringUpError::BadCalibration)
    {
        return TestResult::Fail("ceiling or empty-mask plan was not refused");
    }
    // A transmit chain without any pier within 1000 MHz is refused.
    let mut image = AR9300_DEFAULT;
    for i in 0..3 {
        image[map::PIERS_2G + i] = 0xff;
    }
    if power::plan(&image, 2412, 0x12, 34, 7) != Err(BringUpError::BadCalibration) {
        return TestResult::Fail("chain without a calibration pier was not refused");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_txpower_matches_linux_oracle
);

fn identity(image: &Image) -> Identity {
    Identity {
        mac: [0, 3, 0x7f, 1, 2, 3],
        eeprom_version: image[0],
        template_version: image[1],
        regulatory_domains: [0, 0],
        op_flags: image[map::OP_FLAGS],
        rx_chainmask: image[map::TXRX_MASK] & 0xf,
        tx_chainmask: image[map::TXRX_MASK] >> 4,
        tx_gain: image[map::TXRX_GAIN] >> 4,
        rx_gain: image[map::TXRX_GAIN] & 0xf,
    }
}

fn last(io: &Regs, register: u64) -> Option<u32> {
    io.writes
        .iter()
        .rev()
        .find(|(r, _)| *r == register)
        .map(|&(_, v)| v)
}

fn smoke_ath9k_ar9300_prepare_channel_registers() -> TestResult {
    let revision = Revision {
        chip: Chip::Ar9300,
        mac_rev: 3,
        pcie: true,
    };
    let image = AR9300_DEFAULT;
    let id = identity(&image);
    for (frequency, mantissa, exponent, sgi, mode, synth) in [
        (2412u16, 21737u32, 3u32, 19563u32, 0x4u32, 10_538_188u32),
        (5180, 20243, 4, 18218, 0x104, 5_657_941),
    ] {
        let mut io = Regs::default();
        let Ok(prepared) = prepare(
            &mut io,
            &revision,
            &id,
            super::super::serdes::PllPwrsave::resolve(Chip::Ar9300, 0, 0),
            &image,
            frequency,
            0xe0,
            40,
        ) else {
            return TestResult::Fail("20 MHz channel preparation was refused");
        };
        let five = frequency > 4000;
        let timing3 = io.regs[&AR_PHY_TIMING3];
        let sgi_delta = io.regs[&AR_PHY_SGI_DELTA];
        let m = super::super::eeprom::modal_base(five);
        let bias = u32::from(image[m + modal::XPA_BIAS_LVL]);
        let ant = u32::from_le_bytes(image[m..m + 4].try_into().unwrap());
        let selfgen = if image[map::MISC_CONFIGURATION] & 8 != 0 && id.tx_chainmask == 7 {
            3
        } else {
            u32::from(id.tx_chainmask)
        };
        if io.writes.first() != Some(&(AR_IER, 0))
            || last(&io, AR_RTC_PLL_CONTROL) != Some(0x142c)
            || (timing3 >> 17, (timing3 >> 13) & 0xf) != (mantissa, exponent)
            || ((sgi_delta >> 4) & 0x7fff, sgi_delta & 0xf) != (sgi, exponent)
            || last(&io, AR_PHY_MODE) != Some(mode)
            || last(&io, AR_PHY_RX_CHAINMASK) != Some(u32::from(id.rx_chainmask))
            || last(&io, AR_PHY_CAL_CHAINMASK) != Some(u32::from(id.rx_chainmask))
            || last(&io, AR_SELFGEN_MASK) != Some(selfgen)
            || last(&io, AR_PHY_SYNTH_CONTROL) != Some(if five { 0 } else { 1 << 29 })
            || last(&io, AR_PHY_65NM_CH0_SYNTH7) != Some((synth << 2) | (1 << 30) | (1 << 31))
            || io.regs[&AR_PHY_65NM_CH0_SYNTH4] & 2 == 0
            || io.regs[&0x16288] & 0x300 != (bias & 3) << 8
            || io.regs[&0x16290] & 0x7 != ((bias >> 2) & 3) | 4
            || io.regs[&0xa288] & 0xffff != ant & 0xffff
            || io.regs[&AR_PHY_GEN_CTRL] & 0x6c0 != 0x2c0
            || last(&io, AR_GTXTO) != Some(25 << 16)
            || last(&io, AR_CST) != Some(15 << 16)
            || last(&io, AR_PHY_ACTIVE) != Some(0)
            || last(&io, AR_CR) != Some(AR_CR_RXD)
            || last(&io, 0xa3f0) != Some(0)
            || last(&io, 0xa458) != Some(0)
            || prepared.selfgen_mask as u32 != selfgen
            || prepared.modes_index != if five { 1 } else { 4 }
        {
            return TestResult::Fail("prepared channel registers differ from ar9003_phy.c");
        }
        // The fast-clock table is only written on 5 GHz.
        let fast = tables_fast_clock_first();
        if io.writes.iter().any(|&(r, v)| r == fast.0 && v == fast.1) != five {
            return TestResult::Fail("fast-clock table selection is wrong for the band");
        }
        // Doubler fix: SYNTHON|SYNTHOVR end set on all three chains.
        if RXTX2.iter().any(|r| io.regs[r] & 0xc != 0xc) {
            return TestResult::Fail("doubler fix left SYNTHON/SYNTHOVR clear");
        }
    }
    // Japan 2484 writes the CCK FIR rows; band and channel refusals.
    let mut io = Regs::default();
    if prepare(
        &mut io,
        &revision,
        &id,
        super::super::serdes::PllPwrsave::resolve(Chip::Ar9300, 0, 0),
        &image,
        2484,
        0xe0,
        40,
    )
    .is_err()
    {
        return TestResult::Fail("2484 MHz preparation was refused");
    }
    let japan = super::super::initvals::AR9300_2P2_BASEBAND_CORE_TXFIR_COEFF_JAPAN_2484;
    if japan
        .iter()
        .any(|row| !io.writes.contains(&(u64::from(row[0]), row[1])))
    {
        return TestResult::Fail("Japan 2484 CCK FIR rows were not written");
    }
    let mut no_5g = id;
    no_5g.op_flags = 0x2;
    for (identity, frequency) in [(id, 5170u16), (id, 2413), (no_5g, 5180)] {
        let mut io = Regs::default();
        if prepare(
            &mut io,
            &revision,
            &identity,
            super::super::serdes::PllPwrsave::resolve(Chip::Ar9300, 0, 0),
            &image,
            frequency,
            0xe0,
            40,
        ) != Err(BringUpError::Policy)
            || !io.writes.is_empty()
        {
            return TestResult::Fail("unsupported channel or band was prepared or wrote registers");
        }
    }
    TestResult::Pass
}

/// The first 5 GHz HT20 row of `ar9300_modes_fast_clock_2p2`.
fn tables_fast_clock_first() -> (u64, u32) {
    let row = super::super::initvals::AR9300_MODES_FAST_CLOCK_2P2[0];
    (u64::from(row[0]), row[1])
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_prepare_channel_registers
);

fn smoke_ath9k_ar9300_board_values_follow_eeprom_flags() -> TestResult {
    let mut image = AR9300_DEFAULT;
    // Internal regulator on, drive strength, quick drop, xLNA bias.
    image[map::FEATURE_ENABLE] |= 0x10 | 0x40;
    image[map::MISC_CONFIGURATION] =
        (image[map::MISC_CONFIGURATION] & !0x6) | 0x1 | 0x10 | 0x40 | (2 << 1);
    image[map::SWREG..map::SWREG + 4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    image[map::TUNING_CAPS] = 0xab;
    image[map::MODAL_2G + modal::QUICK_DROP] = (-3i8) as u8;
    image[map::MODAL_2G + modal::XLNA_BIAS_STRENGTH] = 0b10_01_11;
    let mut io = Regs::default();
    io.regs.insert(0x700c, 0x5);
    if board::set_board_values(&mut io, Chip::Ar9300, &image, 2437, 7, 7).is_err() {
        return TestResult::Fail("board values with regulator on were refused");
    }
    let reg1 = io.writes.iter().position(|&w| w == (0x700c, 0x4));
    let reg0 = io.writes.iter().position(|&w| w == (0x7008, 0x1234_5678));
    let reg2 = io.writes.iter().position(|&w| w == (0x700c, 0x5));
    if !(matches!((reg1, reg0, reg2), (Some(a), Some(b), Some(c)) if a < b && b < c))
        || io.regs.contains_key(&0x7048)
        || io.regs[&0x160c0] != 0x00b6_db40
        || io.regs[&0x9e14] & 0x03c0_0000 != ((-3i32 as u32) << 22) & 0x03c0_0000
        || io.regs[&0x16294] & 0x7ffe_0000 != (0x2b << 24) | (0x2b << 17)
        || io.regs[&0x1610c] >> 30 != 0b11
        || io.regs[&0x1650c] >> 30 != 0b01
        || io.regs[&0x1690c] >> 30 != 0b10
        // Thermometer 1 (misc bits 1..2 = 2): override on everywhere,
        // THERM_ON only on chain 1.
        || io.regs[&0x1610c] & 0x3000_0000 != 0x2000_0000
        || io.regs[&0x1650c] & 0x3000_0000 != 0x3000_0000
        || io.regs[&0x1690c] & 0x3000_0000 != 0x2000_0000
    {
        return TestResult::Fail("board values differ from ath9k_hw_ar9300_set_board_values");
    }
    // Regulator off forces the SWREG period; 5 GHz xatten interpolates.
    let mut image = AR9300_DEFAULT;
    image[map::FEATURE_ENABLE] &= !0x10;
    image[map::EXT2 + map::EXT2_XATTEN1_DB_LOW] = 10;
    image[map::MODAL_5G + modal::XATTEN1_DB] = 20;
    image[map::EXT2 + map::EXT2_XATTEN1_DB_HIGH] = 30;
    let mut io = Regs::default();
    if board::set_board_values(&mut io, Chip::Ar9300, &image, 5340, 1, 1).is_err() {
        return TestResult::Fail("5 GHz board values were refused");
    }
    // interpolate(5340, 5180, 5500, 10, 20) = 10 + 5 = 15.
    if io.regs.get(&0x7048) != Some(&4)
        || io.regs[&0x9e18] & 0x3f != 15
        || io.regs.contains_key(&0xae18)
        || io.regs.contains_key(&0xb284)
    {
        return TestResult::Fail("5 GHz xatten or regulator-off values differ");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_board_values_follow_eeprom_flags
);

/// A 2 GHz board image with every board-value field set to a
/// distinguishing value: xPA timing + regulator on + tuning caps,
/// drive strength + quick drop + xLNA + thermometer 1, swreg
/// `0x12345678`, tuning caps `0xab`, bias 3, switch tables
/// `0x00abcdef` / `0x00123456`, chain tables `0x0123` / `0x0abc` /
/// `0x0456`, SPDT `0x0f0f`, xPA on/off `0x5a` / `0xa5`, quick drop -3,
/// xLNA `0b10_01_11`, noise-floor thresholds -10/-20/-30, minCCApwr 2G
/// enabled, xatten 10/11/12 dB with margins 5/6/7.
fn board_image() -> Image {
    let mut image = AR9300_DEFAULT;
    image[map::FEATURE_ENABLE] = 0x80 | 0x10 | 0x40;
    image[map::MISC_CONFIGURATION] = 0x1 | 0x10 | 0x40 | (2 << 1);
    image[map::SWREG..map::SWREG + 4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    image[map::TUNING_CAPS] = 0xab;
    image[map::EXT1 + map::EXT1_MISC_ENABLE] = 4;
    let m = map::MODAL_2G;
    image[m + modal::XPA_BIAS_LVL] = 3;
    image[m + modal::ANT_CTRL_COMMON..m + modal::ANT_CTRL_COMMON + 4]
        .copy_from_slice(&0x00ab_cdefu32.to_le_bytes());
    image[m + modal::ANT_CTRL_COMMON2..m + modal::ANT_CTRL_COMMON2 + 4]
        .copy_from_slice(&0x0012_3456u32.to_le_bytes());
    for (chain, table) in [0x0123u16, 0x0abc, 0x0456].into_iter().enumerate() {
        image[m + modal::ANT_CTRL_CHAIN + 2 * chain..m + modal::ANT_CTRL_CHAIN + 2 * chain + 2]
            .copy_from_slice(&table.to_le_bytes());
        image[m + modal::XATTEN1_DB + chain] = 10 + chain as u8;
        image[m + modal::XATTEN1_MARGIN + chain] = 5 + chain as u8;
        image[m + modal::NOISE_FLOOR_THRESH + chain] = (-10 - 10 * chain as i32) as i8 as u8;
    }
    image[m + modal::SWITCH_COM_SPDT..m + modal::SWITCH_COM_SPDT + 2]
        .copy_from_slice(&0x0f0fu16.to_le_bytes());
    image[m + modal::TX_FRAME_TO_XPA_ON] = 0x5a;
    image[m + modal::TX_END_TO_XPA_OFF] = 0xa5;
    image[m + modal::QUICK_DROP] = (-3i8) as u8;
    image[m + modal::XLNA_BIAS_STRENGTH] = 0b10_01_11;
    image
}

fn smoke_ath9k_ar9462_ar9485_ar9565_board_values_follow_eeprom() -> TestResult {
    // AR9462, 2 GHz, rx == 0x2: TOP (not TOP2), 24-bit switch table,
    // SPDT + GLB_CONTROL bit 0, chain-1 table and attenuation into the
    // chain-0 registers, thermo cal from OTP word 1, swreg into PMU1,
    // tuning caps at the 9462 XTAL, thermometer on chains 0-1 only, and
    // no xPA-timing / quick-drop / xLNA writes.
    let mut image = board_image();
    let mut io = Regs::default();
    io.regs.insert(0x15f18, 0x4);
    io.regs.insert(0x15f1c, 0x3412);
    if board::set_board_values(&mut io, Chip::Ar9462, &image, 2437, 2, 2).is_err() {
        return TestResult::Fail("AR9462 board values were refused");
    }
    if io.regs.get(&0x1628c).copied().unwrap_or(0) & 0x300 != 0x300
        || io.regs.contains_key(&0x16288)
        || io.regs.contains_key(&0x16290)
        || io.regs.get(&0xa288).copied().unwrap_or(0) != 0xabcdef
        || io.regs.get(&0x20044).copied().unwrap_or(0) != 0xf0f1
        || io.regs.get(&0xa284).copied().unwrap_or(0) & 0xfff != 0xabc
        || io.regs.get(&0xb284).copied().unwrap_or(0) & 0xfff != 0xabc
        || io.regs.contains_key(&0xc284)
        || io.regs.get(&0x9e18).copied().unwrap_or(0) != 0x600b
        || io.regs.get(&0xae18).copied().unwrap_or(0) != 0x600b
        || io.regs.contains_key(&0xbe18)
        || io.regs.get(&0xa450).copied().unwrap_or(0) != 0x13412
        || io.regs.get(&0x16340).copied().unwrap_or(0) != 0x1234_5678
        || io.regs.contains_key(&0x7008)
        || io.regs.get(&0x16298).copied().unwrap_or(0) & 0x7ffe_0000 != 0x2b56_0000
        || io.regs.get(&0x1610c).copied().unwrap_or(0) & 0x3000_0000 != 0x2000_0000
        || io.regs.get(&0x1650c).copied().unwrap_or(0) & 0x3000_0000 != 0x3000_0000
        || io.regs.contains_key(&0x1690c)
        || io.regs.get(&0xa264).copied().unwrap_or(0) != 0xa5a5_0000
        || io.regs.get(&0x9e14).copied().unwrap_or(0) & 0x03c0_0000 != 0
        || io.regs.get(&0x1610c).copied().unwrap_or(0) >> 30 != 0
        || io.regs.get(&0x160c0).copied().unwrap_or(0) != 0x00b6_db40
        || io.regs.contains_key(&0x9e20)
        || io.regs.get(&0xae20).copied().unwrap_or(0) != 0x1ec
        || io.regs.contains_key(&0xbe20)
    {
        return TestResult::Fail("AR9462 board values differ from ar9003_eeprom.c");
    }
    // Thermo cal with ko == kg == 0, and with the OTP read failing, both
    // write nothing to AR_PHY_BB_THERM_ADC_3.
    let mut io = Regs::default();
    io.regs.insert(0x15f18, 0x4);
    io.regs.insert(0x15f1c, 0);
    if board::set_board_values(&mut io, Chip::Ar9462, &image, 2437, 2, 2).is_err()
        || io.regs.contains_key(&0xa450)
    {
        return TestResult::Fail("AR9462 zero thermo cal wrote or was refused");
    }
    let mut io = Regs::default();
    if board::set_board_values(&mut io, Chip::Ar9462, &image, 2437, 2, 2).is_err()
        || io.regs.contains_key(&0xa450)
    {
        return TestResult::Fail("AR9462 failed OTP read wrote thermo cal or was refused");
    }
    // AR9462, 5 GHz, rx == 0x2: chain-1 attenuation interpolates into
    // both EXT_ATTEN_CTL_0 and EXT_ATTEN_CTL_1.
    image[map::EXT2 + map::EXT2_XATTEN1_DB_LOW + 1] = 10;
    image[map::MODAL_5G + modal::XATTEN1_DB + 1] = 20;
    image[map::EXT2 + map::EXT2_XATTEN1_DB_HIGH + 1] = 30;
    image[map::EXT2 + map::EXT2_XATTEN1_MARGIN_LOW + 1] = 4;
    image[map::MODAL_5G + modal::XATTEN1_MARGIN + 1] = 8;
    image[map::EXT2 + map::EXT2_XATTEN1_MARGIN_HIGH + 1] = 12;
    image[map::EXT1 + map::EXT1_MISC_ENABLE] = 8;
    image[map::MODAL_5G + modal::NOISE_FLOOR_THRESH + 1] = (-20i8) as u8;
    let mut io = Regs::default();
    io.regs.insert(0x15f18, 0x4);
    io.regs.insert(0x15f1c, 0x3412);
    if board::set_board_values(&mut io, Chip::Ar9462, &image, 5340, 2, 2).is_err()
        || io.regs.get(&0x9e18).copied().unwrap_or(0) != 0x600f
        || io.regs.get(&0xae18).copied().unwrap_or(0) != 0x600f
        || io.regs.contains_key(&0xbe18)
        || io.regs.get(&0xae20).copied().unwrap_or(0) != 0x1ec
    {
        return TestResult::Fail("AR9462 5 GHz board values differ from ar9003_eeprom.c");
    }
    // AR9485, regulator on, ant_div_control 0xc9 (LNA combining):
    // TOP2 bias, 16-bit switch table, antenna-diversity fields, the
    // fixed PMU set, tuning caps at the 9485 XTAL, thermometer on chain
    // 0 only, and no SPDT / thermo-cal / xPA-timing / quick-drop / xLNA
    // writes.
    let mut image = board_image();
    image[map::EXT1 + map::EXT1_ANT_DIV_CONTROL] = 0xc9;
    let mut io = Regs::default();
    if board::set_board_values(&mut io, Chip::Ar9485, &image, 2437, 1, 1).is_err() {
        return TestResult::Fail("AR9485 board values were refused");
    }
    if io.regs.get(&0x16284).copied().unwrap_or(0) & 0xf000 != 0x3000
        || io.regs.contains_key(&0x16288)
        || io.regs.contains_key(&0x1628c)
        || io.regs.get(&0xa288).copied().unwrap_or(0) != 0xcdef
        || io.regs.get(&0xa28c).copied().unwrap_or(0) != 0x123456
        || io.regs.contains_key(&0x20044)
        || io.regs.get(&0x9e28).copied().unwrap_or(0) != 0x1300_0000
        || io.regs.get(&0x9fc0).copied().unwrap_or(0) != 0x2000
        || io.regs.get(&0x16c40).copied().unwrap_or(0) != 0x131c_827a
        || io.regs.get(&0x16c44).copied().unwrap_or(0) != 0x1020_0000
        || io.regs.get(&0x16290).copied().unwrap_or(0) & 0x7ffe_0000 != 0x2b56_0000
        || io.regs.get(&0x1610c).copied().unwrap_or(0) & 0x3000_0000 != 0x2000_0000
        || io.regs.contains_key(&0x1650c)
        || io.regs.contains_key(&0x1690c)
        || io.regs.contains_key(&0xa450)
        || io.regs.get(&0xa264).copied().unwrap_or(0) != 0xa5a5_0000
        || io.regs.get(&0x9e14).copied().unwrap_or(0) & 0x03c0_0000 != 0
        || io.regs.get(&0x1610c).copied().unwrap_or(0) >> 30 != 0
        || io.regs.get(&0x9e20).copied().unwrap_or(0) != 0x1f6
        || io.regs.get(&0x9e18).copied().unwrap_or(0) != 0x500a
        || io.regs.get(&0xa284).copied().unwrap_or(0) & 0xfff != 0x123
        || io.regs.contains_key(&0xb284)
    {
        return TestResult::Fail("AR9485 board values differ from ar9003_eeprom.c");
    }
    // AR9485, regulator off: the PMU PGM/PWD sequence, no RTC write.
    image[map::FEATURE_ENABLE] &= !0x10;
    let mut io = Regs::default();
    if board::set_board_values(&mut io, Chip::Ar9485, &image, 2437, 1, 1).is_err()
        || io.regs.get(&0x16c40).copied().unwrap_or(0) != 0x1
        || io.regs.get(&0x16c44).copied().unwrap_or(0) != 0x200000
        || io.regs.contains_key(&0x7048)
    {
        return TestResult::Fail("AR9485 regulator-off values differ from ar9003_eeprom.c");
    }
    // AR9485, ant_div_control 0x41 (no LNA combining): only the base
    // diversity fields, fast-div clear.
    image[map::FEATURE_ENABLE] |= 0x10;
    image[map::EXT1 + map::EXT1_ANT_DIV_CONTROL] = 0x41;
    let mut io = Regs::default();
    if board::set_board_values(&mut io, Chip::Ar9485, &image, 2437, 1, 1).is_err()
        || io.regs.get(&0x9e28).copied().unwrap_or(0) != 0x0300_0000
        || io.regs.get(&0x9fc0).copied().unwrap_or(0) != 0
    {
        return TestResult::Fail("AR9485 non-combining diversity values differ");
    }
    // AR9565: TOP (not TOP2), 24-bit switch table, SPDT, the DEFAULT
    // ant_div_control 0xc9 (the EEPROM byte is 0x00 here and must be
    // ignored), swreg into PMU1, thermometer on chain 0 only.
    let mut image = board_image();
    image[map::EXT1 + map::EXT1_ANT_DIV_CONTROL] = 0x00;
    let mut io = Regs::default();
    if board::set_board_values(&mut io, Chip::Ar9565, &image, 2437, 1, 1).is_err() {
        return TestResult::Fail("AR9565 board values were refused");
    }
    if io.regs.get(&0x1628c).copied().unwrap_or(0) & 0x300 != 0x300
        || io.regs.get(&0xa288).copied().unwrap_or(0) != 0xabcdef
        || io.regs.get(&0x20044).copied().unwrap_or(0) != 0xf0f1
        || io.regs.get(&0x9e28).copied().unwrap_or(0) != 0x1300_0000
        || io.regs.get(&0x9fc0).copied().unwrap_or(0) != 0x2000
        || io.regs.get(&0x16340).copied().unwrap_or(0) != 0x1234_5678
        || io.regs.get(&0x16298).copied().unwrap_or(0) & 0x7ffe_0000 != 0x2b56_0000
        || io.regs.get(&0x1610c).copied().unwrap_or(0) & 0x3000_0000 != 0x2000_0000
        || io.regs.contains_key(&0x1650c)
        || io.regs.contains_key(&0xa450)
    {
        return TestResult::Fail("AR9565 board values differ from ar9003_eeprom.c");
    }
    // AR9565, regulator off: PMU1 PWD only, no RTC write.
    image[map::FEATURE_ENABLE] &= !0x10;
    let mut io = Regs::default();
    if board::set_board_values(&mut io, Chip::Ar9565, &image, 2437, 1, 1).is_err()
        || io.regs.get(&0x16340).copied().unwrap_or(0) != 0x1
        || io.regs.contains_key(&0x7048)
    {
        return TestResult::Fail("AR9565 regulator-off values differ from ar9003_eeprom.c");
    }
    // AR9580 keeps the AR9300 branch: TOP + THERM bias, xPA timing,
    // quick drop, xLNA, XTAL 0x16294, thermometer on all three chains.
    let image = board_image();
    let mut io = Regs::default();
    io.regs.insert(0x700c, 0x5);
    if board::set_board_values(&mut io, Chip::Ar9580, &image, 2437, 7, 7).is_err() {
        return TestResult::Fail("AR9580 board values were refused");
    }
    if io.regs.get(&0x16288).copied().unwrap_or(0) & 0x300 != 0x300
        || io.regs.get(&0x16290).copied().unwrap_or(0) & 0x7 != 0x4
        || io.regs.get(&0xa264).copied().unwrap_or(0) & 0xff00 != 0x5a00
        || io.regs.get(&0x9e14).copied().unwrap_or(0) & 0x03c0_0000
            != ((-3i32 as u32) << 22) & 0x03c0_0000
        || io.regs.get(&0x1610c).copied().unwrap_or(0) >> 30 != 0b11
        || io.regs.get(&0x1650c).copied().unwrap_or(0) >> 30 != 0b01
        || io.regs.get(&0x1690c).copied().unwrap_or(0) >> 30 != 0b10
        || io.regs.get(&0x16294).copied().unwrap_or(0) & 0x7ffe_0000 != 0x2b56_0000
        || io.regs.get(&0x1610c).copied().unwrap_or(0) & 0x3000_0000 != 0x2000_0000
        || io.regs.get(&0x1650c).copied().unwrap_or(0) & 0x3000_0000 != 0x3000_0000
        || io.regs.get(&0x1690c).copied().unwrap_or(0) & 0x3000_0000 != 0x2000_0000
    {
        return TestResult::Fail("AR9580 board values differ from the AR9300 branch");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_ar9485_ar9565_board_values_follow_eeprom
);

/// `expected` derives exactly what `prepare` returns (INI-defined
/// `TX_CL_CAL`, gain-array `regWrites`, APM selfgen mask, power plan) on
/// both bands, without a single register access, and refuses an
/// unsupported channel the same way.
fn smoke_ath9k_ar9300_expected_preparation_matches_prepare() -> TestResult {
    let revision = Revision {
        chip: Chip::Ar9300,
        mac_rev: 3,
        pcie: true,
    };
    let image = AR9300_DEFAULT;
    let id = identity(&image);
    for frequency in [2412u16, 2437, 2484, 5180, 5825] {
        if !channel_supported(&id, frequency) {
            continue;
        }
        let mut io = Regs::default();
        let (Ok(prepared), Ok(facts)) = (
            prepare(
                &mut io,
                &revision,
                &id,
                super::super::serdes::PllPwrsave::resolve(Chip::Ar9300, 0, 0),
                &image,
                frequency,
                0xe0,
                0,
            ),
            expected(
                &revision,
                &id,
                super::super::serdes::PllPwrsave::resolve(Chip::Ar9300, 0, 0),
                &image,
                frequency,
                0xe0,
                0,
            ),
        ) else {
            return TestResult::Fail("AR9300 preparation or its expected facts refused");
        };
        if prepared != facts {
            return TestResult::Fail("AR9300 expected preparation differs from prepare");
        }
    }
    if expected(
        &revision,
        &id,
        super::super::serdes::PllPwrsave::resolve(Chip::Ar9300, 0, 0),
        &image,
        2465,
        0xe0,
        0,
    ) != Err(BringUpError::Policy)
    {
        return TestResult::Fail("AR9300 expected preparation admitted an off-raster channel");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_expected_preparation_matches_prepare
);

/// `ath_pci_suspend` on an awake AR9300: COLD `ath9k_hw_set_reset_reg`
/// (`AR_RTC_RC` 3 then 0), `ath9k_hw_init_pll`, then
/// `ath9k_set_power_sleep` (PWR_SAV set, force wake and `AR_RTC_RESET_EN`
/// cleared, `AR_WA` without `D3_L1_DISABLE`), in that order.
fn smoke_ath9k_ar9300_disable_and_full_sleep() -> TestResult {
    let mut io = Regs::default();
    io.regs.insert(0x704c, 0x3);
    io.regs.insert(0x7040, 0x1);
    // AR_CFG_HALT_ACK already set: the DMA halt handshake completes.
    io.regs.insert(0x0014, 0x1000);
    let wa = 0x0002_4000 | 0x40;
    if super::super::disable_and_sleep(&mut io, wa).is_err() {
        return TestResult::Fail("AR9300 disable/full sleep refused");
    }
    let at = |w: (u64, u32)| io.writes.iter().position(|x| *x == w);
    let (Some(cold), Some(pll), Some(clk), Some(sav), Some(wake), Some(rtc), Some(l1)) = (
        at((0x7000, 3)),
        at((0x7014, 0x142c)),
        at((0x7048, 2)),
        at((0x8004, 0x0004_0000)),
        at((0x704c, 0x2)),
        at((0x7040, 0)),
        at((0x4004, wa & !0x4000)),
    ) else {
        return TestResult::Fail("AR9300 disable/full-sleep write missing");
    };
    if !(cold < pll && pll < clk && clk < sav && sav < wake && wake < rtc && rtc < l1) {
        return TestResult::Fail("AR9300 disable/full-sleep order differs from Linux");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_disable_and_full_sleep
);
