use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    delays: Vec<u64>,
    gone: bool,
}
impl RegisterIo for Io {
    fn authorized(&self) -> bool {
        !self.gone
    }
    fn read32(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write32(&mut self, at: u64, value: u32) {
        self.regs.insert(at, value);
        self.writes.push((at, value));
    }
    fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
    }
}

/// AR9280 2.0 in the `AR_SREV_ID == 0xff` format: macVersion 0x80, rev 1.
const SREV_9280_20: u32 = 0x0008_01ff;

fn identity(minor: u16) -> Identity {
    Identity {
        revision: 1,
        mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        eeprom_version: 0xe000 | minor,
        regulatory_domains: [0x64, 0],
        rx_chainmask: 3,
        tx_chainmask: 3,
        big_endian_fields: false,
    }
}

/// Synthetic dual-band def map: distinct marker values, never board data.
fn image(big: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; MAP_DEF.bytes()];
    bytes[7] = u8::from(big);
    bytes[OP_CAP_FLAGS] = OPFLAGS_11A | OPFLAGS_11G;
    bytes[PWDCLKIND] = 1;
    let dword = |v: u32| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    for (base, tag) in [(MODAL_2G, 0x20u8), (MODAL_5G, 0x50u8)] {
        bytes[base..base + 4].copy_from_slice(&dword(0x0001_1100 | u32::from(tag)));
        bytes[base + 4..base + 8].copy_from_slice(&dword(0x0002_2200 | u32::from(tag)));
        bytes[base + 12..base + 16].copy_from_slice(&dword(0x0c0c_3300 | u32::from(tag)));
        for (offset, value) in [
            (19, 0x2c), // switchSettling
            (20, 0x11), // txRxAttenCh
            (21, 0x12),
            (23, 0x21), // rxTxMarginCh
            (24, 0x22),
            (26, 0xe2), // adcDesiredSize
            (31, 0x05), // txEndToXpaOff
            (32, 0x07), // txEndToRxOn
            (33, 0x0e), // txFrameToXpaOn
            (34, tag),  // thresh62
            (40, 0x3f), // iqCalICh
            (41, 0x01),
            (43, 0x1e), // iqCalQCh
            (44, 0x02),
            (47, 0x03), // ob
            (48, 0x04), // db
            (49, 0x02), // xpaBiasLvl
            (52, 0x0e), // txFrameToDataStart
            (53, 0x0f), // txFrameToPaOn
            (55, 0x09), // bswAtten
            (56, 0x0a),
            (58, 0x03), // bswMargin
            (59, 0x04),
            (61, 0x31), // swSettleHt40
            (62, 0x05), // xatten2Db
            (63, 0x06),
            (65, 0x07), // xatten2Margin
            (66, 0x08),
            (68, 0x05), // ob_ch1
            (69, 0x06), // db_ch1
            (70, 0x60), // lna_ctl: LOCAL_BIAS | FORCE_XPA
            (71, 0x0d), // miscBits
        ] {
            bytes[base + offset] = value;
        }
        // Empty spur list (AR_NO_SPUR terminator).
        let at = base + SPUR_CHANS;
        bytes[at..at + 2].copy_from_slice(&if big {
            0x8000u16.to_be_bytes()
        } else {
            0x8000u16.to_le_bytes()
        });
    }
    bytes
}

fn ini_hash(writes: &[(u64, u32)], rows: usize) -> Option<u64> {
    let first = writes.iter().position(|&(reg, _)| reg == 0x9830)?;
    let ini = writes.get(first + 2..first + 2 + rows)?;
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for (reg, value) in ini {
        for byte in (*reg as u32)
            .to_le_bytes()
            .into_iter()
            .chain(value.to_le_bytes())
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    Some(hash)
}

fn smoke_ath9k_ar9280_ini_follows_linux_band_and_gain_selection() -> TestResult {
    let srev = Revision::decode(SREV_9280_20).unwrap();
    // Independent FNV-1a oracles over (address, value) LE32 pairs extracted
    // from Linux ar9002_initvals.h by the AR9280_2 selection rules.
    // 2 GHz, minor 16: original RX gain, original TX gain, column 4.
    let mut io = Io::default();
    let Ok(two) = prepare(
        &mut io,
        &srev,
        &identity(0x10),
        &image(false),
        DEVID_PCIE,
        2412,
    ) else {
        return TestResult::Fail("AR9280 2 GHz preparation refused");
    };
    if two.ini_writes != 547
        || ini_rows(&identity(0x10), &image(false), two.tune) != 547
        || ini_hash(&io.writes, 547) != Some(0x6711_58e4_7e49_c34c)
    {
        return TestResult::Fail("AR9280 2 GHz INI differs from ar9002_initvals.h selection");
    }
    // 5 GHz, minor 22: 23 dB backoff RX gain, high-power TX gain, column 1,
    // then the fast-clock table.
    let mut map = image(false);
    map[RX_GAIN_TYPE] = 0;
    map[TX_GAIN_TYPE] = 1;
    let mut io = Io::default();
    let Ok(five) = prepare(&mut io, &srev, &identity(0x16), &map, DEVID_PCIE, 5180) else {
        return TestResult::Fail("AR9280 5 GHz preparation refused");
    };
    if five.ini_writes != 560 || ini_hash(&io.writes, 560) != Some(0x4110_57f3_aba5_4ca3) {
        return TestResult::Fail("AR9280 5 GHz INI differs from ar9002_initvals.h selection");
    }
    // PCI 0x0029, minor > 0x0a, pwdclkind 0: AR_AN_TOP2 PWDCLKIND fixup,
    // 13 dB backoff RX gain; TX gain type ignored below minor 19.
    let mut map = image(false);
    map[PWDCLKIND] = 0;
    map[RX_GAIN_TYPE] = 1;
    map[TX_GAIN_TYPE] = 1;
    let mut io = Io::default();
    if prepare(&mut io, &srev, &identity(0x12), &map, DEVID_PCI, 2437).is_err()
        || ini_hash(&io.writes, 547) != Some(0x6981_3202_1755_3009)
    {
        return TestResult::Fail("AR9280 PCI AN_TOP2 fixup or gain selection wrong");
    }
    if io.writes.first() != Some(&(0x24, 0)) || io.writes.last() != Some(&(0x8, 0x20)) {
        return TestResult::Fail("AR9280 preparation left interrupts or RX enabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9280_ini_follows_linux_band_and_gain_selection
);

fn smoke_ath9k_ar9280_5ghz_synth_rfmode_and_spur_band() -> TestResult {
    // ar9002_hw_set_channel: integer mode for 20/10 MHz aligned centers,
    // fractional CHANSEL_5G otherwise or when EEP_FRAC_N_5G is set.
    let ndiv = 5180 * 3 / 60;
    if channel::synth_5ghz(5180, false) != ((3 << 26) | ((ndiv & 0x1ff) << 17), false)
        || channel::synth_5ghz(5745, false) != ((1 << 28) | (5745 * 0x8000 / 15), true)
        || channel::synth_5ghz(5180, true) != ((1 << 28) | (5180 * 0x8000 / 15), true)
    {
        return TestResult::Fail("AR9280 5 GHz synthesizer differs from ar9002_hw_set_channel");
    }
    let srev = Revision::decode(SREV_9280_20).unwrap();
    let mut io = Io::default();
    io.regs.insert(0x9874, 0xc000_0000);
    io.regs.insert(0x7868, 0x0000_0007);
    let mut map = image(false);
    map[FRAC_N_5G] = 1;
    if prepare(&mut io, &srev, &identity(0x16), &map, DEVID_PCIE, 5745).is_err() {
        return TestResult::Fail("AR9280 UNII-3 preparation refused");
    }
    // The REFDIVA step is an RMW over the post-INI register, not the seed:
    // the COMMON table writes (0x7868, 0xc0102850) during process_ini
    // (initvals_ar9280.rs:407), so the RMW yields
    // (0xc0102850 & !0xf8000000) | (1 << 27) = 0x08102850, not (1 << 27) | 7.
    let wrote = |reg: u64, value: u32| io.writes.contains(&(reg, value));
    if !wrote(0x9874, 0xc000_0000 | (1 << 28) | (5745 * 0x8000 / 15))
        || !wrote(0x7868, 0x0810_2850)
        || !wrote(0xa200, 0x104)
    {
        return TestResult::Fail("AR9280 5 GHz fast-clock tune wrong");
    }
    // 5 GHz board values come from modalHeader[0] (thresh62 tag 0x50).
    if io.regs.get(&0x99b8).map(|v| v & 0xff) != Some(0x50) {
        return TestResult::Fail("AR9280 5 GHz used the 2 GHz modal header");
    }
    // A 5 GHz spur at 5750 MHz (spurChan (5750 - 4900) * 10) is 5 MHz
    // off the 5745 center: denominator 40, not 44.
    let mut spur = image(false);
    let at = MODAL_5G + SPUR_CHANS;
    spur[at..at + 2].copy_from_slice(&8500u16.to_le_bytes());
    let mut io = Io::default();
    if prepare(&mut io, &srev, &identity(0x16), &spur, DEVID_PCIE, 5745).is_err() {
        return TestResult::Fail("AR9280 spur preparation refused");
    }
    let phase = ((5 * 524288) / 10) as u32 & 0xfffff;
    if !io.writes.contains(&(
        0x99a0,
        0x4000_0000 | ((((5 * 2048) / 40) as u32 & 0x3ff) << 20) | phase,
    )) {
        return TestResult::Fail("AR9280 5 GHz spur mitigation not band-scaled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9280_5ghz_synth_rfmode_and_spur_band
);

fn smoke_ath9k_ar9280_board_values_follow_eeprom_def() -> TestResult {
    for big in [false, true] {
        let mut io = Io::default();
        io.regs.insert(0x7810, 0x0000_0fff);
        io.regs.insert(0x7894, 0x0000_0001);
        if set_board_values(&mut io, &identity(0x16), &image(big), false, false).is_err() {
            return TestResult::Fail("AR9280 board values refused");
        }
        let reg = |at: u64| io.regs.get(&at).copied().unwrap_or(0);
        if reg(0x9964) != 0x3320
            || reg(0x9960) != 0x0001_1120
            || reg(0xa960) != 0x0002_2220
            || reg(0x9920) != (0x3f << 5) | 0x1e
            || reg(0xa920) != (1 << 5) | 2
            || reg(0xa20c) != (7 << 17) | (3 << 12) | (5 << 6) | 9
            || reg(0xb20c) != (8 << 17) | (4 << 12) | (6 << 6) | 0x0a
            || reg(0x9848) != (0x11 << 7) | (0x21 << 14)
            || reg(0xa848) != (0x12 << 7) | (0x22 << 14)
            || reg(0x7810) != (3 << 23) | (4 << 26) | 0xfff
            || reg(0x7834) != (5 << 23) | (6 << 26)
            || reg(0x7894) != (2 << 30) | (1 << 21) | 1
            || reg(0xa3d8) != 1
            || reg(0x9844) != 0x2c << 7
            || reg(0x9850) != 0xe2
            || reg(0x9834) != 0x0505_0e0e
            || reg(0x9828) != 0x07 << 16
            || reg(0x9864) != 0x20 << 12
            || reg(0x99b8) != 0x20
            || reg(0x9824) != 0x0f0e
            || reg(0xa204) != (0x0d << 2) & 0x0c
            || reg(0x9944) != (3 << 3)
        {
            return TestResult::Fail("AR9280 board value field placement wrong");
        }
        // Six analog-shift writes plus the DACIPMODE settle.
        if io.delays.iter().filter(|&&us| us == 100).count() != 7 {
            return TestResult::Fail("AR9280 analog shift writes did not settle");
        }
    }
    // Minor 1: default 23 dB TX/RX attenuation, no XATTEN, no RF_CTL2, no
    // HT40 settle, no DAC fields.
    let mut old = Io::default();
    let _ = set_board_values(&mut old, &identity(1), &image(false), false, true);
    let reg = |at: u64| old.regs.get(&at).copied().unwrap_or(0);
    if reg(0x9848) != (23 << 7) | (0x21 << 14)
        || old
            .writes
            .iter()
            .any(|&(r, _)| matches!(r, 0xa20c | 0x9824 | 0xa204 | 0x7890))
        || reg(0x9844) != 0x2c << 7
    {
        return TestResult::Fail("AR9280 minor-version gates differ from eeprom_def.c");
    }
    // 5 GHz: OB5/DB5 fields, attenuation default 44 before minor 3, and
    // dacHiPwrMode_5G forces DACIPMODE 0.
    let mut map = image(false);
    map[DAC_LP_MODE] = 1;
    map[DAC_HI_PWR_MODE_5G] = 1;
    let mut five = Io::default();
    five.regs.insert(0x7890, 0x0004_0000);
    let _ = set_board_values(&mut five, &identity(0x16), &map, true, false);
    let reg = |at: u64| five.regs.get(&at).copied().unwrap_or(0);
    if reg(0x7818) != (3 << 16) | (4 << 19)
        || reg(0x783c) != (5 << 16) | (6 << 19)
        || reg(0x7890) != 0
        || reg(0x9960) != 0x0001_1150
    {
        return TestResult::Fail("AR9280 5 GHz board values wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9280_board_values_follow_eeprom_def
);

fn smoke_ath9k_ar9280_preparation_refuses_wrong_inputs() -> TestResult {
    let good = image(false);
    let srev = Revision::decode(SREV_9280_20).unwrap();
    let ar9287 = Revision::decode(0x0018_03ff).unwrap();
    let mut no_5g = good.clone();
    no_5g[OP_CAP_FLAGS] = OPFLAGS_11G;
    let mut no_2g = good.clone();
    no_2g[OP_CAP_FLAGS] = OPFLAGS_11A;
    let mut open = good.clone();
    open[OPEN_LOOP_PWR_CNTL] = 1;
    let cases: [(&Revision, &[u8], u16, u16, BringUpError); 9] = [
        (
            &ar9287,
            &good,
            DEVID_PCIE,
            2412,
            BringUpError::UnsupportedRevision,
        ),
        (
            &srev,
            &good,
            0x002b,
            2412,
            BringUpError::UnsupportedRevision,
        ),
        (
            &srev,
            &good[..726],
            DEVID_PCIE,
            2412,
            BringUpError::BadLength,
        ),
        (&srev, &good, DEVID_PCIE, 2484, BringUpError::Policy),
        (&srev, &good, DEVID_PCIE, 5170, BringUpError::Policy),
        (&srev, &good, DEVID_PCIE, 5735, BringUpError::Policy),
        (&srev, &no_5g, DEVID_PCIE, 5180, BringUpError::Policy),
        (&srev, &no_2g, DEVID_PCIE, 2412, BringUpError::Policy),
        (&srev, &open, DEVID_PCIE, 2412, BringUpError::BadCalibration),
    ];
    for (revision, map, device, frequency, expected) in cases {
        let mut io = Io::default();
        if prepare(&mut io, revision, &identity(0x16), map, device, frequency) != Err(expected)
            || !io.writes.is_empty()
        {
            return TestResult::Fail("invalid AR9280 preparation input reached registers");
        }
    }
    // Open loop is only read from minor 19.
    let mut io = Io::default();
    if prepare(&mut io, &srev, &identity(0x12), &open, DEVID_PCIE, 2412).is_err() {
        return TestResult::Fail("pre-minor-19 openLoopPwrCntl byte honoured");
    }
    let mut gone = Io {
        gone: true,
        ..Io::default()
    };
    if prepare(&mut gone, &srev, &identity(0x16), &good, DEVID_PCIE, 2412)
        != Err(BringUpError::DeviceGone)
        || !gone.writes.is_empty()
    {
        return TestResult::Fail("revoked AR9280 authority received writes");
    }
    if channel_5ghz(5180) != Some(36)
        || channel_5ghz(5720) != Some(144)
        || channel_5ghz(5825) != Some(165)
        || channel_5ghz(5340).is_some()
        || channel_5ghz(5765) != Some(153)
    {
        return TestResult::Fail("AR9280 5 GHz channel set wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9280_preparation_refuses_wrong_inputs
);
