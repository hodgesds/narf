use super::*;
use crate::ath9k::channel_width::Geometry;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
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
    fn delay_us(&mut self, _: u64) {}
}

pub(in crate::ath9k) fn identity(minor: u16) -> Identity {
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

fn two(frequency: u16) -> Tune {
    Tune::Two(Geometry::from_frequency(frequency).unwrap())
}

/// Synthetic closed-loop dual-band def map: marker values chosen to
/// exercise each Linux branch, never board data.
pub(in crate::ath9k) fn image(tx_mask: u8) -> Vec<u8> {
    let mut b = vec![0u8; MAP_DEF.bytes()];
    b[8] = 0x64; // regDmn[0]: world SKU, NO_CTL minimum walk.
    b[TX_MASK] = tx_mask;
    for modal in [MODAL_2G, MODAL_5G] {
        b[modal + XPD_GAIN] = 0x8; // One PD gain: xpdGainValues[0] = 3.
        b[modal + PD_GAIN_OVERLAP] = 6;
        b[modal + DECREASE_2_CHAIN] = 3;
        b[modal + DECREASE_3_CHAIN] = 5;
    }
    b[MODAL_2G + ANTENNA_GAIN..MODAL_2G + ANTENNA_GAIN + 3].copy_from_slice(&[2, 4, 3]);
    // One calibration pier per band: 2412 MHz (bin 112), 5180 MHz (bin 76).
    b[PIERS_2G..PIERS_2G + 4].copy_from_slice(&[112, 255, 255, 255]);
    b[PIERS_5G..PIERS_5G + 8].copy_from_slice(&[76, 255, 255, 255, 255, 255, 255, 255]);
    for chain in 0..2 {
        for data in [
            CAL_2G + chain * 4 * CAL_STRIDE,
            CAL_5G + chain * 8 * CAL_STRIDE,
        ] {
            b[data..data + 5].copy_from_slice(&[0, 10, 20, 30, 40]); // pwrPdg[0]
            b[data + 20..data + 25].copy_from_slice(&[0, 40, 80, 120, 160]); // vpdPdg[0]
        }
    }
    b[TARGET_CCK..TARGET_CCK + 6].copy_from_slice(&[112, 30, 30, 28, 26, 255]);
    b[TARGET_2G..TARGET_2G + 6].copy_from_slice(&[112, 36, 34, 32, 30, 255]);
    b[TARGET_2G_HT20..TARGET_2G_HT20 + 10]
        .copy_from_slice(&[112, 40, 38, 36, 34, 32, 30, 28, 26, 255]);
    b[TARGET_5G..TARGET_5G + 6].copy_from_slice(&[76, 20, 20, 18, 16, 255]);
    b[TARGET_5G_HT20..TARGET_5G_HT20 + 10]
        .copy_from_slice(&[76, 22, 22, 20, 20, 18, 18, 16, 14, 255]);
    // CTL_11B, CTL_11G, CTL_2GHT20, CTL_11A, CTL_5GHT20 for FCC.
    b[CTL_INDEX..CTL_INDEX + 5].copy_from_slice(&[0x11, 0x12, 0x15, 0x10, 0x16]);
    let edges: [([u8; 2], [u8; 2]); 5] = [
        ([112, 0x40 | 10], [112, 0x40 | 24]),
        ([112, 0x40 | 10], [112, 31]),
        ([112, 0x40 | 10], [112, 28]),
        ([76, 19], [76, 9]),
        ([76, 21], [76, 9]),
    ];
    for (i, (one, two)) in edges.iter().enumerate() {
        let at = CTL_DATA + i * CTL_STRIDE;
        for chain in 0..3 {
            b[at + chain * 16..at + chain * 16 + 16].fill(0);
            b[at + chain * 16 + 2] = 255;
        }
        b[at..at + 2].copy_from_slice(one);
        b[at + 16..at + 18].copy_from_slice(two);
    }
    b
}

/// The Linux detector table for the synthetic pier: one gain over 0..40
/// half-dB with vpd = 4 * power, overlap 6 (`ath9k_hw_get_gain_boundaries_pdadcs`).
fn expected_pdadc(diff: usize) -> [u32; 32] {
    let mut values = [0u8; 128];
    for (k, value) in values.iter_mut().enumerate() {
        *value = match k {
            0..=20 => 8 * k as u8,
            21..=26 => 160 + 8 * (k as u8 - 20),
            _ => 208,
        };
    }
    if diff != 0 {
        let tail = values[128 - diff];
        values.copy_within(diff.., 0);
        values[128 - diff..].fill(tail);
    }
    core::array::from_fn(|j| u32::from_le_bytes(values[4 * j..4 * j + 4].try_into().unwrap()))
}

fn smoke_ath9k_ar9280_txpower_two_chain_closed_loop_2ghz() -> TestResult {
    let mut io = Io::default();
    let p = match program(&mut io, &identity(0x10), &image(3), two(2412), 40) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("two-chain closed-loop def map refused"),
    };
    // Scaled 40 - (max(2, 4, 3) + two-chain 6) = 30; ctlEdges[1] limits:
    // CCK 24, OFDM 31 (scaled 30 wins), HT20 28; then +10 for the default
    // AR5416_PWR_TABLE_OFFSET_DB.
    let rates = [
        (0x9934, 0x2828_2828),
        (0x9938, 0x2828_2828),
        (0xa234, 0x2222_2822),
        (0xa238, 0x2222_2222),
        (0xa38c, 0x2626_2626),
        (0xa390, 0x2426_2626),
        (0xa3c8, (5 << 6) | 3),
        (0x993c, 63),
    ];
    if p.register_count != 8 || p.registers != rates || p.max_power != 36 {
        return TestResult::Fail("AR9280 2 GHz rate table differs from eeprom_def.c");
    }
    let bounds = 6 | (20 << 4) | (20 << 10) | (20 << 16) | (20 << 22);
    let pdadc = expected_pdadc(0);
    for offset in [0u64, 0x1000] {
        if io.regs.get(&(0xa26c + offset)) != Some(&bounds)
            || (0..32).any(|j| io.regs.get(&(0xa280 + offset + 4 * j)) != Some(&pdadc[j as usize]))
        {
            return TestResult::Fail("AR9280 closed-loop PDADC table wrong");
        }
    }
    if io.regs.get(&0xa258) != Some(&(3 << 16)) {
        return TestResult::Fail("AR9280 TPCRG1 PD gains wrong");
    }
    // TPCRG1 first, then each chain's TPCRG5 + PDADC, then the rates.
    let order: Vec<u64> = io.writes.iter().map(|w| w.0).collect();
    if order[..4] != [0xa258; 4]
        || order.get(4) != Some(&0xa26c)
        || order.get(37) != Some(&0xb26c)
        || order.last() != Some(&0x993c)
    {
        return TestResult::Fail("AR9280 transmit power write order differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9280_txpower_two_chain_closed_loop_2ghz
);

fn smoke_ath9k_ar9280_txpower_5ghz_one_chain_and_table_offset() -> TestResult {
    let mut map = image(1);
    map[PWR_TABLE_OFFSET] = (-3i8) as u8;
    let mut io = Io::default();
    let tune = Tune::Five {
        frequency: 5180,
        frac_n: false,
    };
    let p = match program(&mut io, &identity(0x15), &map, tune, 30) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("one-chain 5 GHz def map refused"),
    };
    // ctlEdges[0]: CTL_11A 19, CTL_5GHT20 21; pwr_table_offset -3 adds 6.
    let rates = [
        (0x9934, 0x1919_1919),
        (0x9938, 0x1618_1919),
        (0xa38c, 0x1a1a_1b1b),
        (0xa390, 0x1416_1818),
        (0xa3c8, (5 << 6) | 3),
        (0x993c, 63),
    ];
    if p.register_count != 6 || p.registers[..6] != rates || p.max_power != 21 {
        return TestResult::Fail("AR9280 5 GHz rate table differs from eeprom_def.c");
    }
    if io
        .writes
        .iter()
        .any(|w| matches!(w.0, 0xa234 | 0xa238 | 0xb26c))
    {
        return TestResult::Fail("AR9280 5 GHz wrote CCK rates or the disabled chain");
    }
    // diff = (-3 - -5) * 2 = 4: boundary 20 - 4, table shifted by four.
    let bounds = 6 | (16 << 4) | (20 << 10) | (20 << 16) | (20 << 22);
    let pdadc = expected_pdadc(4);
    if io.regs.get(&0xa26c) != Some(&bounds)
        || (0..32).any(|j| io.regs.get(&(0xa280 + 4 * j)) != Some(&pdadc[j as usize]))
    {
        return TestResult::Fail("AR9280 pwr_table_offset adjustment wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9280_txpower_5ghz_one_chain_and_table_offset
);

fn smoke_ath9k_ar9280_txpower_refuses_before_writes() -> TestResult {
    let good = image(3);
    let mut open = good.clone();
    open[36] = 1; // openLoopPwrCntl (minor 19+).
    let mut below = good.clone();
    below[PWR_TABLE_OFFSET] = (-6i8) as u8; // Linux indexes pdadcValues[-2].
    let mut wrap = good.clone();
    wrap[PWR_TABLE_OFFSET] = 20; // ratesArray - 40 would wrap ATH9K_POW_SM.
    let mut empty = good.clone();
    empty[TARGET_2G] = 255;
    let mut no_gain = good.clone();
    no_gain[MODAL_2G + XPD_GAIN] = 0;
    let cases: [(&[u8], u8); 6] = [
        (&open, 40),
        (&below, 40),
        (&wrap, 40),
        (&empty, 40),
        (&no_gain, 40),
        (&good, 64),
    ];
    for (map, ceiling) in cases {
        let mut io = Io::default();
        if program(&mut io, &identity(0x16), map, two(2412), ceiling).is_ok()
            || !io.writes.is_empty()
        {
            return TestResult::Fail("invalid AR9280 power input reached registers");
        }
    }
    let mut gone = Io {
        gone: true,
        ..Io::default()
    };
    if program(&mut gone, &identity(0x16), &good, two(2412), 40) != Err(BringUpError::DeviceGone)
        || !gone.writes.is_empty()
    {
        return TestResult::Fail("revoked authority received AR9280 power writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9280_txpower_refuses_before_writes
);

fn smoke_ath9k_ar5008_txpower_three_chain_closed_loop() -> TestResult {
    // AR5416/AR9160: three TX chains (chain 2 mirrors chain 1's synthetic
    // pier and ctlEdges[2] mirrors ctlEdges[1]), minor 21 with
    // pwr_table_offset -3, which only AR9280_20_OR_LATER applies.
    let mut map = image(7);
    for (data, stride) in [(CAL_2G, 4), (CAL_5G, 8)] {
        let one = data + stride * CAL_STRIDE;
        let two = data + 2 * stride * CAL_STRIDE;
        map.copy_within(one..one + stride * CAL_STRIDE, two);
    }
    for i in 0..5 {
        let at = CTL_DATA + i * CTL_STRIDE;
        map.copy_within(at + 16..at + 32, at + 32);
    }
    map[PWR_TABLE_OFFSET] = (-3i8) as u8;
    let mut id = identity(0x15);
    id.rx_chainmask = 5;
    id.tx_chainmask = 7;
    let mut io = Io::default();
    let Ok(p) = program_chip(&mut io, &id, &map, two(2412), 40, Chip::Ar5416) else {
        return TestResult::Fail("three-chain AR5416 def map refused");
    };
    // Scaled 40 - (4 + three-chain 10) = 26; CCK edge 24; no table shift.
    let rates = [
        (0x9934, 0x1a1a_1a1a),
        (0x9938, 0x1a1a_1a1a),
        (0xa234, 0x1818_1a18),
        (0xa238, 0x1818_1818),
        (0xa38c, 0x1a1a_1a1a),
        (0xa390, 0x1a1a_1a1a),
        (0xa3c8, (5 << 6) | 3),
        (0x993c, 63),
    ];
    if p.registers != rates || p.max_power != 36 || p.chains.iter().flatten().count() != 3 {
        return TestResult::Fail("AR5416 three-chain rate table differs from eeprom_def.c");
    }
    let pdadc = expected_pdadc(0);
    let bounds = 6 | (20 << 4) | (20 << 10) | (20 << 16) | (20 << 22);
    // RX mask 0x5 swaps chains 1 and 2: +0x2000 then +0x1000.
    let tpcrg5: Vec<u64> = io
        .writes
        .iter()
        .map(|w| w.0)
        .filter(|r| r & 0xfff == 0x26c)
        .collect();
    if tpcrg5 != [0xa26c, 0xc26c, 0xb26c] {
        return TestResult::Fail("AR5416 regChainOffset swap not applied");
    }
    for offset in [0u64, 0x1000, 0x2000] {
        if io.regs.get(&(0xa26c + offset)) != Some(&bounds)
            || (0..32).any(|j| io.regs.get(&(0xa280 + offset + 4 * j)) != Some(&pdadc[j as usize]))
        {
            return TestResult::Fail("AR5416 PDADC table shifted or wrong");
        }
    }
    // The AR9280 plan of the same map still refuses three chains, and a
    // non-def chip or a mask beyond three chains is refused.
    if plan(&identity(0x15), &map, two(2412), 40, 0) != Err(BringUpError::BadIdentity)
        || plan_chip(&id, &map, two(2412), 40, 0, Chip::Ar9285)
            != Err(BringUpError::UnsupportedRevision)
        || plan_chip(&id, &image(8), two(2412), 40, 0, Chip::Ar9160)
            != Err(BringUpError::BadIdentity)
    {
        return TestResult::Fail("def power plan accepted a wrong chip or mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar5008_txpower_three_chain_closed_loop
);
