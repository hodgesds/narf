use super::*;
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

/// Synthetic open-loop map: marker values chosen to exercise each Linux
/// branch, never board data.
pub(in crate::ath9k) fn image(tx_mask: u8) -> Vec<u8> {
    let mut b = vec![0u8; MAP_9287.bytes()];
    b[8] = 0x64; // regDmn[0]: world SKU, NO_CTL minimum walk.
    b[TX_MASK] = tx_mask;
    b[OPEN_LOOP] = 1;
    b[ANTENNA_GAIN] = 4;
    b[ANTENNA_GAIN + 1] = 2;
    b[XPD_GAIN] = 0b1001;
    b[PIERS..PIERS + 3].copy_from_slice(&[112, 137, 162]);
    // pwrPdg[0][0]: chain 0 piers -5, 2; chain 1 piers 20, 31.
    for (chain, pier, value) in [(0, 0, -5i8), (0, 1, 2), (1, 0, 20), (1, 1, 31)] {
        b[CAL + (chain * 3 + pier) * CAL_STRIDE] = value as u8;
    }
    b[CAL + OPEN_VPD] = 0x55;
    b[TARGET_CCK..TARGET_CCK + 15]
        .copy_from_slice(&[112, 30, 30, 28, 26, 162, 34, 34, 32, 30, 255, 0, 0, 0, 0]);
    b[TARGET_OFDM..TARGET_OFDM + 5].copy_from_slice(&[112, 36, 34, 32, 30]);
    b[TARGET_OFDM + 5] = 255;
    b[TARGET_HT20..TARGET_HT20 + 9].copy_from_slice(&[112, 40, 38, 36, 34, 32, 30, 28, 26]);
    b[TARGET_HT20 + 9] = 255;
    b[CTL_INDEX..CTL_INDEX + 4].copy_from_slice(&[0x11, 0x31, 0x12, 0x15]);
    let two: [[u8; 8]; 4] = [
        [112, 0x40 | 26, 162, 26, 255, 0, 255, 0],
        [122, 24, 255, 0, 255, 0, 255, 0],
        [112, 0x40 | 31, 200, 0, 255, 0, 255, 0],
        [112, 0x40 | 28, 162, 0x40 | 20, 255, 0, 255, 0],
    ];
    for (i, edges) in two.iter().enumerate() {
        let at = CTL_DATA + i * CTL_STRIDE;
        // ctlEdges[0] (one chain) differs from ctlEdges[1] (two chains).
        b[at..at + 8].copy_from_slice(&[112, 0x40 | 10, 200, 0, 255, 0, 255, 0]);
        b[at + 8..at + 16].copy_from_slice(edges);
    }
    b
}

fn smoke_ath9k_ar9287_txpower_two_chain_open_loop_and_ctl() -> TestResult {
    let mut io = Io::default();
    io.regs.insert(0xa398, 0x1234_5678);
    let p = match program(&mut io, &image(3), 2422, 40) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("two-chain open-loop map refused"),
    };
    // Scaled power 40 - (gain 4 + two-chain 6) = 30; ctlEdges[1] limits:
    // CCK min(26, 24), OFDM 31 (scaled 30 wins), HT20 28.
    let rates = [
        (0x9934, 0x2828_2828),
        (0x9938, 0x2828_2828),
        (0xa234, 0x2222_2822),
        (0xa238, 0x2222_2222),
        (0xa38c, 0x2626_2626),
        (0xa390, 0x2426_2626),
        (0x993c, 63),
    ];
    if p.registers != rates || p.max_power != 36 {
        return TestResult::Fail("AR9287 per-rate targets or two-chain CTL differ");
    }
    // Chain 0 mean (-5 + 2) / 2 truncates to -1; chain 1 (20 + 31) / 2 = 25.
    if p.olpc != [Some(0xff), Some(25)] || p.init_pdadc != 0x55 {
        return TestResult::Fail("AR9287 OLPC reference power differs");
    }
    let mut expected = vec![
        (0xa258, 0x4000),
        (0xa258, 0x3_4000),
        (0xa258, 0x3_4000),
        (0xa258, 0x3_4000),
        (0xa270, 0x0300_0000),
        (0xb270, 0x0300_0000),
        (0xa398, 0x12ff_5678),
        (0xa270, 0x0300_0000),
        (0xb270, 0x0300_0000),
        (0xb398, 0x0019_0000),
    ];
    expected.extend(rates);
    if io.writes != expected {
        return TestResult::Fail("AR9287 TX power write order differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_txpower_two_chain_open_loop_and_ctl
);

fn smoke_ath9k_ar9287_txpower_one_chain_uses_first_edge_set() -> TestResult {
    let mut io = Io::default();
    let p = match program(&mut io, &image(1), 2422, 40) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("one-chain open-loop map refused"),
    };
    if p.registers[..6].iter().any(|(_, v)| *v != 0x1414_1414) || p.max_power != 10 {
        return TestResult::Fail("one-chain CTL did not use ctlEdges[0]");
    }
    if p.olpc != [Some(0xff), None] || io.writes.iter().any(|(r, _)| *r == 0xb398) {
        return TestResult::Fail("disabled chain 1 received an OLPC power");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_txpower_one_chain_uses_first_edge_set
);

fn smoke_ath9k_ar9287_txpower_refuses_before_writes() -> TestResult {
    let mut closed = image(3);
    closed[OPEN_LOOP] = 0;
    let mut no_gain = image(3);
    no_gain[XPD_GAIN] = 0;
    let mut piers = image(3);
    piers[PIERS..PIERS + 2].copy_from_slice(&[137, 112]);
    let mut long = image(3);
    long.push(0);
    for (map, frequency, ceiling, gone, error) in [
        (closed, 2422, 40, false, BringUpError::BadCalibration),
        (no_gain, 2422, 40, false, BringUpError::BadCalibration),
        (piers, 2422, 40, false, BringUpError::BadCalibration),
        (long, 2422, 40, false, BringUpError::BadLength),
        (image(3), 2407, 40, false, BringUpError::BadCalibration),
        (image(3), 2422, 41, false, BringUpError::BadCalibration),
        (image(3), 2422, 40, true, BringUpError::DeviceGone),
    ] {
        let mut io = Io {
            gone,
            ..Io::default()
        };
        if program(&mut io, &map, frequency, ceiling) != Err(error) || !io.writes.is_empty() {
            return TestResult::Fail("refused AR9287 TX power wrote registers");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_txpower_refuses_before_writes
);
