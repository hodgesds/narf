// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_8851b_rfe_gpio_follows_rtw8851b() -> TestResult {
    // rtw8851b_rfe_gpio: BB half (PHY_0) then MAC half, in order.
    let fields = rfe_gpio_fields(2);
    let head = [
        (0x1_0340, 0x3, 0),
        (0x1_5890, 1 << 16, 1),
        (0x1_5888, 0xF, 8),
        (0x1_0340, 0xC, 0),
        (0x1_5890, 1 << 17, 0),
        (0x1_5888, 0xF0, 8),
    ];
    if fields.as_slice() != head {
        return TestResult::Fail("rfe_gpio BB program differs from rtw8851b");
    }
    let mac = rfe_gpio_mac_fields(2);
    if mac.as_slice() != [(0x02D8, 0x0F, 0x08), (0x02D8, 0xF0, 0x08)] {
        return TestResult::Fail("rfe_gpio MAC program differs from rtw8851b");
    }
    // The flag has no <= 50 bound, but the GPIO writes do: rfe 53 sets
    // ant_diversity yet writes nothing; rfe 51 is past the bound;
    // rfe 4 is not a diversity RFE at all.
    if !rfe_gpio_fields(53).is_empty()
        || !rfe_gpio_mac_fields(53).is_empty()
        || !rfe_gpio_fields(51).is_empty()
        || !rfe_gpio_fields(4).is_empty()
    {
        return TestResult::Fail("rfe_gpio gate differs from rtw8851b");
    }
    // The bound is inclusive: rfe 50 programs exactly the rfe 2 list.
    if rfe_gpio_fields(50).as_slice() != head {
        return TestResult::Fail("rfe_gpio bound differs from rtw8851b");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_rfe_gpio_follows_rtw8851b
);

fn smoke_rtw89_8851b_antdiv_reg_init_follows_phy() -> TestResult {
    let fields = reg_init_fields();
    let expected = [
        (0x1_5868, 1, 0),
        (0x1_5868, 2, 0),
        (0x1_0728, 0xF, 0),
        (0x1_0728, 1 << 12, 0),
        (0x1_5868, 1 << 12, 0),
        (0x1_5870, 0xFFFF, 0x0100),
        (0x1_586C, 1 << 21, 1),
        (0x1_586C, 1 << 16, 0),
        (0x1_586C, 1 << 23, 0),
        (0x1_586C, 1 << 25, 0),
    ];
    if fields != expected {
        return TestResult::Fail("antdiv reg_init differs from phy.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_reg_init_follows_phy
);

fn smoke_rtw89_8851b_antdiv_set_ant_follows_phy() -> TestResult {
    let on_a = AntDiv::new(RF_A, RF_A);
    let expected_a = [
        (0x1_586C, 1 << 17, 0),
        (0x1_586C, 0xF0, 0),
        (0x1_586C, 0xF00, 1),
        (0x1_586C, 0xF000, 0),
    ];
    if on_a.set_ant_fields() != expected_a {
        return TestResult::Fail("set_ant on RF_A differs from phy.c");
    }
    let on_b = AntDiv::new(RF_B, RF_B);
    let expected_b = [
        (0x1_586C, 1 << 17, 1),
        (0x1_586C, 0xF0, 1),
        (0x1_586C, 0xF00, 0),
        (0x1_586C, 0xF000, 1),
    ];
    if on_b.set_ant_fields() != expected_b {
        return TestResult::Fail("set_ant on RF_B differs from phy.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_set_ant_follows_phy
);

fn smoke_rtw89_8851b_antdiv_ewma_follows_average() -> TestResult {
    // DECLARE_EWMA(rssi, 10, 16): first add stores val << 10.
    let mut stats = Stats::default();
    stats.add(PpduClass::Cck, 100, 0);
    if stats.cck.read() != 100 || stats.pkt_cnt_cck != 1 {
        return TestResult::Fail("EWMA first add differs from average.h");
    }
    // Second add: ((102400 << 4) - 102400 + (116 << 10)) >> 4 = 103424,
    // read back >> 10 = 101.
    stats.add(PpduClass::Cck, 116, 0);
    if stats.cck.read() != 101 || stats.pkt_cnt_cck != 2 {
        return TestResult::Fail("EWMA second add differs from average.h");
    }
    // EVM: truncating division, 0 on a zero divisor.
    if Stats::default().evm() != 0 {
        return TestResult::Fail("EVM zero-divisor differs from phy.c");
    }
    let mut evm = Stats::default();
    evm.add(PpduClass::Ofdm, 90, 5);
    evm.add(PpduClass::NonLegacy, 80, 7);
    if evm.evm() != 6 {
        return TestResult::Fail("EVM average differs from phy.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_ewma_follows_average
);

fn smoke_rtw89_8851b_antdiv_stats_dominance_follows_phy() -> TestResult {
    // CCK leads 2-1-1, so CCK wins despite the tie below it.
    let mut stats = Stats::default();
    stats.add(PpduClass::Cck, 100, 0);
    stats.add(PpduClass::Cck, 116, 0);
    stats.add(PpduClass::Ofdm, 90, 0);
    stats.add(PpduClass::NonLegacy, 80, 0);
    if stats.rssi() != 101 {
        return TestResult::Fail("stats dominance differs from phy.c");
    }
    // Non-legacy takes the lead 3-2-1 and wins; the CCK/OFDM tie
    // below it would favor OFDM over CCK.
    stats.add(PpduClass::NonLegacy, 80, 0);
    stats.add(PpduClass::NonLegacy, 80, 0);
    if stats.rssi() != 80 {
        return TestResult::Fail("stats non-legacy dominance differs from phy.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_stats_dominance_follows_phy
);

fn smoke_rtw89_8851b_antdiv_parse_gates_follow_phy() -> TestResult {
    let mut antdiv = AntDiv::new(RF_A, RF_A);
    // Gate closed: target only, never main/aux.
    antdiv.parse(PpduClass::NonLegacy, 80, 0);
    if antdiv.target.pkt_cnt_non_legacy != 1
        || antdiv.main.pkt_cnt_non_legacy != 0
        || antdiv.aux.pkt_cnt_non_legacy != 0
    {
        return TestResult::Fail("parse with closed gate differs from phy.c");
    }
    // Gate open on RF_A: main accumulates, aux does not.
    antdiv.get_stats = true;
    antdiv.parse(PpduClass::NonLegacy, 80, 0);
    if antdiv.main.pkt_cnt_non_legacy != 1 || antdiv.aux.pkt_cnt_non_legacy != 0 {
        return TestResult::Fail("parse on RF_A differs from phy.c");
    }
    // Gate open on RF_B: aux accumulates, main does not.
    antdiv.antenna_rx = RF_B;
    antdiv.parse(PpduClass::NonLegacy, 80, 0);
    if antdiv.main.pkt_cnt_non_legacy != 1 || antdiv.aux.pkt_cnt_non_legacy != 1 {
        return TestResult::Fail("parse on RF_B differs from phy.c");
    }
    // Fixed: nothing accumulates anywhere, not even target.
    antdiv.set_fixed(true);
    antdiv.parse(PpduClass::NonLegacy, 80, 0);
    if antdiv.target.pkt_cnt_non_legacy != 3 {
        return TestResult::Fail("parse when fixed differs from phy.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_parse_gates_follow_phy
);

fn smoke_rtw89_8851b_antdiv_track_follows_phy() -> TestResult {
    let mut antdiv = AntDiv::new(RF_A, RF_A);
    antdiv.parse(PpduClass::NonLegacy, 60, 0);
    // |60 - 0| >= 3: training restarts from count 0.
    if antdiv.track() != TrackOutcome::StartTraining
        || antdiv.rssi_pre() != 60
        || antdiv.training_count() != 0
    {
        return TestResult::Fail("track trigger differs from phy.c");
    }
    // Target reset by the previous track: a fresh 61 reads against 60.
    antdiv.parse(PpduClass::NonLegacy, 61, 0);
    if antdiv.track() != TrackOutcome::Stable || antdiv.rssi_pre() != 61 {
        return TestResult::Fail("track stable band differs from phy.c");
    }
    // A 9-step move restarts training again.
    antdiv.parse(PpduClass::NonLegacy, 70, 0);
    if antdiv.track() != TrackOutcome::StartTraining {
        return TestResult::Fail("track retrigger differs from phy.c");
    }
    // An empty target reads 0, which moves against 70 and retriggers —
    // pinning that track resets the target instance.
    if antdiv.track() != TrackOutcome::StartTraining || antdiv.rssi_pre() != 0 {
        return TestResult::Fail("track target reset differs from phy.c");
    }
    // Fixed: stable, and the previous value is untouched.
    antdiv.set_fixed(true);
    if antdiv.track() != TrackOutcome::Stable || antdiv.rssi_pre() != 0 {
        return TestResult::Fail("track when fixed differs from phy.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_track_follows_phy
);

fn smoke_rtw89_8851b_antdiv_work_cycle_follows_phy() -> TestResult {
    let mut antdiv = AntDiv::new(RF_A, RF_A);
    // Count 0 (even): collect opens for 30 ms, no ANTSEL program.
    match antdiv.step() {
        Work::Training {
            period_ms: 30,
            set_ant: None,
        } if antdiv.training_count() == 1 && antdiv.get_stats() => {}
        _ => return TestResult::Fail("training step 0 differs from phy.c"),
    }
    antdiv.parse(PpduClass::NonLegacy, 50, 0);
    // Count 1 (odd): collect closes, antenna swaps to B, ANTSEL
    // programs the AUX default, 110 ms settle.
    match antdiv.step() {
        Work::Training {
            period_ms: 110,
            set_ant: Some(fields),
        } if antdiv.training_count() == 2
            && !antdiv.get_stats()
            && antdiv.antenna_rx() == RF_B
            && fields[0].2 == 1 => {}
        _ => return TestResult::Fail("training step 1 differs from phy.c"),
    }
    // Count 2 (even): collect reopens for 30 ms, no swap, no program.
    match antdiv.step() {
        Work::Training {
            period_ms: 30,
            set_ant: None,
        } if antdiv.training_count() == 3 && antdiv.get_stats() => {}
        _ => return TestResult::Fail("training step 2 differs from phy.c"),
    }
    antdiv.parse(PpduClass::NonLegacy, 70, 0);
    // Count 3: decision. Main 50 vs aux 70, EVMs tied at 0: RSSI
    // difference 20 > 4 selects RF_B; ANTSEL programs the AUX default.
    match antdiv.step() {
        Work::Decision { set_ant }
            if antdiv.antenna_tx() == RF_B
                && antdiv.training_count() == 0
                && !antdiv.get_stats()
                && set_ant[0].2 == 1 => {}
        _ => return TestResult::Fail("decision step differs from phy.c"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_work_cycle_follows_phy
);

fn smoke_rtw89_8851b_antdiv_decision_prefers_evm_then_rssi() -> TestResult {
    // EVM decides first: main EVM 20 beats aux EVM 5 by more than 8,
    // even though aux RSSI 90 beats main RSSI 50 by far more than 4.
    let mut antdiv = AntDiv::new(RF_A, RF_A);
    antdiv.get_stats = true;
    antdiv.parse(PpduClass::NonLegacy, 50, 20);
    antdiv.antenna_rx = RF_B;
    antdiv.parse(PpduClass::NonLegacy, 90, 5);
    antdiv.training_count = 3;
    match antdiv.step() {
        Work::Decision { .. } if antdiv.antenna_tx() == RF_A => {}
        _ => return TestResult::Fail("EVM-first decision differs from phy.c"),
    }
    // No decision, through a real training cycle: collect on the
    // original antenna (RF_A), swap and collect on RF_B, then decide
    // with EVMs tied and RSSI difference 2 <= 4, so the antenna swaps
    // back to the original and ANTSEL programs the MAIN default.
    let mut antdiv = AntDiv::new(RF_A, RF_A);
    if !matches!(
        antdiv.step(),
        Work::Training {
            period_ms: 30,
            set_ant: None
        }
    ) {
        return TestResult::Fail("no-change cycle step 0 differs from phy.c");
    }
    antdiv.parse(PpduClass::NonLegacy, 50, 0);
    if !matches!(
        antdiv.step(),
        Work::Training {
            period_ms: 110,
            set_ant: Some(_)
        }
    ) {
        return TestResult::Fail("no-change cycle step 1 differs from phy.c");
    }
    if !matches!(
        antdiv.step(),
        Work::Training {
            period_ms: 30,
            set_ant: None
        }
    ) {
        return TestResult::Fail("no-change cycle step 2 differs from phy.c");
    }
    antdiv.parse(PpduClass::NonLegacy, 52, 0);
    match antdiv.step() {
        Work::Decision { set_ant } if antdiv.antenna_tx() == RF_A && set_ant[0].2 == 0 => {}
        _ => return TestResult::Fail("no-change swap-back differs from phy.c"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_decision_prefers_evm_then_rssi
);

/// Minimal `phy_operating` fake: register maps default to 0.
struct Fake {
    regs32: alloc::vec::Vec<(u32, u32)>,
    regs8: alloc::vec::Vec<(u32, u8)>,
}

impl Fake {
    fn new() -> Self {
        Self {
            regs32: alloc::vec::Vec::new(),
            regs8: alloc::vec::Vec::new(),
        }
    }

    fn read32_map(&self, address: u32) -> u32 {
        self.regs32
            .iter()
            .find(|(addr, _)| *addr == address)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    }

    fn read8_map(&self, address: u32) -> u8 {
        self.regs8
            .iter()
            .find(|(addr, _)| *addr == address)
            .map(|(_, value)| *value)
            .unwrap_or(0)
    }
}

impl power::Io for Fake {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        Ok(self.read8_map(address))
    }

    fn read16(&mut self, _address: u32) -> Result<u16, power::Error> {
        Ok(0)
    }

    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        Ok(self.read32_map(address))
    }

    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        match self.regs8.iter_mut().find(|(addr, _)| *addr == address) {
            Some(slot) => slot.1 = value,
            None => self.regs8.push((address, value)),
        }
        Ok(())
    }

    fn write16(&mut self, _address: u32, _value: u16) -> Result<(), power::Error> {
        Ok(())
    }

    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        match self.regs32.iter_mut().find(|(addr, _)| *addr == address) {
            Some(slot) => slot.1 = value,
            None => self.regs32.push((address, value)),
        }
        Ok(())
    }

    fn now_us(&self) -> u64 {
        0
    }

    async fn delay_us(&mut self, _us: u64) {}

    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Ok(None)
    }
}

impl phy_operating::Interface for Fake {
    fn admit(&mut self) -> Result<(), rfk::Error> {
        Ok(())
    }

    async fn xtal_write(&mut self, _address: u8, _value: u8, _mask: u8) -> Result<(), rfk::Error> {
        Ok(())
    }

    async fn xtal_read(&mut self, _address: u8) -> Result<u8, rfk::Error> {
        Ok(0)
    }
}

fn smoke_rtw89_8851b_antdiv_apply_masks_and_shifts() -> TestResult {
    // Masked 32-bit apply: stale nibble replaced, other bits kept.
    let mut fake = Fake::new();
    fake.regs32.push((0x1_586C, 0xFFFF));
    if apply_controls(&mut fake, &[(0x1_586C, 0xF0, 5)]).is_err()
        || fake.read32_map(0x1_586C) != 0xFF5F
    {
        return TestResult::Fail("apply_controls mask differs from write32_mask");
    }
    // A u32::MAX read is gone, not a value.
    fake.regs32.push((0x1_5868, u32::MAX));
    if apply_controls(&mut fake, &[(0x1_5868, 1, 0)]).is_ok() {
        return TestResult::Fail("apply_controls gone read differs from Access");
    }
    // Masking-defeating write8: the unshifted GPIO17 value 0x08 lands
    // on bit 7 (0x80), and the stale high nibble is cleared.
    let mut fake = Fake::new();
    fake.regs8.push((0x02D8, 0xFF));
    if apply_mac8(&mut fake, &[(0x02D8, 0xF0, 0x08)]).is_err() || fake.read8_map(0x02D8) != 0x8F {
        return TestResult::Fail("apply_mac8 shift differs from write8_mask");
    }
    // GPIO16 on a clean register: value 0x08 lands on bit 3.
    let mut fake = Fake::new();
    if apply_mac8(&mut fake, &[(0x02D8, 0x0F, 0x08)]).is_err() || fake.read8_map(0x02D8) != 0x08 {
        return TestResult::Fail("apply_mac8 low nibble differs from write8_mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8851b_antdiv_apply_masks_and_shifts
);
