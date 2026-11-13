use super::super::Chip;
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Read(u64),
    Write(u64, u32),
    Wait(u64, u32, u32, u64),
}

#[derive(Default)]
struct Model {
    registers: BTreeMap<u64, u32>,
    ops: Vec<Op>,
    revoked: bool,
}

impl RegisterIo for Model {
    fn authorized(&self) -> bool {
        !self.revoked
    }
    fn read32(&mut self, offset: u64) -> u32 {
        self.ops.push(Op::Read(offset));
        *self.registers.get(&offset).unwrap_or(&0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.ops.push(Op::Write(offset, value));
        self.registers.insert(offset, value);
    }
    fn wait_us(
        &mut self,
        offset: u64,
        mask: u32,
        expected: u32,
        timeout_us: u64,
    ) -> Result<u32, BringUpError> {
        // Single-shot, no scheduler spin.
        self.ops.push(Op::Wait(offset, mask, expected, timeout_us));
        let value = self.read32(offset);
        if value == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        if value & mask == expected {
            Ok(value)
        } else {
            Err(BringUpError::Timeout)
        }
    }
}

fn rev(chip: Chip, mac_rev: u8) -> Revision {
    Revision {
        chip,
        mac_rev,
        pcie: true,
    }
}

fn last_write(ops: &[Op], addr: u64) -> Option<u32> {
    ops.iter().rev().find_map(|op| match op {
        Op::Write(a, v) if *a == addr => Some(*v),
        _ => None,
    })
}

fn wrote(ops: &[Op], addr: u64) -> bool {
    ops.iter()
        .any(|op| matches!(op, Op::Write(a, _) if *a == addr))
}

fn smoke_ath9k_gen_timer_config_matches_linux() -> TestResult {
    // `hw.c:3072` `gen_tmr_configuration`, literal: timers 0..7 share
    // the NDP registers with mode mask `0x0080`; timers 8..15 step the
    // NDP2 registers by 4 per slot with mode mask `0x0001 << (i - 8)`.
    const LINUX: [(u64, u64, u64, u32); MAX_GEN_TIMER] = [
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x821c, 0x823c, 0x8240, 0x0080),
        (0x8180, 0x81a0, 0x81c0, 0x0001),
        (0x8184, 0x81a4, 0x81c0, 0x0002),
        (0x8188, 0x81a8, 0x81c0, 0x0004),
        (0x818c, 0x81ac, 0x81c0, 0x0008),
        (0x8190, 0x81b0, 0x81c0, 0x0010),
        (0x8194, 0x81b4, 0x81c0, 0x0020),
        (0x8198, 0x81b8, 0x81c0, 0x0040),
        (0x819c, 0x81bc, 0x81c0, 0x0080),
    ];
    for (index, (next, period, mode, mask)) in LINUX.iter().enumerate() {
        let cfg = config(index as u8);
        if cfg.next_addr != *next
            || cfg.period_addr != *period
            || cfg.mode_addr != *mode
            || cfg.mode_mask != *mask
        {
            return TestResult::Fail("gen-timer config row differs from Linux");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/gen_timer",
    smoke_ath9k_gen_timer_config_matches_linux
);

fn smoke_ath9k_gen_timer_alloc_sets_tsf2_enabled_and_restarts() -> TestResult {
    let revision = rev(Chip::Ar9462, 2);
    let mut table = GenTimerTable::default();
    if table.tsf2_enabled() || table.timer_mask() != 0 || table.timer(8).is_some() {
        return TestResult::Fail("gen-timer table did not start empty");
    }
    // `start_tsf2` with no TSF2 timer is a no-op: no register traffic.
    let mut model = Model::default();
    if table.start_tsf2(&mut model).is_err() || !model.ops.is_empty() {
        return TestResult::Fail("start_tsf2 wrote with no TSF2 timer enabled");
    }
    // Below the first generic timer, and past the table, are refused.
    if table.alloc(&mut model, &revision, 6, false, false).is_ok()
        || table.alloc(&mut model, &revision, 16, false, false).is_ok()
    {
        return TestResult::Fail("gen-timer alloc admitted an out-of-range index");
    }
    // A bank-1 timer does not enable TSF2 and writes nothing to the
    // TSF2 restart registers.
    let timer7 = match table.alloc(&mut model, &revision, 7, false, false) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 7"),
    };
    if timer7.index != 7 || table.tsf2_enabled() || wrote(&model.ops, 0x83a0) {
        return TestResult::Fail("bank-1 alloc enabled TSF2 or touched it");
    }
    // The first TSF2 alloc enables TSF2 and restarts it: `AR_DC_AP_STA_EN`
    // in `AR_DIRECT_CONNECT`, `AR_RESET_TSF2_ONCE` in `AR_RESET_TSF`.
    let timer8 = match table.alloc(&mut model, &revision, 8, true, false) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 8"),
    };
    if !table.tsf2_enabled()
        || table.timer(8) != Some(timer8)
        || last_write(&model.ops, 0x83a0) != Some(0x0000_0001)
        || last_write(&model.ops, 0x8020) != Some(0x0200_0000)
    {
        return TestResult::Fail("first TSF2 alloc did not enable and restart TSF2");
    }
    // A second TSF2 alloc keeps the flag but does not restart TSF2 again.
    if table.alloc(&mut model, &revision, 9, false, false).is_err()
        || model
            .ops
            .iter()
            .filter(|op| matches!(op, Op::Write(0x8020, _)))
            .count()
            != 1
    {
        return TestResult::Fail("second TSF2 alloc restarted TSF2 again");
    }
    // A live slot cannot be allocated twice (Linux overwrites it; this
    // tree refuses so a double-alloc is a loud bug, not a silent leak).
    if table.alloc(&mut model, &revision, 8, false, false).is_ok() {
        return TestResult::Fail("gen-timer alloc admitted a live slot twice");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/gen_timer",
    smoke_ath9k_gen_timer_alloc_sets_tsf2_enabled_and_restarts
);

fn smoke_ath9k_gen_timer_start_programs_registers() -> TestResult {
    let revision = rev(Chip::Ar9462, 2);
    let mut table = GenTimerTable::default();
    let mut model = Model::default();
    let timer = match table.alloc(&mut model, &revision, 9, true, true) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 9"),
    };
    if table
        .start(&mut model, &revision, &timer, 0x1111, 0x2222)
        .is_err()
    {
        return TestResult::Fail("gen-timer start faulted");
    }
    // Next/period land in the timer's NDP2 registers, the mode bit is
    // set, TSF2 is selected for the bank-2 timer, and both S5 interrupt
    // bits are armed: trigger `(1 << 9) & 0xFF80 = 0x200`, threshold
    // `((1 << 9) << 16) & 0xFF800000 = 0x02000000`.
    if last_write(&model.ops, 0x8184) != Some(0x1111)
        || last_write(&model.ops, 0x81a4) != Some(0x2222)
        || last_write(&model.ops, 0x81c0) != Some(0x0002)
        || last_write(&model.ops, 0x83d8) != Some(0x0200)
        || last_write(&model.ops, 0x00b8) != Some(0x0200_0200)
        || table.timer_mask() != 1 << 9
    {
        return TestResult::Fail("gen-timer start mis-programmed timer 9");
    }
    // A bank-1 timer selects TSF (bit cleared) and its trigger bit is
    // `(1 << 7) & 0xFF80 = 0x80`.
    let mut model = Model::default();
    let timer7 = match table.alloc(&mut model, &revision, 7, true, false) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 7"),
    };
    if table
        .start(&mut model, &revision, &timer7, 0x3333, 0x4444)
        .is_err()
        || last_write(&model.ops, 0x821c) != Some(0x3333)
        || last_write(&model.ops, 0x823c) != Some(0x4444)
        || last_write(&model.ops, 0x8240) != Some(0x0080)
        || last_write(&model.ops, 0x83d8) != Some(0)
        || last_write(&model.ops, 0x00b8) != Some(0x0080)
    {
        return TestResult::Fail("gen-timer start mis-programmed timer 7");
    }
    // AR9300 has no TSF-select programming at all.
    let mut table = GenTimerTable::default();
    let mut model = Model::default();
    let revision = rev(Chip::Ar9300, 0);
    let timer = match table.alloc(&mut model, &revision, 8, true, true) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 8 on AR9300"),
    };
    if table
        .start(&mut model, &revision, &timer, 0x5555, 0x6666)
        .is_err()
        || wrote(&model.ops, 0x83d8)
    {
        return TestResult::Fail("gen-timer start programmed TSF select on AR9300");
    }
    // Starting a timer this table never allocated is refused.
    let foreign = GenTimer {
        index: 10,
        trigger: false,
        overflow: false,
    };
    if table.start(&mut model, &revision, &foreign, 0, 0).is_ok() {
        return TestResult::Fail("gen-timer start admitted a foreign timer");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/gen_timer",
    smoke_ath9k_gen_timer_start_programs_registers
);

fn smoke_ath9k_gen_timer_stop_clears_mode_and_mask() -> TestResult {
    let revision = rev(Chip::Ar9462, 2);
    let mut table = GenTimerTable::default();
    let mut model = Model::default();
    let timer = match table.alloc(&mut model, &revision, 8, true, true) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 8"),
    };
    if table
        .start(&mut model, &revision, &timer, 0x1111, 0x2222)
        .is_err()
    {
        return TestResult::Fail("gen-timer start faulted");
    }
    if table.stop(&mut model, &revision, &timer).is_err() {
        return TestResult::Fail("gen-timer stop faulted");
    }
    // Mode bit, TSF select, and both S5 bits are cleared; the mask bit
    // drops. The slot stays allocated and TSF2 stays enabled (sticky).
    if last_write(&model.ops, 0x81c0) != Some(0)
        || last_write(&model.ops, 0x83d8) != Some(0)
        || last_write(&model.ops, 0x00b8) != Some(0)
        || table.timer_mask() != 0
        || table.timer(8) != Some(timer)
        || !table.tsf2_enabled()
    {
        return TestResult::Fail("gen-timer stop did not clear mode, select, and mask");
    }
    // Freeing releases the slot but keeps the sticky TSF2 fact; freeing
    // a stale copy cannot release a timer re-allocated at the index.
    table.free(timer);
    if table.timer(8).is_some() || !table.tsf2_enabled() {
        return TestResult::Fail("gen-timer free did not release the slot");
    }
    let timer = match table.alloc(&mut model, &revision, 8, false, false) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer re-alloc refused index 8"),
    };
    table.free(GenTimer {
        index: 8,
        trigger: true,
        overflow: true,
    });
    if table.timer(8) != Some(timer) {
        return TestResult::Fail("stale free released a live timer");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/gen_timer",
    smoke_ath9k_gen_timer_stop_clears_mode_and_mask
);

fn smoke_ath9k_gen_timer_isr_reports_fired() -> TestResult {
    let revision = rev(Chip::Ar9462, 2);
    let mut table = GenTimerTable::default();
    let mut model = Model::default();
    let timer8 = match table.alloc(&mut model, &revision, 8, true, true) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 8"),
    };
    let timer9 = match table.alloc(&mut model, &revision, 9, true, true) {
        Ok(timer) => timer,
        Err(_) => return TestResult::Fail("gen-timer alloc refused index 9"),
    };
    // Before either timer starts, the mask is empty: nothing reports.
    if table.isr(0xffff_ffff, 0xffff_ffff) != GenTimerEvents::default() {
        return TestResult::Fail("gen-timer ISR reported before any timer started");
    }
    if table.start(&mut model, &revision, &timer8, 0, 0).is_err()
        || table.start(&mut model, &revision, &timer9, 0, 0).is_err()
    {
        return TestResult::Fail("gen-timer start faulted");
    }
    // Raw S5 words: trigger bits 8 and 10 set, threshold bit 25 set
    // (timer 9's threshold is bit `9 + 16`). Timer 8 reports a trigger,
    // timer 9 reports an overflow (its trigger is suppressed), and the
    // unallocated timer 10 reports nothing.
    let events = table.isr(0x0000_0500, 0x0200_0000);
    if events.trigger != 1 << 8 || events.overflow != 1 << 9 {
        return TestResult::Fail("gen-timer ISR mis-reported the fired timers");
    }
    if table.isr(0, 0) != GenTimerEvents::default() {
        return TestResult::Fail("gen-timer ISR reported on a quiet S5");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/gen_timer",
    smoke_ath9k_gen_timer_isr_reports_fired
);
