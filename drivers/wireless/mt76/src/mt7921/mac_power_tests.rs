//! The real probe sequence over a stateful HIF register window, including
//! checked fixed/L1 translations. No elapsed-wall-clock waits in this model.
use super::{mac::PowerError, mac_power, registers, regs::*};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Hif {
    did: u16,
    selector: u32,
    own: u32,
    reset: u32,
    now: u64,
    asserted: Option<u64>,
    resets: usize,
    stuck_own: bool,
    reset_rejected: bool,
    ready: bool,
    gone: bool,
    writes: Vec<(u32, u32)>,
    reads: Vec<u32>,
    holds: Vec<u64>,
}
impl Hif {
    fn new() -> Self {
        Self {
            did: MTK_DEV_MT7922,
            selector: 0xa5a51234,
            own: 4,
            reset: 0xa0000011,
            now: 0,
            asserted: None,
            resets: 0,
            stuck_own: false,
            reset_rejected: false,
            ready: true,
            gone: false,
            writes: Vec::new(),
            reads: Vec::new(),
            holds: Vec::new(),
        }
    }
    /// The reset register's L1 window on this fixture's chip: the
    /// CONNAC2 window (`0x40000 + 0x140`, page `0x1800` in the low
    /// selector half) or the MT7925 one (`0x130000 + 0x140`, page
    /// `0x7c00` in the high half).
    fn reset_window(&self) -> Option<u32> {
        if self.selector & 0xffff == 0x1800 {
            Some(MT_HIF_REMAP_BASE_L1 + 0x140)
        } else if self.selector >> 16 == 0x7c00 {
            Some(MT7925_HIF_REMAP_BASE_L1 + 0x140)
        } else {
            None
        }
    }
}
impl registers::Io for Hif {
    fn len(&self) -> u64 {
        // Real 7925 BAR0 is 2 MiB (the 7925 selector needs it);
        // CONNAC2 keeps the 1 MiB probe BAR.
        if is_mt7925_did(self.did) {
            0x200000
        } else {
            0x100000
        }
    }
    fn read(&mut self, offset: u32) -> u32 {
        self.reads.push(offset);
        if self.gone {
            return u32::MAX;
        }
        if offset == MT_HIF_REMAP_L1 || offset == MT7925_HIF_REMAP_L1 {
            self.selector
        } else if offset == 0xe0010 {
            self.own
        } else if Some(offset) == self.reset_window() {
            self.reset
        } else {
            0
        }
    }
    fn write(&mut self, offset: u32, value: u32) {
        if offset == MT_HIF_REMAP_L1 || offset == MT7925_HIF_REMAP_L1 {
            self.selector = value;
        } else {
            self.writes.push((offset, value));
            if offset == 0xe0010 {
                if value == 1 {
                    self.own = 4;
                } else if value == 2 && !self.stuck_own {
                    self.own = 0;
                }
            } else if Some(offset) == self.reset_window() && !self.reset_rejected {
                if value & 1 == 0 {
                    self.asserted = Some(self.now);
                    self.reset = value & !16;
                    self.resets += 1;
                } else {
                    self.holds.push(self.now - self.asserted.take().unwrap());
                    self.reset = value | if self.ready { 16 } else { 0 };
                }
            }
        }
    }
}
impl mac_power::Io for Hif {
    fn sw_rst_b(&self) -> u32 {
        wfsys_sw_rst_b(self.did)
    }
    fn read(&mut self, address: u32) -> Result<u32, PowerError> {
        registers::transaction(self.did, self, address, None).map_err(|_| PowerError::InvalidWindow)
    }
    fn write(&mut self, address: u32, value: u32) -> Result<(), PowerError> {
        registers::transaction(self.did, self, address, Some(value))
            .map(|_| ())
            .map_err(|_| PowerError::InvalidWindow)
    }
    fn delay(&mut self, ms: u64) {
        self.now += ms;
    }
    fn poll(
        &mut self,
        address: u32,
        mask: u32,
        expected: u32,
        ms: u64,
    ) -> Result<bool, PowerError> {
        for _ in 0..=ms {
            let value = mac_power::Io::read(self, address)?;
            if value == u32::MAX {
                return Err(PowerError::DeviceGone);
            }
            if value & mask == expected {
                return Ok(true);
            }
            self.now += 1;
        }
        Ok(false)
    }
}

fn mt76_probe_power_normalizes_ownership_and_resets_before_dma() -> TestResult {
    let mut hif = Hif::new();
    if mac_power::initialize(&mut hif) != Ok(())
        || hif.writes[..2] != [(0xe0010, 1), (0xe0010, 2)]
        || hif.holds != vec![50]
        || hif.resets != 1
        || hif.reset & 0xa0000000 != 0xa0000000
        || hif.own != 0
        || hif.selector != 0xa5a51234
        || hif.writes.iter().any(|(offset, _)| *offset == 0xd4208)
    {
        return TestResult::Fail("probe ownership/reset/selector order or inherited DMA changed");
    }
    for offset in [0xd4204, 0x10188, 0xd41f4] {
        if !hif.writes.contains(&(offset, 0)) {
            return TestResult::Fail("probe left an inherited host interrupt source enabled");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_probe_power_normalizes_ownership_and_resets_before_dma
);

fn mt76_probe_power_ownership_timeout_never_accesses_wfsys() -> TestResult {
    let mut hif = Hif::new();
    hif.stuck_own = true;
    if mac_power::initialize(&mut hif) != Err(PowerError::Timeout)
        || hif.resets != 0
        || !hif.holds.is_empty()
        || hif.own != 4
        || hif.now < 500
        || hif.now > 1000
        || hif.reads.iter().any(|offset| *offset != 0xe0010)
        || hif.writes.iter().any(|(offset, _)| *offset != 0xe0010)
    {
        return TestResult::Fail(
            "failed ownership accessed unowned radio registers or retried indefinitely",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_probe_power_ownership_timeout_never_accesses_wfsys
);

fn mt76_probe_power_rejects_gone_and_unverified_reset() -> TestResult {
    let mut hif = Hif::new();
    hif.gone = true;
    if mac_power::initialize(&mut hif) != Err(PowerError::DeviceGone) || hif.resets != 0 {
        return TestResult::Fail("unavailable function was reset or accepted");
    }
    let mut hif = Hif::new();
    hif.reset_rejected = true;
    if mac_power::initialize(&mut hif) != Err(PowerError::ResetRejected) || hif.resets != 0 {
        return TestResult::Fail("ignored reset assertion accepted");
    }
    let mut hif = Hif::new();
    hif.ready = false;
    if mac_power::initialize(&mut hif) != Err(PowerError::ResetTimeout)
        || hif.writes.contains(&(0x10188, 0))
    {
        return TestResult::Fail("reset readiness timeout did not stop the probe sequence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_probe_power_rejects_gone_and_unverified_reset
);

/// The MT7925 probe power sequence resets WFSYS at the CONNAC3
/// address (`0x7c000140`, L1 window `0x130140`), never the CONNAC2
/// address (`0x18000140`, window `0x40140`). Upstream
/// `mt7925/regs.h:92` at torvalds/linux 8d7fe9885c62.
fn mt76_probe_power_mt7925_reset_uses_connac3_address() -> TestResult {
    let mut hif = Hif::new();
    hif.did = MTK_DEV_MT7925;
    if mac_power::initialize(&mut hif) != Ok(())
        || hif.resets != 1
        || hif.holds != vec![50]
        || hif.selector != 0xa5a51234
        || !hif.writes.iter().any(|(offset, _)| *offset == 0x130140)
        || hif.writes.iter().any(|(offset, _)| *offset == 0x40140)
    {
        return TestResult::Fail("MT7925 probe reset used the CONNAC2 address or window");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921",
    mt76_probe_power_mt7925_reset_uses_connac3_address
);
