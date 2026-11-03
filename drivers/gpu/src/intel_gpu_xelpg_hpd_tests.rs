//! Native register-model fixtures for the MTL hotplug owner.
extern crate alloc;

use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

/// PICA + south-display register file with the source W1C semantics:
/// IIRs are fully W1C, per-port hotplug control status bits are W1C,
/// everything else is plain RW. Pulses latch only while the pin's
/// detection enable is set.
#[derive(Debug)]
pub struct HpdFake {
    regs: RefCell<BTreeMap<u64, u32>>,
    pub writes: RefCell<Vec<(u64, u32)>>,
    pub access: Cell<bool>,
}

impl Default for HpdFake {
    fn default() -> Self {
        Self::new()
    }
}

impl HpdFake {
    pub fn new() -> Self {
        Self {
            regs: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            access: Cell::new(true),
        }
    }
    pub fn set(&self, off: u64, value: u32) {
        self.regs.borrow_mut().insert(off, value);
    }
    pub fn get(&self, off: u64) -> u32 {
        self.regs.borrow().get(&off).copied().unwrap_or(0)
    }
    fn w1c(off: u64) -> u32 {
        if off == PICA_IIR || off == SDE_IIR {
            return u32::MAX;
        }
        if off == SHOTPLUG_CTL_DDI {
            return 0x3333;
        }
        if off == SHOTPLUG_CTL_TC {
            return 0x33_3333;
        }
        if (0..4).any(|tc| off == port_hotplug_ctl(tc)) {
            return 0x33;
        }
        0
    }
    /// Latch a Type-C pulse (DP-alt or TBT) if detection is enabled.
    pub fn pulse_tc(&self, tc: u8, long: bool, tbt: bool) {
        let off = port_hotplug_ctl(tc);
        let ctl = self.get(off);
        let (enable, bit) = match (tbt, long) {
            (false, true) => (DP_ALT_HOTPLUG_ENABLE, DP_ALT_HPD_LONG_DETECT),
            (false, false) => (DP_ALT_HOTPLUG_ENABLE, DP_ALT_HPD_SHORT_DETECT),
            (true, true) => (TBT_HOTPLUG_ENABLE, TBT_HPD_LONG_DETECT),
            (true, false) => (TBT_HOTPLUG_ENABLE, TBT_HPD_SHORT_DETECT),
        };
        if ctl & enable != 0 {
            self.set(off, ctl | bit);
        }
    }
    /// Latch a DDI B pulse if detection is enabled.
    pub fn pulse_ddi_b(&self, long: bool) {
        let ctl = self.get(SHOTPLUG_CTL_DDI);
        if ctl & shotplug_ddi_enable(1) != 0 {
            let bit = if long {
                shotplug_ddi_long(1)
            } else {
                shotplug_ddi_short(1)
            };
            self.set(SHOTPLUG_CTL_DDI, ctl | bit);
        }
    }
    pub fn writes_to(&self, off: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == off)
            .map(|(_, v)| *v)
            .collect()
    }
    pub fn position(&self, off: u64) -> Option<usize> {
        self.writes.borrow().iter().position(|(o, _)| *o == off)
    }
}

impl MmioWindow for HpdFake {
    fn display_access_ok(&self) -> bool {
        self.access.get()
    }
    fn read32(&self, off: u64) -> u32 {
        if !self.access.get() {
            return u32::MAX;
        }
        self.get(off)
    }
    fn write32(&self, off: u64, value: u32) {
        if !self.access.get() {
            return;
        }
        self.writes.borrow_mut().push((off, value));
        let mask = Self::w1c(off);
        let old = self.get(off);
        self.set(off, (old & mask & !value) | (value & !mask));
    }
}

fn drain(monitor: &mut MtlHpdMonitor, io: &HpdFake) -> Vec<MtlHpdEvent> {
    let mut out = Vec::new();
    while let Some(event) = monitor.poll(io) {
        out.push(event);
        if out.len() > 16 {
            break;
        }
    }
    out
}

fn smoke_mtl_hpd_setup_masks_before_enable_and_baselines() -> TestResult {
    let io = HpdFake::new();
    // Live: TC1 DP-alt and DDI B. Inherited state: stale owned latches,
    // a foreign DDI A W1C status, foreign PICA AUX IER/IIR bits.
    io.set(PICA_ISR, pica_dp_alt_hotplug(0));
    io.set(SDE_ISR, sde_ddi_hotplug(1));
    io.set(PICA_IER, 0xF00);
    io.set(PICA_IIR, pica_dp_alt_hotplug(2) | 0x100);
    io.set(SDE_IIR, sde_ddi_hotplug(1) | sde_ddi_hotplug(0));
    io.set(port_hotplug_ctl(1), DP_ALT_HPD_LONG_DETECT);
    io.set(
        SHOTPLUG_CTL_DDI,
        shotplug_ddi_long(1) | shotplug_ddi_long(0) | 0x8,
    );
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let events = drain(&mut monitor, &io);
    if events
        != [
            MtlHpdEvent {
                pin: MtlHpdPin::DdiB,
                kind: MtlHpdKind::Connected(LiveMode::Native),
            },
            MtlHpdEvent {
                pin: MtlHpdPin::Tc1,
                kind: MtlHpdKind::Connected(LiveMode::DpAlt),
            },
        ]
    {
        return TestResult::Fail("initial detection must publish exactly the live pins");
    }
    let owned = MtlHpdMonitor::owned_pica();
    // IMR installed (masked) before IER enables the latch sources.
    let (imr, ier) = match (io.position(PICA_IMR), io.position(PICA_IER)) {
        (Some(a), Some(b)) => (a, b),
        _ => return TestResult::Fail("PICA IMR/IER not programmed"),
    };
    let (simr, sier) = match (io.position(SDE_IMR), io.position(SDE_IER)) {
        (Some(a), Some(b)) => (a, b),
        _ => return TestResult::Fail("SDE IMR/IER not programmed"),
    };
    if imr > ier || simr > sier {
        return TestResult::Fail("IMR must be masked and verified before IER");
    }
    if io.get(PICA_IMR) & owned != owned
        || io.get(PICA_IER) != 0xF00 | owned
        || io.get(SDE_IMR) & sde_ddi_hotplug(1) == 0
        || io.get(SDE_IER) & sde_ddi_hotplug(1) == 0
    {
        return TestResult::Fail("owned sources must be IER-enabled and IMR-masked");
    }
    // Owned IIR acknowledged; foreign AUX/DDI A IIR untouched.
    if io.get(PICA_IIR) != 0x100 || io.get(SDE_IIR) != sde_ddi_hotplug(0) {
        return TestResult::Fail("only owned IIR bits may be acknowledged");
    }
    // Source south setup: 250us filter and the MTP inversion.
    if io.get(SHPD_FILTER_CNT) != SHPD_FILTER_CNT_250
        || io.get(SOUTH_CHICKEN1) & MTP_HPD_INVERT != MTP_HPD_INVERT
    {
        return TestResult::Fail("SHPD filter / HPD invert not programmed");
    }
    for tc in 0..4u8 {
        let ctl = io.get(port_hotplug_ctl(tc));
        if ctl != TBT_HOTPLUG_ENABLE | DP_ALT_HOTPLUG_ENABLE {
            return TestResult::Fail("TC detection must be enabled with latches cleared");
        }
    }
    // DDI B enabled and its stale LONG cleared; DDI A's foreign LONG and
    // enable preserved.
    if io.get(SHOTPLUG_CTL_DDI) != shotplug_ddi_enable(1) | shotplug_ddi_long(0) | 0x8 {
        return TestResult::Fail("SHOTPLUG_CTL_DDI must clear owned status only");
    }
    // Legacy TC sources stay unowned without a legacy declaration.
    if !io.writes_to(SHOTPLUG_CTL_TC).is_empty() || io.get(SDE_IMR) & 0x0F00_0000 != 0 {
        return TestResult::Fail("undeclared legacy TC sources must stay unowned");
    }
    if monitor.status(MtlHpdPin::Tc2) != ConnectorStatus::Disconnected
        || monitor.status(MtlHpdPin::DdiB) != ConnectorStatus::Connected(LiveMode::Native)
    {
        return TestResult::Fail("published connector status wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hpd",
    smoke_mtl_hpd_setup_masks_before_enable_and_baselines
);

fn smoke_mtl_hpd_long_pulse_connect_redetect_disconnect() -> TestResult {
    let io = HpdFake::new();
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    if !drain(&mut monitor, &io).is_empty() || !monitor.initialized() {
        return TestResult::Fail("empty ports must initialize without events");
    }
    // Plug on TC3: level up + long pulse.
    io.set(PICA_ISR, pica_dp_alt_hotplug(2));
    io.pulse_tc(2, true, false);
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: MtlHpdPin::Tc3,
            kind: MtlHpdKind::Connected(LiveMode::DpAlt),
        }]
    {
        return TestResult::Fail("long pulse + live level must connect TC3");
    }
    // The handler wrote the read value back: the latch is consumed.
    if io.get(port_hotplug_ctl(2)) & 0x33 != 0 {
        return TestResult::Fail("TC3 latch must be acknowledged");
    }
    // A second long pulse while still connected: re-detect.
    io.pulse_tc(2, true, false);
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: MtlHpdPin::Tc3,
            kind: MtlHpdKind::Redetect,
        }]
    {
        return TestResult::Fail("long pulse on a connected pin must request re-detection");
    }
    // Long pulse with the level low: unplug.
    io.set(PICA_ISR, 0);
    io.pulse_tc(2, true, false);
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: MtlHpdPin::Tc3,
            kind: MtlHpdKind::Disconnected,
        }]
        || monitor.status(MtlHpdPin::Tc3) != ConnectorStatus::Disconnected
    {
        return TestResult::Fail("long pulse + low level must disconnect TC3");
    }
    // Plug then IRQ_HPD before the consumer polls: the status change
    // dominates the coalesced short pulse.
    io.set(PICA_ISR, pica_dp_alt_hotplug(2));
    io.pulse_tc(2, true, false);
    let _ = monitor.poll(&io);
    io.pulse_tc(2, false, false);
    if monitor.status(MtlHpdPin::Tc3) != ConnectorStatus::Connected(LiveMode::DpAlt) {
        return TestResult::Fail("status must track the reconnect");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hpd",
    smoke_mtl_hpd_long_pulse_connect_redetect_disconnect
);

fn smoke_mtl_hpd_short_pulse_and_low_level_never_unplug() -> TestResult {
    let io = HpdFake::new();
    io.set(SDE_ISR, sde_ddi_hotplug(1));
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let _ = drain(&mut monitor, &io);
    // IRQ_HPD with the level momentarily low: short pulse only.
    io.set(SDE_ISR, 0);
    io.pulse_ddi_b(false);
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: MtlHpdPin::DdiB,
            kind: MtlHpdKind::ShortPulse,
        }]
    {
        return TestResult::Fail("short pulse must not be read as unplug");
    }
    // A low level without any latched pulse proves nothing.
    if !drain(&mut monitor, &io).is_empty()
        || monitor.status(MtlHpdPin::DdiB) != ConnectorStatus::Connected(LiveMode::Native)
    {
        return TestResult::Fail("a single low sample must not unplug");
    }
    // Short pulses on a disconnected pin are dropped.
    io.pulse_tc(0, false, false);
    if !drain(&mut monitor, &io).is_empty() {
        return TestResult::Fail("short pulse on a disconnected pin must be ignored");
    }
    // A short TBT pulse also counts as a pulse on its TC pin.
    io.set(PICA_ISR, pica_tbt_hotplug(3));
    io.pulse_tc(3, true, true);
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: MtlHpdPin::Tc4,
            kind: MtlHpdKind::Connected(LiveMode::TbtAlt),
        }]
    {
        return TestResult::Fail("TBT long pulse must publish a TBT-alt connection");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hpd",
    smoke_mtl_hpd_short_pulse_and_low_level_never_unplug
);

fn smoke_mtl_hpd_live_mode_decode_and_legacy_declaration() -> TestResult {
    let tc2 = MtlHpdPin::Tc2;
    if live_mode(tc2, false, pica_tbt_hotplug(1), 0) != Some(LiveMode::TbtAlt)
        || live_mode(tc2, false, pica_tbt_hotplug(1) | pica_dp_alt_hotplug(1), 0)
            != Some(LiveMode::DpAlt)
        || live_mode(tc2, false, 0, sde_tc_hotplug(1)).is_some()
        || live_mode(tc2, true, pica_dp_alt_hotplug(1), sde_tc_hotplug(1)) != Some(LiveMode::Legacy)
        || live_mode(tc2, false, pica_dp_alt_hotplug(0), 0).is_some()
        || live_mode(MtlHpdPin::DdiB, false, u32::MAX >> 1, sde_ddi_hotplug(0)).is_some()
    {
        return TestResult::Fail("live mode decode must follow xelpdp_tc_phy_hpd_live_status");
    }
    // A declared legacy TC2 owns its SDE source and SHOTPLUG_CTL_TC nibble.
    let io = HpdFake::new();
    io.set(SDE_ISR, sde_tc_hotplug(1));
    io.set(SHOTPLUG_CTL_TC, icp_tc_hpd_long(0)); // foreign TC1 latch
    let mut config = MtlHpdConfig::TYPE_C;
    config.legacy_tc[1] = true;
    let mut monitor = MtlHpdMonitor::new(config);
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: tc2,
            kind: MtlHpdKind::Connected(LiveMode::Legacy),
        }]
    {
        return TestResult::Fail("declared legacy TC2 must be detected through SDE");
    }
    if io.get(SHOTPLUG_CTL_TC) != icp_tc_hpd_enable(1) | icp_tc_hpd_long(0)
        || io.get(SDE_IER) & sde_tc_hotplug(1) == 0
        || io.get(SDE_IMR) & sde_tc_hotplug(1) == 0
    {
        return TestResult::Fail("legacy TC2 source must be owned; TC1 latch preserved");
    }
    // Legacy long pulse with the level low disconnects.
    io.set(SDE_ISR, 0);
    io.set(
        SHOTPLUG_CTL_TC,
        io.get(SHOTPLUG_CTL_TC) | icp_tc_hpd_long(1),
    );
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: tc2,
            kind: MtlHpdKind::Disconnected,
        }]
        || io.get(SHOTPLUG_CTL_TC) & icp_tc_hpd_long(0) == 0
    {
        return TestResult::Fail("legacy unplug must decode while preserving foreign latches");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hpd",
    smoke_mtl_hpd_live_mode_decode_and_legacy_declaration
);

fn smoke_mtl_hpd_access_loss_is_uncertain_until_teardown() -> TestResult {
    let io = HpdFake::new();
    io.set(PICA_ISR, pica_dp_alt_hotplug(0));
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    let _ = drain(&mut monitor, &io);
    io.pulse_tc(0, true, false);
    io.access.set(false);
    if monitor.poll(&io).is_some()
        || !monitor.uncertain()
        || monitor.status(MtlHpdPin::Tc1) != ConnectorStatus::Unknown
    {
        return TestResult::Fail("lost authority must be uncertain, never an event");
    }
    io.access.set(true);
    if monitor.poll(&io).is_some() {
        return TestResult::Fail("restored access alone must not resume an uncertain monitor");
    }
    // Teardown (reset/suspend) withdraws the owned sources and clears the
    // latch so the next incarnation cannot inherit the old LONG.
    if !monitor.teardown(&io) {
        return TestResult::Fail("teardown with authority must prove withdrawal");
    }
    let owned = MtlHpdMonitor::owned_pica();
    if io.get(PICA_IER) & owned != 0
        || io.get(PICA_IMR) & owned != owned
        || io.get(SDE_IER) & sde_ddi_hotplug(1) != 0
        || io.get(port_hotplug_ctl(0)) != 0
        || io.get(SHOTPLUG_CTL_DDI) & shotplug_ddi_enable(1) != 0
    {
        return TestResult::Fail("teardown must disable owned IER and detection");
    }
    if monitor.initialized() || monitor.uncertain() {
        return TestResult::Fail("teardown must leave a fresh incarnation");
    }
    // Resume: fresh baseline reports the live sink once.
    if drain(&mut monitor, &io)
        != [MtlHpdEvent {
            pin: MtlHpdPin::Tc1,
            kind: MtlHpdKind::Connected(LiveMode::DpAlt),
        }]
    {
        return TestResult::Fail("resume must rebuild the baseline from live levels");
    }
    // Teardown without authority resets state but reports refusal.
    io.access.set(false);
    if monitor.teardown(&io) || monitor.initialized() {
        return TestResult::Fail("teardown without authority must report failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hpd",
    smoke_mtl_hpd_access_loss_is_uncertain_until_teardown
);

fn smoke_mtl_hpd_generation_gate_and_imr_refusal() -> TestResult {
    struct NoAccess;
    impl MmioWindow for NoAccess {
        fn read32(&self, _: u64) -> u32 {
            panic!("non-MTL HPD read");
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("non-MTL HPD write");
        }
    }
    for generation in [
        crate::intel_gpu::Generation::TigerLake,
        crate::intel_gpu::Generation::AlderLake,
        crate::intel_gpu::Generation::LunarLake,
        crate::intel_gpu::Generation::PantherLake,
    ] {
        if poll_hpd_event(&NoAccess, generation).is_some() || !teardown_hpd(&NoAccess, generation) {
            return TestResult::Fail("non-MTL generations must not touch the MTL HPD block");
        }
    }
    // An IMR that refuses the mask must stop setup before IER.
    #[derive(Debug)]
    struct StuckImr(HpdFake);
    impl MmioWindow for StuckImr {
        fn display_access_ok(&self) -> bool {
            self.0.display_access_ok()
        }
        fn read32(&self, off: u64) -> u32 {
            if off == PICA_IMR {
                0
            } else {
                self.0.read32(off)
            }
        }
        fn write32(&self, off: u64, value: u32) {
            self.0.write32(off, value)
        }
    }
    let io = StuckImr(HpdFake::new());
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    if monitor.poll(&io).is_some() || !monitor.uncertain() || io.0.position(PICA_IER).is_some() {
        return TestResult::Fail("unverified IMR must refuse before enabling IER");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hpd",
    smoke_mtl_hpd_generation_gate_and_imr_refusal
);

fn smoke_mtl_hpd_fresh_teardown_touches_nothing() -> TestResult {
    struct Panics;
    impl MmioWindow for Panics {
        fn read32(&self, _: u64) -> u32 {
            panic!("fresh teardown read a register");
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("fresh teardown wrote a register");
        }
    }
    // A monitor that never initialized owns no source: suspend/reset
    // teardown completes without register access.
    let mut monitor = MtlHpdMonitor::new(MtlHpdConfig::TYPE_C);
    if !monitor.teardown(&Panics) || monitor.initialized() || monitor.uncertain() {
        return TestResult::Fail("fresh teardown must be a complete no-op");
    }
    // After a real baseline the same call withdraws the sources.
    let io = HpdFake::new();
    let _ = drain(&mut monitor, &io);
    let before = io.writes.borrow().len();
    if !monitor.teardown(&io) || io.writes.borrow().len() == before {
        return TestResult::Fail("initialized teardown must withdraw owned sources");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_hpd",
    smoke_mtl_hpd_fresh_teardown_touches_nothing
);
