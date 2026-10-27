use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// A HUBPREQ/OTG register file with the flip latch: writing the low address
/// arms a flip (FLIP_PENDING) that latches into EARLIEST_INUSE after
/// `latch_after` reads of FLIP_CONTROL (None: never, a stuck pipe).
struct Fake {
    values: Vec<u32>,
    writes: Vec<(u64, u32)>,
    armed: Option<u64>,
    latch_after: Option<u32>,
    gone: bool,
    /// Frame count advances on every read of it, to model a racing vsync.
    racing: u32,
}
impl Fake {
    fn new() -> Self {
        Self {
            values: vec![0; LAST_REG as usize + 1],
            writes: Vec::new(),
            armed: None,
            latch_after: Some(2),
            gone: false,
            racing: 0,
        }
    }
}
impl Io for Fake {
    fn read(&mut self, reg: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        if reg % HUBP_STRIDE == FLIP_CONTROL % HUBP_STRIDE && reg < OTG_V_BLANK_START_END {
            if let (Some(address), Some(n)) = (self.armed, self.latch_after.as_mut()) {
                if *n == 0 {
                    let pipe = (reg - FLIP_CONTROL) / HUBP_STRIDE;
                    self.values[(EARLIEST_INUSE + pipe * HUBP_STRIDE) as usize] = address as u32;
                    self.values[(EARLIEST_INUSE_HIGH + pipe * HUBP_STRIDE) as usize] =
                        (address >> 32) as u32;
                    self.values[reg as usize] &= !FLIP_PENDING;
                    self.armed = None;
                } else {
                    *n -= 1;
                }
            }
        }
        if reg >= OTG_STATUS_FRAME_COUNT
            && (reg - OTG_STATUS_FRAME_COUNT) % OTG_STRIDE == 0
            && self.racing > 0
        {
            self.racing -= 1;
            self.values[reg as usize] += 1;
        }
        self.values[reg as usize]
    }
    fn write(&mut self, reg: u64, value: u32) {
        self.writes.push((reg, value));
        self.values[reg as usize] = value;
        if reg % HUBP_STRIDE == PRIMARY_SURFACE_ADDRESS % HUBP_STRIDE && reg < OTG_V_BLANK_START_END
        {
            let pipe = (reg - PRIMARY_SURFACE_ADDRESS) / HUBP_STRIDE;
            let high = self.values[(PRIMARY_SURFACE_ADDRESS_HIGH + pipe * HUBP_STRIDE) as usize];
            self.armed = Some(u64::from(high) << 32 | u64::from(value));
            self.values[(FLIP_CONTROL + pipe * HUBP_STRIDE) as usize] |= FLIP_PENDING;
        }
    }
}
fn engine(pipe: u8) -> Engine<Fake> {
    Engine {
        io: Fake::new(),
        authority: Cap::bootstrap(),
        pipe,
        requested: None,
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
/// Counts wakes instead of sleeping.
struct Count(u32);
impl Wake for Count {
    async fn wait(&mut self, _: u64) {
        self.0 += 1;
    }
}

fn dcn30_flip_programs_vsync_flip_with_low_address_last() -> TestResult {
    let mut e = engine(2);
    let base = 2 * HUBP_STRIDE;
    // Stale immediate-flip, stereo and TMZ state from a previous owner.
    e.io.values[(base + FLIP_CONTROL) as usize] = FLIP_TYPE | STEREO;
    e.io.values[(base + SURFACE_CONTROL) as usize] = TMZ | 0x2;
    e.io.values[(base + VMID_SETTINGS_0) as usize] = 0x5;
    let address = 0x0001_2345_6700;
    if e.program_flip(address).is_err() {
        return TestResult::Fail("flip refused");
    }
    let writes = &e.io.writes;
    let low = writes
        .iter()
        .position(|&(r, _)| r == base + PRIMARY_SURFACE_ADDRESS);
    let high = writes
        .iter()
        .position(|&(r, _)| r == base + PRIMARY_SURFACE_ADDRESS_HIGH);
    if low != Some(writes.len() - 1) || high != Some(writes.len() - 2) {
        return TestResult::Fail("address halves out of order");
    }
    let v = &e.io.values;
    if v[(base + FLIP_CONTROL) as usize] & (FLIP_TYPE | STEREO) != 0
        || v[(base + SURFACE_CONTROL) as usize] != 0x2
        || v[(base + VMID_SETTINGS_0) as usize] != 0
        || v[(base + PRIMARY_SURFACE_ADDRESS_HIGH) as usize] != 0x1
        || v[(base + PRIMARY_SURFACE_ADDRESS) as usize] != 0x2345_6700
    {
        return TestResult::Fail("flip fields");
    }
    for bad in [0, 0x100_0000_0000_0000, 0x1_0000_0080] {
        if e.program_flip(bad) != Err(Error::Invalid) {
            return TestResult::Fail("invalid address accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_flip_programs_vsync_flip_with_low_address_last
);

fn dcn30_flip_completes_only_when_earliest_inuse_names_new_surface() -> TestResult {
    let mut e = engine(0);
    e.io.values[EARLIEST_INUSE as usize] = 0x1000;
    e.adopt(0x1000);
    if e.pending() != Ok(false) {
        return TestResult::Fail("adopted surface pending");
    }
    let _ = e.program_flip(0x2000);
    if e.pending() != Ok(true) {
        return TestResult::Fail("armed flip not pending");
    }
    let mut wake = Count(0);
    if run(e.wait_flip(1_000_000, &mut wake)).is_err() || e.in_use() != Ok(0x2000) {
        return TestResult::Fail("latched flip not observed");
    }
    // Pending cleared but the old surface is still the earliest in use.
    let _ = e.program_flip(0x3000);
    e.io.armed = None;
    e.io.values[FLIP_CONTROL as usize] &= !FLIP_PENDING;
    if e.pending() != Ok(true) {
        return TestResult::Fail("old surface still fetched counted as done");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_flip_completes_only_when_earliest_inuse_names_new_surface
);

fn dcn30_flip_timeout_and_device_loss_propagate() -> TestResult {
    let mut e = engine(1);
    e.io.latch_after = None;
    e.adopt(0x1000);
    let _ = e.program_flip(0x2000);
    let mut wake = Poll;
    if run(e.wait_flip(3_000, &mut wake)) != Err(Error::Timeout) {
        return TestResult::Fail("stuck flip did not time out");
    }
    // The flip stays requested: the old surface is still considered live.
    if e.pending() != Ok(true) || e.requested != Some(0x2000) {
        return TestResult::Fail("timeout forgot the outstanding flip");
    }
    e.io.gone = true;
    if run(e.wait_flip(3_000, &mut wake)) != Err(Error::DeviceGone) {
        return TestResult::Fail("device loss not reported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_flip_timeout_and_device_loss_propagate
);

fn dcn30_display_interrupts_follow_irq_service_dcn30() -> TestResult {
    let mut e = engine(3);
    let otg = OTG_GLOBAL_SYNC_STATUS + 3 * OTG_STRIDE;
    let hubp = FLIP_INTERRUPT + 3 * HUBP_STRIDE;
    // Pending events must not be acknowledged by an enable.
    e.io.values[otg as usize] = VSTARTUP_EVENT_CLEAR | VUPDATE_NO_LOCK_EVENT_CLEAR | 0x4;
    if e.set_interrupt(Interrupt::Vupdate, true).is_err()
        || e.io.values[otg as usize] != VUPDATE_NO_LOCK_INT_EN | 0x4
    {
        return TestResult::Fail("vupdate enable");
    }
    if e.set_interrupt(Interrupt::Vblank, true).is_err()
        || e.io.values[otg as usize] != VUPDATE_NO_LOCK_INT_EN | VSTARTUP_INT_EN | 0x4
    {
        return TestResult::Fail("vblank enable");
    }
    if e.ack(Interrupt::Vupdate).is_err()
        || e.io.values[otg as usize] != VUPDATE_NO_LOCK_INT_EN | VSTARTUP_INT_EN | 0x4 | 1 << 16
    {
        return TestResult::Fail("vupdate ack");
    }
    if e.set_interrupt(Interrupt::Flip, true).is_err()
        || e.io.values[hubp as usize] != FLIP_INT_MASK
        || e.ack(Interrupt::Flip).is_err()
        || e.io.values[hubp as usize] != FLIP_INT_MASK | FLIP_CLEAR
        || e.set_interrupt(Interrupt::Flip, false).is_err()
        || e.io.values[hubp as usize] != 0
    {
        return TestResult::Fail("pflip enable/ack");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_display_interrupts_follow_irq_service_dcn30
);

fn dcn30_position_samples_a_stable_frame_count() -> TestResult {
    let mut e = engine(0);
    e.io.values[OTG_V_BLANK_START_END as usize] = 41 << 16 | 1121;
    e.io.values[OTG_STATUS_POSITION as usize] = 1000 << 16 | 500;
    e.io.values[OTG_STATUS_FRAME_COUNT as usize] = 0x0100_0010;
    e.io.racing = 1;
    let Ok(p) = e.position() else {
        return TestResult::Fail("position refused");
    };
    if p != (Position {
        frame: 0x11,
        vpos: 500,
        hpos: 1000,
        vblank_start: 1121,
        vblank_end: 41,
    }) {
        return TestResult::Fail("position fields");
    }
    e.io.racing = 100;
    if e.position() != Err(Error::Busy) {
        return TestResult::Fail("unstable frame count accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_position_samples_a_stable_frame_count
);

fn dcn30_flip_drr_trigger_follows_surface_address_publication() -> TestResult {
    let mut e = engine(2);
    if e.program_flip(0x1_2345_6700).is_err() || e.manual_trigger().is_err() {
        return TestResult::Fail("DRR flip arm/trigger");
    }
    let last = e.io.writes.last().copied();
    if last != Some((0x1c3a, 1))
        || e.io
            .writes
            .iter()
            .position(|w| w.0 == PRIMARY_SURFACE_ADDRESS + 2 * HUBP_STRIDE)
            .is_none_or(|i| i + 1 != e.io.writes.len() - 1)
    {
        return TestResult::Fail("manual trigger preceded address or used another pipe");
    }
    let writes = e.io.writes.len();
    e.authority.revoke();
    if e.manual_trigger() != Err(Error::Revoked) || e.io.writes.len() != writes {
        return TestResult::Fail("revoked authority triggered DRR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_flip_drr_trigger_follows_surface_address_publication
);

fn dcn30_flip_samples_last_drr_total_with_position() -> TestResult {
    let mut e = engine(1);
    let base = OTG_STRIDE;
    e.io.values[(base + OTG_STATUS_FRAME_COUNT) as usize] = 7;
    e.io.values[(base + OTG_STATUS_POSITION) as usize] = 1400;
    e.io.values[(base + OTG_V_BLANK_START_END) as usize] = 1084 | 41 << 16;
    e.io.values[(base + 0x1b9b) as usize] = 1687 << 16;
    if e.position_drr().map_or(true, |(p, total)| {
        p.vpos != 1400 || p.frame != 7 || total != 1688
    }) {
        return TestResult::Fail("stretched-frame sample lost hardware total");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    dcn30_flip_samples_last_drr_total_with_position
);
