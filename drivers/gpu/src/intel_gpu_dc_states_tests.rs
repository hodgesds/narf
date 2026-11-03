//! Display-14 DC-state service fixtures. The fake is a plain register
//! file that can model the hardware behaviours the service must
//! tolerate: a `DC_STATE_EN` write the DMC ignores (once or forever),
//! a function out of D0 (all-ones), and program RAM that drops writes.
//! Expected conversations are hand-derived from the pinned
//! `intel_display_power_well.c` / `intel_dmc.c` sequences cited in the
//! module header; clocks are explicit, nothing sleeps or spawns.

use super::*;
use crate::intel_gpu_dmc::{GEN9_CLKGATE_DIS_0, TGL_DMC_DEBUG_DC5_COUNT};
use alloc::collections::BTreeMap;
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

const DC5_COUNT: u64 = DG1_DMC_DEBUG_DC5_COUNT;
const PLANE_CTL_A: u64 = 0x70180;
const MS: u64 = 1_000_000;

#[derive(Default)]
struct Fake {
    regs: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    reads: RefCell<Vec<u64>>,
    dc_ignore: Cell<u32>,
    dc_never_stick: Cell<bool>,
    dead: Cell<bool>,
    drop_program_ram: Cell<bool>,
}

impl Fake {
    fn set(&self, off: u64, val: u32) {
        self.regs.borrow_mut().insert(off, val);
    }
    fn get(&self, off: u64) -> u32 {
        *self.regs.borrow().get(&off).unwrap_or(&0)
    }
    fn writes_to(&self, off: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == off)
            .map(|(_, v)| *v)
            .collect()
    }
    fn clear_log(&self) {
        self.writes.borrow_mut().clear();
    }
    fn log(&self) -> Vec<(u64, u32)> {
        self.writes.borrow().clone()
    }
    /// S3 / D3cold: every register back at reset.
    fn power_loss(&self) {
        self.regs.borrow_mut().clear();
    }
}

impl MmioWindow for Fake {
    fn read32(&self, off: u64) -> u32 {
        self.reads.borrow_mut().push(off);
        if self.dead.get() {
            return u32::MAX;
        }
        self.get(off)
    }
    fn write32(&self, off: u64, val: u32) {
        if self.dead.get() {
            return;
        }
        self.writes.borrow_mut().push((off, val));
        if off == DC_STATE_EN {
            if self.dc_never_stick.get() {
                return;
            }
            if self.dc_ignore.get() > 0 {
                self.dc_ignore.set(self.dc_ignore.get() - 1);
                return;
            }
        }
        if self.drop_program_ram.get() && (0x80000..0x8F000).contains(&off) {
            return;
        }
        self.set(off, val);
    }
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// A display-14 container with one wildcard main v3 program at
/// 0x80000, laid out field by field from the format description in
/// `intel_gpu_dmc` (CSS 128 bytes, package v2 with 32 entries).
fn mtl_container(payload: &[u32]) -> Vec<u8> {
    let package = 16 + 32 * 12;
    let mut blob = alloc::vec![0u8; 128 + package];
    put32(&mut blob, 0, 0x09);
    put32(&mut blob, 4, 32);
    put32(&mut blob, 8, 0x1_0000);
    put32(&mut blob, 88, 0x0002_0015);
    blob[128] = (package / 4) as u8;
    blob[129] = 2;
    put32(&mut blob, 128 + 12, 1);
    let entry = 128 + 16;
    blob[entry + 2] = b'*';
    blob[entry + 3] = b'*';
    let prog = blob.len();
    blob.resize(prog + 256 + payload.len() * 4, 0);
    put32(&mut blob, prog, 0x4040_3E3E);
    blob[prog + 4] = 64;
    blob[prog + 5] = 3;
    put32(&mut blob, prog + 12, payload.len() as u32);
    put32(&mut blob, prog + 16, 0x0002_0015);
    put32(&mut blob, prog + 20, 0x80000);
    put32(&mut blob, prog + 92, 2);
    put32(&mut blob, prog + 96, 0x8F074);
    put32(&mut blob, prog + 100, 0x8F034);
    put32(&mut blob, prog + 176, 0x2FC0);
    put32(&mut blob, prog + 180, 0x8003_3200);
    for (i, v) in payload.iter().enumerate() {
        put32(&mut blob, prog + 256 + 4 * i, *v);
    }
    blob
}

fn firmware() -> Result<Arc<Vec<u8>>, DcRefusal> {
    Ok(Arc::new(mtl_container(&[0xD0C0_0001, 0xD0C0_0002])))
}

/// A core past probe: sanitized, Init held, program loaded and the
/// Init release due at `now`. Returns the deadline.
fn booted(fake: &Fake, now: u64) -> (IrqSafeSpinLock<DcCore>, u64) {
    let core = IrqSafeSpinLock::new(DcCore::new(XELPDP_ALLOWED_DC_MASK));
    {
        let mut c = core.lock();
        let _ = c.sanitize(fake);
        let _ = c.get(fake, DcUser::Init);
    }
    let due = publication_step(&core, fake, now, firmware).unwrap_or(0);
    (core, due)
}

/// [`booted`] and re-entered DC6.
fn armed(fake: &Fake) -> IrqSafeSpinLock<DcCore> {
    let (core, due) = booted(fake, 0);
    let _ = core.lock().arm_if_due(fake, due, ArmGates::default());
    core
}

fn smoke_dc_states_register_facts_pinned() -> TestResult {
    // intel_display_regs.h / intel_backlight_regs.h /
    // intel_display_power_well.c::gen9_dc_mask (display >= 12).
    if DC_STATE_EN != 0x45504
        || DC_STATE_EN_UPTO_DC5 != 1
        || DC_STATE_EN_UPTO_DC6 != 2
        || DC_STATE_EN_DC9 != 1 << 3
        || DC_STATE_EN_DC3CO != 1 << 30
        || GEN12_DC_MASK != 0x4000_000B
    {
        return TestResult::Fail("DC_STATE_EN field facts diverge");
    }
    if UTIL_PIN_CTL != 0x48400
        || UTIL_PIN_ENABLE != 1 << 31
        || UTIL_PIN_MODE_MASK != 0xF << 24
        || UTIL_PIN_MODE_PWM != 1 << 24
    {
        return TestResult::Fail("UTIL_PIN_CTL facts diverge");
    }
    if DC_REENABLE_DELAY_NS != 17 * MS
        || DC_WRITE_MAX_REWRITES != 100
        || XELPDP_ALLOWED_DC_MASK != DC_STATE_EN_UPTO_DC6
        || PIPEDMC_ENABLE_MTL_ALL != 0x1111
    {
        return TestResult::Fail("service policy constants diverge");
    }
    // sanitize_target_dc_state: DC6 -> DC5 -> disabled.
    if sanitize_target(DC_STATE_EN_UPTO_DC6, DC_STATE_EN_UPTO_DC6) != DC_STATE_EN_UPTO_DC6
        || sanitize_target(DC_STATE_EN_UPTO_DC5, DC_STATE_EN_UPTO_DC6) != DC_STATE_EN_UPTO_DC5
        || sanitize_target(0, DC_STATE_EN_UPTO_DC6) != DC_STATE_DISABLE
    {
        return TestResult::Fail("target sanitization diverges from i915");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_register_facts_pinned
);

fn smoke_dc_states_write_stick_discipline() -> TestResult {
    // A write that sticks: one write, then seven agreeing reads.
    let fake = Fake::default();
    if write_dc_state_sticky(&fake, 0x802) != Ok(()) || fake.writes_to(DC_STATE_EN) != [0x802] {
        return TestResult::Fail("a sticking DC write must be written exactly once");
    }
    // The DMC ignores the first write: one rewrite restarts the count.
    let fake = Fake::default();
    fake.dc_ignore.set(1);
    if write_dc_state_sticky(&fake, 0x2) != Ok(()) || fake.writes_to(DC_STATE_EN) != [0x2, 0x2] {
        return TestResult::Fail("an ignored DC write must be rewritten until it sticks");
    }
    // Never sticks: the initial write plus 100 rewrites, then refuse
    // with the observed value.
    let fake = Fake::default();
    fake.set(DC_STATE_EN, 0x1);
    fake.dc_never_stick.set(true);
    if write_dc_state_sticky(&fake, 0x0) != Err(0x1) {
        return TestResult::Fail("a DC write that never sticks must report the observed value");
    }
    if fake.writes_to(DC_STATE_EN).len() != 101 {
        return TestResult::Fail("the rewrite ceiling must be gen9_write_dc_state's 100");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_write_stick_discipline
);

fn smoke_dc_states_init_held_until_program_loaded() -> TestResult {
    let fake = Fake::default();
    // Firmware left DC6 enabled; bit 11 is unrelated and must survive.
    fake.set(DC_STATE_EN, 0x802);
    fake.set(DC5_COUNT, 40);
    let core = IrqSafeSpinLock::new(DcCore::new(XELPDP_ALLOWED_DC_MASK));
    {
        let mut c = core.lock();
        if c.sanitize(&fake) != Ok(()) || c.tracked() != 0x2 {
            return TestResult::Fail("sanitize must adopt the hardware DC field");
        }
        if c.get(&fake, DcUser::Init) != Ok(()) {
            return TestResult::Fail("the Init reference must exit DC states");
        }
    }
    if fake.writes_to(DC_STATE_EN) != [0x800] || core.lock().armed() {
        return TestResult::Fail("Init must program DC_STATE_DISABLE, preserving other bits");
    }
    // Without firmware nothing can release Init.
    let due = publication_step(&core, &fake, 0, || {
        Err(DcRefusal::Registry(narf_firmware::FirmwareError::NotFound))
    });
    if due.is_some() || core.lock().refs(DcUser::Init) != 1 {
        return TestResult::Fail("an absent DMC must keep the Init reference held");
    }
    if core.lock().arm_if_due(&fake, u64::MAX, ArmGates::default()) != Err(ArmBlock::Busy) {
        return TestResult::Fail("DC re-entry must be refused while Init is held");
    }
    // Firmware arrives on a later publication: load, verify, release.
    fake.clear_log();
    let Some(due) = publication_step(&core, &fake, 5 * MS, firmware) else {
        return TestResult::Fail("a loaded program must release Init and schedule re-entry");
    };
    if due != 5 * MS + DC_REENABLE_DELAY_NS {
        return TestResult::Fail("re-entry must be deferred by 17 ms");
    }
    let log = fake.log();
    if log.first() != Some(&(GEN9_CLKGATE_DIS_0, 0xC000))
        || log.last() != Some(&(crate::intel_gpu_dmc::DC_STATE_DEBUG, 0x3))
        || !log.contains(&(0x80000, 0xD0C0_0001))
        || !log.contains(&(0x8F034, 0x8003_3200))
        || log.iter().any(|(o, _)| *o == DC_STATE_EN)
    {
        return TestResult::Fail("the load must be the MTL DMC conversation, under DC_off");
    }
    let (program, total) = {
        let c = core.lock();
        (c.program(), c.total())
    };
    if program
        != (ProgramState::Loaded {
            version: 0x0002_0015,
        })
        || total != 0
    {
        return TestResult::Fail("program must be Loaded with every reference released");
    }
    if core.lock().arm_if_due(&fake, due - 1, ArmGates::default()) != Err(ArmBlock::NotDue(due)) {
        return TestResult::Fail("re-entry before the deferral must wait");
    }
    if core.lock().arm_if_due(&fake, due, ArmGates::default()) != Ok(DC_STATE_EN_UPTO_DC6) {
        return TestResult::Fail("a due, gated-clear release must re-enter DC6");
    }
    if fake.get(DC_STATE_EN) != 0x802 || !core.lock().armed() || core.lock().arms() != 1 {
        return TestResult::Fail("DC6 must be programmed as field 2, preserving other bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_init_held_until_program_loaded
);

fn smoke_dc_states_bad_firmware_fails_closed() -> TestResult {
    // A container that fails display-14 validation.
    let fake = Fake::default();
    let core = IrqSafeSpinLock::new(DcCore::new(XELPDP_ALLOWED_DC_MASK));
    let _ = core.lock().get(&fake, DcUser::Init);
    let mut corrupt = mtl_container(&[1]);
    put32(&mut corrupt, 128 + 400, 0xDEAD_BEEF);
    let parsed = parse_dmc_firmware_xelpdp(&corrupt, b'*', b'*').err();
    if parsed != Some(DmcError::BadSignature(0xDEAD_BEEF)) {
        return TestResult::Fail("fixture container must fail the signature check");
    }
    let due = publication_step(&core, &fake, 0, || {
        Err(DcRefusal::Parse(DmcError::BadSignature(0xDEAD_BEEF)))
    });
    if due.is_some()
        || core.lock().program()
            != ProgramState::Refused(DcRefusal::Parse(DmcError::BadSignature(0xDEAD_BEEF)))
        || core.lock().refs(DcUser::Init) != 1
    {
        return TestResult::Fail("a refused container must latch and keep DC0");
    }
    if fake
        .log()
        .iter()
        .any(|(o, _)| (0x80000..0x90000).contains(o) || *o == GEN9_CLKGATE_DIS_0)
    {
        return TestResult::Fail("a refused container must never reach program RAM");
    }
    // A container that parses but does not read back as loaded.
    let fake = Fake::default();
    fake.drop_program_ram.set(true);
    let core = IrqSafeSpinLock::new(DcCore::new(XELPDP_ALLOWED_DC_MASK));
    let _ = core.lock().get(&fake, DcUser::Init);
    if publication_step(&core, &fake, 0, firmware).is_some() {
        return TestResult::Fail("a failed verification must not release Init");
    }
    let (program, init, load) = {
        let c = core.lock();
        (c.program(), c.refs(DcUser::Init), c.refs(DcUser::Load))
    };
    if !matches!(
        program,
        ProgramState::Refused(DcRefusal::Verify(DmcVerifyError::ProgramStart { .. }))
    ) || init != 1
        || load != 0
    {
        return TestResult::Fail("verification failure must latch, release Load, keep Init");
    }
    // Every display user still works (DC states stay off), and the
    // last of them never re-enters.
    let mut c = core.lock();
    if c.get(&fake, DcUser::Kms) != Ok(()) || c.put(DcUser::Kms, 0).is_some() {
        return TestResult::Fail("users must still be served while DC0 is held");
    }
    if fake.writes_to(DC_STATE_EN).iter().any(|v| *v & 3 != 0) {
        return TestResult::Fail("no DC5/DC6 target may ever be written after a refusal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_bad_firmware_fails_closed
);

fn smoke_dc_states_exit_before_hardware_and_refcount() -> TestResult {
    let fake = Fake::default();
    let core = armed(&fake);
    if !core.lock().armed() {
        return TestResult::Fail("fixture must start in DC6");
    }
    fake.clear_log();
    // A KMS session: DC exit must precede its first plane write.
    if core.lock().get(&fake, DcUser::Kms) != Ok(()) {
        return TestResult::Fail("the first reference must exit DC6");
    }
    fake.write32(PLANE_CTL_A, 0x8400_0000);
    let log = fake.log();
    if log.first() != Some(&(DC_STATE_EN, 0)) || log.last() != Some(&(PLANE_CTL_A, 0x8400_0000)) {
        return TestResult::Fail("DC exit must be written before any display register");
    }
    // Nested users exit nothing further.
    fake.clear_log();
    {
        let mut c = core.lock();
        if c.get(&fake, DcUser::Modeset) != Ok(()) || c.get(&fake, DcUser::Psr) != Ok(()) {
            return TestResult::Fail("nested references must be granted");
        }
        if !fake.log().is_empty() || c.total() != 3 {
            return TestResult::Fail("nested references must not touch DC_STATE_EN");
        }
        if c.put(DcUser::Modeset, 1).is_some() || c.put(DcUser::Psr, 2).is_some() {
            return TestResult::Fail("re-entry must wait for every user");
        }
        // An unbalanced release is ignored, not underflowed.
        if c.put(DcUser::Suspend, 3).is_some() || c.refs(DcUser::Kms) != 1 {
            return TestResult::Fail("an unbalanced release must not release another user");
        }
        if c.arm_if_due(&fake, u64::MAX, ArmGates::default()) != Err(ArmBlock::Busy) {
            return TestResult::Fail("re-entry with a held reference must refuse");
        }
        if c.put(DcUser::Kms, 10 * MS) != Some(10 * MS + DC_REENABLE_DELAY_NS) {
            return TestResult::Fail("the last release must schedule re-entry");
        }
        // A new user inside the deferral cancels it without a DC write:
        // the hardware is still in DC0.
        if c.get(&fake, DcUser::Kms) != Ok(()) || c.arm_deadline().is_some() {
            return TestResult::Fail("a reference during the deferral must cancel re-entry");
        }
    }
    if !fake.log().is_empty() {
        return TestResult::Fail("cancelling a deferral must not write DC_STATE_EN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_exit_before_hardware_and_refcount
);

fn smoke_dc_states_flip_during_dc6_counts_residency() -> TestResult {
    let fake = Fake::default();
    fake.set(DC5_COUNT, 100);
    let core = armed(&fake);
    // The DMC entered DC5 fifteen times while DC6 was allowed.
    fake.set(DC5_COUNT, 115);
    // Flip: exit, program, release, re-enter after the deferral.
    let mut c = core.lock();
    if c.get(&fake, DcUser::Kms) != Ok(()) || fake.get(DC_STATE_EN) & 3 != 0 {
        return TestResult::Fail("a flip during DC6 must exit to DC0 first");
    }
    if c.dc6_allowed_count() != 15 {
        return TestResult::Fail("DC6-allowed residency must count DC5 entries while allowed");
    }
    fake.write32(0x7019c, 0x10_0000); // PLANE_SURF_A
    let Some(due) = c.put(DcUser::Kms, 20 * MS) else {
        return TestResult::Fail("the flip's release must schedule re-entry");
    };
    if c.arm_if_due(&fake, due, ArmGates::default()) != Ok(DC_STATE_EN_UPTO_DC6) {
        return TestResult::Fail("DC6 must be re-entered after the flip");
    }
    fake.set(DC5_COUNT, 120);
    let _ = c.get(&fake, DcUser::Kms);
    if c.dc6_allowed_count() != 20 {
        return TestResult::Fail("re-entry must restart the DC6 residency window");
    }
    // The pre-display-14 counters are not this platform's.
    let reads = fake.reads.borrow().clone();
    if reads.contains(&TGL_DMC_DEBUG_DC5_COUNT) || !reads.contains(&DC5_COUNT) {
        return TestResult::Fail("display 14 must count through DG1_DMC_DEBUG_DC5_COUNT only");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_flip_during_dc6_counts_residency
);

fn smoke_dc_states_stuck_write_latches_fault() -> TestResult {
    let fake = Fake::default();
    let core = armed(&fake);
    let mut c = core.lock();
    // The DMC refuses the exit: no reference, typed error, latched.
    fake.dc_never_stick.set(true);
    match c.get(&fake, DcUser::Kms) {
        Err(DcError::DidNotStick {
            wanted: 0,
            found: 2,
        }) => {}
        _ => return TestResult::Fail("an exit that never sticks must refuse the caller"),
    }
    if c.total() != 0 || c.fault().is_none() {
        return TestResult::Fail("a refused exit must count nothing and latch the fault");
    }
    // Hardware recovers: users are served again, but DC states are
    // never re-entered after the latched failure.
    fake.dc_never_stick.set(false);
    if c.get(&fake, DcUser::Kms) != Ok(()) || fake.get(DC_STATE_EN) & 3 != 0 {
        return TestResult::Fail("a later exit that sticks must serve the user");
    }
    let Some(due) = c.put(DcUser::Kms, 0) else {
        return TestResult::Fail("release must still be scheduled");
    };
    if c.arm_if_due(&fake, due, ArmGates::default()) != Err(ArmBlock::Faulted)
        || fake.get(DC_STATE_EN) & 3 != 0
    {
        return TestResult::Fail("a latched write failure must keep DC0");
    }
    // A function out of D0 is unavailable, not a fault.
    let fake = Fake::default();
    fake.dead.set(true);
    let mut c = DcCore::new(XELPDP_ALLOWED_DC_MASK);
    if c.get(&fake, DcUser::Kms) != Err(DcError::Unavailable)
        || c.total() != 0
        || c.fault().is_some()
    {
        return TestResult::Fail("an all-ones DC_STATE_EN must refuse without latching");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_stuck_write_latches_fault
);

fn smoke_dc_states_suspend_resume_restore() -> TestResult {
    let fake = Fake::default();
    let core = armed(&fake);
    fake.clear_log();
    {
        let mut c = core.lock();
        if c.suspend_begin(&fake) != Ok(()) || fake.get(DC_STATE_EN) & 3 != 0 {
            return TestResult::Fail("suspend must exit DC states first");
        }
        // Idempotent: a retried preparation does not stack references.
        if c.suspend_begin(&fake) != Ok(()) || c.refs(DcUser::Suspend) != 1 {
            return TestResult::Fail("suspend_begin must be idempotent");
        }
        fake.clear_log();
        c.suspend_commit(&fake);
        let mut expected = alloc::vec![(GEN9_CLKGATE_DIS_0, 0xC000)];
        for h in 0..8u64 {
            expected.push((0x8F034 + 4 * h, 0x0003_0100));
            expected.push((0x8F004 + 4 * h, 0));
        }
        if fake.log() != expected || c.program() != ProgramState::Disabled {
            return TestResult::Fail(
                "suspend must disable the program (intel_dmc_disable_program)",
            );
        }
        if c.release_held(1).is_some() || c.refs(DcUser::Suspend) != 1 {
            return TestResult::Fail("a disabled program must not release the Suspend reference");
        }
    }
    // S3: program RAM and DC_STATE_EN are lost.
    fake.power_loss();
    fake.clear_log();
    // First publication after resume: reload, verify, release.
    let Some(due) = publication_step(&core, &fake, 50 * MS, || {
        Err(DcRefusal::Authority) // a retained container is reused
    }) else {
        return TestResult::Fail("resume must reload and schedule re-entry");
    };
    let (program, total) = {
        let c = core.lock();
        (c.program(), c.total())
    };
    if !fake.log().contains(&(0x80000, 0xD0C0_0001))
        || !matches!(program, ProgramState::Loaded { .. })
        || total != 0
    {
        return TestResult::Fail("resume must reload the retained program before release");
    }
    if core.lock().arm_if_due(&fake, due, ArmGates::default()) != Ok(DC_STATE_EN_UPTO_DC6)
        || fake.get(DC_STATE_EN) & 3 != 2
    {
        return TestResult::Fail("DC6 must be restored after the reload");
    }
    // A failed preparation instead drops the Suspend reference and
    // re-enters without a reload.
    let fake = Fake::default();
    let core = armed(&fake);
    let mut c = core.lock();
    let _ = c.suspend_begin(&fake);
    let Some(due) = c.suspend_abort(7 * MS) else {
        return TestResult::Fail("an aborted suspend must schedule re-entry");
    };
    if c.arm_if_due(&fake, due, ArmGates::default()) != Ok(DC_STATE_EN_UPTO_DC6) {
        return TestResult::Fail("an aborted suspend must leave the program usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_suspend_resume_restore
);

fn smoke_dc_states_program_loss_reloads_before_reentry() -> TestResult {
    let fake = Fake::default();
    let core = armed(&fake);
    let due = {
        let mut c = core.lock();
        let _ = c.get(&fake, DcUser::Kms);
        c.put(DcUser::Kms, 30 * MS).unwrap_or(0)
    };
    // Program RAM lost behind the driver's back (no suspend hook ran).
    fake.set(0x80000, 0);
    fake.clear_log();
    match arm_step(&core, &fake, due, ArmGates::default()) {
        Err(ArmBlock::NotDue(next)) if next == due + DC_REENABLE_DELAY_NS => {}
        _ => return TestResult::Fail("a lost program must be reloaded, then re-entry rescheduled"),
    }
    if fake.writes_to(DC_STATE_EN).iter().any(|v| *v & 3 != 0)
        || !fake.log().contains(&(0x80000, 0xD0C0_0001))
    {
        return TestResult::Fail("re-entry must not precede the reload");
    }
    if arm_step(
        &core,
        &fake,
        due + DC_REENABLE_DELAY_NS,
        ArmGates::default(),
    ) != Ok(DC_STATE_EN_UPTO_DC6)
    {
        return TestResult::Fail("re-entry must follow a verified reload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_program_loss_reloads_before_reentry
);

fn smoke_dc_states_arm_gates_refuse() -> TestResult {
    let release = |core: &IrqSafeSpinLock<DcCore>, fake: &Fake| -> u64 {
        let mut c = core.lock();
        let _ = c.get(fake, DcUser::Kms);
        c.put(DcUser::Kms, 0).unwrap_or(0)
    };
    let fake = Fake::default();
    let (core, due) = booted(&fake, 0);
    // Utility pin in PWM mode (assert_can_enable_dc6).
    fake.set(UTIL_PIN_CTL, UTIL_PIN_ENABLE | UTIL_PIN_MODE_PWM);
    if core.lock().arm_if_due(&fake, due, ArmGates::default()) != Err(ArmBlock::UtilPinPwm) {
        return TestResult::Fail("DC6 must be refused with the utility pin in PWM mode");
    }
    // The refusal consumed the release.
    if core.lock().arm_if_due(&fake, due, ArmGates::default()) != Err(ArmBlock::NotScheduled) {
        return TestResult::Fail("a refusal must consume the release");
    }
    fake.set(UTIL_PIN_CTL, 0);
    // A pipe DMC this driver never loaded is enabled.
    fake.set(MTL_PIPEDMC_CONTROL, pipedmc_enable_mtl(1));
    let due = release(&core, &fake);
    if core.lock().arm_if_due(&fake, due, ArmGates::default())
        != Err(ArmBlock::UnownedPipeDmc(0x10))
    {
        return TestResult::Fail("an unowned enabled pipe DMC must refuse re-entry");
    }
    fake.set(MTL_PIPEDMC_CONTROL, 0);
    let due = release(&core, &fake);
    let gates = ArmGates {
        external_route_active: true,
    };
    if core.lock().arm_if_due(&fake, due, gates) != Err(ArmBlock::ExternalRoute) {
        return TestResult::Fail("a live external route must refuse re-entry");
    }
    // Out of D0: refused, nothing written.
    let due = release(&core, &fake);
    fake.dead.set(true);
    if core.lock().arm_if_due(&fake, due, ArmGates::default()) != Err(ArmBlock::Unavailable) {
        return TestResult::Fail("an unreadable function must refuse re-entry");
    }
    fake.dead.set(false);
    if fake.writes_to(DC_STATE_EN).iter().any(|v| *v & 3 != 0) {
        return TestResult::Fail("no refused gate may write a DC target");
    }
    // A DC5-only allowed mask sanitizes the target to field 1, and the
    // UTIL_PIN check is a DC6-only precondition.
    let fake = Fake::default();
    fake.set(UTIL_PIN_CTL, UTIL_PIN_ENABLE | UTIL_PIN_MODE_PWM);
    let core = IrqSafeSpinLock::new(DcCore::new(DC_STATE_EN_UPTO_DC5));
    let _ = core.lock().get(&fake, DcUser::Init);
    let Some(due) = publication_step(&core, &fake, 0, firmware) else {
        return TestResult::Fail("DC5-only core must still load");
    };
    if core.lock().arm_if_due(&fake, due, ArmGates::default()) != Ok(DC_STATE_EN_UPTO_DC5)
        || fake.get(DC_STATE_EN) & 3 != 1
    {
        return TestResult::Fail("a DC5-only mask must program field 1");
    }
    // An empty mask never targets anything.
    let fake = Fake::default();
    let core = IrqSafeSpinLock::new(DcCore::new(0));
    let _ = core.lock().get(&fake, DcUser::Init);
    let due = publication_step(&core, &fake, 0, firmware).unwrap_or(0);
    if core.lock().arm_if_due(&fake, due, ArmGates::default()) != Err(ArmBlock::NoTarget) {
        return TestResult::Fail("an empty allowed mask must never re-enter");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_arm_gates_refuse
);

fn smoke_dc_states_firmware_authority_refusal() -> TestResult {
    let (write, read) = narf_firmware::bootstrap_authority();
    write.revoke();
    if open_firmware(&read) != Err(DcRefusal::Authority) {
        return TestResult::Fail("DMC acquisition must refuse a revoked registry authority");
    }
    if MAX_DMC_CONTAINER_BYTES < 128 + 400 + 32 * (256 + 0x7000) {
        return TestResult::Fail("the copy bound must admit a full display-14 container");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_firmware_authority_refusal
);

fn smoke_dc_states_reference_inert_without_service() -> TestResult {
    // No display-14 function is bound in the test kernel: every
    // production hook (KMS, modeset, PSR) must hold nothing and write
    // nothing, so Gen12 and fixture platforms are unchanged.
    if service().is_some() {
        return TestResult::Skip("a display-14 DC service is bound on this machine");
    }
    let reference = match acquire(DcUser::Kms) {
        Ok(reference) => reference,
        Err(_) => return TestResult::Fail("an absent service must not refuse"),
    };
    if reference.service.is_some() {
        return TestResult::Fail("an absent service must yield an inert reference");
    }
    drop(reference);
    let bar = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0xF000_0000),
        virt: 0,
        len: 0,
        kind: narf_bus::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    if acquire_for_bar(&bar, DcUser::Psr).map(|r| r.service.is_some()) != Ok(false) {
        return TestResult::Fail("a BAR without a service must yield an inert reference");
    }
    // Suspend hooks are no-ops without a service.
    if suspend_begin_for_bar(&bar) != Ok(()) {
        return TestResult::Fail("suspend without a service must succeed untouched");
    }
    suspend_finish_for_bar(&bar, true);
    service_after_publication(&bar);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_reference_inert_without_service
);

fn smoke_dc_states_external_route_guard_blocks_reentry() -> TestResult {
    let fake = Fake::default();
    let core = armed(&fake);
    let mut c = core.lock();
    // Route activation: DC exit before the first PHY/DDI access.
    fake.clear_log();
    if c.get(&fake, DcUser::ExternalRoute) != Ok(()) || fake.get(DC_STATE_EN) & 3 != 0 {
        return TestResult::Fail("an external route must exit DC states before activation");
    }
    if fake.log().first() != Some(&(DC_STATE_EN, 0)) {
        return TestResult::Fail("the DC exit must precede any route register write");
    }
    // HPD passes inside a live route neither exit nor schedule anything.
    for t in 1..4 {
        if c.get(&fake, DcUser::Hotplug) != Ok(()) || c.put(DcUser::Hotplug, t).is_some() {
            return TestResult::Fail("a hotplug pass inside a live route must not schedule");
        }
    }
    // A stray hotplug release can never release the route.
    if c.put(DcUser::Hotplug, 5).is_some() || c.refs(DcUser::ExternalRoute) != 1 {
        return TestResult::Fail("an unbalanced hotplug release must not end the route");
    }
    // The live route blocks re-entry regardless of the defensive gate.
    let flip_due = {
        let _ = c.get(&fake, DcUser::Kms);
        c.put(DcUser::Kms, 6)
    };
    if flip_due.is_some()
        || c.arm_if_due(&fake, u64::MAX, ArmGates::default()) != Err(ArmBlock::Busy)
    {
        return TestResult::Fail("a held route must block DC re-entry");
    }
    // Verified route stop: the release schedules re-entry.
    let Some(due) = c.put(DcUser::ExternalRoute, 10 * MS) else {
        return TestResult::Fail("the route's release must schedule re-entry");
    };
    if c.arm_if_due(&fake, due, ArmGates::default()) != Ok(DC_STATE_EN_UPTO_DC6) {
        return TestResult::Fail("DC6 must re-enter after the route stopped");
    }
    // Hotplug pass with no route: exit, then re-entry after the pass.
    if c.get(&fake, DcUser::Hotplug) != Ok(()) || fake.get(DC_STATE_EN) & 3 != 0 {
        return TestResult::Fail("a hotplug pass must exit DC states first");
    }
    if c.put(DcUser::Hotplug, 20 * MS) != Some(20 * MS + DC_REENABLE_DELAY_NS) {
        return TestResult::Fail("a hotplug pass must release like any user");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_external_route_guard_blocks_reentry
);

fn smoke_dc_states_audit_unreachable_display_paths_on_mtl() -> TestResult {
    use crate::intel_gpu::Generation;
    // The DC6-safety audit proves these display-MMIO classes unreachable
    // on display 14 rather than referencing them. Pin the gates it relies
    // on: if any of them opens, those paths need a DC_off reference.
    if Generation::MeteorLake.backlight_supported() {
        return TestResult::Fail("MTL PWM backlight would run without DC_off");
    }
    if Generation::MeteorLake.external_display_supported() {
        return TestResult::Fail("MTL external DP/HDMI/MST/HPD would run without DC_off");
    }
    if !Generation::MeteorLake.display_supported() {
        return TestResult::Fail("the audited internal-panel path must stay admitted");
    }
    // An inert reference (every non-display-14 platform) holds nothing.
    if DcRef::none(DcUser::Kms).service.is_some() {
        return TestResult::Fail("an inert reference must hold no service");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dc_states",
    smoke_dc_states_audit_unreachable_display_paths_on_mtl
);
