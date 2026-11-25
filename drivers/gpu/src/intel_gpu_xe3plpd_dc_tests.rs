//! Display-35 (Xe3P_LPD, Nova Lake-S) DC service fixtures. Expected values
//! are worked by hand from Linux 7.4-rc4: intel_dmc.c (`XE3P_LPD_DMC_PATH`
//! `xe3p_lpd_dmc.bin`, `intel_dmc_load_program`'s `DMC_FQ_W2_PTS_CFG_SEL` and
//! `xe3lpd_enable_dc_count`, `pipedmc_interrupt_mask` for display >= 35),
//! intel_display_power.c (`get_allowed_dc_mask` `max_dc` 4 on display >= 35,
//! `sanitize_target_dc_state` from DC6), intel_display_power_well.c
//! (`gen9_dc_mask`, `dc_state_ro_mask`, `gen9_write_dc_state`) and
//! intel_display_regs.h / intel_dmc_regs.h (`DC_STATE_EN` fields,
//! `DC_COUNT_EN` 0x457B4 bit 31, `PIPEDMC_INTERRUPT(_MASK)` 0x5F190/0x5F194,
//! `PIPEDMC_FLIPQ_PROG_DONE` bit 3, `PIPEDMC_ERROR` bit 2,
//! `PIPEDMC_ENABLE_MTL(pipe)` bit `4 * pipe`). The container is laid out
//! field by field, independently of the production parser. Clocks are
//! explicit; nothing sleeps or spawns.

use super::*;
use alloc::collections::BTreeMap;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

const MS: u64 = 1_000_000;
/// `DC_STATE_EN_UPTO_DC6`.
const DC6: u32 = 2;
/// `DC_COUNT_EN` and `DC_COUNT_EN_COUNTER_ENABLE`.
const DC_COUNT: (u64, u32) = (0x457b4, 1 << 31);
/// `PIPEDMC_INTERRUPT(PIPE_A)` and `PIPEDMC_INTERRUPT_MASK(PIPE_A)`.
const PIPEDMC_INTERRUPT_A: u64 = 0x5f190;
const PIPEDMC_INTERRUPT_MASK_A: u64 = 0x5f194;
/// `PIPEDMC_FLIPQ_PROG_DONE | PIPEDMC_ERROR`.
const NOVA_PIPEDMC_IRQS: u32 = (1 << 3) | (1 << 2);

/// A register file with a write log. `cmtg_status` models the read-only
/// `DC_STATE_EN_CSR_MASK_CMTG_1/0` status bits: they read set and ignore
/// writes.
#[derive(Default)]
pub(crate) struct Regs {
    regs: RefCell<BTreeMap<u64, u32>>,
    pub(crate) writes: RefCell<Vec<(u64, u32)>>,
    cmtg_status: Cell<bool>,
}

impl Regs {
    pub(crate) fn get(&self, off: u64) -> u32 {
        *self.regs.borrow().get(&off).unwrap_or(&0)
    }
    fn set(&self, off: u64, val: u32) {
        self.regs.borrow_mut().insert(off, val);
    }
    fn written(&self, off: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == off)
            .map(|(_, v)| *v)
            .collect()
    }
    fn position(&self, w: (u64, u32)) -> Option<usize> {
        self.writes.borrow().iter().position(|x| *x == w)
    }
}

impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        let v = self.get(off);
        if off == DC_STATE_EN && self.cmtg_status.get() {
            v | (1 << 11) | (1 << 10)
        } else {
            v
        }
    }
    fn write32(&self, off: u64, val: u32) {
        self.writes.borrow_mut().push((off, val));
        if off == DC_STATE_EN && self.cmtg_status.get() {
            self.set(off, val & !((1 << 11) | (1 << 10)));
        } else {
            self.set(off, val);
        }
    }
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// (DMC id, load address, payload dwords, MMIO table) of one program.
type Spec<'a> = (u8, u32, usize, &'a [(u32, u32)]);

/// A wildcard v3 container (CSS 128 bytes, package v2 with 32 entries)
/// carrying `programs`; payload dword `i` of program `id` is
/// `0xD350_0000 | id << 16 | i`.
fn container(programs: &[Spec<'_>]) -> Vec<u8> {
    let package = 16 + 32 * 12;
    let mut blob = alloc::vec![0u8; 128 + package];
    put32(&mut blob, 0, 0x09);
    put32(&mut blob, 4, 32);
    put32(&mut blob, 8, 0x1_0000);
    put32(&mut blob, 88, 0x0002_0023);
    blob[128] = (package / 4) as u8;
    blob[129] = 2;
    put32(&mut blob, 128 + 12, programs.len() as u32);
    for (i, (id, start, dwords, mmio)) in programs.iter().enumerate() {
        let entry = 128 + 16 + 12 * i;
        blob[entry + 1] = *id;
        blob[entry + 2] = b'*';
        blob[entry + 3] = b'*';
        let prog = blob.len();
        put32(&mut blob, entry + 4, ((prog - (128 + package)) / 4) as u32);
        blob.resize(prog + 256 + dwords * 4, 0);
        put32(&mut blob, prog, 0x4040_3E3E);
        blob[prog + 4] = 64;
        blob[prog + 5] = 3;
        put32(&mut blob, prog + 12, *dwords as u32);
        put32(&mut blob, prog + 16, 0x0002_0023);
        put32(&mut blob, prog + 20, *start);
        put32(&mut blob, prog + 92, mmio.len() as u32);
        for (j, (a, d)) in mmio.iter().enumerate() {
            put32(&mut blob, prog + 96 + 4 * j, *a);
            put32(&mut blob, prog + 176 + 4 * j, *d);
        }
        for j in 0..*dwords {
            put32(
                &mut blob,
                prog + 256 + 4 * j,
                0xD350_0000 | u32::from(*id) << 16 | j as u32,
            );
        }
    }
    blob
}

const MAIN: Spec<'static> = (0, 0x80000, 2, &[(0x8F074, 0x86FC0), (0x8F034, 0x8003_3200)]);
const PIPE_A: Spec<'static> = (1, 0x90000, 2, &[(0x5F074, 0x96FC0), (0x5F034, 0x8003_DF00)]);

/// A main-only `xe3p_lpd_dmc.bin` stand-in.
pub(crate) fn nova_firmware() -> Result<Arc<Vec<u8>>, DcRefusal> {
    Ok(Arc::new(container(&[MAIN])))
}

/// A fixture [`DcOff`]: a core of its own, written through the holder's
/// window (so its `DC_STATE_EN` writes land in the holder's write log), with
/// an explicit clock and the last scheduled re-entry deadline.
pub(crate) struct LocalDcOff {
    pub(crate) core: IrqSafeSpinLock<DcCore>,
    pub(crate) now: AtomicU64,
    pub(crate) deadline: AtomicU64,
}

impl DcOff for LocalDcOff {
    fn get(&self, regs: &dyn MmioWindow, user: DcUser) -> Result<bool, DcError> {
        self.core.lock().get(regs, user).map(|()| true)
    }
    fn put(&self, user: DcUser) {
        if let Some(at) = self.core.lock().put(user, self.now.load(Ordering::Relaxed)) {
            self.deadline.store(at, Ordering::Relaxed);
        }
    }
}

/// A [`DcOff`] whose DC exit always fails (`DC_STATE_EN` unavailable).
pub(crate) struct RefuseDcOff;

impl DcOff for RefuseDcOff {
    fn get(&self, _regs: &dyn MmioWindow, _user: DcUser) -> Result<bool, DcError> {
        Err(DcError::Unavailable)
    }
    fn put(&self, _user: DcUser) {}
}

/// A display-35 core past probe on `regs`: Init held, the main-only
/// container loaded at time 0 and DC6 entered at its deadline, all through
/// `regs`.
pub(crate) fn armed_local<M: MmioWindow + ?Sized>(regs: &M) -> Result<LocalDcOff, &'static str> {
    let core = IrqSafeSpinLock::new(DcCore::new_for(
        DmcPlatform::Xe3pLpd,
        XE3PLPD_ALLOWED_DC_MASK,
    ));
    {
        let mut c = core.lock();
        c.sanitize(regs).map_err(|_| "sanitize")?;
        c.get(regs, DcUser::Init).map_err(|_| "Init")?;
    }
    let due = publication_step(&core, regs, 0, nova_firmware).ok_or("the container must load")?;
    if core.lock().arm_if_due(regs, due, ArmGates::default()) != Ok(DC6) {
        return Err("display 35 must enter DC6 after the load");
    }
    Ok(LocalDcOff {
        core,
        now: AtomicU64::new(0),
        deadline: AtomicU64::new(0),
    })
}

/// Profile selection: the owned Nova route's display 35.00 installs the
/// `xe3p_lpd_dmc.bin` service targeting DC6, only behind both Nova options;
/// no Wa_15015404425 read flush. `get_allowed_dc_mask` allows DC3CO | DC6
/// | DC9 there; the service targets DC6 alone.
fn smoke_xe3plpd_dc_service_profile_and_options() -> TestResult {
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_xe2lpd::DisplayIp;
    use narf_boot::args::KernelCmdline;
    let nova = Some((DisplayIp::NovaLakeS, false));
    if service_profile_for(Generation::PantherLake, nova, true)
        != Some((DmcPlatform::Xe3pLpd, DC6, false))
    {
        return TestResult::Fail("the owned Nova route must install the display-35 service");
    }
    if service_profile_for(Generation::PantherLake, nova, false).is_some() {
        return TestResult::Fail("without both Nova options nothing is installed");
    }
    // A stray flush fact never turns the read flush on for display 35.
    if service_profile_for(
        Generation::PantherLake,
        Some((DisplayIp::NovaLakeS, true)),
        true,
    ) != Some((DmcPlatform::Xe3pLpd, DC6, false))
    {
        return TestResult::Fail("display 35 takes no Wa_15015404425 flush");
    }
    // The options do not move the other display-30-family profiles.
    if service_profile_for(
        Generation::PantherLake,
        Some((DisplayIp::Xe3Lpd, true)),
        true,
    ) != Some((DmcPlatform::Xe3Lpd, DC6, true))
        || service_profile_for(Generation::PantherLake, None, true).is_some()
        || service_profile_for(Generation::MeteorLake, nova, true)
            != Some((DmcPlatform::Xelpdp, DC6, false))
    {
        return TestResult::Fail("the Nova options must not move other profiles");
    }
    if !nova_requested(KernelCmdline::new(
        "quiet narf.intel.nvl_display=1 narf.intel.nvl_modeset=1",
    )) {
        return TestResult::Fail("both Nova options must opt in");
    }
    for line in [
        "",
        "narf.intel.nvl_display=1",
        "narf.intel.nvl_modeset=1",
        "narf.intel.nvl_display=1 narf.intel.nvl_modeset=0",
        "narf.intel.nvl_display=1 -- narf.intel.nvl_modeset=1",
    ] {
        if nova_requested(KernelCmdline::new(line)) {
            return TestResult::Fail("one Nova option alone must not opt in");
        }
    }
    if firmware_path(DmcPlatform::Xe3pLpd) != "i915/xe3p_lpd_dmc.bin" {
        return TestResult::Fail("display 35 loads xe3p_lpd_dmc.bin");
    }
    // max_dc 4 on display >= 35 plus DC9; the target is DC6 alone.
    let allowed = DisplayIp::NovaLakeS.allowed_dc_mask();
    if allowed & DC_STATE_EN_UPTO_DC6 == 0
        || allowed & DC_STATE_EN_DC9 == 0
        || XE3PLPD_ALLOWED_DC_MASK != DC6
        || XE3PLPD_ALLOWED_DC_MASK & !allowed != 0
        || sanitize_target(XE3PLPD_ALLOWED_DC_MASK, DC6) != DC6
    {
        return TestResult::Fail("display 35 targets DC6 inside its allowed mask");
    }
    // gen9_dc_mask (7.4-rc4, display >= 12): 0x3 | DC9; dc_state_ro_mask
    // (display >= 20): CMTG_1 | CMTG_0.
    if dc_mask(DmcPlatform::Xe3pLpd) != 0xB
        || dc_state_ro_mask(DmcPlatform::Xe3pLpd) != 0xC00
        || dc_mask(DmcPlatform::Xe3Lpd) != GEN12_DC_MASK
        || dc_state_ro_mask(DmcPlatform::Xe3Lpd) != 0
    {
        return TestResult::Fail("the display-35 DC_STATE_EN masks moved");
    }
    // The production hook is inert without a display-35 service.
    if service().is_none() && Xe3pLpdDcOff.get(&Regs::default(), DcUser::Aux) != Ok(false) {
        return TestResult::Fail("without a display-35 service the hook must count nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_dc",
    smoke_xe3plpd_dc_service_profile_and_options
);

/// The display-35 load and DC6 entry: Init held until the program loads,
/// `DC_FQ_W2_PTS_CFG_SEL` after the program, `DC_COUNT_EN` after the debug
/// masks, the lit Pipe A's DMC enabled with the display-35 interrupt mask,
/// and DC6 entered 17 ms after the Init release. The CMTG status bits do not
/// fault the sticky write, and bit 30 (no DC state on 7.4-rc4) is kept.
fn smoke_xe3plpd_dc_loads_dmc_and_enters_dc6() -> TestResult {
    let regs = Regs::default();
    regs.cmtg_status.set(true);
    regs.set(DC_STATE_EN, 1 << 30);
    let core = IrqSafeSpinLock::new(DcCore::new_for(
        DmcPlatform::Xe3pLpd,
        XE3PLPD_ALLOWED_DC_MASK,
    ));
    {
        let mut c = core.lock();
        if c.sanitize(&regs).is_err() || c.tracked() != 0 {
            return TestResult::Fail("bit 30 and the CMTG status are not tracked DC states");
        }
        if c.get(&regs, DcUser::Init).is_err() {
            return TestResult::Fail("Init must be granted");
        }
        // KMS install reports the owned Pipe A lit before any program.
        if c.pipe_lit(&regs, 0) {
            return TestResult::Fail("a lit pipe without a program is only recorded");
        }
    }
    let Some(due) = publication_step(&core, &regs, 0, || Ok(Arc::new(container(&[MAIN, PIPE_A]))))
    else {
        return TestResult::Fail("the display-35 container must load and release Init");
    };
    if due != DC_REENABLE_DELAY_NS || core.lock().refs(DcUser::Init) != 0 {
        return TestResult::Fail("Init is released after the load, re-entry 17 ms later");
    }
    let program = regs.position((0x80000, 0xD350_0000));
    let w2 = regs.position((0x8f240, 0x0302_0100));
    let debug = regs
        .writes
        .borrow()
        .iter()
        .position(|(o, _)| *o == crate::intel_gpu_dmc::DC_STATE_DEBUG);
    let count = regs.position(DC_COUNT);
    match (program, w2, debug, count) {
        (Some(p), Some(w), Some(d), Some(c)) if p < w && w < d && d < c => {}
        _ => return TestResult::Fail("load order: program, W2 PTS, debug masks, DC_COUNT_EN"),
    }
    // intel_dmc_enable_pipe on display >= 35: FLIPQ_PROG_DONE | ERROR.
    if regs.written(PIPEDMC_INTERRUPT_A) != [NOVA_PIPEDMC_IRQS]
        || regs.written(PIPEDMC_INTERRUPT_MASK_A) != [!NOVA_PIPEDMC_IRQS]
        || regs.get(MTL_PIPEDMC_CONTROL) != 1
        || core.lock().pipes_enabled() != 1
    {
        return TestResult::Fail("Pipe A's DMC must arm the display-35 interrupts and enable");
    }
    if core.lock().arm_if_due(&regs, due - 1, ArmGates::default()) != Err(ArmBlock::NotDue(due)) {
        return TestResult::Fail("re-entry waits for the deadline");
    }
    if core.lock().arm_if_due(&regs, due, ArmGates::default()) != Ok(DC6) {
        return TestResult::Fail("display 35 must enter DC6 with its status bits set");
    }
    if regs.get(DC_STATE_EN) != (1 << 30) | DC6 || core.lock().fault().is_some() {
        return TestResult::Fail("DC6 is written under the 7.4-rc4 mask, bit 30 kept");
    }
    // The next reference exits DC6 the same way.
    if core.lock().get(&regs, DcUser::Kms).is_err() || regs.get(DC_STATE_EN) != 1 << 30 {
        return TestResult::Fail("a reference must exit DC6");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_dc",
    smoke_xe3plpd_dc_loads_dmc_and_enters_dc6
);

/// Without a usable `xe3p_lpd_dmc.bin` (absent, or past the 0x8000 payload
/// ceiling) the Init reference stays held: DC0, no program RAM written, and
/// re-entry refused even once every other reference is gone.
fn smoke_xe3plpd_dc_refuses_without_dmc() -> TestResult {
    for (absent, refusal) in [
        (true, "an absent container must keep DC states off"),
        (false, "an oversized container must keep DC states off"),
    ] {
        let regs = Regs::default();
        let core = IrqSafeSpinLock::new(DcCore::new_for(
            DmcPlatform::Xe3pLpd,
            XE3PLPD_ALLOWED_DC_MASK,
        ));
        {
            let mut c = core.lock();
            let _ = c.sanitize(&regs);
            let _ = c.get(&regs, DcUser::Init);
        }
        let acquire = || {
            if absent {
                Err(DcRefusal::Registry(narf_firmware::FirmwareError::NotFound))
            } else {
                let big: Spec<'_> = (0, 0x80000, 0x8004 / 4, &[]);
                let blob = container(&[big]);
                parse_for(DmcPlatform::Xe3pLpd, &blob).map_err(DcRefusal::Parse)?;
                Ok(Arc::new(blob))
            }
        };
        if publication_step(&core, &regs, 0, acquire).is_some() {
            return TestResult::Fail(refusal);
        }
        let c = core.lock();
        if !matches!(c.program(), ProgramState::Refused(_))
            || c.refs(DcUser::Init) != 1
            || regs
                .writes
                .borrow()
                .iter()
                .any(|(o, _)| *o >= 0x80000 && *o < 0x8F000)
            || regs.get(DC_STATE_EN) != 0
        {
            return TestResult::Fail(refusal);
        }
    }
    // A core with no program and every reference gone still refuses
    // (assert_can_enable_dc6's assert_main_dmc_loaded), writing nothing.
    let regs = Regs::default();
    let mut bare = DcCore::new_for(DmcPlatform::Xe3pLpd, XE3PLPD_ALLOWED_DC_MASK);
    let _ = bare.get(&regs, DcUser::Kms);
    let Some(due) = bare.put(DcUser::Kms, 0) else {
        return TestResult::Fail("the last release schedules re-entry");
    };
    regs.writes.borrow_mut().clear();
    if bare.arm_if_due(&regs, due, ArmGates::default()) != Err(ArmBlock::NoProgram)
        || !regs.writes.borrow().is_empty()
    {
        return TestResult::Fail("re-entry without the DMC must refuse and write nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_dc",
    smoke_xe3plpd_dc_refuses_without_dmc
);

/// System suspend and the post-resume reload on display 35, as on Panther
/// Lake: the Suspend reference exits DC6, the suspend commit disables Pipe
/// A's DMC (enable clear, interrupts masked and cleared with the display-35
/// mask) and the program; after the power loss the first publication
/// reloads the container (`DC_COUNT_EN` again), re-enables the lit Pipe A
/// and only then releases the Suspend reference; DC6 follows 17 ms later.
fn smoke_xe3plpd_dc_suspend_and_post_resume_reload() -> TestResult {
    let regs = Regs::default();
    let core = IrqSafeSpinLock::new(DcCore::new_for(
        DmcPlatform::Xe3pLpd,
        XE3PLPD_ALLOWED_DC_MASK,
    ));
    {
        let mut c = core.lock();
        let _ = c.sanitize(&regs);
        let _ = c.get(&regs, DcUser::Init);
        c.pipe_lit(&regs, 0);
    }
    let firmware = || Ok(Arc::new(container(&[MAIN, PIPE_A])));
    let Some(due) = publication_step(&core, &regs, 0, firmware) else {
        return TestResult::Fail("probe-time load");
    };
    let _ = core.lock().arm_if_due(&regs, due, ArmGates::default());
    regs.writes.borrow_mut().clear();
    {
        let mut c = core.lock();
        if c.suspend_begin(&regs).is_err() || regs.get(DC_STATE_EN) & 3 != 0 {
            return TestResult::Fail("suspend preparation must exit DC6");
        }
        c.suspend_commit(&regs);
        if c.program() != ProgramState::Disabled || c.pipes_enabled() != 0 {
            return TestResult::Fail("the suspend commit disables the pipe DMC and the program");
        }
    }
    let disable = regs.position((MTL_PIPEDMC_CONTROL, 0));
    let mask = regs.position((PIPEDMC_INTERRUPT_MASK_A, !0));
    let clear = regs.position((PIPEDMC_INTERRUPT_A, NOVA_PIPEDMC_IRQS));
    match (disable, mask, clear) {
        (Some(d), Some(m), Some(c)) if d < m && m < c => {}
        _ => return TestResult::Fail("intel_dmc_disable_pipe order with the display-35 mask"),
    }
    // S3: every register back at reset.
    regs.regs.borrow_mut().clear();
    regs.writes.borrow_mut().clear();
    let Some(due) = publication_step(&core, &regs, 40 * MS, firmware) else {
        return TestResult::Fail("the post-resume publication must reload and release");
    };
    if due != 40 * MS + DC_REENABLE_DELAY_NS || core.lock().refs(DcUser::Suspend) != 0 {
        return TestResult::Fail("the Suspend reference is released after the reload");
    }
    if regs.get(0x80000) != 0xD350_0000
        || regs.get(0x90000) != 0xD351_0000
        || regs.written(DC_COUNT.0) != [DC_COUNT.1]
        || regs.written(PIPEDMC_INTERRUPT_A) != [NOVA_PIPEDMC_IRQS]
        || regs.get(MTL_PIPEDMC_CONTROL) != 1
    {
        return TestResult::Fail("the reload restores the programs, DC_COUNT_EN and Pipe A");
    }
    if core.lock().arm_if_due(&regs, due, ArmGates::default()) != Ok(DC6) {
        return TestResult::Fail("DC6 must be re-entered after the reload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_dc",
    smoke_xe3plpd_dc_suspend_and_post_resume_reload
);

/// The hold guard counts through its hook, releases exactly what it took,
/// and a refused exit counts nothing.
fn smoke_xe3plpd_dc_guard_releases_what_it_took() -> TestResult {
    let regs = Regs::default();
    let local = match armed_local(&regs) {
        Ok(local) => local,
        Err(why) => return TestResult::Fail(why),
    };
    local.now.store(3 * MS, Ordering::Relaxed);
    regs.writes.borrow_mut().clear();
    {
        let Ok(_outer) = hold(&local, &regs, DcUser::Aux) else {
            return TestResult::Fail("hold must exit DC6");
        };
        let Ok(_inner) = hold(&local, &regs, DcUser::Phy) else {
            return TestResult::Fail("a nested hold must be granted");
        };
        if regs.written(DC_STATE_EN) != [0] || local.core.lock().total() != 2 {
            return TestResult::Fail("one DC exit, two references");
        }
    }
    if local.core.lock().total() != 0
        || local.deadline.load(Ordering::Relaxed) != 3 * MS + DC_REENABLE_DELAY_NS
    {
        return TestResult::Fail("dropping the guards releases and defers re-entry");
    }
    if hold(&RefuseDcOff, &regs, DcUser::Aux).is_ok() {
        return TestResult::Fail("a refused exit must refuse the hold");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_dc",
    smoke_xe3plpd_dc_guard_releases_what_it_took
);

/// `intel_display_power_dc3co_compute` (Linux 7.4-rc4) on display 35: one
/// active pipe, eDP only, the CMTG's 1:1 pipe/port (A/A or B/B, unjoined,
/// `intel_dc3co_port_pipe_compatible`), PSR2 not in deep sleep, and a
/// trigger (`DC3CO_TRIGGER_LOBF`, `_PANEL_REPLAY` with AS SDP, `_PSR2` for
/// selective update) that AS SDP skip frames clears. The owned Nova panel
/// has none of the triggers, and a triggered state is still refused for
/// the unowned CMTG, so the service keeps DC6.
fn smoke_xe3plpd_dc3co_trigger_and_owned_refusal() -> TestResult {
    let panel = Dc3coState::OWNED_NOVA_PANEL;
    let psr2 = Dc3coState {
        sel_update: true,
        ..panel
    };
    let cases = [
        (panel, Err(Dc3coRefusal::NoTrigger)),
        (psr2, Ok(1)),
        (Dc3coState { lobf: true, ..panel }, Ok(2)),
        (
            Dc3coState {
                panel_replay_as_sdp: true,
                lobf: true,
                ..panel
            },
            Ok(6),
        ),
        (
            Dc3coState {
                pr_skip_frames: true,
                ..psr2
            },
            Err(Dc3coRefusal::NoTrigger),
        ),
        (
            Dc3coState {
                active_pipes: 0b11,
                ..psr2
            },
            Err(Dc3coRefusal::NotSinglePipe),
        ),
        (
            Dc3coState {
                active_pipes: 0,
                ..psr2
            },
            Err(Dc3coRefusal::NotSinglePipe),
        ),
        (Dc3coState { edp: false, ..psr2 }, Err(Dc3coRefusal::NotEdp)),
        (
            Dc3coState {
                active_pipes: 0b10,
                port: 1,
                ..psr2
            },
            Ok(1),
        ),
        (
            Dc3coState {
                active_pipes: 0b10,
                ..psr2
            },
            Err(Dc3coRefusal::PortPipe),
        ),
        (
            Dc3coState {
                active_pipes: 0b100,
                port: 2,
                ..psr2
            },
            Err(Dc3coRefusal::PortPipe),
        ),
        (
            Dc3coState {
                joined_pipes: 2,
                ..psr2
            },
            Err(Dc3coRefusal::PortPipe),
        ),
        (
            Dc3coState {
                psr2_deep_sleep: true,
                ..psr2
            },
            Err(Dc3coRefusal::Psr2DeepSleep),
        ),
    ];
    for (state, expected) in cases {
        if dc3co_trigger(&state) != expected {
            return TestResult::Fail("DC3CO trigger must follow intel_display_power_dc3co_compute");
        }
    }
    if xe3plpd_dc3co_refusal(&panel) != Dc3coRefusal::NoTrigger
        || xe3plpd_dc3co_refusal(&psr2) != Dc3coRefusal::CmtgUnowned
        || XE3PLPD_ALLOWED_DC_MASK & DC_STATE_EN_DC3CO != 0
        || XE3PLPD_ALLOWED_DC_MASK != DC6
    {
        return TestResult::Fail("the owned Nova panel keeps DC6 and never targets DC3CO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_dc",
    smoke_xe3plpd_dc3co_trigger_and_owned_refusal
);

/// The DMC wakelock (`intel_dmc_wl.c`): its mode is enabled only by the
/// driver, in `DMC_WAKELOCK_CFG`, as it enables DC5/DC6
/// (`intel_dmc_wl_enable`), and only then must accesses hold
/// `DMC_WAKELOCK1_CTL` to exit DC states. The display-35 service never
/// enables it and exits DC through `DC_off`, so a mode an earlier owner left
/// on (or an unreadable `DMC_WAKELOCK_CFG`) refuses re-entry before any
/// `DC_STATE_EN` write; with the mode off, the next release enters DC6.
fn smoke_xe3plpd_dc_refuses_inherited_dmc_wakelock_mode() -> TestResult {
    let regs = Regs::default();
    let core = IrqSafeSpinLock::new(DcCore::new_for(
        DmcPlatform::Xe3pLpd,
        XE3PLPD_ALLOWED_DC_MASK,
    ));
    {
        let mut c = core.lock();
        if c.sanitize(&regs).is_err() || c.get(&regs, DcUser::Init).is_err() {
            return TestResult::Fail("Init must be granted");
        }
    }
    let Some(mut due) =
        publication_step(&core, &regs, 0, || Ok(Arc::new(container(&[MAIN, PIPE_A]))))
    else {
        return TestResult::Fail("the display-35 container must load and release Init");
    };
    for (cfg, refusal) in [
        (DMC_WAKELOCK_CFG_ENABLE, ArmBlock::DmcWakelock),
        (u32::MAX, ArmBlock::Unavailable),
    ] {
        regs.set(DMC_WAKELOCK_CFG, cfg);
        regs.writes.borrow_mut().clear();
        if core.lock().arm_if_due(&regs, due, ArmGates::default()) != Err(refusal)
            || !regs.written(DC_STATE_EN).is_empty()
            || regs.get(DC_STATE_EN) & DC6 != 0
            || !regs.written(DMC_WAKELOCK_CFG).is_empty()
        {
            return TestResult::Fail("an inherited wakelock mode must keep DC0 untouched");
        }
        let mut c = core.lock();
        if c.get(&regs, DcUser::Kms).is_err() {
            return TestResult::Fail("a reference must still be granted in DC0");
        }
        match c.put(DcUser::Kms, due) {
            Some(next) => due = next,
            None => return TestResult::Fail("the release must reschedule re-entry"),
        }
    }
    regs.set(DMC_WAKELOCK_CFG, 0);
    if core.lock().arm_if_due(&regs, due, ArmGates::default()) != Ok(DC6)
        || regs.get(DC_STATE_EN) & DC6 == 0
    {
        return TestResult::Fail("with the wakelock mode off the service must enter DC6");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3plpd_dc",
    smoke_xe3plpd_dc_refuses_inherited_dmc_wakelock_mode
);
