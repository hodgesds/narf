//! Gen9 `DC_off` service fixtures. The fake is a plain register file with a
//! write log; the DMC program is the Gen9 DMC fixture container, streamed in
//! by the production `load_program`. Expected values are hand-derived from
//! the Linux sources cited in the module header (`gen9_dc_mask`,
//! `get_allowed_dc_mask`, `sanitize_target_dc_state`, `gen9_enable_dc5`,
//! `skl_enable_dc6`, `assert_can_enable_dc5` / `_dc6`, the `*_pwdoms_dc_off`
//! lists and `HSW_PWR_WELL_CTL_REQ/STATE`), never recorded from the service.
//! Clocks are explicit; nothing sleeps or spawns.

use super::*;
use crate::intel_gpu_dc_states::DC_STATE_EN_DC9;
use crate::intel_gpu_dmc::{load_program, parse_dmc_firmware_gen9_max, SKL_DMC_MAX_FW_SIZE};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

const MS: u64 = 1_000_000;
/// `DC_STATE_EN_UPTO_DC6` (0x2) and `DC_STATE_EN_UPTO_DC5` (0x1),
/// `intel_display_regs.h`.
const DC6: u32 = 0x2;
const DC5: u32 = 0x1;
/// `HSW_PWR_WELL_CTL_REQ(15) | HSW_PWR_WELL_CTL_STATE(15)`:
/// `(0x2 << 30) | (0x1 << 30)`.
const PW2_BITS: u32 = 0xC000_0000;
/// `UTIL_PIN_ENABLE | UTIL_PIN_MODE_PWM` (`intel_backlight_regs.h`).
const UTIL_PWM: u32 = (1 << 31) | (1 << 24);

/// A register file with a write log. The display-core wells model their
/// hardware: a `HSW_PWR_WELL_CTL2` request reports its state, the DBUF
/// slice's state follows its request, the PG0/PG1 fuses read distributed
/// (unless `fuse_stuck`), the DE PLL and DPLL0 (`LCPLL1_CTL`) lock while
/// enabled, and the pcode mailbox completes at once (its DATA0 reply is the
/// request, so Skylake's `SKL_CDCLK_PREPARE_FOR_CHANGE` 0x3 reads back with
/// `SKL_CDCLK_READY_FOR_CHANGE` 0x1 set). `drop_ram` drops DMC program-RAM
/// writes.
#[derive(Default)]
pub(crate) struct Fake {
    regs: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    dead: Cell<bool>,
    fuse_stuck: Cell<bool>,
    drop_ram: Cell<bool>,
}

impl Fake {
    pub(crate) fn set(&self, off: u64, val: u32) {
        self.regs.borrow_mut().insert(off, val);
    }
    pub(crate) fn get(&self, off: u64) -> u32 {
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
    /// S3: every register back at reset, program RAM included.
    fn power_loss(&self) {
        self.regs.borrow_mut().clear();
    }
}

/// `BXT_DE_PLL_ENABLE`, `BXT_DE_PLL_PLL_ENABLE` and `BXT_DE_PLL_LOCK`.
const DE_PLL_ENABLE: u64 = 0x46070;
const DE_PLL_ON: u32 = 1 << 31;
const DE_PLL_LOCK: u32 = 1 << 30;
/// `LCPLL1_CTL` (DPLL0): `LCPLL_PLL_ENABLE` bit 31 and `LCPLL_PLL_LOCK` bit
/// 30, the same bits as the DE PLL's.
const LCPLL1: u64 = 0x46010;
/// `BXT_DE_PLL_CTL` and `CDCLK_CTL`.
const DE_PLL_CTL: u64 = 0x6d000;
const CDCLK: u64 = 0x46000;
/// `DPLL_CTRL1`.
const CTRL1: u64 = 0x6c058;

impl MmioWindow for Fake {
    fn read32(&self, off: u64) -> u32 {
        if self.dead.get() {
            return u32::MAX;
        }
        if off == SKL_FUSE_STATUS && !self.fuse_stuck.get() {
            return self.get(off) | (1 << 27) | (1 << 26);
        }
        self.get(off)
    }
    fn write32(&self, off: u64, val: u32) {
        if self.dead.get() {
            return;
        }
        self.writes.borrow_mut().push((off, val));
        let stored = match off {
            HSW_PWR_WELL_CTL2 => (val & 0xAAAA_AAAA) | ((val & 0xAAAA_AAAA) >> 1),
            DBUF_CTL_S1 if val & (1 << 31) != 0 => val | (1 << 30),
            DBUF_CTL_S1 => val & !(1 << 30),
            DE_PLL_ENABLE if val & DE_PLL_ON != 0 => val | DE_PLL_LOCK,
            DE_PLL_ENABLE => val & !DE_PLL_LOCK,
            LCPLL1 if val & DE_PLL_ON != 0 => val | DE_PLL_LOCK,
            LCPLL1 => val & !DE_PLL_LOCK,
            crate::intel_gpu_pcode::PCODE_MAILBOX => 0,
            _ if self.drop_ram.get() && (0x80000..0x8F000).contains(&off) => return,
            _ => val,
        };
        self.set(off, stored);
    }
}

/// The Gen9 DMC fixture container, leaked for the service's `'static`
/// resident copy (the production copy is leaked once per boot too).
pub(crate) fn resident() -> &'static [u8] {
    alloc::boxed::Box::leak(crate::intel_gpu_gen9_dmc::tests::fixture_dmc_blob().into_boxed_slice())
}

/// Stream the fixture program into `regs` with the production loader.
pub(crate) fn load(regs: &dyn MmioWindow, blob: &'static [u8]) {
    let firmware = parse_dmc_firmware_gen9_max(blob, b'*', b'*', SKL_DMC_MAX_FW_SIZE)
        .expect("fixture DMC parses");
    load_program(regs, &firmware);
}

/// A core past probe on `fake`: booted (Init held), the program loaded and
/// handed over, Init released at `now`. Returns the core and the deadline.
pub(crate) fn booted(fake: &Fake, platform: Gen9Platform, now: u64) -> (Gen9DcCore, u64) {
    let blob = resident();
    load(fake, blob);
    let mut core = Gen9DcCore::new(platform);
    let _ = core.boot(fake);
    core.provide_program(blob, SKL_DMC_MAX_FW_SIZE);
    let due = core.release_init(now).unwrap_or(u64::MAX);
    (core, due)
}

/// [`booted`] and re-entered.
pub(crate) fn armed(fake: &Fake, platform: Gen9Platform) -> Gen9DcCore {
    let (mut core, due) = booted(fake, platform, 0);
    let _ = core.arm_if_due(fake, due, Gen9ArmGates::default());
    core
}

/// A fixture hook: a core of its own, written through whatever window the
/// holder passes (so its `DC_STATE_EN` writes land in the holder's write
/// log), with an explicit clock and the last scheduled deadline.
#[derive(Debug)]
pub(crate) struct LocalDc {
    pub(crate) core: IrqSafeSpinLock<Gen9DcCore>,
    pub(crate) now: AtomicU64,
    pub(crate) deadline: AtomicU64,
}

impl LocalDc {
    pub(crate) fn new(core: Gen9DcCore) -> Self {
        Self {
            core: IrqSafeSpinLock::new(core),
            now: AtomicU64::new(0),
            deadline: AtomicU64::new(0),
        }
    }
}

impl Gen9DcOff for LocalDc {
    fn get(&self, regs: &dyn MmioWindow, user: Gen9DcUser) -> Result<bool, DcError> {
        self.core.lock().get(regs, user)
    }
    fn put(&self, user: Gen9DcUser) {
        if let Some(at) = self.core.lock().put(user, self.now.load(Ordering::Relaxed)) {
            self.deadline.store(at, Ordering::Relaxed);
        }
    }
}

fn smoke_gen9_dc_service_register_facts() -> TestResult {
    // intel_display_regs.h: HSW_PWR_WELL_CTL1..4 at 0x45400..0x4540C,
    // SKL_PW_CTL_IDX_PW_2 = 15, REQ(i) = 0x2 << 2i, STATE(i) = 0x1 << 2i;
    // GEN8_CHICKEN_DCPR_1 at 0x46430, SKL_SELECT_ALTERNATE_DC_EXIT bit 30.
    if HSW_PWR_WELL_CTL1 != 0x45400
        || HSW_PWR_WELL_CTL2 != 0x45404
        || HSW_PWR_WELL_CTL3 != 0x45408
        || HSW_PWR_WELL_CTL4 != 0x4540C
        || PW_2_REQ_STATE != PW2_BITS
    {
        return TestResult::Fail("power-well control facts moved");
    }
    if GEN8_CHICKEN_DCPR_1 != 0x46430 || SKL_SELECT_ALTERNATE_DC_EXIT != 1 << 30 {
        return TestResult::Fail("Wa Display #1183 register facts moved");
    }
    // intel_display_power_map.c: GMBUS is in bxt/glk_pwdoms_dc_off only.
    let skl = Gen9DcCore::new(Gen9Platform::Skylake);
    let bxt = Gen9DcCore::new(Gen9Platform::Broxton);
    let glk = Gen9DcCore::new(Gen9Platform::GeminiLake);
    if skl.needs_dc_off(Gen9DcUser::Gmbus)
        || !bxt.needs_dc_off(Gen9DcUser::Gmbus)
        || !glk.needs_dc_off(Gen9DcUser::Gmbus)
    {
        return TestResult::Fail("GMBUS needs DC_off on Broxton/Gemini Lake only");
    }
    if !skl.needs_dc_off(Gen9DcUser::Aux) || !skl.needs_dc_off(Gen9DcUser::Modeset) {
        return TestResult::Fail("AUX_A and the commit's DC_OFF are dc_off domains on display 9");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_service_register_facts
);

/// Skylake re-enters DC6 (max_dc 2 → UPTO_DC6) with Wa Display #1183
/// written first; Broxton and Gemini Lake re-enter DC5 (max_dc 1, DC6
/// sanitized to DC5) without it (`DISPLAY_VER == 9 && !broxton`; Gemini
/// Lake is display 10).
fn smoke_gen9_dc_skylake_dc6_versus_lp_dc5() -> TestResult {
    for platform in [
        Gen9Platform::Skylake,
        Gen9Platform::KabyLake,
        Gen9Platform::CometLake,
    ] {
        let fake = Fake::default();
        let (mut core, due) = booted(&fake, platform, 0);
        if fake.get(DC_STATE_EN) != 0 || core.refs(Gen9DcUser::Init) != 0 {
            return TestResult::Fail("boot must leave DC0 and release Init with a program");
        }
        if due != DC_REENABLE_DELAY_NS {
            return TestResult::Fail("the Init release must defer re-entry 17 ms");
        }
        fake.clear_log();
        if core.arm_if_due(&fake, due - 1, Gen9ArmGates::default())
            != Err(Gen9ArmBlock::NotDue(due))
        {
            return TestResult::Fail("re-entry before the deadline must wait");
        }
        if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC6) {
            return TestResult::Fail("display 9 must re-enter DC6");
        }
        let log = fake.log();
        let wa = log
            .iter()
            .position(|(o, v)| *o == GEN8_CHICKEN_DCPR_1 && *v & (1 << 30) != 0);
        let dc = log.iter().position(|(o, v)| *o == DC_STATE_EN && *v == DC6);
        match (wa, dc) {
            (Some(wa), Some(dc)) if wa < dc => {}
            _ => return TestResult::Fail("Wa #1183 must be written before DC6 is enabled"),
        }
        if fake.get(DC_STATE_EN) != DC6 || !core.armed() {
            return TestResult::Fail("DC_STATE_EN must read UPTO_DC6");
        }
    }
    for platform in [Gen9Platform::Broxton, Gen9Platform::GeminiLake] {
        let fake = Fake::default();
        let (mut core, due) = booted(&fake, platform, 0);
        fake.clear_log();
        if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC5) {
            return TestResult::Fail("Gen9 LP must re-enter DC5");
        }
        if fake.get(DC_STATE_EN) != DC5 {
            return TestResult::Fail("DC_STATE_EN must read UPTO_DC5 on Gen9 LP");
        }
        if !fake.writes_to(GEN8_CHICKEN_DCPR_1).is_empty() {
            return TestResult::Fail("Wa #1183 must not be written on Broxton/Gemini Lake");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_skylake_dc6_versus_lp_dc5
);

/// Without a DMC program the Init reference is kept (DC0, wells up), and a
/// forced release still refuses re-entry: nothing is written.
fn smoke_gen9_dc_refuses_without_dmc() -> TestResult {
    let fake = Fake::default();
    fake.set(DC_STATE_EN, DC6);
    let mut core = Gen9DcCore::new(Gen9Platform::Skylake);
    let _ = core.boot(&fake);
    // skl_display_core_init: DC_STATE_DISABLE first.
    if fake.get(DC_STATE_EN) != 0 || core.refs(Gen9DcUser::Init) != 1 {
        return TestResult::Fail("boot must disable DC states and hold Init");
    }
    if core.release_init(0).is_some() || core.refs(Gen9DcUser::Init) != 1 {
        return TestResult::Fail("Init must be kept without a DMC program");
    }
    // A reference taken and dropped by another user while Init is pinned:
    // the release is not the last one.
    if core.get(&fake, Gen9DcUser::Modeset) != Ok(true)
        || core.put(Gen9DcUser::Modeset, 0).is_some()
    {
        return TestResult::Fail("Init must keep the well held across other users");
    }
    // Even with every reference gone, no program means no re-entry.
    let mut bare = Gen9DcCore::new(Gen9Platform::Skylake);
    let _ = bare.get(&fake, Gen9DcUser::Kms);
    let Some(due) = bare.put(Gen9DcUser::Kms, 0) else {
        return TestResult::Fail("the last release must schedule re-entry");
    };
    fake.clear_log();
    if bare.arm_if_due(&fake, due, Gen9ArmGates::default()) != Err(Gen9ArmBlock::NoProgram) {
        return TestResult::Fail("re-entry without a DMC program must refuse");
    }
    if !fake.log().is_empty() {
        return TestResult::Fail("a refused re-entry must write nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_refuses_without_dmc
);

/// assert_can_enable_dc5: power well 2 must be off. Any requester's REQ bit
/// (BIOS, driver, KVMR, debug) or the STATE bit refuses, for the DC6 target
/// too; the utility pin in PWM mode refuses DC6 only.
fn smoke_gen9_dc_refuses_with_power_well_2() -> TestResult {
    for reg in [
        HSW_PWR_WELL_CTL1,
        HSW_PWR_WELL_CTL2,
        HSW_PWR_WELL_CTL3,
        HSW_PWR_WELL_CTL4,
    ] {
        for bits in [1u32 << 31, 1 << 30] {
            let fake = Fake::default();
            let (mut core, due) = booted(&fake, Gen9Platform::Skylake, 0);
            // DDI IO A (idx 1) for the eDP panel does not block DC5.
            fake.set(HSW_PWR_WELL_CTL2, 0xC);
            fake.set(reg, fake.get(reg) | bits);
            fake.clear_log();
            match core.arm_if_due(&fake, due, Gen9ArmGates::default()) {
                Err(Gen9ArmBlock::PowerWell2 { reg: r, .. }) if r == reg => {}
                _ => {
                    return TestResult::Fail("a PW_2 request or state bit must refuse DC re-entry")
                }
            }
            if !fake.log().is_empty() || fake.get(DC_STATE_EN) != 0 {
                return TestResult::Fail("a PW_2 refusal must write nothing");
            }
        }
    }
    // PW_2 off but DDI IO A requested: Skylake arms.
    let fake = Fake::default();
    let (mut core, due) = booted(&fake, Gen9Platform::Skylake, 0);
    fake.set(HSW_PWR_WELL_CTL2, 0xC);
    if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC6) {
        return TestResult::Fail("DDI IO wells alone must not block DC6");
    }
    // Utility pin in PWM mode: DC6 refused on Skylake ...
    let fake = Fake::default();
    let (mut core, due) = booted(&fake, Gen9Platform::Skylake, 0);
    fake.set(UTIL_PIN_CTL, UTIL_PWM);
    if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Err(Gen9ArmBlock::UtilPinPwm) {
        return TestResult::Fail("DC6 with the utility pin in PWM mode must refuse");
    }
    // ... but not checked for Broxton's DC5 (gen9_enable_dc5 has no
    // utility-pin assert).
    let fake = Fake::default();
    let (mut core, due) = booted(&fake, Gen9Platform::Broxton, 0);
    fake.set(UTIL_PIN_CTL, UTIL_PWM);
    if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC5) {
        return TestResult::Fail("DC5 does not depend on the utility pin");
    }
    // A live external route refuses too.
    let fake = Fake::default();
    let (mut core, due) = booted(&fake, Gen9Platform::Skylake, 0);
    let gates = Gen9ArmGates {
        external_route_active: true,
    };
    if core.arm_if_due(&fake, due, gates) != Err(Gen9ArmBlock::ExternalRoute) {
        return TestResult::Fail("a live external route must refuse re-entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_refuses_with_power_well_2
);

/// The first reference exits DC6 before the holder touches hardware;
/// nested references write nothing; the last release defers re-entry 17
/// ms; a reference inside the deferral cancels it without a write.
fn smoke_gen9_dc_exit_before_hardware_and_deferral() -> TestResult {
    let fake = Fake::default();
    let mut core = armed(&fake, Gen9Platform::Skylake);
    if fake.get(DC_STATE_EN) != DC6 {
        return TestResult::Fail("fixture must start in DC6");
    }
    fake.clear_log();
    if core.get(&fake, Gen9DcUser::Aux) != Ok(true) {
        return TestResult::Fail("the first reference must be granted");
    }
    fake.write32(0x64010, 0x8000_0000); // DDI_AUX_CTL_A
    let log = fake.log();
    if log.first() != Some(&(DC_STATE_EN, 0)) || log.last() != Some(&(0x64010, 0x8000_0000)) {
        return TestResult::Fail("DC exit must be written before any display register");
    }
    fake.clear_log();
    if core.get(&fake, Gen9DcUser::Modeset) != Ok(true) || !fake.log().is_empty() {
        return TestResult::Fail("a nested reference must not touch DC_STATE_EN");
    }
    if core.put(Gen9DcUser::Modeset, 5 * MS).is_some() {
        return TestResult::Fail("re-entry must wait for every user");
    }
    if core.put(Gen9DcUser::Suspend, 5 * MS).is_some() || core.refs(Gen9DcUser::Aux) != 1 {
        return TestResult::Fail("an unbalanced release must not release another user");
    }
    if core.arm_if_due(&fake, u64::MAX, Gen9ArmGates::default()) != Err(Gen9ArmBlock::Busy) {
        return TestResult::Fail("re-entry with a held reference must refuse");
    }
    let Some(due) = core.put(Gen9DcUser::Aux, 10 * MS) else {
        return TestResult::Fail("the last release must schedule re-entry");
    };
    if due != 10 * MS + 17 * MS {
        return TestResult::Fail("re-entry must be deferred 17 ms");
    }
    if core.get(&fake, Gen9DcUser::Kms) != Ok(true) || core.arm_deadline().is_some() {
        return TestResult::Fail("a reference inside the deferral must cancel re-entry");
    }
    if !fake.log().is_empty() {
        return TestResult::Fail("cancelling a deferral must not write DC_STATE_EN");
    }
    let due = core.put(Gen9DcUser::Kms, 30 * MS).unwrap_or(0);
    if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC6) {
        return TestResult::Fail("DC6 must be re-entered after the deferral");
    }
    // GMBUS on display 9 holds nothing: DC6 stays armed.
    fake.clear_log();
    if core.get(&fake, Gen9DcUser::Gmbus) != Ok(false) || !fake.log().is_empty() {
        return TestResult::Fail("GMBUS is not a dc_off domain on display 9");
    }
    // On Gen9 LP it exits DC5.
    let lp = Fake::default();
    let mut core = armed(&lp, Gen9Platform::GeminiLake);
    if lp.get(DC_STATE_EN) != DC5 || core.get(&lp, Gen9DcUser::Gmbus) != Ok(true) {
        return TestResult::Fail("GMBUS must take DC_off on Gemini Lake");
    }
    if lp.get(DC_STATE_EN) != 0 {
        return TestResult::Fail("GMBUS on Gemini Lake must exit DC5 first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_exit_before_hardware_and_deferral
);

/// System suspend disarms DC6 and holds DC states off. Resume runs the
/// display-core init (`skl_display_core_init(resume)`: DC_STATE_DISABLE, the
/// PCH reset handshake, PW_1 with its PG0/PG1 fuses, MISC IO,
/// `intel_cdclk_init_hw`, the DBUF slice) and reloads the resident program
/// (`intel_dmc_load_program`) before releasing the Suspend reference: DC6
/// returns 17 ms later whether the program survived (s2idle) or was lost
/// with system power (S3).
fn smoke_gen9_dc_suspend_disarms() -> TestResult {
    let fake = Fake::default();
    let mut core = armed(&fake, Gen9Platform::Skylake);
    fake.clear_log();
    if core.suspend_begin(&fake).is_err() || core.suspend_begin(&fake).is_err() {
        return TestResult::Fail("suspend preparation must succeed (idempotently)");
    }
    if fake.writes_to(DC_STATE_EN).first() != Some(&0) || fake.get(DC_STATE_EN) != 0 {
        return TestResult::Fail("suspend must disarm to DC_STATE_DISABLE");
    }
    if core.refs(Gen9DcUser::Suspend) != 1 || core.armed() {
        return TestResult::Fail("suspend must hold one Suspend reference");
    }
    if core.arm_if_due(&fake, u64::MAX, Gen9ArmGates::default()) != Err(Gen9ArmBlock::Busy) {
        return TestResult::Fail("no re-entry while suspended");
    }
    // Display 9 has no DC9: the LP-only step refuses before any write.
    fake.clear_log();
    if core.dc9_admit(&fake) != Err(Dc9Block::NotLp) || !fake.log().is_empty() {
        return TestResult::Fail("DC9 is not a display-9 state");
    }
    // Program retained: reloaded anyway, released and re-armed.
    let Ok(Some(due)) = core.resume(&fake, 40 * MS) else {
        return TestResult::Fail("a reloaded program must release the Suspend reference");
    };
    if due != 57 * MS || core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC6) {
        return TestResult::Fail("DC6 must be re-entered 17 ms after resume");
    }
    // Power loss across the suspend: the display-core init and the reload
    // restore the program, then the Suspend reference is released.
    if core.suspend_begin(&fake).is_err() {
        return TestResult::Fail("second suspend preparation failed");
    }
    fake.power_loss();
    fake.clear_log();
    let Ok(Some(due)) = core.resume(&fake, 100 * MS) else {
        return TestResult::Fail("the post-S3 reload must release the Suspend reference");
    };
    let log = fake.log();
    let pw1 = log
        .iter()
        .position(|(o, v)| *o == HSW_PWR_WELL_CTL2 && v & (1 << 29) != 0);
    let misc_io = log
        .iter()
        .position(|(o, v)| *o == HSW_PWR_WELL_CTL2 && v & (1 << 1) != 0);
    let dbuf = log
        .iter()
        .position(|(o, v)| *o == DBUF_CTL_S1 && v & (1 << 31) != 0);
    let ram = log.iter().position(|(o, _)| (0x80000..0x8F000).contains(o));
    let pch = log
        .iter()
        .position(|(o, v)| *o == HSW_NDE_RSTWRN_OPT && v & (1 << 4) != 0);
    let cdclk = log.iter().position(|(o, _)| *o == CDCLK);
    match (pch, pw1, misc_io, cdclk, dbuf, ram) {
        (Some(h), Some(p), Some(m), Some(c), Some(d), Some(r))
            if h < p && p < m && m < c && c < d && d < r => {}
        _ => {
            return TestResult::Fail(
                "PCH handshake, PW_1, MISC IO, CDCLK and DBUF must precede the program reload",
            )
        }
    }
    if core.program_lost()
        || due != 117 * MS
        || core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC6)
    {
        return TestResult::Fail("DC6 must be re-entered after the post-S3 reload");
    }
    // A program RAM that drops the reload: lost, Suspend kept, DC0.
    let _ = core.suspend_begin(&fake);
    fake.power_loss();
    fake.drop_ram.set(true);
    if core.resume(&fake, 200 * MS) != Ok(None)
        || core.refs(Gen9DcUser::Suspend) != 1
        || !core.program_lost()
        || fake.get(DC_STATE_EN) != 0
    {
        return TestResult::Fail("a reload that does not verify must keep DC states off");
    }
    // A PG1 fuse that never distributes: the init refuses and nothing is
    // reloaded.
    fake.drop_ram.set(false);
    fake.fuse_stuck.set(true);
    fake.power_loss();
    fake.clear_log();
    if core.resume(&fake, 300 * MS) != Ok(None)
        || fake
            .log()
            .iter()
            .any(|(o, _)| (0x80000..0x8F000).contains(o))
    {
        return TestResult::Fail("a failed display-core init must not reload the program");
    }
    // A DC9 bit left by firmware on Gen9 LP is cleared by the resume
    // (gen9_dc_mask carries DC9 there); LP requests no MISC IO well.
    let lp = Fake::default();
    let mut core = armed(&lp, Gen9Platform::Broxton);
    let _ = core.suspend_begin(&lp);
    lp.set(DC_STATE_EN, DC_STATE_EN_DC9);
    lp.clear_log();
    if core.resume(&lp, 0).is_err() || lp.get(DC_STATE_EN) & DC_STATE_EN_DC9 != 0 {
        return TestResult::Fail("resume must leave no DC state enabled");
    }
    if lp.get(HSW_PWR_WELL_CTL2) & (1 << 1) != 0 || core.refs(Gen9DcUser::Suspend) != 0 {
        return TestResult::Fail("Gen9 LP resumes PW_1 alone and releases Suspend");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_suspend_disarms
);

/// Gen9 LP system suspend (`intel_display_power_suspend_late`): after the
/// Suspend reference, with the display dark, `bxt_display_core_uninit`
/// (DBUF off, CDCLK to the bypass with the DE PLL off, the PW_1 request
/// dropped) and `bxt_enable_dc9` (`bxt_pps_reset_all`, then DC_STATE_EN =
/// DC9). Nothing is granted while DC9 holds. Resume
/// (`intel_display_power_resume_early`) runs `bxt_disable_dc9`, the
/// display-core init and the reload, then DC5 returns.
fn smoke_gen9_lp_dc9_suspend_and_resume() -> TestResult {
    const DC9: u32 = 1 << 3;
    for platform in [Gen9Platform::Broxton, Gen9Platform::GeminiLake] {
        let fake = Fake::default();
        let mut core = armed(&fake, platform);
        // The display core as probe left it: PW_1 requested, DBUF powered,
        // the DE PLL locked at 624 (BXT) or 316.8 MHz (GLK).
        fake.write32(HSW_PWR_WELL_CTL2, 1 << 29);
        fake.write32(DBUF_CTL_S1, 1 << 31);
        fake.set(DE_PLL_ENABLE, DE_PLL_ON | DE_PLL_LOCK);
        fake.set(
            0x6d000,
            if platform == Gen9Platform::GeminiLake {
                33
            } else {
                65
            },
        );
        if core.suspend_begin(&fake).is_err() || fake.get(DC_STATE_EN) != 0 {
            return TestResult::Fail("suspend must exit DC5 first");
        }
        fake.clear_log();
        if core.dc9_admit(&fake).is_err() || !fake.log().is_empty() {
            return TestResult::Fail("a dark display must admit DC9 without a write");
        }
        if display_core_uninit_lp(&fake, core.glk()).is_err() {
            return TestResult::Fail("the display-core uninit must complete");
        }
        if core.enter_dc9(&fake).is_err() || !core.dc9() || fake.get(DC_STATE_EN) != DC9 {
            return TestResult::Fail("DC_STATE_EN must read DC9");
        }
        let log = fake.log();
        let dbuf = log
            .iter()
            .position(|(o, v)| *o == DBUF_CTL_S1 && v & (1 << 31) == 0);
        let pll = log.iter().position(|w| *w == (DE_PLL_ENABLE, 0));
        let pw1 = log
            .iter()
            .position(|(o, v)| *o == HSW_PWR_WELL_CTL2 && v & (1 << 29) == 0);
        let dc9 = log.iter().position(|w| *w == (DC_STATE_EN, DC9));
        match (dbuf, pll, pw1, dc9) {
            (Some(d), Some(p), Some(w), Some(c)) if d < p && p < w && w < c => {}
            _ => return TestResult::Fail("DBUF, DE PLL, PW_1, then DC9"),
        }
        // CDCLK_CTL's decimal field: DIV_ROUND_CLOSEST(19200 - 1000, 500).
        if fake.get(0x46000) & 0x7ff != 36 {
            return TestResult::Fail("CDCLK must sit at the 19.2 MHz bypass");
        }
        // Fenced: no holder runs in DC9.
        fake.clear_log();
        if core.get(&fake, Gen9DcUser::Aux) != Err(DcError::Unavailable) || !fake.log().is_empty() {
            return TestResult::Fail("no reference may be granted in DC9");
        }
        // bxt_pps_reset_all, consumed once by the next sequencer user.
        if !core.take_pps_reset() || core.take_pps_reset() {
            return TestResult::Fail("DC9 entry must flag the PPS for reprogramming once");
        }
        // Resume: DC9 exit, PW_1 and DBUF back, the program reloaded.
        fake.power_loss();
        fake.set(DC_STATE_EN, DC9);
        fake.clear_log();
        let Ok(Some(due)) = core.resume(&fake, 50 * MS) else {
            return TestResult::Fail("the resume must release the Suspend reference");
        };
        let log = fake.log();
        let exit = log.iter().position(|w| *w == (DC_STATE_EN, 0));
        let pw1 = log
            .iter()
            .position(|(o, v)| *o == HSW_PWR_WELL_CTL2 && v & (1 << 29) != 0);
        let ram = log.iter().position(|(o, _)| (0x80000..0x8F000).contains(o));
        match (exit, pw1, ram) {
            (Some(0), Some(p), Some(r)) if p < r => {}
            _ => return TestResult::Fail("bxt_disable_dc9, then PW_1, then the reload"),
        }
        if core.dc9() || core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Ok(DC5) {
            return TestResult::Fail("DC5 must return after the resume");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_lp_dc9_suspend_and_resume
);

/// DC9 admission refuses before any write (`assert_can_enable_dc9`'s
/// checks, the dark-display check, a busy holder), and the abort lifts the
/// fence: the Suspend reference and DC0 stay.
fn smoke_gen9_lp_dc9_refusals() -> TestResult {
    let refuse = |setup: &dyn Fn(&Fake, &mut Gen9DcCore), want: Dc9Block| -> bool {
        let fake = Fake::default();
        let mut core = armed(&fake, Gen9Platform::Broxton);
        if core.suspend_begin(&fake).is_err() {
            return false;
        }
        setup(&fake, &mut core);
        fake.clear_log();
        let got = core.dc9_admit(&fake);
        core.dc9_abort();
        got == Err(want)
            && fake.log().is_empty()
            && core.get(&fake, Gen9DcUser::Kms) == Ok(true)
            && core.refs(Gen9DcUser::Suspend) == 1
    };
    if !refuse(
        &|fake, _| fake.set(0x70008, 1 << 31),
        Dc9Block::DisplayActive {
            reg: 0x70008,
            value: 1 << 31,
        },
    ) || !refuse(
        &|fake, _| fake.set(0x7f008, (1 << 31) | (1 << 30)),
        Dc9Block::DisplayActive {
            reg: 0x7f008,
            value: (1 << 31) | (1 << 30),
        },
    ) {
        return TestResult::Fail("an enabled transcoder must refuse DC9");
    }
    if !refuse(
        &|fake, _| fake.set(HSW_PWR_WELL_CTL2, 1 << 31),
        Dc9Block::PowerWell2(1 << 31),
    ) {
        return TestResult::Fail("a PW_2 request must refuse DC9");
    }
    if !refuse(
        &|fake, _| fake.set(DC_STATE_EN, DC5),
        Dc9Block::Dc5Programmed,
    ) || !refuse(
        &|fake, _| fake.set(DC_STATE_EN, DC_STATE_EN_DC9),
        Dc9Block::AlreadyProgrammed,
    ) {
        return TestResult::Fail("DC5 or DC9 already programmed must refuse DC9");
    }
    if !refuse(
        &|fake, core| {
            let _ = core.get(fake, Gen9DcUser::Aux);
        },
        Dc9Block::Busy,
    ) {
        return TestResult::Fail("a holder in its conversation must refuse DC9");
    }
    // DC9 without the Suspend reference, and before any admission.
    let fake = Fake::default();
    let mut core = armed(&fake, Gen9Platform::GeminiLake);
    if core.dc9_admit(&fake) != Err(Dc9Block::NotSuspending)
        || core.enter_dc9(&fake) != Err(Dc9Block::NotSuspending)
    {
        return TestResult::Fail("DC9 needs the Suspend reference and an admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_lp_dc9_refusals
);

/// `__gt_unpark` holds `POWER_DOMAIN_GT_IRQ` (in every Gen9 `dc_off` list)
/// while the GT is awake; `__gt_park` drops it with the 100 ms async put.
/// Re-entry after the GT parks waits those 100 ms even past a later 17 ms
/// release; a new unpark takes the pending put over.
fn smoke_gen9_dc_gt_irq_hold_while_unparked() -> TestResult {
    for platform in [
        Gen9Platform::Skylake,
        Gen9Platform::Broxton,
        Gen9Platform::GeminiLake,
    ] {
        if !Gen9DcCore::new(platform).needs_dc_off(Gen9DcUser::GtIrq) {
            return TestResult::Fail("GT_IRQ is a dc_off domain on every Gen9 part");
        }
    }
    if GT_IRQ_PUT_DELAY_NS != 100 * MS {
        return TestResult::Fail("the GT_IRQ put is Linux's default 100 ms async put");
    }
    let fake = Fake::default();
    let mut core = armed(&fake, Gen9Platform::Skylake);
    fake.clear_log();
    // Unpark: DC6 exits before the GT touches anything.
    if core.get(&fake, Gen9DcUser::GtIrq) != Ok(true)
        || fake.log().first() != Some(&(DC_STATE_EN, 0))
    {
        return TestResult::Fail("unpark must exit DC6");
    }
    // Display work while the GT is awake never schedules re-entry.
    let _ = core.get(&fake, Gen9DcUser::Kms);
    if core.put(Gen9DcUser::Kms, 5 * MS).is_some() {
        return TestResult::Fail("the awake GT must keep DC states off");
    }
    // Park at 10 ms: re-entry at 110 ms, not 27 ms.
    if core.put(Gen9DcUser::GtIrq, 10 * MS) != Some(110 * MS) {
        return TestResult::Fail("the GT_IRQ release must defer re-entry 100 ms");
    }
    if core.arm_if_due(&fake, 27 * MS, Gen9ArmGates::default())
        != Err(Gen9ArmBlock::NotDue(110 * MS))
    {
        return TestResult::Fail("no re-entry inside the GT_IRQ put");
    }
    // A display release inside the put still waits for it.
    let _ = core.get(&fake, Gen9DcUser::Kms);
    if core.put(Gen9DcUser::Kms, 30 * MS) != Some(110 * MS) {
        return TestResult::Fail("a 17 ms release must not shorten the GT_IRQ put");
    }
    // A new unpark takes the pending put over; its own park restarts it.
    let _ = core.get(&fake, Gen9DcUser::GtIrq);
    if core.put(Gen9DcUser::GtIrq, 200 * MS) != Some(300 * MS) {
        return TestResult::Fail("the second park restarts the 100 ms put");
    }
    // Once it has passed, a display release is back to 17 ms.
    let _ = core.get(&fake, Gen9DcUser::Kms);
    if core.put(Gen9DcUser::Kms, 400 * MS) != Some(417 * MS) {
        return TestResult::Fail("an elapsed GT_IRQ put must not delay later releases");
    }
    if core.arm_if_due(&fake, 417 * MS, Gen9ArmGates::default()) != Ok(DC6) {
        return TestResult::Fail("DC6 must return once the GT is parked");
    }
    // Without a Gen9 service the production hold is inert.
    if service().is_none() {
        let bar = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0xF000_0000),
            virt: 0,
            len: 0,
            kind: narf_bus::BarKind::Mmio64 {
                prefetchable: false,
            },
        };
        if gt_unparked(&bar).is_none_or(|r| r.service.is_some()) || take_pps_reset_for_bar(&bar) {
            return TestResult::Fail("without a service the GT_IRQ hold must be inert");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_gt_irq_hold_while_unparked
);

/// A program that stops verifying is never re-entered; an all-ones
/// `DC_STATE_EN` refuses the reference with nothing counted.
fn smoke_gen9_dc_lost_program_and_faults() -> TestResult {
    let fake = Fake::default();
    let (mut core, due) = booted(&fake, Gen9Platform::Skylake, 0);
    fake.set(0x80000, 0);
    if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Err(Gen9ArmBlock::ProgramLost) {
        return TestResult::Fail("a program that no longer verifies must refuse re-entry");
    }
    if fake.get(DC_STATE_EN) != 0 || !core.program_lost() {
        return TestResult::Fail("a lost program must leave DC0 and latch");
    }
    let _ = core.get(&fake, Gen9DcUser::Kms);
    let due = core.put(Gen9DcUser::Kms, 0).unwrap_or(0);
    if core.arm_if_due(&fake, due, Gen9ArmGates::default()) != Err(Gen9ArmBlock::ProgramLost) {
        return TestResult::Fail("a lost program stays lost");
    }
    // Function out of D0: the reference refuses, nothing is written.
    let fake = Fake::default();
    let mut core = armed(&fake, Gen9Platform::Skylake);
    fake.dead.set(true);
    if core.get(&fake, Gen9DcUser::Modeset) != Err(DcError::Unavailable)
        || core.refs(Gen9DcUser::Modeset) != 0
    {
        return TestResult::Fail("an all-ones DC_STATE_EN must refuse the reference");
    }
    // A boot that could not write DC_STATE_DISABLE keeps Init for good,
    // even with a program handed over.
    let mut core = Gen9DcCore::new(Gen9Platform::Skylake);
    if core.boot(&fake) != Err(DcError::Unavailable) {
        return TestResult::Fail("boot over an all-ones DC_STATE_EN must fail");
    }
    core.provide_program(resident(), SKL_DMC_MAX_FW_SIZE);
    if core.release_init(0).is_some() || core.refs(Gen9DcUser::Init) != 1 {
        return TestResult::Fail("a failed boot must keep the Init reference");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_lost_program_and_faults
);

/// The guard: `hold` counts through the hook before returning, its drop
/// releases exactly what it counted, and a user outside the platform's
/// `DC_off` domains (GMBUS on display 9) neither counts nor releases.
fn smoke_gen9_dc_guard_releases_what_it_took() -> TestResult {
    let fake = Fake::default();
    let local = LocalDc::new(armed(&fake, Gen9Platform::Skylake));
    local.now.store(3 * MS, Ordering::Relaxed);
    fake.clear_log();
    {
        let Ok(_outer) = hold(&local, &fake, Gen9DcUser::Modeset) else {
            return TestResult::Fail("hold must exit DC6");
        };
        if fake.log().first() != Some(&(DC_STATE_EN, 0)) {
            return TestResult::Fail("hold must write the DC exit before returning");
        }
        let Ok(_inner) = hold(&local, &fake, Gen9DcUser::Aux) else {
            return TestResult::Fail("a nested hold must be granted");
        };
        if local.core.lock().total() != 2 {
            return TestResult::Fail("both holds must be counted");
        }
    }
    if local.core.lock().total() != 0
        || local.deadline.load(Ordering::Relaxed) != 3 * MS + DC_REENABLE_DELAY_NS
    {
        return TestResult::Fail("dropping the guards must release and schedule re-entry");
    }
    let due = local.deadline.load(Ordering::Relaxed);
    if local
        .core
        .lock()
        .arm_if_due(&fake, due, Gen9ArmGates::default())
        != Ok(DC6)
    {
        return TestResult::Fail("DC6 must be re-entered after the guards dropped");
    }
    fake.clear_log();
    match hold(&local, &fake, Gen9DcUser::Gmbus) {
        Ok(guard) => drop(guard),
        Err(_) => return TestResult::Fail("an inert hold must succeed"),
    }
    if !fake.log().is_empty() || local.core.lock().arm_deadline().is_some() {
        return TestResult::Fail("an inert hold must neither exit nor reschedule");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_guard_releases_what_it_took
);

/// The option is strict and default off: without exactly one
/// `narf.intel.gen9_dc=1` before `--` no core is created and nothing is
/// written; with it, install disables DC states (`skl_display_core_init`'s
/// DC_STATE_DISABLE) and holds Init.
fn smoke_gen9_dc_refuses_without_the_option() -> TestResult {
    use narf_boot::args::KernelCmdline;
    if !requested(KernelCmdline::new("quiet narf.intel.gen9_dc=1")) {
        return TestResult::Fail("narf.intel.gen9_dc=1 must opt in");
    }
    for line in [
        "",
        "quiet",
        "narf.intel.gen9_dc",
        "narf.intel.gen9_dc=0",
        "narf.intel.gen9_dc=yes",
        "narf.intel.gen9_dc=1 narf.intel.gen9_dc=1",
        "-- narf.intel.gen9_dc=1",
    ] {
        if requested(KernelCmdline::new(line)) {
            return TestResult::Fail("only one exact narf.intel.gen9_dc=1 before -- opts in");
        }
    }
    let fake = Fake::default();
    fake.set(DC_STATE_EN, DC6);
    if boot_if_requested(false, Gen9Platform::Skylake, &fake).is_some() {
        return TestResult::Fail("no core may exist without the option");
    }
    if !fake.log().is_empty() || fake.get(DC_STATE_EN) != DC6 {
        return TestResult::Fail("without the option nothing may be written");
    }
    let Some(core) = boot_if_requested(true, Gen9Platform::Skylake, &fake) else {
        return TestResult::Fail("the option must create the core");
    };
    if fake.writes_to(DC_STATE_EN) != [0] || core.refs(Gen9DcUser::Init) != 1 || core.armed() {
        return TestResult::Fail("install must write DC_STATE_DISABLE and hold Init");
    }
    // Probe with no service installed (every fixture boot, and every boot
    // without the option): the production references hold nothing.
    if service().is_none() {
        match acquire(Gen9DcUser::Modeset) {
            Ok(reference) if reference.service.is_none() => {}
            _ => return TestResult::Fail("without a service the reference must be inert"),
        }
        if ServiceDcOff.get(&fake, Gen9DcUser::Aux) != Ok(false) {
            return TestResult::Fail("without a service the hook must count nothing");
        }
    }
    // The shared KMS/legacy-guard vocabulary lands on the matching users.
    if Gen9DcUser::from(DcUser::Kms) != Gen9DcUser::Kms
        || Gen9DcUser::from(DcUser::Modeset) != Gen9DcUser::Modeset
        || Gen9DcUser::from(DcUser::Aux) != Gen9DcUser::Aux
        || Gen9DcUser::from(DcUser::External) != Gen9DcUser::External
        || Gen9DcUser::from(DcUser::Suspend) != Gen9DcUser::Suspend
        || Gen9DcUser::from(DcUser::Phy) != Gen9DcUser::Modeset
    {
        return TestResult::Fail("the display-14 users must map onto the Gen9 users");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_refuses_without_the_option
);

/// A hook whose DC exit always fails (`DC_STATE_EN` unavailable).
struct Refuse;

impl Gen9DcOff for Refuse {
    fn get(&self, _regs: &dyn MmioWindow, _user: Gen9DcUser) -> Result<bool, DcError> {
        Err(DcError::Unavailable)
    }
    fn put(&self, _user: Gen9DcUser) {}
}

/// A Skylake sink window armed in DC6: the fixture DMC loaded, the core
/// booted, Init released and DC6 re-entered, all through `sink`.
fn armed_sink(
    sink: &crate::intel_gpu_modeset::tests::ScriptedSinkMmio,
) -> Result<LocalDc, &'static str> {
    let blob = resident();
    load(sink, blob);
    let mut core = Gen9DcCore::new(Gen9Platform::Skylake);
    let _ = core.boot(sink);
    core.provide_program(blob, SKL_DMC_MAX_FW_SIZE);
    let due = core
        .release_init(0)
        .ok_or("Init must be released with a program")?;
    if core.arm_if_due(sink, due, Gen9ArmGates::default()) != Ok(DC6) {
        return Err("the sink fixture must start in DC6");
    }
    Ok(LocalDc::new(core))
}

/// The Gen9 modeset holds DC_off for its whole run
/// (`intel_atomic_commit_tail`'s `POWER_DOMAIN_DC_OFF`): `DC_STATE_EN` is
/// written to `DC_STATE_DISABLE` before any other display register, is not
/// re-armed while the run lasts, and re-entry is deferred 17 ms after it.
/// A refused DC exit runs nothing.
fn smoke_gen9_dc_brackets_the_modeset() -> TestResult {
    use crate::intel_gpu_ddi::Ddi;
    use crate::intel_gpu_modeset::tests::ScriptedSinkMmio;
    use crate::intel_gpu_modeset::{Framebuffer, Modeset, ModesetError, PixelFormat};
    crate::intel_gpu_gen9_dmc::set_gen9_dmc_loaded_for_test(true);
    let fb = Framebuffer {
        phys_addr: 0x100_0000,
        stride_bytes: 1920 * 4,
        format: PixelFormat::Xrgb8888,
    };
    let sku = crate::intel_gpu_gen9_ddi::sku_family_for_did(0x1912);
    let sink = ScriptedSinkMmio::new(1 << 29);
    let local = match armed_sink(&sink) {
        Ok(local) => local,
        Err(why) => return TestResult::Fail(why),
    };
    local.now.store(100 * MS, Ordering::Relaxed);
    sink.writes.borrow_mut().clear();
    let mut ms = Modeset::new(&sink, Ddi::A);
    ms.set_gen9_platform(Gen9Platform::Skylake);
    ms.set_gen9_sku_family(sku);
    ms.set_gen9_dc(&local);
    if ms.modeset(&fb, None).is_err() {
        return TestResult::Fail("the Skylake panel modeset must succeed");
    }
    let writes = sink.writes.borrow().clone();
    if writes.first() != Some(&(DC_STATE_EN, 0)) || writes.len() < 2 {
        return TestResult::Fail("DC_STATE_DISABLE must precede every modeset register write");
    }
    if sink.writes_to(DC_STATE_EN) != [0] {
        return TestResult::Fail("DC states must stay off for the whole modeset");
    }
    if local.core.lock().total() != 0
        || local.deadline.load(Ordering::Relaxed) != 100 * MS + DC_REENABLE_DELAY_NS
    {
        return TestResult::Fail("the modeset's release must defer re-entry 17 ms");
    }
    // The lit eDP panel holds only DDI IO A (PW_1 domains): DC6 is legal.
    let due = local.deadline.load(Ordering::Relaxed);
    if local
        .core
        .lock()
        .arm_if_due(&sink, due, Gen9ArmGates::default())
        != Ok(DC6)
    {
        return TestResult::Fail("DC6 must be re-entered after the modeset");
    }
    // A refused DC exit: the modeset refuses before any register write.
    let sink = ScriptedSinkMmio::new(1 << 29);
    let mut ms = Modeset::new(&sink, Ddi::A);
    ms.set_gen9_platform(Gen9Platform::Skylake);
    ms.set_gen9_sku_family(sku);
    ms.set_gen9_dc(&Refuse);
    if ms.modeset(&fb, None) != Err(ModesetError::PowerWellTimeout) {
        return TestResult::Fail("a refused DC exit must refuse the modeset");
    }
    if !sink.writes.borrow().is_empty() {
        return TestResult::Fail("a refused DC exit must write nothing");
    }
    // Teardown holds DC_off too.
    let sink = ScriptedSinkMmio::new(1 << 29);
    let local = match armed_sink(&sink) {
        Ok(local) => local,
        Err(why) => return TestResult::Fail(why),
    };
    sink.writes.borrow_mut().clear();
    let mut ms = Modeset::new(&sink, Ddi::A);
    ms.set_gen9_platform(Gen9Platform::Skylake);
    ms.set_gen9_sku_family(sku);
    ms.set_gen9_dc(&local);
    ms.teardown();
    if sink.writes.borrow().first() != Some(&(DC_STATE_EN, 0)) {
        return TestResult::Fail("the pipeline teardown must exit DC states first");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_brackets_the_modeset
);

/// Every AUX transfer holds DC_off (`intel_dp_aux_xfer`'s AUX_A domain, a
/// Gen9 `dc_off` domain): the exit is written before the first AUX
/// register write, and re-entry is deferred after the transfer. A refused
/// exit touches no AUX register.
fn smoke_gen9_dc_brackets_an_aux_transfer() -> TestResult {
    use crate::dp_aux::{AuxChannel as _, AuxError};
    use crate::intel_gpu_aux::IntelAux;
    use crate::intel_gpu_ddi::Ddi;
    use crate::intel_gpu_modeset::tests::ScriptedSinkMmio;
    let sink = ScriptedSinkMmio::new(1 << 29);
    let local = match armed_sink(&sink) {
        Ok(local) => local,
        Err(why) => return TestResult::Fail(why),
    };
    local.now.store(7 * MS, Ordering::Relaxed);
    sink.writes.borrow_mut().clear();
    let mut buf = [0u8; 1];
    let mut aux = IntelAux::new(&sink, Ddi::A).with_gen9_dc(&local);
    if aux.dpcd_read(0x000, &mut buf).is_err() {
        return TestResult::Fail("the DPCD read must complete");
    }
    let writes = sink.writes.borrow().clone();
    let ctl = Ddi::A.base() + crate::intel_gpu_aux::DDI_AUX_CTL_OFFSET;
    let exit = writes.iter().position(|w| *w == (DC_STATE_EN, 0));
    let first_aux = writes.iter().position(|(o, _)| *o == ctl);
    match (exit, first_aux) {
        (Some(0), Some(aux_at)) if aux_at > 0 => {}
        _ => return TestResult::Fail("DC exit must precede the transfer's first AUX write"),
    }
    if sink.writes_to(DC_STATE_EN) != [0] {
        return TestResult::Fail("DC states must stay off for the whole transfer");
    }
    if local.core.lock().total() != 0
        || local.deadline.load(Ordering::Relaxed) != 7 * MS + DC_REENABLE_DELAY_NS
    {
        return TestResult::Fail("the transfer's release must defer re-entry 17 ms");
    }
    let sink = ScriptedSinkMmio::new(1 << 29);
    let mut aux = IntelAux::new(&sink, Ddi::A).with_gen9_dc(&Refuse);
    if !matches!(aux.dpcd_read(0x000, &mut buf), Err(AuxError::Deferred)) {
        return TestResult::Fail("a refused DC exit must refuse the transfer");
    }
    if !sink.writes.borrow().is_empty() {
        return TestResult::Fail("a refused DC exit must touch no AUX register");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_dc_brackets_an_aux_transfer
);

/// `PCODE_MAILBOX` with `GEN6_PCODE_READY` and `SKL_PCODE_CDCLK_CONTROL`
/// (0x7): one Skylake CDCLK notify (pre or post).
const SKL_CDCLK_NOTIFY: u32 = 0x8000_0007;

/// The resume's display-core init on display 9 proper after power loss,
/// in `skl_display_core_init`'s order: the PCH reset handshake enabled (the
/// rest of `HSW_NDE_RSTWRN_OPT` kept), PW_1 and MISC IO, `skl_cdclk_init_hw`,
/// then DBUF. With DPLL0 off the CDCLK is programmed from scratch at the
/// preferred VCO's lowest rung: 337.5 MHz at VCO 8100 (`CDCLK_FREQ_337_308`
/// 2 << 26, decimal `DIV_ROUND_CLOSEST(336500, 500)` = 673 = 0x2A1; DPLL_CTRL1
/// `OVERRIDE(0) | LINK_RATE(810 = 2, 0)` = 0x5), through `skl_set_cdclk`'s Wa
/// #1183 dance and both pcode notifies; 308.571 MHz at VCO 8640 on Kaby Lake
/// (decimal 615 = 0x267, `LINK_RATE_1080` 4: 0x9). Skylake never takes VCO
/// 8640 (Wa Display #1183).
fn smoke_gen9_resume_cdclk_init_and_pch_handshake() -> TestResult {
    let fake = Fake::default();
    // An unrelated bit of HSW_NDE_RSTWRN_OPT survives the handshake.
    fake.set(HSW_NDE_RSTWRN_OPT, 1);
    if display_core_init(&fake, Gen9Platform::Skylake, 0).is_err() {
        return TestResult::Fail("the Skylake display-core init must complete");
    }
    if fake.writes_to(HSW_NDE_RSTWRN_OPT) != [0x11] {
        return TestResult::Fail("RESET_PCH_HANDSHAKE_ENABLE (bit 4) must be set, bit 0 kept");
    }
    if fake.writes_to(CDCLK) != [0x0800_02A1, 0x0808_02A1, 0x0008_0000, 0x0808_02A1, 0x0800_02A1]
    {
        return TestResult::Fail("CDCLK_CTL must take skl_set_cdclk's 337.5 MHz Wa #1183 dance");
    }
    if fake.writes_to(CTRL1) != [0x5] || fake.get(LCPLL1) & (1 << 31) == 0 {
        return TestResult::Fail("DPLL0 must run at VCO 8100 (DPLL_CTRL1 0x5, LCPLL enabled)");
    }
    if fake
        .writes_to(crate::intel_gpu_pcode::PCODE_MAILBOX)
        .iter()
        .filter(|w| **w == SKL_CDCLK_NOTIFY)
        .count()
        != 2
    {
        return TestResult::Fail("the CDCLK change must be pre- and post-notified");
    }
    let log = fake.log();
    let at = |pred: &dyn Fn(&(u64, u32)) -> bool| log.iter().position(pred);
    let order = [
        at(&|(o, _)| *o == HSW_NDE_RSTWRN_OPT),
        at(&|(o, v)| *o == HSW_PWR_WELL_CTL2 && v & (1 << 29) != 0),
        at(&|(o, v)| *o == HSW_PWR_WELL_CTL2 && v & (1 << 1) != 0),
        at(&|(o, _)| *o == CDCLK),
        at(&|(o, v)| *o == DBUF_CTL_S1 && v & (1 << 31) != 0),
    ];
    if order.iter().any(Option::is_none) || order.windows(2).any(|w| w[0] >= w[1]) {
        return TestResult::Fail("PCH handshake, PW_1, MISC IO, CDCLK, DBUF: in that order");
    }
    // Kaby Lake keeps the eDP 1.4 VCO it ran before the suspend.
    let fake = Fake::default();
    if display_core_init(&fake, Gen9Platform::KabyLake, 8_640_000).is_err()
        || fake.get(CDCLK) != 0x0800_0267
        || fake.writes_to(CTRL1) != [0x9]
    {
        return TestResult::Fail("Kaby Lake must restore VCO 8640 at 308.571 MHz");
    }
    // Skylake refuses VCO 8640 (Wa Display #1183): VCO 8100 instead.
    let fake = Fake::default();
    if display_core_init(&fake, Gen9Platform::Skylake, 8_640_000).is_err()
        || fake.get(CDCLK) != 0x0800_02A1
        || fake.writes_to(CTRL1) != [0x5]
    {
        return TestResult::Fail("Skylake must fall back to VCO 8100");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_resume_cdclk_init_and_pch_handshake
);

/// `skl_sanitize_cdclk`: a locked DPLL0 at VCO 8100 with `CDCLK_CTL` at 450
/// MHz (`CDCLK_FREQ_450_432` 0, decimal 898 = 0x382) is kept untouched; a
/// wrong decimal alone is rewritten in place; any other stray bit (the Wa
/// #1183 override left set) forces DPLL0 off and on again and the full
/// program at the preferred VCO.
fn smoke_gen9_resume_cdclk_sanitize_skl() -> TestResult {
    use crate::intel_gpu_gen9_cdclk::{init_hw, InitOutcome};
    let running = |cdclk: u32| {
        let fake = Fake::default();
        fake.write32(CTRL1, 0x5);
        fake.write32(LCPLL1, 1 << 31);
        fake.set(CDCLK, cdclk);
        fake.clear_log();
        fake
    };
    let fake = running(0x0000_0382);
    if init_hw(&fake, Gen9Platform::Skylake, 8_100_000) != Ok(InitOutcome::Kept)
        || !fake.log().is_empty()
    {
        return TestResult::Fail("a sane 450 MHz CDCLK must be kept without a write");
    }
    let fake = running(0x0000_0381);
    if init_hw(&fake, Gen9Platform::Skylake, 8_100_000) != Ok(InitOutcome::DecimalFixed)
        || fake.log() != [(CDCLK, 0x0000_0382)]
    {
        return TestResult::Fail("a wrong decimal alone must be rewritten in place");
    }
    let fake = running(0x0008_0382);
    let programmed = InitOutcome::Programmed {
        vco: 8_100_000,
        cdclk_khz: 337_500,
    };
    if init_hw(&fake, Gen9Platform::Skylake, 8_100_000) != Ok(programmed) {
        return TestResult::Fail("a stray CDCLK_CTL bit must force the full program");
    }
    // "force full PLL disable + enable": ENABLE cleared, then set again.
    let lcpll = fake.writes_to(LCPLL1);
    if lcpll.len() != 2 || lcpll[0] & (1 << 31) != 0 || lcpll[1] & (1 << 31) == 0 {
        return TestResult::Fail("DPLL0 must be disabled then re-enabled");
    }
    if fake.get(CDCLK) != 0x0800_02A1 {
        return TestResult::Fail("the forced program must land on 337.5 MHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_resume_cdclk_sanitize_skl
);

/// Gen9 LP: `bxt_display_core_init` clears the PCH reset handshake (no PCH
/// answers it) and `bxt_cdclk_init_hw` programs the lowest table CDCLK on
/// a DE PLL that lost power: Broxton 144 MHz on ratio 60 (VCO 1152 MHz, CD2X
/// divider 4: `BXT_CDCLK_CD2X_DIV_SEL_4` 3 << 22, `PIPE_NONE` 3 << 20,
/// decimal 286 = 0x11E), Gemini Lake 79.2 MHz on ratio 33 (VCO 633.6 MHz,
/// divider 4, decimal 156 = 0x9C). A sane 288 MHz Broxton clock is kept even
/// with its CD2X pipe field naming pipe A (`bxt_sanitize_cdclk` ignores it).
fn smoke_gen9_resume_cdclk_init_lp() -> TestResult {
    for (platform, ratio, ctl) in [
        (Gen9Platform::Broxton, 60, 0x00F0_011E),
        (Gen9Platform::GeminiLake, 33, 0x00F0_009C),
    ] {
        let fake = Fake::default();
        fake.set(HSW_NDE_RSTWRN_OPT, (1 << 4) | 1);
        if display_core_init(&fake, platform, 0).is_err() {
            return TestResult::Fail("the Gen9 LP display-core init must complete");
        }
        if fake.writes_to(HSW_NDE_RSTWRN_OPT) != [0x1] {
            return TestResult::Fail("Gen9 LP must clear RESET_PCH_HANDSHAKE_ENABLE only");
        }
        if fake.writes_to(DE_PLL_CTL) != [ratio] || fake.writes_to(CDCLK) != [ctl] {
            return TestResult::Fail("the DE PLL ratio and CDCLK_CTL of the lowest table rung");
        }
        if fake.get(HSW_PWR_WELL_CTL2) & (1 << 1) != 0 {
            return TestResult::Fail("Gen9 LP requests no MISC IO well");
        }
    }
    // An already-clear handshake bit is not rewritten (intel_de_rmw).
    let fake = Fake::default();
    if display_core_init(&fake, Gen9Platform::Broxton, 0).is_err()
        || !fake.writes_to(HSW_NDE_RSTWRN_OPT).is_empty()
    {
        return TestResult::Fail("an unchanged handshake bit must not be written");
    }
    // 288 MHz: ratio 60, divider 2 (2 << 22), decimal 574 = 0x23E, CD2X pipe
    // A (0 << 20) where bxt_cdclk_ctl would name PIPE_NONE.
    let fake = Fake::default();
    fake.write32(DE_PLL_CTL, 60);
    fake.write32(DE_PLL_ENABLE, DE_PLL_ON);
    fake.set(CDCLK, 0x0080_023E);
    fake.clear_log();
    if crate::intel_gpu_bxt_cdclk::init_hw(&fake, false)
        != Ok(crate::intel_gpu_gen9_cdclk::InitOutcome::Kept)
        || !fake.log().is_empty()
    {
        return TestResult::Fail("a sane Broxton CDCLK must be kept whatever its pipe field");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_resume_cdclk_init_lp
);

/// `skl_display_core_uninit` after the DC exit: DBUF off, then
/// `skl_cdclk_uninit_hw` (DPLL0 disabled first, so the frequency is not
/// written before the Wa #1183 override and DPLL0 is not re-enabled; CDCLK_CTL
/// ends at `CDCLK_FREQ_337_308` with the 24 MHz decimal 46 = 0x2E), then the
/// driver's PW_1 request dropped with MISC IO kept. The VCO DPLL0 ran at is
/// returned for the resume.
fn smoke_gen9_skl_display_core_uninit() -> TestResult {
    let fake = Fake::default();
    fake.write32(HSW_PWR_WELL_CTL2, (1 << 29) | (1 << 1));
    fake.write32(DBUF_CTL_S1, 1 << 31);
    fake.write32(CTRL1, 0x5);
    fake.write32(LCPLL1, 1 << 31);
    fake.set(CDCLK, 0x0800_02A1);
    fake.clear_log();
    if display_core_uninit_skl(&fake, Gen9Platform::Skylake) != Ok(8_100_000) {
        return TestResult::Fail("the uninit must complete and report VCO 8100");
    }
    if fake.writes_to(CDCLK) != [0x0808_02A1, 0x0008_0000, 0x0808_002E, 0x0800_002E] {
        return TestResult::Fail("CDCLK_CTL must take skl_set_cdclk's VCO-0 sequence");
    }
    if !fake.writes_to(CTRL1).is_empty() || fake.get(LCPLL1) & (1 << 31) != 0 {
        return TestResult::Fail("DPLL0 must be left off");
    }
    let wells = fake.get(HSW_PWR_WELL_CTL2);
    if wells & (1 << 29) != 0 || wells & (1 << 1) == 0 {
        return TestResult::Fail("PW_1's request must drop and MISC IO's stay");
    }
    let log = fake.log();
    let dbuf = log
        .iter()
        .position(|(o, v)| *o == DBUF_CTL_S1 && v & (1 << 31) == 0);
    let pll = log.iter().position(|(o, v)| *o == LCPLL1 && v & (1 << 31) == 0);
    let pw1 = log
        .iter()
        .position(|(o, v)| *o == HSW_PWR_WELL_CTL2 && v & (1 << 29) == 0);
    match (dbuf, pll, pw1) {
        (Some(d), Some(p), Some(w)) if d < p && p < w => {}
        _ => return TestResult::Fail("DBUF, then DPLL0, then PW_1"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gen9_dc_states",
    smoke_gen9_skl_display_core_uninit
);
