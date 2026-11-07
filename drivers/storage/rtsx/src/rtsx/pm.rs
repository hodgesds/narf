//! RTSX device power management (#839).
//!
//! System suspend/resume through the `narf_power::device_pm` fan-out
//! plus runtime idle power gating, following the AHCI contract from
//! #932 (merged #977) and mirroring the sibling SDHCI module
//! (`crate::sdhci::pm`):
//!
//! - **Suspend**: refuse new I/O first (the block surface fails fast
//!   through `with_controller`), wait out in-flight I/O on the
//!   global controller lock (which `with_controller` holds across a
//!   transfer), then power the SD slot down (`disable_sd_slot`:
//!   clock off + card power off), power the SSC clock source down
//!   (FPDCTL `SSC_POWER_DOWN`, the inverse of `init_controller`)
//!   and mask the completion/card interrupts (BIER = 0). A slot
//!   power-off failure reports `Busy`, which aborts the system
//!   suspend; the suspended flag stays set and the orchestrator's
//!   abort path runs the resume handlers (`power/src/suspend.rs`
//!   resumes every device after a failed fan-out), exactly like
//!   AHCI.
//! - **Resume**: re-run the controller init (BIER + SSC power) and,
//!   for a `Ready` slot, re-enable the slot and re-identify the
//!   card, then compare the fresh identity against the pre-suspend
//!   card. A match (same CID + capacity + high-capacity class; the
//!   RCA is host-assigned per enumeration and is not identity)
//!   restores service; a mismatch keeps the controller suspended
//!   and reports `DriverError` — never serve a stranger's card
//!   under the old name. A card that was removed while suspended
//!   unregisters `mmcblk0` (+ partitions + sysfs) instead of
//!   leaving a phantom behind, and resume reports `Ok` with the
//!   slot empty — the card-poll task then registers whatever card
//!   is inserted next. A slot that held no published card
//!   (`Empty` / `Error` / `Inserted`) just gets the controller
//!   re-init; the poll task re-services it.
//! - **Runtime idle gating**: after [`RUNTIME_IDLE_TIMEOUT_MS`]
//!   with no block I/O, the card-poll task gates the slot (clock +
//!   power off, SSC down, BIER 0). The next block I/O ungates
//!   synchronously under the controller lock (same re-init +
//!   re-identify + verify as system resume) before touching the
//!   hardware, so I/O never fails just because the reader was idle.
//!   Only a `Ready` slot is gated: an empty slot stays powered so
//!   insertions keep being detected by the poll task (a gated chip
//!   cannot report BIPR.SD_EXIST reliably).
//!
//! The card-poll task never services the slot while the chip is
//! powered down (`poll_card_slot` returns early): a removal or
//! insertion during a powered-down window is re-observed on the
//! next ungate instead (resume re-checks card presence before
//! identifying).
//!
//! ## Why not `narf_power::runtime_pm`
//!
//! Same reason as the SDHCI module: the `RuntimePmDevice` core is
//! async-first, and the synchronous `BlockDeviceSync` path must
//! *wake* the card on I/O rather than fail it — so idle gating
//! here is a small synchronous state machine (gated flag +
//! last-busy timestamp + the shared resume helper), driven by the
//! existing poll task.
//!
//! ## State placement
//!
//! The flags live in this module, not on `RtsxController`: the
//! driver is a single install-once controller (`RTSX` is written
//! exactly once at probe), so module-level state is exactly
//! equivalent to per-controller state. Fixture tests reset the
//! flags explicitly through [`__reset_for_test`].
//!
//! ## Remainders (deliberate, not oversights)
//!
//! - No chip-specific PHY / SSC tuning on resume: `init_controller`
//!   restores the same BIER + SSC state probe programs; the
//!   per-chip `pcr_ops` tuning the driver already leaves out stays
//!   out.
//! - No wake-on-card-insert: the chip has no wakeup wiring in this
//!   driver, and the poll task is the insertion detector.
//! - A card swapped while runtime-gated stays gated with I/O
//!   refusing (same contract as the system-suspend mismatch): the
//!   recovery is remove-the-card (observed as absent on the next
//!   ungate attempt, which unregisters and re-arms the slot) and
//!   re-insert.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_power::device_pm::{register_device_pm, DeviceSuspendError};

use super::card::{SdCardInfo, SlotState};
use super::regs::{BIER, FPDCTL, SSC_POWER_DOWN};
use super::{block_bridge, RtsxController, RTSX};

/// NARF idle-gating policy: gate the slot clock + power after this
/// long without block I/O. A NARF policy constant, not a Linux
/// default — no autosuspend-delay claim is made about Linux here.
pub const RUNTIME_IDLE_TIMEOUT_MS: u64 = 5_000;
const RUNTIME_IDLE_TIMEOUT_NS: u64 = RUNTIME_IDLE_TIMEOUT_MS * 1_000_000;

/// True between the device_pm suspend handler setting it and the
/// resume handler clearing it. The block surface (`with_controller`)
/// refuses new I/O while set.
static SYSTEM_SUSPENDED: AtomicBool = AtomicBool::new(false);

/// True while the slot clock + power are gated by the idle monitor.
/// The next block I/O ungates synchronously (re-init + re-identify)
/// before touching the hardware.
static RUNTIME_GATED: AtomicBool = AtomicBool::new(false);

/// Monotonic timestamp (ns) of the last completed block I/O.
static LAST_BUSY_NS: AtomicU64 = AtomicU64::new(0);

/// Join the `device_pm` suspend/resume fan-out (called from
/// `probe`, after the controller installs — the AHCI pattern).
/// Idempotent on the name.
pub fn register() {
    register_device_pm("rtsx", suspend_all, resume_all);
}

/// True while the system-suspend handler has this controller quiesced.
pub fn is_system_suspended() -> bool {
    SYSTEM_SUSPENDED.load(Ordering::Acquire)
}

/// True while the idle monitor has the slot clock + power gated.
pub fn is_runtime_gated() -> bool {
    RUNTIME_GATED.load(Ordering::Acquire)
}

/// True while the chip is powered down for either reason — the card
/// poll must not touch the hardware then.
pub fn is_powered_down() -> bool {
    is_system_suspended() || is_runtime_gated()
}

/// Record completed block I/O (called from `with_controller` after
/// each transfer, including a transfer that ungated the controller).
pub fn mark_busy() {
    LAST_BUSY_NS.store(narf_time::monotonic_ns(), Ordering::Release);
}

/// Pure idle-expiry predicate, so the timeout is testable without
/// wall time.
fn idle_expired(last_busy_ns: u64, now_ns: u64) -> bool {
    now_ns.saturating_sub(last_busy_ns) >= RUNTIME_IDLE_TIMEOUT_NS
}

/// Card identity for resume re-identification: the CID captured by
/// CMD2 plus the CSD-decoded capacity and the high-capacity class.
/// The RCA is host-assigned at each enumeration and is deliberately
/// not identity; `selected` is always true after identification.
pub fn card_identity_matches(old: &SdCardInfo, new: &SdCardInfo) -> bool {
    old.cid == new.cid
        && old.capacity_blocks == new.capacity_blocks
        && old.high_capacity == new.high_capacity
}

/// Power the chip down past the slot: SSC clock source off
/// (FPDCTL `SSC_POWER_DOWN` — the inverse of `init_controller`)
/// and interrupt enables clear. Best-effort: a failed HAIMR write
/// leaves the chip partly powered, which resume re-inits anyway.
fn chip_power_down(ctrl: &RtsxController) {
    let _ = ctrl.haimr_write(FPDCTL, SSC_POWER_DOWN, SSC_POWER_DOWN);
    ctrl.write32(BIER, 0);
}

/// Resume with the controller lock already held. Shared by the
/// system-resume handler and the runtime-ungate path in
/// `with_controller` — both hold the lock, so no transfer can
/// interleave with the re-init + re-identify below.
///
/// # Precondition
///
/// Callers hold the `RTSX` lock.
pub fn resume_locked(ctrl: &mut RtsxController) -> Result<(), DeviceSuspendError> {
    // Controller-level re-init first (BIER + SSC on) — always, even
    // for an empty slot: the chip lost power.
    ctrl.init_controller()
        .map_err(|_| DeviceSuspendError::DriverError)?;
    match ctrl.sd_slot {
        SlotState::Ready(old) => {
            // Card removed while suspended: withdraw the stale block
            // device instead of leaving a phantom `mmcblk0` behind.
            // The slot is empty and re-armed; resume reports `Ok`
            // and the poll task registers whatever is inserted next.
            if !ctrl.card_inserted() {
                block_bridge::unregister_card(old);
                ctrl.sd_slot = SlotState::Empty;
                RUNTIME_GATED.store(false, Ordering::Release);
                SYSTEM_SUSPENDED.store(false, Ordering::Release);
                return Ok(());
            }
            // Re-enable the slot and re-identify the card.
            ctrl.enable_sd_slot()
                .map_err(|_| DeviceSuspendError::DriverError)?;
            let fresh = ctrl
                .identify_sd_card()
                .map_err(|_| DeviceSuspendError::DriverError)?;
            // A card that came back with a different identity is a
            // swap under a suspended system: keep the controller
            // suspended and fail rather than serve a stranger's card
            // under the old name (the AHCI #981 contract).
            if !card_identity_matches(&old, &fresh) {
                return Err(DeviceSuspendError::DriverError);
            }
            ctrl.sd_slot = SlotState::Ready(fresh);
            RUNTIME_GATED.store(false, Ordering::Release);
            SYSTEM_SUSPENDED.store(false, Ordering::Release);
            mark_busy();
            Ok(())
        }
        // No published card to revalidate: the chip is re-armed and
        // the poll task re-services the slot (insertion / retry).
        SlotState::Empty | SlotState::Error | SlotState::Inserted => {
            RUNTIME_GATED.store(false, Ordering::Release);
            SYSTEM_SUSPENDED.store(false, Ordering::Release);
            Ok(())
        }
    }
}

/// Suspend the installed controller. No controller → nothing to suspend.
fn suspend_all() -> Result<(), DeviceSuspendError> {
    let mut g = RTSX.lock();
    let Some(ctrl) = g.as_mut() else {
        return Ok(());
    };
    if SYSTEM_SUSPENDED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    // No I/O can be in flight: `with_controller` holds this lock
    // across a transfer, and the lock acquisition above waited it out.
    // Power the slot down whenever it is not already empty; a slot
    // power-off failure aborts the suspend (Busy) instead of
    // powering down over a live card. The flag stays set and the
    // orchestrator's abort path runs the resume handlers.
    if !matches!(ctrl.sd_slot, SlotState::Empty) && ctrl.disable_sd_slot().is_err() {
        return Err(DeviceSuspendError::Busy);
    }
    chip_power_down(ctrl);
    Ok(())
}

/// Resume the installed controller. No controller → nothing to resume.
fn resume_all() -> Result<(), DeviceSuspendError> {
    let mut g = RTSX.lock();
    let Some(ctrl) = g.as_mut() else {
        return Ok(());
    };
    if !is_powered_down() {
        return Ok(());
    }
    resume_locked(ctrl)
}

/// One idle-gate attempt at time `now_ns` (production passes
/// `narf_time::monotonic_ns()`): if a `Ready` card has been idle
/// past the timeout, quiesce the slot (clock + power off, SSC down,
/// BIER 0) and mark it runtime-gated. Skips when system-suspended,
/// already gated, no controller installed, no card `Ready`, not yet
/// idle, or I/O is in flight (the lock is taken with `try_lock` —
/// never spun on from the poll task; a busy controller is retried
/// on the next tick). An empty slot is never gated: the poll task
/// must keep detecting insertions. Returns true when the controller
/// was gated by this call.
pub fn try_idle_gate_at(now_ns: u64) -> bool {
    if is_powered_down() {
        return false;
    }
    if !idle_expired(LAST_BUSY_NS.load(Ordering::Acquire), now_ns) {
        return false;
    }
    let Some(mut g) = RTSX.try_lock() else {
        return false;
    };
    let Some(ctrl) = g.as_mut() else {
        return false;
    };
    if !ctrl.sd_slot.is_ready() {
        return false;
    }
    if ctrl.disable_sd_slot().is_err() {
        return false;
    }
    chip_power_down(ctrl);
    RUNTIME_GATED.store(true, Ordering::Release);
    true
}

/// Test-only: reset the PM flags (fixture setup/teardown). The
/// controller slot itself is reset by `super::__reset_for_test`.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    SYSTEM_SUSPENDED.store(false, Ordering::Release);
    RUNTIME_GATED.store(false, Ordering::Release);
    LAST_BUSY_NS.store(0, Ordering::Release);
}

/// Test-only: set the last-busy timestamp directly, so idle-expiry
/// tests run on synthetic time instead of wall time.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn __set_last_busy_for_test(now_ns: u64) {
    LAST_BUSY_NS.store(now_ns, Ordering::Release);
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use alloc::sync::Arc;

    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::super::card::{SdCardInfo, SlotState};
    use super::super::fixture_tests::{FixtureCard, FixtureTransport};
    use super::super::regs::{
        BIER, CARD_CLK_EN, CARD_PWR_CTL, FPDCTL, SD_CLK_EN, SD_POWER_OFF, SD_POWER_ON,
        SSC_POWER_DOWN,
    };
    use super::super::{
        RtsxTransport, __install_for_test, __reset_for_test as reset_controller, poll_card_slot,
        with_controller,
    };
    use super::*;

    /// Install a fixture chip as the global controller and snapshot
    /// the block registry; returns the snapshot for `restore`.
    fn install(
        transport: Arc<FixtureTransport>,
    ) -> alloc::vec::Vec<narf_block::registry::RegisteredBlockDevice> {
        let saved = narf_block::registry::__snapshot_for_test();
        narf_block::registry::__reset_for_test();
        __install_for_test(transport, 0x5229);
        __reset_for_test();
        saved
    }

    fn restore(saved: alloc::vec::Vec<narf_block::registry::RegisteredBlockDevice>) {
        narf_block::registry::__restore_for_test(saved);
        reset_controller();
        __reset_for_test();
    }

    /// The `Ready` slot's card info, if any.
    fn slot_info() -> Option<SdCardInfo> {
        with_controller(|c| c.sd_slot).and_then(|s| match s {
            SlotState::Ready(info) => Some(info),
            _ => None,
        })
    }

    fn slot_state() -> SlotState {
        with_controller(|c| c.sd_slot).unwrap_or(SlotState::Empty)
    }

    /// Write a patterned block through the registered `mmcblk0`,
    /// then read it back — proves the block path end to end.
    fn write_then_read_block(lba: u32, tag: u8) -> Result<(), &'static str> {
        let dev =
            narf_block::registry::find_block_device("mmcblk0").ok_or("mmcblk0 not registered")?;
        let mut data = [0u8; 512];
        for (i, x) in data.iter_mut().enumerate() {
            *x = tag ^ (i as u8);
        }
        dev.write(lba as u64, 1, &data)
            .map_err(|_| "mmcblk0 write failed")?;
        let mut back = [0u8; 512];
        dev.read(lba as u64, 1, &mut back)
            .map_err(|_| "mmcblk0 read failed")?;
        if back != data {
            return Err("mmcblk0 round-trip data mismatch");
        }
        Ok(())
    }

    fn read_mmcblk0_block(lba: u32) -> Result<[u8; 512], &'static str> {
        let dev =
            narf_block::registry::find_block_device("mmcblk0").ok_or("mmcblk0 not registered")?;
        let mut buf = [0u8; 512];
        dev.read(lba as u64, 1, &mut buf)
            .map_err(|_| "mmcblk0 read failed")?;
        Ok(buf)
    }

    fn fixture_pm_suspend_powers_off_and_resume_reidentifies() -> TestResult {
        let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
        let saved = install(transport.clone());
        let result = (|| {
            poll_card_slot();
            let info = slot_info().ok_or("slot must be Ready after poll")?;
            if info.capacity_blocks != 16_777_216 {
                return Err("capacity must come from the CSD (16,777,216 blocks)");
            }
            write_then_read_block(100, 0x5A)?;
            let cmds_before = transport.cmd_indices();
            let cmd0_before = cmds_before.iter().filter(|&&c| c == 0).count();

            // Suspend: slot power + SSC + interrupts go off.
            suspend_all().map_err(|_| "suspend_all failed")?;
            if !is_system_suspended() {
                return Err("suspended flag must be set after suspend_all");
            }
            if transport.internal_reg(CARD_PWR_CTL) != SD_POWER_OFF {
                return Err("CARD_PWR_CTL must be SD_POWER_OFF after suspend");
            }
            if transport.internal_reg(CARD_CLK_EN) & SD_CLK_EN != 0 {
                return Err("SD_CLK_EN must be clear after suspend");
            }
            if transport.internal_reg(FPDCTL) & SSC_POWER_DOWN == 0 {
                return Err("SSC_POWER_DOWN must be set after suspend");
            }
            if transport.read_hba(BIER) != 0 {
                return Err("BIER must be 0 after suspend");
            }
            // Block I/O refuses while suspended.
            if read_mmcblk0_block(100).is_ok() {
                return Err("block I/O must fail while system-suspended");
            }
            // The poll task is a no-op while suspended: no new SD
            // commands run.
            let cmds_suspended = transport.cmd_indices().len();
            poll_card_slot();
            if transport.cmd_indices().len() != cmds_suspended {
                return Err("poll_card_slot must not run commands while suspended");
            }
            // Resume: the card is re-identified (a second CMD0 ran),
            // power is back, and the same card serves the same data.
            resume_all().map_err(|_| "resume_all failed")?;
            if is_system_suspended() {
                return Err("suspended flag must be clear after resume_all");
            }
            if transport.internal_reg(CARD_PWR_CTL) != SD_POWER_ON {
                return Err("CARD_PWR_CTL must be SD_POWER_ON after resume");
            }
            if transport.internal_reg(FPDCTL) & SSC_POWER_DOWN != 0 {
                return Err("SSC_POWER_DOWN must be clear after resume");
            }
            let cmds_after = transport.cmd_indices();
            let cmd0_after = cmds_after.iter().filter(|&&c| c == 0).count();
            if cmd0_after != cmd0_before + 1 {
                return Err("resume must re-run the identify sequence (one more CMD0)");
            }
            let fresh = slot_info().ok_or("slot must be Ready after resume")?;
            if fresh.cid != info.cid || fresh.capacity_blocks != info.capacity_blocks {
                return Err("resumed card identity must match the pre-suspend card");
            }
            let mut expect = [0u8; 512];
            for (i, x) in expect.iter_mut().enumerate() {
                *x = 0x5A ^ (i as u8);
            }
            if read_mmcblk0_block(100)? != expect {
                return Err("post-resume read must return the pre-suspend data");
            }
            // Suspend/resume are idempotent.
            suspend_all().map_err(|_| "second suspend failed")?;
            suspend_all().map_err(|_| "third suspend (already suspended) failed")?;
            resume_all().map_err(|_| "second resume failed")?;
            resume_all().map_err(|_| "third resume (already resumed) failed")?;
            if read_mmcblk0_block(100).is_err() {
                return Err("I/O must work after the idempotent resume");
            }
            Ok(())
        })();
        restore(saved);
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/pm",
        fixture_pm_suspend_powers_off_and_resume_reidentifies
    );

    fn fixture_pm_resume_swapped_card_stays_suspended() -> TestResult {
        let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
        let saved = install(transport.clone());
        let result = (|| {
            poll_card_slot();
            let info = slot_info().ok_or("slot must be Ready after poll")?;
            if info.capacity_blocks != 16_777_216 {
                return Err("baseline capacity must be the 8 GiB SDHC card");
            }
            suspend_all().map_err(|_| "suspend_all failed")?;
            // A different card (2 MiB SDSC, different CID) is in the
            // slot when the system resumes.
            transport.insert_card(FixtureCard::sdsc_2mib());
            match resume_all() {
                Err(DeviceSuspendError::DriverError) => {}
                Ok(()) => {
                    return Err("resume must fail when the card was swapped");
                }
                Err(_) => return Err("resume must report DriverError on a swap"),
            }
            // The controller stays suspended and the old name keeps
            // refusing I/O — never serve the stranger's card.
            if !is_system_suspended() {
                return Err("suspended flag must stay set after a swap");
            }
            if read_mmcblk0_block(100).is_ok() {
                return Err("block I/O must fail after a swap");
            }
            if narf_block::registry::find_block_device("mmcblk0").is_none() {
                return Err("mmcblk0 must stay registered (suspended, not withdrawn)");
            }
            Ok(())
        })();
        restore(saved);
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/pm",
        fixture_pm_resume_swapped_card_stays_suspended
    );

    fn fixture_pm_resume_removed_card_unpublishes() -> TestResult {
        let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
        let saved = install(transport.clone());
        let result = (|| {
            poll_card_slot();
            if slot_info().is_none() {
                return Err("slot must be Ready after poll");
            }
            write_then_read_block(100, 0x5A)?;
            suspend_all().map_err(|_| "suspend_all failed")?;
            // The card is pulled while suspended.
            transport.remove_card();
            resume_all().map_err(|_| "resume with the card removed must report Ok")?;
            if is_system_suspended() {
                return Err("suspended flag must clear on resume-absent");
            }
            // No phantom: the block device is withdrawn and the slot
            // is empty.
            if narf_block::registry::find_block_device("mmcblk0").is_some() {
                return Err("mmcblk0 must be unpublished when the card is gone");
            }
            if slot_state() != SlotState::Empty {
                return Err("slot must be Empty after resume-absent");
            }
            // Recovery: a card inserted later is detected by the poll
            // task and registered again.
            transport.insert_card(FixtureCard::sdhc_8gib());
            poll_card_slot();
            if slot_info().is_none() {
                return Err("slot must be Ready after re-insertion + poll");
            }
            if narf_block::registry::find_block_device("mmcblk0").is_none() {
                return Err("mmcblk0 must register again after re-insertion");
            }
            write_then_read_block(100, 0xA5)?;
            Ok(())
        })();
        restore(saved);
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/pm",
        fixture_pm_resume_removed_card_unpublishes
    );

    fn fixture_pm_suspend_resume_without_card() -> TestResult {
        let transport = Arc::new(FixtureTransport::empty());
        let saved = install(transport.clone());
        let result = (|| {
            poll_card_slot();
            if slot_state() != SlotState::Empty {
                return Err("slot must be Empty with no card");
            }
            suspend_all().map_err(|_| "suspend with no card failed")?;
            resume_all().map_err(|_| "resume with no card failed")?;
            if is_system_suspended() || is_runtime_gated() {
                return Err("no PM flag may stick with no card");
            }
            // The chip is re-armed: a later insertion is detected.
            transport.insert_card(FixtureCard::sdhc_8gib());
            poll_card_slot();
            if slot_info().is_none() {
                return Err("insertion after an empty suspend/resume must register");
            }
            Ok(())
        })();
        restore(saved);
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/pm",
        fixture_pm_suspend_resume_without_card
    );

    fn fixture_pm_identity_match_predicate() -> TestResult {
        let base = SdCardInfo {
            rca: 0x9ABC,
            high_capacity: true,
            capacity_blocks: 16_777_216,
            selected: true,
            cid: [0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888],
        };
        if !card_identity_matches(&base, &base) {
            return TestResult::Fail("identical cards must match");
        }
        // The RCA is host-assigned per enumeration: a fresh RCA on the
        // same card is still the same card.
        let mut other = base;
        other.rca = 0x1234;
        if !card_identity_matches(&base, &other) {
            return TestResult::Fail("a different RCA must not break identity");
        }
        let mut other = base;
        other.cid[0] ^= 0xFFFF_FFFF;
        if card_identity_matches(&base, &other) {
            return TestResult::Fail("a different CID must not match");
        }
        let mut other = base;
        other.capacity_blocks = 4096;
        if card_identity_matches(&base, &other) {
            return TestResult::Fail("a different capacity must not match");
        }
        let mut other = base;
        other.high_capacity = false;
        if card_identity_matches(&base, &other) {
            return TestResult::Fail("a different capacity class must not match");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/storage/rtsx/pm",
        fixture_pm_identity_match_predicate
    );

    fn fixture_pm_runtime_gate_and_ungate_on_io() -> TestResult {
        let transport = Arc::new(FixtureTransport::with_card(Some(FixtureCard::sdhc_8gib())));
        let saved = install(transport.clone());
        let result = (|| {
            poll_card_slot();
            if slot_info().is_none() {
                return Err("slot must be Ready after poll");
            }
            write_then_read_block(100, 0x5A)?;
            // Synthetic time: idle for 4.999 s — not yet gated.
            __set_last_busy_for_test(0);
            if try_idle_gate_at(4_999_000_000) {
                return Err("must not gate before the idle timeout");
            }
            if is_runtime_gated() {
                return Err("gated flag must be clear before the timeout");
            }
            // Idle for exactly the timeout — gated, slot + SSC off.
            if !try_idle_gate_at(5_000_000_000) {
                return Err("must gate once the idle timeout expires");
            }
            if !is_runtime_gated() {
                return Err("gated flag must be set after gating");
            }
            if transport.internal_reg(CARD_PWR_CTL) != SD_POWER_OFF {
                return Err("CARD_PWR_CTL must be SD_POWER_OFF after the idle gate");
            }
            if transport.internal_reg(FPDCTL) & SSC_POWER_DOWN == 0 {
                return Err("SSC_POWER_DOWN must be set after the idle gate");
            }
            // The next block I/O ungates synchronously (re-init +
            // re-identify) and returns the same data.
            let mut expect = [0u8; 512];
            for (i, x) in expect.iter_mut().enumerate() {
                *x = 0x5A ^ (i as u8);
            }
            if read_mmcblk0_block(100)? != expect {
                return Err("post-ungate read must return the pre-gate data");
            }
            if is_runtime_gated() {
                return Err("gated flag must clear after the ungating I/O");
            }
            if transport.internal_reg(CARD_PWR_CTL) != SD_POWER_ON {
                return Err("slot power must be back on after the ungating I/O");
            }
            // A gate attempt while system-suspended never powers the
            // chip off a second time (already powered down).
            suspend_all().map_err(|_| "suspend_all failed")?;
            __set_last_busy_for_test(0);
            if try_idle_gate_at(60_000_000_000) {
                return Err("must not idle-gate while system-suspended");
            }
            resume_all().map_err(|_| "resume_all failed")?;
            if read_mmcblk0_block(100).is_err() {
                return Err("I/O must work after the resume");
            }
            Ok(())
        })();
        restore(saved);
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/pm",
        fixture_pm_runtime_gate_and_ungate_on_io
    );

    fn fixture_pm_runtime_gate_never_gates_empty_slot() -> TestResult {
        let transport = Arc::new(FixtureTransport::empty());
        let saved = install(transport.clone());
        let result = (|| {
            poll_card_slot();
            if slot_state() != SlotState::Empty {
                return Err("slot must be Empty with no card");
            }
            // Even after a long idle, an empty slot stays powered so
            // the poll task keeps detecting insertions.
            __set_last_busy_for_test(0);
            if try_idle_gate_at(60_000_000_000) {
                return Err("must never idle-gate an empty slot");
            }
            if is_runtime_gated() {
                return Err("gated flag must stay clear for an empty slot");
            }
            transport.insert_card(FixtureCard::sdhc_8gib());
            poll_card_slot();
            if slot_info().is_none() {
                return Err("insertion must still be detected after the skipped gate");
            }
            Ok(())
        })();
        restore(saved);
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "drivers/storage/rtsx/pm",
        fixture_pm_runtime_gate_never_gates_empty_slot
    );
}
