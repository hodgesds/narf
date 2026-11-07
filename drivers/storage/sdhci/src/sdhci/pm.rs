//! SDHCI device power management (#839).
//!
//! System suspend/resume through the `narf_power::device_pm` fan-out
//! plus runtime idle power gating, following the AHCI contract from
//! #932 (merged #977):
//!
//! - **Suspend**: refuse new I/O first (the block surface fails fast
//!   through `with_controller`), wait out in-flight I/O on the
//!   request gate, drain the controller (`wait_idle`), then cut the
//!   SD clock and card power (SDHCI 3.00 §2.2.14 / §2.2.10). A
//!   controller whose DAT line stays busy reports `Busy`, which
//!   aborts the system suspend; the suspended flag stays set and the
//!   orchestrator's abort path runs the resume handlers
//!   (`power/src/suspend.rs` resumes every device after a failed
//!   fan-out), exactly like AHCI.
//! - **Resume**: re-run the bring-up hardware sequence against the
//!   SAME mapped BAR0 (reset, 3.3 V power-on, 400 kHz init clock,
//!   timeout, interrupt enables) and re-identify the card, then
//!   compare the fresh identity against the pre-suspend card. A
//!   match (same CID + capacity + CCS; the RCA is host-assigned per
//!   enumeration and is not identity) restores service; a mismatch
//!   keeps the controller suspended and reports `DriverError` —
//!   never serve a stranger's card under the old name. A card that
//!   was removed while suspended unpublishes `sdhci0` (+ partitions)
//!   instead of leaving a phantom behind, and resume reports `Ok`
//!   with the slot empty.
//! - **Runtime idle gating**: after [`RUNTIME_IDLE_TIMEOUT_MS`] with
//!   no block I/O, the idle-monitor task (Stage::Late, spawned by
//!   the storage facade when a controller probed) gates the card
//!   clock + power. The next block I/O ungates synchronously under
//!   the request gate (same re-init + re-identify + verify as system
//!   resume) before touching the hardware, so I/O never fails just
//!   because the controller was idle.
//!
//! ## Why not `narf_power::runtime_pm`
//!
//! The `RuntimePmDevice` core is async-first: its `get_sync` is a
//! future, and the sync `get_if_active` can only fail I/O on a
//! suspended device (the display driver's `wakeref_if_active`
//! precedent). The SD block path is synchronous
//! (`BlockDeviceSync::read` / `write`), and a read must *wake* the
//! card, not fail — so idle gating here is a small synchronous
//! state machine (gated flag + last-busy timestamp + the shared
//! resume helper), driven by the monitor task. The async core stays
//! available for a later migration if the block path ever grows an
//! async entry point.
//!
//! ## State placement
//!
//! The flags live in this module, not on `Sdhci`: the driver is a
//! single install-once controller (`CONTROLLER` is written exactly
//! once and never replaced), so module-level state is exactly
//! equivalent to per-controller state, and it keeps this lane out
//! of the struct / bring-up regions the #837 data-path lane is
//! rewriting. Fixture tests reset the flags explicitly through
//! [`__reset_for_test`].
//!
//! ## Remainders (deliberate, not oversights)
//!
//! - Resume restores the *identification* profile (400 kHz, PIO,
//!   1-bit). The #837 negotiated data path (clock raise, bus width,
//!   DMA) is not re-negotiated on resume yet — the card is usable
//!   but slow until that follow-up lands.
//! - No CMD13 programming-state poll before power-off: the drain is
//!   the controller-level `wait_idle` (DAT_INHIBIT clear). A card
//!   still programming flash internally after transfer-complete is a
//!   known hardening follow-up.
//! - No wake-on-card-insert: the Wakeup Control register (§2.2.12)
//!   is untouched — NARF has no wakeup framework wired for SDHCI.
//! - No hot-insert detection: a card inserted after boot (or after
//!   a resume-absent unpublish) is never identified — pre-existing
//!   gap, out of scope for this lane.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_power::device_pm::{register_device_pm, DeviceSuspendError};

use super::{
    probed_sdhci, publish_card, SdCard, Sdhci, SdhciError, CLK_INTERNAL_EN, CLK_INTERNAL_STABLE,
    CLK_SD_EN, POWER_3V3, POWER_ON, PSTATE_CARD_INSERTED, REG_CLOCK_CONTROL, REG_ERROR_INT_EN,
    REG_NORMAL_INT_EN, REG_POWER_CONTROL, REG_PRESENT_STATE, REG_SOFT_RESET, REG_TIMEOUT_CTRL,
    SRST_ALL,
};
use crate::req_gate::ReqGate;

/// NARF idle-gating policy: gate the card clock + power after this
/// long without block I/O. A NARF policy constant, not a Linux
/// default — no autosuspend-delay claim is made about Linux here.
pub const RUNTIME_IDLE_TIMEOUT_MS: u64 = 5_000;
const RUNTIME_IDLE_TIMEOUT_NS: u64 = RUNTIME_IDLE_TIMEOUT_MS * 1_000_000;

/// True between the device_pm suspend handler setting it and the
/// resume handler clearing it. The block surface (`with_controller`)
/// refuses new I/O while set.
static SYSTEM_SUSPENDED: AtomicBool = AtomicBool::new(false);

/// True while the card clock + power are gated by the idle monitor.
/// The next block I/O ungates synchronously (re-init + re-identify)
/// before touching the hardware.
static RUNTIME_GATED: AtomicBool = AtomicBool::new(false);

/// Monotonic timestamp (ns) of the last completed block I/O.
static LAST_BUSY_NS: AtomicU64 = AtomicU64::new(0);

/// Join the `device_pm` suspend/resume fan-out (called from
/// `probe`, after the controller installs — the AHCI pattern).
/// Idempotent on the name.
pub fn register() {
    register_device_pm("sdhci", suspend_all, resume_all);
}

/// True while the system-suspend handler has this controller quiesced.
pub fn is_system_suspended() -> bool {
    SYSTEM_SUSPENDED.load(Ordering::Acquire)
}

/// True while the idle monitor has the card clock + power gated.
pub fn is_runtime_gated() -> bool {
    RUNTIME_GATED.load(Ordering::Acquire)
}

/// True while the chip is powered down for either reason — the card
/// poll / idle paths must not touch the hardware then.
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
/// CMD2 plus the CSD-decoded capacity and the CCS class bit. The RCA
/// is host-assigned at each enumeration and is deliberately not
/// identity; `if_cond_match` is a protocol-version signal, not
/// identity either.
pub fn card_identity_matches(old: &SdCard, new: &SdCard) -> bool {
    old.cid == new.cid && old.capacity_blocks == new.capacity_blocks && old.ccs == new.ccs
}

/// Cut the card clock + power (SDHCI 3.00 §2.2.14 / §2.2.10):
/// SD clock off, internal clock off, then power off. Clock first,
/// power second — powering off under a running SD clock is the
/// sequence the spec's power-down path avoids.
fn power_off(ctrl: &Sdhci) {
    let clk = ctrl.io.read16(REG_CLOCK_CONTROL);
    ctrl.io
        .write16(REG_CLOCK_CONTROL, clk & !(CLK_SD_EN | CLK_INTERNAL_EN));
    ctrl.io.write8(REG_POWER_CONTROL, 0);
}

/// Re-initialise the controller after power loss (system resume or
/// runtime ungate): the `bring_up` hardware sequence minus BAR
/// mapping and minus the AMD pre-reset D3hot quirk (power was cut,
/// so no sticky DATA-line state survives to need it), at the
/// identification profile (400 kHz init clock, PIO, 1-bit).
/// Returns the freshly identified card.
fn reinit_and_identify(ctrl: &Sdhci) -> Result<SdCard, SdhciError> {
    // 1. Software reset — Reset All (§3.6); SRST_ALL self-clears
    // within 100 ms (§2.2.16).
    ctrl.io.write8(REG_SOFT_RESET, SRST_ALL);
    let done = narf_scheduler::responsive_spin_until(
        || ctrl.io.read8(REG_SOFT_RESET) & SRST_ALL == 0,
        narf_time::Deadline::after_ms(100),
    );
    if !done {
        return Err(SdhciError::ResetTimeout);
    }

    // 2. Power-on at 3.3V (§2.2.10).
    ctrl.io.write8(REG_POWER_CONTROL, POWER_3V3 | POWER_ON);

    // 3. Internal clock enable + 400 kHz init clock — the same 0x80
    // divider `bring_up` programs (§2.2.14). The stable-bit wait is
    // ignored exactly as at bring-up: a slow controller still comes
    // up and the SD clock is enabled regardless.
    let div = 0x80u16;
    let clk = ((div & 0xFF) << 8) | ((div >> 8) & 0x3) << 6 | CLK_INTERNAL_EN;
    ctrl.io.write16(REG_CLOCK_CONTROL, clk);
    let _ = narf_scheduler::responsive_spin_until(
        || ctrl.io.read16(REG_CLOCK_CONTROL) & CLK_INTERNAL_STABLE != 0,
        narf_time::Deadline::after_ms(150),
    );
    let v = ctrl.io.read16(REG_CLOCK_CONTROL);
    ctrl.io.write16(REG_CLOCK_CONTROL, v | CLK_SD_EN);

    // 4. Default DTOCV = 0xE (max timeout).
    ctrl.io.write8(REG_TIMEOUT_CTRL, 0x0E);

    // 5. Enable normal + error interrupt status reporting (the
    // driver polls, but the status bits only set when enabled).
    ctrl.io.write16(REG_NORMAL_INT_EN, 0xFFFF);
    ctrl.io.write16(REG_ERROR_INT_EN, 0xFFFF);

    // 6. Card-present check.
    if ctrl.io.read32(REG_PRESENT_STATE) & PSTATE_CARD_INSERTED == 0 {
        return Err(SdhciError::NoCard);
    }

    // 7. Re-run the identification sequence.
    // SAFETY: same exclusive-ownership reasoning as `bring_up` —
    // the controller is exclusively owned by this driver and no
    // transfer is in flight (callers hold the request gate), so
    // re-identification on resume is the sequence's second
    // legitimate call site.
    unsafe { ctrl.identify_sequence() }
}

/// Withdraw the stale `sdhci0` block device + its partition children
/// (mirrors the RTSX `unregister_card` dance): the card is gone, so
/// the name must not keep resolving to a phantom.
fn unpublish_card() {
    let children: alloc::vec::Vec<&'static str> = narf_block::registry::block_devices()
        .iter()
        .filter(|e| e.parent == Some("sdhci0"))
        .map(|e| e.name)
        .collect();
    for child in children {
        narf_block::registry::unregister_block_device(child);
    }
    narf_block::registry::unregister_block_device("sdhci0");
}

/// Resume with the request gate already held. Shared by the
/// system-resume handler and the runtime-ungate path in
/// `with_controller` — both hold the gate, so no transfer can
/// interleave with the re-init + re-identify below.
///
/// # Precondition
///
/// Callers hold `ctrl`'s request gate.
pub fn resume_locked(ctrl: &Sdhci) -> Result<(), DeviceSuspendError> {
    let old = *ctrl.card.lock();
    match reinit_and_identify(ctrl) {
        Ok(fresh) => {
            // A card that came back with a different identity is a
            // swap under a suspended system: keep the controller
            // suspended and fail rather than serve a stranger's card
            // under the old name (the AHCI #981 contract).
            if let Some(old_card) = old {
                if !card_identity_matches(&old_card, &fresh) {
                    return Err(DeviceSuspendError::DriverError);
                }
            } else {
                // No card was held (a previous resume-absent
                // unpublished it, and one has since appeared): the
                // freshly identified card needs publishing, exactly
                // as at probe — otherwise the driver would hold a
                // card no block device reaches.
                publish_card(fresh.capacity_blocks);
            }
            *ctrl.card.lock() = Some(fresh);
            // A runtime gate (if any) is subsumed by the resume.
            RUNTIME_GATED.store(false, Ordering::Release);
            SYSTEM_SUSPENDED.store(false, Ordering::Release);
            mark_busy();
            Ok(())
        }
        Err(SdhciError::NoCard) => {
            // Card removed while suspended: withdraw the stale block
            // device instead of leaving a phantom `sdhci0` behind.
            // The slot is empty and re-armed; resume reports `Ok`.
            if old.is_some() {
                unpublish_card();
            }
            *ctrl.card.lock() = None;
            RUNTIME_GATED.store(false, Ordering::Release);
            SYSTEM_SUSPENDED.store(false, Ordering::Release);
            Ok(())
        }
        Err(_) => Err(DeviceSuspendError::DriverError),
    }
}

/// Suspend every installed controller (there is at most one).
/// No controller → nothing to suspend.
fn suspend_all() -> Result<(), DeviceSuspendError> {
    let Some(ctrl) = probed_sdhci() else {
        return Ok(());
    };
    if SYSTEM_SUSPENDED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let _gate = ReqGate::acquire(&ctrl.req_gate);
    // Already runtime-gated: clock + power are off, and no I/O can
    // be in flight — `with_controller` ungates under the gate first,
    // so anything past the gate check already finished. The
    // wait + power-off below would read a powered-down chip.
    if RUNTIME_GATED.load(Ordering::Acquire) {
        return Ok(());
    }
    // Drain the controller before cutting power: DAT_INHIBIT clears
    // once the in-flight data phase is done. A line that stays busy
    // past the 1 s budget aborts the suspend (Busy) instead of
    // powering off mid-transfer; the flag stays set and the
    // orchestrator's abort path runs the resume handlers.
    if ctrl.wait_idle(true).is_err() {
        return Err(DeviceSuspendError::Busy);
    }
    power_off(ctrl);
    Ok(())
}

/// Resume every installed controller. No controller → nothing to resume.
fn resume_all() -> Result<(), DeviceSuspendError> {
    let Some(ctrl) = probed_sdhci() else {
        return Ok(());
    };
    if !is_powered_down() {
        return Ok(());
    }
    let _gate = ReqGate::acquire(&ctrl.req_gate);
    resume_locked(ctrl)
}

/// One idle-gate attempt at time `now_ns` (production passes
/// `narf_time::monotonic_ns()`): if the controller has been idle
/// past the timeout, quiesce it (clock + power off) and mark it
/// runtime-gated. Skips when system-suspended, already gated, no
/// controller installed, not yet idle, or I/O is in flight (the
/// gate is taken with `try_acquire` — never spun on from the
/// monitor; a busy controller is retried on the next tick).
/// Returns true when the controller was gated by this call.
pub fn try_idle_gate_at(now_ns: u64) -> bool {
    if is_powered_down() {
        return false;
    }
    if !idle_expired(LAST_BUSY_NS.load(Ordering::Acquire), now_ns) {
        return false;
    }
    let Some(ctrl) = probed_sdhci() else {
        return false;
    };
    let Some(_gate) = ReqGate::try_acquire(&ctrl.req_gate) else {
        return false;
    };
    power_off(ctrl);
    RUNTIME_GATED.store(true, Ordering::Release);
    true
}

/// Spawn the idle-monitor task (Stage::Late; the storage facade
/// spawns it when a controller probed): every second, gate the
/// controller if it has been idle past the timeout.
pub fn spawn_idle_monitor_task() {
    narf_scheduler::spawn_stackful(async {
        loop {
            try_idle_gate_at(narf_time::monotonic_ns());
            narf_time::sleep_cycles(narf_time::ns_to_cycles(1_000_000_000)).await;
        }
    });
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
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;

    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::super::fixture_tests::FixtureTransport;
    use super::super::{
        __install_for_test, __reset_for_test as reset_controller, probed_sdhci, publish_card,
        SdhciTransport, PSTATE_DAT_INHIBIT,
    };
    use super::*;

    /// Install a fixture controller as the global controller and
    /// snapshot the block registry; returns the transport + snapshot.
    fn install(
        image: BTreeMap<u32, [u8; 512]>,
    ) -> (
        Arc<FixtureTransport>,
        alloc::vec::Vec<narf_block::registry::RegisteredBlockDevice>,
    ) {
        let saved = narf_block::registry::__snapshot_for_test();
        narf_block::registry::__reset_for_test();
        let transport = Arc::new(FixtureTransport::with_image(image));
        __install_for_test(transport.clone());
        __reset_for_test();
        (transport, saved)
    }

    fn restore(saved: alloc::vec::Vec<narf_block::registry::RegisteredBlockDevice>) {
        narf_block::registry::__restore_for_test(saved);
        reset_controller();
        __reset_for_test();
    }

    /// Identify the fixture card through the production sequence and
    /// publish it exactly as `probe` does after bring-up.
    fn identify_and_publish() -> Result<SdCard, &'static str> {
        let ctrl = probed_sdhci().ok_or("fixture controller not installed")?;
        // SAFETY: the fixture transport is exclusively owned by this
        // test and `identify_sequence` runs here as it does at
        // bring-up / resume, with no transfer in flight.
        let card = unsafe { ctrl.identify_sequence() }.map_err(|_| "identify_sequence failed")?;
        *ctrl.card.lock() = Some(card);
        publish_card(card.capacity_blocks);
        Ok(card)
    }

    /// One partitioned fixture card image (same MBR layout the
    /// fixture suite uses: p1 at 2048, p2 at 8192).
    fn partitioned_image() -> BTreeMap<u32, [u8; 512]> {
        let mut mbr = [0u8; 512];
        // MBR entry: type 0x83, start 2048, 4096 sectors.
        let off = 446;
        mbr[off + 4] = 0x83;
        mbr[off + 8..off + 12].copy_from_slice(&2048u32.to_le_bytes());
        mbr[off + 12..off + 16].copy_from_slice(&4096u32.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        let mut image = BTreeMap::new();
        image.insert(0, mbr);
        let mut block = [0u8; 512];
        for (i, x) in block.iter_mut().enumerate() {
            *x = 0xA1 ^ (i as u8);
        }
        image.insert(2048, block);
        image
    }

    fn read_sdhci0_block(lba: u32) -> Result<[u8; 512], &'static str> {
        let dev =
            narf_block::registry::find_block_device("sdhci0").ok_or("sdhci0 not registered")?;
        let mut buf = [0u8; 512];
        dev.read(lba as u64, 1, &mut buf)
            .map_err(|_| "sdhci0 read failed")?;
        Ok(buf)
    }

    fn fixture_pm_suspend_powers_off_and_resume_reidentifies() -> TestResult {
        let (transport, saved) = install(partitioned_image());
        let result = (|| {
            let card = identify_and_publish()?;
            if card.capacity_blocks != 16_777_216 {
                return Err("capacity must come from the CSD (16,777,216 blocks)");
            }
            // Baseline I/O works and returns the MBR entry's block.
            let first = read_sdhci0_block(2048)?;
            if first[0] != 0xA1 {
                return Err("baseline read must return the fixture block");
            }
            let cmds_before = transport.cmd_indices();
            let cmd0_before = cmds_before.iter().filter(|&&c| c == 0).count();

            // Suspend: power + clock go off (register-visible).
            suspend_all().map_err(|_| "suspend_all failed")?;
            if !is_system_suspended() {
                return Err("suspended flag must be set after suspend_all");
            }
            if transport.read8(REG_POWER_CONTROL) != 0 {
                return Err("POWER_CONTROL must be 0 (power off) after suspend");
            }
            if transport.read16(REG_CLOCK_CONTROL) & CLK_SD_EN != 0 {
                return Err("CLK_SD_EN must be clear after suspend");
            }
            // Block I/O refuses while suspended.
            if read_sdhci0_block(2048).is_ok() {
                return Err("block I/O must fail while system-suspended");
            }
            // Resume: the card is re-identified (a second CMD0 ran)
            // and power is back.
            resume_all().map_err(|_| "resume_all failed")?;
            if is_system_suspended() {
                return Err("suspended flag must be clear after resume_all");
            }
            if transport.read8(REG_POWER_CONTROL) & POWER_ON == 0 {
                return Err("POWER_CONTROL must have POWER_ON after resume");
            }
            if transport.read16(REG_CLOCK_CONTROL) & CLK_SD_EN == 0 {
                return Err("CLK_SD_EN must be set after resume");
            }
            let cmds_after = transport.cmd_indices();
            let cmd0_after = cmds_after.iter().filter(|&&c| c == 0).count();
            if cmd0_after != cmd0_before + 1 {
                return Err("resume must re-run the identify sequence (one more CMD0)");
            }
            // Same card, same data — service is restored.
            let again = read_sdhci0_block(2048)?;
            if again != first {
                return Err("post-resume read must return the same block");
            }
            // Suspend/resume are idempotent.
            suspend_all().map_err(|_| "second suspend failed")?;
            suspend_all().map_err(|_| "third suspend (already suspended) failed")?;
            resume_all().map_err(|_| "second resume failed")?;
            resume_all().map_err(|_| "third resume (already resumed) failed")?;
            if read_sdhci0_block(2048).is_err() {
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
        "drivers/storage/sdhci/pm",
        fixture_pm_suspend_powers_off_and_resume_reidentifies
    );

    fn fixture_pm_suspend_busy_aborts_and_resume_recovers() -> TestResult {
        let (transport, saved) = install(partitioned_image());
        let result = (|| {
            identify_and_publish()?;
            // Hold DAT_INHIBIT: the controller looks mid-transfer, so
            // the suspend drain must time out and abort the suspend.
            transport.write32(REG_PRESENT_STATE, PSTATE_DAT_INHIBIT);
            match suspend_all() {
                Err(DeviceSuspendError::Busy) => {}
                Ok(()) => return Err("suspend must report Busy with DAT_INHIBIT held"),
                Err(_) => return Err("suspend must report Busy (not DriverError)"),
            }
            // The flag stays set (AHCI contract) so I/O still refuses
            // while the abort is unwound by the resume handlers.
            if !is_system_suspended() {
                return Err("suspended flag must stay set after a Busy abort");
            }
            if read_sdhci0_block(2048).is_ok() {
                return Err("block I/O must fail after a Busy abort");
            }
            // The transfer finishes; the orchestrator's abort path runs
            // resume, which re-inits and restores service.
            transport.write32(REG_PRESENT_STATE, 0);
            resume_all().map_err(|_| "resume after Busy abort failed")?;
            if read_sdhci0_block(2048).is_err() {
                return Err("I/O must work after the abort-path resume");
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
        "drivers/storage/sdhci/pm",
        fixture_pm_suspend_busy_aborts_and_resume_recovers
    );

    /// Transport that delegates to the fixture except for the card-
    /// present bit, so the test can model a card removed while the
    /// system was suspended — without touching the shared fixture.
    #[derive(Debug)]
    struct NoCardTransport {
        inner: Arc<FixtureTransport>,
        present: AtomicBool,
    }

    impl NoCardTransport {
        fn new(inner: Arc<FixtureTransport>) -> Self {
            NoCardTransport {
                inner,
                present: AtomicBool::new(true),
            }
        }
        fn set_present(&self, present: bool) {
            self.present.store(present, Ordering::Release);
        }
    }

    impl SdhciTransport for NoCardTransport {
        fn read8(&self, offset: u64) -> u8 {
            self.inner.read8(offset)
        }
        fn read16(&self, offset: u64) -> u16 {
            self.inner.read16(offset)
        }
        fn read32(&self, offset: u64) -> u32 {
            let v = self.inner.read32(offset);
            if offset == REG_PRESENT_STATE && !self.present.load(Ordering::Acquire) {
                v & !PSTATE_CARD_INSERTED
            } else {
                v
            }
        }
        fn write8(&self, offset: u64, value: u8) {
            self.inner.write8(offset, value);
        }
        fn write16(&self, offset: u64, value: u16) {
            self.inner.write16(offset, value);
        }
        fn write32(&self, offset: u64, value: u32) {
            self.inner.write32(offset, value);
        }
    }

    fn fixture_pm_resume_absent_card_unpublishes() -> TestResult {
        let saved = narf_block::registry::__snapshot_for_test();
        narf_block::registry::__reset_for_test();
        let inner = Arc::new(FixtureTransport::with_image(partitioned_image()));
        let transport = Arc::new(NoCardTransport::new(inner));
        __install_for_test(transport.clone());
        __reset_for_test();
        let result = (|| {
            identify_and_publish()?;
            if narf_block::registry::find_block_device("sdhci0").is_none() {
                return Err("sdhci0 must register at identify");
            }
            suspend_all().map_err(|_| "suspend_all failed")?;
            // The card is pulled while suspended.
            transport.set_present(false);
            resume_all().map_err(|_| "resume with the card removed must report Ok")?;
            if is_system_suspended() {
                return Err("suspended flag must clear on resume-absent");
            }
            // No phantom: the block device is withdrawn and the driver
            // holds no card.
            if narf_block::registry::find_block_device("sdhci0").is_some() {
                return Err("sdhci0 must be unpublished when the card is gone");
            }
            let ctrl = probed_sdhci().ok_or("controller missing")?;
            if ctrl.card.lock().is_some() {
                return Err("driver must hold no card after resume-absent");
            }
            // A card that appears before the NEXT suspend/resume cycle
            // is identified and re-published by that resume — the
            // driver must not hold a card no block device reaches.
            transport.set_present(true);
            suspend_all().map_err(|_| "second suspend_all failed")?;
            resume_all().map_err(|_| "second resume_all failed")?;
            if narf_block::registry::find_block_device("sdhci0").is_none() {
                return Err("sdhci0 must re-register on the resume that finds a card");
            }
            if read_sdhci0_block(2048).is_err() {
                return Err("I/O must work after the re-publish resume");
            }
            Ok(())
        })();
        narf_block::registry::__restore_for_test(saved);
        reset_controller();
        __reset_for_test();
        match result {
            Ok(()) => TestResult::Pass,
            Err(m) => TestResult::Fail(m),
        }
    }
    kernel_test_in!(
        "drivers/storage/sdhci/pm",
        fixture_pm_resume_absent_card_unpublishes
    );

    fn fixture_pm_identity_match_predicate() -> TestResult {
        let base = SdCard {
            rca: 0x0001,
            cid: [0x1111_2222, 0x3333_4444, 0x5555_6666, 0x7777_8888],
            if_cond_match: true,
            ccs: true,
            s18a: false,
            capacity_blocks: 16_777_216,
        };
        if !card_identity_matches(&base, &base) {
            return TestResult::Fail("identical cards must match");
        }
        // The RCA is host-assigned per enumeration: a fresh RCA on the
        // same card is still the same card.
        let mut other = base;
        other.rca = 0x0002;
        if !card_identity_matches(&base, &other) {
            return TestResult::Fail("a different RCA must not break identity");
        }
        // if_cond_match is a protocol-version signal, not identity.
        let mut other = base;
        other.if_cond_match = false;
        if !card_identity_matches(&base, &other) {
            return TestResult::Fail("if_cond_match must not affect identity");
        }
        let mut other = base;
        other.cid[0] ^= 0xFFFF_FFFF;
        if card_identity_matches(&base, &other) {
            return TestResult::Fail("a different CID must not match");
        }
        let mut other = base;
        other.capacity_blocks = 8_388_608;
        if card_identity_matches(&base, &other) {
            return TestResult::Fail("a different capacity must not match");
        }
        let mut other = base;
        other.ccs = false;
        if card_identity_matches(&base, &other) {
            return TestResult::Fail("a different CCS class must not match");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/storage/sdhci/pm",
        fixture_pm_identity_match_predicate
    );

    fn fixture_pm_runtime_gate_and_ungate_on_io() -> TestResult {
        let (transport, saved) = install(partitioned_image());
        let result = (|| {
            identify_and_publish()?;
            let first = read_sdhci0_block(2048)?;
            // Synthetic time: idle for 4.999 s — not yet gated.
            __set_last_busy_for_test(0);
            if try_idle_gate_at(4_999_000_000) {
                return Err("must not gate before the idle timeout");
            }
            if is_runtime_gated() {
                return Err("gated flag must be clear before the timeout");
            }
            // Idle for exactly the timeout — gated, power + clock off.
            if !try_idle_gate_at(5_000_000_000) {
                return Err("must gate once the idle timeout expires");
            }
            if !is_runtime_gated() {
                return Err("gated flag must be set after gating");
            }
            if transport.read8(REG_POWER_CONTROL) != 0 {
                return Err("POWER_CONTROL must be 0 after the idle gate");
            }
            if transport.read16(REG_CLOCK_CONTROL) & CLK_SD_EN != 0 {
                return Err("CLK_SD_EN must be clear after the idle gate");
            }
            // The next block I/O ungates synchronously (re-init +
            // re-identify) and returns the same data.
            let again = read_sdhci0_block(2048)?;
            if again != first {
                return Err("post-ungate read must return the same block");
            }
            if is_runtime_gated() {
                return Err("gated flag must clear after the ungating I/O");
            }
            if transport.read8(REG_POWER_CONTROL) & POWER_ON == 0 {
                return Err("power must be back on after the ungating I/O");
            }
            // A gate attempt while system-suspended never powers the
            // chip off a second time (already powered down).
            suspend_all().map_err(|_| "suspend_all failed")?;
            __set_last_busy_for_test(0);
            if try_idle_gate_at(60_000_000_000) {
                return Err("must not idle-gate while system-suspended");
            }
            resume_all().map_err(|_| "resume_all failed")?;
            if read_sdhci0_block(2048).is_err() {
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
        "drivers/storage/sdhci/pm",
        fixture_pm_runtime_gate_and_ungate_on_io
    );

    fn fixture_pm_runtime_gate_skips_busy_controller() -> TestResult {
        let (_transport, saved) = install(partitioned_image());
        let result = (|| {
            identify_and_publish()?;
            let ctrl = probed_sdhci().ok_or("fixture controller not installed")?;
            // Hold the request gate (an I/O in flight): the monitor
            // must not spin on it — it skips this tick.
            let _gate = ReqGate::acquire(&ctrl.req_gate);
            __set_last_busy_for_test(0);
            if try_idle_gate_at(60_000_000_000) {
                return Err("must not gate while the request gate is held");
            }
            if is_runtime_gated() {
                return Err("gated flag must stay clear when the gate is busy");
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
        "drivers/storage/sdhci/pm",
        fixture_pm_runtime_gate_skips_busy_controller
    );
}
