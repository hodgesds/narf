//! Volatile-write-cache flush and clean controller shutdown — the register
//! protocol of Linux `nvme_disable_ctrl(ctrl, shutdown = true)` /
//! `nvme_wait_ready` and the quiesce order of `nvme_shutdown` →
//! `nvme_dev_disable`, kept free of MMIO so it is model-testable.
//!
//! Order on reboot / power-off, per controller: every namespace is flushed
//! (when the controller reports a volatile write cache) and each flush's
//! completion is awaited, THEN CC.SHN = normal shutdown is written and
//! CSTS.SHST is polled until "shutdown processing complete", bounded by
//! RTD3E clamped to Linux's `shutdown_timeout` range (5..=60 s).

/// CC.SHN (bits 15:14). `01b` = normal shutdown notification.
pub const CC_SHN_MASK: u32 = 3 << 14;
pub const CC_SHN_NORMAL: u32 = 1 << 14;
/// CC.EN.
pub const CC_EN: u32 = 1;
/// CSTS.SHST (bits 3:2). `10b` = shutdown processing complete.
pub const CSTS_SHST_MASK: u32 = 3 << 2;
pub const CSTS_SHST_CMPLT: u32 = 2 << 2;
/// Write CDW12 bit 30: Force Unit Access.
pub const CDW12_FUA: u32 = 1 << 30;
/// Identify Controller VWC bit 0: a volatile write cache is present.
pub const VWC_PRESENT: u8 = 1;

/// Linux `shutdown_timeout` module default, seconds.
pub const DEFAULT_SHUTDOWN_TIMEOUT_S: u64 = 5;
/// Linux clamps the RTD3E-derived timeout to at most 60 s.
pub const MAX_SHUTDOWN_TIMEOUT_S: u64 = 60;

/// Shutdown wait budget from Identify Controller RTD3E (microseconds),
/// as Linux `nvme_init_ctrl_finish`: `clamp(rtd3e / 1e6, 5, 60)` seconds,
/// 5 s when RTD3E is not reported.
pub fn shutdown_timeout_ms(rtd3e_us: u32) -> u64 {
    let s = if rtd3e_us == 0 {
        DEFAULT_SHUTDOWN_TIMEOUT_S
    } else {
        (rtd3e_us as u64 / 1_000_000).clamp(DEFAULT_SHUTDOWN_TIMEOUT_S, MAX_SHUTDOWN_TIMEOUT_S)
    };
    s * 1000
}

/// Whether Identify Controller VWC reports a volatile write cache.
pub fn has_volatile_write_cache(vwc: u8) -> bool {
    vwc & VWC_PRESENT != 0
}

/// The controller registers the shutdown protocol touches.
pub trait CtrlRegs {
    fn read_cc(&self) -> u32;
    fn write_cc(&self, v: u32);
    fn read_csts(&self) -> u32;
}

/// Result of [`normal_shutdown`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// CSTS.SHST reported shutdown processing complete.
    Complete,
    /// SHST never completed within the budget.
    TimedOut,
    /// CSTS reads all-ones: the function is gone (surprise removal).
    Gone,
    /// CC.EN was already 0: nothing to shut down (Linux skips it too).
    NotEnabled,
}

/// Send CC.SHN = normal and wait for CSTS.SHST = complete. `spin(cond,
/// timeout_ms)` polls `cond` until it is true or the budget runs out and
/// returns whether it became true (the driver passes
/// `narf_scheduler::responsive_spin_until`).
pub fn normal_shutdown(
    regs: &dyn CtrlRegs,
    timeout_ms: u64,
    spin: &mut dyn FnMut(&mut dyn FnMut() -> bool, u64) -> bool,
) -> ShutdownOutcome {
    if regs.read_csts() == u32::MAX {
        return ShutdownOutcome::Gone;
    }
    let cc = regs.read_cc();
    if cc & CC_EN == 0 {
        return ShutdownOutcome::NotEnabled;
    }
    regs.write_cc((cc & !CC_SHN_MASK) | CC_SHN_NORMAL);
    let mut gone = false;
    let done = spin(
        &mut || {
            let csts = regs.read_csts();
            if csts == u32::MAX {
                gone = true;
                return true;
            }
            csts & CSTS_SHST_MASK == CSTS_SHST_CMPLT
        },
        timeout_ms,
    );
    match (done, gone) {
        (_, true) => ShutdownOutcome::Gone,
        (true, false) => ShutdownOutcome::Complete,
        (false, false) => ShutdownOutcome::TimedOut,
    }
}

/// What [`quiesce`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuiesceReport<E> {
    /// Per namespace flushed: `(nsid, result)`. Empty without a VWC.
    pub flushes: alloc::vec::Vec<(u32, Result<(), E>)>,
    pub shutdown: ShutdownOutcome,
}

/// One controller's final quiesce: flush every namespace (only when the
/// controller has a volatile write cache; `flush(nsid)` returns once the
/// Flush completed), then [`normal_shutdown`]. Flush errors do not stop the
/// shutdown — a controller that cannot flush still gets SHN, which itself
/// obliges it to commit its cache (NVMe Base 2.0c §3.6.2).
pub fn quiesce<E>(
    nsids: &[u32],
    vwc: u8,
    flush: &mut dyn FnMut(u32) -> Result<(), E>,
    regs: &dyn CtrlRegs,
    timeout_ms: u64,
    spin: &mut dyn FnMut(&mut dyn FnMut() -> bool, u64) -> bool,
) -> QuiesceReport<E> {
    let mut flushes = alloc::vec::Vec::new();
    if has_volatile_write_cache(vwc) {
        for &nsid in nsids {
            flushes.push((nsid, flush(nsid)));
        }
    }
    let shutdown = normal_shutdown(regs, timeout_ms, spin);
    QuiesceReport { flushes, shutdown }
}
