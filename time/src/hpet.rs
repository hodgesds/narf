//! High Precision Event Timer (HPET) — clean-room.
//!
//! Spec: Intel **"IA-PC HPET (High Precision Event Timers)
//! Specification"** rev 1.0a (free PDF, intel.com). Section
//! references below (`§3.2`) point at that document.
//!
//! HPET is a free-running monotonic counter at a fixed,
//! firmware-discoverable frequency (~14.31818 MHz on most systems).
//! NARF uses HPET as a TSC-validation cross-check + fallback
//! clocksource on hosts where TSC isn't invariant.
//!
//! ## Discovery
//!
//! The HPET base address normally lives in the ACPI **HPET** table.
//! Without a full ACPI parser in tree, we fall back to the
//! ubiquitous default placement: x86_64 chipsets (Intel ICH /
//! AMD FCH / QEMU q35) all expose HPET at physical `0xFED00000`.
//! Boot code can override the discovered base via
//! [`set_base_phys`] once an ACPI walker lands.
//!
//! ## Register layout (§3.2)
//!
//! | offset  | name                      | width |
//! |---------|---------------------------|-------|
//! | 0x000   | General Capabilities + ID | u64   |
//! | 0x010   | General Configuration     | u64   |
//! | 0x020   | General Interrupt Status  | u64   |
//! | 0x0F0   | Main Counter Value        | u64   |
//! | 0x100+  | Per-comparator block      | …     |
//!
//! General Capabilities + ID (§3.2.1):
//!
//! | bits    | field                                  |
//! |---------|----------------------------------------|
//! | [7:0]   | REV_ID                                 |
//! | [12:8]  | NUM_TIM_CAP — number of comparators-1  |
//! | [13]    | COUNT_SIZE — 1 = 64-bit main counter   |
//! | [15]    | LEG_RT_CAP                             |
//! | [16:31] | VENDOR_ID                              |
//! | [32:63] | COUNTER_CLK_PERIOD (femtoseconds)      |
//!
//! Main Counter Value: free-running 64-bit (or 32-bit) counter.
//!
//! Stage cut: read-only counter access + frequency derivation. No
//! comparator programming yet — that lands when the kernel needs a
//! HPET-driven oneshot wakeup beyond the LAPIC timer.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Default HPET physical base on x86_64 (Intel ICH / AMD FCH /
/// QEMU q35). ACPI HPET-table parsing can override via
/// [`set_base_phys`].
pub const HPET_DEFAULT_BASE: u64 = 0xFED0_0000;

const REG_CAP_ID: u64 = 0x000;
const REG_GEN_CONF: u64 = 0x010;
const REG_INT_STS: u64 = 0x020;
const REG_MAIN_CNT: u64 = 0x0F0;
const REG_TIMER_BASE: u64 = 0x100;
const REG_TIMER_STRIDE: u64 = 0x20;

const GEN_CONF_ENABLE_CNF: u64 = 1 << 0;

/// One femtosecond.
pub const FEMTOS_PER_SEC: u64 = 1_000_000_000_000_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpetError {
    /// HPET memory window doesn't carry a valid capabilities word.
    NotPresent,
    /// COUNTER_CLK_PERIOD reads as zero or implausibly large.
    BadFrequency,
}

#[derive(Copy, Clone, Debug)]
pub struct HpetCaps {
    pub rev_id: u8,
    /// Number of comparators (NUM_TIM_CAP + 1).
    pub num_comparators: u8,
    pub counter_64bit: bool,
    pub legacy_route_cap: bool,
    pub vendor_id: u16,
    /// Tick period in femtoseconds.
    pub clk_period_fs: u32,
}

impl HpetCaps {
    /// Tick frequency in Hz.
    pub fn frequency_hz(&self) -> u64 {
        if self.clk_period_fs == 0 {
            return 0;
        }
        FEMTOS_PER_SEC / self.clk_period_fs as u64
    }
}

#[derive(Debug)]
pub struct Hpet {
    base_phys: u64,
    caps: HpetCaps,
}

impl Hpet {
    /// Probe HPET at `base_phys`. Reads the capabilities word + the
    /// counter clock period; returns `NotPresent` if the
    /// capabilities word is all-zeros / all-ones (no chip behind
    /// the address) and `BadFrequency` if `clk_period_fs == 0`.
    ///
    /// # Safety
    /// Caller asserts that `base_phys` is a valid 1 KiB MMIO
    /// window backed by HPET.
    pub unsafe fn probe(base_phys: u64) -> Result<Self, HpetError> {
        // SAFETY: caller-asserted MMIO window; identity-mapped on
        // x86_64 (HPET base is in the legacy MMIO hole below 4 GiB).
        let cap = unsafe { read_u64(base_phys + REG_CAP_ID) };
        if cap == 0 || cap == u64::MAX {
            return Err(HpetError::NotPresent);
        }
        let clk = ((cap >> 32) & 0xFFFF_FFFF) as u32;
        if clk == 0 || clk > 200_000_000 {
            // > 0.2 ns / tick is implausible for any real HPET.
            return Err(HpetError::BadFrequency);
        }
        let caps = HpetCaps {
            rev_id: (cap & 0xFF) as u8,
            num_comparators: (((cap >> 8) & 0x1F) + 1) as u8,
            counter_64bit: (cap >> 13) & 1 != 0,
            legacy_route_cap: (cap >> 15) & 1 != 0,
            vendor_id: ((cap >> 16) & 0xFFFF) as u16,
            clk_period_fs: clk,
        };
        Ok(Self { base_phys, caps })
    }

    /// Enable the main counter (set GEN_CONF.ENABLE_CNF).
    ///
    /// # Safety
    /// Caller owns the HPET window exclusively.
    pub unsafe fn enable(&self) {
        // SAFETY: identity-mapped MMIO.
        let g = unsafe { read_u64(self.base_phys + REG_GEN_CONF) };
        // SAFETY: same.
        unsafe {
            write_u64(self.base_phys + REG_GEN_CONF, g | GEN_CONF_ENABLE_CNF);
        }
    }

    /// Disable the main counter.
    ///
    /// # Safety
    /// Caller owns the HPET window exclusively.
    pub unsafe fn disable(&self) {
        // SAFETY: identity-mapped MMIO.
        let g = unsafe { read_u64(self.base_phys + REG_GEN_CONF) };
        // SAFETY: same.
        unsafe {
            write_u64(self.base_phys + REG_GEN_CONF, g & !GEN_CONF_ENABLE_CNF);
        }
    }

    /// Snapshot of the main counter (free-running ticks).
    ///
    /// # Safety
    /// HPET window must be live.
    pub unsafe fn read_counter(&self) -> u64 {
        // SAFETY: caller-asserted live window.
        unsafe { read_u64(self.base_phys + REG_MAIN_CNT) }
    }

    pub fn caps(&self) -> HpetCaps {
        self.caps
    }
    pub fn base_phys(&self) -> u64 {
        self.base_phys
    }
}

// ── Singleton + raw reads ──────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn read_u64(phys: u64) -> u64 {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe { core::ptr::read_volatile(phys as *const u64) }
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_u64(phys: u64, v: u64) {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe {
        core::ptr::write_volatile(phys as *mut u64, v);
    }
}

// On non-x86_64, HPET doesn't exist (Generic Timer fills the role).
// Stub the helpers so the module compiles cross-arch.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_u64(_phys: u64) -> u64 {
    0
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn write_u64(_phys: u64, _v: u64) {}

static HPET: IrqSafeSpinLock<Option<Hpet>> = IrqSafeSpinLock::new(None);
static BASE_OVERRIDE: AtomicU64 = AtomicU64::new(0);

/// Override the HPET MMIO base — for ACPI HPET-table parsing.
/// Must be called before [`init`].
pub fn set_base_phys(phys: u64) {
    BASE_OVERRIDE.store(phys, Ordering::Release);
}

/// Probe + enable HPET. Returns `Ok` on x86_64 with a working
/// HPET, `Err(NotPresent)` everywhere else (aarch64) or when the
/// HPET window is inert.
///
/// # Safety
/// First-caller wins; callers assert single-threaded boot context.
pub unsafe fn init() -> Result<(), HpetError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(HpetError::NotPresent);
    }
    let base = match BASE_OVERRIDE.load(Ordering::Acquire) {
        0 => HPET_DEFAULT_BASE,
        v => v,
    };
    // SAFETY: caller-asserted boot-time exclusivity.
    let dev = unsafe { Hpet::probe(base) }?;
    // SAFETY: caller asserted single-threaded.
    unsafe {
        dev.enable();
    }
    *HPET.lock() = Some(dev);
    Ok(())
}

/// Tick frequency in Hz (0 if HPET wasn't initialised).
pub fn frequency_hz() -> u64 {
    HPET.lock().as_ref().map_or(0, |h| h.caps.frequency_hz())
}

/// Read the main counter (0 if HPET wasn't initialised).
pub fn read_counter() -> u64 {
    let g = HPET.lock();
    match g.as_ref() {
        Some(h) => {
            // SAFETY: HPET stays alive for the lifetime of the
            // singleton; the lock holds for the read.
            unsafe { h.read_counter() }
        }
        None => 0,
    }
}

/// Capabilities snapshot (None if HPET wasn't initialised).
pub fn caps() -> Option<HpetCaps> {
    HPET.lock().as_ref().map(|h| h.caps)
}

/// `true` iff HPET probe succeeded.
pub fn is_present() -> bool {
    HPET.lock().is_some()
}

/// Convert a HPET tick delta to nanoseconds. Returns 0 if HPET
/// isn't initialised or the period is degenerate.
pub fn ticks_to_nanos(ticks: u64) -> u64 {
    let g = HPET.lock();
    match g.as_ref() {
        Some(h) => {
            let period_fs = h.caps.clk_period_fs as u64;
            // ns = ticks * period_fs / 1_000_000.
            ticks.saturating_mul(period_fs) / 1_000_000
        }
        None => 0,
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    *HPET.lock() = None;
    BASE_OVERRIDE.store(0, Ordering::Release);
}
