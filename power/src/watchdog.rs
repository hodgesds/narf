//! Hardware watchdog register codecs — clean-room.
//!
//! Three timer-block layouts covering the watchdogs every modern
//! consumer device exposes:
//!
//! - [`itco`] — Intel TCO timer (ICH/PCH).
//! - [`sp5100`] — AMD SP5100 / FCH watchdog.
//! - [`sp805`] — ARM PrimeCell SP805 watchdog (every ARMv8 SoC).
//!
//! All three are pure register codecs — no live MMIO here. Drivers
//! call `compose_kick()` to produce the value to write to the
//! corresponding register; tests round-trip the codec without an IO
//! stack.

extern crate alloc;

// ── Intel iTCO (ICH/PCH) ─────────────────────────────────────────

/// Intel TCO watchdog.
///
/// ## Reference (public only)
///
/// - **Intel® 100-Series Chipset Family Platform Controller Hub
///   (PCH) Datasheet**, vol. 2, §"TCO Functions". Public datasheet.
///   <https://www.intel.com/content/www/us/en/products/docs/chipsets/100-series-chipset-family-platform-controller-hub-datasheet-vol-2.html>
///
/// The TCO registers live in PMC ACPI Base I/O space + 0x60. Layout:
///
/// ```text
///   0x00  TCO_RLD       16-bit — reload (any write reloads the timer)
///   0x02  TCOv2_TMR     16-bit — timer countdown value
///   0x04  TCO_DAT_IN    8-bit  — TCO message byte 0
///   0x05  TCO_DAT_OUT   8-bit  — message byte 1
///   0x06  TCO1_STS      16-bit — status (TCO timeout fires bit 3)
///   0x08  TCO2_STS      16-bit — secondary status
///   0x12  TCO1_TMR      16-bit — initial value (1.6 s tick); program
///                                 with 4..0x3FF before kicking
/// ```
pub mod itco {
    pub const TCO_RLD: usize = 0x00;
    pub const TCOV2_TMR: usize = 0x02;
    pub const TCO1_STS: usize = 0x06;
    pub const TCO2_STS: usize = 0x08;
    pub const TCO1_TMR: usize = 0x12;

    /// `TCO1_STS` bit 3 — Timer Timeout. W1C.
    pub const TCO1_STS_TIMEOUT: u16 = 1 << 3;
    /// `TCO1_STS` bit 1 — TCO Slave Write Boot Status. W1C.
    pub const TCO1_STS_SW_TCO: u16 = 1 << 1;

    /// Compose a `TCO1_TMR` initial value clamped to spec range
    /// (4..=0x3FF). The TCO clock ticks at ~1/0.6 Hz on most PCHs;
    /// `seconds * 1_000 / 600` rounds toward the next tick.
    pub fn compose_initial_seconds(seconds: u32) -> u16 {
        let ticks = seconds.saturating_mul(1000) / 600;
        ticks.clamp(4, 0x3FF) as u16
    }

    /// Anything written to `TCO_RLD` reloads the timer with the
    /// `TCO1_TMR` initial value. Any 16-bit value works; we use 1
    /// to keep wire payload small.
    pub const TCO_RLD_KICK: u16 = 1;
}

// ── AMD SP5100 / FCH watchdog ────────────────────────────────────

/// AMD SP5100 (and successors — the AMD Fusion Controller Hub
/// "CG-WDT") watchdog.
///
/// ## Reference (public only)
///
/// - **AMD SB700 / SB710 / SB750 Register Reference Guide**, AMD,
///   2010. Public.
///   <https://www.amd.com/system/files/TechDocs/43009_sb7xx_rrg_pub_1.00.pdf>
///   §2.6 "Watchdog Timer Function".
///
/// Layout (memory-mapped at the AcpiMmioBase + 0x0xCD7000):
///
/// ```text
///   0x00  CONTROL  bit 0 = enable, bit 1 = action (0=reset, 1=irq),
///                  bit 6 = trigger (write 1 to reload)
///   0x04  COUNT    32-bit — 32-bit countdown in 1-Hz ticks
/// ```
pub mod sp5100 {
    pub const CONTROL: usize = 0x00;
    pub const COUNT: usize = 0x04;

    pub const CONTROL_ENABLE: u32 = 1 << 0;
    /// 0 = reset on timeout, 1 = signal IRQ.
    pub const CONTROL_ACTION_IRQ: u32 = 1 << 1;
    /// Write 1 to reload `COUNT` from the configured initial value.
    pub const CONTROL_TRIGGER: u32 = 1 << 6;

    /// Compose the COUNT register value for the requested timeout
    /// in seconds. Tick rate is 1 Hz, so this is the identity for
    /// `seconds <= u32::MAX`.
    pub fn compose_count_seconds(seconds: u32) -> u32 {
        seconds
    }
}

// ── ARM PrimeCell SP805 ──────────────────────────────────────────

/// ARM PrimeCell SP805 watchdog.
///
/// ## Reference (public only)
///
/// - **ARM PrimeCell Watchdog (SP805) Technical Reference Manual,
///   Revision r1p0**, ARM. Public.
///   <https://developer.arm.com/documentation/ddi0270/b/>
///
/// Layout (4 KiB register window):
///
/// ```text
///   0x000  WDOGLOAD     32-bit — load value (counts down from this)
///   0x004  WDOGVALUE    32-bit (RO) — current count
///   0x008  WDOGCONTROL  32-bit — bit 0 = INTEN, bit 1 = RESEN
///   0x00C  WDOGINTCLR   32-bit — write any value to ack interrupt
///                                 *and* reload from WDOGLOAD
///   0x010  WDOGRIS      32-bit (RO) — raw interrupt status
///   0x014  WDOGMIS      32-bit (RO) — masked interrupt status
///   0xC00  WDOGLOCK     32-bit — write 0x1ACCE551 to unlock
/// ```
pub mod sp805 {
    pub const WDOGLOAD: usize = 0x000;
    pub const WDOGVALUE: usize = 0x004;
    pub const WDOGCONTROL: usize = 0x008;
    pub const WDOGINTCLR: usize = 0x00C;
    pub const WDOGRIS: usize = 0x010;
    pub const WDOGMIS: usize = 0x014;
    pub const WDOGLOCK: usize = 0xC00;

    pub const CONTROL_INTEN: u32 = 1 << 0;
    pub const CONTROL_RESEN: u32 = 1 << 1;

    /// Magic write to `WDOGLOCK` that re-enables register writes.
    pub const LOCK_UNLOCK: u32 = 0x1ACC_E551;
    /// Any other write to `WDOGLOCK` re-locks the register file.
    pub const LOCK_LOCK: u32 = 0x0000_0000;

    /// Compose the WDOGLOAD value for a given timeout in seconds
    /// at the supplied input clock frequency. The watchdog fires at
    /// half the load value (the second-stage interrupt → reset
    /// chain), so we double internally.
    pub fn compose_load_seconds(seconds: u32, clock_hz: u32) -> u32 {
        // Avoid overflow on big timeouts — clamp at u32::MAX.
        seconds
            .saturating_mul(clock_hz / 2)
            .max(1)
    }
}
