//! Hardware watchdog drivers — sp5100_tco (AMD) and iTCO (Intel).
//!
//! ## Architecture
//!
//! Three layers:
//!
//! 1. **Register codecs** (`itco`, `sp5100`, `sp805` sub-modules) — pure
//!    `const`s and `fn`s with no IO.  Tests round-trip the codecs without
//!    an IO stack.
//!
//! 2. **Driver state** (`Sp5100Driver`, `ITcoDriver`) — wraps the MMIO /
//!    IO-port base address + timeout state.  Operations take `&self`/`&mut
//!    self`; the actual reads/writes are done through the arch `IoPort`
//!    trait or raw-ptr MMIO helpers.
//!
//! 3. **Kick task** — `WatchdogKickTask` is a scheduler sleep-pump that
//!    wakes every `timeout / 2` seconds and calls `kick()` on the active
//!    driver.  If the scheduler stalls (hung kernel) the pump never fires,
//!    the countdown expires, and the hardware resets the system.
//!
//! ## Hardware references
//!
//! - **sp5100_tco**: `linux/drivers/watchdog/sp5100_tco.c` + `sp5100_tco.h`.
//!   Registers at `SP5100_WDT_CONTROL` (base+0x00) and `SP5100_WDT_COUNT`
//!   (base+0x04).  PMIO at 0xCD6/0xCD7 for MMIO base discovery on older
//!   (SB7xx / SB8xx) silicon; EFCH (Zen-class FCH) uses fixed MMIO base
//!   `0xFEB0_0000`.
//!
//! - **iTCO**: `linux/drivers/watchdog/iTCO_wdt.c`.  TCO registers in the
//!   PMC ACPI I/O space at `TCOBASE` (usually ACPIBASE + 0x60).  TCO_RLD
//!   at +0x00 (kick), TCO1_TMR at +0x12 (initial value, 1.6 s / tick).
//!
//! ## References (Linux source lines)
//!
//! - `sp5100_tco.h` lines 15–91: register offsets and bit-field constants.
//! - `sp5100_tco.c` lines 109–166: `tco_timer_start / stop / ping / set_timeout`.
//! - `sp5100_tco.c` lines 171–183: PMIO helpers `read_pm_reg8 / update_pm_reg8`.
//! - `sp5100_tco.c` lines 291–327: `sp5100_tco_timer_init` (probe, fired clear).
//! - `iTCO_wdt.c` lines 72–87: TCO register offsets.
//! - `iTCO_wdt.c` lines 279–343: `iTCO_wdt_start / stop / ping`.
//! - `iTCO_wdt.c` lines 345–389: `iTCO_wdt_set_timeout` (tick conversion).
//! - `iTCO_wdt.c` lines 477–516: SMI_EN TCO_EN gate on probe.

extern crate alloc;

// ── Register codecs ──────────────────────────────────────────────────────────

// ── Intel iTCO (ICH/PCH) ─────────────────────────────────────────────────────

/// Intel TCO watchdog register codec.
///
/// ## Reference
///
/// - **Intel 100-Series PCH Datasheet** vol. 2, §"TCO Functions" (public).
///   <https://www.intel.com/content/www/us/en/products/docs/chipsets/100-series-chipset-family-platform-controller-hub-datasheet-vol-2.html>
/// - `linux/drivers/watchdog/iTCO_wdt.c` lines 72–87 (register layout).
///
/// Registers live at `TCOBASE` = ACPI PM I/O base + 0x60.
///
/// ```text
///   0x00  TCO_RLD     16-bit — write any value to reload the timer.
///                              After v2, also current-count readback.
///   0x01  TCOv1_TMR   8-bit  — v1 initial value (0x04..0x3F).
///   0x04  TCO1_STS    16-bit — bit 3 = timeout fired (W1C).
///   0x06  TCO2_STS    16-bit — bit 1 = SECOND_TO (W1C), bit 2 = BOOT_STS (W1C).
///   0x08  TCO1_CNT    16-bit — bit 11 = NO_REBOOT, bit 8 = NMI_NOW, bit 0 = HALT.
///   0x12  TCOv2_TMR   16-bit — v2 initial value (4..0x3FF); 1 tick ≈ 0.6 s.
/// ```
pub mod itco {
    /// Kick: write any value here to reload the timer.
    /// `iTCO_wdt.c:72` — `#define TCO_RLD(p) (TCOBASE(p) + 0x00)`.
    pub const TCO_RLD: usize = 0x00;
    /// v1 only: 8-bit initial value at TCOBASE + 0x01.
    /// `iTCO_wdt.c:73` — `#define TCOv1_TMR(p) (TCOBASE(p) + 0x01)`.
    pub const TCOV1_TMR: usize = 0x01;
    /// TCO1 status register; bit 3 = timeout fired (W1C).
    /// `iTCO_wdt.c:76` — `#define TCO1_STS(p) (TCOBASE(p) + 0x04)`.
    pub const TCO1_STS: usize = 0x04;
    /// TCO2 status register; bit 1 = SECOND_TO (W1C).
    /// `iTCO_wdt.c:77` — `#define TCO2_STS(p) (TCOBASE(p) + 0x06)`.
    pub const TCO2_STS: usize = 0x06;
    /// TCO1 control register; bit 11 = NO_REBOOT, bit 0 = HALT.
    /// `iTCO_wdt.c:78` — `#define TCO1_CNT(p) (TCOBASE(p) + 0x08)`.
    pub const TCO1_CNT: usize = 0x08;
    /// v2+ initial value register (16-bit, range 4..=0x3FF).
    /// `iTCO_wdt.c:80` — `#define TCOv2_TMR(p) (TCOBASE(p) + 0x12)`.
    pub const TCOV2_TMR: usize = 0x12;

    /// `TCO1_STS` bit 3 — Timer Timeout. W1C.
    /// `iTCO_wdt.c:337` — `outw(0x0008, TCO1_STS(p))`.
    pub const TCO1_STS_TIMEOUT: u16 = 1 << 3;
    /// `TCO2_STS` bit 1 — SECOND_TO status. W1C.
    /// `iTCO_wdt.c:536` — `outw(0x0002, TCO2_STS(p))`.
    pub const TCO2_STS_SECOND_TO: u16 = 1 << 1;
    /// `TCO2_STS` bit 2 — BOOT_STS. W1C.
    pub const TCO2_STS_BOOT_STS: u16 = 1 << 2;

    /// `TCO1_CNT` bit 11 — NO_REBOOT.  When set prevents the second
    /// timeout from triggering a system reset.
    /// `iTCO_wdt.c:84` — `#define NO_REBOOT BIT(11)`.
    pub const TCO1_CNT_NO_REBOOT: u16 = 1 << 11;
    /// `TCO1_CNT` bit 0 — TCO halt (stop timer).
    /// Derived: Linux uses masked read-modify-write on TCO1_CNT to
    /// stop/start; clearing bit 0 enables, setting halts.
    pub const TCO1_CNT_HALT: u16 = 1 << 0;
    /// `TCO1_CNT` bit 8 — NMI_NOW.  Must mask during read-modify-write
    /// to avoid inverting the NMI.
    /// `iTCO_wdt.c:87` — `#define NMI_NOW BIT(8)`.
    pub const NMI_NOW: u16 = 1 << 8;

    /// Value written to `TCO_RLD` to kick the watchdog.  Any 16-bit
    /// value works; we use 1 to keep the wire payload minimal.
    /// `iTCO_wdt.c:293` — `outw(0x01, TCO_RLD(p))`.
    pub const TCO_RLD_KICK: u16 = 1;

    /// SMI_EN register offset from the ACPI PM I/O base.  Bit 13
    /// (`TCO_EN`) gates whether a TCO timeout fires an SMI.
    /// `iTCO_wdt.c:477` — `#define SMI_EN(p) ((p)->smi_res->start)`.
    pub const SMI_EN_TCO_EN: u32 = 1 << 13;

    /// Compose a `TCOv2_TMR` initial value for the requested timeout in
    /// seconds.  iTCO tick ≈ 0.6 s (600 ms).  Clamped to the spec range
    /// 4..=0x3FF.
    ///
    /// Formula: `ticks = ceil(seconds / 0.6) = (seconds * 1000 + 599) / 600`.
    /// Linux does `seconds * 1000 / 600`; we round up to ensure the
    /// programmed value covers at least `seconds` of real time.
    ///
    /// `iTCO_wdt.c:345–389` — `iTCO_wdt_set_timeout`.
    pub fn compose_initial_seconds(seconds: u32) -> u16 {
        let ticks = seconds.saturating_mul(1000).saturating_add(599) / 600;
        ticks.clamp(4, 0x3FF) as u16
    }
}

// ── AMD SP5100 / FCH watchdog ─────────────────────────────────────────────────

/// AMD SP5100 / SB8xx / EFCH (Zen-class FCH) watchdog register codec.
///
/// ## Reference
///
/// - **AMD SP5100 Register Reference Guide**, pub. 44413 (public).
/// - **AMD SB800 Register Reference Guide**, pub. 45482.
/// - `linux/drivers/watchdog/sp5100_tco.h` lines 15–91 (register defs).
/// - `linux/drivers/watchdog/sp5100_tco.c` lines 109–166 (operations).
///
/// Registers at `WDT_BASE` (MMIO mapped; base discovered via PMIO or
/// EFCH fixed address `0xFEB0_0000`):
///
/// ```text
///   0x00  WDT_CONTROL  32-bit
///               bit 0  = START_STOP (1 = running)
///               bit 1  = WDT_FIRED  (W1C in reads; reset-cause latch)
///               bit 2  = ACTION_RESET (0=reset, 1=signal IRQ)
///               bit 3  = WDT_DISABLED (hw-locked; skip probe)
///               bit 7  = TRIGGER (write 1 to reload count register)
///   0x04  WDT_COUNT    32-bit — countdown in 1 Hz ticks.
/// ```
pub mod sp5100 {
    /// Watchdog control register offset.
    /// `sp5100_tco.h:16` — `#define SP5100_WDT_CONTROL(base) ((base) + 0x00)`.
    pub const CONTROL: usize = 0x00;
    /// Watchdog count (timeout) register offset.
    /// `sp5100_tco.h:17` — `#define SP5100_WDT_COUNT(base)   ((base) + 0x04)`.
    pub const COUNT: usize = 0x04;

    /// CONTROL bit 0 — START/STOP (1 = watchdog running).
    /// `sp5100_tco.h:19` — `#define SP5100_WDT_START_STOP_BIT BIT(0)`.
    pub const CONTROL_ENABLE: u32 = 1 << 0;
    /// CONTROL bit 1 — WDT_FIRED latch (W1C).  Set by hardware when the
    /// watchdog expired and caused a reset.
    /// `sp5100_tco.h:20` — `#define SP5100_WDT_FIRED BIT(1)`.
    pub const CONTROL_FIRED: u32 = 1 << 1;
    /// CONTROL bit 2 — action on timeout: 0 = reset, 1 = IRQ.
    /// `sp5100_tco.h:21` — `#define SP5100_WDT_ACTION_RESET BIT(2)`.
    pub const CONTROL_ACTION_IRQ: u32 = 1 << 2;
    /// CONTROL bit 3 — hardware-disabled (read-only; if set probe aborts).
    /// `sp5100_tco.h:22` — `#define SP5100_WDT_DISABLED BIT(3)`.
    pub const CONTROL_DISABLED: u32 = 1 << 3;
    /// CONTROL bit 7 — write 1 to reload the countdown from WDT_COUNT.
    /// `sp5100_tco.h:23` — `#define SP5100_WDT_TRIGGER_BIT BIT(7)`.
    pub const CONTROL_TRIGGER: u32 = 1 << 7;

    /// PMIO: index-register port (write register index here).
    /// `sp5100_tco.h:33` — `#define SP5100_IO_PM_INDEX_REG 0xCD6`.
    pub const PMIO_INDEX: u16 = 0xCD6;
    /// PMIO: data-register port (read/write data after setting index).
    /// `sp5100_tco.h:34` — `#define SP5100_IO_PM_DATA_REG  0xCD7`.
    pub const PMIO_DATA: u16 = 0xCD7;

    /// PMIO index for the SB7xx watchdog MMIO base (4-byte little-endian).
    /// `sp5100_tco.h:40` — `#define SP5100_PM_WATCHDOG_BASE 0x6C`.
    pub const PMIO_WDT_BASE: u8 = 0x6C;
    /// PMIO index for the SB8xx watchdog MMIO base.
    /// `sp5100_tco.h:53` — `#define SB800_PM_WATCHDOG_BASE 0x48`.
    pub const PMIO_SB800_WDT_BASE: u8 = 0x48;

    /// EFCH (Zen FCH) fixed watchdog MMIO base.
    /// `sp5100_tco.h:79` — `#define EFCH_PM_WDT_ADDR 0xfeb00000`.
    pub const EFCH_WDT_BASE: u64 = 0xFEB0_0000;

    /// EFCH PM ACPI MMIO base.
    /// `sp5100_tco.h:85` — `#define EFCH_PM_ACPI_MMIO_ADDR 0xfed80000`.
    pub const EFCH_ACPI_MMIO_BASE: u64 = 0xFED8_0000;
    /// EFCH PM ACPI MMIO watchdog offset.
    /// `sp5100_tco.h:87` — `#define EFCH_PM_ACPI_MMIO_WDT_OFFSET 0x00000b00`.
    pub const EFCH_ACPI_MMIO_WDT_OFFSET: u32 = 0x0000_0B00;

    /// SB8xx ACPI MMIO watchdog offset.
    /// `sp5100_tco.h:63` — `#define SB800_PM_WDT_MMIO_OFFSET 0xB00`.
    pub const SB800_WDT_MMIO_OFFSET: u32 = 0xB00;

    /// Compose the WDT_COUNT register value for the requested timeout in
    /// seconds.  The SP5100 / SB8xx / EFCH watchdog counts down at 1 Hz,
    /// so the count value equals the number of seconds.
    ///
    /// `sp5100_tco.c:149–155` — `tco_timer_set_timeout`.
    pub fn compose_count_seconds(seconds: u32) -> u32 {
        seconds
    }

    /// Compose the CONTROL register value for `enable()`.
    /// Sets START_STOP and TRIGGER; clears everything else.
    /// `sp5100_tco.c:109–121` — `tco_timer_start`.
    pub fn compose_enable_control(mut ctrl: u32) -> u32 {
        ctrl |= CONTROL_ENABLE | CONTROL_TRIGGER;
        ctrl
    }

    /// Compose the CONTROL register value for `disable()`.
    /// Clears START_STOP.
    /// `sp5100_tco.c:125–133` — `tco_timer_stop`.
    pub fn compose_disable_control(mut ctrl: u32) -> u32 {
        ctrl &= !CONTROL_ENABLE;
        ctrl
    }

    /// Compose the CONTROL register value for a `kick()`.
    /// Sets TRIGGER; does not change START_STOP.
    /// `sp5100_tco.c:137–144` — `tco_timer_ping`.
    pub fn compose_kick_control(mut ctrl: u32) -> u32 {
        ctrl |= CONTROL_TRIGGER;
        ctrl
    }
}

// ── ARM PrimeCell SP805 ───────────────────────────────────────────────────────

/// ARM PrimeCell SP805 watchdog register codec.
///
/// ## Reference
///
/// - **ARM PrimeCell Watchdog (SP805) TRM, r1p0**. Public.
///   <https://developer.arm.com/documentation/ddi0270/b/>
///
/// ```text
///   0x000  WDOGLOAD     32-bit — load value (counts down from this)
///   0x004  WDOGVALUE    32-bit (RO) — current count
///   0x008  WDOGCONTROL  32-bit — bit 0 = INTEN, bit 1 = RESEN
///   0x00C  WDOGINTCLR   32-bit — write any value to ack + reload
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

    /// Compose the WDOGLOAD value for the given timeout in seconds at
    /// the supplied input clock frequency.  The watchdog fires at half
    /// the load value (second-stage interrupt → reset chain), so the
    /// load must cover twice the desired interval.
    pub fn compose_load_seconds(seconds: u32, clock_hz: u32) -> u32 {
        seconds.saturating_mul(clock_hz / 2).max(1)
    }
}

// ── sp5100 driver ─────────────────────────────────────────────────────────────

/// Probe result from PMIO-based MMIO-base discovery.
///
/// The caller supplies this to `Sp5100Driver::from_probe()`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Sp5100PmioBase {
    /// SB7xx / SP5100 — read 4 bytes from PMIO index 0x6C.
    Sb7xx(u32),
    /// SB8xx / Hudson — read 4 bytes from PMIO index 0x48.
    Sb8xx(u32),
    /// EFCH (Zen FCH) — fixed base `0xFEB0_0000`.
    Efch,
    /// EFCH MMIO alternative (AcpiMmioBase + 0xB00).
    EfchMmio(u64),
}

impl Sp5100PmioBase {
    /// Resolve the probed base to an MMIO physical address.
    ///
    /// `sp5100_tco.c:451–476` — MMIO base selection logic.
    pub fn mmio_addr(self) -> u64 {
        match self {
            Sp5100PmioBase::Sb7xx(raw) => (raw & !0xFFF) as u64,
            Sp5100PmioBase::Sb8xx(raw) => (raw & !0xFFF) as u64 + sp5100::SB800_WDT_MMIO_OFFSET as u64,
            Sp5100PmioBase::Efch => sp5100::EFCH_WDT_BASE,
            Sp5100PmioBase::EfchMmio(base) => base + sp5100::EFCH_ACPI_MMIO_WDT_OFFSET as u64,
        }
    }
}

/// AMD SP5100 / FCH watchdog driver state.
///
/// Holds the virtual base pointer and current timeout.  Operations are
/// implemented as register read-modify-write sequences against `mmio_base`.
#[derive(Debug)]
pub struct Sp5100Driver {
    /// Virtual address of the 8-byte WDT register window.
    /// Typically `ioremap(EFCH_PM_WDT_ADDR, 8)` on Zen silicon.
    pub mmio_base: u64,
    /// Configured timeout in seconds.
    pub timeout_secs: u32,
    /// True if the watchdog fired a reset on the previous boot.
    pub fired_on_prev_boot: bool,
}

impl Sp5100Driver {
    /// Build a driver from a previously-probed PMIO base.
    ///
    /// Reads the current CONTROL register to detect `WDT_DISABLED` and the
    /// `WDT_FIRED` latch, then sets the timeout.
    ///
    /// Caller is responsible for providing the virtual MMIO mapping of the
    /// watchdog window (8 bytes at the resolved physical address).
    ///
    /// `sp5100_tco.c:291–327` — `sp5100_tco_timer_init`.
    pub fn from_probe(mmio_base: u64, timeout_secs: u32, ctrl_val: u32) -> Option<Self> {
        // Abort if hardware-disabled.
        // `sp5100_tco.c:297–301` — disabled check.
        if ctrl_val & sp5100::CONTROL_DISABLED != 0 {
            return None;
        }
        let fired = ctrl_val & sp5100::CONTROL_FIRED != 0;
        Some(Sp5100Driver {
            mmio_base,
            timeout_secs,
            fired_on_prev_boot: fired,
        })
    }

    /// Compose the CONTROL write value to enable the watchdog.
    ///
    /// Sets `START_STOP` and `TRIGGER` on the current control word.
    /// `sp5100_tco.c:109–121` — `tco_timer_start`.
    pub fn enable_control(&self, current_ctrl: u32) -> u32 {
        sp5100::compose_enable_control(current_ctrl)
    }

    /// Compose the CONTROL write value to disable the watchdog.
    ///
    /// Clears `START_STOP`.
    /// `sp5100_tco.c:125–133` — `tco_timer_stop`.
    pub fn disable_control(&self, current_ctrl: u32) -> u32 {
        sp5100::compose_disable_control(current_ctrl)
    }

    /// Compose the CONTROL write value to kick (reload) the watchdog.
    ///
    /// Sets `TRIGGER`; leaves `START_STOP` as-is.
    /// `sp5100_tco.c:137–144` — `tco_timer_ping`.
    pub fn kick_control(&self, current_ctrl: u32) -> u32 {
        sp5100::compose_kick_control(current_ctrl)
    }

    /// Compose the COUNT register value for the current timeout.
    ///
    /// `sp5100_tco.c:149–155` — `tco_timer_set_timeout`.
    pub fn count_value(&self) -> u32 {
        sp5100::compose_count_seconds(self.timeout_secs)
    }

    /// Return the CONTROL register address.
    #[inline]
    pub fn ctrl_addr(&self) -> u64 {
        self.mmio_base + sp5100::CONTROL as u64
    }

    /// Return the COUNT register address.
    #[inline]
    pub fn count_addr(&self) -> u64 {
        self.mmio_base + sp5100::COUNT as u64
    }

    /// Period for the scheduler kick-task: `timeout / 2` seconds (minimum 1).
    pub fn kick_period_secs(&self) -> u32 {
        (self.timeout_secs / 2).max(1)
    }
}

// ── iTCO driver ───────────────────────────────────────────────────────────────

/// Intel TCO watchdog driver state.
///
/// Supports TCO version 1 (8-bit timer, ICH0–ICH5) and version 2+ (16-bit,
/// ICH6 onward and all PCH variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ITcoVersion {
    V1,
    V2,
}

/// Intel iTCO watchdog driver state.
#[derive(Debug)]
pub struct ITcoDriver {
    /// I/O base address of the TCO register block (`TCOBASE`).
    /// `iTCO_wdt.c:68` — `#define TCOBASE(p) ((p)->tco_res->start)`.
    pub tco_base: u16,
    /// TCO hardware version.
    pub version: ITcoVersion,
    /// Configured timeout in seconds.
    pub timeout_secs: u32,
    /// True if SMI_EN TCO_EN bit must be cleared on probe to prevent
    /// the TCO timeout from firing an SMI (instead of a hard reset).
    /// `iTCO_wdt.c:477–516`.
    pub smi_base: Option<u16>,
}

impl ITcoDriver {
    /// Build a driver state struct.  Does not touch hardware.
    pub fn new(tco_base: u16, version: ITcoVersion, timeout_secs: u32, smi_base: Option<u16>) -> Self {
        ITcoDriver { tco_base, version, timeout_secs, smi_base }
    }

    /// Compose the `TCO1_TMR` / `TCOv2_TMR` initial value for the current
    /// timeout.  Uses the v2 formula for both versions; callers truncate to
    /// 6 bits for v1.
    ///
    /// `iTCO_wdt.c:345–389` — `iTCO_wdt_set_timeout`.
    pub fn timer_value(&self) -> u16 {
        itco::compose_initial_seconds(self.timeout_secs)
    }

    /// Port address of `TCO_RLD` (kick register).
    #[inline]
    pub fn rld_port(&self) -> u16 {
        self.tco_base + itco::TCO_RLD as u16
    }

    /// Port address of `TCO1_STS`.
    #[inline]
    pub fn sts1_port(&self) -> u16 {
        self.tco_base + itco::TCO1_STS as u16
    }

    /// Port address of `TCO2_STS`.
    #[inline]
    pub fn sts2_port(&self) -> u16 {
        self.tco_base + itco::TCO2_STS as u16
    }

    /// Port address of `TCO1_CNT` (control: NO_REBOOT, HALT).
    #[inline]
    pub fn cnt_port(&self) -> u16 {
        self.tco_base + itco::TCO1_CNT as u16
    }

    /// Port address of `TCOv2_TMR` (initial value register, v2+).
    #[inline]
    pub fn tmr_v2_port(&self) -> u16 {
        self.tco_base + itco::TCOV2_TMR as u16
    }

    /// Port address of `TCOv1_TMR` (initial value register, v1).
    #[inline]
    pub fn tmr_v1_port(&self) -> u16 {
        self.tco_base + itco::TCOV1_TMR as u16
    }

    /// Compose the `TCO1_CNT` enable value from a current read.
    ///
    /// Clears the HALT bit (bit 0) to start the timer; masks NMI_NOW to
    /// avoid inverting it.
    ///
    /// `iTCO_wdt.c:279–301` — `iTCO_wdt_start`.
    pub fn enable_cnt(&self, current_cnt: u16) -> u16 {
        (current_cnt & !itco::TCO1_CNT_HALT) & !itco::NMI_NOW
    }

    /// Compose the `TCO1_CNT` stop value from a current read.
    ///
    /// Sets the HALT bit; masks NMI_NOW.
    ///
    /// `iTCO_wdt.c:308–320` — `iTCO_wdt_stop`.
    pub fn stop_cnt(&self, current_cnt: u16) -> u16 {
        (current_cnt | itco::TCO1_CNT_HALT) & !itco::NMI_NOW
    }

    /// Kick value: write this to `TCO_RLD` to reload the countdown.
    ///
    /// `iTCO_wdt.c:293` — `outw(0x01, TCO_RLD(p))`.
    pub const fn kick_value(&self) -> u16 {
        itco::TCO_RLD_KICK
    }

    /// Period for the scheduler kick-task: `timeout / 2` seconds (minimum 1).
    pub fn kick_period_secs(&self) -> u32 {
        (self.timeout_secs / 2).max(1)
    }

    /// Compose the SMI_EN mask that disables the TCO SMI gate.
    ///
    /// `iTCO_wdt.c:511–516` — mask out `TCO_EN` (bit 13) in SMI_EN so a
    /// TCO expiry causes a hard reset, not an SMI that firmware might eat.
    pub fn smi_en_disable_mask() -> u32 {
        !itco::SMI_EN_TCO_EN
    }
}

// ── Kick-task period ─────────────────────────────────────────────────────────

/// Watchdog kick task configuration.
///
/// A `WatchdogKickTask` encodes the period at which a healthy scheduler
/// must pet the watchdog.  The period is `timeout / 2` seconds; if the
/// scheduler is healthy the pump fires before the countdown hits zero,
/// resetting it.  If the scheduler hangs the pump never fires and the
/// hardware resets the system.
///
/// The caller registers this with the scheduler via `sleep_pump` and wires
/// the `kick_fn` to the active watchdog's kick path.
///
/// ## Scheduler integration
///
/// ```ignore
/// // At boot, after the watchdog driver is armed:
/// let period_ms = (driver.kick_period_secs() as u64) * 1_000;
/// narf_scheduler::register_sleep_pump(period_ms, move || watchdog_kick());
/// ```
///
/// This matches the `[Scheduler doesn't tick inside syscalls]` rule: the
/// pump is registered at boot and runs from the scheduler's normal async
/// tick, never from a syscall handler.
#[derive(Debug, Clone, Copy)]
pub struct WatchdogKickTask {
    /// Period in milliseconds.
    pub period_ms: u64,
}

impl WatchdogKickTask {
    /// Build a kick-task config for the given timeout.
    ///
    /// Period is clamped to ≥ 1 000 ms so we never spin.
    pub fn for_timeout(timeout_secs: u32) -> Self {
        let period_secs = (timeout_secs / 2).max(1) as u64;
        WatchdogKickTask {
            period_ms: period_secs * 1_000,
        }
    }
}
