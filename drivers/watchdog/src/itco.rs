//! Intel TCO (iTCO) watchdog driver.
//!
//! The driver programs the TCO register block whose base comes from
//! the ACPI WDDT (`narf_acpi::WddtInfo::base`). It is intentionally
//! narrow: timer programming, pet, halt, and status. It never
//! touches SMI routing, NO_REBOOT, or the SMBus message registers.
//!
//! ## Pinned register map
//!
//! Sources: Intel Core Ultra 200S/200HX SoC I/O Registers (EDC ID
//! 834819, 2025-01-29), SMBus TCO block; Linux
//! `drivers/watchdog/iTCO_wdt.c` + `iTCO_vendor_support.c`
//! (reference implementation). Every offset below is cited to one
//! of those two; nothing is carried over from recollection.
//!
//! | Register | Offset | Width | Pinned fact |
//! |----------|--------|-------|-------------|
//! | TCO_RLD  | +0x00  | u16   | EDC TRLD: bits 9:0 TCORLD. Read returns the
//!   current count; writing any value reloads the timer. |
//! | TCO1_STS | +0x04  | u16   | EDC TSTS1: sticky bits cleared by writing
//!   1 (RW/1C); bit 3 TIMEOUT = SMI caused by the timer reaching 0. |
//! | TCO2_STS | +0x06  | u8    | 8-bit register between the 16-bit STS1 at
//!   +0x04 and CNT1 at +0x08; bit 1 SECOND_TO_STS (ICH9 commit
//!   text: set when TIMEOUT was set and a second timeout occurred
//!   before TCO_RLD was written; with NO_REBOOT clear the platform
//!   reboots after the second timeout). |
//! | TCO1_CNT | +0x08  | u16   | Linux stop path: bit 11 (0x0800)
//!   TCO_TMR_HLT, 1 = timer disabled. |
//! | TCO2_CNT | +0x0a  | u16   | EDC TCTL2: OS_POLICY bits 5:4,
//!   SMB_ALERT_DISABLE bit 3, INTRD_SEL bits 2:1. Documented, not
//!   programmed by this driver. |
//! | TCO_TMR  | +0x12  | u16   | EDC TTMR: bits 9:0 TCOTMR, the value
//!   loaded into the timer each time TCO_RLD is written; values 0
//!   and 1 are ignored; the timer ticks at ~0.6s, giving 1.2–613.8s. |
//!
//! ## Deliberate omissions (see the crate spec §8)
//!
//! - NO_REBOOT: the v6 TCO1_CNT bit position is not pinned to a
//!   citable source, so the driver never reads or writes it and
//!   reports `no_reboot_control: false`. Expiry behaviour on
//!   NO_REBOOT-set firmware therefore follows firmware policy.
//! - SMI_EN / TCO_EN (ACPIBASE + 0x30, bit 13 in Linux vendor
//!   support): BIOS/vendor territory; the driver never touches SMI
//!   routing, so a BIOS that clears the watchdog via SMI keeps
//!   doing so until it hands the timer over.
//! - WDDT `period_us` is ignored: its unit is not pinned, and the
//!   EDC 0.6s tick is the pinned source for the TCO timer. WDDT
//!   counts bound the tick range only when they intersect [2, 1023].

use alloc::sync::Arc;

use crate::class::{WatchdogDevice, WatchdogError, WatchdogStatus};

/// Port-I/O backend for the TCO block. Production uses the x86
/// I/O-port instructions; the fixture implements the documented
/// TCO state machine over a byte array.
pub trait PortIo: Send + Sync + core::fmt::Debug {
    /// Read a byte from an I/O port.
    fn read_u8(&self, port: u16) -> u8;
    /// Write a byte to an I/O port.
    fn write_u8(&self, port: u16, val: u8);
    /// Read a 16-bit word from an I/O port.
    fn read_u16(&self, port: u16) -> u16;
    /// Write a 16-bit word to an I/O port.
    fn write_u16(&self, port: u16, val: u16);
}

/// Production port-I/O backend (x86_64 only).
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone, Debug, Default)]
pub struct RealPortIo;

#[cfg(target_arch = "x86_64")]
impl PortIo for RealPortIo {
    fn read_u8(&self, port: u16) -> u8 {
        // SAFETY: kernel context runs at CPL=0, and `port` is
        // always inside the WDDT-provided TCO block, whose
        // registers tolerate byte reads; the device is exclusively
        // owned by its single ItcoWatchdog, so no conflicting
        // access races this read.
        unsafe { narf_arch::x86_64::io_port::inb(port) }
    }
    fn write_u8(&self, port: u16, val: u8) {
        // SAFETY: same as the read case; the caller owns the
        // port-sequence correctness, and this backend is only
        // driven with the pinned TCO register offsets.
        unsafe { narf_arch::x86_64::io_port::outb(port, val) }
    }
    fn read_u16(&self, port: u16) -> u16 {
        // SAFETY: same as the byte-read case; TCO status/control
        // registers tolerate word reads.
        unsafe { narf_arch::x86_64::io_port::inw(port) }
    }
    fn write_u16(&self, port: u16, val: u16) {
        // SAFETY: same as the byte-write case; the caller owns
        // the port-sequence correctness, and this backend is only
        // driven with the pinned TCO register offsets.
        unsafe { narf_arch::x86_64::io_port::outw(port, val) }
    }
}

/// TCO register offsets within the block (see the module docs).
const TCO_RLD: u16 = 0x00;
const TCO1_STS: u16 = 0x04;
const TCO2_STS: u16 = 0x06;
const TCO1_CNT: u16 = 0x08;
/// Documented for the map; not programmed by this driver.
#[allow(dead_code)]
const TCO2_CNT: u16 = 0x0a;
const TCO_TMR: u16 = 0x12;

/// TCO1_STS bit 3: first-timeout latch (RW/1C).
const STS1_TIMEOUT: u16 = 0x0008;
/// TCO2_STS bit 1: second-timeout latch.
const STS2_SECOND_TO: u8 = 0x02;
/// TCO1_CNT bit 11: 1 = timer halted.
const CNT1_TMR_HLT: u16 = 0x0800;

/// EDC timer bounds: TCOTMR is 10 bits, values 0/1 ignored, so the
/// usable tick range is [2, 1023] at ~0.6s per tick.
const TICK_MIN: u16 = 2;
const TICK_MAX: u16 = 1023;

/// Convert whole seconds to TCO ticks, rounding up (a requested
/// timeout must never be shorter than asked for). Returns `None`
/// when the request is outside the EDC tick range.
fn secs_to_ticks(secs: u32) -> Option<u16> {
    // ticks = ceil(secs / 0.6) = ceil(secs * 5 / 3), in u64 to
    // avoid overflow on large requests.
    let ticks = (secs as u64 * 5).div_ceil(3);
    if ticks < TICK_MIN as u64 || ticks > TICK_MAX as u64 {
        return None;
    }
    Some(ticks as u16)
}

/// Resolve the usable tick range from a WDDT table: the WDDT
/// counts bound the range only when they intersect [2, 1023];
/// otherwise the EDC range stands (this covers absent counts and
/// firmware that fills the fields with a wider domain).
fn tick_range(info: &narf_acpi::WddtInfo) -> (u16, u16) {
    let (min, max) = (info.timer_min_count, info.timer_max_count);
    if max > 0 && max >= min {
        let lo = min.max(TICK_MIN);
        let hi = max.min(TICK_MAX);
        if lo <= hi {
            return (lo, hi);
        }
    }
    (TICK_MIN, TICK_MAX)
}

/// Intel TCO watchdog device over a [`PortIo`] backend.
#[derive(Debug)]
pub struct ItcoWatchdog<P: PortIo> {
    base: u16,
    io: P,
    tick_lo: u16,
    tick_hi: u16,
}

impl<P: PortIo> ItcoWatchdog<P> {
    /// Build a device from a WDDT table + backend. Returns `None`
    /// when the table carries no usable base: a zero base, or a
    /// base outside the 16-bit I/O-port space (the WDDT record
    /// carries no address-space ID, so a large base cannot be a
    /// TCO I/O block and must fail safe rather than be truncated).
    pub fn probe_from_info(info: narf_acpi::WddtInfo, io: P) -> Option<Arc<Self>> {
        if info.base == 0 || info.base > u16::MAX as u64 {
            return None;
        }
        let (tick_lo, tick_hi) = tick_range(&info);
        Some(Arc::new(Self {
            base: info.base as u16,
            io,
            tick_lo,
            tick_hi,
        }))
    }

    /// The TCO block base this device was probed at.
    pub fn base(&self) -> u16 {
        self.base
    }

    /// The usable tick range resolved from the WDDT table.
    pub fn tick_range(&self) -> (u16, u16) {
        (self.tick_lo, self.tick_hi)
    }

    fn read_sts1(&self) -> u16 {
        self.io.read_u16(self.base + TCO1_STS)
    }

    fn read_sts2(&self) -> u8 {
        self.io.read_u8(self.base + TCO2_STS)
    }

    fn read_cnt1(&self) -> u16 {
        self.io.read_u16(self.base + TCO1_CNT)
    }

    /// Clear exactly the TIMEOUT latch (RW/1C: set bits clear,
    /// zero bits leave the register untouched).
    fn clear_timeout(&self) {
        self.io.write_u16(self.base + TCO1_STS, STS1_TIMEOUT);
    }

    /// Program the reload value without touching the halt bit.
    fn program_timer(&self, ticks: u16) {
        self.io.write_u16(self.base + TCO_TMR, ticks);
    }

    /// Clear the halt bit, preserving every other CNT1 bit.
    fn clear_halt(&self) {
        let cnt = self.read_cnt1() & !CNT1_TMR_HLT;
        self.io.write_u16(self.base + TCO1_CNT, cnt);
    }

    /// Set the halt bit, preserving every other CNT1 bit.
    fn set_halt(&self) {
        let cnt = self.read_cnt1() | CNT1_TMR_HLT;
        self.io.write_u16(self.base + TCO1_CNT, cnt);
    }

    /// Reload the timer from the programmed value. Any written
    /// value reloads; 0 is used.
    fn reload(&self) {
        self.io.write_u16(self.base + TCO_RLD, 0);
    }
}

impl<P: PortIo> WatchdogDevice for ItcoWatchdog<P> {
    fn name(&self) -> &str {
        "watchdog0"
    }

    fn set_timeout(&self, secs: u32) -> Result<(), WatchdogError> {
        let ticks = secs_to_ticks(secs).ok_or(WatchdogError::InvalidTimeout)?;
        if ticks < self.tick_lo || ticks > self.tick_hi {
            return Err(WatchdogError::InvalidTimeout);
        }
        // Order matters: clear any latched first-timeout, program
        // the reload value, un-halt, then reload so the countdown
        // starts from the new value immediately.
        self.clear_timeout();
        self.program_timer(ticks);
        self.clear_halt();
        self.reload();
        Ok(())
    }

    fn pet(&self) {
        // Reload first (averts a pending second timeout), then
        // clear a latched first-timeout so the SMI state does not
        // linger after the timer was serviced in time.
        self.reload();
        self.clear_timeout();
    }

    fn stop(&self) {
        self.set_halt();
    }

    fn status(&self) -> WatchdogStatus {
        let sts1 = self.read_sts1();
        let sts2 = self.read_sts2();
        let cnt1 = self.read_cnt1();
        let count = self.io.read_u16(self.base + TCO_RLD) & 0x03ff;
        WatchdogStatus {
            armed: cnt1 & CNT1_TMR_HLT == 0,
            timed_out: sts1 & STS1_TIMEOUT != 0,
            second_timeout: sts2 & STS2_SECOND_TO != 0,
            // ~0.6s per tick, truncated: secs = count * 3 / 5.
            timeleft_secs: (count as u32 * 3) / 5,
            // NO_REBOOT is never touched: its v6 bit position is
            // unpinned, so the driver cannot claim control of it.
            no_reboot_control: false,
        }
    }
}

/// Probe the iTCO device from the boot-parsed WDDT (x86_64 only).
/// Returns `None` when no WDDT was parsed or its base is unusable;
/// probe itself performs no register writes.
#[cfg(target_arch = "x86_64")]
pub fn probe_from_wddt() -> Option<Arc<ItcoWatchdog<RealPortIo>>> {
    let info = narf_acpi::wddt_info()?;
    ItcoWatchdog::probe_from_info(info, RealPortIo)
}
