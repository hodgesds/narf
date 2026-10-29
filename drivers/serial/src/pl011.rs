//! ARM PrimeCell UART (PL011) driver — devicetree-bound.
//!
//! The first DT-native device driver in the tree (DT programme
//! step 4, issue #1048): the driver registers a `DtMatch` for
//! `arm,pl011`, and `probe_all` hands it the enumerated
//! `BusKind::Platform` record — reg window and GIC-resolved IRQ
//! come from the device tree, not from a hardcoded constant. The
//! probe maps the window, programs the UART, and publishes the
//! port in the serial registry as `ttyAMA0`.
//!
//! The early console (`narf_console`) drives the same UART from
//! boot; the two coexist the way Linux's console and `amba-pl011`
//! do — the console owns the device until the driver binds, and
//! both program the same 115200 8N1 line format here, so the
//! takeover re-init below is a register-identical reprogram on
//! QEMU `virt`.
//!
//! Clock: divisors are computed for a 24 MHz UARTCLK. On QEMU
//! `virt` that is the fixed `/apb-pclk` the node's `clocks`
//! property references; resolving the referenced clock (and its
//! rate) from the tree is the clock framework's work (issue
//! #1052), at which point the constant becomes a lookup.
//!
//! IRQ: the record's INTID is published in the registry entry.
//! RX is polled (as the console backend is); IRQ-driven RX into
//! the TTY layer is a follow-on, not part of the binding proof.
//!
//! References: ARM PrimeCell UART (PL011) Technical Reference
//! Manual (DDI 0183); `linux/drivers/tty/serial/amba-pl011.c`.

extern crate alloc;

use core::fmt::Write;
use narf_bus::{BusDevice, BusKind, DtMatch, ProbeError};
use narf_capabilities::{Cap, Write as CapWrite};
use narf_console::Writer;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::{ioremap, IoMapping, MmioAttrs};
use narf_memory::PhysAddr;

use crate::registry;

// PL011 register offsets (DDI 0183 §3.2).
const DR: u64 = 0x000;
const FR: u64 = 0x018;
const IBRD: u64 = 0x024;
const FBRD: u64 = 0x028;
const LCR_H: u64 = 0x02C;
const CR: u64 = 0x030;
const ICR: u64 = 0x044;

const FR_TXFE: u32 = 1 << 7;
const FR_TXFF: u32 = 1 << 5;
const FR_RXFE: u32 = 1 << 4;
const FR_BUSY: u32 = 1 << 3;

const CR_UARTEN: u32 = 1 << 0;
const CR_LBE: u32 = 1 << 7;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

const LCR_H_FEN: u32 = 1 << 4;
const LCR_H_WLEN_8: u32 = 0b11 << 5;

/// UARTCLK the divisors are computed against (see module docs).
const UARTCLK_HZ: u32 = 24_000_000;
/// Line format this driver programs: 115200 8N1.
pub const DEFAULT_BAUD: u32 = 115_200;

/// A bound PL011 port: the mapped register block plus the
/// DT-described identity (physical base, resolved IRQ).
#[derive(Debug)]
pub struct Pl011 {
    mapping: IoMapping,
    base: PhysAddr,
    irq: Option<u32>,
}

/// Outcome of the PL011 register-level config proof (the QEMU
/// smoke's UART-health check). It proves the mapped window is
/// the live, correctly programmed device without asserting RX
/// loopback, which QEMU 8.2's `virt` model does not deliver
/// (see [`LoopbackOutcome`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigOutcome {
    Pass,
    /// CR.LBE did not stick when read back (CR value shown).
    LbeNotSet(u32),
    /// The UART was not fully enabled at selftest time
    /// (UARTEN|TXE|RXE bits missing; CR value shown).
    NotEnabled(u32),
    /// Line control is not the programmed FEN|WLEN_8
    /// (LCR_H value shown).
    BadLineControl(u32),
    /// Pattern bytes were accepted but the TX FIFO never
    /// drained within the poll budget.
    TxStuck,
}

/// Outcome of the PL011 loopback self-test, with the failure
/// mode named. The CI log's single "mismatch" string could not
/// distinguish an empty RX FIFO from a wrong byte.
/// NOTE on QEMU: measured on QEMU 8.2 `virt`, the model does
/// NOT deliver loopback bytes to RX — the driver programs the
/// UART exactly per DDI 0183 (UARTEN|TXE|RXE, LBE stuck, FIFOs
/// on) and the pattern bytes still reach the backend console,
/// but RX stays empty across the full poll budget, under every
/// guest-side precondition tried (FIFOs on/off, LBE set before
/// or after UARTEN, RX interrupt masked in). The earlier claim
/// that the model loops back synchronously at DR-write time
/// does not hold for this model version. This self-test is
/// therefore hardware validation; the QEMU smoke gates on the
/// register-level config proof instead (see
/// [`Pl011::config_selftest_diag`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackOutcome {
    Pass,
    /// CR.LBE did not stick when read back (CR value shown).
    LbeNotSet(u32),
    /// No byte arrived within the poll budget at this pattern
    /// position.
    RxEmpty(usize),
    /// Wrong byte at this pattern position.
    WrongByte {
        position: usize,
        want: u8,
        got: u8,
    },
}

impl Pl011 {
    /// Map the register window described by the device record.
    ///
    /// # Safety
    /// `base`/`len` must name this device's real MMIO window (the
    /// enumerator took them from the machine's device tree) and
    /// the caller must hold the device exclusively — `probe_all`'s
    /// cap-mint is that exclusivity.
    unsafe fn new(base: PhysAddr, len: u64, irq: Option<u32>) -> Result<Self, ProbeError> {
        // SAFETY: caller-asserted device window (see above).
        let mapping = unsafe { ioremap(base.raw(), len, MmioAttrs::Device) }
            .map_err(|_| ProbeError::Other("pl011: ioremap of the DT reg window failed"))?;
        Ok(Self { mapping, base, irq })
    }

    fn read(&self, off: u64) -> u32 {
        // SAFETY: `off` is a PL011 register offset inside the
        // mapped window (all call sites use the constants above).
        unsafe {
            (self.mapping.va() as *const u32)
                .byte_add(off as usize)
                .read_volatile()
        }
    }

    fn write(&self, off: u64, val: u32) {
        // SAFETY: same window contract as `read`.
        unsafe {
            (self.mapping.va() as *mut u32)
                .byte_add(off as usize)
                .write_volatile(val)
        }
    }

    /// Program the UART to `baud` 8N1 with FIFOs on: disable,
    /// clear stale interrupt status, divisors, line control,
    /// enable. Runs the full sequence even when the console has
    /// already programmed the same format (identical values on
    /// QEMU `virt`), so the driver owns the programming path on
    /// boards whose firmware never touched the UART.
    pub fn init(&mut self, baud: u32) {
        let denom = 16 * baud;
        let ibrd = UARTCLK_HZ / denom;
        let rem = UARTCLK_HZ % denom;
        // Fractional divisor, rounded to the nearest 1/64.
        let fbrd = (rem * 64 + denom / 2) / denom;
        self.write(CR, 0);
        self.write(ICR, 0x7FF);
        self.write(IBRD, ibrd);
        self.write(FBRD, fbrd);
        self.write(LCR_H, LCR_H_FEN | LCR_H_WLEN_8);
        self.write(CR, CR_UARTEN | CR_TXE | CR_RXE);
    }

    /// Blocking single-byte TX (polled on the TX FIFO flag, the
    /// console backend's pattern).
    pub fn write_byte(&self, byte: u8) {
        while self.read(FR) & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        self.write(DR, byte as u32);
    }

    /// Non-blocking single-byte RX; `None` when the RX FIFO is
    /// empty.
    pub fn try_read_byte(&self) -> Option<u8> {
        if self.read(FR) & FR_RXFE != 0 {
            return None;
        }
        Some(self.read(DR) as u8)
    }

    /// Hardware loopback round-trip (CR.LBE): the TX path drives
    /// the RX path internally. Proves the mapped window is the
    /// live device. HARDWARE ONLY: QEMU 8.2's `virt` model does
    /// not deliver loopback bytes to RX (measured; see the
    /// [`LoopbackOutcome`] note), so this fails on QEMU runs
    /// even with a correct driver — the QEMU smoke gates on
    /// [`Self::config_selftest_diag`] instead. Pattern bytes on
    /// the console are the TX half escaping to the backend, not
    /// a failure sign on their own.
    ///
    /// Failure modes are named, not collapsed into one
    /// "mismatch": the loopback bit is verified stuck via a CR
    /// read-back; the transmitter-drain wait is advisory only
    /// (FR.BUSY's model semantics are not the real-hardware
    /// bit-time contract — a BUSY wait that never clears must
    /// never skip the read-back, as the old code did); the
    /// read-back poll budget is generous so host-scheduling
    /// delays in the model cannot masquerade as a device
    /// failure.
    pub fn loopback_selftest_diag(&mut self) -> LoopbackOutcome {
        while self.try_read_byte().is_some() {} // drain stale RX
        let cr = self.read(CR);
        self.write(CR, cr | CR_LBE);
        // Verify the loopback bit actually stuck: a CR write
        // that does not land must fail loudly here, not as a
        // downstream "mismatch".
        let cr_after = self.read(CR);
        if cr_after & CR_LBE == 0 {
            self.write(CR, cr);
            return LoopbackOutcome::LbeNotSet(cr_after);
        }
        const PATTERN: [u8; 3] = [0xA5, 0x3C, 0x55];
        for &b in &PATTERN {
            self.write_byte(b);
        }
        // Advisory drain wait only — never gates the read-back.
        for _ in 0..10_000_000 {
            if self.read(FR) & FR_BUSY == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        let mut outcome = LoopbackOutcome::Pass;
        for (i, &want) in PATTERN.iter().enumerate() {
            let mut got = None;
            for _ in 0..10_000_000 {
                if let Some(b) = self.try_read_byte() {
                    got = Some(b);
                    break;
                }
                core::hint::spin_loop();
            }
            match got {
                None => {
                    outcome = LoopbackOutcome::RxEmpty(i);
                    break;
                }
                Some(b) if b != want => {
                    outcome = LoopbackOutcome::WrongByte {
                        position: i,
                        want,
                        got: b,
                    };
                    break;
                }
                _ => {}
            }
        }
        self.write(CR, cr & !CR_LBE);
        while self.try_read_byte().is_some() {} // drain any residue
        outcome
    }

    /// Boolean form of [`Self::loopback_selftest_diag`].
    pub fn loopback_selftest(&mut self) -> bool {
        self.loopback_selftest_diag() == LoopbackOutcome::Pass
    }

    /// Register-level config proof for model runs: the mapped
    /// window returns the programmed line/control state, LBE
    /// sticks, and TX drains. Does NOT assert RX loopback (see
    /// [`LoopbackOutcome`]): QEMU 8.2's `virt` model never
    /// delivers loopback bytes to RX, so gating the QEMU smoke
    /// on loopback would fail a correct driver. The pattern
    /// bytes still reach the backend console, which is the
    /// TX half of the proof; RX loopback stays hardware-only
    /// validation via [`Self::loopback_selftest_diag`].
    pub fn config_selftest_diag(&mut self) -> ConfigOutcome {
        while self.try_read_byte().is_some() {} // drain stale RX
        let cr = self.read(CR);
        if cr & (CR_UARTEN | CR_TXE | CR_RXE) != (CR_UARTEN | CR_TXE | CR_RXE) {
            return ConfigOutcome::NotEnabled(cr);
        }
        let lcr = self.read(LCR_H);
        if lcr & (LCR_H_FEN | LCR_H_WLEN_8) != (LCR_H_FEN | LCR_H_WLEN_8) {
            return ConfigOutcome::BadLineControl(lcr);
        }
        self.write(CR, cr | CR_LBE);
        // Verify the loopback bit actually stuck: a CR write
        // that does not land must fail loudly here, not as a
        // downstream "mismatch".
        let cr_after = self.read(CR);
        if cr_after & CR_LBE == 0 {
            self.write(CR, cr);
            return ConfigOutcome::LbeNotSet(cr_after);
        }
        const PATTERN: [u8; 3] = [0xA5, 0x3C, 0x55];
        for &b in &PATTERN {
            self.write_byte(b);
        }
        // TX-drain proof: the pattern bytes must leave the TX
        // FIFO within the budget. On QEMU this is immediate
        // (synchronous TX to the backend); on hardware it takes
        // ~3 byte times at the programmed baud.
        let mut drained = false;
        for _ in 0..10_000_000 {
            if self.read(FR) & FR_TXFE != 0 {
                drained = true;
                break;
            }
            core::hint::spin_loop();
        }
        self.write(CR, cr & !CR_LBE);
        while self.try_read_byte().is_some() {} // drain any residue
        if drained {
            ConfigOutcome::Pass
        } else {
            ConfigOutcome::TxStuck
        }
    }
}

/// The bound port, stashed at probe (the `probe_all` pattern —
/// drivers keep their controller in a static).
static BOUND: IrqSafeSpinLock<Option<Pl011>> = IrqSafeSpinLock::new(None);

/// `(physical base, resolved IRQ)` of the bound port, if a PL011
/// has been bound. Test/diagnostic surface.
pub fn bound_port() -> Option<(u64, Option<u32>)> {
    BOUND.lock().as_ref().map(|p| (p.base.raw(), p.irq))
}

/// Run the loopback self-test on the bound port; `None` when no
/// PL011 is bound.
pub fn selftest_loopback() -> Option<bool> {
    BOUND.lock().as_mut().map(|p| p.loopback_selftest())
}

/// Diagnostic form of [`selftest_loopback`]: the failure mode,
/// not just pass/fail.
pub fn selftest_loopback_diag() -> Option<LoopbackOutcome> {
    BOUND.lock().as_mut().map(|p| p.loopback_selftest_diag())
}

/// Register-level config proof on the bound port; `None` when
/// no PL011 is bound.
pub fn selftest_config_diag() -> Option<ConfigOutcome> {
    BOUND.lock().as_mut().map(|p| p.config_selftest_diag())
}

fn probe_pl011(
    device: BusDevice,
    _cap: Cap<narf_bus::BusDeviceCap, CapWrite>,
) -> Result<(), ProbeError> {
    let BusKind::Platform(rec) = device.kind else {
        return Err(ProbeError::NotForThisDriver);
    };
    let Some(win) = rec.reg_windows().first() else {
        return Err(ProbeError::BadDevice);
    };
    let irq = rec.irq_list().first().map(|i| i.intid);
    // SAFETY: the record's window is this machine's DT-described
    // PL011 window and `probe_all` minted us the device cap.
    let mut uart = unsafe { Pl011::new(win.base, win.len, irq)? };
    uart.init(DEFAULT_BAUD);
    registry::register(registry::UartInfo {
        io_base: 0,
        mmio_base: win.base.raw(),
        irq: irq.and_then(|i| u16::try_from(i).ok()),
        name: "ttyAMA0",
        baud: DEFAULT_BAUD,
    });
    let _ = writeln!(
        Writer,
        "  serial: pl011 bound from DT at {:#x} (irq {:?}), published as ttyAMA0",
        win.base.raw(),
        irq
    );
    *BOUND.lock() = Some(uart);
    Ok(())
}

/// Register the PL011 DT driver: a `DtMatch` for `arm,pl011`,
/// registered when the serial crate's Stage::Subsys initcall runs
/// so Stage::Device's `probe_all` can bind against it.
///
/// (The pre-step-4 body nested a second `narf_init::register` for
/// a banner closure; `run_stage` snapshots a stage's calls before
/// running them, so that registration could never execute — dead
/// code, removed rather than preserved.)
pub fn register_initcalls() {
    narf_bus::register_dt_driver(DtMatch {
        name: "pl011",
        compatible: "arm,pl011",
        probe: probe_pl011,
    });
    let _ = writeln!(
        Writer,
        "  serial: ARM PrimeCell PL011 UART driver registered (DT match arm,pl011)"
    );
}
