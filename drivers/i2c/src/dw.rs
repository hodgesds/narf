//! DesignWare APB I2C register-access seam, shared by the two
//! DW-core drivers in this crate (AMD FCH `amd_fch` and Intel LPSS
//! `lpss`).
//!
//! Both drivers were written against `narf_arch::mmio` directly,
//! which left the transfer state machines impossible to fixture:
//! the existing smokes back MMIO with a flat array, and a flat array
//! has no FIFO — a `IC_DATA_CMD` write overwrites the previous one,
//! `IC_STATUS` never evolves, and no transfer loop ever runs (#1029).
//!
//! `DwRegs` is the same seam shape the tree already uses for this
//! (`CrbRegs` in drivers/platform, `AhciRegs` in drivers/storage,
//! `CcpMmio` in drivers/crypto): production constructs the drivers
//! with [`MmioDwRegs`] and the monomorphised code is identical to
//! the previous direct calls; fixtures plug a behavioural register
//! model (`crate::dw_model`, kernel-test only) that implements FIFO
//! fill/drain, `IC_STATUS` evolution, TX_ABRT raising, and a virtual
//! target device on the other end of the bus.

use narf_memory::PhysAddr;

/// Register-level access to one DW I2C controller window.
///
/// Implementors must tolerate the drivers' access pattern: bursts of
/// `IC_DATA_CMD` writes interleaved with `IC_STATUS` /
/// `IC_RAW_INTR_STAT` / `IC_RXFLR` polls, all from a single logical
/// thread of execution at a time (the owning driver serialises
/// transfers with its bus mutex; probe/enable run serially before
/// registration).
pub trait DwRegs: Send + Sync + core::fmt::Debug {
    /// Read the 32-bit register at byte offset `off`.
    ///
    /// # Safety
    /// Same contract as `narf_arch::mmio::read32`: `off` must be a
    /// naturally-aligned register offset inside the controller
    /// window the implementor was constructed over, and the window
    /// must tolerate the read (including read-to-clear registers).
    unsafe fn read32(&self, off: u64) -> u32;

    /// Write `val` to the 32-bit register at byte offset `off`.
    ///
    /// # Safety
    /// Same contract as `narf_arch::mmio::write32`: `off` must be a
    /// naturally-aligned register offset inside the controller
    /// window the implementor was constructed over.
    unsafe fn write32(&self, off: u64, val: u32);
}

/// Production [`DwRegs`]: real MMIO through `narf_arch::mmio`,
/// behaviour-identical to the drivers' previous open-coded calls.
#[derive(Debug)]
pub struct MmioDwRegs {
    base: u64,
}

impl MmioDwRegs {
    pub fn new(base: PhysAddr) -> Self {
        Self { base: base.raw() }
    }
}

impl DwRegs for MmioDwRegs {
    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        // SAFETY: forwarded — the caller upholds the DwRegs contract
        // (valid offset inside the window this backend was built
        // over, which is the mapping `base` names).
        unsafe { narf_arch::mmio::read32(self.base + off) }
    }

    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        // SAFETY: forwarded — same contract as read32.
        unsafe { narf_arch::mmio::write32(self.base + off, val) }
    }
}
