//! The legacy MM_INDEX register port uses aligned BYTE addresses.
//!
//! Driver register IDs remain DWORD offsets, like Linux RREG32/WREG32.
//! The conversion belongs at this hardware boundary, not in every caller.

use core::sync::atomic::{compiler_fence, Ordering};
use narf_driver_runtime::MmioRegion;

const INDEX: u64 = 0;
const DATA: u64 = 4;
/// A valid, aligned register address; selecting it does not access its data.
pub(super) const PROBE_ADDRESS: u32 = super::RCC_CONFIG_MEMSIZE * 4;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ProbeError {
    Unresponsive,
    Mismatch { previous: u32, echo: u32 },
}

trait RegisterIo {
    fn read32(&mut self, offset: u64) -> u32;
    fn write32(&mut self, offset: u64, value: u32);
}

struct Registers<'a>(&'a MmioRegion);

impl RegisterIo for Registers<'_> {
    fn read32(&mut self, offset: u64) -> u32 {
        // SAFETY: public-to-parent entry points require exclusive ownership
        // of a live, >=8-byte BAR5 mapping; offsets are only INDEX or DATA.
        unsafe { self.0.read32(offset) }
    }

    fn write32(&mut self, offset: u64, value: u32) {
        // SAFETY: same mapping/latch ownership contract as read32.
        unsafe { self.0.write32(offset, value) }
    }
}

fn probe_with(io: &mut impl RegisterIo) -> Result<(), ProbeError> {
    let previous = io.read32(INDEX);
    if previous == u32::MAX {
        return Err(ProbeError::Unresponsive);
    }
    io.write32(INDEX, PROBE_ADDRESS);
    compiler_fence(Ordering::SeqCst);
    let echo = io.read32(INDEX);
    io.write32(INDEX, previous);
    if echo != PROBE_ADDRESS {
        return Err(ProbeError::Mismatch { previous, echo });
    }
    Ok(())
}

fn byte_address(dword: u32) -> Option<u32> {
    // Bit 31 switches the port to VRAM access. A register operation must
    // neither wrap its DWORD offset nor accidentally select memory mode.
    dword
        .checked_mul(4)
        .filter(|address| address & (1 << 31) == 0)
}

fn read_with(io: &mut impl RegisterIo, dword: u32) -> u32 {
    let Some(address) = byte_address(dword) else {
        return u32::MAX;
    };
    io.write32(INDEX, address);
    compiler_fence(Ordering::SeqCst);
    io.read32(DATA)
}

fn write_with(io: &mut impl RegisterIo, dword: u32, value: u32) {
    let Some(address) = byte_address(dword) else {
        return;
    };
    io.write32(INDEX, address);
    compiler_fence(Ordering::SeqCst);
    io.write32(DATA, value);
}

/// Probe without reading/writing the selected register or changing its latch.
///
/// # Safety
/// `regs` is a live BAR5 mapping of at least eight bytes. The caller owns the
/// index/data latch exclusively and holds current PCI authority.
pub(super) unsafe fn probe(regs: &MmioRegion) -> Result<(), ProbeError> {
    probe_with(&mut Registers(regs))
}

/// Read a DWORD register ID through the byte-addressed index port.
///
/// # Safety
/// Same mapping, latch ownership and PCI authority contract as `probe`.
pub(super) unsafe fn read(regs: &MmioRegion, dword: u32) -> u32 {
    read_with(&mut Registers(regs), dword)
}

/// Write a DWORD register ID through the byte-addressed index port.
///
/// # Safety
/// Same mapping, latch ownership and PCI authority contract as `probe`.
pub(super) unsafe fn write(regs: &MmioRegion, dword: u32, value: u32) {
    write_with(&mut Registers(regs), dword, value);
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_index_tests.rs"]
mod tests;
