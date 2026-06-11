//! aarch64 GICv3 ITS — Interrupt Translation Service.
//!
//! Spec: `arch/specification/irq-cache-numa.md` §3.
//!
//! v0.1 surfaces the register layout, caps decode, and
//! enable / disable. Command-queue submission (MAPI / MAPC /
//! INV / SYNC) lands when `interrupts/` grows an LPI router.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

pub const GITS_CTLR: usize = 0x0000;
pub const GITS_IIDR: usize = 0x0004;
pub const GITS_TYPER: usize = 0x0008;
pub const GITS_CBASER: usize = 0x0080;
pub const GITS_CWRITER: usize = 0x0088;
pub const GITS_CREADR: usize = 0x0090;
pub const GITS_BASER0: usize = 0x0100;

pub const CTLR_ENABLE: u32 = 1 << 0;
pub const CTLR_QUIESC: u32 = 1 << 1;
pub const CTLR_READY: u32 = 1 << 31;

#[derive(Copy, Clone, Debug, Default)]
pub struct GitsCaps {
    pub id_bits: u8,
    pub dev_bits: u8,
    pub hcc: u16,
    pub physical: bool,
}

unsafe fn r32(base: usize, off: usize) -> u32 {
    // SAFETY: caller-asserted MMIO mapping covers the offset.
    unsafe { read_volatile((base + off) as *const u32) }
}
unsafe fn r64(base: usize, off: usize) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { read_volatile((base + off) as *const u64) }
}
unsafe fn w32(base: usize, off: usize, v: u32) {
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile((base + off) as *mut u32, v);
    }
}
unsafe fn w64(base: usize, off: usize, v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        write_volatile((base + off) as *mut u64, v);
    }
}

/// Decode the read-only TYPER register.
///
/// # Safety
/// `reg_base` is a strong-uncacheable MMIO mapping of a GICv3
/// ITS register block.
pub unsafe fn read_caps(reg_base: usize) -> GitsCaps {
    // SAFETY: caller-asserted.
    let typer = unsafe { r64(reg_base, GITS_TYPER) };
    decode_caps(typer)
}

pub fn decode_caps(typer: u64) -> GitsCaps {
    GitsCaps {
        id_bits: ((typer & 0x1F) + 1) as u8,
        dev_bits: (((typer >> 8) & 0x1F) + 1) as u8,
        hcc: ((typer >> 16) & 0xFFFF) as u16,
        physical: typer & (1 << 32) != 0,
    }
}

/// Set `GITS_CTLR.Enable`.
///
/// # Safety
/// `reg_base` is the engine's MMIO mapping; the command queue
/// has been programmed via `write_cbaser`.
pub unsafe fn enable(reg_base: usize) {
    // SAFETY: caller-asserted MMIO base; read-modify-write of GITS_CTLR.
    let v = unsafe { r32(reg_base, GITS_CTLR) } | CTLR_ENABLE;
    // SAFETY: same caller-asserted MMIO base; writes back GITS_CTLR.Enable.
    unsafe {
        w32(reg_base, GITS_CTLR, v);
    }
}

/// Clear `GITS_CTLR.Enable`.
///
/// # Safety
/// `reg_base` is the engine's MMIO mapping; caller ensures the
/// command queue is quiesced before disabling.
pub unsafe fn disable(reg_base: usize) {
    // SAFETY: caller-asserted MMIO base; read-modify-write of GITS_CTLR.
    let v = unsafe { r32(reg_base, GITS_CTLR) } & !CTLR_ENABLE;
    // SAFETY: same caller-asserted MMIO base.
    unsafe {
        w32(reg_base, GITS_CTLR, v);
    }
}

/// Program the command-queue base register.
///
/// # Safety
/// `reg_base` is the engine's MMIO mapping; `value` packs a
/// page-aligned base + cacheability + size per Arm IHI 0069.
pub unsafe fn write_cbaser(reg_base: usize, value: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        w64(reg_base, GITS_CBASER, value);
    }
}
