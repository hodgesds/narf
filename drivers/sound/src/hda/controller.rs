//! HDA controller — PCI probe, BAR map, GCAP / GCTL / INTCTL reset.
//!
//! References:
//! - Intel "High Definition Audio Specification" rev 1.0a, §3.3
//!   (controller register block).
//! - Linux `sound/hda/controllers/intel.c::azx_first_init`,
//!   `azx_init_chip`.
//! - Linux `sound/hda/core/controller.c::azx_reset`.

use core::sync::atomic::{AtomicBool, Ordering};

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::hda::corb::{Corb, CORB_BYTES};
use crate::hda::rirb::{Rirb, RIRB_BYTES};
use crate::hda::streams::{StreamDescriptor, StreamSlot};

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Class triple for an HDA controller: 0x04 / 0x03 / 0x00 (multimedia /
// HD audio / no programming interface). Linux `azx_ids` enumerates
// device-specific quirks; here we list only the families we actually
// target.

/// Class triple `0x040300` = HDA controller. The bus-level
/// `MatchKind::ClassFull` lets a single probe entry catch every
/// HDA-class controller without enumerating PCI IDs first; the probe
/// then opts out (via `ProbeError::NotForThisDriver`) for chips it
/// doesn't recognise.
pub const HDA_CLASS_TRIPLE: u32 = 0x0403_00;

/// AMD vendor ID. Renoir / Lucienne (Zen2) + Phoenix (Zen4) iGPUs
/// expose HDA on the PCH; both use this vendor.
pub const HDA_AMD_VENDOR: u16 = 0x1022;
/// AMD Renoir / Lucienne (Zen2 mobile APUs) HDA controller —
/// the user's first bring-up laptop.
pub const HDA_AMD_RENOIR_VENDOR: u16 = 0x1022;
pub const HDA_AMD_RENOIR_DEVICE: u16 = 0x15E3;
/// AMD Phoenix / HawkPoint (Zen4 mobile APUs) HDA controller —
/// the user's second bring-up laptop.
pub const HDA_AMD_PHOENIX_VENDOR: u16 = 0x1022;
pub const HDA_AMD_PHOENIX_DEVICE: u16 = 0x15E2;
/// AMD Radeon iGPU HD Audio (HDMI/DP audio side). Same programming
/// model.
pub const HDA_AMD_RADEON_DEVICE: u16 = 0x1640;

/// Intel vendor ID. Every PCH HDA / iGPU display-audio controller
/// shares this.
pub const HDA_INTEL_VENDOR: u16 = 0x8086;
// A handful of widely-deployed Intel HDA PCI IDs the controller
// probe explicitly recognises. The class-triple match catches
// everything else.
pub const HDA_INTEL_SUNRISE_LP_A: u16 = 0x9D70;
pub const HDA_INTEL_CANNON_LAKE: u16 = 0xA348;
pub const HDA_INTEL_COMET_LAKE_A: u16 = 0xA171;
pub const HDA_INTEL_TIGER_LAKE_LP: u16 = 0xA0C8;
pub const HDA_INTEL_ALDER_LAKE: u16 = 0x7AD0;
pub const HDA_INTEL_METEOR_LAKE: u16 = 0x7E28;

// ── HDA register block (HDA Spec §3.3) ──────────────────────────────

/// 16-bit Global Capabilities. Encodes:
///   bit 0      64-bit address support
///   bits 3:1   number of serial-data-out signals
///   bits 7:4   number of bidirectional streams
///   bits 11:8  number of input streams (NISS)
///   bits 15:12 number of output streams (NOSS)
pub const REG_GCAP: u64 = 0x00;
pub const REG_VMIN: u64 = 0x02;
pub const REG_VMAJ: u64 = 0x03;
pub const REG_OUTPAY: u64 = 0x04;
pub const REG_INPAY: u64 = 0x06;
pub const REG_GCTL: u64 = 0x08;
pub const REG_WAKEEN: u64 = 0x0C;
pub const REG_STATESTS: u64 = 0x0E;
pub const REG_GSTS: u64 = 0x10;
pub const REG_INTCTL: u64 = 0x20;
pub const REG_INTSTS: u64 = 0x24;
pub const REG_WALCLK: u64 = 0x30;
pub const REG_SSYNC: u64 = 0x38;
// CORB
pub const REG_CORBLBASE: u64 = 0x40;
pub const REG_CORBUBASE: u64 = 0x44;
pub const REG_CORBWP: u64 = 0x48;
pub const REG_CORBRP: u64 = 0x4A;
pub const REG_CORBCTL: u64 = 0x4C;
pub const REG_CORBSTS: u64 = 0x4D;
pub const REG_CORBSIZE: u64 = 0x4E;
// RIRB
pub const REG_RIRBLBASE: u64 = 0x50;
pub const REG_RIRBUBASE: u64 = 0x54;
pub const REG_RIRBWP: u64 = 0x58;
pub const REG_RINTCNT: u64 = 0x5A;
pub const REG_RIRBCTL: u64 = 0x5C;
pub const REG_RIRBSTS: u64 = 0x5D;
pub const REG_RIRBSIZE: u64 = 0x5E;
// Immediate command interface (legacy, optional).
pub const REG_ICOI: u64 = 0x60;
pub const REG_ICII: u64 = 0x64;
pub const REG_ICIS: u64 = 0x68;
// DMA position lower / upper base — for the DMA-pos write-back buffer.
pub const REG_DPLBASE: u64 = 0x70;
pub const REG_DPUBASE: u64 = 0x74;

/// Stream descriptor block starts here. Stream count and direction
/// is encoded in GCAP (NISS / NOSS / NBSS).
pub const REG_STREAM_BASE: u64 = 0x80;
/// Each stream descriptor is 0x20 bytes.
pub const STREAM_DESC_STRIDE: u64 = 0x20;

// GCTL bits.
pub const GCTL_CRST: u32 = 1 << 0;
pub const GCTL_FCNTRL: u32 = 1 << 1;
pub const GCTL_UNSOL: u32 = 1 << 8;

// INTCTL bits.
pub const INTCTL_SIE_MASK: u32 = 0x3FFF_FFFF;
pub const INTCTL_CIE: u32 = 1 << 30;
pub const INTCTL_GIE: u32 = 1 << 31;

// INTSTS bits.
pub const INTSTS_GIS: u32 = 1 << 31;
pub const INTSTS_CIS: u32 = 1 << 30;

// CORBCTL / RIRBCTL bits.
pub const CORBCTL_CMEIE: u8 = 1 << 0;
pub const CORBCTL_RUN: u8 = 1 << 1;
pub const RIRBCTL_RINTCTL: u8 = 1 << 0;
pub const RIRBCTL_RUN: u8 = 1 << 1;
pub const RIRBCTL_OIC: u8 = 1 << 2;

// CORBSIZE / RIRBSIZE encoding: bits[1:0] = 00 (2 entries), 01 (16),
// 10 (256). bits[7:4] = SZCAP (read-only).
pub const CORBSIZE_256: u8 = 0b10;
pub const RIRBSIZE_256: u8 = 0b10;

// ── ProbeError ──────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProbeError {
    /// PCI BAR0 wasn't mapped to MMIO.
    NoBar,
    /// Controller didn't leave reset within the allotted spin count.
    ResetTimeout,
    /// Couldn't allocate the CORB or RIRB ring buffers.
    NoMemory,
    /// CRST self-clear never asserted.
    CrstNotAsserted,
    /// Probe handed off but no codec responded.
    NoCodecOnLink,
    /// Driver does not handle this vendor/device pair.
    NotForThisDriver,
}

// ── Controller state ────────────────────────────────────────────────

/// One probed HDA controller.
#[derive(Debug)]
pub struct HdaController {
    /// Stable index in the controller registry. Card binding uses
    /// this to find the controller again.
    pub index: usize,
    /// PCI BAR0 physical base. Identity-mapped through the kernel
    /// memory map; we hold the value purely for diagnostics.
    pub bar0_phys: u64,
    /// PCI BAR0 size in bytes.
    pub bar0_size: u64,
    /// Decoded capability count: number of output stream descriptors
    /// (GCAP NOSS).
    pub output_streams: u8,
    /// Decoded capability count: number of input stream descriptors
    /// (GCAP NISS).
    pub input_streams: u8,
    /// Bidirectional streams (GCAP NBSS).
    pub bidir_streams: u8,
    /// 64-bit address support (GCAP bit 0).
    pub addr64: bool,
    /// HDA major / minor version (VMAJ / VMIN).
    pub version: (u8, u8),
    /// PCI vendor ID of the controller.
    pub vendor: u16,
    /// PCI device ID of the controller.
    pub device: u16,
    /// CORB ring buffer.
    pub corb: Corb,
    /// RIRB ring buffer.
    pub rirb: Rirb,
    /// Stream descriptor allocation map. `Some(slot)` means in use.
    pub streams: Vec<StreamSlot>,
    /// Bitmap of codec addresses that responded on the link (STATESTS).
    pub codec_mask: u16,
    /// Whether the controller is brought out of reset.
    pub ready: bool,
}

impl HdaController {
    /// Decode GCAP into stream / 64-bit / bidir counts.
    /// HDA §3.3.2.
    pub fn decode_gcap(gcap: u16) -> (u8, u8, u8, bool) {
        let addr64 = (gcap & 0x1) != 0;
        let nbss = ((gcap >> 4) & 0xF) as u8; // bidir
        let niss = ((gcap >> 8) & 0xF) as u8; // input
        let noss = ((gcap >> 12) & 0xF) as u8; // output
        (noss, niss, nbss, addr64)
    }

    /// Total number of stream descriptors = output + input + bidir.
    pub fn total_streams(&self) -> usize {
        (self.output_streams + self.input_streams + self.bidir_streams) as usize
    }

    /// Offset of the i-th output stream descriptor.
    /// Output streams start *after* input streams in the descriptor
    /// block, per HDA §3.3.41.
    pub fn output_stream_offset(&self, i: u8) -> u64 {
        let input_block = self.input_streams as u64 * STREAM_DESC_STRIDE;
        REG_STREAM_BASE + input_block + (i as u64) * STREAM_DESC_STRIDE
    }

    /// Offset of the i-th input stream descriptor.
    pub fn input_stream_offset(&self, i: u8) -> u64 {
        REG_STREAM_BASE + (i as u64) * STREAM_DESC_STRIDE
    }

    /// Allocate one output stream. Returns the slot index in the
    /// `streams` vector, or `None` if all output streams are claimed.
    pub fn claim_output(&mut self) -> Option<usize> {
        for (i, slot) in self.streams.iter_mut().enumerate() {
            if let StreamSlot::FreeOutput = slot {
                *slot = StreamSlot::TakenOutput;
                return Some(i);
            }
        }
        None
    }

    /// Allocate one input stream.
    pub fn claim_input(&mut self) -> Option<usize> {
        for (i, slot) in self.streams.iter_mut().enumerate() {
            if let StreamSlot::FreeInput = slot {
                *slot = StreamSlot::TakenInput;
                return Some(i);
            }
        }
        None
    }

    /// Release a previously-claimed stream.
    pub fn release(&mut self, slot_index: usize) {
        if let Some(slot) = self.streams.get_mut(slot_index) {
            match slot {
                StreamSlot::TakenOutput => *slot = StreamSlot::FreeOutput,
                StreamSlot::TakenInput => *slot = StreamSlot::FreeInput,
                _ => {}
            }
        }
    }

    /// Map a slot index to its stream descriptor.
    pub fn stream_descriptor(&self, slot: usize) -> StreamDescriptor {
        // Input streams come first per HDA §3.3.41.
        let input_count = self.input_streams as usize;
        let is_input = slot < input_count;
        let offset = REG_STREAM_BASE + (slot as u64) * STREAM_DESC_STRIDE;
        StreamDescriptor { offset, is_input }
    }
}

// ── Controller registry ─────────────────────────────────────────────

pub static REGISTRY: IrqSafeSpinLock<Vec<HdaController>> = IrqSafeSpinLock::new(Vec::new());

/// Reset the registry — test-only.
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
    PROBED.store(false, Ordering::SeqCst);
}

/// Probe-once guard. The bus walk may invoke `probe` multiple times
/// for the same device on a re-init; this gate keeps us idempotent.
static PROBED: AtomicBool = AtomicBool::new(false);

/// Reset the controller — drive CRST, wait for self-clear,
/// then leave reset. HDA §4.2.2.
///
/// `read_gctl` / `write_gctl` are passed in so tests can drive the
/// sequence against a synthetic register file. On real HW the bus
/// crate's `bar::read_u32` / `bar::write_u32` are the canonical
/// transports.
pub fn reset_controller(
    mut read_gctl: impl FnMut() -> u32,
    mut write_gctl: impl FnMut(u32),
) -> Result<(), ProbeError> {
    // Step 1: assert CRST = 0 (writing 0 → reset enter).
    write_gctl(0);
    // Step 2: wait for the controller to acknowledge reset (CRST reads back as 0).
    for _ in 0..1024 {
        if (read_gctl() & GCTL_CRST) == 0 {
            break;
        }
    }
    if (read_gctl() & GCTL_CRST) != 0 {
        return Err(ProbeError::ResetTimeout);
    }
    // Step 3: leave reset by writing CRST = 1.
    write_gctl(GCTL_CRST);
    // Step 4: wait for the controller to come back (CRST reads back as 1).
    for _ in 0..1024 {
        if (read_gctl() & GCTL_CRST) != 0 {
            break;
        }
    }
    if (read_gctl() & GCTL_CRST) == 0 {
        return Err(ProbeError::CrstNotAsserted);
    }
    Ok(())
}

/// Initialise interrupt enables and the unsolicited-response gate.
/// Sets GIE + CIE in INTCTL and UNSOL in GCTL.
pub fn enable_irqs(mut read_intctl: impl FnMut() -> u32, mut write_intctl: impl FnMut(u32)) {
    let cur = read_intctl();
    write_intctl(cur | INTCTL_GIE | INTCTL_CIE);
}

/// Validate that a discovered controller is one we can drive.
/// Returns `Ok(true)` for an HDA-class controller from a known
/// vendor/device. Returns `Ok(false)` to skip a class-backstop match
/// the driver doesn't actually want to claim.
pub fn supported_device(vendor: u16, device: u16) -> bool {
    match (vendor, device) {
        (HDA_AMD_RENOIR_VENDOR, HDA_AMD_RENOIR_DEVICE) => true,
        (HDA_AMD_PHOENIX_VENDOR, HDA_AMD_PHOENIX_DEVICE) => true,
        (HDA_AMD_VENDOR, HDA_AMD_RADEON_DEVICE) => true,
        (HDA_INTEL_VENDOR, _) => true,
        _ => false,
    }
}

/// CORB ring buffer size used by this driver. The HDA spec mandates
/// a 1024-byte (256-entry) CORB on chips that advertise SZCAP for
/// 256 entries.
pub const CORB_BUFFER_BYTES: usize = CORB_BYTES;
/// RIRB ring buffer size used by this driver. 2048 bytes (256 × 8).
pub const RIRB_BUFFER_BYTES: usize = RIRB_BYTES;
