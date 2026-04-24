//! narf-drivers-nvme — NVMe host driver skeleton.
//!
//! Spec: `drivers/nvme/specification/spec.md` (Stage-4 primary
//! crate). The real driver needs:
//!
//! - PCIe BAR0 MMIO mapping (Admin Queue Address, Capabilities,
//!   Controller Config, Version registers).
//! - Admin submission + completion queue allocation.
//! - Feature identification (IDENTIFY CONTROLLER, IDENTIFY
//!   NAMESPACE).
//! - I/O submission/completion queue pair per CPU.
//! - MSI-X vector binding.
//!
//! What lands here at this Stage-4 skeleton pass:
//!
//! - `NvmeRegister` offsets + `NvmeCaps` bitfield accessor.
//! - `AdminOpcode` / `IoOpcode` u8 enumerations.
//! - `Controller` type holding the BAR0 base + identified state,
//!   with `probe(cap: &Cap<BusDevice, Write>) -> Result<_, NvmeError>`
//!   that returns `NotImplemented` until the MMIO + DMA plumbing
//!   comes online.
//! - `BlockDevice` impl wired to stubbed futures that return
//!   `DeviceRemoved` — the shape is real, the body lands when
//!   `memory/` MMIO mapping + `io/` IOMMU programming are usable
//!   against real virtio / NVMe hardware under QEMU.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use core::future::Future;

use narf_block::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockRequest,
    CancelResult, LbaRange,
};

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvmeError {
    NotImplemented,
    BadBar,
    UnsupportedVersion,
    ControllerFailed,
}

// ── Register offsets (NVMe base spec §3.1) ──────────────────────────

/// BAR0-relative register offsets. Values are stable per the spec.
#[non_exhaustive]
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvmeRegister {
    Cap    = 0x00,   // Controller Capabilities (64-bit)
    Vs     = 0x08,   // Version
    Intms  = 0x0C,   // Interrupt Mask Set
    Intmc  = 0x10,   // Interrupt Mask Clear
    Cc     = 0x14,   // Controller Config
    Csts   = 0x1C,   // Controller Status
    Aqa    = 0x24,   // Admin Queue Attributes
    Asq    = 0x28,   // Admin Submission Queue Base Address (64-bit)
    Acq    = 0x30,   // Admin Completion Queue Base Address (64-bit)
}

/// Decoded CAP register bitfields.
#[derive(Copy, Clone, Debug)]
pub struct NvmeCaps {
    /// Maximum queue entries supported (CAP.MQES).
    pub mqes:      u16,
    /// Doorbell-stride exponent (CAP.DSTRD).
    pub dstrd:     u8,
    /// Memory-page-size minimum (2^(12+MPSMIN)).
    pub mpsmin:    u8,
    /// Memory-page-size maximum.
    pub mpsmax:    u8,
}

impl NvmeCaps {
    /// Decode a 64-bit CAP register read.
    #[inline]
    pub const fn from_raw(r: u64) -> Self {
        Self {
            mqes:    (r & 0xFFFF) as u16,
            dstrd:   ((r >> 32) & 0xF) as u8,
            mpsmin:  ((r >> 48) & 0xF) as u8,
            mpsmax:  ((r >> 52) & 0xF) as u8,
        }
    }

    /// Required per-queue doorbell stride in bytes: `4 << DSTRD`.
    #[inline]
    pub const fn doorbell_stride(&self) -> u64 { 4u64 << self.dstrd }
}

// ── Opcodes (NVMe base spec §5 Admin + NVM Command Sets) ────────────

#[non_exhaustive]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AdminOpcode {
    DeleteSq            = 0x00,
    CreateSq            = 0x01,
    GetLogPage          = 0x02,
    DeleteCq            = 0x04,
    CreateCq            = 0x05,
    Identify            = 0x06,
    Abort               = 0x08,
    SetFeatures         = 0x09,
    GetFeatures         = 0x0A,
    AsyncEventRequest   = 0x0C,
}

#[non_exhaustive]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoOpcode {
    Flush       = 0x00,
    Write       = 0x01,
    Read        = 0x02,
    WriteZeroes = 0x08,
    DatasetMgmt = 0x09,  // for TRIM
}

// ── Controller ──────────────────────────────────────────────────────

/// NVMe controller handle. Stage-4 stub: holds the BAR0 base and
/// decoded caps, but offers no DMA / queue / doorbell machinery yet.
#[derive(Debug)]
pub struct Controller {
    pub bar0:  u64,
    pub caps:  Option<NvmeCaps>,
}

impl Controller {
    pub const fn new(bar0: u64) -> Self { Self { bar0, caps: None } }

    /// Pretend-probe — structural contract only. Returns
    /// `NotImplemented` because the MMIO read from BAR0 is gated on
    /// `memory/` exposing a volatile-read primitive and `io/`
    /// mapping MMIO into the driver's domain. Stage-4 fills in the
    /// body.
    pub fn probe(
        &mut self,
        _cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Result<(), NvmeError> {
        if self.bar0 == 0 { return Err(NvmeError::BadBar); }
        Err(NvmeError::NotImplemented)
    }
}

/// Stub `BlockDevice` impl. Every op returns `DeviceRemoved` —
/// structurally well-formed, body lands with the MMIO primitive.
#[derive(Debug)]
pub struct NvmeBlockDevice(pub Controller);

impl BlockDevice for NvmeBlockDevice {
    fn logical_block_size(&self)  -> u32 { 512 }
    fn physical_block_size(&self) -> u32 { 4096 }
    fn capacity_blocks(&self)     -> u64 { 0 }
    fn supports(&self, f: BlockFeature) -> bool {
        matches!(f, BlockFeature::Flush | BlockFeature::WriteZeroes
                  | BlockFeature::Discard | BlockFeature::Fua)
    }

    fn submit(&self, req: BlockRequest)
        -> impl Future<Output = BlockCompletion>
    {
        async move {
            BlockCompletion {
                tag:      0,
                user_tag: req.user_tag,
                result:   Err(BlockError::DeviceRemoved),
            }
        }
    }
    fn flush(&self)                    -> impl Future<Output = ()> { async {} }
    fn discard(&self, _r: LbaRange)    -> impl Future<Output = ()> { async {} }
    fn cancel(&self, _tag: u64)        -> impl Future<Output = CancelResult> {
        async { CancelResult::NotFound }
    }
}
