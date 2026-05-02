//! narf-drivers-gpu — GPU driver skeleton.
//!
//! Spec: `drivers/gpu/specification/spec.md` (Stage-4 partial per
//! ROADMAP — full driver is a later-stage goal). The real driver
//! model needs:
//!
//! - A display-mode enumerate + set surface (EDID / DisplayPort).
//! - A command-buffer submission path (likely mapping onto the
//!   `abi/` submission ring for cap-gated access).
//! - Shader / compute-kernel upload (OpenCL / Vulkan-SPIRV target).
//! - DRM-style framebuffer pinning against `io/` DMA buffers.
//!
//! What lands at this skeleton pass:
//!
//! - `GpuFamily` enum of the Stage-4 target backends.
//! - `Mode` + `ModeList` for display-mode enumeration.
//! - `SubmitKind` + `CommandBuffer` request shapes for the GPU
//!   submission path.
//! - `GpuFence` for command-buffer completion tracking.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::vec::Vec;

/// GPU backends the Stage-4 driver set targets. Focus is on
/// virtualised + software-rasteriser paths first; real hardware
/// requires display-output + IOMMU coordination that lands later.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpuFamily {
    /// virtio-gpu — test-rig + VM-in-a-VM target.
    VirtioGpu,
    /// Simple framebuffer from UEFI / bootloader.
    Simplefb,
    /// Intel integrated GPUs (gen8+ / Skylake+).
    IntelI915,
    /// AMD GCN / RDNA (amdgpu).
    Amdgpu,
    /// Nvidia (nouveau or proprietary, via the command-stream
    /// interface).
    Nvidia,
}

/// Display mode descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mode {
    pub width:       u32,
    pub height:      u32,
    pub refresh_hz:  u16,
    pub bpp:         u8,
}

impl Mode {
    /// A common default for tests — 1920×1080 at 60 Hz, 32 bpp.
    pub const FHD_60: Mode = Mode {
        width: 1920, height: 1080, refresh_hz: 60, bpp: 32,
    };
    /// VM console default — 1024×768 at 60 Hz.
    pub const XGA_60: Mode = Mode {
        width: 1024, height: 768, refresh_hz: 60, bpp: 32,
    };
}

/// Enumerated modes from a backend.
#[derive(Debug, Default)]
pub struct ModeList { pub modes: Vec<Mode> }

/// Submission type for a GPU command buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubmitKind {
    Gfx,
    Compute,
    Dma,
}

/// Command-buffer handle. Stage-4 skeleton: just the kind + a
/// physical-address tuple; the real shader bytecode + descriptor
/// heap bind-up happens in the per-backend driver.
#[derive(Copy, Clone, Debug)]
pub struct CommandBuffer {
    pub kind:      SubmitKind,
    pub phys_addr: u64,
    pub byte_len:  u64,
}

/// Completion fence. The GPU bumps `seq` when the command buffer
/// retires; consumers poll or wait on it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GpuFence {
    pub id:  u64,
    pub seq: u64,
}

/// Errors from the GPU surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpuError {
    NotImplemented,
    InvalidMode,
    InvalidSubmission,
}

pub mod amdgpu;
pub mod amdgpu_atombios;
pub mod amdgpu_atom_dcn;
pub mod amdgpu_atom_displayobj;
pub mod amdgpu_atom_fwinfo;
pub mod amdgpu_offsets;
pub mod amdgpu_pm4;
pub mod amdgpu_pptable;
pub mod amdgpu_pptable_subtables;
pub mod amdgpu_ring;
pub mod amdgpu_rlc;
pub mod amdgpu_ucode;
pub mod dp_aux;
pub mod dp_edid;
pub mod dp_link_training;

mod tests;

/// Stage::Subsys initcalls — register every GPU driver with the
/// bus match table.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "amdgpu-pci", || {
        amdgpu::register_pci_driver();
        InitResult::Ok
    });
}
