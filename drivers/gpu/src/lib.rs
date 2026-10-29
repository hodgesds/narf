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
    /// ASPEED AST2400/2500 BMC basic display.
    Aspeed,
    /// QXL Virtual GPU.
    Qxl,
    /// VMware SVGA II Virtual GPU.
    VmwareSvga,
}

/// Display mode descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub refresh_hz: u16,
    pub bpp: u8,
}

/// Build the initial DRM view of VirtIO-GPU's boot scanout.
///
/// This is deliberately separate from the transport's boot resource: the
/// latter has been attached to scanout so early console output is visible,
/// but it has no corresponding DRM framebuffer object in this card.  Its
/// scanout is nevertheless already live: KWin validates an unchanged
/// page-flip with no ALLOW_MODESET, and therefore needs to observe an active
/// CRTC.  The compositor still owns the first DRM primary plane.
fn virtio_boot_crtc(mode: Mode) -> drm::card::Crtc {
    drm::card::Crtc {
        id: 1,
        mode: Some(mode),
        // The transport has completed SET_SCANOUT before this card is
        // registered.  This is an active *hardware* CRTC, even though its
        // boot resource is deliberately absent from the DRM FB namespace.
        // Keeping those facts distinct prevents a compositor's no-modeset
        // TEST_ONLY page-flip from becoming a synthetic ACTIVE transition.
        enabled: true,
        primary_fb: None,
        x: 0,
        y: 0,
    }
}

impl Mode {
    /// A common default for tests — 1920×1080 at 60 Hz, 32 bpp.
    pub const FHD_60: Mode = Mode {
        width: 1920,
        height: 1080,
        refresh_hz: 60,
        bpp: 32,
    };
    /// VM console default — 1024×768 at 60 Hz.
    pub const XGA_60: Mode = Mode {
        width: 1024,
        height: 768,
        refresh_hz: 60,
        bpp: 32,
    };
}

/// Enumerated modes from a backend.
#[derive(Debug, Default)]
pub struct ModeList {
    pub modes: Vec<Mode>,
}

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
    pub kind: SubmitKind,
    pub phys_addr: u64,
    pub byte_len: u64,
}

/// Completion fence. The GPU bumps `seq` when the command buffer
/// retires; consumers poll or wait on it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GpuFence {
    pub id: u64,
    pub seq: u64,
}

/// Errors from the GPU surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpuError {
    NotImplemented,
    InvalidMode,
    InvalidSubmission,
}

#[cfg(feature = "amdgpu")]
pub mod amdgpu;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_atom_displayobj;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_atom_encoder_caps;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_atom_fwinfo;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_atom_gpiopin;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_atom_vm;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_atombios;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_backlight;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_bo_list;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_bringup;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_clearstate;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_clearstate_gfx10;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_compute;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_cp_fw;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_panel_backlight;
#[path = "amdgpu_cp_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_cp;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_cp as amdgpu_cp_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_cs;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ctx;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dc;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dccg;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn20_audio;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_audio;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_clk;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_cursor;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_ddc;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_dp;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_dp_link;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_dsc;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_flip;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_hdmi;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_hubbub;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_mst;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_takeover;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn30_watermarks;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_clk;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_dccg;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_dml;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_dscl;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_otg;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_resource;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_spl;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn401_spl_filters;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_clk;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_color;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_dccg;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_display;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_hubp;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_inventory;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_otg;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_plane;
#[cfg(feature = "amdgpu")]
mod amdgpu_dcn_profile;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dcn_stream;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ddc;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ddc_navi48;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dio;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_discovery;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dm_modifiers;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dml;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dml30;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dml_regs;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dmub;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dmub_boot;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dmub_firmware;
#[path = "amdgpu_dmub_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_dmub;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_dmub as amdgpu_dmub_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dmub_navi48;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dp_training;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dp_tunnel;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dpm;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_dsc;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_mst_dsc;
#[path = "amdgpu_fence_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_fence;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_fence as amdgpu_fence_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_freesync;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_frl_cap;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_frl_training;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gddr6;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gem;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx10_topology;
#[cfg(feature = "amdgpu")]
mod amdgpu_gfx12_draw;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx12_queue;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx12_rs64;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx12_setup;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx12_shader;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx12_topology;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gfx_firmware;
#[path = "amdgpu_gfx_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_gfx;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_gfx as amdgpu_gfx_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gmc;
#[path = "amdgpu_gmc_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_gmc;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_gmc as amdgpu_gmc_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_gmc_navi48;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_hdmi_audio;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_hdr;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_hpd;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_hwmon;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ih;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ih7;
#[path = "amdgpu_ih_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_ih;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_ih as amdgpu_ih_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_info;
#[cfg(feature = "amdgpu")]
pub(crate) mod amdgpu_info_stats;
#[path = "amdgpu_info_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_info;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_info as amdgpu_info_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_jpeg_navi48;
#[path = "amdgpu_kiq_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_kiq;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_kiq as amdgpu_kiq_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_mes;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_mes12;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_mes12_hw;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_mes_hw;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_modeset;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_mqd;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_mst;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_native_kms;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_present_damage;
#[path = "amdgpu_navi22_bios.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_bios;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_bios as amdgpu_navi22_bios;
#[path = "amdgpu_navi22_boot.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_boot;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_boot as amdgpu_navi22_boot;
#[path = "amdgpu_navi22_cs.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_cs;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_cs as amdgpu_navi22_cs;
#[path = "amdgpu_navi22_display.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_display;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_display as amdgpu_navi22_display;
#[path = "amdgpu_navi22_gating.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_gating;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_gating as amdgpu_navi22_gating;
#[path = "amdgpu_navi22_gfxoff.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_gfxoff;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_gfxoff as amdgpu_navi22_gfxoff;
#[path = "amdgpu_navi22_kms.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_kms;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_kms as amdgpu_navi22_kms;
#[path = "amdgpu_navi22_modeset.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_modeset;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_modeset as amdgpu_navi22_modeset;
#[cfg(all(feature = "kernel-test", feature = "amdgpu"))]
mod amdgpu_navi22_modeset_model;
#[path = "amdgpu_navi22_platform.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_platform;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_platform as amdgpu_navi22_platform;
#[path = "amdgpu_navi22_power.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_power;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_power as amdgpu_navi22_power;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_power_controls;
#[path = "amdgpu_navi22_power_policy.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_power_policy;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_power_policy as amdgpu_navi22_power_policy;
#[path = "amdgpu_navi22_power_saving.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_power_saving;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_power_saving as amdgpu_navi22_power_saving;
#[path = "amdgpu_navi22_recovery.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_recovery;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_recovery as amdgpu_navi22_recovery;
#[path = "amdgpu_navi22_scanout.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_scanout;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_scanout as amdgpu_navi22_scanout;
#[path = "amdgpu_navi22_submit.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_submit;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_submit as amdgpu_navi22_submit;
#[path = "amdgpu_navi22_tdr.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_tdr;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_tdr as amdgpu_navi22_tdr;
#[path = "amdgpu_navi22_thermal.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_thermal;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_thermal as amdgpu_navi22_thermal;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_boot;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_dispatch;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_display;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_faults;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_firmware;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_interrupts;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_kms;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_msi;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_platform;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_power;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_ras;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_runtime_pm;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_sources;
#[cfg(all(feature = "kernel-test", feature = "amdgpu"))]
mod amdgpu_navi48_tests;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_navi48_ucode;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_offsets;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_pageflip;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_pcie_recovery;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_platform;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_pm4;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_pm4_defs;
#[path = "amdgpu_power_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_board_power;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_board_power as amdgpu_power_navi22;
#[cfg(feature = "amdgpu")]
mod amdgpu_admission;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_psp;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_psp_boot;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_psp_firmware;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_psp_ring;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2;
#[cfg(feature = "amdgpu")]
mod amdgpu_rdna2_mmr;
#[path = "amdgpu_reset_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_reset;
#[cfg(feature = "amdgpu")]
mod amdgpu_rdna2_vram;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna4;
#[cfg(feature = "amdgpu")]
mod amdgpu_reg_window;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_reset;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_reset as amdgpu_reset_navi22;
#[path = "amdgpu_sdma_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_sdma;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ring;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ring_watch;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rlc;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_sdma;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_sdma as amdgpu_sdma_navi22;
#[path = "amdgpu_sdma_navi22_queues.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_sdma_queues;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_sdma_queues as amdgpu_sdma_navi22_queues;
#[path = "amdgpu_smu_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_smu;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_sdma_navi48;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_smc_firmware;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_smu;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_smu as amdgpu_smu_navi22;
#[path = "amdgpu_smu_navi22_telemetry.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_smu_telemetry;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_smu_telemetry as amdgpu_smu_navi22_telemetry;
#[path = "amdgpu_vcn_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_vcn;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_smu_navi48;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_smu_navi48_telemetry;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_smu_v12;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_smu_v13;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_smuio14;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_uapi;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_ucode_header;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_usbc;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_vbios;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_vcn as amdgpu_vcn_navi22;
#[path = "amdgpu_vcn_navi22_cs.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_vcn_cs;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_vcn_cs as amdgpu_vcn_navi22_cs;
#[cfg(feature = "amdgpu")]
mod amdgpu_media_reservation;
#[path = "amdgpu_video_caps_navi22.rs"]
#[cfg(feature = "amdgpu")]
pub mod amdgpu_rdna2_video_caps;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_vcn_navi48;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_video;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_video_caps_navi48;
/// Compatibility alias for the original Navi22 API.
#[cfg(feature = "amdgpu")]
pub use amdgpu_rdna2_video_caps as amdgpu_video_caps_navi22;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_vm;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_vmhub_regs;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_vmid;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_vram;
#[cfg(feature = "amdgpu")]
mod amdgpu_vram_access;
#[cfg(feature = "amdgpu")]
pub mod amdgpu_vram_boot;
pub mod aspeed;
#[cfg(feature = "amdgpu")]
pub mod atombios;
pub mod backlight;
pub mod dmabuf;
pub mod dp_aux;
pub mod dp_edid;
pub mod dp_link_training;
pub mod dp_mst;
pub mod dp_mst_mgr;
pub mod drm;
pub mod drm_devfs_bridge;
pub mod drm_fb_hook;
pub mod drm_ioctl_bridge;
#[cfg(feature = "amdgpu")]
pub mod drm_native_planes;
pub mod drm_registry;
pub mod drm_sysfs_bridge;
pub mod drm_uapi;
#[cfg(feature = "intel")]
pub mod intel_gpu;
#[cfg(feature = "intel")]
pub mod intel_gpu_audio;
#[cfg(feature = "intel")]
pub mod intel_gpu_aux;
#[cfg(feature = "intel")]
pub mod intel_gpu_ddi;
#[cfg(feature = "intel")]
pub mod intel_gpu_dmc;
#[cfg(feature = "intel")]
pub mod intel_gpu_dp;
#[cfg(feature = "intel")]
pub mod intel_gpu_dp_bridge;
#[cfg(feature = "intel")]
pub mod intel_gpu_edp;
#[cfg(feature = "intel")]
pub mod intel_gpu_exec;
#[cfg(feature = "intel")]
pub mod intel_gpu_fence;
#[cfg(feature = "intel")]
pub mod intel_gpu_forcewake;
#[cfg(feature = "intel")]
pub mod intel_gpu_gem;
#[cfg(feature = "intel")]
pub mod intel_gpu_gmbus;
#[cfg(feature = "intel")]
pub mod intel_gpu_gtt;
#[cfg(feature = "intel")]
pub mod intel_gpu_guc;
#[cfg(feature = "intel")]
pub mod intel_gpu_guc_firmware;
#[cfg(feature = "intel")]
pub mod intel_gpu_guc_transport;
#[cfg(feature = "intel")]
pub mod intel_gpu_hdmi;
#[cfg(feature = "intel")]
pub mod intel_gpu_media;
#[cfg(feature = "intel")]
pub mod intel_gpu_modeset;
#[cfg(feature = "intel")]
pub mod intel_gpu_modeset_xelpg;
#[cfg(feature = "intel")]
pub mod intel_gpu_mst;
#[cfg(feature = "intel")]
pub mod intel_gpu_multipipe;
#[cfg(feature = "intel")]
pub mod intel_gpu_pcode;
#[cfg(feature = "intel")]
pub mod intel_gpu_pipes;
#[cfg(feature = "intel")]
pub mod intel_gpu_pll;
#[cfg(feature = "intel")]
pub mod intel_gpu_pm;
#[cfg(feature = "intel")]
pub mod intel_gpu_ppgtt;
#[cfg(feature = "intel")]
pub mod intel_gpu_rc6;
#[cfg(feature = "intel")]
pub mod intel_gpu_rcs;
#[cfg(feature = "intel")]
pub mod intel_gpu_regions;
#[cfg(feature = "intel")]
pub mod intel_gpu_render;
#[cfg(feature = "intel")]
pub mod intel_gpu_uapi;
#[cfg(feature = "intel")]
pub mod intel_gpu_wm;
#[cfg(feature = "intel")]
pub mod intel_gpu_xelpg;
pub mod nvidia_gpu;
pub mod nvidia_gpu_disp;
pub mod nvidia_gpu_falcon;
pub mod nvidia_gpu_fifo;
pub mod nvidia_gpu_gsp;
pub mod nvidia_gpu_pmc;
pub mod qxl;
pub mod scanout_access;
pub mod vmware_svga;

mod tests;

#[cfg(feature = "kernel-test")]
mod e2e_tests;

#[cfg(feature = "kernel-test")]
mod e2e_ring_tests;

#[cfg(feature = "kernel-test")]
mod atomic_e2e_tests;

#[cfg(feature = "kernel-test")]
mod drm_ioctl_smokes;

#[cfg(all(feature = "kernel-test", feature = "amdgpu", target_arch = "x86_64"))]
mod drm_sync_tests;

/// Stage::Subsys initcalls — register every GPU driver with the
/// bus match table. Stage::Late initcalls hook DP Alt Mode →
/// GPU bridges into the usbpd registry so a USB-C port that finishes
/// VESA DP negotiation can hand off to the right display engine.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    #[cfg(feature = "amdgpu")]
    narf_init::register(Stage::Subsys, "amdgpu-pci", || {
        amdgpu::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "aspeed-pci", || {
        aspeed::register_pci_driver();
        InitResult::Ok
    });
    #[cfg(feature = "intel")]
    narf_init::register(Stage::Subsys, "intel-gpu-pci", || {
        intel_gpu::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "nvidia-gpu-pci", || {
        nvidia_gpu::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "qxl-gpu-pci", || {
        qxl::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "vmware-svga-pci", || {
        vmware_svga::register_pci_driver();
        InitResult::Ok
    });
    #[cfg(feature = "intel")]
    narf_init::register(Stage::Late, "intel-gpu-dp-bridge", || {
        intel_gpu_dp_bridge::register_bridge();
        InitResult::Ok
    });
    #[cfg(feature = "amdgpu")]
    narf_init::register(Stage::Late, "amdgpu-usbc", amdgpu_usbc::start);
    narf_init::register(Stage::Device, "gpu-backlight", || {
        backlight::init_backlight_initcall();
        InitResult::Ok
    });
    // bochs DRM card registration. Must run at Late stage: the bochs
    // PCI device isn't probed until the post-Device probe phase, so
    // `is_probed()` is still false at Device stage (the card would
    // silently never register and /dev/dri/card0 would be absent).
    // Registers a BochsCard with the DRM registry so
    // /sys/class/drm/card<N>/ and /dev/dri/card<N> appear.
    // Linux ref: drm_dev_register (drivers/gpu/drm/drm_drv.c).
    narf_init::register(Stage::Late, "virtio-gpu-drm-card", || {
        if let Some(virtio) = narf_drivers_virtio::gpu_pci::probed_device() {
            // Make the actual paravirtual GPU the primary DRM device. This
            // deliberately happens before the bochs fallback below: QEMU's
            // full profile presents both devices, but a VirGL host must not
            // make Mesa select the unrelated bochs render node.
            if virtio.init_scanout().is_err() {
                // A bound GPU that cannot programme scanout is a real boot
                // failure, not an absent optional device.  Surface it in the
                // normal init summary so a black GTK window has a precise
                // cause without retaining a separate diagnostic service.
                return InitResult::Error("virtio-gpu scanout initialisation failed");
            }
            use drm::card::{
                Card, Connector, ConnectorStatus, ConnectorType, Encoder, EncoderType,
            };
            let mode = virtio.mode();
            if mode.width == 0 || mode.height == 0 {
                return InitResult::NotPresent;
            }
            let count = drm_registry::count() as u32;
            let card_name = alloc::format!("card{}", count);
            let card = drm_devfs_bridge::VirtioGpuCard::new(card_name);
            // DRM driver version MUST match Linux's virtio_gpu exactly: major=0,
            // minor=1, patchlevel=0 (drivers/gpu/drm/virtio/virtgpu_drv.h
            // DRIVER_MAJOR/MINOR/PATCHLEVEL). Mesa's virgl DRM winsys gates on
            // version_major == 0; reporting major=1 makes it reject the device as
            // "not a virtio_gpu it understands" and drop to llvmpipe instead of
            // taking the classic-VirGL path.
            let mut kms = Card::new("virtio_gpu", "NARF VirtIO GPU driver", (0, 1, 0));
            kms.crtcs.push(virtio_boot_crtc(Mode {
                width: mode.width,
                height: mode.height,
                refresh_hz: 60,
                bpp: 32,
            }));
            kms.encoders.push(Encoder {
                id: 2,
                encoder_type: EncoderType::Virtual,
                possible_crtcs: 0x1,
                possible_clones: 0,
                crtc_id: Some(1),
            });
            kms.connectors.push(Connector {
                id: 3,
                connector_type: ConnectorType::Virtual,
                connector_type_id: 1,
                status: ConnectorStatus::Connected,
                encoder_id: Some(2),
                modes: alloc::vec![Mode {
                    width: mode.width,
                    height: mode.height,
                    refresh_hz: 60,
                    bpp: 32,
                }],
            });
            let idx = drm_registry::register_drm_card_with_state(alloc::sync::Arc::new(card), kms);
            let _ = idx;
            return InitResult::Ok;
        }
        InitResult::NotPresent
    });
    narf_init::register(Stage::Late, "bochs-drm-card", || {
        if narf_graphics_driver::bochs::is_probed() {
            use drm::card::{
                Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType,
            };
            let count = drm_registry::count() as u32;
            let card_name = alloc::format!("card{}", count);
            let card = drm_devfs_bridge::BochsCard::new(card_name);

            // Build a mode_state Card with 1 CRTC + 1 encoder + 1 connector
            // taken from the bochs scanout geometry.
            let (w, h) = narf_graphics_driver::bochs::with_controller(|d| (d.width, d.height))
                .unwrap_or((1024, 768));

            let mut kms = Card::new("narf-drm", "narf bochs driver", (1, 0, 0));
            kms.crtcs.push(Crtc {
                id: 1,
                mode: Some(Mode {
                    width: w,
                    height: h,
                    refresh_hz: 60,
                    bpp: 32,
                }),
                enabled: true,
                primary_fb: None,
                x: 0,
                y: 0,
            });
            kms.encoders.push(Encoder {
                id: 2,
                encoder_type: EncoderType::Virtual,
                possible_crtcs: 0x1,
                possible_clones: 0,
                crtc_id: Some(1),
            });
            kms.connectors.push(Connector {
                id: 3,
                connector_type: ConnectorType::Virtual,
                connector_type_id: 1,
                status: ConnectorStatus::Connected,
                encoder_id: Some(2),
                modes: alloc::vec![Mode {
                    width: w,
                    height: h,
                    refresh_hz: 60,
                    bpp: 32
                }],
            });

            let idx = drm_registry::register_drm_card(alloc::sync::Arc::new(card));
            drm_registry::attach_mode_state(idx, kms);
        }
        InitResult::Ok
    });
    // DRM devfs bridge: install /dev/dri/ delegate.
    // Linux ref: drm_dev_register (drivers/gpu/drm/drm_drv.c).
    narf_init::register(Stage::Late, "drm-devfs-bridge", || {
        drm_devfs_bridge::install_dri_dir();
        // Let the syscall layer export a GEM handle as a dma-buf fd
        // (DRM_IOCTL_PRIME_HANDLE_TO_FD): Mesa GBM's gbm_bo_get_fd needs it
        // to CPU-mmap the kwin QPainter swapchain buffer.
        narf_filesystem::install_drm_prime_export_hook(drm_devfs_bridge::prime_export_fileops);
        InitResult::Ok
    });
    // DRM sysfs bridge: populate /sys/class/drm/.
    // Linux ref: drm_sysfs.c::dev_show.
    narf_init::register(Stage::Late, "drm-sysfs-bridge", || {
        drm_sysfs_bridge::populate_drm_class();
        InitResult::Ok
    });
}
