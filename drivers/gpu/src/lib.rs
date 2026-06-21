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

pub mod amdgpu;
pub mod amdgpu_atom_dcn;
pub mod amdgpu_atom_displayobj;
pub mod amdgpu_atom_encoder_caps;
pub mod amdgpu_atom_fwinfo;
pub mod amdgpu_atom_gpiopin;
pub mod amdgpu_atom_vm;
pub mod amdgpu_atombios;
pub mod amdgpu_backlight;
pub mod amdgpu_compute;
pub mod amdgpu_cp_fw;
pub mod amdgpu_dc;
pub mod amdgpu_dccg;
pub mod amdgpu_dcn;
pub mod amdgpu_ddc;
pub mod amdgpu_discovery;
pub mod amdgpu_dpm;
pub mod amdgpu_gfx;
pub mod amdgpu_gmc;
pub mod amdgpu_hdmi_audio;
pub mod amdgpu_hpd;
pub mod amdgpu_ih;
pub mod amdgpu_mes;
pub mod amdgpu_modeset;
pub mod amdgpu_mst;
pub mod amdgpu_offsets;
pub mod amdgpu_pageflip;
pub mod amdgpu_pcie_recovery;
pub mod amdgpu_pm4;
pub mod amdgpu_pptable;
pub mod amdgpu_pptable_subtables;
pub mod amdgpu_psp;
pub mod amdgpu_reset;
pub mod amdgpu_ring;
pub mod amdgpu_rlc;
pub mod amdgpu_sdma;
pub mod amdgpu_smu;
pub mod amdgpu_smu_v12;
pub mod amdgpu_smu_v13;
pub mod amdgpu_ucode;
pub mod amdgpu_ucode_header;
pub mod amdgpu_video;
pub mod amdgpu_vmhub_regs;
pub mod amdgpu_vmid;
pub mod aspeed;
pub mod atombios;
pub mod backlight;
pub mod dmabuf;
pub mod dp_aux;
pub mod dp_edid;
pub mod dp_link_training;
pub mod drm;
pub mod drm_devfs_bridge;
pub mod drm_fb_hook;
pub mod drm_ioctl_bridge;
pub mod drm_registry;
#[cfg(feature = "linux-compat")]
pub mod drm_sysfs_bridge;
pub mod drm_uapi;
pub mod intel_gpu;
pub mod intel_gpu_aux;
pub mod intel_gpu_ddi;
pub mod intel_gpu_dp_bridge;
pub mod intel_gpu_gmbus;
pub mod intel_gpu_gtt;
pub mod intel_gpu_modeset;
pub mod intel_gpu_pipes;
pub mod intel_gpu_pll;
pub mod intel_gpu_regions;
pub mod nvidia_gpu;
pub mod nvidia_gpu_disp;
pub mod nvidia_gpu_falcon;
pub mod nvidia_gpu_fifo;
pub mod nvidia_gpu_gsp;
pub mod nvidia_gpu_pmc;
pub mod qxl;
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

/// Stage::Subsys initcalls — register every GPU driver with the
/// bus match table. Stage::Late initcalls hook DP Alt Mode →
/// GPU bridges into the usbpd registry so a USB-C port that finishes
/// VESA DP negotiation can hand off to the right display engine.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "amdgpu-pci", || {
        amdgpu::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "aspeed-pci", || {
        aspeed::register_pci_driver();
        InitResult::Ok
    });
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
    narf_init::register(Stage::Late, "intel-gpu-dp-bridge", || {
        intel_gpu_dp_bridge::register_bridge();
        InitResult::Ok
    });
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
        InitResult::Ok
    });
    // DRM sysfs bridge: populate /sys/class/drm/.
    // Linux ref: drm_sysfs.c::dev_show.
    narf_init::register(Stage::Late, "drm-sysfs-bridge", || {
        #[cfg(feature = "linux-compat")]
        drm_sysfs_bridge::populate_drm_class();
        InitResult::Ok
    });
}
