//! narf-drivers-nvidia — full NVIDIA GPU driver scaffold.
//!
//! Targets GeForce GTX (Maxwell+) through GeForce RTX (Ada) for
//! discrete and the mobile siblings; Tegra is out of scope.
//!
//! ## Authoritative reference
//!
//! Linux's **Nouveau** driver:
//! `/home/daniel/git/linux/drivers/gpu/drm/nouveau/`.
//!
//! Specifically:
//! - `nouveau_drv.c`, `nouveau_chan.c` — top-level + channel
//!   bring-up.
//! - `nvkm/device/` — per-ASIC dispatch table (Fermi=NVC0,
//!   Kepler=NVE0, Maxwell=NV110, Pascal=NV130, Volta=NV140,
//!   Turing=NV160, Ampere=NV170, Ada=NV190).
//! - `nvkm/falcon/` — Falcon microcontroller framework (used by
//!   PMU, SEC2, GSP, GR-FECS, NVDEC, NVENC).
//! - `nvkm/subdev/{mc,fb,bar,mmu}/` — Master Controller, frame
//!   buffer, BAR window, GPU MMU.
//! - `nvkm/subdev/{pmu,gsp,bios}/` — power management,
//!   GSP runtime, VBIOS table parse.
//! - `nvkm/engine/{fifo,gr,ce}/` — host FIFO, graphics, copy.
//! - `dispnv50/` — Maxwell+ display (CRTC + SOR + DP AUX).
//! - `dispnv04/` — pre-Maxwell display (we don't intend to
//!   support this in narf).
//!
//! NARF licence: GPL-2.0-or-later (`LICENSE`). Nouveau citations
//! are first-class references.

//! ## Dual-build (built-in or loadable `.ko`)
//!
//! `default = builtin` links the full driver into the kernel. The
//! `module` build (`--no-default-features --features module`) drops
//! every kernel crate and the driver body, registering the PCI match
//! through the `narf_register_pci_driver` KSYMTAB export (registration-
//! only, `-ENOSYS` probe until the GPU datapath ABI is exported). See
//! `narf-drivers-net-e1000`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "nvidia",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "NVIDIA GPU driver (Maxwell through Ada Lovelace)",
        target_domain: "graphics",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    pci::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

#[cfg(feature = "builtin")]
pub mod bar;
#[cfg(feature = "builtin")]
pub mod ce;
#[cfg(feature = "builtin")]
pub mod chip;
#[cfg(feature = "builtin")]
pub mod disp;
#[cfg(feature = "builtin")]
pub mod dispc57d;
#[cfg(feature = "builtin")]
pub mod dispc57e;
#[cfg(feature = "builtin")]
pub mod dp;
#[cfg(feature = "builtin")]
pub mod edid_aux;
#[cfg(feature = "builtin")]
pub mod falcon;
#[cfg(feature = "builtin")]
pub mod fb;
#[cfg(feature = "builtin")]
pub mod fence;
#[cfg(feature = "builtin")]
pub mod fifo;
#[cfg(feature = "builtin")]
pub mod flip;
#[cfg(feature = "builtin")]
pub mod fwsec;
#[cfg(feature = "builtin")]
pub mod gr;
#[cfg(feature = "builtin")]
pub mod gsp;
#[cfg(feature = "builtin")]
pub mod gsp_args;
#[cfg(feature = "builtin")]
pub mod gsp_boot;
#[cfg(feature = "builtin")]
pub mod gsp_chan;
#[cfg(feature = "builtin")]
pub mod gsp_disp;
#[cfg(feature = "builtin")]
pub mod gsp_dp;
#[cfg(feature = "builtin")]
pub mod gsp_elf;
#[cfg(feature = "builtin")]
pub mod gsp_fw;
#[cfg(feature = "builtin")]
pub mod gsp_image;
#[cfg(feature = "builtin")]
pub mod gsp_live;
#[cfg(feature = "builtin")]
pub mod gsp_modeset;
#[cfg(feature = "builtin")]
pub mod gsp_payload;
#[cfg(feature = "builtin")]
pub mod gsp_ring;
#[cfg(feature = "builtin")]
pub mod gsp_rm;
#[cfg(feature = "builtin")]
pub mod gsp_rm_api;
#[cfg(feature = "builtin")]
pub mod gsp_seq;
#[cfg(feature = "builtin")]
pub mod gsp_static;
#[cfg(feature = "builtin")]
pub mod hdcp;
#[cfg(feature = "builtin")]
pub mod hpd;
#[cfg(feature = "builtin")]
pub mod irq;
#[cfg(feature = "builtin")]
pub mod kms;
#[cfg(feature = "builtin")]
pub mod mc;
#[cfg(feature = "builtin")]
pub mod mmu;
#[cfg(feature = "builtin")]
pub mod mst;
#[cfg(feature = "builtin")]
pub mod nvdec;
#[cfg(feature = "builtin")]
pub mod nvenc;
#[cfg(feature = "builtin")]
pub mod pb;
#[cfg(feature = "builtin")]
pub mod pci;
#[cfg(feature = "builtin")]
pub mod pcie_recovery;
#[cfg(feature = "builtin")]
pub mod pmu;
#[cfg(feature = "builtin")]
pub mod sec2;
#[cfg(feature = "builtin")]
pub mod vbios;

#[cfg(feature = "kernel-test")]
mod tests;

/// Initcall registration. Stage::Subsys — runs alongside other
/// PCI-driver subsys initcalls so the bus scan finds us.
#[cfg(feature = "builtin")]
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "nvidia-pci", || {
        pci::register_pci_driver();
        InitResult::Ok
    });
}

/// Register the `Stage::Late` GSP firmware acquisition pass (Turing+).
/// Must be called *after* the firmware initramfs/rootfs scans are
/// registered so the registry is populated when the pass runs; see
/// [`gsp_fw::register_gsp_firmware_pass`].
#[cfg(feature = "builtin")]
pub fn register_gsp_firmware_pass() {
    gsp_fw::register_gsp_firmware_pass();
}
