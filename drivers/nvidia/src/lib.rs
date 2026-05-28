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

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod bar;
pub mod ce;
pub mod chip;
pub mod disp;
pub mod dp;
pub mod falcon;
pub mod fb;
pub mod fifo;
pub mod gr;
pub mod gsp;
pub mod hpd;
pub mod mc;
pub mod mmu;
pub mod pci;
pub mod pmu;
pub mod vbios;

mod tests;

/// Initcall registration. Stage::Subsys — runs alongside other
/// PCI-driver subsys initcalls so the bus scan finds us.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "nvidia-pci", || {
        pci::register_pci_driver();
        InitResult::Ok
    });
}
