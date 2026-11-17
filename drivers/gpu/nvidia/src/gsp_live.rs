//! GSP live boot orchestration — the single runnable entry point.
//!
//! Chains the pieces built across the GSP lanes into one sequence a
//! Turing card can actually run, and reports — via [`BootReport`] — the
//! furthest [`BootStage`] reached so a bring-up tester can see exactly
//! where a real GPU stops. QEMU cannot exercise any of the hardware
//! steps (no NVIDIA GPU); this is the tester's path.
//!
//! ## What runs today
//!
//! The **VBIOS → FWSEC → WPR2** path is wired end to end and is the
//! gating hardware step (and the one most likely to surface a problem
//! on real silicon): read the VBIOS, [`locate_fwsec`], patch the FRTS
//! command + signature, [`run_fwsec_frts`], and confirm WPR2 is
//! established. Everything needed for it — [`crate::fwsec`] — is built
//! and the pure parts are tested.
//!
//! ## Two entry points
//!
//! - [`boot_gsp_live`] — the FWSEC → WPR2 path alone (needs only BAR0
//!   + `bios_addr`).
//! - [`boot_gsp_full`] — FWSEC → WPR2, then build the GSP-RM image +
//!   radix3 + WprMeta ([`crate::gsp_image`]), stage + run the booter on
//!   SEC2 ([`crate::gsp_boot`]), and wait for the GSP RISC-V core to go
//!   active. It returns the [`GspImage`] the caller must keep alive.
//!
//! `boot_gsp_full` stops at [`BootStage::BooterRun`]: the RPC-ring
//! handshake (SET_SYSTEM_INFO / SET_REGISTRY), the CPU sequencer loop,
//! and the GSP_INIT_DONE poll are the hardware-in-the-loop remainder —
//! all their components are built ([`crate::gsp`], [`crate::gsp_seq`],
//! [`crate::gsp_args`], [`crate::gsp_payload`]) but wiring the ring
//! receive loop is best iterated against a real card.

#![allow(dead_code)]

use alloc::vec::Vec;

use narf_driver_runtime::MmioRegion;

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FALCON_BASE_SEC2};
use crate::fwsec::{
    locate_fwsec, patch_frts, patch_signature, run_fwsec_frts, select_signature_index,
    FalconUcodeDescV3, FwsecError, RSA3K_SIG_SIZE,
};
use crate::gsp_boot::{booter_sections, load_booter, run_booter, wait_riscv_active};
use crate::gsp_image::{build_gsp_image, GspImage, ImageError};
use crate::gsp_rm::{align_down, FbRegion};

/// BAR0 offset of the VBIOS expansion ROM window. Cite nova-core
/// `vbios.rs` `ROM_OFFSET`.
pub const VBIOS_ROM_OFFSET: u64 = 0x0030_0000;
/// Default VBIOS scan length (1 MiB). Cite `BIOS_MAX_SCAN_LEN`.
pub const VBIOS_SCAN_LEN: usize = 0x0010_0000;
/// FWSEC-FRTS region size (fixed 1 MiB). Cite `tu102_gsp_oneinit`.
pub const FRTS_SIZE: u64 = 0x0010_0000;

/// Milestones of the live GSP boot, in order.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootStage {
    /// Nothing done yet.
    Start,
    /// VBIOS image read from the ROM window.
    VbiosRead,
    /// FWSEC ucode located + descriptor parsed.
    FwsecLocated,
    /// FRTS command + signature patched into the ucode.
    FwsecPatched,
    /// FWSEC ran and WPR2 is established.
    Wpr2Established,
    // ── remaining stages (components built; need ELF extraction) ──
    /// GSP-RM ELF image + radix3 built in DMA memory.
    GspImageBuilt,
    /// Booter ran; GSP RISC-V core active.
    BooterRun,
    /// RPC rings up; SET_SYSTEM_INFO + SET_REGISTRY sent.
    HandshakeSent,
    /// CPU sequencer drained; GSP_INIT_DONE received.
    InitDone,
}

/// Why the boot stopped.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootError {
    /// A FWSEC step failed (locate / patch / run).
    Fwsec(FwsecError),
    /// The GSP-RM image build failed (sections / alloc / radix3).
    Image(ImageError),
    /// The booter run / RISC-V bring-up failed.
    Booter(crate::gsp_boot::BootError),
    /// A later stage's component exists but is not yet wired.
    NotImplemented(&'static str),
}

impl From<FwsecError> for BootError {
    fn from(e: FwsecError) -> Self {
        BootError::Fwsec(e)
    }
}

impl From<ImageError> for BootError {
    fn from(e: ImageError) -> Self {
        BootError::Image(e)
    }
}

impl From<crate::gsp_boot::BootError> for BootError {
    fn from(e: crate::gsp_boot::BootError) -> Self {
        BootError::Booter(e)
    }
}

/// The outcome of a live-boot attempt: the furthest stage reached and,
/// if it stopped, why.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BootReport {
    pub reached: BootStage,
    pub result: Result<(), BootError>,
}

impl BootReport {
    const fn stop(reached: BootStage, err: BootError) -> Self {
        Self {
            reached,
            result: Err(err),
        }
    }
}

/// The FWSEC-FRTS framebuffer region, derived from the VBIOS/VGA base.
/// Only `bios_addr` is needed (the full FB layout — which also needs
/// the ELF/bootloader sizes — is not required just to carve WPR2).
/// Cite `tu102_gsp_oneinit`: `frts.addr = ALIGN_DOWN(bios.addr,
/// 0x20000) - 0x100000`.
pub fn frts_region(bios_addr: u64) -> FbRegion {
    FbRegion::new(align_down(bios_addr, 0x2_0000) - FRTS_SIZE, FRTS_SIZE)
}

/// Byte range of signature `idx` within the VBIOS, given the located
/// signature base. Each signature is [`RSA3K_SIG_SIZE`] bytes.
pub fn signature_range(sig_offset: usize, idx: usize) -> core::ops::Range<usize> {
    let start = sig_offset + idx * RSA3K_SIG_SIZE;
    start..start + RSA3K_SIG_SIZE
}

/// Read `len` bytes of the VBIOS from the ROM window at BAR0
/// `VBIOS_ROM_OFFSET`, as little-endian 32-bit reads.
///
/// # Safety
/// `bar0` is the mapped BAR0 window and the ROM window is readable
/// (the caller has enabled the ROM shadow if the chip requires it).
pub unsafe fn read_vbios_rom(bar0: &MmioRegion, len: usize) -> Vec<u8> {
    let mut rom = Vec::with_capacity(len);
    let words = len / 4;
    for i in 0..words {
        // SAFETY: caller's responsibility; offset within BAR0.
        let w = unsafe { bar0.read32(VBIOS_ROM_OFFSET + (i as u64) * 4) };
        rom.extend_from_slice(&w.to_le_bytes());
    }
    rom
}

/// Read the VBIOS, locate + patch FWSEC, and run it to carve WPR2.
/// On failure returns the stage reached and the error.
///
/// # Safety
/// `bar0` is the mapped BAR0 window and the caller owns the GSP Falcon.
unsafe fn fwsec_to_wpr2(
    bar0: &MmioRegion,
    bios_addr: u64,
    budget: u32,
) -> Result<(), (BootStage, BootError)> {
    // SAFETY: caller's responsibility.
    let rom = unsafe { read_vbios_rom(bar0, VBIOS_SCAN_LEN) };
    let loc = locate_fwsec(&rom).map_err(|e| (BootStage::VbiosRead, e.into()))?;
    let desc = FalconUcodeDescV3::parse(&rom[loc.desc_offset..])
        .map_err(|e| (BootStage::VbiosRead, e.into()))?;

    let mut ucode = rom[loc.ucode_offset..loc.ucode_offset + loc.ucode_len].to_vec();
    let frts = frts_region(bios_addr);
    patch_frts(&mut ucode, &desc, frts.addr, frts.size)
        .map_err(|e| (BootStage::FwsecLocated, e.into()))?;
    // Turing fuse version is 0 (no fuse read) -> signature index 0.
    let idx = select_signature_index(desc.signature_versions, 0)
        .map_err(|e| (BootStage::FwsecLocated, e.into()))?;
    let sig = rom.get(signature_range(loc.sig_offset, idx)).ok_or((
        BootStage::FwsecLocated,
        FwsecError::OutOfBounds("vbios_sig").into(),
    ))?;
    patch_signature(&mut ucode, &desc, sig).map_err(|e| (BootStage::FwsecLocated, e.into()))?;

    // SAFETY: caller owns the GSP Falcon + BAR0.
    unsafe { run_fwsec_frts(bar0, &ucode, &desc, budget) }
        .map_err(|e| (BootStage::FwsecPatched, e.into()))?;
    Ok(())
}

/// Run the VBIOS → FWSEC → WPR2 path and stop (the gating hardware
/// step). For the full boot use [`boot_gsp_full`].
///
/// `bios_addr` is the VBIOS/VGA-workspace base (`fb_size - 0x100000`
/// absent a display override) — a chip-specific hardware read the
/// caller supplies. `budget` bounds the FWSEC Falcon poll loops.
///
/// # Safety
/// `bar0` is the mapped BAR0 window and the caller owns the GSP + SEC2
/// Falcons exclusively. Cannot run under QEMU.
pub unsafe fn boot_gsp_live(bar0: &MmioRegion, bios_addr: u64, budget: u32) -> BootReport {
    // SAFETY: caller's responsibility.
    match unsafe { fwsec_to_wpr2(bar0, bios_addr, budget) } {
        Ok(()) => BootReport::stop(
            BootStage::Wpr2Established,
            BootError::NotImplemented(
                "GSP-RM image build needs the firmware blobs (boot_gsp_full)",
            ),
        ),
        Err((reached, err)) => BootReport {
            reached,
            result: Err(err),
        },
    }
}

/// Everything [`boot_gsp_full`] needs beyond the BAR0 window: the three
/// firmware blobs (acquired via [`crate::gsp_fw`]), the chip identity,
/// and the chip-specific hardware reads.
#[derive(Clone, Copy, Debug)]
pub struct GspBootInputs<'a> {
    /// `gsp.bin` — the GSP-RM image ELF.
    pub gsp_rm: &'a [u8],
    /// `bootloader-*.bin` — the RISC-V bootloader container.
    pub bootloader: &'a [u8],
    /// `booter_load-*.bin` — the HS booter.
    pub booter_load: &'a [u8],
    pub family: ChipFamily,
    pub asic: &'static str,
    /// VRAM size (`nvkm_fb_vidmem_size`).
    pub fb_size: u64,
    /// VBIOS / VGA-workspace base.
    pub bios_addr: u64,
    /// WPR heap size (`tu102_gsp_wpr_heap_size`).
    pub wpr_heap_size: u64,
}

/// Run the live GSP boot through booter + RISC-V bring-up, returning
/// the [`BootReport`] and — if it got far enough to allocate — the
/// [`GspImage`] the caller must keep alive (the GPU DMAs from it for
/// its whole lifetime).
///
/// Sequence: FWSEC → WPR2, then build the GSP-RM image + radix3 +
/// WprMeta ([`build_gsp_image`]), stage + run the booter on SEC2
/// ([`crate::gsp_boot`]), and wait for the GSP RISC-V core to go
/// active. It stops at [`BootStage::BooterRun`] with
/// [`BootError::NotImplemented`] for the RPC-ring handshake + CPU
/// sequencer loop — the part that benefits from hardware-in-the-loop
/// iteration (its components, [`crate::gsp`] + [`crate::gsp_seq`] +
/// [`crate::gsp_args`] + [`crate::gsp_payload`], are all built).
///
/// # Safety
/// `bar0` is the mapped BAR0 window and the caller owns the GSP + SEC2
/// Falcons exclusively. Cannot run under QEMU.
pub unsafe fn boot_gsp_full(
    bar0: &MmioRegion,
    inputs: &GspBootInputs,
    budget: u32,
) -> (BootReport, Option<GspImage>) {
    // SAFETY: caller's responsibility.
    if let Err((reached, err)) = unsafe { fwsec_to_wpr2(bar0, inputs.bios_addr, budget) } {
        return (
            BootReport {
                reached,
                result: Err(err),
            },
            None,
        );
    }

    // Build the GSP-RM image + radix3 + WprMeta in DMA memory.
    let image = match build_gsp_image(
        inputs.gsp_rm,
        inputs.bootloader,
        inputs.booter_load,
        inputs.family,
        inputs.asic,
        inputs.fb_size,
        inputs.bios_addr,
        inputs.wpr_heap_size,
    ) {
        Ok(i) => i,
        Err(e) => return (BootReport::stop(BootStage::Wpr2Established, e.into()), None),
    };

    // Stage + run the booter on SEC2; it copies the RM image into WPR2.
    let load = match booter_sections(inputs.booter_load, &image.booter) {
        Ok(l) => l,
        Err(_) => {
            return (
                BootReport::stop(BootStage::GspImageBuilt, ImageError::BadBooter.into()),
                Some(image),
            )
        }
    };
    let sec2 = Falcon::new(bar0, FALCON_BASE_SEC2, "sec2");
    // SAFETY: caller owns the SEC2 Falcon.
    if let Err(e) = unsafe { load_booter(&sec2, &load) } {
        return (
            BootReport::stop(BootStage::GspImageBuilt, e.into()),
            Some(image),
        );
    }
    // SAFETY: SEC2 is staged; the WprMeta phys is live DMA memory.
    if let Err(e) = unsafe { run_booter(&sec2, image.bootvec, image.wpr_meta_phys, budget) } {
        return (
            BootReport::stop(BootStage::GspImageBuilt, e.into()),
            Some(image),
        );
    }
    // SAFETY: BAR0 window; the GSP RISC-V status is a plain read.
    if let Err(e) = unsafe { wait_riscv_active(bar0, budget) } {
        return (
            BootReport::stop(BootStage::GspImageBuilt, e.into()),
            Some(image),
        );
    }

    // RISC-V is active. The RPC-ring handshake (SET_SYSTEM_INFO /
    // SET_REGISTRY), the CPU sequencer loop, and the GSP_INIT_DONE poll
    // are the hardware-in-the-loop remainder.
    (
        BootReport::stop(
            BootStage::BooterRun,
            BootError::NotImplemented("RPC ring handshake + CPU sequencer + GSP_INIT_DONE"),
        ),
        Some(image),
    )
}
