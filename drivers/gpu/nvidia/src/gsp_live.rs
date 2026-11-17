//! GSP live boot orchestration — the single runnable entry point.
//!
//! Chains the pieces built across the GSP lanes into one sequence and
//! reports — via [`BootReport`] — the furthest [`BootStage`] reached,
//! so a failure during bring-up pinpoints the step that stopped.
//!
//! ## Two entry points
//!
//! - [`boot_gsp_live`] — the FWSEC → WPR2 path alone (needs only BAR0
//!   + `bios_addr`).
//! - [`boot_gsp_full`] — the **complete** boot to `GSP_INIT_DONE`:
//!   FWSEC → WPR2, build the GSP-RM image + radix3 + WprMeta
//!   ([`crate::gsp_image`]), set up the RPC rings + rmargs/libos
//!   ([`crate::gsp_ring`]), run the booter on SEC2 ([`crate::gsp_boot`]),
//!   wait for the GSP RISC-V core, then send SET_SYSTEM_INFO +
//!   SET_REGISTRY and drain the CPU sequencer until GSP_INIT_DONE. It
//!   returns the [`GspLive`] the caller must keep alive.
//!
//! The [`BootStage`] report pinpoints where the boot stops; the
//! RPC-ring cross-wiring + handshake ordering are the parts most worth
//! confirming against silicon.

#![allow(dead_code)]

use alloc::vec::Vec;

use narf_driver_runtime::MmioRegion;

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FALCON_BASE_GSP, FALCON_BASE_SEC2, FALCON_MAILBOX0, FALCON_MAILBOX1};
use crate::fwsec::{
    locate_fwsec, patch_frts, patch_signature, run_fwsec_frts, select_signature_index,
    FalconUcodeDescV3, FwsecError, RSA3K_SIG_SIZE,
};
use crate::gsp_boot::{booter_sections, load_booter, run_booter, wait_riscv_active};
use crate::gsp_image::{build_gsp_image, GspImage, ImageError};
use crate::gsp_ring::{system_info_payload, GspRings, RingError};
use crate::gsp_rm::{align_down, FbRegion};

/// GSP Falcon OS register (`app_version` goes here before RISC-V start).
const FLCN_OS: u64 = 0x080;

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
    /// The RPC ring handshake / CPU sequencer failed.
    Ring(RingError),
    /// A later stage's component exists but is not yet wired.
    NotImplemented(&'static str),
}

impl From<RingError> for BootError {
    fn from(e: RingError) -> Self {
        BootError::Ring(e)
    }
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
/// Falcons exclusively.
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
    /// BAR0/BAR1/BAR2 physical bases (for `GspSystemInfo`).
    pub bar0_phys: u64,
    pub bar1_phys: u64,
    pub bar2_phys: u64,
    /// PCI bus + devfn (`nvDomainBusDeviceFunc`).
    pub pci_bus: u8,
    pub pci_devfn: u8,
    /// Kernel user-VA limit (`maxUserVa`).
    pub max_user_va: u64,
}

/// The live GSP state the caller must keep alive for the card's
/// lifetime: the RM image buffers + the RPC rings (the GPU DMAs from
/// both continuously).
#[derive(Debug)]
pub struct GspLive {
    pub image: GspImage,
    pub rings: GspRings,
}

/// Run the complete live GSP boot to `GSP_INIT_DONE`, returning the
/// [`BootReport`] and — once allocated — the [`GspLive`] the caller
/// must keep alive (the GPU DMAs from it for its whole lifetime).
///
/// Sequence, grounded in `tu102_gsp_{oneinit,init}` + `r535_gsp_init`:
/// FWSEC → WPR2; build the GSP-RM image + radix3 + WprMeta; set up the
/// RPC rings + rmargs/libos; write the libOS address to the GSP
/// mailboxes; stage + run the booter on SEC2; write `app_version` and
/// wait for the GSP RISC-V core; then run the handshake — send
/// SET_SYSTEM_INFO + SET_REGISTRY and drain the msgq (running the CPU
/// sequencer) until GSP_INIT_DONE.
///
/// The exact ordering of the handshake vs. the sequencer events is the
/// part most worth confirming against silicon (hence the
/// [`BootStage`] report).
///
/// # Safety
/// `bar0` is the mapped BAR0 window and the caller owns the GSP + SEC2
/// Falcons exclusively.
pub unsafe fn boot_gsp_full(
    bar0: &MmioRegion,
    inputs: &GspBootInputs,
    budget: u32,
) -> (BootReport, Option<GspLive>) {
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

    // Set up the RPC rings + rmargs/libos.
    let mut rings = match GspRings::init() {
        Ok(r) => r,
        Err(e) => return (BootReport::stop(BootStage::GspImageBuilt, e.into()), None),
    };
    let live = |image, rings| GspLive { image, rings };

    // Hand the libOS args address to the GSP via its mailboxes before
    // the booter releases the RISC-V core.
    let gsp = Falcon::new(bar0, FALCON_BASE_GSP, "gsp");
    // SAFETY: caller owns the GSP Falcon.
    unsafe {
        gsp.wr32(FALCON_MAILBOX0, rings.libos_dma as u32);
        gsp.wr32(FALCON_MAILBOX1, (rings.libos_dma >> 32) as u32);
    }

    // Stage + run the booter on SEC2; it copies the RM image into WPR2.
    let sec2 = Falcon::new(bar0, FALCON_BASE_SEC2, "sec2");
    let load = match booter_sections(inputs.booter_load, &image.booter) {
        Ok(l) => l,
        Err(_) => {
            return (
                BootReport::stop(BootStage::GspImageBuilt, ImageError::BadBooter.into()),
                Some(live(image, rings)),
            )
        }
    };
    // SAFETY: caller owns the SEC2 Falcon.
    if let Err(e) = unsafe { load_booter(&sec2, &load) } {
        return (
            BootReport::stop(BootStage::GspImageBuilt, e.into()),
            Some(live(image, rings)),
        );
    }
    // SAFETY: SEC2 is staged; the WprMeta phys is live DMA memory.
    if let Err(e) = unsafe { run_booter(&sec2, image.bootvec, image.wpr_meta_phys, budget) } {
        return (
            BootReport::stop(BootStage::GspImageBuilt, e.into()),
            Some(live(image, rings)),
        );
    }

    // app_version → GSP OS register, then wait for the RISC-V core.
    // SAFETY: caller owns the GSP Falcon.
    unsafe { gsp.wr32(FLCN_OS, image.app_version) };
    // SAFETY: BAR0 window; the GSP RISC-V status is a plain read.
    if let Err(e) = unsafe { wait_riscv_active(bar0, budget) } {
        return (
            BootReport::stop(BootStage::BooterRun, e.into()),
            Some(live(image, rings)),
        );
    }

    // Handshake: SET_SYSTEM_INFO + SET_REGISTRY, then drain the CPU
    // sequencer until GSP_INIT_DONE.
    let sysinfo = system_info_payload(
        inputs.bar0_phys,
        inputs.bar1_phys,
        inputs.bar2_phys,
        inputs.pci_bus,
        inputs.pci_devfn,
        inputs.max_user_va,
    );
    // SAFETY: GSP is up; caller owns the Falcons + BAR0.
    let result = unsafe { rings.run_handshake(bar0, &sysinfo, image.app_version, budget) };
    match result {
        Ok(()) => (
            BootReport {
                reached: BootStage::InitDone,
                result: Ok(()),
            },
            Some(live(image, rings)),
        ),
        Err(e) => (
            BootReport::stop(BootStage::HandshakeSent, e.into()),
            Some(live(image, rings)),
        ),
    }
}
