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
//! ## What stops here
//!
//! The stages past WPR2 (build the GSP-RM image + radix3, run the
//! booter, set up the RPC rings, send SET_SYSTEM_INFO / SET_REGISTRY,
//! drive the CPU sequencer, poll GSP_INIT_DONE) all have their
//! components built ([`crate::gsp_rm`], [`crate::gsp_args`],
//! [`crate::gsp_payload`], [`crate::gsp_boot`], [`crate::gsp`],
//! [`crate::gsp_seq`]) but need one more parsing piece — extracting the
//! `.fwimage` / `.fwsignature` / bootloader ELF sections from the
//! acquired `gsp.bin` — before they can be allocated and wired. The
//! orchestration reports [`BootError::NotImplemented`] at that point.

#![allow(dead_code)]

use alloc::vec::Vec;

use narf_driver_runtime::MmioRegion;

use crate::fwsec::{
    locate_fwsec, patch_frts, patch_signature, run_fwsec_frts, select_signature_index,
    FalconUcodeDescV3, FwsecError, RSA3K_SIG_SIZE,
};
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
    /// A later stage's component exists but is not yet wired.
    NotImplemented(&'static str),
}

impl From<FwsecError> for BootError {
    fn from(e: FwsecError) -> Self {
        BootError::Fwsec(e)
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

/// Run the live GSP boot as far as the built components allow,
/// returning a [`BootReport`].
///
/// `bios_addr` is the VBIOS/VGA-workspace base (`fb_size - 0x100000`
/// absent a display override) — a chip-specific hardware read the
/// caller supplies. `budget` bounds the FWSEC Falcon poll loops.
///
/// # Safety
/// `bar0` is the mapped BAR0 window and the caller owns the GSP + SEC2
/// Falcons exclusively. Cannot run under QEMU.
pub unsafe fn boot_gsp_live(bar0: &MmioRegion, bios_addr: u64, budget: u32) -> BootReport {
    // 1. Read the VBIOS.
    // SAFETY: caller's responsibility.
    let rom = unsafe { read_vbios_rom(bar0, VBIOS_SCAN_LEN) };

    // 2. Locate FWSEC + parse its descriptor.
    let loc = match locate_fwsec(&rom) {
        Ok(l) => l,
        Err(e) => return BootReport::stop(BootStage::VbiosRead, e.into()),
    };
    let desc = match FalconUcodeDescV3::parse(&rom[loc.desc_offset..]) {
        Ok(d) => d,
        Err(e) => return BootReport::stop(BootStage::VbiosRead, e.into()),
    };

    // 3. Copy the ucode and patch the FRTS command + signature.
    let mut ucode = rom[loc.ucode_offset..loc.ucode_offset + loc.ucode_len].to_vec();
    let frts = frts_region(bios_addr);
    if let Err(e) = patch_frts(&mut ucode, &desc, frts.addr, frts.size) {
        return BootReport::stop(BootStage::FwsecLocated, e.into());
    }
    // Turing fuse version is 0 (no fuse read) -> signature index 0.
    let idx = match select_signature_index(desc.signature_versions, 0) {
        Ok(i) => i,
        Err(e) => return BootReport::stop(BootStage::FwsecLocated, e.into()),
    };
    let sig = match rom.get(signature_range(loc.sig_offset, idx)) {
        Some(s) => s,
        None => {
            return BootReport::stop(
                BootStage::FwsecLocated,
                FwsecError::OutOfBounds("vbios_sig").into(),
            )
        }
    };
    if let Err(e) = patch_signature(&mut ucode, &desc, sig) {
        return BootReport::stop(BootStage::FwsecLocated, e.into());
    }

    // 4. Run FWSEC to carve WPR2 (the gating hardware step).
    // SAFETY: caller owns the GSP Falcon + BAR0.
    if let Err(e) = unsafe { run_fwsec_frts(bar0, &ucode, &desc, budget) } {
        return BootReport::stop(BootStage::FwsecPatched, e.into());
    }

    // 5. WPR2 is up. The remaining stages (GSP-RM image + radix3,
    //    booter, rings, handshake, sequencer, INIT_DONE) have their
    //    components built but need the gsp.bin ELF section extraction
    //    to allocate and wire — the next lane.
    BootReport::stop(
        BootStage::Wpr2Established,
        BootError::NotImplemented(
            "GSP-RM ELF section extraction (.fwimage/.fwsignature/bootloader)",
        ),
    )
}
