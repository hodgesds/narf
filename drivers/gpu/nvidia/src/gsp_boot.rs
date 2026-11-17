//! GSP boot step 2 — stage the signed HS "booter" ucode and detect
//! WPR2 / RISC-V bring-up (Turing).
//!
//! ## Where this sits
//!
//! [`crate::gsp_fw`] (GSP-1) located and parsed the firmware blobs.
//! This module stages the booter ucode onto its Falcon and defines
//! the completion checks. [`crate::gsp`] (GSP-4) then speaks RPCs to
//! the running GSP-RM. The VRAM image + WPR metadata the booter
//! consumes come from GSP-3 (not yet built); the mailbox address this
//! module writes is that metadata's physical address, passed in by
//! the caller.
//!
//! ## Turing boot sequence (grounded in `/usr/src/linux`)
//!
//! Cite `nvkm/subdev/gsp/tu102.c`, `fwsec.c`, `nvkm/falcon/{v1,gm200}.c`,
//! and the Rust `drivers/gpu/nova-core/gsp/boot.rs`:
//!
//! 1. **FWSEC-FRTS** runs on the **GSP** Falcon (`0x110000`) — carves
//!    the WPR2 region in framebuffer. Afterwards
//!    `NV_PFB_PRI_MMU_WPR2_ADDR_HI` (`0x1FA828`) is non-zero.
//! 2. Host builds `GspFwWprMeta` + the RADIX3 GSP-RM image in VRAM
//!    (GSP-3) and resets the GSP Falcon into RISC-V bootloader mode.
//! 3. **booter_load** (an HS ucode) runs on the **SEC2** Falcon
//!    (`0x840000`) — it reads the `GspFwWprMeta` whose address the
//!    host writes to SEC2 MAILBOX0/1, copies the GSP-RM image into
//!    WPR2, and releases the GSP RISC-V core. `mbox0 == 0` on success.
//! 4. Host polls the GSP RISC-V "active" bit (`0x111240` bit 0).
//!
//! **Turing-specific:** both FWSEC and booter_load load by **PIO**
//! (register writes), and the booter has a **non-secure** IMEM
//! section in addition to the secure one. GA102+ loads by DMA and has
//! no non-secure section — a later lane.
//!
//! ## Scope — what GSP-2 lands
//!
//! The pure, unit-testable logic (section slicing, IMEM tag/pad math
//! in [`crate::falcon`], WPR2 / mailbox / RISC-V-status decode) plus
//! the host staging orchestration. The live run can only be proven on
//! real silicon (QEMU has no NVIDIA GPU) and needs GSP-3's WPR
//! metadata; those steps are `unsafe` and clearly marked.

#![allow(dead_code)]

use narf_driver_runtime::MmioRegion;

use crate::falcon::{Falcon, FalconError, FalconMem, FALCON_MAILBOX0, FALCON_MAILBOX1};
use crate::gsp_fw::BooterImage;

// ── WPR2 framebuffer window registers ────────────────────────────
//
// Cite `nvkm/subdev/gsp/tu102.c` (0x1fa824/0x1fa828) and nova-core
// `regs.rs` `NV_PFB_PRI_MMU_WPR2_ADDR_{LO,HI}` (field `*_val @ 31:4`
// = address bits 12..39; zero means the window is not set).

/// `NV_PFB_PRI_MMU_WPR2_ADDR_LO` — BAR0 offset.
pub const WPR2_ADDR_LO: u64 = 0x001F_A824;
/// `NV_PFB_PRI_MMU_WPR2_ADDR_HI` — BAR0 offset. (GSP-1's `gsp.rs`
/// `WPR2_HI_SCRATCH` names this register; it is the WPR2 bound, not a
/// GC6 scratch.)
pub const WPR2_ADDR_HI: u64 = 0x001F_A828;

/// Decode a `WPR2_ADDR_{LO,HI}` register value to its byte address.
/// The field sits at bits[31:4] and encodes address bits[12:39].
pub const fn wpr2_addr(raw: u32) -> u64 {
    ((raw >> 4) as u64) << 12
}

/// True when the WPR2 window is established (register non-zero).
pub const fn wpr2_set(raw: u32) -> bool {
    raw != 0
}

// ── GSP RISC-V status ────────────────────────────────────────────
//
// Cite `nvkm/falcon/tu102.c::tu102_flcn_riscv_active` — reads
// `falcon->addr2 + 0x240` bit0, with the GSP subdev's
// `falcon.addr = 0x110000`, `addr2 = 0x1000` (tu102.c), i.e. the
// absolute BAR0 offset below.

/// GSP PFALCON2 block base (`0x110000 + 0x1000`).
pub const GSP_FALCON2_BASE: u64 = 0x0011_1000;
/// RISC-V core status register within PFALCON2.
pub const RISCV_STATUS_OFFSET: u64 = 0x0240;
/// Absolute BAR0 offset of the GSP RISC-V core status register.
pub const GSP_RISCV_STATUS: u64 = GSP_FALCON2_BASE + RISCV_STATUS_OFFSET;
/// RISC-V "core active" bit.
pub const RISCV_STATUS_ACTIVE: u32 = 1 << 0;

/// True when the RISC-V-status register value reports the core active.
pub const fn riscv_active(raw: u32) -> bool {
    raw & RISCV_STATUS_ACTIVE != 0
}

// ── Booter section slicing (pure) ────────────────────────────────

/// One contiguous region to stage into a Falcon's IMEM or DMEM.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FalconSection<'a> {
    pub mem: FalconMem,
    /// Bytes to upload (already sliced from the firmware blob).
    pub data: &'a [u8],
    /// Destination offset within the Falcon's IMEM/DMEM.
    pub dst: u32,
    /// Physical-page tag for the first block (IMEM only; `dst >> 8`).
    pub tag: u16,
    /// Whether the IMEM pages are marked SECURE (HS code).
    pub secure: bool,
}

/// The three sections of a Turing booter upload plus its boot vector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BooterLoad<'a> {
    /// Non-secure IMEM (OS code).
    pub ns: FalconSection<'a>,
    /// Secure IMEM (`app[0]`, HS code).
    pub sec: FalconSection<'a>,
    /// DMEM (OS data + signature).
    pub dmem: FalconSection<'a>,
    /// Falcon boot vector = OS code offset.
    pub bootvec: u32,
}

/// Error slicing the booter image.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BooterLayoutError {
    /// A section ran past the end of the firmware blob.
    OutOfBounds(&'static str),
    /// The container declared no secure (`app[0]`) section; a Turing
    /// booter must have one.
    NoSecureSection,
}

/// Compute the IMEM tag (`dst >> 8`) for a section destination.
pub const fn section_tag(dst: u32) -> u16 {
    (dst >> 8) as u16
}

/// Slice the three Turing-booter sections out of the firmware blob,
/// using the parsed [`BooterImage`]. The source layout within the
/// ucode image (`blob[image_offset..]`) is, per
/// `tu102.c::tu102_gsp_booter_ctor`:
///
/// - non-secure code: `image[0 .. code_size]`         → IMEM @ `code_offset`
/// - secure code:     `image[code_size .. +sec_size]` → IMEM @ `sec_offset` (SECURE)
/// - data:            `image[data_offset .. +data_size]` → DMEM @ 0
///
/// and the boot vector is `code_offset`.
pub fn booter_sections<'a>(
    blob: &'a [u8],
    img: &BooterImage,
) -> Result<BooterLoad<'a>, BooterLayoutError> {
    if img.sec_size == 0 {
        return Err(BooterLayoutError::NoSecureSection);
    }
    let base = img.image_offset as usize;
    let ns = slice(blob, base, 0, img.code_size, "ns")?;
    let sec = slice(blob, base, img.code_size, img.sec_size, "sec")?;
    let dmem = slice(blob, base, img.data_offset, img.data_size, "dmem")?;
    Ok(BooterLoad {
        ns: FalconSection {
            mem: FalconMem::Imem,
            data: ns,
            dst: img.code_offset,
            tag: section_tag(img.code_offset),
            secure: false,
        },
        sec: FalconSection {
            mem: FalconMem::Imem,
            data: sec,
            dst: img.sec_offset,
            tag: section_tag(img.sec_offset),
            secure: true,
        },
        dmem: FalconSection {
            mem: FalconMem::Dmem,
            data: dmem,
            dst: 0,
            tag: 0,
            secure: false,
        },
        bootvec: img.code_offset,
    })
}

/// Borrow `len` bytes at `base + rel` from `blob`, bounds-checked.
fn slice<'a>(
    blob: &'a [u8],
    base: usize,
    rel: u32,
    len: u32,
    tag: &'static str,
) -> Result<&'a [u8], BooterLayoutError> {
    let start = base
        .checked_add(rel as usize)
        .ok_or(BooterLayoutError::OutOfBounds(tag))?;
    let end = start
        .checked_add(len as usize)
        .ok_or(BooterLayoutError::OutOfBounds(tag))?;
    blob.get(start..end)
        .ok_or(BooterLayoutError::OutOfBounds(tag))
}

// ── Host orchestration (hardware; QEMU cannot exercise these) ─────

/// Error running the booter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootError {
    /// Falcon reset/idle/halt timed out.
    Falcon(FalconError),
    /// The booter halted with a non-zero MAILBOX0 status (its error
    /// code).
    BooterFailed(u32),
    /// The GSP RISC-V core did not report active within the budget.
    RiscvInactive,
}

impl From<FalconError> for BootError {
    fn from(e: FalconError) -> Self {
        BootError::Falcon(e)
    }
}

/// Stage the booter ucode into the SEC2 Falcon: reset, wait idle, PIO
/// the non-secure + secure IMEM sections and the DMEM section. Does
/// not start the CPU — see [`run_booter`].
///
/// # Safety
/// `sec2` is the SEC2 Falcon and the caller owns it exclusively.
pub unsafe fn load_booter(sec2: &Falcon, load: &BooterLoad) -> Result<(), BootError> {
    // SAFETY: caller owns SEC2.
    unsafe {
        sec2.reset();
        sec2.wait_idle(10_000)?;
        sec2.load_imem_v1(load.ns.data, load.ns.dst, load.ns.tag, false);
        sec2.load_imem_v1(load.sec.data, load.sec.dst, load.sec.tag, true);
        sec2.load_dmem(load.dmem.data, load.dmem.dst)?;
    }
    Ok(())
}

/// Start the staged booter and wait for it to halt. `wpr_meta_phys`
/// is the physical address of the `GspFwWprMeta` (from GSP-3); the
/// booter reads it from MAILBOX0/1. Returns `Ok` only when the booter
/// halts with MAILBOX0 == 0.
///
/// # Safety
/// `sec2` holds the staged booter ([`load_booter`]) and the caller
/// owns it exclusively.
pub unsafe fn run_booter(
    sec2: &Falcon,
    bootvec: u32,
    wpr_meta_phys: u64,
    max_polls: u32,
) -> Result<(), BootError> {
    // SAFETY: caller owns SEC2 and it is staged.
    unsafe {
        sec2.wr32(FALCON_MAILBOX0, wpr_meta_phys as u32);
        sec2.wr32(FALCON_MAILBOX1, (wpr_meta_phys >> 32) as u32);
        sec2.start(bootvec);
        sec2.wait_halt(max_polls)?;
        let status = sec2.mailbox0();
        if status != 0 {
            return Err(BootError::BooterFailed(status));
        }
    }
    Ok(())
}

/// Read `NV_PFB_PRI_MMU_WPR2_ADDR_HI` and report whether WPR2 is up.
///
/// # Safety
/// `bar0` is the mapped BAR0 register window.
pub unsafe fn wpr2_active(bar0: &MmioRegion) -> bool {
    // SAFETY: WPR2_ADDR_HI is within the 16 MiB BAR0 window.
    wpr2_set(unsafe { bar0.read32(WPR2_ADDR_HI) })
}

/// Poll the GSP RISC-V core-active bit up to `max_polls` times.
///
/// # Safety
/// `bar0` is the mapped BAR0 register window.
pub unsafe fn wait_riscv_active(bar0: &MmioRegion, max_polls: u32) -> Result<(), BootError> {
    for _ in 0..max_polls {
        // SAFETY: GSP_RISCV_STATUS is within the BAR0 window.
        if riscv_active(unsafe { bar0.read32(GSP_RISCV_STATUS) }) {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(BootError::RiscvInactive)
}
