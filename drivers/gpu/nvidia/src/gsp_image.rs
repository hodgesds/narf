//! GSP-RM image build — allocate the DMA buffers and lay out the
//! GSP-RM image, RADIX3 page tables, bootloader, signature, and
//! `GspFwWprMeta` that the booter DMAs into WPR2.
//!
//! The allocated buffers must persist for the GSP's lifetime (the GPU
//! DMAs from them continuously after boot), so they are owned by
//! [`GspImage`], which the caller keeps alive. This wires together the
//! tested builders ([`crate::gsp_elf`], [`crate::gsp_rm`],
//! [`crate::gsp_fw`]) onto narf's DMA allocator; it is hardware
//! integration and cannot be exercised under QEMU, but the builders it
//! calls are all unit-tested and its API usage is compile-checked.

#![allow(dead_code)]

use alloc::vec::Vec;

use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;
use narf_memory::{alloc_frame, PhysFrame};

use crate::chip::ChipFamily;
use crate::gsp_elf::{gsp_rm_sections, parse_riscv_desc};
use crate::gsp_fw::{parse_booter, BooterImage};
use crate::gsp_rm::{
    build_radix3, fb_layout, radix3_fits, radix3_lvl2_bytes, WprMeta, WPR_META_SIZE,
};

const GSP_PAGE: usize = 4096;

/// Owns every DMA buffer the GSP references for its lifetime. Dropping
/// it frees the firmware backing out from under a running GSP, so the
/// driver keeps it alive as long as the card is bound.
pub struct GspImage {
    _elf_frames: Vec<PhysFrame>,
    _lvl0: DmaBuffer,
    _lvl1: DmaBuffer,
    _lvl2: DmaBuffer,
    _bootloader: DmaBuffer,
    _signature: DmaBuffer,
    _wpr_meta: DmaBuffer,
    /// Physical address of the `GspFwWprMeta` (goes to SEC2 MAILBOX0/1).
    pub wpr_meta_phys: u64,
    /// GSP-RM `appVersion` (written to the GSP Falcon OS register).
    pub app_version: u32,
    /// The parsed booter image (for staging onto SEC2).
    pub booter: BooterImage,
    /// Booter boot vector (`os_code_offset`).
    pub bootvec: u32,
}

impl core::fmt::Debug for GspImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GspImage")
            .field("wpr_meta_phys", &self.wpr_meta_phys)
            .field("app_version", &self.app_version)
            .field("bootvec", &self.bootvec)
            .field("elf_frames", &self._elf_frames.len())
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImageError {
    /// `.fwimage` / `.fwsignature_*` not found in `gsp.bin`.
    NoSections,
    /// The bootloader blob did not parse.
    BadBootloader,
    /// The booter_load blob did not parse.
    BadBooter,
    /// The GSP-RM image exceeds RADIX3's 1 GiB reach.
    TooLarge,
    /// A DMA allocation failed.
    Alloc,
    /// RADIX3 construction failed (table too small for the image).
    Radix3,
}

/// Build the GSP-RM image + descriptors in DMA memory.
///
/// `gsp_rm` is the `gsp.bin` ELF, `bootloader` the `bootloader-*.bin`
/// blob, `booter_load` the `booter_load-*.bin` blob. `fb_size` /
/// `bios_addr` / `wpr_heap_size` come from hardware reads / the heap
/// formula (chip-specific; supplied by the caller).
#[allow(clippy::too_many_arguments)]
pub fn build_gsp_image(
    gsp_rm: &[u8],
    bootloader: &[u8],
    booter_load: &[u8],
    family: ChipFamily,
    asic: &str,
    fb_size: u64,
    bios_addr: u64,
    wpr_heap_size: u64,
) -> Result<GspImage, ImageError> {
    let sections = gsp_rm_sections(gsp_rm, family, asic).ok_or(ImageError::NoSections)?;
    let riscv = parse_riscv_desc(bootloader).ok_or(ImageError::BadBootloader)?;
    let booter = parse_booter(booter_load).map_err(|_| ImageError::BadBooter)?;

    let elf = sections.fwimage;
    let elf_size = elf.len();
    if !radix3_fits(elf_size as u64) {
        return Err(ImageError::TooLarge);
    }

    // 1. GSP-RM ELF image — one owned frame per page, fwimage copied in.
    let n_pages = elf_size.div_ceil(GSP_PAGE);
    let mut elf_frames = Vec::new();
    let mut elf_phys = Vec::new();
    for i in 0..n_pages {
        let frame = alloc_frame().map_err(|_| ImageError::Alloc)?;
        let pa = frame.start_address();
        let off = i * GSP_PAGE;
        let end = (off + GSP_PAGE).min(elf_size);
        // SAFETY: a freshly allocated frame we exclusively own; the
        // page is identity-mapped in the kernel direct map.
        unsafe {
            let dst = pa.kernel_mut_ptr::<u8>();
            core::ptr::write_bytes(dst, 0, GSP_PAGE);
            core::ptr::copy_nonoverlapping(elf.as_ptr().add(off), dst, end - off);
        }
        elf_phys.push(pa.raw());
        elf_frames.push(frame);
    }

    // 2. RADIX3 tables (lvl0 → lvl1 → lvl2 → image pages).
    let lvl2_bytes = radix3_lvl2_bytes(elf_size as u64) as usize;
    let lvl2 = alloc_coherent(lvl2_bytes, DomainId::DRIVER_0).map_err(|_| ImageError::Alloc)?;
    let lvl1 = alloc_coherent(GSP_PAGE, DomainId::DRIVER_0).map_err(|_| ImageError::Alloc)?;
    let lvl0 = alloc_coherent(GSP_PAGE, DomainId::DRIVER_0).map_err(|_| ImageError::Alloc)?;
    let lvl2_dma = lvl2.dma_addr().raw();
    let lvl2_page_phys: Vec<u64> = (0..lvl2_bytes / GSP_PAGE)
        .map(|i| lvl2_dma + (i * GSP_PAGE) as u64)
        .collect();
    // SAFETY: each buffer is a unique DMA-coherent allocation we own;
    // the u64 views cover exactly the allocation length.
    let built = unsafe {
        let l0 = core::slice::from_raw_parts_mut(lvl0.cpu_mut_ptr::<u64>(), GSP_PAGE / 8);
        let l1 = core::slice::from_raw_parts_mut(lvl1.cpu_mut_ptr::<u64>(), GSP_PAGE / 8);
        let l2 = core::slice::from_raw_parts_mut(lvl2.cpu_mut_ptr::<u64>(), lvl2_bytes / 8);
        build_radix3(
            l0,
            l1,
            l2,
            lvl1.dma_addr().raw(),
            &lvl2_page_phys,
            &elf_phys,
        )
    };
    if !built {
        return Err(ImageError::Radix3);
    }

    // 3. Bootloader payload.
    let bl_src = bootloader
        .get(riscv.ucode_start..riscv.ucode_start + riscv.ucode_len)
        .ok_or(ImageError::BadBootloader)?;
    let mut bootloader_buf =
        alloc_coherent(riscv.ucode_len, DomainId::DRIVER_0).map_err(|_| ImageError::Alloc)?;
    bootloader_buf.as_mut_slice()[..riscv.ucode_len].copy_from_slice(bl_src);

    // 4. Signature.
    let sig = sections.signatures;
    let mut sig_buf =
        alloc_coherent(sig.len(), DomainId::DRIVER_0).map_err(|_| ImageError::Alloc)?;
    sig_buf.as_mut_slice()[..sig.len()].copy_from_slice(sig);

    // 5. FB layout + GspFwWprMeta.
    let fb = fb_layout(
        fb_size,
        bios_addr,
        riscv.ucode_len as u64,
        elf_size as u64,
        wpr_heap_size,
    );
    let meta = WprMeta::from_layout(
        &fb,
        lvl0.dma_addr().raw(),
        bootloader_buf.dma_addr().raw(),
        riscv.ucode_len as u64,
        riscv.code_offset as u64,
        riscv.data_offset as u64,
        riscv.manifest_offset as u64,
        sig_buf.dma_addr().raw(),
        sig.len() as u64,
    );
    let mut wpr_meta =
        alloc_coherent(WPR_META_SIZE, DomainId::DRIVER_0).map_err(|_| ImageError::Alloc)?;
    wpr_meta.as_mut_slice()[..WPR_META_SIZE].copy_from_slice(&meta.to_bytes());
    let wpr_meta_phys = wpr_meta.dma_addr().raw();

    Ok(GspImage {
        _elf_frames: elf_frames,
        _lvl0: lvl0,
        _lvl1: lvl1,
        _lvl2: lvl2,
        _bootloader: bootloader_buf,
        _signature: sig_buf,
        _wpr_meta: wpr_meta,
        wpr_meta_phys,
        app_version: riscv.app_version,
        bootvec: booter.code_offset,
        booter,
    })
}
