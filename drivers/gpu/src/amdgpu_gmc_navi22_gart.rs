//! VMID0 GART: gmc_v10_0_gart_init/gart_enable, amdgpu_gart.c bind/unbind,
//! gfxhub_v2_1/mmhub_v2_0 init_gart_aperture_regs and setup_vmid_config.
//! Like Linux, the 512 MiB table lives in owned VRAM; its entries point at
//! pinned system DMA pages. The first 2 MiB keep the boot `Aperture` pages.
use super::*;
use crate::amdgpu_vm::{with_mtype, MTYPE_UC, PTE_EXECUTABLE, PTE_READABLE, PTE_SNOOPED};
use crate::amdgpu_vm::{PTE_SYSTEM, PTE_VALID, PTE_WRITEABLE};
use alloc::vec::Vec;
use narf_io::DmaBuffer;

/// gmc_v10_0_mc_init default for GC 10.3.2 (`amdgpu_gart_size == -1`).
pub const GART_SIZE: u64 = 512 << 20; // linux: n/a (literal 512ULL << 20 in gmc_v10_0_mc_init)
const PAGES: u64 = GART_SIZE / 4096; // linux: n/a (AMDGPU_GPU_PAGE_SIZE pages)
const TABLE: u64 = PAGES * 8; // linux: n/a (gart.table_size = num_gpu_pages * 8)
/// Shared all-invalid PDB2 for unbound user VMIDs, after the GART table.
const EMPTY_ROOT: u64 = TABLE;
const BOOT_PAGES: u64 = APERTURE_SIZE / 4096; // linux: n/a (NARF boot aperture)
/// gmc_v10_0_sw_init: dma_set_mask_and_coherent(DMA_BIT_MASK(44)).
// linux: n/a (DMA_BIT_MASK(44) literal in gmc_v10_0_sw_init)
pub(super) const DMA_LIMIT: u64 = 1 << 44;
/// AMDGPU_GMC_HOLE_START: Linux caps MC placement below the hole.
// linux: n/a (AMDGPU_GMC_HOLE_START, runtime macro on max_level)
const HOLE_START: u64 = 0x0000_8000_0000_0000;
/// vm_manager.max_pfn for amdgpu_vm_adjust_size(adev, 256 * 1024, 9, 3, 48).
pub(super) const MAX_PFN: u64 = 1 << 36; // linux: n/a (amdgpu_vm_adjust_size 48-bit max_pfn)
/// CONTEXT1_CNTL fields setup_vmid_config sets plus the seven interrupt
/// enables of `vm_cntx_cntl_vm_fault`; RETRY_OTHER_FAULT is left as read.
// linux: GCVM_CONTEXT1_CNTL__ENABLE_CONTEXT_MASK | GCVM_CONTEXT1_CNTL__PAGE_TABLE_DEPTH_MASK | GCVM_CONTEXT1_CNTL__PAGE_TABLE_BLOCK_SIZE_MASK | GCVM_CONTEXT1_CNTL__RETRY_PERMISSION_OR_INVALID_PAGE_FAULT_MASK | GCVM_CONTEXT1_CNTL__RANGE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__RANGE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__DUMMY_PAGE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__DUMMY_PAGE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__PDE0_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__PDE0_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__VALID_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__VALID_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__READ_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__READ_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__WRITE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__WRITE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__EXECUTE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__EXECUTE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK
pub(super) const CTX_MASK: u32 = 0x7f_feff;
/// ENABLE_CONTEXT, PAGE_TABLE_DEPTH=num_level(3), BLOCK_SIZE=block_size-9
/// (0), RETRY_PERMISSION_OR_INVALID=!noretry (0), all *_ENABLE_DEFAULT.
// linux: GCVM_CONTEXT1_CNTL__ENABLE_CONTEXT_MASK | (3 << GCVM_CONTEXT1_CNTL__PAGE_TABLE_DEPTH__SHIFT) | GCVM_CONTEXT1_CNTL__RANGE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__DUMMY_PAGE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__PDE0_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__VALID_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__READ_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__WRITE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK | GCVM_CONTEXT1_CNTL__EXECUTE_PROTECTION_FAULT_ENABLE_DEFAULT_MASK
pub(super) const CTX_VALUE: u32 = 0x55_5407;
// linux: GCVM_CONTEXT1_CNTL__RANGE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__DUMMY_PAGE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__PDE0_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__VALID_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__READ_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__WRITE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK | GCVM_CONTEXT1_CNTL__EXECUTE_PROTECTION_FAULT_ENABLE_INTERRUPT_MASK
pub(super) const CTX_FAULT_IRQS: u32 = 0x2a_aa00;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GartInfo {
    /// GPU address of the first GART page (VMID0 PAGE_TABLE_START << 12).
    pub start: u64,
    pub size: u64,
    /// GPU (MC) address of the VRAM-resident table.
    pub table: u64,
}
#[derive(Debug)]
pub(super) struct Gart {
    memory: Reservation,
    used: Vec<u64>,
    info: GartInfo,
    enabled: bool,
}
impl Gart {
    /// Whether only the boot pages are in use: no GTT binding is live or
    /// quarantined, so nothing would lose its entries when `enable_gart`
    /// zeroes the table again.
    pub(super) fn only_boot_pages(&self) -> bool {
        (0..self.used.len() as u64 * 64)
            .filter(|&page| self.used[(page / 64) as usize] & (1 << (page % 64)) != 0)
            .all(|page| page < BOOT_PAGES)
    }
    /// Disabled on the same table; `enable_gart` zeroes it and maps the boot
    /// pages again.
    pub(super) fn rearm(&mut self) {
        self.enabled = false;
    }
    pub(super) fn info(&self) -> Option<GartInfo> {
        self.enabled.then_some(self.info)
    }
    pub(super) fn empty_root(&self) -> u64 {
        self.memory.address() + EMPTY_ROOT
    }
    fn is_used(&self, page: u64) -> bool {
        self.used[(page / 64) as usize] & (1 << (page % 64)) != 0
    }
    fn mark(&mut self, first: u64, pages: u64, used: bool) {
        for page in first..first + pages {
            let word = &mut self.used[(page / 64) as usize];
            if used {
                *word |= 1 << (page % 64);
            } else {
                *word &= !(1 << (page % 64));
            }
        }
    }
    /// First-fit run after the retained boot aperture.
    fn find(&self, pages: u64) -> Option<u64> {
        let mut start = BOOT_PAGES;
        let mut page = BOOT_PAGES;
        while page < PAGES {
            if self.is_used(page) {
                start = page + 1;
            } else if page + 1 - start == pages {
                return Some(start);
            }
            page += 1;
        }
        None
    }
}
/// A GART binding. Owns its pinned pages: dropping it (or a failed unbind)
/// leaks them deliberately, since the GPU may still translate to them.
#[derive(Debug)]
pub struct Gtt {
    buffer: Option<DmaBuffer>,
    address: u64,
    first: u64,
    pages: u64,
    owner: u64,
}
impl Gtt {
    /// VMID0 GPU address of the first page.
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn size(&self) -> u64 {
        self.pages * 4096
    }
    /// CPU view of the bound pages.
    pub fn buffer(&self) -> Option<&DmaBuffer> {
        self.buffer.as_ref()
    }
}
impl Drop for Gtt {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            core::mem::forget(buffer);
        }
    }
}
/// amdgpu_ttm_tt_pte_flags for a CPU-cached TT page: VALID | SYSTEM |
/// SNOOPED | gart_pte_flags (MTYPE_UC | EXECUTABLE) | READABLE [| WRITEABLE].
pub(super) fn gtt_flags(writable: bool) -> u64 {
    let flags = with_mtype(
        PTE_VALID | PTE_SYSTEM | PTE_SNOOPED | PTE_EXECUTABLE | PTE_READABLE,
        MTYPE_UC,
    );
    if writable {
        flags | PTE_WRITEABLE
    } else {
        flags
    }
}
/// Validate a contiguous DMA region against the GMC10 44-bit mask.
pub(super) fn dma_range(buffer: &DmaBuffer) -> Result<(u64, u64), Error> {
    let address = buffer.dma_addr().raw();
    let size = buffer.len() as u64;
    if size == 0
        || size % 4096 != 0
        || address % 4096 != 0
        || address.checked_add(size).is_none_or(|end| end > DMA_LIMIT)
    {
        return Err(Error::Invalid);
    }
    Ok((address, size))
}
impl<I: Io> Engine<I> {
    pub(super) fn prepare_gart(&mut self) -> Result<(), Error> {
        if self.gart.is_some() || !matches!(self.state, State::Prepared | State::Ready) {
            return Err(Error::Busy);
        }
        let mut used = Vec::new();
        used.try_reserve_exact((PAGES / 64) as usize)
            .map_err(|_| Error::Allocation)?;
        used.resize((PAGES / 64) as usize, 0);
        let memory = self
            .pool
            .reserve(TABLE + 4096)
            .map_err(|_| Error::Allocation)?;
        self.gart = Some(Gart {
            info: GartInfo {
                start: 0,
                size: GART_SIZE,
                table: memory.address(),
            },
            memory,
            used,
            enabled: false,
        });
        Ok(())
    }
    pub(super) async fn enable_gart(&mut self) -> Result<GartInfo, Error> {
        self.idle()?;
        let geometry = self.geometry.ok_or(Error::Invalid)?;
        let gart = self.gart.as_mut().ok_or(Error::Invalid)?;
        if gart.enabled {
            return Err(Error::Busy);
        }
        // The boot aperture already sits at Linux's BEST_FIT GART start
        // (amdgpu_gmc_gart_location: 0 for this board's 0x80_0000_0000 FB),
        // so its two pages keep their addresses. Re-check Linux's intent:
        // 4 GiB aligned, no 4 GiB crossing, below the MC hole.
        let start = geometry.aperture.start;
        if start % FOUR_GB + GART_SIZE > FOUR_GB
            || start
                .checked_add(GART_SIZE)
                .is_none_or(|end| end > HOLE_START)
        {
            return Err(Error::Invalid);
        }
        gart.info.start = start;
        self.begin()?;
        let result = self.enable_gart_inner(geometry).await;
        self.finish(result)
    }
    async fn enable_gart_inner(&mut self, geometry: Geometry) -> Result<GartInfo, Error> {
        let layout = self.layout;
        let boot = self.memory.address();
        let irqs = if self.fault_irqs { CTX_FAULT_IRQS } else { 0 };
        let Engine {
            io,
            authority,
            gart,
            ..
        } = self;
        let gart = gart.as_mut().ok_or(Error::Invalid)?;
        let info = gart.info;
        let map = gart.memory.mapping();
        invoke(authority, io, |io| {
            zero(io, map);
            // Carry the flat table's two boot pages into GART pages 0 and 1.
            for (index, offset) in [8192, 12288].into_iter().enumerate() {
                entry(
                    io,
                    map,
                    index as u64,
                    // linux-lit: 0x61=AMDGPU_PTE_VALID | AMDGPU_PTE_READABLE | AMDGPU_PTE_WRITEABLE
                    geometry.physical(boot + offset) | 0x61,
                );
            }
            flush(io, layout.nbio);
            Ok(())
        })?;
        // Published before either hub can hold the table or empty root.
        gart.memory.publish();
        gart.mark(0, BOOT_PAGES, true);
        let table = geometry.physical(info.table) | PTE_VALID;
        let root = geometry.physical(gart.empty_root()) | PTE_VALID;
        invoke(authority, io, |io| {
            for (base, r) in layout.bases.into_iter().zip(layout.hubs) {
                program_gart_hub(io, base, r, (table, root), info, irqs)?;
            }
            Ok(())
        })?;
        self.flush_tlb(0, false).await?;
        let gart = self.gart.as_mut().ok_or(Error::Invalid)?;
        gart.enabled = true;
        Ok(gart.info)
    }
    pub(super) async fn bind_gtt(
        &mut self,
        buffer: DmaBuffer,
        writable: bool,
    ) -> Result<Gtt, Error> {
        self.idle()?;
        let (address, size) = dma_range(&buffer)?;
        let gart = self
            .gart
            .as_mut()
            .filter(|g| g.enabled)
            .ok_or(Error::Invalid)?;
        let pages = size / 4096;
        let first = gart.find(pages).ok_or(Error::Exhausted)?;
        gart.mark(first, pages, true);
        let gtt = Gtt {
            buffer: Some(buffer),
            address: gart.info.start + first * 4096,
            first,
            pages,
            owner: self.token,
        };
        let map = gart.memory.mapping();
        self.begin()?;
        let nbio = self.layout.nbio;
        let flags = gtt_flags(writable);
        let result = self.access(|io| {
            // amdgpu_gart_map then amdgpu_gart_invalidate_tlb.
            for page in 0..pages {
                entry(io, map, first + page, (address + page * 4096) | flags);
            }
            flush(io, nbio);
            Ok(())
        });
        let result = match result {
            Ok(()) => self.flush_tlb(0, false).await,
            Err(error) => Err(error),
        };
        // On failure `gtt` drops here and quarantines both pages and range.
        self.finish(result).map(|()| gtt)
    }
    pub(super) async fn unbind_gtt(&mut self, mut gtt: Gtt) -> Result<DmaBuffer, Error> {
        if gtt.owner != self.token {
            return Err(Error::Invalid);
        }
        self.idle()?;
        let map = self
            .gart
            .as_ref()
            .filter(|g| g.enabled)
            .ok_or(Error::Invalid)?
            .memory
            .mapping();
        self.begin()?;
        let nbio = self.layout.nbio;
        let (first, pages) = (gtt.first, gtt.pages);
        // amdgpu_gart_unbind: zero flags ("system bit must be 0 to mean
        // invalid" since Vega10); NARF writes a zero address too.
        let result = self.access(|io| {
            for page in first..first + pages {
                entry(io, map, page, 0);
            }
            flush(io, nbio);
            Ok(())
        });
        let result = match result {
            Ok(()) => self.flush_tlb(0, false).await,
            Err(error) => Err(error),
        };
        self.finish(result)?;
        if let Some(gart) = self.gart.as_mut() {
            gart.mark(first, pages, false);
        }
        gtt.buffer.take().ok_or(Error::Invalid)
    }
}

// mmhub_v2_3_gart_disable's fields.
const L1_ENABLE_L1_TLB: u32 = 1 << 0; // linux: MMMC_VM_MX_L1_TLB_CNTL__ENABLE_L1_TLB_MASK
const L1_ENABLE_ADM: u32 = 1 << 6; // linux: MMMC_VM_MX_L1_TLB_CNTL__ENABLE_ADVANCED_DRIVER_MODEL_MASK
const L2_ENABLE_L2_CACHE: u32 = 1 << 0; // linux: MMVM_L2_CNTL__ENABLE_L2_CACHE_MASK
/// The MMHUB in `layout.bases`/`layout.hubs` (the GFX hub is index 0).
const MMHUB: usize = 1;
impl<I: Io> Engine<I> {
    /// `init_nbio` again (`Gmc::resume_nbio`), on a booted engine.
    pub(super) fn resume_nbio(&mut self) -> Result<(), Error> {
        self.idle()?;
        let init = self.layout.init;
        self.access(|io| init_nbio(io, init))
    }
    /// `mmhub_v2_3_gart_disable`: every MMHUB context off, its L1 TLB and
    /// advanced driver model off, its L2 cache off and `L2_CNTL3` cleared.
    pub(super) fn suspend_mmhub(&mut self) -> Result<(), Error> {
        self.idle()?;
        if self.mmhub_suspended {
            return Err(Error::Busy);
        }
        let (base, r) = (self.layout.bases[MMHUB], self.layout.hubs[MMHUB]);
        self.access(|io| {
            // linux: n/a (AMDGPU_NUM_VMID 16 contexts)
            for context in 0..16 {
                io.write(base + u64::from(r.ctx + context * r.ctx_distance) * 4, 0);
            }
            update(io, base, r.l1, L1_ENABLE_L1_TLB | L1_ENABLE_ADM, 0)?;
            update(io, base, r.l2, L2_ENABLE_L2_CACHE, 0)?;
            io.write(base + u64::from(r.l2_3) * 4, 0);
            Ok(())
        })?;
        self.mmhub_suspended = true;
        Ok(())
    }
    /// The MMHUB half of `gmc_v10_0_gart_enable` after `suspend_mmhub`:
    /// `program` as `initialize` ran it, then (with the GART enabled) the
    /// GART step `enable_gart` ran, then the fault-interrupt switch as last
    /// set, then the MMHUB TLB flush.
    pub(super) async fn resume_mmhub(&mut self) -> Result<(), Error> {
        self.idle()?;
        if !self.mmhub_suspended {
            return Err(Error::Busy);
        }
        let geometry = self.geometry.ok_or(Error::Invalid)?;
        let (base, r) = (self.layout.bases[MMHUB], self.layout.hubs[MMHUB]);
        let address = self.memory.address();
        let gart = self.gart.as_ref().filter(|g| g.enabled).map(|g| {
            (
                (
                    geometry.physical(g.info.table) | PTE_VALID,
                    geometry.physical(g.empty_root()) | PTE_VALID,
                ),
                g.info,
            )
        });
        let fault_irqs = self.fault_irqs;
        let irqs = if fault_irqs { CTX_FAULT_IRQS } else { 0 };
        self.access(|io| {
            program(io, base, r, geometry, address)?;
            if let Some((bases, info)) = gart {
                program_gart_hub(io, base, r, bases, info, irqs)?;
            }
            super::vm::fault_irqs_hub(io, base, r, fault_irqs)
        })?;
        self.flush_tlb_on(0, false, &[(MMHUB, Hub::Mm)]).await?;
        self.mmhub_suspended = false;
        Ok(())
    }
}

/// One hub's half of `gart_enable` once the GART exists:
/// `init_gart_aperture_regs` for VMID0 (`table`, PDE form), then
/// `setup_vmid_config` for VMIDs 1..15. Linux leaves the table base
/// unprogrammed until a ring flush, but NARF points unbound contexts at an
/// all-invalid `root` so that stray use only faults.
pub(super) fn program_gart_hub<I: Io>(
    io: &mut I,
    base: u64,
    r: HubRegs,
    (table, root): (u64, u64),
    info: GartInfo,
    irqs: u32,
) -> Result<(), Error> {
    pair(io, base, r.pt_base, table);
    pair(io, base, r.pt_start, info.start >> 12);
    pair(io, base, r.pt_end, (info.start + info.size - 1) >> 12);
    for step in 1..16u32 {
        // linux: n/a (VMIDs 1..15, setup_vmid_config i <= 14)
        pair(io, base, r.pt_base + step * r.ctx_addr_distance, root);
        update(
            io,
            base,
            r.ctx + step * r.ctx_distance,
            CTX_MASK,
            CTX_VALUE | irqs,
        )?;
        pair(io, base, r.pt_start + step * r.ctx_addr_distance, 0);
        pair(io, base, r.pt_end + step * r.ctx_addr_distance, MAX_PFN - 1);
    }
    Ok(())
}
