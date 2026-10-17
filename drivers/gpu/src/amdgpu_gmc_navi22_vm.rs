//! Per-client GPUVM contexts for VMIDs 1–15: amdgpu_vm.c / amdgpu_vm_pt.c
//! table walks, gmc_v10_0_get_vm_pde/pte encodings, and CPU-side updates
//! (amdgpu_vm_cpu.c: store, HDP flush, then gmc_v10_0_flush_gpu_tlb).
//!
//! Geometry is Linux's for GC 10.3.x: `amdgpu_vm_adjust_size(adev, 256 *
//! 1024, 9, 3, 48)` — the same call GMC11 makes, so `Geometry::GMC11`'s
//! PDB2 → PDB1 → PDB0 → PTB, 512 entries each, 48-bit space applies.
//! `translate_further` is never set on GMC10, so PDEs carry no BFS/TF bits.
//!
//! Each VM owns its VMID while it lives (Linux grabs VMIDs per submission);
//! page tables are owned VRAM pages, never client-visible buffers. A VM can
//! translate only to `Buffer`s explicitly mapped into it.
use super::gart::{dma_range, CTX_FAULT_IRQS, MAX_PFN};
use super::*;
use crate::amdgpu_uapi as uapi;
use crate::amdgpu_vm::{
    with_mtype, Geometry as Layout, Level, MTYPE_CC, MTYPE_NC, MTYPE_UC, MTYPE_WC, PTE_EXECUTABLE,
    PTE_NOALLOC, PTE_READABLE, PTE_SNOOPED, PTE_SYSTEM, PTE_VALID, PTE_WRITEABLE,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use narf_io::DmaBuffer;

const GEOMETRY: Layout = Layout::GMC11;
/// Page-table pages per VM (4 MiB of VRAM): bounds a client's PT footprint.
const MAX_TABLES: usize = 1024;
const KNOWN_FLAGS: u32 = uapi::AMDGPU_VM_PAGE_READABLE
    | uapi::AMDGPU_VM_PAGE_WRITEABLE
    | uapi::AMDGPU_VM_PAGE_EXECUTABLE
    | uapi::AMDGPU_VM_MTYPE_MASK
    | uapi::AMDGPU_VM_PAGE_NOALLOC;
/// AMDGPU_GMC9_FAULT_SOURCE_DATA_{RETRY,WRITE}.
const FAULT_RETRY: u32 = 0x80;
const FAULT_WRITE: u32 = 0x20;

#[derive(Debug)]
pub(super) enum Memory {
    Vram(Reservation),
    System(DmaBuffer),
}
/// Memory a client may map. VRAM comes only from this owner's exclusive pool
/// (never firmware/TMR/scanout), system pages only from pinned DMA buffers.
/// Mapped buffers are retained by the VM until invalidation is acknowledged.
#[derive(Debug)]
pub struct Buffer {
    pub(super) memory: Memory,
    owner: u64,
    read_only: bool,
    uncached: bool,
}
impl Buffer {
    /// Wrap pinned, CPU-cached system pages (TT placement: SYSTEM|SNOOPED).
    pub fn system(buffer: DmaBuffer, read_only: bool) -> Result<Self, Error> {
        dma_range(&buffer)?;
        Ok(Self {
            memory: Memory::System(buffer),
            owner: 0,
            read_only,
            uncached: false,
        })
    }
    /// AMDGPU_GEM_CREATE_{COHERENT,EXT_COHERENT,UNCACHED}: force MTYPE_UC.
    pub fn uncached(mut self) -> Self {
        self.uncached = true;
        self
    }
    pub fn size(&self) -> u64 {
        match &self.memory {
            Memory::Vram(memory) => memory.size(),
            Memory::System(buffer) => buffer.len() as u64,
        }
    }
    pub fn system_pages(&self) -> Option<&DmaBuffer> {
        match &self.memory {
            Memory::System(buffer) => Some(buffer),
            Memory::Vram(_) => None,
        }
    }
    /// CPU (BAR) view of VRAM-backed memory.
    pub fn vram_mapping(&self) -> Option<MmioRegion> {
        match &self.memory {
            Memory::Vram(memory) => Some(memory.mapping()),
            Memory::System(_) => None,
        }
    }
    /// Device address of the first byte as a PTE holds it.
    pub(super) fn device_address(&self, geometry: Geometry) -> u64 {
        match &self.memory {
            Memory::Vram(memory) => geometry.physical(memory.address()),
            Memory::System(buffer) => buffer.dma_addr().raw(),
        }
    }
}
/// amdgpu_ttm_tt_pte_flags (VALID [| SYSTEM | SNOOPED] | MTYPE_UC |
/// EXECUTABLE | READABLE [| WRITEABLE]), amdgpu_vm_bo_update's R/W filter,
/// then gmc_v10_0_get_vm_pte. PRT is refused before this point.
pub(super) fn pte_flags(system: bool, read_only: bool, uncached: bool, vm: u32) -> u64 {
    let mut flags = with_mtype(PTE_VALID | PTE_EXECUTABLE | PTE_READABLE, MTYPE_UC);
    if system {
        flags |= PTE_SYSTEM | PTE_SNOOPED;
    }
    if !read_only {
        flags |= PTE_WRITEABLE;
    }
    if vm & uapi::AMDGPU_VM_PAGE_READABLE == 0 {
        flags &= !PTE_READABLE;
    }
    if vm & uapi::AMDGPU_VM_PAGE_WRITEABLE == 0 {
        flags &= !PTE_WRITEABLE;
    }
    if vm & uapi::AMDGPU_VM_PAGE_EXECUTABLE != 0 {
        flags |= PTE_EXECUTABLE;
    } else {
        flags &= !PTE_EXECUTABLE;
    }
    flags = with_mtype(
        flags,
        match vm & uapi::AMDGPU_VM_MTYPE_MASK {
            uapi::AMDGPU_VM_MTYPE_WC => MTYPE_WC,
            uapi::AMDGPU_VM_MTYPE_CC => MTYPE_CC,
            uapi::AMDGPU_VM_MTYPE_UC => MTYPE_UC,
            _ => MTYPE_NC,
        },
    );
    if vm & uapi::AMDGPU_VM_PAGE_NOALLOC != 0 {
        flags |= PTE_NOALLOC;
    } else {
        flags &= !PTE_NOALLOC;
    }
    if uncached {
        flags = with_mtype(flags, MTYPE_UC);
    }
    flags
}
/// gmc_v10_0_get_vm_pde for a VRAM table: MC→PA, VALID, no BFS/TF.
fn pde(geometry: Geometry, table: &Reservation) -> u64 {
    geometry.physical(table.address()) | PTE_VALID
}

/// One `AMDGPU_GEM_VA` map request, in hole-stripped GPU addresses and bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub va: u64,
    /// Byte offset into the buffer.
    pub offset: u64,
    pub size: u64,
    /// `AMDGPU_VM_PAGE_*` and `AMDGPU_VM_MTYPE_*`; PRT is not supported.
    pub flags: u32,
}
/// Exclusive client handle. Not `Clone`: only its holder can map or destroy.
/// Dropping it without `destroy_vm` leaks the VMID and every mapped buffer.
#[derive(Debug)]
pub struct Vm {
    vmid: u8,
    generation: u64,
    owner: u64,
}
impl Vm {
    pub fn vmid(&self) -> u8 {
        self.vmid
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmInfo {
    pub vmid: u8,
    pub generation: u64,
    /// CONTEXTn_PAGE_TABLE_BASE value (amdgpu_gmc_pd_addr of the root), as a
    /// ring's emit_flush_gpu_tlb would program it.
    pub page_table_base: u64,
    pub mappings: usize,
    pub tables: usize,
}
/// A decoded VMC (MMHUB) or UTCL2 (GFXHUB) fault IV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    pub hub: Hub,
    pub vmid: u8,
    pub address: u64,
    pub retry: bool,
    pub write: bool,
}
impl Fault {
    /// SOC15_IH_CLIENTID_VMC / _UTCL2; both use source id 0
    /// (VMC_1_0__SRCID__VM_FAULT, UTCL2_1_0__SRCID__FAULT).
    pub const CLIENT_VMC: u8 = 0x12;
    pub const CLIENT_UTCL2: u8 = 0x1b;
    /// gmc_v10_0_process_interrupt's decode of `src_data[0..2]`.
    pub fn decode(client: u8, source: u8, vmid: u8, data: [u32; 2]) -> Option<Self> {
        let hub = match (client, source) {
            (Self::CLIENT_VMC, 0) => Hub::Mm,
            (Self::CLIENT_UTCL2, 0) => Hub::Gfx,
            _ => return None,
        };
        if vmid > 15 {
            return None;
        }
        Some(Self {
            hub,
            vmid,
            address: u64::from(data[0]) << 12 | u64::from(data[1] & 0xf) << 44,
            retry: data[1] & FAULT_RETRY != 0,
            write: data[1] & FAULT_WRITE != 0,
        })
    }
}
/// amdgpu_vm_update_fault_cache, plus a saturating count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultInfo {
    pub hub: Hub,
    pub address: u64,
    /// L2_PROTECTION_FAULT_STATUS (CID, RW, VMID, MAPPING/PERMISSION bits).
    pub status: u32,
    pub write: bool,
    pub retry: bool,
    pub count: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultOwner {
    Kernel,
    Vm {
        vmid: u8,
        generation: u64,
    },
    /// No bound VM: a stale VMID or a fault after teardown.
    Unowned,
}

#[derive(Debug)]
struct Table {
    memory: Reservation,
    children: BTreeMap<u16, Table>,
}
#[derive(Debug)]
struct Mapped {
    mapping: Mapping,
    buffer: Arc<Buffer>,
}
#[derive(Debug)]
struct Space {
    generation: u64,
    root: Table,
    tables: usize,
    mappings: BTreeMap<u64, Mapped>,
    fault: Option<FaultInfo>,
}
impl Drop for Space {
    fn drop(&mut self) {
        // Only a successful destroy empties this first. Otherwise hardware may
        // still reach these buffers: never let their backing be freed.
        for (_, mapped) in core::mem::take(&mut self.mappings) {
            core::mem::forget(mapped.buffer);
        }
    }
}
#[derive(Debug)]
pub(super) struct Vms {
    slots: [Option<Space>; 16],
    next: u8,
    generation: u64,
}
impl Vms {
    pub(super) fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            next: 1,
            generation: 0,
        }
    }
    /// Round-robin so a just-freed VMID (and its late faults) is reused last.
    fn free(&mut self) -> Option<u8> {
        for step in 0..15 {
            let vmid = (self.next - 1 + step) % 15 + 1;
            if self.slots[usize::from(vmid)].is_none() {
                self.next = vmid % 15 + 1;
                return Some(vmid);
            }
        }
        None
    }
    fn space(&self, vm: &Vm, owner: u64) -> Result<&Space, Error> {
        match &self.slots[usize::from(vm.vmid)] {
            Some(space) if vm.owner == owner && space.generation == vm.generation => Ok(space),
            _ => Err(Error::Invalid),
        }
    }
}
fn path(va: u64) -> [u16; 4] {
    [Level::Pdb2, Level::Pdb1, Level::Pdb0, Level::Ptb].map(|l| GEOMETRY.index_at(va, l) as u16)
}
/// Tables a map of `[va, end)` would add below `root`.
fn missing(root: &Table, va: u64, end: u64) -> usize {
    let mut absent = BTreeSet::new();
    let mut chunk = va & !((2 << 20) - 1);
    while chunk < end {
        let [a, b, c, _] = path(chunk);
        let pdb1 = root.children.get(&a);
        let pdb0 = pdb1.and_then(|t| t.children.get(&b));
        let ptb = pdb0.and_then(|t| t.children.get(&c));
        for (present, key) in [
            (pdb1.is_some(), (1, a, 0, 0)),
            (pdb0.is_some(), (2, a, b, 0)),
            (ptb.is_some(), (3, a, b, c)),
        ] {
            if !present {
                absent.insert(key);
            }
        }
        chunk += 2 << 20;
    }
    absent.len()
}
/// Walk to the PTB for `va`, linking zeroed spare tables where absent. New
/// tables are cleared and HDP-flushed before their PDE is stored.
fn ensure<'a, I: Io>(
    io: &mut I,
    nbio: u64,
    geometry: Geometry,
    root: &'a mut Table,
    va: u64,
    spare: &mut Vec<Reservation>,
    created: &mut usize,
) -> Result<&'a mut Table, Error> {
    let index = path(va);
    let mut table = root;
    for slot in index.into_iter().take(3) {
        if !table.children.contains_key(&slot) {
            let mut memory = spare.pop().ok_or(Error::Invalid)?;
            zero(io, memory.mapping());
            flush(io, nbio);
            memory.publish();
            entry(
                io,
                table.memory.mapping(),
                u64::from(slot),
                pde(geometry, &memory),
            );
            table.children.insert(
                slot,
                Table {
                    memory,
                    children: BTreeMap::new(),
                },
            );
            *created += 1;
        }
        table = table.children.get_mut(&slot).ok_or(Error::Invalid)?;
    }
    Ok(table)
}
fn leaf(root: &Table, va: u64) -> Option<&Table> {
    let index = path(va);
    let mut table = root;
    for slot in index.into_iter().take(3) {
        table = table.children.get(&slot)?;
    }
    Some(table)
}
/// Release published page tables after hardware stopped using them.
fn stop_tables(table: &mut Table) {
    // SAFETY: called only after the context was moved off this tree and
    // both hubs acknowledged invalidation of its VMID.
    unsafe { table.memory.stopped() };
    for child in table.children.values_mut() {
        stop_tables(child);
    }
}
impl<I: Io> Engine<I> {
    pub(super) fn allocate_vram(&mut self, size: u64, read_only: bool) -> Result<Buffer, Error> {
        self.idle()?;
        let memory = self.pool.reserve(size).map_err(|_| Error::Allocation)?;
        let map = memory.mapping();
        // Pool pages may hold another client's or a freed page table's data.
        self.access(|io| {
            zero(io, map);
            Ok(())
        })?;
        Ok(Buffer {
            memory: Memory::Vram(memory),
            owner: self.token,
            read_only,
            uncached: false,
        })
    }
    fn user_ready(&self) -> Result<Geometry, Error> {
        self.idle()?;
        if self.gart.as_ref().and_then(gart::Gart::info).is_none() {
            return Err(Error::Invalid); // user contexts not armed yet
        }
        self.geometry.ok_or(Error::Invalid)
    }
    /// Store `value` into context `vmid`'s table base on both hubs.
    fn set_base(&mut self, vmid: u8, value: u64) -> Result<(), Error> {
        let layout = self.layout;
        self.access(|io| {
            for (base, r) in layout.bases.into_iter().zip([GFX, MM]) {
                pair(
                    io,
                    base,
                    r.pt_base + u32::from(vmid) * regs::CTX_ADDR_DISTANCE,
                    value,
                );
            }
            Ok(())
        })
    }
    pub(super) async fn create_vm(&mut self) -> Result<Vm, Error> {
        let geometry = self.user_ready()?;
        let vmid = self.vms.free().ok_or(Error::Exhausted)?;
        let memory = self.pool.reserve(4096).map_err(|_| Error::Allocation)?;
        self.begin()?;
        self.vms.generation += 1;
        let generation = self.vms.generation;
        let root = pde(geometry, &memory);
        // Retained in the slot from here on: a failure poisons the VMID.
        self.vms.slots[usize::from(vmid)] = Some(Space {
            generation,
            root: Table {
                memory,
                children: BTreeMap::new(),
            },
            tables: 1,
            mappings: BTreeMap::new(),
            fault: None,
        });
        let result = self.create_inner(vmid, root).await;
        self.finish(result).map(|()| Vm {
            vmid,
            generation,
            owner: self.token,
        })
    }
    async fn create_inner(&mut self, vmid: u8, root: u64) -> Result<(), Error> {
        let nbio = self.layout.nbio;
        let Engine {
            io, authority, vms, ..
        } = self;
        let space = vms.slots[usize::from(vmid)]
            .as_mut()
            .ok_or(Error::Invalid)?;
        let map = space.root.memory.mapping();
        invoke(authority, io, |io| {
            zero(io, map);
            flush(io, nbio);
            Ok(())
        })?;
        space.root.memory.publish();
        self.set_base(vmid, root)?;
        self.flush_tlb(vmid, false).await
    }
    pub(super) async fn map(
        &mut self,
        vm: &Vm,
        m: Mapping,
        buffer: Arc<Buffer>,
    ) -> Result<(), Error> {
        let geometry = self.user_ready()?;
        let space = self.vms.space(vm, self.token)?;
        let end = m.va.checked_add(m.size).ok_or(Error::Invalid)?;
        if m.size == 0
            || (m.va | m.size | m.offset) % 4096 != 0
            || end > MAX_PFN << 12
            || m.offset
                .checked_add(m.size)
                .is_none_or(|e| e > buffer.size())
            || m.flags & !KNOWN_FLAGS != 0
            || matches!(buffer.memory, Memory::Vram(_)) && buffer.owner != self.token
        {
            return Err(Error::Invalid);
        }
        if space
            .mappings
            .range(..end)
            .next_back()
            .is_some_and(|(_, prior)| prior.mapping.va + prior.mapping.size > m.va)
        {
            return Err(Error::Invalid); // amdgpu_vm_bo_map: conflict is -EINVAL
        }
        let count = missing(&space.root, m.va, end);
        if space.tables + count > MAX_TABLES {
            return Err(Error::Exhausted);
        }
        let mut spare = Vec::new();
        spare
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        for _ in 0..count {
            spare.push(self.pool.reserve(4096).map_err(|_| Error::Allocation)?);
        }
        let system = matches!(buffer.memory, Memory::System(_));
        let flags = pte_flags(system, buffer.read_only, buffer.uncached, m.flags);
        let first = buffer.device_address(geometry) + m.offset;
        self.begin()?;
        let vmid = vm.vmid;
        let nbio = self.layout.nbio;
        let Engine {
            io, authority, vms, ..
        } = self;
        let Some(space) = vms.slots[usize::from(vmid)].as_mut() else {
            return self.finish(Err(Error::Invalid));
        };
        // Recorded first, so any later failure retains the buffer.
        space.mappings.insert(m.va, Mapped { mapping: m, buffer });
        let result = invoke(authority, io, |io| {
            let mut created = 0;
            let mut va = m.va;
            while va < end {
                let table = ensure(
                    io,
                    nbio,
                    geometry,
                    &mut space.root,
                    va,
                    &mut spare,
                    &mut created,
                );
                let table = match table {
                    Ok(table) => table,
                    Err(error) => {
                        space.tables += created;
                        return Err(error);
                    }
                };
                let map = table.memory.mapping();
                // Stay within this PTB.
                let stop = end.min((va | ((2 << 20) - 1)) + 1);
                while va < stop {
                    let index = u64::from(path(va)[3]);
                    entry(io, map, index, (first + (va - m.va)) | flags);
                    va += 4096;
                }
            }
            space.tables += created;
            flush(io, nbio);
            Ok(())
        });
        let result = match result {
            Ok(()) => self.flush_tlb(vmid, false).await,
            Err(error) => Err(error),
        };
        self.finish(result)
    }
    pub(super) async fn unmap(&mut self, vm: &Vm, va: u64) -> Result<(), Error> {
        self.user_ready()?;
        let space = self.vms.space(vm, self.token)?;
        let m = space.mappings.get(&va).ok_or(Error::Invalid)?.mapping;
        self.begin()?;
        let vmid = vm.vmid;
        let nbio = self.layout.nbio;
        let Engine {
            io, authority, vms, ..
        } = self;
        let Some(space) = vms.slots[usize::from(vmid)].as_ref() else {
            return self.finish(Err(Error::Invalid));
        };
        let result = invoke(authority, io, |io| {
            let mut va = m.va;
            while va < m.va + m.size {
                let table = leaf(&space.root, va).ok_or(Error::Invalid)?;
                entry(io, table.memory.mapping(), u64::from(path(va)[3]), 0);
                va += 4096;
            }
            flush(io, nbio);
            Ok(())
        });
        let result = match result {
            Ok(()) => self.flush_tlb(vmid, false).await,
            Err(error) => Err(error),
        };
        self.finish(result)?;
        // Both hubs acknowledged: the buffer is unreachable from this VMID.
        if let Some(space) = self.vms.slots[usize::from(vmid)].as_mut() {
            space.mappings.remove(&va);
        }
        Ok(())
    }
    pub(super) async fn destroy_vm(&mut self, vm: Vm) -> Result<(), Error> {
        self.user_ready()?;
        self.vms.space(&vm, self.token)?;
        let root = {
            let gart = self.gart.as_ref().ok_or(Error::Invalid)?;
            self.geometry
                .ok_or(Error::Invalid)?
                .physical(gart.empty_root())
                | PTE_VALID
        };
        self.begin()?;
        let result = match self.set_base(vm.vmid, root) {
            Ok(()) => self.flush_tlb(vm.vmid, false).await,
            Err(error) => Err(error),
        };
        self.finish(result)?;
        if let Some(mut space) = self.vms.slots[usize::from(vm.vmid)].take() {
            stop_tables(&mut space.root);
            space.mappings.clear(); // drops buffers normally
        }
        Ok(())
    }
    pub(super) fn vm_info(&self, vm: &Vm) -> Option<VmInfo> {
        let space = self.vms.space(vm, self.token).ok()?;
        Some(VmInfo {
            vmid: vm.vmid,
            generation: space.generation,
            page_table_base: pde(self.geometry?, &space.root.memory),
            mappings: space.mappings.len(),
            tables: space.tables,
        })
    }
    pub(super) fn vm_fault(&self, vm: &Vm) -> Option<FaultInfo> {
        self.vms.space(vm, self.token).ok()?.fault
    }
    /// gmc_v10_0_process_interrupt minus printing: read the hub's L2
    /// protection status, `WREG32_P(fault_cntl, 1, ~1)` to re-arm the status
    /// address, then attribute by VMID. Retry faults (noretry=1 on GC 10.3,
    /// so unexpected) are reported, never recovered.
    pub(super) fn handle_fault(&mut self, fault: Fault) -> Result<FaultOwner, Error> {
        if self.geometry.is_none() || fault.vmid > 15 {
            return Err(Error::Invalid);
        }
        let (index, r) = match fault.hub {
            Hub::Gfx => (0, GFX),
            Hub::Mm => (1, MM),
        };
        let base = self.layout.bases[index];
        let status = self.access(|io| {
            let status = checked(io.read(base + u64::from(r.fault_status) * 4))?;
            update(io, base, r.fault_cntl, 1, 1)?;
            Ok(status)
        })?;
        if fault.vmid == 0 {
            return Ok(FaultOwner::Kernel);
        }
        let Some(space) = self.vms.slots[usize::from(fault.vmid)].as_mut() else {
            return Ok(FaultOwner::Unowned);
        };
        let count = space.fault.map_or(0, |f| f.count).saturating_add(1);
        space.fault = Some(FaultInfo {
            hub: fault.hub,
            address: fault.address,
            status,
            write: fault.write,
            retry: fault.retry,
            count,
        });
        Ok(FaultOwner::Vm {
            vmid: fault.vmid,
            generation: space.generation,
        })
    }
    /// amdgpu_gmc_set_vm_fault_masks on MMHUB then GFXHUB, all 16 contexts,
    /// plus the per-client L2 fault interrupt enables VMID0 init cleared
    /// (Linux leaves them at the 0x3ffffffc reset default).
    pub(super) fn set_fault_interrupts(&mut self, enable: bool) -> Result<(), Error> {
        if self.state != State::Ready || self.runtime == Runtime::Busy {
            return Err(Error::Busy);
        }
        let layout = self.layout;
        self.access(|io| {
            for (base, r) in [(layout.bases[1], MM), (layout.bases[0], GFX)] {
                update(
                    io,
                    base,
                    r.fault_cntl,
                    0x3fff_e000,
                    if enable { 0x3fff_e000 } else { 0 },
                )?;
                for context in 0..16 {
                    update(
                        io,
                        base,
                        r.ctx + context * regs::CTX_DISTANCE,
                        CTX_FAULT_IRQS,
                        if enable { CTX_FAULT_IRQS } else { 0 },
                    )?;
                }
            }
            Ok(())
        })?;
        self.fault_irqs = enable;
        Ok(())
    }
}
