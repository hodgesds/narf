//! AMD VMID (virtual memory ID) management.
//!
//! Each AMD GPU exposes 16 VMIDs per VM hub (the on-die MMU
//! cluster). VMID 0 is the system / kernel VMID; VMIDs 1–15 are
//! assigned to user-mode processes (one per OpenCL / Vulkan
//! context). The GPU walks per-VMID page tables on every
//! command-stream evaluation; the host populates the page-table
//! root + manages the per-VMID `MC_VM_CONTEXT*_PAGE_TABLE_BASE`
//! registers.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/amdgpu/amdgpu_ids.c` — VMID
//!   ring scheduler + LRU
//! - Linux `drivers/gpu/drm/amd/amdgpu/gmc_v9_0.c::gmc_v9_0_setup_vm_pt_regs`
//! - Linux `drivers/gpu/drm/amd/amdgpu/gmc_v11_0.c` — Phoenix VM hub
//! - Linux `drivers/gpu/drm/amd/include/asic_reg/mmhub/mmhub_2_0_offset.h`
//!   — MMHUB register offsets
//!
//! GPL-2.0-or-later (matches NARF). Adapted directly.
//!
//! ## VM hubs
//!
//! Modern AMD GPUs have multiple VM hubs:
//!   - **GFXHUB** — serves the GFX command processor, MEC, SDMA.
//!   - **MMHUB** — serves the multimedia clients (VCN, DCN, JPEG).
//!
//! Each hub has its own VMID pool. A user process that touches
//! both compute and video gets a VMID allocated in each hub
//! that shares the same root page table.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

// ── VMID count + constants ──────────────────────────────────────

/// Total VMIDs per VM hub. AMD GPUs since Vega expose 16; older
/// (Polaris) had 8. Phoenix retains 16.
pub const VMIDS_PER_HUB: usize = 16;

/// The kernel-owned VMID. Always 0 — the driver pins it for
/// system mappings.
pub const KERNEL_VMID: u8 = 0;

/// First user-allocatable VMID.
pub const FIRST_USER_VMID: u8 = 1;

/// Last user-allocatable VMID.
pub const LAST_USER_VMID: u8 = (VMIDS_PER_HUB as u8) - 1;

// ── VM hub identifier ───────────────────────────────────────────

/// VM hub identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmHub {
    Gfx,
    Mm,
}

impl VmHub {
    pub fn name(self) -> &'static str {
        match self {
            VmHub::Gfx => "gfxhub",
            VmHub::Mm => "mmhub",
        }
    }
}

// ── PASID ────────────────────────────────────────────────────────

/// Process Address Space ID — the per-process identifier the
/// PCIe ATS / PRI subsystem uses. Range is 1..=0xFFFF; 0 is
/// reserved for "no PASID" (legacy GFX submissions).
///
/// VMID binds 1:1 to PASID for the active context but the
/// scheduler can evict + remint VMIDs while PASIDs are stable.
pub type Pasid = u16;

// ── Per-VMID state ───────────────────────────────────────────────

/// State of one VMID slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmidState {
    /// Slot is free + available for allocation.
    Free,
    /// Slot is bound to a PASID + page table root.
    Bound {
        pasid: Pasid,
        page_table_root_phys: u64,
        /// Logical timestamp of last use; the LRU evictor reads this.
        last_use_tag: u64,
    },
}

impl VmidState {
    pub fn is_free(&self) -> bool {
        matches!(self, VmidState::Free)
    }

    pub fn pasid(&self) -> Option<Pasid> {
        if let VmidState::Bound { pasid, .. } = self {
            Some(*pasid)
        } else {
            None
        }
    }
}

// ── VMID pool ────────────────────────────────────────────────────

/// Per-hub VMID pool. Tracks which VMIDs are bound to which
/// PASIDs + manages LRU eviction when a new PASID needs a slot
/// and all VMIDs are taken.
#[derive(Clone, Debug)]
pub struct VmidPool {
    pub hub: VmHub,
    /// Per-VMID state. VMID 0 is permanently bound to the kernel.
    pub slots: Vec<VmidState>,
    /// Monotonic clock for LRU.
    next_tag: u64,
    /// LRU ordering (front = LRU). Used to pick eviction victims.
    lru: VecDeque<u8>,
    /// PASID → VMID lookup. Set on bind, cleared on evict.
    pasid_to_vmid: Vec<(Pasid, u8)>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmidError {
    /// Caller asked for VMID 0; that's kernel-reserved.
    ReservedVmid,
    /// Pool is full and there's nothing to evict (every slot
    /// is kernel-pinned). Shouldn't happen in practice (only
    /// VMID 0 is pinned) but surfaced as an error rather than
    /// a panic.
    NoVictim,
    /// PASID is invalid (0).
    BadPasid,
    /// Page-table root not 4 KiB aligned.
    BadPageTable,
}

impl VmidPool {
    pub fn new(hub: VmHub) -> Self {
        let mut slots = Vec::with_capacity(VMIDS_PER_HUB);
        // VMID 0 = kernel.
        slots.push(VmidState::Bound {
            pasid: 0,
            page_table_root_phys: 0,
            last_use_tag: 0,
        });
        for _ in 1..VMIDS_PER_HUB {
            slots.push(VmidState::Free);
        }
        Self {
            hub,
            slots,
            next_tag: 1,
            lru: VecDeque::new(),
            pasid_to_vmid: Vec::new(),
        }
    }

    fn allocate_tag(&mut self) -> u64 {
        let t = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1);
        t
    }

    /// Look up the VMID currently bound to `pasid`. `None` if
    /// the PASID has no live VMID binding (the next submission
    /// for this PASID will call `bind` to allocate one).
    pub fn vmid_for_pasid(&self, pasid: Pasid) -> Option<u8> {
        self.pasid_to_vmid
            .iter()
            .find(|(p, _)| *p == pasid)
            .map(|(_, v)| *v)
    }

    /// Bind a PASID to a VMID. If the PASID already has a VMID
    /// in this hub, bump its LRU tag and return it. Otherwise
    /// pick a free slot or evict the LRU.
    pub fn bind(
        &mut self,
        pasid: Pasid,
        page_table_root_phys: u64,
    ) -> Result<u8, VmidError> {
        if pasid == 0 {
            return Err(VmidError::BadPasid);
        }
        if page_table_root_phys & 0xFFF != 0 {
            return Err(VmidError::BadPageTable);
        }
        // Already bound? Touch + return.
        if let Some(vmid) = self.vmid_for_pasid(pasid) {
            self.touch(vmid);
            return Ok(vmid);
        }
        // Allocate fresh slot.
        let vmid = self.allocate_slot()?;
        let tag = self.allocate_tag();
        self.slots[vmid as usize] = VmidState::Bound {
            pasid,
            page_table_root_phys,
            last_use_tag: tag,
        };
        self.pasid_to_vmid.push((pasid, vmid));
        self.lru.push_back(vmid);
        Ok(vmid)
    }

    /// Find a slot to assign. Prefers a free slot; falls back
    /// to LRU eviction.
    fn allocate_slot(&mut self) -> Result<u8, VmidError> {
        // Free slot wins.
        for (i, s) in self
            .slots
            .iter()
            .enumerate()
            .skip(FIRST_USER_VMID as usize)
        {
            if s.is_free() {
                return Ok(i as u8);
            }
        }
        // No free slot — evict LRU.
        let victim = self.lru.pop_front().ok_or(VmidError::NoVictim)?;
        // Drop the evicted PASID's mapping.
        if let Some(pos) = self
            .pasid_to_vmid
            .iter()
            .position(|(_, v)| *v == victim)
        {
            self.pasid_to_vmid.swap_remove(pos);
        }
        self.slots[victim as usize] = VmidState::Free;
        Ok(victim)
    }

    /// Touch a VMID — mark it most-recently-used + bump its tag.
    pub fn touch(&mut self, vmid: u8) {
        if let Some(slot) = self.slots.get_mut(vmid as usize) {
            if let VmidState::Bound { last_use_tag, .. } = slot {
                let new_tag = self.next_tag;
                self.next_tag = self.next_tag.wrapping_add(1);
                *last_use_tag = new_tag;
            }
        }
        // Move VMID to the back of the LRU.
        if let Some(pos) = self.lru.iter().position(|v| *v == vmid) {
            self.lru.remove(pos);
            self.lru.push_back(vmid);
        }
    }

    /// Explicitly release a VMID (process exit / context teardown).
    /// VMID 0 (kernel) is not releasable — silently ignored.
    pub fn release(&mut self, vmid: u8) {
        if vmid == KERNEL_VMID {
            return;
        }
        if let Some(slot) = self.slots.get_mut(vmid as usize) {
            *slot = VmidState::Free;
        }
        if let Some(pos) = self.lru.iter().position(|v| *v == vmid) {
            self.lru.remove(pos);
        }
        self.pasid_to_vmid.retain(|(_, v)| *v != vmid);
    }

    /// Count of currently-bound user VMIDs.
    pub fn user_bound_count(&self) -> usize {
        self.slots
            .iter()
            .skip(FIRST_USER_VMID as usize)
            .filter(|s| !s.is_free())
            .count()
    }

    /// `true` if all user VMIDs are bound (next bind will evict).
    pub fn is_saturated(&self) -> bool {
        self.user_bound_count() >= (LAST_USER_VMID - FIRST_USER_VMID + 1) as usize
    }

    /// Bind a PASID and program the silicon to back the VMID.
    ///
    /// Combines [`VmidPool::bind`] (logical pool allocation) with
    /// `amdgpu_vmhub_regs::write_vmid_pt_base` (the MMIO writes
    /// that make the GPU walk the new page table). On real
    /// silicon callers go through this entry; `bind` alone
    /// remains useful for tests + scheduling.
    ///
    /// `regs` is the per-(family, hub) layout from
    /// `amdgpu_vmhub_regs::regs_for`. Aborts if the page-table
    /// programming fails — the slot remains live in the pool
    /// either way (`bind` doesn't roll back on MMIO error; the
    /// next submission against the PASID will re-bind).
    pub fn bind_and_program<M: crate::amdgpu_vmhub_regs::VmHubMmio>(
        &mut self,
        pasid: Pasid,
        page_table_root_phys: u64,
        mmio: &mut M,
        regs: &crate::amdgpu_vmhub_regs::VmHubRegs,
    ) -> Result<u8, VmidError> {
        let vmid = self.bind(pasid, page_table_root_phys)?;
        crate::amdgpu_vmhub_regs::write_vmid_pt_base(
            mmio,
            regs,
            vmid,
            page_table_root_phys,
        );
        Ok(vmid)
    }

    /// Pin a specific user VMID for the kernel's own use (e.g.
    /// a privileged context). Reserves it from the LRU pool.
    /// Idempotent.
    pub fn pin_for_kernel(&mut self, vmid: u8, page_table_root_phys: u64) -> Result<(), VmidError> {
        if vmid == KERNEL_VMID {
            return Ok(());
        }
        if !(FIRST_USER_VMID..=LAST_USER_VMID).contains(&vmid) {
            return Err(VmidError::ReservedVmid);
        }
        if page_table_root_phys & 0xFFF != 0 {
            return Err(VmidError::BadPageTable);
        }
        // Bind to PASID 0 — sentinel for "kernel-pinned".
        // Remove from LRU + pasid map so it won't be evicted.
        if let Some(pos) = self.lru.iter().position(|v| *v == vmid) {
            self.lru.remove(pos);
        }
        self.pasid_to_vmid.retain(|(_, v)| *v != vmid);
        self.slots[vmid as usize] = VmidState::Bound {
            pasid: 0,
            page_table_root_phys,
            last_use_tag: u64::MAX,
        };
        Ok(())
    }
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_vmid_pool_init_kernel_pinned() -> TestResult {
        let pool = VmidPool::new(VmHub::Gfx);
        if pool.slots.len() != VMIDS_PER_HUB {
            return TestResult::Fail("slot count wrong");
        }
        // VMID 0 = kernel bound.
        match &pool.slots[0] {
            VmidState::Bound { pasid: 0, .. } => {}
            _ => return TestResult::Fail("VMID 0 not kernel-bound"),
        }
        // VMIDs 1..=15 free.
        for i in 1..VMIDS_PER_HUB {
            if !pool.slots[i].is_free() {
                return TestResult::Fail("user VMID not free at init");
            }
        }
        if pool.user_bound_count() != 0 {
            return TestResult::Fail("user_bound_count not 0 at init");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmid_pool_init_kernel_pinned);

    fn smoke_vmid_bind_validates_input() -> TestResult {
        let mut p = VmidPool::new(VmHub::Gfx);
        // PASID 0 rejected.
        if p.bind(0, 0x1000) != Err(VmidError::BadPasid) {
            return TestResult::Fail("PASID 0 should fail");
        }
        // Unaligned PT rejected.
        if p.bind(1, 0x1001) != Err(VmidError::BadPageTable) {
            return TestResult::Fail("misaligned PT should fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmid_bind_validates_input);

    fn smoke_vmid_bind_assigns_unique() -> TestResult {
        let mut p = VmidPool::new(VmHub::Gfx);
        // Bind PASID 1 → expect VMID 1 (first free).
        let v1 = p.bind(1, 0x1000).expect("bind 1");
        if v1 != 1 {
            return TestResult::Fail("first bind didn't get VMID 1");
        }
        // Bind PASID 2 → expect VMID 2.
        let v2 = p.bind(2, 0x2000).expect("bind 2");
        if v2 != 2 {
            return TestResult::Fail("second bind didn't get VMID 2");
        }
        // Re-bind PASID 1 → idempotent, returns same VMID.
        let v1_again = p.bind(1, 0x1000).expect("rebind 1");
        if v1_again != v1 {
            return TestResult::Fail("re-bind not idempotent");
        }
        if p.user_bound_count() != 2 {
            return TestResult::Fail("user_bound_count wrong");
        }
        if p.vmid_for_pasid(1) != Some(1) {
            return TestResult::Fail("vmid_for_pasid wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmid_bind_assigns_unique);

    fn smoke_vmid_release_frees_slot() -> TestResult {
        let mut p = VmidPool::new(VmHub::Gfx);
        let v = p.bind(42, 0x1000).expect("bind");
        if v == 0 {
            return TestResult::Fail("VMID 0 returned for user");
        }
        p.release(v);
        if !p.slots[v as usize].is_free() {
            return TestResult::Fail("released VMID not free");
        }
        if p.vmid_for_pasid(42).is_some() {
            return TestResult::Fail("released PASID still maps");
        }
        // Releasing VMID 0 is a no-op.
        p.release(0);
        if p.slots[0].is_free() {
            return TestResult::Fail("VMID 0 should not be releasable");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmid_release_frees_slot);

    fn smoke_vmid_lru_eviction() -> TestResult {
        let mut p = VmidPool::new(VmHub::Gfx);
        // Saturate: 15 user VMIDs (PASIDs 1..=15) → all taken.
        for pasid in 1..=15 {
            p.bind(pasid as Pasid, (pasid as u64) << 12).expect("saturate");
        }
        if !p.is_saturated() {
            return TestResult::Fail("not saturated after 15 binds");
        }
        // Touch PASID 1 — moves it to the back of the LRU.
        let v1 = p.vmid_for_pasid(1).unwrap();
        p.touch(v1);
        // Bind a 16th PASID — should evict LRU (VMID for PASID 2).
        let evicted_pasid = 2;
        let v_evicted = p.vmid_for_pasid(evicted_pasid).unwrap();
        let new_vmid = p.bind(99, 0x9000).expect("evict + bind");
        if new_vmid != v_evicted {
            return TestResult::Fail("eviction didn't take LRU slot");
        }
        // PASID 2 → no longer mapped.
        if p.vmid_for_pasid(evicted_pasid).is_some() {
            return TestResult::Fail("evicted PASID still mapped");
        }
        // PASID 1 → still mapped (we touched it).
        if p.vmid_for_pasid(1).is_none() {
            return TestResult::Fail("touched PASID got evicted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmid_lru_eviction);

    fn smoke_vmid_pin_for_kernel_not_evictable() -> TestResult {
        let mut p = VmidPool::new(VmHub::Mm);
        // Pin VMID 15 for kernel use.
        p.pin_for_kernel(15, 0xF000).expect("pin");
        // Bind 14 user PASIDs → fill 1..=14 (15 is pinned, 0 is kernel).
        for pasid in 1..=14 {
            p.bind(pasid as Pasid, (pasid as u64) << 12).expect("bind");
        }
        // 15th user bind → triggers eviction; pinned VMID 15 NOT in LRU
        // so the evictor picks the LRU among VMIDs 1..=14.
        let v_evict = p.bind(99, 0x9000).expect("evict-or-fit");
        if v_evict == 15 {
            return TestResult::Fail("pinned VMID got evicted");
        }
        // VMID 15 still bound to kernel sentinel.
        if !matches!(p.slots[15], VmidState::Bound { pasid: 0, .. }) {
            return TestResult::Fail("pinned slot wrong state");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmid_pin_for_kernel_not_evictable);

    fn smoke_vmhub_distinct_pools() -> TestResult {
        // GFX + MM hubs are separate VMID pools — same PASID
        // gets different VMIDs in each.
        let mut g = VmidPool::new(VmHub::Gfx);
        let mut m = VmidPool::new(VmHub::Mm);
        let _vg = g.bind(7, 0x1000).expect("gfx bind");
        // Saturate gfx so pasid 8 in mm doesn't match gfx vmid by coincidence.
        for p in 2..=14 {
            g.bind(p as Pasid, (p as u64) << 12).expect("gfx fill");
        }
        // mm bind starts fresh from VMID 1.
        let vm = m.bind(7, 0x2000).expect("mm bind");
        if vm != 1 {
            return TestResult::Fail("mm bind didn't get fresh VMID 1");
        }
        if g.hub.name() != "gfxhub" || m.hub.name() != "mmhub" {
            return TestResult::Fail("hub names wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmhub_distinct_pools);

    fn smoke_bind_and_program_writes_mmio() -> TestResult {
        use crate::amdgpu_vmhub_regs::{test_support::MockVmHubMmio, GFXHUB_V3_0};
        let mut p = VmidPool::new(VmHub::Gfx);
        let mut mmio = MockVmHubMmio::new();
        let vmid = p
            .bind_and_program(42, 0xCAFE_0000, &mut mmio, &GFXHUB_V3_0)
            .expect("bind+program");
        if vmid == 0 {
            return TestResult::Fail("got kernel VMID for user PASID");
        }
        // 2 writes: lo + hi PT base.
        if mmio.writes.len() != 2 {
            return TestResult::Fail("expected 2 MMIO writes from bind+program");
        }
        // The lo register write should match the per-VMID stride.
        let want_lo = (GFXHUB_V3_0.ctx0_pt_base_lo + (vmid as u32) * GFXHUB_V3_0.ctx_addr_distance)
            << 2;
        if mmio.writes[0].0 != want_lo {
            return TestResult::Fail("lo register offset wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_bind_and_program_writes_mmio);

    fn smoke_vmidstate_pasid_accessor() -> TestResult {
        let s = VmidState::Bound {
            pasid: 42,
            page_table_root_phys: 0x1000,
            last_use_tag: 99,
        };
        if s.pasid() != Some(42) {
            return TestResult::Fail("pasid accessor failed");
        }
        if VmidState::Free.pasid().is_some() {
            return TestResult::Fail("free has pasid");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_vmidstate_pasid_accessor);
}
