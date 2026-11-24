//! Persistent Xe VM metadata. Each execution receives private immutable tables;
//! binds serialize with prior submissions before publishing a new mapping set.
//!
//! MAP_USERPTR bindings mirror a CPU range (MIT Linux
//! b90c984d615e8ce2af96f5b1411a962d83fed2ad `xe_userptr.c`): each binding
//! registers a `narf_memory::mmu_notifier` interval over its CPU range before
//! pinning, and the pins it publishes carry the interval sequence they were
//! collected under. Exec re-collects every binding invalidated since
//! (`xe_vm_userptr_pin`) before building a job's private tables.
use crate::{
    intel_gpu_exec::VmMapping,
    intel_gpu_fence::CompletionFence,
    intel_gpu_gem::{GemObject, GemState},
    intel_gpu_gt::GtPlatform,
    intel_gpu_uapi::{u32_at, u64_at},
};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_filesystem::{FsError, IoctlContext};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};
use narf_memory::mmu_notifier::{
    MmuInterval, MmuIntervalNotifier, MmuIntervalNotifierOps, MmuNotifierRange,
};

static NEXT_VM: AtomicU64 = AtomicU64::new(1);
pub(crate) const MAX_MAPPINGS: usize = 4096;
pub(crate) const MAX_VA: u64 = 1 << 48;
/// `read_begin`/`read_retry` rounds for one USERPTR collection. Linux
/// `drm_gpusvm_get_pages` retries until `HMM_RANGE_DEFAULT_TIMEOUT` and then
/// fails `-EBUSY`, which bind reports as `-ENOMEM`.
pub(crate) const USERPTR_PIN_ROUNDS: usize = 8;

#[derive(Debug)]
pub(crate) struct Vm {
    pub identity: u64,
    pub scratch: bool,
    pub lr: bool,
    pub fault: bool,
    pub dead: AtomicBool,
    pub state: Mutex<State>,
    /// Published MAP_USERPTR bindings. Changed only with `state` held; the
    /// lock is held only to move the list in or out, never across a pin.
    userptrs: IrqSafeSpinLock<Vec<Userptr>>,
    /// The VM's interval-notifier consumer; holds no VM reference, so the
    /// registry never keeps a destroyed VM alive.
    userptr_ops: Arc<UserptrNotifier>,
}
#[derive(Debug)]
pub(crate) struct State {
    pub mappings: Vec<VmMapping>,
    pub active: Vec<Arc<CompletionFence>>,
}
impl Vm {
    pub fn new(scratch: bool, lr: bool, fault: bool) -> Result<Arc<Self>, FsError> {
        let identity = NEXT_VM
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| FsError::OutOfMemory)?;
        Ok(Arc::new(Self {
            identity,
            scratch,
            lr,
            fault,
            dead: AtomicBool::new(false),
            state: Mutex::new(State {
                mappings: Vec::new(),
                active: Vec::new(),
            }),
            userptrs: IrqSafeSpinLock::new(Vec::new()),
            userptr_ops: Arc::new(UserptrNotifier),
        }))
    }
    pub fn check(&self) -> Result<(), FsError> {
        if self.dead.load(Ordering::Acquire) {
            Err(FsError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Track the MAP_USERPTR bindings a bind just published and forget every
    /// binding no published mapping names any more. A forgotten binding's
    /// interval is removed; jobs that still hold its pins keep them, and so
    /// its frames, until they retire. Call with `state` held, after
    /// [`State::publish`]; it does not await.
    pub fn adopt_userptrs(&self, mappings: &[VmMapping], fresh: Vec<Userptr>) {
        let mut records = core::mem::take(&mut *self.userptrs.lock());
        records.extend(fresh);
        records.retain(|record| mappings.iter().any(|mapping| record.names(mapping)));
        *self.userptrs.lock() = records;
    }

    /// `__xe_vm_userptr_needs_repin`: some binding was invalidated after its
    /// pins were collected. Exec checks this after building a job's tables
    /// and rebuilds them if so (`xe_exec_ioctl`'s `-EAGAIN` retry).
    pub fn userptrs_stale(&self) -> bool {
        self.userptrs.lock().iter().any(Userptr::stale)
    }

    /// `xe_vm_userptr_pin` and the rebind that follows it (non-fault VM),
    /// with `state` held: re-collect every invalidated binding before a job
    /// is built from the published mappings. Each mapping slice naming an
    /// invalidated binding is re-collected over exactly its CPU range under a
    /// fresh interval, as Linux splits a USERPTR VMA's notifier with the VMA.
    ///
    /// A slice whose range is gone (`EFAULT`: unmapped, or the binder's
    /// address space has exited) is removed from the mappings, as
    /// `xe_vm_userptr_pin` invalidates the VMA's GPU mapping, and the exec
    /// proceeds. Any other error (`EPERM` for a writable binding over memory
    /// made read-only, `ENOMEM`, `EBUSY` when every collection round was
    /// raced) fails the exec with nothing republished; the
    /// bindings stay invalidated and the next exec retries. Linux collects
    /// through the binder's mm from any caller; here only the binder's own
    /// address space can (`ENOSYS` from another process).
    pub fn revalidate_userptrs(
        &self,
        state: &mut State,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        if !self.userptrs_stale() {
            return Ok(());
        }
        // Bindings change only under `state`, which the caller holds, so the
        // list is worked on unlocked (pins fault user memory) and put back.
        let mut records = core::mem::take(&mut *self.userptrs.lock());
        let outcome = self
            .recollect(&records, &state.mappings, user)
            .map(|(mappings, fresh)| {
                state.publish(mappings);
                records.extend(fresh);
                records.retain(|record| state.mappings.iter().any(|m| record.names(m)));
            });
        *self.userptrs.lock() = records;
        outcome
    }

    /// The replacement mapping set and bindings for every invalidated
    /// binding in `records`; see [`Self::revalidate_userptrs`].
    fn recollect(
        &self,
        records: &[Userptr],
        published: &[VmMapping],
        user: &dyn IoctlContext,
    ) -> Result<(Vec<VmMapping>, Vec<Userptr>), FsError> {
        let caller = user.address_space_identity();
        let mut mappings = published.to_vec();
        let mut gone = Vec::new();
        let mut fresh = Vec::new();
        for record in records.iter().filter(|record| record.stale()) {
            for (index, mapping) in mappings.iter_mut().enumerate() {
                if !record.names(mapping) {
                    continue;
                }
                let released = record.notifier.is_released();
                if !released && caller != Some(record.notifier.address_space_id()) {
                    return Err(FsError::NotImplemented);
                }
                let collected = if released {
                    Err(FsError::BadAddress)
                } else {
                    pin_userptr(
                        self,
                        user,
                        record.address + mapping.offset,
                        mapping.length,
                        record.writable,
                    )
                };
                match collected {
                    Ok((object, mirror)) => {
                        mapping.object = Some(object);
                        mapping.offset = 0;
                        fresh.push(mirror);
                    }
                    Err(FsError::BadAddress) => gone.push(index),
                    Err(error) => return Err(error),
                }
            }
        }
        let mut index = 0;
        mappings.retain(|_| {
            index += 1;
            !gone.contains(&(index - 1))
        });
        Ok((mappings, fresh))
    }
}

/// The VM's interval-notifier consumer (`vma_userptr_invalidate`). It runs
/// under the CPU address space's IRQ-masked mapping locks and must not block,
/// so it cannot wait for the VM's jobs as Linux does, and it has nothing
/// else to do: the registry has already published the new sequence, which
/// exec compares before building and again before submitting a job (the
/// `invalidated` list Linux moves the VMA to), and every running job holds
/// the pins it was built with until it retires, so the GPU never reaches a
/// released frame. Jobs submitted before the invalidation finish against
/// those retained frames instead of being waited for.
#[derive(Debug, Default)]
pub(crate) struct UserptrNotifier;

impl MmuIntervalNotifierOps for UserptrNotifier {
    fn invalidate(&self, _interval: &MmuInterval, _range: &MmuNotifierRange, _cur_seq: u64) {}
}

/// One published MAP_USERPTR binding: the interval over its CPU range and
/// the pinned object every mapping slice of the binding names.
#[derive(Debug)]
pub(crate) struct Userptr {
    notifier: MmuIntervalNotifier,
    /// CPU address of the object's first page.
    address: u64,
    /// Interval sequence the object's pins were collected under.
    seq: u64,
    object: Weak<GemObject>,
    writable: bool,
}

impl Userptr {
    fn names(&self, mapping: &VmMapping) -> bool {
        mapping
            .object
            .as_ref()
            .is_some_and(|object| core::ptr::eq(Arc::as_ptr(object), self.object.as_ptr()))
    }

    fn stale(&self) -> bool {
        self.notifier.read_retry(self.seq)
    }
}

/// `xe_vma_userptr_pin_pages`: register an interval over
/// `[address, address + length)` of the caller's address space, then collect
/// the range inside `read_begin`/`read_retry` until no invalidation raced
/// the collection.
fn pin_userptr(
    vm: &Vm,
    user: &dyn IoctlContext,
    address: u64,
    length: u64,
    writable: bool,
) -> Result<(Arc<GemObject>, Userptr), FsError> {
    let notifier = user.mmu_interval_notifier(address, length, vm.userptr_ops.clone())?;
    for _ in 0..USERPTR_PIN_ROUNDS {
        let seq = notifier.read_begin();
        let pins = user.pin_user_pages(address, length / 4096, writable)?;
        if notifier.read_retry(seq) {
            continue;
        }
        let object = GemObject::from_user_pins(pins, vm.identity)?;
        let mirror = Userptr {
            notifier,
            address,
            seq,
            object: Arc::downgrade(&object),
            writable,
        };
        return Ok((object, mirror));
    }
    // drm_gpusvm_get_pages' -EBUSY: exec returns it; bind maps it to ENOMEM.
    Err(FsError::Busy)
}

#[derive(Debug)]
pub(crate) struct Bind {
    pub object: Option<Arc<crate::intel_gpu_gem::GemObject>>,
    pub address: u64,
    pub length: u64,
    pub op: u32,
    pub mapping: Option<VmMapping>,
    /// MAP_USERPTR source address, pinned only after every op's arguments
    /// validate (Linux checks all ops before faulting any pages).
    pub userptr: Option<u64>,
    /// The collected MAP_USERPTR binding, adopted when the bind publishes.
    pub mirror: Option<Userptr>,
    /// DRM_XE_VM_BIND_OP_PREFETCH target memory region (0 = sysmem, 1 = VRAM).
    pub prefetch_region: u32,
}

/// One programmed PAT index (xe_pat.c): whether it snoops CPU caches
/// (`coh_mode` at least one-way) and whether it compresses through flat CCS
/// (`XE2_COMP_EN`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PatEntry {
    pub coherent: bool,
    pub compressed: bool,
}

/// The PAT table the GT owner programs, indexed as userspace names it.
/// `None` for an index past `n_entries` or a hardware-reserved one, which
/// Linux refuses (`vm_bind_ioctl_check_args`). Gen9/Gen11 bind through the
/// i915 node, never this table.
pub(crate) fn pat_entry(platform: GtPlatform, pat: u16) -> Option<PatEntry> {
    let plain = |coherent| {
        Some(PatEntry {
            coherent,
            compressed: false,
        })
    };
    match platform {
        // xelp_pat_table: PAT0 WB (at least one-way), PAT1 WC, PAT2 WT,
        // PAT3 UC.
        GtPlatform::ArcticSoundM | GtPlatform::Alchemist | GtPlatform::Gen12(_) => match pat {
            0 => plain(true),
            1..=3 => plain(false),
            _ => None,
        },
        GtPlatform::Gen11(_) | GtPlatform::Gen9(_) => None,
        _ if platform.is_xe2() => {
            let value = crate::intel_gpu_gt_hw::xe2_pat_value(platform, pat)?;
            Some(PatEntry {
                coherent: value & crate::intel_gpu_gt_hw::XE2_COH_MODE != 0,
                compressed: value & crate::intel_gpu_gt_hw::XE2_COMP_EN != 0,
            })
        }
        GtPlatform::Battlemage | GtPlatform::WildcatLake | GtPlatform::NovaLakeS => {
            unreachable!("Xe2 handled above")
        }
        // xelpg_pat_table: the coherency mode is the entry's low two bits.
        GtPlatform::Integrated(_) => crate::intel_gpu_gt::media::XELPG_PAT
            .get(usize::from(pat))
            .and_then(|value| plain(value & 3 != 0)),
    }
}

/// PAT indices coherent with CPU caches, admitted for any object.
pub(crate) fn pat_allowed(platform: GtPlatform, pat: u16) -> bool {
    pat_entry(platform, pat).is_some_and(|entry| entry.coherent)
}

/// XE_COH_NONE indices, admitted only for objects created without
/// write-back CPU caching (`xe_vm_bind_ioctl_validate_bo`).
pub(crate) fn pat_noncoherent(platform: GtPlatform, pat: u16) -> bool {
    pat_entry(platform, pat).is_some_and(|entry| !entry.coherent)
}

/// Indices that compress through flat CCS (Xe2/Xe3 only).
pub(crate) fn pat_compressed(platform: GtPlatform, pat: u16) -> bool {
    pat_entry(platform, pat).is_some_and(|entry| entry.compressed)
}

impl Bind {
    /// The object a MAP names through a compressed PAT index.
    pub(crate) fn compressed_object(&self, platform: GtPlatform) -> Option<Arc<GemObject>> {
        self.mapping
            .as_ref()
            .filter(|mapping| pat_compressed(platform, u16::from(mapping.pat)))
            .and_then(|mapping| mapping.object.clone())
    }

    pub fn read(
        wire: &[u8],
        vm: &Vm,
        gem: &GemState,
        platform: GtPlatform,
    ) -> Result<Self, FsError> {
        if u64_at(wire, 0) != 0 || wire[14..16] != [0; 2] || wire[52..80].iter().any(|b| *b != 0) {
            return Err(FsError::InvalidData);
        }
        let object = u32_at(wire, 8);
        let pat = u16::from_le_bytes(wire[12..14].try_into().unwrap());
        let offset = u64_at(wire, 16);
        let length = u64_at(wire, 24);
        let address = u64_at(wire, 32);
        let op = u32_at(wire, 40);
        let flags = u32_at(wire, 44);
        // op > DRM_XE_VM_BIND_OP_PREFETCH is EINVAL; PREFETCH itself is a
        // valid operation that this VM does not implement.
        if flags & !0x1f != 0 || u32_at(wire, 48) != 0 || op > 4 {
            return Err(FsError::InvalidData);
        }
        if op == 3 {
            if object == 0 || address != 0 || length != 0 || flags & 4 != 0 {
                return Err(FsError::InvalidData);
            }
            return Ok(Self {
                object: Some(gem.object(object)?),
                address,
                length,
                op,
                mapping: None,
                userptr: None,
                mirror: None,
                prefetch_region: 0,
            });
        }
        if address % 4096 != 0
            || length == 0
            || length % 4096 != 0
            || address.checked_add(length).is_none_or(|end| end > MAX_VA)
        {
            return Err(FsError::InvalidData);
        }
        if op == 1 {
            if object != 0 || flags & 4 != 0 {
                return Err(FsError::InvalidData);
            }
            return Ok(Self {
                object: None,
                address,
                length,
                op,
                mapping: None,
                userptr: None,
                mirror: None,
                prefetch_region: 0,
            });
        }
        if op == 2 {
            // DRM_XE_VM_BIND_OP_MAP_USERPTR (vm_bind_ioctl_check_args): no
            // object, not NULL, a coherent uncompressed PAT and an aligned
            // address.
            if object != 0
                || flags & 4 != 0
                || !pat_allowed(platform, pat)
                || pat_compressed(platform, pat)
                || offset % 4096 != 0
            {
                return Err(FsError::InvalidData);
            }
            return Ok(Self {
                object: None,
                address,
                length,
                op: 0,
                mapping: Some(VmMapping {
                    dumpable: flags & 8 != 0,
                    object: None,
                    va: address,
                    offset: 0,
                    length,
                    writable: flags & 1 == 0,
                    pat: pat as u8,
                }),
                userptr: Some(offset),
                mirror: None,
                prefetch_region: 0,
            });
        }
        if op == 4 {
            // DRM_XE_VM_BIND_OP_PREFETCH: requires FAULT_MODE, no BO or NULL
            // flag, and a valid target memory region (0 = sysmem, 1 = VRAM0).
            if !vm.fault
                || object != 0
                || flags & 4 != 0
                || offset > u64::from(platform.is_discrete())
            {
                return Err(FsError::InvalidData);
            }
            return Ok(Self {
                object: None,
                address,
                length,
                op: 4,
                mapping: None,
                userptr: None,
                mirror: None,
                prefetch_region: offset as u32,
            });
        }
        if op != 0 {
            return Err(FsError::InvalidData);
        }
        let null = flags & 4 != 0;
        let entry = pat_entry(platform, pat);
        let object_arc = if null {
            if object != 0 || offset != 0 || flags & 1 != 0 || entry.is_none() {
                return Err(FsError::InvalidData);
            }
            None
        } else {
            let Some(entry) = entry.filter(|_| offset % 4096 == 0) else {
                return Err(FsError::InvalidData);
            };
            let object = gem.object(object)?;
            if object.is_vram()
                && object.vram_page_size() == 65536
                && (!platform.is_dg2() || (address | offset | length) & 65535 != 0)
            {
                return Err(FsError::InvalidData);
            }
            // xe_vm_bind_ioctl_validate_bo: XE_COH_NONE on a WB object would
            // let the GPU miss dirty CPU lines (or the CPU miss GPU writes),
            // and a NO_COMPRESSION object takes no compressed index.
            if (!entry.coherent && object.cpu_caching_wb())
                || (entry.compressed && object.no_compression())
                || object.vm_owner().is_some_and(|owner| owner != vm.identity)
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > object.size())
            {
                return Err(FsError::InvalidData);
            }
            Some(object)
        };
        Ok(Self {
            object: None,
            address,
            length,
            op,
            mapping: Some(VmMapping {
                dumpable: flags & 8 != 0,
                object: object_arc,
                va: address,
                offset,
                length,
                writable: flags & 1 == 0,
                pat: pat as u8,
            }),
            userptr: None,
            mirror: None,
            prefetch_region: 0,
        })
    }

    /// Fault in and pin a MAP_USERPTR range (write-resolving unless READONLY)
    /// as a VM-private object, under an interval notifier registered first
    /// (`xe_userptr_setup` then `xe_vma_userptr_pin_pages`). Pins are lifetime
    /// holds: jobs and mappings retain them, so the GPU never reaches freed
    /// memory; the notifier makes exec re-collect the range once the CPU
    /// mapping changes. An invalidation racing every collection round is
    /// `-EBUSY` from `drm_gpusvm_get_pages`, which bind reports as `ENOMEM`.
    pub fn pin(&mut self, vm: &Vm, user: &dyn IoctlContext) -> Result<(), FsError> {
        let Some(address) = self.userptr else {
            return Ok(());
        };
        let mapping = self.mapping.as_mut().expect("userptr mapping");
        // new_vma: "-EBUSY ... can only fail with -EBUSY if we are low on
        // memory so convert this to -ENOMEM".
        let (object, mirror) = pin_userptr(vm, user, address, mapping.length, mapping.writable)
            .map_err(|error| match error {
                FsError::Busy => FsError::OutOfMemory,
                error => error,
            })?;
        mapping.object = Some(object);
        self.mirror = Some(mirror);
        Ok(())
    }
}

/// Remove an interval, preserving left/right slices and their object offsets.
fn remove(mappings: &mut Vec<VmMapping>, start: u64, length: u64) {
    let end = start + length;
    let mut retained = Vec::new();
    for mapping in mappings.drain(..) {
        let limit = mapping.va + mapping.length;
        if limit <= start || mapping.va >= end {
            retained.push(mapping);
            continue;
        }
        if mapping.va < start {
            let mut left = mapping.clone();
            left.length = start - mapping.va;
            retained.push(left);
        }
        if limit > end {
            let mut right = mapping;
            right.offset += end - right.va;
            right.va = end;
            right.length = limit - end;
            retained.push(right);
        }
    }
    *mappings = retained;
}

impl State {
    /// Publish a prepared mapping set. Objects it names count as VM-bound
    /// while it is published (Linux xe_bo_is_vm_bound).
    pub fn publish(&mut self, mappings: Vec<VmMapping>) {
        for object in mappings.iter().filter_map(|m| m.object.as_ref()) {
            object.vm_bind();
        }
        for object in self.mappings.iter().filter_map(|m| m.object.as_ref()) {
            object.vm_unbind();
        }
        self.mappings = mappings;
    }

    pub fn prepare(&self, binds: &[Bind], scratch: bool) -> Result<Vec<VmMapping>, FsError> {
        let mut mappings = self.mappings.clone();
        for bind in binds {
            if bind.op == 4 {
                if !crate::intel_gpu_exec::mappings_cover_any(
                    &mappings,
                    bind.address,
                    bind.length,
                    false,
                ) {
                    return Err(FsError::InvalidData);
                }
                continue;
            }
            if bind.op == 3 {
                let object = bind.object.as_ref().expect("retained unmap object");
                mappings.retain(|m| {
                    !m.object
                        .as_ref()
                        .is_some_and(|old| Arc::ptr_eq(old, object))
                });
            } else {
                if (bind.address | bind.length) & 65535 != 0
                    && mappings.iter().any(|m| {
                        m.va < bind.address + bind.length
                            && bind.address < m.va + m.length
                            && m.object
                                .as_ref()
                                .is_some_and(|o| o.is_vram() && o.vram_page_size() == 65536)
                    })
                {
                    return Err(FsError::InvalidData);
                }
                remove(&mut mappings, bind.address, bind.length);
                if let Some(mapping) = &bind.mapping {
                    mappings.push(mapping.clone());
                }
            }
            if mappings.len() > MAX_MAPPINGS {
                return Err(FsError::OutOfMemory);
            }
        }
        mappings.sort_unstable_by_key(|m| m.va);
        let bytes = mappings
            .iter()
            .filter(|m| m.object.is_some() || !scratch)
            .try_fold(0u64, |sum, m| sum.checked_add(m.length))
            .ok_or(FsError::OutOfMemory)?;
        if bytes > 512 * 1024 * 1024 {
            return Err(FsError::OutOfMemory);
        }
        Ok(mappings)
    }

    pub async fn retire(&mut self) -> Result<(), FsError> {
        for fence in &self.active {
            fence
                .wait()
                .await
                .map_err(|_| crate::intel_gpu_user::io_error())?;
        }
        self.active.clear();
        Ok(())
    }
}

impl Drop for State {
    fn drop(&mut self) {
        for object in self.mappings.iter().filter_map(|m| m.object.as_ref()) {
            object.vm_unbind();
        }
    }
}

pub(crate) fn read(
    user: &dyn IoctlContext,
    address: u64,
    count: usize,
) -> Result<Vec<u8>, FsError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    address
        .checked_add(count as u64)
        .ok_or(FsError::BadAddress)?;
    let mut wire = alloc::vec![0; count];
    user.read(address, &mut wire)?;
    Ok(wire)
}
pub(crate) fn zero(wire: &[u8]) -> Result<(), FsError> {
    if wire.iter().any(|byte| *byte != 0) {
        Err(FsError::InvalidData)
    } else {
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_xe_vm_interval_split_replace_and_atomic_failure() -> TestResult {
        let gem = GemState::new();
        let mut handle = 0;
        gem.create(16384, |h, _| {
            handle = h;
            Ok(())
        })
        .unwrap();
        let mut state = State {
            mappings: Vec::new(),
            active: Vec::new(),
        };
        state.publish(alloc::vec![VmMapping {
            dumpable: false,
            object: Some(gem.object(handle).unwrap()),
            va: 0x10000,
            offset: 0,
            length: 16384,
            writable: true,
            pat: 2,
        }]);
        assert!(gem.object(handle).unwrap().vm_bound());
        let unmap = Bind {
            object: None,
            address: 0x11000,
            length: 8192,
            op: 1,
            mapping: None,
            userptr: None,
            mirror: None,
            prefetch_region: 0,
        };
        let mapped = state.prepare(&[unmap], true).unwrap();
        assert_eq!(
            mapped
                .iter()
                .map(|m| (m.va, m.offset, m.length))
                .collect::<Vec<_>>(),
            [(0x10000, 0, 4096), (0x13000, 12288, 4096)]
        );
        assert_eq!(
            state.mappings.len(),
            1,
            "preparation mutated the published VM"
        );
        drop(mapped);
        let replace = Bind {
            object: None,
            address: 0x11000,
            length: 8192,
            op: 0,
            mapping: Some(VmMapping {
                dumpable: false,
                object: None,
                va: 0x11000,
                offset: 0,
                length: 8192,
                writable: true,
                pat: 0,
            }),
            userptr: None,
            mirror: None,
            prefetch_region: 0,
        };
        let mapped = state.prepare(&[replace], true).unwrap();
        assert_eq!(mapped.len(), 3);
        assert!(mapped[1].object.is_none());
        assert_eq!(mapped[2].offset, 12288);
        drop(mapped);
        let weak = Arc::downgrade(&gem.object(handle).unwrap());
        let all = Bind {
            object: Some(gem.object(handle).unwrap()),
            address: 0,
            length: 0,
            op: 3,
            mapping: None,
            userptr: None,
            mirror: None,
            prefetch_region: 0,
        };
        gem.close(handle).unwrap();
        let mapped = state.prepare(&[all], true).unwrap();
        assert!(mapped.is_empty());
        assert!(weak.upgrade().is_some());
        drop(state);
        assert!(weak.upgrade().is_none());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe",
        smoke_xe_vm_interval_split_replace_and_atomic_failure
    );
}
