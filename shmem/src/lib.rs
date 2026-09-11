//! narf-shmem — userspace-mappable shared-memory handles.
//!
//! Named `Shmem` objects are kernel-allocated, page-aligned regions of coherent
//! frames owned by a process pid. The handle is the public name; userspace maps
//! the region via `SYS_SHMEM_MAP`. Anonymous `MAP_SHARED` backing instead has
//! no public handle and carries per-page references in a sharded registry.
//! Kernel-side consumers (audio's tx ring, fb's blit source) read pixel/PCM
//! data through named objects' same frames via the identity map.
//!
//! Surface mirrors `narf-fb`'s registry pattern: a static
//! registry, a monotonic id allocator, and an exit-observer
//! reaper hooked into `narf-userspace`.
//!
//! Today's per-handle limit is 256 frames (1 MiB). Audio playback
//! buffers (~64-128 KiB), small blit sources (icons, glyph
//! atlases), and ring-shaped command queues all fit comfortably.
//! Larger consumers (full-screen blit, gpu command buffers) lift
//! the cap once a real use case materialises.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{Cap, CapKind, CapType, Read, Write};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

/// Cap-typed authority over a shmem region. `Read` = mappable
/// read-only; `Write` = read+write. The handle id is the public
/// name; the cap is the gate.
#[derive(Copy, Clone, Debug)]
pub struct ShmemCap;

impl CapType for ShmemCap {
    const KIND: CapKind = CapKind::DmaBuffer;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShmemError {
    OutOfMemory,
    BadLen,
    NotFound,
    NotOwner,
}

const PAGE: u64 = 4096;
const MAX_PAGES_PER_HANDLE: usize = 256; // 1 MiB

/// One live shared-memory region.
pub struct Entry {
    pub handle: u64,
    pub pid: u64,
    pub frames: Vec<u64>, // phys addrs, page-sized
    /// Number of live user mappings for each backing frame.
    pub refs: Vec<u32>,
    pub len: u64,
    /// User whose RLIMIT_MEMLOCK accounting owns this SHM_LOCK charge.
    pub locked_user: Option<(u64, u32)>,
    /// IPC_RMID/process exit has removed the public handle. Existing
    /// mappings remain valid until their final per-page reference drops.
    pub removed: bool,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("handle", &self.handle)
            .field("pid", &self.pid)
            .field("len", &self.len)
            .field("frames", &self.frames.len())
            .field("removed", &self.removed)
            .finish_non_exhaustive()
    }
}

// Keep entries indirect: stressors can have thousands of live SysV segments,
// while each entry remains a small independent allocation.  The secondary
// indexes keep handle, backing-frame, owner-exit, and SHM_LOCK-accounting
// operations from scanning every live and IPC_RMID-retained segment.
#[allow(clippy::vec_box)]
#[derive(Default)]
struct Registry {
    entries: BTreeMap<u64, Box<Entry>>,
    frames: BTreeMap<u64, (u64, usize)>,
    owners: BTreeMap<u64, BTreeSet<u64>>,
    locked_bytes: BTreeMap<(u64, u32), u64>,
    live: usize,
}

static REGISTRY: IrqSafeSpinLock<Option<Registry>> = IrqSafeSpinLock::new(None);
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

// Anonymous MAP_SHARED objects have no public handle after mmap returns. Keep
// their lifetime directly beside each backing-page identity rather than
// routing every retain/drop through the named-object registry above. Linux's
// shmem pages likewise carry per-page references; 64 cache-line-isolated
// shards let unrelated processes map and unmap concurrently.
const ANON_PAGE_SHARDS: usize = 64;

#[repr(align(64))]
struct AnonymousPageShard {
    refs: IrqSafeSpinLock<Option<BTreeMap<u64, u32>>>,
}

impl AnonymousPageShard {
    const fn new() -> Self {
        Self {
            refs: IrqSafeSpinLock::new(None),
        }
    }
}

static ANONYMOUS_PAGES: [AnonymousPageShard; ANON_PAGE_SHARDS] =
    [const { AnonymousPageShard::new() }; ANON_PAGE_SHARDS];

#[inline]
fn anonymous_page_shard(phys: u64) -> usize {
    (phys >> 12) as usize & (ANON_PAGE_SHARDS - 1)
}

fn with_registry<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    let mut registry = REGISTRY.lock();
    f(registry.get_or_insert_with(Registry::default))
}

fn allocate_zeroed_frames(len: u64) -> Result<(u64, Vec<u64>), ShmemError> {
    if len == 0 {
        return Err(ShmemError::BadLen);
    }
    let len_pg = len
        .checked_add(PAGE - 1)
        .map(|value| value & !(PAGE - 1))
        .ok_or(ShmemError::BadLen)?;
    let pages = (len_pg / PAGE) as usize;
    if pages > MAX_PAGES_PER_HANDLE {
        return Err(ShmemError::BadLen);
    }
    let mut frames = Vec::with_capacity(pages);
    for _ in 0..pages {
        let frame = match narf_memory::alloc_frame() {
            Ok(frame) => frame,
            Err(_) => {
                free_phys_frames(frames);
                return Err(ShmemError::OutOfMemory);
            }
        };
        let phys = frame.start_address().raw();
        // SAFETY: this freshly allocated frame is exclusively owned here and
        // is reachable through the kernel direct map.
        unsafe {
            core::ptr::write_bytes(PhysAddr::new(phys).kernel_mut_ptr::<u8>(), 0, PAGE as usize);
        }
        frames.push(phys);
    }
    Ok((len_pg, frames))
}

/// Allocate a fresh shared-memory region of `len` bytes (rounded
/// up to a page). Returns the new handle id (>0).
pub fn create(pid: u64, len: u64) -> Result<u64, ShmemError> {
    let (len_pg, frames) = allocate_zeroed_frames(len)?;
    let pages = frames.len();
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let entry = Box::new(Entry {
        handle,
        pid,
        frames,
        refs: alloc::vec![0; pages],
        len: len_pg,
        locked_user: None,
        removed: false,
    });
    with_registry(|registry| {
        for (page, phys) in entry.frames.iter().copied().enumerate() {
            assert!(
                registry.frames.insert(phys, (handle, page)).is_none(),
                "shmem frame already indexed"
            );
        }
        registry.owners.entry(pid).or_default().insert(handle);
        registry.live = registry.live.checked_add(1).expect("shmem live overflow");
        assert!(
            registry.entries.insert(handle, entry).is_none(),
            "duplicate shmem handle"
        );
    });
    Ok(handle)
}

/// Allocate an unnamed anonymous shared object and return its page snapshot.
/// Each returned page carries one creator reference. The mmap path releases
/// that reference after publishing (or abandoning) the VMA; mapping and fork
/// references are retained through the ordinary shared-frame hooks.
fn vt_create_anonymous(len: u64, out: &mut Vec<u64>) -> bool {
    let (_, frames) = match allocate_zeroed_frames(len) {
        Ok(result) => result,
        Err(_) => return false,
    };
    for &phys in &frames {
        let mut guard = ANONYMOUS_PAGES[anonymous_page_shard(phys)].refs.lock();
        let refs = guard.get_or_insert_with(BTreeMap::new);
        assert!(
            refs.insert(phys, 1).is_none(),
            "anonymous shmem frame already indexed"
        );
    }
    out.clear();
    out.extend_from_slice(&frames);
    true
}

/// Phys addr at `byte_offset` into the region. Used by kernel-
/// side consumers (audio submit, fb blit) to translate a
/// (handle, offset) pair into a phys for DMA. Returns `None` on
/// bad handle or out-of-range offset.
pub fn phys_at(handle: u64, byte_offset: u64) -> Option<u64> {
    let g = REGISTRY.lock();
    let e = g.as_ref()?.entries.get(&handle).filter(|e| !e.removed)?;
    if byte_offset >= e.len {
        return None;
    }
    let page_idx = (byte_offset / PAGE) as usize;
    let intra = byte_offset & (PAGE - 1);
    Some(e.frames[page_idx] + intra)
}

/// Scatter-gather descriptor: one physically-contiguous run within
/// a shmem region. Drivers iterate these to build per-segment
/// device-side descriptors (virtio chained desc, NVMe PRP/SGL,
/// GPU command-buffer entries).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SgEntry {
    pub phys: u64,
    pub len: u32,
}

/// Walk a `(handle, byte_offset, byte_len)` slice as scatter-
/// gather entries. Each entry is bounded above by `byte_len`,
/// the page boundary, and the region's end. Returns `None` if
/// the handle is unknown or `(byte_offset + byte_len)` exceeds
/// the region.
///
/// # Example
/// A 7000-byte slice starting at offset 100 of a 2-page region
/// yields two entries:
/// - `(frame0 + 100, 4096 - 100 = 3996)`
/// - `(frame1, 7000 - 3996 = 3004)`
pub fn sg_iter(handle: u64, byte_offset: u64, byte_len: u64) -> Option<SgIter> {
    let g = REGISTRY.lock();
    let e = g.as_ref()?.entries.get(&handle).filter(|e| !e.removed)?;
    let end = byte_offset.checked_add(byte_len)?;
    if end > e.len {
        return None;
    }
    Some(SgIter {
        frames: e.frames.clone(),
        cursor: byte_offset,
        remaining: byte_len,
    })
}

/// Iterator returned by [`sg_iter`]. `Iterator::Item` is one
/// `SgEntry` per contiguous page-bounded run.
#[derive(Debug)]
pub struct SgIter {
    frames: Vec<u64>,
    cursor: u64,
    remaining: u64,
}

impl Iterator for SgIter {
    type Item = SgEntry;
    fn next(&mut self) -> Option<SgEntry> {
        if self.remaining == 0 {
            return None;
        }
        let page_idx = (self.cursor / PAGE) as usize;
        let intra = self.cursor & (PAGE - 1);
        let in_page = PAGE - intra;
        let take = in_page.min(self.remaining);
        let phys = self.frames[page_idx] + intra;
        self.cursor += take;
        self.remaining -= take;
        Some(SgEntry {
            phys,
            len: take as u32,
        })
    }
}

/// Snapshot of the per-page phys list, for the syscall handler
/// that installs the user-VA mapping.
pub fn frames_of(handle: u64) -> Option<Vec<PhysAddr>> {
    let g = REGISTRY.lock();
    let e = g.as_ref()?.entries.get(&handle).filter(|e| !e.removed)?;
    Some(e.frames.iter().copied().map(PhysAddr::new).collect())
}

/// Total length (page-rounded) of the region.
pub fn len_of(handle: u64) -> Option<u64> {
    REGISTRY
        .lock()
        .as_ref()?
        .entries
        .get(&handle)
        .filter(|e| !e.removed)
        .map(|e| e.len)
}

/// Owner pid of the region.
pub fn pid_of(handle: u64) -> Option<u64> {
    REGISTRY
        .lock()
        .as_ref()?
        .entries
        .get(&handle)
        .filter(|e| !e.removed)
        .map(|e| e.pid)
}

fn free_phys_frames(frames: Vec<u64>) {
    for phys in frames {
        narf_memory::free_frame(narf_memory::PhysFrame::new(PhysAddr::new(phys)));
    }
}

/// Reclaim unreferenced pages of a removed entry. Returns frames that must be
/// freed after the registry lock is released.
fn reap_removed_entry(registry: &mut Registry, handle: u64) -> Vec<u64> {
    let mut reclaim = Vec::new();
    let fully_reaped = {
        let Some(entry) = registry.entries.get_mut(&handle) else {
            return reclaim;
        };
        if !entry.removed {
            return reclaim;
        }
        for page in 0..entry.frames.len() {
            if entry.frames[page] != 0 && entry.refs[page] == 0 {
                reclaim.push(core::mem::take(&mut entry.frames[page]));
            }
        }
        entry.frames.iter().all(|phys| *phys == 0)
    };
    for phys in &reclaim {
        let removed = registry.frames.remove(phys);
        debug_assert!(removed.is_some(), "reclaimed shmem frame was not indexed");
    }
    if fully_reaped {
        let entry = registry
            .entries
            .remove(&handle)
            .expect("reaped shmem entry disappeared");
        if let Some(user) = entry.locked_user {
            let charge = registry
                .locked_bytes
                .get_mut(&user)
                .expect("locked shmem entry had no user charge");
            *charge = charge
                .checked_sub(entry.len)
                .expect("shmem lock charge underflow");
            if *charge == 0 {
                registry.locked_bytes.remove(&user);
            }
        }
    }
    reclaim
}

/// Remove a region's public handle. Unmapped pages are reclaimed immediately;
/// pages in existing mappings remain alive until their last alias disappears.
pub fn destroy(handle: u64) -> bool {
    let reclaim = with_registry(|registry| {
        let entry = registry.entries.get_mut(&handle).filter(|e| !e.removed)?;
        let pid = entry.pid;
        entry.removed = true;
        registry.live = registry.live.checked_sub(1).expect("shmem live underflow");
        if let Some(handles) = registry.owners.get_mut(&pid) {
            handles.remove(&handle);
            if handles.is_empty() {
                registry.owners.remove(&pid);
            }
        }
        Some(reap_removed_entry(registry, handle))
    });
    let Some(reclaim) = reclaim else {
        return false;
    };
    free_phys_frames(reclaim);
    true
}

/// Destroy every region owned by `pid`. Called from the process-
/// exit observer wired in `register_initcalls`.
pub fn destroy_all_for_pid(pid: u64) -> u32 {
    let (removed, reclaim) = with_registry(|registry| {
        let handles = registry.owners.remove(&pid).unwrap_or_default();
        let removed = u32::try_from(handles.len()).unwrap_or(u32::MAX);
        let mut reclaim = Vec::new();
        for handle in handles {
            let entry = registry
                .entries
                .get_mut(&handle)
                .expect("shmem owner index named a missing entry");
            debug_assert!(!entry.removed);
            entry.removed = true;
            registry.live = registry.live.checked_sub(1).expect("shmem live underflow");
            reclaim.extend(reap_removed_entry(registry, handle));
        }
        (removed, reclaim)
    });
    free_phys_frames(reclaim);
    removed
}

/// Number of live regions — for diagnostics + tests.
pub fn count() -> usize {
    REGISTRY.lock().as_ref().map_or(0, |registry| registry.live)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let mut frames: Vec<u64> = {
        let mut registry = REGISTRY.lock();
        core::mem::take(&mut *registry)
            .unwrap_or_default()
            .entries
            .into_iter()
            .flat_map(|(_, entry)| entry.frames)
            .filter(|phys| *phys != 0)
            .collect()
    };
    for shard in &ANONYMOUS_PAGES {
        if let Some(refs) = core::mem::take(&mut *shard.refs.lock()) {
            frames.extend(refs.into_keys());
        }
    }
    free_phys_frames(frames);
    NEXT_HANDLE.store(1, Ordering::Relaxed);
}

// ── Syscall vtable ──────────────────────────────────────────────────

/// Vtable installed in `narf_userspace::handlers`. Same shape as
/// the FB vtable: each fn pointer is the kernel-side
/// implementation of one syscall.
pub fn syscall_vtable() -> &'static narf_userspace::handlers::ShmemSyscallVtable {
    use narf_userspace::handlers::ShmemSyscallVtable;
    static V: ShmemSyscallVtable = ShmemSyscallVtable {
        create: vt_create,
        create_anonymous: vt_create_anonymous,
        max_len: vt_max_len,
        len_of: vt_len_of,
        frames: vt_frames,
        destroy: vt_destroy,
        pid_of: vt_pid_of,
        owns_frame: vt_owns_frame,
        frame_locked: vt_frame_locked,
        lock: vt_lock,
        unlock: vt_unlock,
        replace_frame: vt_replace_frame,
        retain_frame: vt_retain_frame,
        release_frame: vt_release_frame,
    };
    &V
}

fn vt_max_len() -> u64 {
    MAX_PAGES_PER_HANDLE as u64 * PAGE
}

fn vt_retain_frame(phys: u64) -> bool {
    {
        let mut guard = ANONYMOUS_PAGES[anonymous_page_shard(phys)].refs.lock();
        if let Some(count) = guard.as_mut().and_then(|refs| refs.get_mut(&phys)) {
            *count = count
                .checked_add(1)
                .expect("anonymous shmem mapping reference overflow");
            return true;
        }
    }
    with_registry(|registry| {
        let Some(&(handle, page)) = registry.frames.get(&phys) else {
            return false;
        };
        let entry = registry
            .entries
            .get_mut(&handle)
            .expect("shmem frame index named a missing entry");
        entry.refs[page] = entry.refs[page]
            .checked_add(1)
            .expect("shmem mapping reference overflow");
        true
    })
}

fn vt_release_frame(phys: u64) -> bool {
    let anonymous_release = {
        let mut guard = ANONYMOUS_PAGES[anonymous_page_shard(phys)].refs.lock();
        guard.as_mut().and_then(|refs| {
            let count = refs.get_mut(&phys)?;
            assert!(*count > 0, "anonymous shmem mapping reference underflow");
            *count -= 1;
            if *count == 0 {
                refs.remove(&phys);
                Some(true)
            } else {
                Some(false)
            }
        })
    };
    if let Some(release) = anonymous_release {
        if release {
            narf_memory::free_frame(narf_memory::PhysFrame::new(PhysAddr::new(phys)));
        }
        return true;
    }

    let (owned, reclaim) = with_registry(|registry| {
        let Some(&(handle, page)) = registry.frames.get(&phys) else {
            return (false, Vec::new());
        };
        let entry = registry
            .entries
            .get_mut(&handle)
            .expect("shmem frame index named a missing entry");
        assert!(entry.refs[page] > 0, "shmem mapping reference underflow");
        entry.refs[page] -= 1;
        (true, reap_removed_entry(registry, handle))
    });
    free_phys_frames(reclaim);
    owned
}

fn vt_owns_frame(phys: u64) -> bool {
    if ANONYMOUS_PAGES[anonymous_page_shard(phys)]
        .refs
        .lock()
        .as_ref()
        .is_some_and(|refs| refs.contains_key(&phys))
    {
        return true;
    }
    REGISTRY
        .lock()
        .as_ref()
        .is_some_and(|registry| registry.frames.contains_key(&phys))
}

fn vt_frame_locked(phys: u64) -> bool {
    if ANONYMOUS_PAGES[anonymous_page_shard(phys)]
        .refs
        .lock()
        .as_ref()
        .is_some_and(|refs| refs.contains_key(&phys))
    {
        return false;
    }
    REGISTRY
        .lock()
        .as_ref()
        .and_then(|registry| {
            let (handle, _) = registry.frames.get(&phys)?;
            registry.entries.get(handle)
        })
        .is_some_and(|entry| entry.locked_user.is_some())
}

fn vt_lock(
    handle: u64,
    user_ns: u64,
    uid: u32,
    limit: u64,
    bypass: bool,
) -> Result<(), narf_userspace::handlers::ShmemLockError> {
    use narf_userspace::handlers::ShmemLockError;
    with_registry(|registry| {
        let Some(entry) = registry.entries.get(&handle).filter(|e| !e.removed) else {
            return Err(ShmemLockError::NotFound);
        };
        if entry.locked_user.is_some() {
            return Ok(());
        }
        let user = (user_ns, uid);
        let len = entry.len;
        let charged = registry.locked_bytes.get(&user).copied().unwrap_or(0);
        if !bypass && charged.saturating_add(len) > limit {
            return Err(ShmemLockError::Limit);
        }
        registry
            .entries
            .get_mut(&handle)
            .expect("checked shmem entry disappeared")
            .locked_user = Some(user);
        registry
            .locked_bytes
            .insert(user, charged.saturating_add(len));
        Ok(())
    })
}

fn vt_unlock(handle: u64) -> bool {
    with_registry(|registry| {
        let Some(entry) = registry.entries.get_mut(&handle).filter(|e| !e.removed) else {
            return false;
        };
        let len = entry.len;
        let Some(user) = entry.locked_user.take() else {
            return true;
        };
        let charge = registry
            .locked_bytes
            .get_mut(&user)
            .expect("locked shmem entry had no user charge");
        *charge = charge
            .checked_sub(len)
            .expect("shmem lock charge underflow");
        if *charge == 0 {
            registry.locked_bytes.remove(&user);
        }
        true
    })
}

fn vt_replace_frame(old_phys: u64, new_phys: u64) -> bool {
    let old_shard = anonymous_page_shard(old_phys);
    let new_shard = anonymous_page_shard(new_phys);
    if old_shard == new_shard {
        let mut guard = ANONYMOUS_PAGES[old_shard].refs.lock();
        if let Some(refs) = guard.as_mut() {
            if let Some(count) = refs.remove(&old_phys) {
                assert!(
                    refs.insert(new_phys, count).is_none(),
                    "replacement anonymous shmem frame already indexed"
                );
                return true;
            }
        }
    } else if old_shard < new_shard {
        let mut old_guard = ANONYMOUS_PAGES[old_shard].refs.lock();
        if old_guard
            .as_ref()
            .is_some_and(|refs| refs.contains_key(&old_phys))
        {
            let mut new_guard = ANONYMOUS_PAGES[new_shard].refs.lock();
            let count = old_guard
                .as_mut()
                .and_then(|refs| refs.remove(&old_phys))
                .expect("checked anonymous shmem frame disappeared");
            assert!(
                new_guard
                    .get_or_insert_with(BTreeMap::new)
                    .insert(new_phys, count)
                    .is_none(),
                "replacement anonymous shmem frame already indexed"
            );
            return true;
        }
    } else {
        let mut new_guard = ANONYMOUS_PAGES[new_shard].refs.lock();
        let mut old_guard = ANONYMOUS_PAGES[old_shard].refs.lock();
        if let Some(count) = old_guard.as_mut().and_then(|refs| refs.remove(&old_phys)) {
            assert!(
                new_guard
                    .get_or_insert_with(BTreeMap::new)
                    .insert(new_phys, count)
                    .is_none(),
                "replacement anonymous shmem frame already indexed"
            );
            return true;
        }
    }

    with_registry(|registry| {
        let Some((handle, page)) = registry.frames.remove(&old_phys) else {
            return false;
        };
        let slot = registry
            .entries
            .get_mut(&handle)
            .expect("shmem frame index named a missing entry")
            .frames
            .get_mut(page)
            .expect("shmem frame index named a missing page");
        debug_assert_eq!(*slot, old_phys);
        *slot = new_phys;
        assert!(
            registry.frames.insert(new_phys, (handle, page)).is_none(),
            "replacement shmem frame already indexed"
        );
        true
    })
}

fn vt_create(pid: u64, len: u64) -> u64 {
    create(pid, len).unwrap_or(0)
}

fn vt_len_of(handle: u64) -> u64 {
    len_of(handle).unwrap_or(0)
}

fn vt_frames(handle: u64, out: &mut Vec<u64>) -> bool {
    let frames = match frames_of(handle) {
        Some(f) => f,
        None => return false,
    };
    out.clear();
    for p in frames {
        out.push(p.raw());
    }
    true
}

fn vt_destroy(handle: u64) -> bool {
    destroy(handle)
}

fn vt_pid_of(handle: u64) -> u64 {
    pid_of(handle).unwrap_or(0)
}

// ── Init wiring ─────────────────────────────────────────────────────

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "shmem-syscall-vtable", || {
        narf_userspace::handlers::install_shmem_syscall_vtable(syscall_vtable());
        InitResult::Ok
    });
    // Process-exit observer: reap any shmem the dying process held.
    narf_init::register(Stage::Subsys, "shmem-exit-observer", || {
        narf_userspace::user_task::register_process_exit_observer(|pid, _tid| {
            let _ = destroy_all_for_pid(pid);
        });
        InitResult::Ok
    });
}

// Read-cap stub for future audit smokes.
#[allow(dead_code)]
fn _read_cap_demo(_c: Cap<ShmemCap, Read>) {}
#[allow(dead_code)]
fn _write_cap_demo(_c: Cap<ShmemCap, Write>) {}

// Per-crate smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite.
mod tests;
