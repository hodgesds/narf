//! Navi 22 native render ABI: `DRM_IOCTL_AMDGPU_{GEM_CREATE, GEM_MMAP,
//! GEM_VA, GEM_WAIT_IDLE, GEM_OP, GEM_METADATA, BO_LIST, CS, WAIT_CS,
//! WAIT_FENCES, FENCE_TO_HANDLE}`, `GEM_CLOSE`, and DRM syncobjs (binary and
//! timeline) on the amdgpu nodes of a bound RX 6750 XT, as Linux
//! `amdgpu_gem.c`, `amdgpu_bo_list.c`, `amdgpu_cs.c` and `drm_syncobj.c`
//! answer them.
//!
//! One [`FileState`] per open (`struct drm_file` + `amdgpu_fpriv`) owns the
//! client's GEM handles, its GPUVM (created on first use; one VMID for the
//! VM's lifetime), its VA mappings, BO lists and syncobjs. Device access goes
//! through [`Device`]: in production [`Platform`], which serialises on the
//! retained cold-boot owner (`amdgpu_navi22_platform::owner`) and places
//! memory with `amdgpu_gmc_navi22`; in tests an in-memory model.
//!
//! Submission: every IB must lie inside one VA mapping of the submitting
//! client's VM (`amdgpu_cs_find_mapping`); IB contents are not parsed (the
//! VMID's page tables are the boundary). Dependencies (SYNCOBJ_IN, timeline
//! waits, DEPENDENCIES) are awaited before the job is queued instead of by a
//! scheduler, without holding the file. The job then runs on the Navi22
//! kernel queue via `amdgpu_navi22_submit`, and the returned 64-bit sequence
//! is the CS handle. Fences become signalled when the ring's fence reaches
//! that sequence, or when a GPU recovery abandoned them; a context created
//! before a recovery gets `ECANCELED`, as Linux's VRAM-lost check returns.
//!
//! LINUX-GAP: no TTM: a BO never migrates, VRAM is preferred for any domain
//! set containing VRAM, and GTT BOs are single contiguous DMA buffers of at
//! most 4 MiB (larger GTT requests are placed in CPU-visible VRAM). GDS, GWS,
//! OA and DOORBELL domains, `GEM_USERPTR`, PRT/sparse mappings, `SET_PLACEMENT`,
//! encrypted BOs and secure IBs are refused. Syncobj file descriptors
//! (`HANDLE_TO_FD`/`FD_TO_HANDLE`, sync_file import/export) and the
//! user-fence BO are emulated only as far as stated at each handler: the user
//! fence is written by the CPU when a wait observes completion.
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{future::Future, pin::Pin};

use narf_filesystem::{FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_navi22_submit::{Ib, Ring, VmRef, MAX_IBS};
use crate::amdgpu_uapi as uapi;
use crate::drm_uapi;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Device failures, mapped to Linux errnos at the ioctl boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevError {
    /// Two submissions outstanding: wait for this ring sequence and retry.
    Busy(u64),
    NoMemory,
    Invalid,
    /// No accelerated device (not booted, recovered, or lost).
    Gone,
}

/// One `AMDGPU_GEM_VA` mapping in hole-stripped addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaMap {
    pub va: u64,
    pub offset: u64,
    pub size: u64,
    pub flags: u32,
}

/// The GPU operations the render ABI needs.
pub trait Device: Send + Sync + 'static {
    type Vm: Send + Sync + 'static;
    type Bo: Send + Sync + 'static;
    /// Whether an accelerated, verified Navi 22 is behind this device.
    fn active(&self) -> bool;
    /// Completed GPU recoveries (fence/VM epoch).
    fn epoch(&self) -> u64;
    fn create_vm(&self) -> BoxFut<'_, Result<(Self::Vm, VmRef), DevError>>;
    fn destroy_vm(&self, vm: Self::Vm) -> BoxFut<'_, ()>;
    /// Zeroed memory; `vram` selects VRAM over a GTT DMA buffer.
    fn alloc(
        &self,
        size: u64,
        vram: bool,
        uncached: bool,
    ) -> BoxFut<'_, Result<Self::Bo, DevError>>;
    /// CPU physical frames for an mmap of `[offset, offset + len)`.
    fn frames(&self, bo: &Self::Bo, offset: u64, len: u64) -> Result<Vec<u64>, DevError>;
    fn write_u64(&self, bo: &Self::Bo, offset: u64, value: u64);
    fn is_vram(&self, bo: &Self::Bo) -> bool;
    fn size(&self, bo: &Self::Bo) -> u64;
    fn map<'a>(
        &'a self,
        vm: &'a Self::Vm,
        map: VaMap,
        bo: Arc<Self::Bo>,
    ) -> BoxFut<'a, Result<(), DevError>>;
    fn unmap<'a>(&'a self, vm: &'a Self::Vm, va: u64) -> BoxFut<'a, Result<(), DevError>>;
    /// Queue `ibs`; the 64-bit ring sequence its fence will reach.
    fn submit<'a>(
        &'a self,
        ring: Ring,
        vm: VmRef,
        context: u64,
        ibs: &'a [Ib],
    ) -> BoxFut<'a, Result<u64, DevError>>;
    /// Last 64-bit sequence the ring completed.
    fn completed(&self, ring: Ring) -> BoxFut<'_, Result<u64, DevError>>;
}

/// A ring fence. Fences of an older epoch were abandoned by a recovery and
/// count as signalled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fence {
    pub ring: Ring,
    pub seq: u64,
    pub epoch: u64,
}

async fn signaled<D: Device>(dev: &D, fence: &Fence) -> bool {
    if fence.epoch != dev.epoch() {
        return true;
    }
    // A lost device cannot complete anything: report signalled rather than
    // leave waiters asleep forever.
    dev.completed(fence.ring)
        .await
        .map_or(true, |done| done >= fence.seq)
}

/// Absolute CLOCK_MONOTONIC deadline, as `amdgpu_gem_timeout` and
/// `drm_timeout_abs_to_jiffies` read the ioctl timeouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Until {
    Forever,
    At(u64),
}
impl Until {
    fn from_abs(timeout_ns: u64) -> Self {
        if (timeout_ns as i64) < 0 {
            Until::Forever
        } else {
            Until::At(timeout_ns)
        }
    }
    fn expired(self) -> bool {
        match self {
            Until::Forever => false,
            Until::At(t) => narf_time::monotonic_ns() >= t,
        }
    }
}
/// Fence sampling interval when no wake arrives.
const POLL_US: u64 = 500;

/// Wait until `ready` holds or the deadline passes; the sample runs once
/// after expiry so a completion racing the deadline is not a timeout.
async fn wait_for<F, Fut>(until: Until, mut ready: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    loop {
        let expired = until.expired();
        if ready().await {
            return true;
        }
        if expired {
            return false;
        }
        crate::amdgpu_cp_navi22::delay(POLL_US).await;
    }
}

// ── syncobjs ─────────────────────────────────────────────────────────

/// A syncobj: a timeline of (point, fences) nodes. A binary syncobj holds at
/// most one node at point 0. An empty fence list is the signalled stub.
#[derive(Clone, Debug, Default)]
struct Syncobj {
    nodes: Vec<(u64, Vec<Fence>)>,
}
impl Syncobj {
    fn replace(&mut self, fences: Vec<Fence>) {
        self.nodes = vec![(0, fences)];
    }
    fn reset(&mut self) {
        self.nodes.clear();
    }
    /// `drm_syncobj_add_point`.
    fn add_point(&mut self, point: u64, fences: Vec<Fence>) {
        let at = self.nodes.partition_point(|(p, _)| *p <= point);
        self.nodes.insert(at, (point, fences));
    }
    /// Fences point `point` waits for, or `None` if nothing was submitted
    /// for it yet (`drm_syncobj_find_fence` → -ENOENT / WAIT_FOR_SUBMIT).
    /// Point 0 is the latest node; point p is the first node at or after p
    /// together with every earlier node, as a dma_fence_chain signals.
    fn wait_set(&self, point: u64) -> Option<Vec<Fence>> {
        if point == 0 {
            return self.nodes.last().map(|(_, f)| f.clone());
        }
        let end = self.nodes.iter().position(|(p, _)| *p >= point)?;
        Some(
            self.nodes[..=end]
                .iter()
                .flat_map(|(_, f)| f.iter().copied())
                .collect(),
        )
    }
    fn last_point(&self) -> u64 {
        self.nodes.last().map_or(0, |(p, _)| *p)
    }
}

// ── per-file state ───────────────────────────────────────────────────

/// First GEM handle; disjoint from dumb-buffer and the generic amdgpu GEM
/// tables, so `GEM_CLOSE` and mmap offsets cannot cross namespaces.
pub const HANDLE_BASE: u32 = 0x4000_0000;

struct Bo<D: Device> {
    obj: Arc<D::Bo>,
    create: [u64; 4],
    fence: Option<Fence>,
    tiling: u64,
    metadata_flags: u64,
    metadata: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct Mapped {
    handle: u32,
    map: VaMap,
}

/// A user fence BO write owed when `fence` signals.
struct UserFence<D: Device> {
    bo: Arc<D::Bo>,
    offset: u64,
    fence: Fence,
}

struct Inner<D: Device> {
    epoch: u64,
    vm: Option<(D::Vm, VmRef)>,
    next_handle: u32,
    bos: BTreeMap<u32, Bo<D>>,
    /// Keyed by hole-stripped start VA.
    mappings: BTreeMap<u64, Mapped>,
    next_list: u32,
    bo_lists: BTreeMap<u32, Vec<u32>>,
    next_syncobj: u32,
    syncobjs: BTreeMap<u32, Syncobj>,
    user_fences: Vec<UserFence<D>>,
}

/// One open's Navi 22 render state.
pub struct FileState<D: Device = Platform> {
    device: D,
    inner: narf_lib::mutex::Mutex<Inner<D>>,
    /// Handle → object for the synchronous mmap path.
    mmaps: IrqSafeSpinLock<BTreeMap<u32, Arc<D::Bo>>>,
}

impl<D: Device> core::fmt::Debug for FileState<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Navi22FileState").finish_non_exhaustive()
    }
}

impl Default for FileState<Platform> {
    fn default() -> Self {
        Self::new(Platform)
    }
}

impl<D: Device> FileState<D> {
    pub fn new(device: D) -> Self {
        Self {
            inner: narf_lib::mutex::Mutex::new(Inner {
                epoch: device.epoch(),
                vm: None,
                next_handle: HANDLE_BASE,
                bos: BTreeMap::new(),
                mappings: BTreeMap::new(),
                next_list: 1,
                bo_lists: BTreeMap::new(),
                next_syncobj: 1,
                syncobjs: BTreeMap::new(),
                user_fences: Vec::new(),
            }),
            device,
            mmaps: IrqSafeSpinLock::new(BTreeMap::new()),
        }
    }

    /// Whether this open should route its amdgpu/syncobj ioctls here.
    pub fn active(&self) -> bool {
        self.device.active()
    }

    /// `GEM_MMAP` offsets are `handle << PAGE_SHIFT`.
    pub fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        let handle = u32::try_from(offset >> 12).map_err(|_| FsError::InvalidData)?;
        let bo = self
            .mmaps
            .lock()
            .get(&handle)
            .cloned()
            .ok_or(FsError::InvalidData)?;
        self.device
            .frames(&bo, 0, len as u64)
            .map_err(|_| FsError::InvalidData)
    }
    /// The object an mmap of `offset` keeps alive.
    pub fn mmap_owner(&self, offset: u64) -> Option<Arc<D::Bo>> {
        let handle = u32::try_from(offset >> 12).ok()?;
        self.mmaps.lock().get(&handle).cloned()
    }

    /// PRIME export (`amdgpu_gem_prime_export`): the object, its CPU frames
    /// and size, for a dma-buf file. Implicit-sync fences are not attached.
    pub fn export(&self, handle: u32) -> Option<(Arc<D::Bo>, Vec<u64>, u64)> {
        let bo = self.mmaps.lock().get(&handle).cloned()?;
        let size = self.device.size(&bo);
        let frames = self.device.frames(&bo, 0, size).ok()?;
        Some((bo, frames, size))
    }
    /// PRIME import of a buffer this device exported (`amdgpu_gem_prime_import`
    /// of a same-device dma-buf): a new handle on the same object.
    pub fn import(&self, bo: Arc<D::Bo>) -> Result<u32, FsError> {
        if let Some((h, _)) = self.mmaps.lock().iter().find(|(_, b)| Arc::ptr_eq(b, &bo)) {
            return Ok(*h);
        }
        let mut g = self.inner.try_lock().ok_or(FsError::Busy)?;
        let handle = g.next_handle;
        g.next_handle = handle.checked_add(1).ok_or(FsError::NoSpace)?;
        let size = self.device.size(&bo);
        let domain = if self.device.is_vram(&bo) {
            uapi::AMDGPU_GEM_DOMAIN_VRAM
        } else {
            uapi::AMDGPU_GEM_DOMAIN_GTT
        };
        self.mmaps.lock().insert(handle, Arc::clone(&bo));
        g.bos.insert(
            handle,
            Bo {
                obj: bo,
                create: [size, PAGE, u64::from(domain), 0],
                fence: None,
                tiling: 0,
                metadata_flags: 0,
                metadata: Vec::new(),
            },
        );
        Ok(handle)
    }

    /// File close: tear down the VM (`amdgpu_driver_postclose_kms`).
    pub async fn release(&self) {
        let mut g = self.inner.lock().await;
        g.mappings.clear();
        g.bos.clear();
        g.user_fences.clear();
        self.mmaps.lock().clear();
        if let Some((vm, _)) = g.vm.take() {
            if g.epoch == self.device.epoch() {
                self.device.destroy_vm(vm).await;
            }
        }
    }
}

// ── ioctl plumbing ───────────────────────────────────────────────────

/// Linux errnos without an `FsError` of their own, returned as the raw
/// negative syscall value.
const ETIME: i64 = 62;
const ECANCELED: i64 = 125;
fn errno(e: i64) -> u64 {
    (-e) as u64
}

fn read<const N: usize>(ctx: &dyn IoctlContext, at: u64) -> Result<[u8; N], FsError> {
    let mut b = [0u8; N];
    ctx.read(at, &mut b).map_err(|_| FsError::BadAddress)?;
    Ok(b)
}
fn read_vec(ctx: &dyn IoctlContext, at: u64, len: usize) -> Result<Vec<u8>, FsError> {
    // Bounded by every caller (counts are checked first).
    let mut b = vec![0u8; len];
    if len != 0 {
        ctx.read(at, &mut b).map_err(|_| FsError::BadAddress)?;
    }
    Ok(b)
}
fn write(ctx: &dyn IoctlContext, at: u64, bytes: &[u8]) -> Result<(), FsError> {
    ctx.write(at, bytes).map_err(|_| FsError::BadAddress)
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn dev_err(e: DevError) -> FsError {
    match e {
        DevError::NoMemory => FsError::OutOfMemory,
        DevError::Invalid => FsError::InvalidData,
        DevError::Gone | DevError::Busy(_) => FsError::NoDevice,
    }
}

const DRM_TYPE: u32 = b'd' as u32;
fn nr_of(cmd: u32) -> Option<u32> {
    ((cmd >> 8) & 0xff == DRM_TYPE).then(|| drm_uapi::ioc_nr(cmd))
}
/// Driver ioctls are `DRM_COMMAND_BASE..DRM_COMMAND_END`; core DRM ioctls
/// (syncobjs at 0xbf+) lie above it.
const DRM_COMMAND_END: u32 = 0xa0;
const NR_VERSION: u32 = 0x00;
const NR_GEM_CLOSE: u32 = 0x09;
const NR_GET_CAP: u32 = 0x0c;
const NR_SYNCOBJ_CREATE: u32 = 0xbf;
const NR_SYNCOBJ_DESTROY: u32 = 0xc0;
const NR_SYNCOBJ_HANDLE_TO_FD: u32 = 0xc1;
const NR_SYNCOBJ_FD_TO_HANDLE: u32 = 0xc2;
const NR_SYNCOBJ_WAIT: u32 = 0xc3;
const NR_SYNCOBJ_RESET: u32 = 0xc4;
const NR_SYNCOBJ_SIGNAL: u32 = 0xc5;
const NR_SYNCOBJ_TIMELINE_WAIT: u32 = 0xca;
const NR_SYNCOBJ_QUERY: u32 = 0xcb;
const NR_SYNCOBJ_TRANSFER: u32 = 0xcc;
const NR_SYNCOBJ_TIMELINE_SIGNAL: u32 = 0xcd;

/// Whether `cmd` is one this module answers for an active Navi 22.
pub fn handles(cmd: u32) -> bool {
    let Some(nr) = nr_of(cmd) else {
        return false;
    };
    if (drm_uapi::DRM_COMMAND_BASE..DRM_COMMAND_END).contains(&nr) {
        return matches!(
            nr - drm_uapi::DRM_COMMAND_BASE,
            uapi::DRM_AMDGPU_GEM_CREATE
                | uapi::DRM_AMDGPU_GEM_MMAP
                | uapi::DRM_AMDGPU_BO_LIST
                | uapi::DRM_AMDGPU_CS
                | uapi::DRM_AMDGPU_GEM_METADATA
                | uapi::DRM_AMDGPU_GEM_WAIT_IDLE
                | uapi::DRM_AMDGPU_GEM_VA
                | uapi::DRM_AMDGPU_WAIT_CS
                | uapi::DRM_AMDGPU_GEM_OP
                | uapi::DRM_AMDGPU_GEM_USERPTR
                | uapi::DRM_AMDGPU_WAIT_FENCES
                | uapi::DRM_AMDGPU_FENCE_TO_HANDLE
        );
    }
    matches!(
        nr,
        NR_VERSION
            | NR_GEM_CLOSE
            | NR_GET_CAP
            | NR_SYNCOBJ_CREATE
            | NR_SYNCOBJ_DESTROY
            | NR_SYNCOBJ_HANDLE_TO_FD
            | NR_SYNCOBJ_FD_TO_HANDLE
            | NR_SYNCOBJ_WAIT
            | NR_SYNCOBJ_RESET
            | NR_SYNCOBJ_SIGNAL
            | NR_SYNCOBJ_TIMELINE_WAIT
            | NR_SYNCOBJ_QUERY
            | NR_SYNCOBJ_TRANSFER
            | NR_SYNCOBJ_TIMELINE_SIGNAL
    )
}

/// `amdgpu` 3.64.0, `KMS_DRIVER_{MAJOR,MINOR,PATCHLEVEL}`, once submissions
/// run; 3.0.0 before (Mesa requires minor ≥ 54 and declines the device).
pub fn drm_version() -> (u32, u32, u32) {
    if crate::amdgpu_info_navi22::SUBMISSION == crate::amdgpu_info_navi22::Submission::Wired {
        (3, 64, 0)
    } else {
        (3, 0, 0)
    }
}

/// Dispatch one ioctl. `None`: not ours, fall through to the generic path.
pub async fn ioctl<D: Device>(
    state: &FileState<D>,
    ctxs: &crate::amdgpu_ctx::CtxState,
    cmd: u32,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Option<Result<u64, FsError>> {
    if !handles(cmd) || !state.device.active() {
        return None;
    }
    let nr = nr_of(cmd)?;
    Some(
        if (drm_uapi::DRM_COMMAND_BASE..DRM_COMMAND_END).contains(&nr) {
            match nr - drm_uapi::DRM_COMMAND_BASE {
                uapi::DRM_AMDGPU_GEM_CREATE => gem_create(state, arg, ctx).await,
                uapi::DRM_AMDGPU_GEM_MMAP => gem_mmap(state, arg, ctx).await,
                uapi::DRM_AMDGPU_GEM_VA => gem_va(state, arg, ctx).await,
                uapi::DRM_AMDGPU_GEM_WAIT_IDLE => gem_wait_idle(state, arg, ctx).await,
                uapi::DRM_AMDGPU_GEM_OP => gem_op(state, arg, ctx).await,
                uapi::DRM_AMDGPU_GEM_METADATA => gem_metadata(state, arg, ctx).await,
                uapi::DRM_AMDGPU_GEM_USERPTR => Err(FsError::InvalidData),
                uapi::DRM_AMDGPU_BO_LIST => bo_list(state, arg, ctx).await,
                uapi::DRM_AMDGPU_CS => cs(state, ctxs, arg, ctx).await,
                uapi::DRM_AMDGPU_WAIT_CS => wait_cs(state, ctxs, arg, ctx).await,
                uapi::DRM_AMDGPU_WAIT_FENCES => wait_fences(state, ctxs, arg, ctx).await,
                uapi::DRM_AMDGPU_FENCE_TO_HANDLE => fence_to_handle(state, ctxs, arg, ctx).await,
                _ => return None,
            }
        } else {
            match nr {
                NR_VERSION => version(arg, ctx),
                NR_GET_CAP => return get_cap(arg, ctx),
                NR_GEM_CLOSE => match gem_close(state, arg, ctx).await {
                    // A dumb-buffer handle: the generic path owns it.
                    Err(FsError::Unsupported) => return None,
                    other => other,
                },
                _ => syncobj(state, nr, arg, ctx).await,
            }
        },
    )
}

/// `DRM_IOCTL_VERSION` for the amdgpu node, whether or not a display owner
/// has attached KMS state.
fn version(arg: u64, ctx: &dyn IoctlContext) -> Result<u64, FsError> {
    // struct drm_version: 3 x i32, pad, then (len u64, ptr u64) x 3.
    let mut b: [u8; 64] = read(ctx, arg)?;
    let (major, minor, patch) = drm_version();
    b[0..4].copy_from_slice(&(major as i32).to_le_bytes());
    b[4..8].copy_from_slice(&(minor as i32).to_le_bytes());
    b[8..12].copy_from_slice(&(patch as i32).to_le_bytes());
    for (i, text) in [&b"amdgpu"[..], b"20150101", b"AMD GPU"].iter().enumerate() {
        let len_at = 16 + i * 16;
        let cap = u64_at(&b, len_at) as usize;
        let ptr = u64_at(&b, len_at + 8);
        if ptr != 0 && cap != 0 {
            write(ctx, ptr, &text[..text.len().min(cap)])?;
        }
        b[len_at..len_at + 8].copy_from_slice(&(text.len() as u64).to_le_bytes());
    }
    write(ctx, arg, &b)?;
    Ok(0)
}

/// `DRM_IOCTL_GET_CAP` as `drm_getcap` answers for amdgpu, for the render
/// capabilities this module implements (so the render node answers them
/// with or without KMS state). `None`: a KMS capability, generic path.
fn get_cap(arg: u64, ctx: &dyn IoctlContext) -> Option<Result<u64, FsError>> {
    let b: [u8; 16] = match read(ctx, arg) {
        Ok(b) => b,
        Err(e) => return Some(Err(e)),
    };
    let value: u64 = match u64_at(&b, 0) {
        0x01 => 1, // DUMB_BUFFER
        0x05 => 3, // PRIME import | export
        0x06 => 1, // TIMESTAMP_MONOTONIC
        0x13 => 1, // SYNCOBJ
        0x14 => 1, // SYNCOBJ_TIMELINE
        _ => return None,
    };
    let mut out = b;
    out[8..16].copy_from_slice(&value.to_le_bytes());
    Some(write(ctx, arg, &out).map(|()| 0))
}

// ── GEM ──────────────────────────────────────────────────────────────

const PAGE: u64 = 4096;
/// `AMDGPU_GEM_CREATE_SETTABLE_MASK` (see `amdgpu_gem`).
const SETTABLE: u64 = (uapi::AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED
    | uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS
    | uapi::AMDGPU_GEM_CREATE_CPU_GTT_USWC
    | uapi::AMDGPU_GEM_CREATE_VRAM_CLEARED
    | uapi::AMDGPU_GEM_CREATE_VM_ALWAYS_VALID
    | uapi::AMDGPU_GEM_CREATE_EXPLICIT_SYNC
    | uapi::AMDGPU_GEM_CREATE_VRAM_WIPE_ON_RELEASE
    | uapi::AMDGPU_GEM_CREATE_ENCRYPTED
    | uapi::AMDGPU_GEM_CREATE_GFX12_DCC
    | uapi::AMDGPU_GEM_CREATE_DISCARDABLE
    | uapi::AMDGPU_GEM_CREATE_COHERENT
    | uapi::AMDGPU_GEM_CREATE_UNCACHED
    | uapi::AMDGPU_GEM_CREATE_EXT_COHERENT) as u64;
/// One contiguous coherent DMA buffer (`narf_io` order 10).
const MAX_GTT: u64 = 4 << 20;

async fn gem_create<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 32] = read(ctx, arg)?;
    let (size, alignment, domains, flags) =
        (u64_at(&b, 0), u64_at(&b, 8), u64_at(&b, 16), u64_at(&b, 24));
    // amdgpu_gem_create_ioctl, in its order.
    if flags & !SETTABLE != 0 || domains & !u64::from(uapi::AMDGPU_GEM_DOMAIN_MASK) != 0 {
        return Err(FsError::InvalidData);
    }
    // No TMZ on this ASIC by default (amdgpu_is_tmz false).
    if flags & uapi::AMDGPU_GEM_CREATE_ENCRYPTED as u64 != 0 {
        return Err(FsError::InvalidData);
    }
    let normal = u64::from(
        uapi::AMDGPU_GEM_DOMAIN_CPU | uapi::AMDGPU_GEM_DOMAIN_GTT | uapi::AMDGPU_GEM_DOMAIN_VRAM,
    );
    if domains & !normal != 0 || domains == 0 || size == 0 {
        // GDS/GWS/OA/DOORBELL are not provided (see the module LINUX-GAP).
        return Err(FsError::InvalidData);
    }
    let bytes = size
        .checked_next_multiple_of(PAGE)
        .ok_or(FsError::InvalidData)?;
    let vram = domains & u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM) != 0 || bytes > MAX_GTT;
    let uncached = flags
        & (uapi::AMDGPU_GEM_CREATE_CPU_GTT_USWC
            | uapi::AMDGPU_GEM_CREATE_COHERENT
            | uapi::AMDGPU_GEM_CREATE_UNCACHED
            | uapi::AMDGPU_GEM_CREATE_EXT_COHERENT) as u64
        != 0;
    let obj = Arc::new(
        s.device
            .alloc(bytes, vram, uncached)
            .await
            .map_err(dev_err)?,
    );
    let mut g = s.inner.lock().await;
    let handle = g.next_handle;
    g.next_handle = handle.checked_add(1).ok_or(FsError::NoSpace)?;
    s.mmaps.lock().insert(handle, Arc::clone(&obj));
    g.bos.insert(
        handle,
        Bo {
            obj,
            create: [bytes, alignment, domains, flags],
            fence: None,
            tiling: 0,
            metadata_flags: 0,
            metadata: Vec::new(),
        },
    );
    drop(g);
    // out.handle overlays in.bo_size.
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&handle.to_le_bytes());
    write(ctx, arg, &out)?;
    Ok(0)
}

async fn gem_mmap<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 8] = read(ctx, arg)?;
    let handle = u32_at(&b, 0);
    if !s.inner.lock().await.bos.contains_key(&handle) {
        return Err(FsError::NotFound);
    }
    write(ctx, arg, &(u64::from(handle) << 12).to_le_bytes())?;
    Ok(0)
}

async fn gem_close<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 8] = read(ctx, arg)?;
    let handle = u32_at(&b, 0);
    if handle < HANDLE_BASE {
        // Not one of ours: dumb buffers keep the generic path.
        return Err(FsError::Unsupported);
    }
    // amdgpu_gem_object_close: wait for the BO's work, then drop its VAs.
    let fence = s
        .inner
        .lock()
        .await
        .bos
        .get(&handle)
        .ok_or(FsError::InvalidData)?
        .fence;
    if let Some(f) = fence {
        wait_for(
            Until::At(narf_time::monotonic_ns() + 10_000_000_000),
            || signaled(&s.device, &f),
        )
        .await;
    }
    let mut g = s.inner.lock().await;
    g.bos.remove(&handle).ok_or(FsError::InvalidData)?;
    s.mmaps.lock().remove(&handle);
    let vas: Vec<u64> = g
        .mappings
        .iter()
        .filter(|(_, m)| m.handle == handle)
        .map(|(va, _)| *va)
        .collect();
    for va in vas {
        g.mappings.remove(&va);
        if let Some((vm, _)) = g.vm.as_ref() {
            let _ = s.device.unmap(vm, va).await;
        }
    }
    Ok(0)
}

/// The VM of this open, created on first use (`amdgpu_driver_open_kms`
/// creates it at open; deferring keeps idle opens from holding a VMID).
async fn vm_of<D: Device>(s: &FileState<D>, g: &mut Inner<D>) -> Result<VmRef, FsError> {
    if g.epoch != s.device.epoch() {
        return Err(FsError::NoDevice);
    }
    if let Some((_, r)) = g.vm.as_ref() {
        return Ok(*r);
    }
    let (vm, r) = s.device.create_vm().await.map_err(dev_err)?;
    g.vm = Some((vm, r));
    Ok(r)
}

async fn gem_va<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 40] = read(ctx, arg)?;
    let handle = u32_at(&b, 0);
    let (op, flags) = (u32_at(&b, 8), u32_at(&b, 12));
    let (va_raw, offset, size) = (u64_at(&b, 16), u64_at(&b, 24), u64_at(&b, 32));
    let va =
        crate::amdgpu_vm::validate_va(&crate::amdgpu_vm::Geometry::GMC11, va_raw, size, flags)?;
    if !matches!(
        op,
        uapi::AMDGPU_VA_OP_MAP
            | uapi::AMDGPU_VA_OP_UNMAP
            | uapi::AMDGPU_VA_OP_CLEAR
            | uapi::AMDGPU_VA_OP_REPLACE
    ) {
        return Err(FsError::InvalidData);
    }
    if flags & uapi::AMDGPU_VM_PAGE_PRT != 0 {
        return Err(FsError::InvalidData);
    }
    if va % PAGE != 0 || offset % PAGE != 0 || size % PAGE != 0 {
        return Err(FsError::InvalidData);
    }
    let mut g = s.inner.lock().await;
    let bo = if op == uapi::AMDGPU_VA_OP_CLEAR {
        None
    } else {
        let bo = g.bos.get(&handle).ok_or(FsError::NotFound)?;
        Some((Arc::clone(&bo.obj), bo.create[0]))
    };
    vm_of(s, &mut g).await?;
    let end = va.checked_add(size).ok_or(FsError::InvalidData)?;
    match op {
        uapi::AMDGPU_VA_OP_UNMAP => {
            let m = g.mappings.get(&va).copied().ok_or(FsError::NotFound)?;
            if m.handle != handle {
                return Err(FsError::NotFound);
            }
            g.mappings.remove(&va);
            let (vm, _) = g.vm.as_ref().unwrap();
            s.device.unmap(vm, va).await.map_err(dev_err)?;
            return Ok(0);
        }
        uapi::AMDGPU_VA_OP_CLEAR | uapi::AMDGPU_VA_OP_REPLACE => {
            // Mappings wholly inside the range go; a partial overlap would
            // need a split this VM does not support.
            let hit: Vec<Mapped> = g
                .mappings
                .values()
                .filter(|m| m.map.va < end && va < m.map.va + m.map.size)
                .copied()
                .collect();
            if hit
                .iter()
                .any(|m| m.map.va < va || m.map.va + m.map.size > end)
            {
                return Err(FsError::InvalidData);
            }
            for m in hit {
                g.mappings.remove(&m.map.va);
                let (vm, _) = g.vm.as_ref().unwrap();
                s.device.unmap(vm, m.map.va).await.map_err(dev_err)?;
            }
            if op == uapi::AMDGPU_VA_OP_CLEAR {
                return Ok(0);
            }
        }
        _ => {}
    }
    // MAP / REPLACE.
    let (obj, bo_size) = bo.ok_or(FsError::NotFound)?;
    if size == 0 || offset.checked_add(size).is_none_or(|e| e > bo_size) {
        return Err(FsError::InvalidData);
    }
    if g.mappings
        .values()
        .any(|m| m.map.va < end && va < m.map.va + m.map.size)
    {
        return Err(FsError::InvalidData);
    }
    let map = VaMap {
        va,
        offset,
        size,
        flags,
    };
    let (vm, _) = g.vm.as_ref().unwrap();
    s.device.map(vm, map, obj).await.map_err(dev_err)?;
    g.mappings.insert(va, Mapped { handle, map });
    Ok(0)
}

async fn gem_wait_idle<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 16] = read(ctx, arg)?;
    let handle = u32_at(&b, 0);
    let until = Until::from_abs(u64_at(&b, 8));
    let (fence, vram) = {
        let g = s.inner.lock().await;
        let bo = g.bos.get(&handle).ok_or(FsError::NotFound)?;
        (bo.fence, s.device.is_vram(&bo.obj))
    };
    let idle = match fence {
        None => true,
        Some(f) => wait_for(until, || signaled(&s.device, &f)).await,
    };
    s.flush_user_fences().await;
    // out { status: 1 busy / 0 idle, domain }.
    let domain = if vram {
        uapi::AMDGPU_GEM_DOMAIN_VRAM
    } else {
        uapi::AMDGPU_GEM_DOMAIN_GTT
    };
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&u32::from(!idle).to_le_bytes());
    out[4..8].copy_from_slice(&domain.to_le_bytes());
    write(ctx, arg, &out)?;
    Ok(0)
}

async fn gem_op<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 16] = read(ctx, arg)?;
    let (handle, op, value) = (u32_at(&b, 0), u32_at(&b, 4), u64_at(&b, 8));
    let create = s
        .inner
        .lock()
        .await
        .bos
        .get(&handle)
        .ok_or(FsError::NotFound)?
        .create;
    match op {
        uapi::AMDGPU_GEM_OP_GET_GEM_CREATE_INFO => {
            let mut out = [0u8; 32];
            for (i, v) in create.iter().enumerate() {
                out[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            write(ctx, value, &out)?;
            Ok(0)
        }
        _ => Err(FsError::InvalidData),
    }
}

async fn gem_metadata<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    // { handle u32, op u32, data { flags u64, tiling_info u64,
    //   data_size_bytes u32, data[64] u32 } }, 288 bytes with padding.
    let mut b: [u8; 288] = read(ctx, arg)?;
    let (handle, op) = (u32_at(&b, 0), u32_at(&b, 4));
    let mut g = s.inner.lock().await;
    let bo = g.bos.get_mut(&handle).ok_or(FsError::NotFound)?;
    match op {
        uapi::AMDGPU_GEM_METADATA_OP_SET_METADATA => {
            let len = u32_at(&b, 24) as usize;
            if len > 256 {
                return Err(FsError::InvalidData);
            }
            bo.metadata_flags = u64_at(&b, 8);
            bo.tiling = u64_at(&b, 16);
            bo.metadata = b[28..28 + len].to_vec();
            Ok(0)
        }
        uapi::AMDGPU_GEM_METADATA_OP_GET_METADATA => {
            b[8..16].copy_from_slice(&bo.metadata_flags.to_le_bytes());
            b[16..24].copy_from_slice(&bo.tiling.to_le_bytes());
            b[24..28].copy_from_slice(&(bo.metadata.len() as u32).to_le_bytes());
            b[28..28 + bo.metadata.len()].copy_from_slice(&bo.metadata);
            drop(g);
            write(ctx, arg, &b)?;
            Ok(0)
        }
        _ => Err(FsError::InvalidData),
    }
}

// ── BO lists ─────────────────────────────────────────────────────────

/// `amdgpu_bo_create_list_entry_array`: `bo_info_size` may be larger
/// (newer userspace) or the 8-byte `drm_amdgpu_bo_list_entry`.
fn list_entries(
    ctx: &dyn IoctlContext,
    ptr: u64,
    count: u32,
    stride: u32,
) -> Result<Vec<u32>, FsError> {
    if count > 128 * 1024 || !(4..=64).contains(&stride) {
        return Err(FsError::InvalidData);
    }
    let raw = read_vec(ctx, ptr, count as usize * stride as usize)?;
    Ok((0..count as usize)
        .map(|i| u32_at(&raw, i * stride as usize))
        .collect())
}

async fn bo_list<D: Device>(
    s: &FileState<D>,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 24] = read(ctx, arg)?;
    let (op, list, count, stride, ptr) = (
        u32_at(&b, 0),
        u32_at(&b, 4),
        u32_at(&b, 8),
        u32_at(&b, 12),
        u64_at(&b, 16),
    );
    let mut g = s.inner.lock().await;
    match op {
        uapi::AMDGPU_BO_LIST_OP_CREATE | uapi::AMDGPU_BO_LIST_OP_UPDATE => {
            let handles = list_entries(ctx, ptr, count, stride)?;
            if handles.iter().any(|h| !g.bos.contains_key(h)) {
                return Err(FsError::NotFound);
            }
            let id = if op == uapi::AMDGPU_BO_LIST_OP_CREATE {
                let id = g.next_list;
                g.next_list += 1;
                id
            } else if g.bo_lists.contains_key(&list) {
                list
            } else {
                return Err(FsError::NotFound);
            };
            g.bo_lists.insert(id, handles);
            drop(g);
            let mut out = [0u8; 24];
            out[0..4].copy_from_slice(&id.to_le_bytes());
            write(ctx, arg, &out)?;
            Ok(0)
        }
        uapi::AMDGPU_BO_LIST_OP_DESTROY => {
            g.bo_lists.remove(&list).ok_or(FsError::NotFound)?;
            Ok(0)
        }
        _ => Err(FsError::InvalidData),
    }
}

// ── command submission ───────────────────────────────────────────────

/// `amdgpu_ctx_get_entity` for this ASIC: one gfx entity, four compute
/// entities on the single kernel compute queue, one per SDMA engine.
fn ring_of(ip: u32, instance: u32, ring: u32) -> Result<Ring, FsError> {
    if instance != 0 {
        return Err(FsError::InvalidData);
    }
    match ip {
        uapi::AMDGPU_HW_IP_GFX if ring < 1 => Ok(Ring::Gfx),
        uapi::AMDGPU_HW_IP_COMPUTE if ring < 4 => Ok(Ring::Compute),
        uapi::AMDGPU_HW_IP_DMA if ring < 2 => Ok(Ring::Sdma(ring as u8)),
        _ => Err(FsError::InvalidData),
    }
}

/// A dependency awaited before the job is queued.
enum Dep {
    Fences(Vec<Fence>),
    /// (syncobj, point) a WAIT_FOR_SUBMIT dependency resolves once submitted.
    Pending(u32, u64),
}

struct Job {
    ring: Option<Ring>,
    ibs: Vec<Ib>,
    deps: Vec<Dep>,
    signal: Vec<(u32, u64)>,
    bos: Vec<u32>,
    user_fence: Option<(u32, u32)>,
}

/// AMDGPU_CS: amdgpu_cs_pass1/pass2 parse, then wait, queue and signal.
async fn cs<D: Device>(
    s: &FileState<D>,
    ctxs: &crate::amdgpu_ctx::CtxState,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 24] = read(ctx, arg)?;
    let (ctx_id, list, num_chunks, flags, chunks) = (
        u32_at(&b, 0),
        u32_at(&b, 4),
        u32_at(&b, 8),
        u32_at(&b, 12),
        u64_at(&b, 16),
    );
    let context = ctxs.get(ctx_id).ok_or(FsError::InvalidData)?;
    if context.reset_epoch != s.device.epoch() {
        return Ok(errno(ECANCELED));
    }
    if num_chunks == 0 || num_chunks > 64 || flags & !1 != 0 {
        return Err(FsError::InvalidData);
    }
    let ptrs = read_vec(ctx, chunks, num_chunks as usize * 8)?;
    let mut job = Job {
        ring: None,
        ibs: Vec::new(),
        deps: Vec::new(),
        signal: Vec::new(),
        bos: Vec::new(),
        user_fence: None,
    };
    let mut has_bo_handles = false;
    {
        let g = s.inner.lock().await;
        for i in 0..num_chunks as usize {
            let c: [u8; 16] = read(ctx, u64_at(&ptrs, i * 8))?;
            let (id, len_dw, data) = (u32_at(&c, 0), u32_at(&c, 4), u64_at(&c, 8));
            if len_dw > 64 * 1024 {
                return Err(FsError::InvalidData);
            }
            let raw = read_vec(ctx, data, len_dw as usize * 4)?;
            let entries = |size: usize| -> Result<usize, FsError> {
                if raw.len() % size != 0 {
                    Err(FsError::InvalidData)
                } else {
                    Ok(raw.len() / size)
                }
            };
            match id {
                uapi::AMDGPU_CHUNK_ID_IB => {
                    if raw.len() < 32 {
                        return Err(FsError::InvalidData);
                    }
                    let (ib_flags, va, bytes) =
                        (u32_at(&raw, 4), u64_at(&raw, 8), u32_at(&raw, 16));
                    let ring = ring_of(u32_at(&raw, 20), u32_at(&raw, 24), u32_at(&raw, 28))?;
                    if job.ring.is_some_and(|r| r != ring) || job.ibs.len() == MAX_IBS {
                        return Err(FsError::InvalidData);
                    }
                    if ib_flags & (uapi::AMDGPU_IB_FLAGS_SECURE | uapi::AMDGPU_IB_FLAG_CE) != 0 {
                        return Err(FsError::InvalidData);
                    }
                    if bytes == 0 || bytes % 4 != 0 {
                        return Err(FsError::InvalidData);
                    }
                    // amdgpu_cs_find_mapping: inside one mapping of this VM.
                    let start = crate::amdgpu_vm::strip_hole(va);
                    let end = start
                        .checked_add(u64::from(bytes))
                        .ok_or(FsError::InvalidData)?;
                    let inside = g
                        .mappings
                        .range(..=start)
                        .next_back()
                        .is_some_and(|(_, m)| end <= m.map.va + m.map.size);
                    if !inside {
                        return Err(FsError::InvalidData);
                    }
                    job.ring = Some(ring);
                    job.ibs.push(Ib {
                        va: start,
                        dwords: bytes / 4,
                    });
                }
                uapi::AMDGPU_CHUNK_ID_BO_HANDLES => {
                    if raw.len() < 24 {
                        return Err(FsError::InvalidData);
                    }
                    has_bo_handles = true;
                    let handles =
                        list_entries(ctx, u64_at(&raw, 16), u32_at(&raw, 8), u32_at(&raw, 12))?;
                    if handles.iter().any(|h| !g.bos.contains_key(h)) {
                        return Err(FsError::InvalidData);
                    }
                    job.bos.extend(handles);
                }
                uapi::AMDGPU_CHUNK_ID_FENCE => {
                    if raw.len() < 8 {
                        return Err(FsError::InvalidData);
                    }
                    let (handle, offset) = (u32_at(&raw, 0), u32_at(&raw, 4));
                    let bo = g.bos.get(&handle).ok_or(FsError::InvalidData)?;
                    if u64::from(offset) + 8 > bo.create[0] || offset % 8 != 0 {
                        return Err(FsError::InvalidData);
                    }
                    job.user_fence = Some((handle, offset));
                }
                uapi::AMDGPU_CHUNK_ID_DEPENDENCIES
                | uapi::AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES => {
                    for k in 0..entries(24)? {
                        let d = &raw[k * 24..];
                        let ring = ring_of(u32_at(d, 0), u32_at(d, 4), u32_at(d, 8))?;
                        let dep_ctx = ctxs.get(u32_at(d, 12)).ok_or(FsError::InvalidData)?;
                        job.deps.push(Dep::Fences(vec![Fence {
                            ring,
                            seq: u64_at(d, 16),
                            epoch: dep_ctx.reset_epoch,
                        }]));
                    }
                }
                uapi::AMDGPU_CHUNK_ID_SYNCOBJ_IN => {
                    for k in 0..entries(4)? {
                        let handle = u32_at(&raw, k * 4);
                        let so = g.syncobjs.get(&handle).ok_or(FsError::InvalidData)?;
                        job.deps
                            .push(Dep::Fences(so.wait_set(0).ok_or(FsError::InvalidData)?));
                    }
                }
                uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT => {
                    for k in 0..entries(16)? {
                        let d = &raw[k * 16..];
                        let (handle, wflags, point) = (u32_at(d, 0), u32_at(d, 4), u64_at(d, 8));
                        let so = g.syncobjs.get(&handle).ok_or(FsError::InvalidData)?;
                        match so.wait_set(point) {
                            Some(f) => job.deps.push(Dep::Fences(f)),
                            None if wflags & SYNCOBJ_WAIT_FOR_SUBMIT != 0 => {
                                job.deps.push(Dep::Pending(handle, point))
                            }
                            None => return Err(FsError::InvalidData),
                        }
                    }
                }
                uapi::AMDGPU_CHUNK_ID_SYNCOBJ_OUT => {
                    for k in 0..entries(4)? {
                        let handle = u32_at(&raw, k * 4);
                        g.syncobjs.get(&handle).ok_or(FsError::InvalidData)?;
                        job.signal.push((handle, 0));
                    }
                }
                uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL => {
                    for k in 0..entries(16)? {
                        let d = &raw[k * 16..];
                        let handle = u32_at(d, 0);
                        g.syncobjs.get(&handle).ok_or(FsError::InvalidData)?;
                        job.signal.push((handle, u64_at(d, 8)));
                    }
                }
                _ => return Err(FsError::InvalidData),
            }
        }
        // A BO list handle and a BO_HANDLES chunk are exclusive.
        if list != 0 {
            if has_bo_handles {
                return Err(FsError::InvalidData);
            }
            job.bos.extend(
                g.bo_lists
                    .get(&list)
                    .ok_or(FsError::InvalidData)?
                    .iter()
                    .copied(),
            );
        }
    }
    let ring = job.ring.ok_or(FsError::InvalidData)?;
    // Dependencies, without holding the file.
    for dep in &job.deps {
        let ok = match dep {
            Dep::Fences(fences) => {
                wait_all(
                    &s.device,
                    fences,
                    Until::At(narf_time::monotonic_ns() + DEP_TIMEOUT_NS),
                )
                .await
            }
            Dep::Pending(handle, point) => {
                let until = Until::At(narf_time::monotonic_ns() + DEP_TIMEOUT_NS);
                let set = loop {
                    let expired = until.expired();
                    let set = s
                        .inner
                        .lock()
                        .await
                        .syncobjs
                        .get(handle)
                        .and_then(|so| so.wait_set(*point));
                    if set.is_some() || expired {
                        break set;
                    }
                    crate::amdgpu_cp_navi22::delay(POLL_US).await;
                };
                match set {
                    Some(set) => wait_all(&s.device, &set, until).await,
                    None => false,
                }
            }
        };
        if !ok {
            return Err(FsError::Busy);
        }
    }
    let mut g = s.inner.lock().await;
    let vm = vm_of(s, &mut g).await?;
    // Queue, waiting out the per-ring throttle with the file released.
    let seq = loop {
        match s.device.submit(ring, vm, u64::from(ctx_id), &job.ibs).await {
            Ok(seq) => break seq,
            Err(DevError::Busy(oldest)) => {
                drop(g);
                let f = Fence {
                    ring,
                    seq: oldest,
                    epoch: s.device.epoch(),
                };
                wait_for(
                    Until::At(narf_time::monotonic_ns() + DEP_TIMEOUT_NS),
                    || signaled(&s.device, &f),
                )
                .await;
                g = s.inner.lock().await;
            }
            Err(e) => return Err(dev_err(e)),
        }
    };
    let fence = Fence {
        ring,
        seq,
        epoch: s.device.epoch(),
    };
    for h in &job.bos {
        if let Some(bo) = g.bos.get_mut(h) {
            bo.fence = Some(fence);
        }
    }
    for (h, point) in &job.signal {
        if let Some(so) = g.syncobjs.get_mut(h) {
            if *point == 0 {
                so.replace(vec![fence]);
            } else {
                so.add_point(*point, vec![fence]);
            }
        }
    }
    if let Some((h, offset)) = job.user_fence {
        if let Some(bo) = g.bos.get(&h) {
            let bo = Arc::clone(&bo.obj);
            g.user_fences.push(UserFence {
                bo,
                offset: u64::from(offset),
                fence,
            });
        }
    }
    drop(g);
    // out.handle overlays the in arm.
    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&seq.to_le_bytes());
    write(ctx, arg, &out)?;
    Ok(0)
}
/// Dependency bound in place of a scheduler's indefinite wait.
const DEP_TIMEOUT_NS: u64 = 10_000_000_000;

async fn wait_all<D: Device>(dev: &D, fences: &[Fence], until: Until) -> bool {
    wait_for(until, || async {
        for f in fences {
            if !signaled(dev, f).await {
                return false;
            }
        }
        true
    })
    .await
}

impl<D: Device> FileState<D> {
    /// Write every user fence whose job completed (Linux's RELEASE_MEM to
    /// the user fence BO, performed by the CPU here).
    async fn flush_user_fences(&self) {
        let mut g = self.inner.lock().await;
        let mut keep = Vec::new();
        for uf in core::mem::take(&mut g.user_fences) {
            if signaled(&self.device, &uf.fence).await {
                self.device.write_u64(&uf.bo, uf.offset, uf.fence.seq);
            } else {
                keep.push(uf);
            }
        }
        g.user_fences = keep;
    }
}

fn fence_from(ctxs: &crate::amdgpu_ctx::CtxState, d: &[u8]) -> Result<Fence, FsError> {
    // drm_amdgpu_fence { ctx_id, ip_type, ip_instance, ring, seq_no u64 }.
    let c = ctxs.get(u32_at(d, 0)).ok_or(FsError::InvalidData)?;
    Ok(Fence {
        ring: ring_of(u32_at(d, 4), u32_at(d, 8), u32_at(d, 12))?,
        seq: u64_at(d, 16),
        epoch: c.reset_epoch,
    })
}

async fn wait_cs<D: Device>(
    s: &FileState<D>,
    ctxs: &crate::amdgpu_ctx::CtxState,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    // in { handle u64, timeout u64, ip_type, ip_instance, ring, ctx_id }.
    let b: [u8; 32] = read(ctx, arg)?;
    let c = ctxs.get(u32_at(&b, 28)).ok_or(FsError::InvalidData)?;
    let f = Fence {
        ring: ring_of(u32_at(&b, 16), u32_at(&b, 20), u32_at(&b, 24))?,
        seq: u64_at(&b, 0),
        epoch: c.reset_epoch,
    };
    let done = wait_for(Until::from_abs(u64_at(&b, 8)), || signaled(&s.device, &f)).await;
    s.flush_user_fences().await;
    // out.status: 1 when the timeout expired first.
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&u64::from(!done).to_le_bytes());
    write(ctx, arg, &out)?;
    Ok(0)
}

async fn wait_fences<D: Device>(
    s: &FileState<D>,
    ctxs: &crate::amdgpu_ctx::CtxState,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    // in { fences u64, fence_count u32, wait_all u32, timeout_ns u64 }.
    let b: [u8; 24] = read(ctx, arg)?;
    let count = u32_at(&b, 8);
    if count == 0 || count > 4096 {
        return Err(FsError::InvalidData);
    }
    let raw = read_vec(ctx, u64_at(&b, 0), count as usize * 24)?;
    let fences: Vec<Fence> = (0..count as usize)
        .map(|i| fence_from(ctxs, &raw[i * 24..]))
        .collect::<Result<_, _>>()?;
    let all = u32_at(&b, 12) != 0;
    let until = Until::from_abs(u64_at(&b, 16));
    let mut first = 0u32;
    let done = if all {
        wait_all(&s.device, &fences, until).await
    } else {
        loop {
            let expired = until.expired();
            let mut hit = None;
            for (i, f) in fences.iter().enumerate() {
                if signaled(&s.device, f).await {
                    hit = Some(i as u32);
                    break;
                }
            }
            if let Some(i) = hit {
                first = i;
                break true;
            }
            if expired {
                break false;
            }
            crate::amdgpu_cp_navi22::delay(POLL_US).await;
        }
    };
    s.flush_user_fences().await;
    // out { status u32 (1 = signalled), first_signaled u32 }.
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&u32::from(done).to_le_bytes());
    out[4..8].copy_from_slice(&first.to_le_bytes());
    write(ctx, arg, &out)?;
    Ok(0)
}

async fn fence_to_handle<D: Device>(
    s: &FileState<D>,
    ctxs: &crate::amdgpu_ctx::CtxState,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b: [u8; 32] = read(ctx, arg)?;
    let fence = fence_from(ctxs, &b[0..24])?;
    match u32_at(&b, 24) {
        uapi::AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ => {
            let mut g = s.inner.lock().await;
            let handle = g.next_syncobj;
            g.next_syncobj += 1;
            let mut so = Syncobj::default();
            so.replace(vec![fence]);
            g.syncobjs.insert(handle, so);
            drop(g);
            let mut out = [0u8; 32];
            out[0..4].copy_from_slice(&handle.to_le_bytes());
            write(ctx, arg, &out)?;
            Ok(0)
        }
        // SYNCOBJ_FD and SYNC_FILE_FD: see the module LINUX-GAP.
        _ => Err(FsError::InvalidData),
    }
}

// ── syncobj ioctls (drm_syncobj.c) ───────────────────────────────────

const SYNCOBJ_CREATE_SIGNALED: u32 = 1;
const SYNCOBJ_WAIT_ALL: u32 = 1;
const SYNCOBJ_WAIT_FOR_SUBMIT: u32 = 2;
const SYNCOBJ_WAIT_AVAILABLE: u32 = 4;
const SYNCOBJ_WAIT_DEADLINE: u32 = 8;
const SYNCOBJ_QUERY_LAST_SUBMITTED: u32 = 1;

async fn syncobj<D: Device>(
    s: &FileState<D>,
    nr: u32,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    match nr {
        NR_SYNCOBJ_CREATE => {
            let b: [u8; 8] = read(ctx, arg)?;
            let flags = u32_at(&b, 4);
            if flags & !SYNCOBJ_CREATE_SIGNALED != 0 {
                return Err(FsError::InvalidData);
            }
            let mut g = s.inner.lock().await;
            let handle = g.next_syncobj;
            g.next_syncobj += 1;
            let mut so = Syncobj::default();
            if flags & SYNCOBJ_CREATE_SIGNALED != 0 {
                so.replace(Vec::new());
            }
            g.syncobjs.insert(handle, so);
            drop(g);
            let mut out = b;
            out[0..4].copy_from_slice(&handle.to_le_bytes());
            write(ctx, arg, &out)?;
            Ok(0)
        }
        NR_SYNCOBJ_DESTROY => {
            let b: [u8; 8] = read(ctx, arg)?;
            if u32_at(&b, 4) != 0 {
                return Err(FsError::InvalidData);
            }
            s.inner
                .lock()
                .await
                .syncobjs
                .remove(&u32_at(&b, 0))
                .ok_or(FsError::InvalidData)?;
            Ok(0)
        }
        NR_SYNCOBJ_WAIT | NR_SYNCOBJ_TIMELINE_WAIT => {
            syncobj_wait(s, nr == NR_SYNCOBJ_TIMELINE_WAIT, arg, ctx).await
        }
        NR_SYNCOBJ_RESET | NR_SYNCOBJ_SIGNAL => {
            // { handles u64, count_handles u32, pad u32 }
            let b: [u8; 16] = read(ctx, arg)?;
            if u32_at(&b, 12) != 0 {
                return Err(FsError::InvalidData);
            }
            let handles = handle_array(ctx, u64_at(&b, 0), u32_at(&b, 8))?;
            let mut g = s.inner.lock().await;
            if handles.iter().any(|h| !g.syncobjs.contains_key(h)) {
                return Err(FsError::InvalidData);
            }
            for h in handles {
                let so = g.syncobjs.get_mut(&h).unwrap();
                if nr == NR_SYNCOBJ_RESET {
                    so.reset();
                } else {
                    so.replace(Vec::new());
                }
            }
            Ok(0)
        }
        NR_SYNCOBJ_TIMELINE_SIGNAL | NR_SYNCOBJ_QUERY => {
            // { handles u64, points u64, count_handles u32, flags u32 }
            let b: [u8; 24] = read(ctx, arg)?;
            let (count, flags) = (u32_at(&b, 16), u32_at(&b, 20));
            let handles = handle_array(ctx, u64_at(&b, 0), count)?;
            let points_raw = read_vec(ctx, u64_at(&b, 8), count as usize * 8)?;
            let mut g = s.inner.lock().await;
            if handles.iter().any(|h| !g.syncobjs.contains_key(h)) {
                return Err(FsError::InvalidData);
            }
            if nr == NR_SYNCOBJ_TIMELINE_SIGNAL {
                if flags != 0 {
                    return Err(FsError::InvalidData);
                }
                for (i, h) in handles.iter().enumerate() {
                    let point = u64_at(&points_raw, i * 8);
                    let so = g.syncobjs.get_mut(h).unwrap();
                    if point == 0 {
                        so.replace(Vec::new());
                    } else {
                        so.add_point(point, Vec::new());
                    }
                }
                return Ok(0);
            }
            if flags & !SYNCOBJ_QUERY_LAST_SUBMITTED != 0 {
                return Err(FsError::InvalidData);
            }
            // Highest point whose chain has signalled (or was submitted).
            let snapshot: Vec<Syncobj> = handles.iter().map(|h| g.syncobjs[h].clone()).collect();
            drop(g);
            let mut out = Vec::with_capacity(snapshot.len() * 8);
            for so in snapshot {
                let mut value = 0;
                if flags & SYNCOBJ_QUERY_LAST_SUBMITTED != 0 {
                    value = so.last_point();
                } else {
                    for (p, _) in &so.nodes {
                        let set = so.wait_set((*p).max(1)).unwrap_or_default();
                        if wait_all(&s.device, &set, Until::At(0)).await {
                            value = *p;
                        } else {
                            break;
                        }
                    }
                }
                out.extend_from_slice(&value.to_le_bytes());
            }
            write(ctx, u64_at(&b, 8), &out)?;
            Ok(0)
        }
        NR_SYNCOBJ_TRANSFER => {
            // { src u32, dst u32, src_point u64, dst_point u64, flags u32, pad }
            let b: [u8; 32] = read(ctx, arg)?;
            let (src, dst, sp, dp) = (u32_at(&b, 0), u32_at(&b, 4), u64_at(&b, 8), u64_at(&b, 16));
            let mut g = s.inner.lock().await;
            let set = g
                .syncobjs
                .get(&src)
                .ok_or(FsError::InvalidData)?
                .wait_set(sp)
                .ok_or(FsError::InvalidData)?;
            let d = g.syncobjs.get_mut(&dst).ok_or(FsError::InvalidData)?;
            if dp == 0 {
                d.replace(set);
            } else {
                d.add_point(dp, set);
            }
            Ok(0)
        }
        // NR_SYNCOBJ_HANDLE_TO_FD / FD_TO_HANDLE: see the module LINUX-GAP.
        _ => Err(FsError::InvalidData),
    }
}

fn handle_array(ctx: &dyn IoctlContext, ptr: u64, count: u32) -> Result<Vec<u32>, FsError> {
    if count == 0 || count > 4096 {
        return Err(FsError::InvalidData);
    }
    let raw = read_vec(ctx, ptr, count as usize * 4)?;
    Ok((0..count as usize).map(|i| u32_at(&raw, i * 4)).collect())
}

/// `drm_syncobj_wait_ioctl` / `drm_syncobj_timeline_wait_ioctl`.
async fn syncobj_wait<D: Device>(
    s: &FileState<D>,
    timeline: bool,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    // wait: { handles, timeout i64, count, flags, first_signaled, pad, deadline }
    // timeline: { handles, points, timeout i64, count, flags, first, pad, deadline }
    let mut b: [u8; 48] = [0; 48];
    let size = if timeline { 48 } else { 40 };
    ctx.read(arg, &mut b[..size])
        .map_err(|_| FsError::BadAddress)?;
    let o = if timeline { 8 } else { 0 };
    let (timeout, count, flags) = (u64_at(&b, 8 + o), u32_at(&b, 16 + o), u32_at(&b, 20 + o));
    let allowed = SYNCOBJ_WAIT_ALL
        | SYNCOBJ_WAIT_FOR_SUBMIT
        | SYNCOBJ_WAIT_DEADLINE
        | if timeline { SYNCOBJ_WAIT_AVAILABLE } else { 0 };
    if flags & !allowed != 0 {
        return Err(FsError::InvalidData);
    }
    let handles = handle_array(ctx, u64_at(&b, 0), count)?;
    let points: Vec<u64> = if timeline {
        let raw = read_vec(ctx, u64_at(&b, 8), count as usize * 8)?;
        (0..count as usize).map(|i| u64_at(&raw, i * 8)).collect()
    } else {
        vec![0; count as usize]
    };
    {
        let g = s.inner.lock().await;
        for (h, p) in handles.iter().zip(&points) {
            let so = g.syncobjs.get(h).ok_or(FsError::InvalidData)?;
            // Without WAIT_FOR_SUBMIT an unsubmitted point is -EINVAL.
            if so.wait_set(*p).is_none() && flags & SYNCOBJ_WAIT_FOR_SUBMIT == 0 {
                return Err(FsError::InvalidData);
            }
        }
    }
    let until = Until::from_abs(timeout);
    let available_only = flags & SYNCOBJ_WAIT_AVAILABLE != 0;
    let mut first = u32::MAX;
    let done = loop {
        let expired = until.expired();
        let sets: Vec<Option<Vec<Fence>>> = {
            let g = s.inner.lock().await;
            handles
                .iter()
                .zip(&points)
                .map(|(h, p)| g.syncobjs.get(h).and_then(|so| so.wait_set(*p)))
                .collect()
        };
        let mut all = true;
        let mut any = false;
        for (i, set) in sets.iter().enumerate() {
            let ok = match set {
                None => false,
                Some(_) if available_only => true,
                Some(set) => wait_all(&s.device, set, Until::At(0)).await,
            };
            if ok && first == u32::MAX {
                first = i as u32;
            }
            all &= ok;
            any |= ok;
        }
        if (flags & SYNCOBJ_WAIT_ALL != 0 && all) || (flags & SYNCOBJ_WAIT_ALL == 0 && any) {
            break true;
        }
        if expired {
            break false;
        }
        crate::amdgpu_cp_navi22::delay(POLL_US).await;
    };
    s.flush_user_fences().await;
    if !done {
        return Ok(errno(ETIME));
    }
    let at = if timeline { 32 } else { 24 };
    b[at..at + 4].copy_from_slice(&first.min(count - 1).to_le_bytes());
    write(ctx, arg, &b[..size])?;
    Ok(0)
}

// ── production device ────────────────────────────────────────────────

/// The bound Navi 22 through its retained cold-boot owner.
#[derive(Debug, Default, Clone, Copy)]
pub struct Platform;

/// Per-ring scheduling memory and 64-bit sequence extension.
#[derive(Clone, Copy, Debug, Default)]
struct Track {
    state: crate::amdgpu_navi22_submit::RingState,
    emitted: u64,
    epoch: u64,
}
static TRACKS: IrqSafeSpinLock<[Track; 4]> = IrqSafeSpinLock::new(
    [Track {
        state: crate::amdgpu_navi22_submit::RingState::new(),
        emitted: 0,
        epoch: 0,
    }; 4],
);
fn track_index(ring: Ring) -> usize {
    match ring {
        Ring::Gfx => 0,
        Ring::Compute => 1,
        Ring::Sdma(0) => 2,
        Ring::Sdma(_) => 3,
    }
}
/// Extend a 32-bit ring value that trails `emitted` by less than 2^31.
fn extend(emitted: u64, value: u32) -> u64 {
    emitted.wrapping_sub(u64::from((emitted as u32).wrapping_sub(value)))
}
fn boot_err(_: crate::amdgpu_navi22_boot::Error) -> DevError {
    DevError::Gone
}

impl Device for Platform {
    type Vm = crate::amdgpu_gmc_navi22::Vm;
    type Bo = crate::amdgpu_gmc_navi22::Buffer;
    fn active(&self) -> bool {
        crate::amdgpu::is_navi22()
            && crate::amdgpu_navi22_platform::queues_ready()
            && crate::amdgpu_info_navi22::SUBMISSION == crate::amdgpu_info_navi22::Submission::Wired
    }
    fn epoch(&self) -> u64 {
        crate::amdgpu_navi22_recovery::recoveries()
    }
    fn create_vm(&self) -> BoxFut<'_, Result<(Self::Vm, VmRef), DevError>> {
        Box::pin(async move {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            let gmc = owner
                .as_mut()
                .ok_or(DevError::Gone)?
                .memory()
                .map_err(boot_err)?;
            let vm = gmc.create_vm().await.map_err(|_| DevError::NoMemory)?;
            let info = gmc.vm_info(&vm).ok_or(DevError::Invalid)?;
            let r = VmRef {
                vmid: info.vmid,
                generation: info.generation,
                page_table_base: info.page_table_base,
            };
            // A recycled VMID is a new owner: every ring flushes it again.
            for t in TRACKS.lock().iter_mut() {
                crate::amdgpu_navi22_submit::forget(&mut t.state, r.vmid);
            }
            Ok((vm, r))
        })
    }
    fn destroy_vm(&self, vm: Self::Vm) -> BoxFut<'_, ()> {
        Box::pin(async move {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            if let Some(gmc) = owner.as_mut().and_then(|b| b.memory().ok()) {
                let _ = gmc.destroy_vm(vm).await;
            }
        })
    }
    fn alloc(
        &self,
        size: u64,
        vram: bool,
        uncached: bool,
    ) -> BoxFut<'_, Result<Self::Bo, DevError>> {
        Box::pin(async move {
            if vram {
                let mut owner = crate::amdgpu_navi22_platform::owner().await;
                let gmc = owner
                    .as_mut()
                    .ok_or(DevError::Gone)?
                    .memory()
                    .map_err(boot_err)?;
                return gmc
                    .allocate_vram(size, false)
                    .map_err(|_| DevError::NoMemory);
            }
            let mut dma = narf_driver_runtime::alloc_coherent(
                size as usize,
                narf_driver_runtime::DomainId::DRIVER_0,
            )
            .map_err(|_| DevError::NoMemory)?;
            dma.as_mut_slice().fill(0);
            let bo = crate::amdgpu_gmc_navi22::Buffer::system(dma, false)
                .map_err(|_| DevError::Invalid)?;
            Ok(if uncached { bo.uncached() } else { bo })
        })
    }
    fn frames(&self, bo: &Self::Bo, offset: u64, len: u64) -> Result<Vec<u64>, DevError> {
        if offset.checked_add(len).is_none_or(|e| e > bo.size()) {
            return Err(DevError::Invalid);
        }
        let base = match (bo.vram_mapping(), bo.system_pages()) {
            (Some(map), _) => map.phys.raw(),
            (None, Some(dma)) => dma.phys_addr().raw(),
            (None, None) => return Err(DevError::Invalid),
        };
        Ok((offset / PAGE..(offset + len).div_ceil(PAGE))
            .map(|p| base + p * PAGE)
            .collect())
    }
    fn write_u64(&self, bo: &Self::Bo, offset: u64, value: u64) {
        if offset + 8 > bo.size() {
            return;
        }
        if let Some(map) = bo.vram_mapping() {
            // SAFETY: bounded by the buffer's own BAR mapping.
            unsafe {
                map.write32(offset, value as u32);
                map.write32(offset + 4, (value >> 32) as u32);
            }
        } else if let Some(dma) = bo.system_pages() {
            // SAFETY: offset + 8 lies within the pinned coherent buffer.
            unsafe {
                core::ptr::write_volatile(
                    dma.as_mut_ptr().add(offset as usize).cast::<u64>(),
                    value,
                )
            };
        }
    }
    fn is_vram(&self, bo: &Self::Bo) -> bool {
        bo.vram_mapping().is_some()
    }
    fn size(&self, bo: &Self::Bo) -> u64 {
        bo.size()
    }
    fn map<'a>(
        &'a self,
        vm: &'a Self::Vm,
        map: VaMap,
        bo: Arc<Self::Bo>,
    ) -> BoxFut<'a, Result<(), DevError>> {
        Box::pin(async move {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            let gmc = owner
                .as_mut()
                .ok_or(DevError::Gone)?
                .memory()
                .map_err(boot_err)?;
            gmc.map(
                vm,
                crate::amdgpu_gmc_navi22::Mapping {
                    va: map.va,
                    offset: map.offset,
                    size: map.size,
                    flags: map.flags,
                },
                bo,
            )
            .await
            .map_err(|_| DevError::Invalid)
        })
    }
    fn unmap<'a>(&'a self, vm: &'a Self::Vm, va: u64) -> BoxFut<'a, Result<(), DevError>> {
        Box::pin(async move {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            let gmc = owner
                .as_mut()
                .ok_or(DevError::Gone)?
                .memory()
                .map_err(boot_err)?;
            gmc.unmap(vm, va).await.map_err(|_| DevError::Invalid)
        })
    }
    fn submit<'a>(
        &'a self,
        ring: Ring,
        vm: VmRef,
        context: u64,
        ibs: &'a [Ib],
    ) -> BoxFut<'a, Result<u64, DevError>> {
        Box::pin(async move {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            let boot = owner.as_mut().ok_or(DevError::Gone)?;
            let epoch = self.epoch();
            let mut tracks = TRACKS.lock();
            let t = &mut tracks[track_index(ring)];
            if t.epoch != epoch {
                *t = Track {
                    epoch,
                    ..Track::default()
                };
            }
            match boot.submit(ring, &mut t.state, vm, context, ibs) {
                Ok(seq) => {
                    t.emitted = t
                        .emitted
                        .wrapping_add(u64::from(seq.wrapping_sub(t.emitted as u32)));
                    Ok(t.emitted)
                }
                Err(crate::amdgpu_navi22_boot::Error::Queues(
                    crate::amdgpu_cp_navi22::Error::Busy,
                )) => {
                    let (_, throttle) = boot.fences(ring).map_err(boot_err)?;
                    Err(DevError::Busy(extend(t.emitted, throttle)))
                }
                Err(crate::amdgpu_navi22_boot::Error::Queues(
                    crate::amdgpu_cp_navi22::Error::Invalid,
                )) => Err(DevError::Invalid),
                Err(_) => Err(DevError::Gone),
            }
        })
    }
    fn completed(&self, ring: Ring) -> BoxFut<'_, Result<u64, DevError>> {
        Box::pin(async move {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            let boot = owner.as_mut().ok_or(DevError::Gone)?;
            let (done, _) = boot.fences(ring).map_err(boot_err)?;
            let t = TRACKS.lock()[track_index(ring)];
            Ok(extend(t.emitted, done))
        })
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_drm_tests.rs"]
mod tests;
