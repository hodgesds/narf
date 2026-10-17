//! Model tests for the DRM/amdgpu synchronisation ABI against Linux:
//! timeline syncobjs (`drm_syncobj.c`, `dma-fence-chain.c`), syncobj and
//! sync_file fds, `SYNCOBJ_EVENTFD`, the CS timeline chunks, dependencies,
//! `AMDGPU_WAIT_FENCES`, `AMDGPU_FENCE_TO_HANDLE`, `AMDGPU_BO_LIST` and
//! implicit sync (`amdgpu_cs.c`, `amdgpu_bo_list.c`). The CS cases run
//! against a Navi 22-shaped engine (four rings, `amdgpu_navi22_cs` ticket
//! layout) and a Navi 48-shaped one (gfx, compute, SDMA0).
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_filesystem::{DrmFence, FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_uapi as u;
use crate::drm::syncobj::{self as so, BinaryFence, DmaFence, SyncObjCore, SyncObjTable};
use crate::drm::syncobj_ioctl::{dispatch_sync, step, Step};

const ETIME: u64 = (-62i64) as u64;
const EOPNOTSUPP: u64 = (-95i64) as u64;
const EBADF: u64 = (-9i64) as u64;

fn fence() -> Arc<BinaryFence> {
    BinaryFence::new()
}

/// A syncobj ioctl on `table`, waiting synchronously.
fn ioctl(
    nr: u32,
    arg: &mut [u8],
    table: &IrqSafeSpinLock<SyncObjTable>,
    timeline: bool,
) -> Result<u64, FsError> {
    dispatch_sync(nr, arg.as_mut_ptr() as usize, table, timeline).unwrap()
}

/// A syncobj ioctl with descriptor operations through `files`.
fn ioctl_files(
    nr: u32,
    arg: &mut [u8],
    table: &IrqSafeSpinLock<SyncObjTable>,
    files: &dyn IoctlContext,
) -> Result<u64, FsError> {
    match step(
        nr,
        arg.as_mut_ptr() as usize,
        table,
        true,
        Some(files),
        narf_time::monotonic_ns(),
    ) {
        Step::Done(r) => r,
        Step::Pending { .. } => Err(FsError::WouldBlock),
    }
}

fn array(handles: &[u32], count: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&(handles.as_ptr() as u64).to_le_bytes());
    b[8..12].copy_from_slice(&count.to_le_bytes());
    b
}

fn timeline_array(handles: &[u32], points: &[u64], flags: u32) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&(handles.as_ptr() as u64).to_le_bytes());
    b[8..16].copy_from_slice(&(points.as_ptr() as u64).to_le_bytes());
    b[16..20].copy_from_slice(&(handles.len() as u32).to_le_bytes());
    b[20..24].copy_from_slice(&flags.to_le_bytes());
    b
}

fn wait_req(handles: &[u32], timeout: i64, flags: u32) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[0..8].copy_from_slice(&(handles.as_ptr() as u64).to_le_bytes());
    b[8..16].copy_from_slice(&timeout.to_le_bytes());
    b[16..20].copy_from_slice(&(handles.len() as u32).to_le_bytes());
    b[20..24].copy_from_slice(&flags.to_le_bytes());
    b
}

fn timeline_wait_req(handles: &[u32], points: &[u64], timeout: i64, flags: u32) -> [u8; 48] {
    let mut b = [0u8; 48];
    b[0..8].copy_from_slice(&(handles.as_ptr() as u64).to_le_bytes());
    b[8..16].copy_from_slice(&(points.as_ptr() as u64).to_le_bytes());
    b[16..24].copy_from_slice(&timeout.to_le_bytes());
    b[24..28].copy_from_slice(&(handles.len() as u32).to_le_bytes());
    b[28..32].copy_from_slice(&flags.to_le_bytes());
    b
}

fn query(table: &IrqSafeSpinLock<SyncObjTable>, handle: u32, flags: u32) -> Option<u64> {
    let handles = [handle];
    let mut points = [0u64; 1];
    let mut b = timeline_array(&handles, &points, flags);
    b[8..16].copy_from_slice(&(points.as_mut_ptr() as u64).to_le_bytes());
    ioctl(0xcb, &mut b, table, true).ok()?;
    Some(points[0])
}

fn far_future() -> i64 {
    (narf_time::monotonic_ns() + 10_000_000_000) as i64
}

// ── dma_fence_chain ───────────────────────────────────────────────────

/// Points 1..3 on unsignalled fences: QUERY reports the last signalled
/// point of the run (0 until point 1 signals; a signalled later point
/// behind an unsignalled one does not count), LAST_SUBMITTED the last
/// attached; a point resolves to the node covering it, which waits for
/// every earlier point; an unsubmitted point is -EINVAL.
fn sync_timeline_points_and_query() -> TestResult {
    let core = SyncObjCore::new(None);
    let f: Vec<Arc<BinaryFence>> = (0..3).map(|_| fence()).collect();
    for (i, f) in f.iter().enumerate() {
        core.add_point(f.clone(), i as u64 + 1);
    }
    let q = |last| so::query_point(core.fence(), last);
    if q(true) != 3 || q(false) != 0 {
        return TestResult::Fail("fresh timeline: last submitted 3, signalled 0");
    }
    let Ok(p2) = core.find_fence(2) else {
        return TestResult::Fail("point 2 resolves");
    };
    if core.find_fence(4).is_ok() || so::find_seqno(None, 0).is_ok() {
        return TestResult::Fail("an unsubmitted point or no payload is -EINVAL");
    }
    f[2].signal();
    if q(false) != 0 || p2.is_signalled() {
        return TestResult::Fail("point 3 alone signals nothing below it");
    }
    f[0].signal();
    if q(false) != 1 || p2.is_signalled() {
        return TestResult::Fail("point 1 signalled");
    }
    f[1].signal();
    if q(false) != 3 || !p2.is_signalled() || !core.is_signalled() {
        return TestResult::Fail("every point signalled");
    }
    // Every node signalled: a covered point is the signalled stub.
    match core.find_fence(2) {
        Ok(stub) if stub.is_signalled() => {}
        _ => return TestResult::Fail("a signalled point is the stub"),
    }
    // Binary payloads query as 0.
    let binary = SyncObjCore::new(Some(fence()));
    if so::query_point(binary.fence(), true) != 0 || binary.find_fence(1).is_ok() {
        return TestResult::Fail("a binary syncobj has no points");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_timeline_points_and_query);

/// An unordered point (`dma_fence_chain_init`): a point at or below the
/// last starts a new run whose point is the old maximum; QUERY stops at the
/// run boundary and LAST_SUBMITTED keeps the maximum.
fn sync_timeline_unordered_points() -> TestResult {
    let core = SyncObjCore::new(None);
    let (a, b) = (fence(), fence());
    core.add_point(a.clone(), 5);
    core.add_point(b.clone(), 2);
    let head = core.fence().unwrap();
    let Some(chain) = head.as_chain() else {
        return TestResult::Fail("payload is a chain");
    };
    if chain.seqno() != 5 || chain.prev_seqno() != 0 {
        return TestResult::Fail("unordered node takes max(prev, point), new run");
    }
    b.signal();
    // The new run's head fence is signalled but point 5 (old run) is not, so
    // the head is unsignalled and QUERY reports its prev_seqno: 0 — the
    // "payload returned from query_ioctl is 0" case drm_syncobj_add_point
    // warns about. LAST_SUBMITTED keeps the maximum.
    if so::query_point(core.fence(), false) != 0 || so::query_point(core.fence(), true) != 5 {
        return TestResult::Fail("query of an unordered timeline");
    }
    if head.is_signalled() {
        return TestResult::Fail("the chain waits for the earlier run too");
    }
    a.signal();
    if !head.is_signalled() || so::query_point(core.fence(), false) != 5 {
        return TestResult::Fail("both runs signalled");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_timeline_unordered_points);

/// Garbage collection and release: signalled nodes are unlinked as points
/// are added (a timeline of 50 000 signalled points stays short), and
/// dropping a long unsignalled chain does not recurse per node.
fn sync_timeline_gc_and_iterative_release() -> TestResult {
    let core = SyncObjCore::new(None);
    for p in 1..=50_000u64 {
        core.add_point(so::stub(), p);
    }
    let head = core.fence().unwrap();
    if head.as_chain().and_then(|c| c.walk()).is_some()
        || so::query_point(core.fence(), false) != 50_000
    {
        return TestResult::Fail("signalled points are collected");
    }
    let pending = SyncObjCore::new(None);
    let gate = fence();
    for p in 1..=50_000u64 {
        pending.add_point(gate.clone(), p);
    }
    drop(pending);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm-sync",
    sync_timeline_gc_and_iterative_release
);

// ── the generic ioctls ────────────────────────────────────────────────

/// CREATE/DESTROY/RESET/SIGNAL/WAIT errnos as `drm_syncobj.c` returns them.
fn sync_binary_ioctl_errnos() -> TestResult {
    let table = IrqSafeSpinLock::new(SyncObjTable::new());
    let create = |flags: u32| {
        let mut b = [0u8; 8];
        b[4..8].copy_from_slice(&flags.to_le_bytes());
        ioctl(0xbf, &mut b, &table, true).map(|_| u32::from_le_bytes(b[0..4].try_into().unwrap()))
    };
    if create(2) != Err(FsError::InvalidData) {
        return TestResult::Fail("CREATE: unknown flags are EINVAL");
    }
    let (Ok(unsig), Ok(sig)) = (create(0), create(so::SYNCOBJ_CREATE_SIGNALED)) else {
        return TestResult::Fail("CREATE");
    };
    let destroy = |h: u32, pad: u32| {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&h.to_le_bytes());
        b[4..8].copy_from_slice(&pad.to_le_bytes());
        ioctl(0xc0, &mut b, &table, true)
    };
    if destroy(sig, 1) != Err(FsError::InvalidData)
        || destroy(0xdead, 0) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("DESTROY: pad and unknown handle are EINVAL");
    }
    let h = [unsig, 0xdead];
    for nr in [0xc4, 0xc5] {
        if ioctl(nr, &mut array(&h, 0), &table, true) != Err(FsError::InvalidData) {
            return TestResult::Fail("RESET/SIGNAL: no handles is EINVAL");
        }
        let mut padded = array(&h, 1);
        padded[12] = 1;
        if ioctl(nr, &mut padded, &table, true) != Err(FsError::InvalidData) {
            return TestResult::Fail("RESET/SIGNAL: pad is EINVAL");
        }
        if ioctl(nr, &mut array(&h, 2), &table, true) != Err(FsError::NotFound) {
            return TestResult::Fail("RESET/SIGNAL: unknown handle is ENOENT");
        }
    }
    // WAIT: no handles succeeds; an unknown handle is ENOENT; AVAILABLE is
    // a timeline-only flag; an unsubmitted syncobj is EINVAL without
    // WAIT_FOR_SUBMIT and pending with it; an expired absolute timeout ETIME.
    if ioctl(0xc3, &mut wait_req(&[], 0, 0), &table, true) != Ok(0)
        || ioctl(0xc3, &mut wait_req(&[0xdead], 0, 0), &table, true) != Err(FsError::NotFound)
        || ioctl(
            0xc3,
            &mut wait_req(&[sig], 0, so::SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE),
            &table,
            true,
        ) != Err(FsError::InvalidData)
        || ioctl(0xc3, &mut wait_req(&[unsig], 0, 0), &table, true) != Err(FsError::InvalidData)
        || ioctl(
            0xc3,
            &mut wait_req(&[unsig], 0, so::SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT),
            &table,
            true,
        ) != Ok(ETIME)
    {
        return TestResult::Fail("WAIT errnos");
    }
    // ANY reports the first signalled index; ALL of a pending one is ETIME
    // at its deadline (a past absolute instant polls).
    let pending = fence();
    table
        .lock()
        .get(unsig)
        .unwrap()
        .replace_fence(pending.clone());
    let any_handles = [unsig, sig];
    let mut any = wait_req(&any_handles, far_future(), 0);
    if ioctl(0xc3, &mut any, &table, true) != Ok(0)
        || u32::from_le_bytes(any[24..28].try_into().unwrap()) != 1
    {
        return TestResult::Fail("WAIT any: first_signaled");
    }
    let past = narf_time::monotonic_ns() as i64 - 1;
    if ioctl(
        0xc3,
        &mut wait_req(&[unsig, sig], past, so::SYNCOBJ_WAIT_FLAGS_WAIT_ALL),
        &table,
        true,
    ) != Ok(ETIME)
    {
        return TestResult::Fail("WAIT all: pending at an expired deadline");
    }
    pending.signal();
    if ioctl(
        0xc3,
        &mut wait_req(&[unsig, sig], far_future(), so::SYNCOBJ_WAIT_FLAGS_WAIT_ALL),
        &table,
        true,
    ) != Ok(0)
    {
        return TestResult::Fail("WAIT all signalled");
    }
    // SIGNAL replaces the payload with a stub (the shared fence is not
    // signalled); RESET detaches it.
    let shared = fence();
    table
        .lock()
        .get(unsig)
        .unwrap()
        .replace_fence(shared.clone());
    if ioctl(0xc5, &mut array(&[unsig], 1), &table, true) != Ok(0)
        || shared.is_signalled()
        || !table.lock().get(unsig).unwrap().is_signalled()
    {
        return TestResult::Fail("SIGNAL");
    }
    if ioctl(0xc4, &mut array(&[unsig], 1), &table, true) != Ok(0)
        || table.lock().get(unsig).unwrap().fence().is_some()
    {
        return TestResult::Fail("RESET");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_binary_ioctl_errnos);

/// TIMELINE_WAIT, QUERY, TRANSFER and TIMELINE_SIGNAL: -EOPNOTSUPP without
/// DRIVER_SYNCOBJ_TIMELINE, then their semantics and errnos.
fn sync_timeline_ioctls() -> TestResult {
    let table = IrqSafeSpinLock::new(SyncObjTable::new());
    let a = table.lock().create(0).unwrap();
    let b = table.lock().create(0).unwrap();
    for nr in [0xca, 0xcb, 0xcc, 0xcd, 0xcf] {
        let mut buf = [0u8; 48];
        if ioctl(nr, &mut buf, &table, false) != Ok(EOPNOTSUPP) {
            return TestResult::Fail("timeline ioctls need DRIVER_SYNCOBJ_TIMELINE");
        }
    }
    // TIMELINE_SIGNAL: flags must be 0, no handles EINVAL, unknown ENOENT.
    let points = [3u64];
    if ioctl(0xcd, &mut timeline_array(&[a], &points, 1), &table, true) != Err(FsError::InvalidData)
        || ioctl(0xcd, &mut timeline_array(&[], &points, 0), &table, true)
            != Err(FsError::InvalidData)
        || ioctl(
            0xcd,
            &mut timeline_array(&[0xdead], &points, 0),
            &table,
            true,
        ) != Err(FsError::NotFound)
        || ioctl(0xcd, &mut timeline_array(&[a], &points, 0), &table, true) != Ok(0)
    {
        return TestResult::Fail("TIMELINE_SIGNAL errnos");
    }
    // QUERY: unknown flags / no handles EINVAL; values.
    if ioctl(0xcb, &mut timeline_array(&[a], &points, 2), &table, true) != Err(FsError::InvalidData)
        || ioctl(0xcb, &mut timeline_array(&[], &points, 0), &table, true)
            != Err(FsError::InvalidData)
        || query(&table, a, 0) != Some(3)
        || query(&table, b, so::SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED) != Some(0)
    {
        return TestResult::Fail("QUERY");
    }
    // TIMELINE_WAIT: point 3 signalled; point 5 unsubmitted is EINVAL, and
    // pending under WAIT_FOR_SUBMIT / WAIT_AVAILABLE until the deadline.
    let past = narf_time::monotonic_ns() as i64 - 1;
    if ioctl(0xca, &mut timeline_wait_req(&[a], &[3], 0, 0), &table, true) != Ok(0)
        || ioctl(0xca, &mut timeline_wait_req(&[a], &[5], 0, 0), &table, true)
            != Err(FsError::InvalidData)
        || ioctl(
            0xca,
            &mut timeline_wait_req(&[a], &[5], past, so::SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE),
            &table,
            true,
        ) != Ok(ETIME)
        || ioctl(
            0xca,
            &mut timeline_wait_req(&[a], &[5], 0, 0x10),
            &table,
            true,
        ) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("TIMELINE_WAIT errnos");
    }
    // WAIT_AVAILABLE: an attached but unsignalled point satisfies it; a
    // plain wait on it times out.
    let gate = fence();
    table
        .lock()
        .get(a)
        .unwrap()
        .core()
        .add_point(gate.clone(), 5);
    let (avail_handles, avail_points) = ([b, a], [0u64, 5]);
    let mut avail = timeline_wait_req(
        &avail_handles,
        &avail_points,
        past,
        so::SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE,
    );
    if ioctl(0xca, &mut avail, &table, true) != Ok(0)
        || u32::from_le_bytes(avail[32..36].try_into().unwrap()) != 1
    {
        return TestResult::Fail("TIMELINE_WAIT with WAIT_AVAILABLE");
    }
    if ioctl(
        0xca,
        &mut timeline_wait_req(&[a], &[5], past, 0),
        &table,
        true,
    ) != Ok(ETIME)
        || ioctl(
            0xca,
            &mut timeline_wait_req(&[a], &[4], past, 0),
            &table,
            true,
        ) != Ok(ETIME)
    {
        return TestResult::Fail("TIMELINE_WAIT on an attached unsignalled point");
    }
    if ioctl(
        0xca,
        &mut timeline_wait_req(&[a], &[3], past, 0),
        &table,
        true,
    ) != Ok(0)
    {
        return TestResult::Fail("TIMELINE_WAIT on a signalled earlier point");
    }
    gate.signal();
    // TRANSFER { src, dst, src_point, dst_point, flags, pad }.
    let transfer = |src: u32, dst: u32, sp: u64, dp: u64, flags: u32, pad: u32| {
        let mut t = [0u8; 32];
        t[0..4].copy_from_slice(&src.to_le_bytes());
        t[4..8].copy_from_slice(&dst.to_le_bytes());
        t[8..16].copy_from_slice(&sp.to_le_bytes());
        t[16..24].copy_from_slice(&dp.to_le_bytes());
        t[24..28].copy_from_slice(&flags.to_le_bytes());
        t[28..32].copy_from_slice(&pad.to_le_bytes());
        ioctl(0xcc, &mut t, &table, true)
    };
    let c = table.lock().create(0).unwrap();
    if transfer(a, b, 5, 0, 0, 1) != Err(FsError::InvalidData)
        || transfer(a, 0xdead, 5, 0, 0, 0) != Err(FsError::NotFound)
        || transfer(0xdead, b, 5, 0, 0, 0) != Err(FsError::NotFound)
        || transfer(a, b, 9, 0, 0, 0) != Err(FsError::InvalidData)
        || transfer(a, b, 5, 0, 4, 0) != Err(FsError::InvalidData)
        || transfer(c, b, 0, 0, 0, 0) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("TRANSFER errnos");
    }
    // Timeline point → binary, then binary → a timeline point of `c`.
    if transfer(a, b, 5, 0, 0, 0) != Ok(0) || !table.lock().get(b).unwrap().is_signalled() {
        return TestResult::Fail("TRANSFER to binary");
    }
    if transfer(b, c, 0, 7, 0, 0) != Ok(0) || query(&table, c, 0) != Some(7) {
        return TestResult::Fail("TRANSFER to a timeline point");
    }
    // WAIT_FOR_SUBMIT on an unsubmitted point: pending within 5 s of the
    // ioctl's start, -ETIME after (drm_syncobj_find_fence).
    let core = table.lock().get(c).unwrap().core().clone();
    let flags = u64::from(so::SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT);
    let now = narf_time::monotonic_ns();
    if !matches!(
        crate::drm::syncobj_ioctl::find_fence_step(&core, 9, flags, now),
        Ok(None)
    ) || !matches!(
        crate::drm::syncobj_ioctl::find_fence_step(
            &core,
            9,
            flags,
            now.saturating_sub(6_000_000_000)
        ),
        Err(Ok(ETIME))
    ) || !matches!(
        crate::drm::syncobj_ioctl::find_fence_step(&core, 9, 0, now),
        Err(Err(FsError::InvalidData))
    ) || !matches!(
        crate::drm::syncobj_ioctl::find_fence_step(&core, 7, flags, now),
        Ok(Some(_))
    ) {
        return TestResult::Fail("WAIT_FOR_SUBMIT lookup bound");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_timeline_ioctls);

// ── fds ───────────────────────────────────────────────────────────────

/// A descriptor table double: opaque files from fd 100, sync_files from
/// fd 200 (their leaves recorded), an eventfd double at fd 300.
struct Files {
    files: IrqSafeSpinLock<Vec<Arc<dyn FileOps>>>,
    syncs: IrqSafeSpinLock<Vec<Vec<Arc<dyn DrmFence>>>>,
    full: AtomicBool,
}
impl Default for Files {
    fn default() -> Self {
        Files {
            files: IrqSafeSpinLock::new(Vec::new()),
            syncs: IrqSafeSpinLock::new(Vec::new()),
            full: AtomicBool::new(false),
        }
    }
}
impl IoctlContext for Files {
    fn read(&self, _: u64, _: &mut [u8]) -> Result<(), FsError> {
        Err(FsError::BadAddress)
    }
    fn write(&self, _: u64, _: &[u8]) -> Result<(), FsError> {
        Err(FsError::BadAddress)
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn file(&self, fd: i32) -> Result<Arc<dyn FileOps>, FsError> {
        if (200..300).contains(&fd) {
            return Ok(Arc::new(Plain(None)));
        }
        self.files
            .lock()
            .get((fd - 100) as usize)
            .cloned()
            .ok_or(FsError::BadFd)
    }
    fn install_file(&self, file: Arc<dyn FileOps>, cloexec: bool) -> Result<i32, FsError> {
        if self.full.load(Ordering::SeqCst) || !cloexec {
            return Err(FsError::OutOfMemory);
        }
        let mut files = self.files.lock();
        files.push(file);
        Ok(99 + files.len() as i32)
    }
    fn sync_file_fences(&self, fd: i32) -> Option<Vec<Arc<dyn DrmFence>>> {
        self.syncs.lock().get((fd - 200) as usize).cloned()
    }
    fn install_sync_file(
        &self,
        fences: Vec<Arc<dyn DrmFence>>,
        report: &mut dyn FnMut(i32) -> Result<(), FsError>,
    ) -> Result<i32, narf_filesystem::InstallFdError> {
        if self.full.load(Ordering::SeqCst) {
            return Err(narf_filesystem::InstallFdError::NoDescriptor);
        }
        let fd = 200 + self.syncs.lock().len() as i32;
        report(fd).map_err(narf_filesystem::InstallFdError::Report)?;
        self.syncs.lock().push(fences);
        Ok(fd)
    }
}

/// A file of another type; with a name, an eventfd double recording writes.
struct Plain(Option<AtomicU32>);
impl FileOps for Plain {
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Ok(0) })
    }
    fn write<'a>(&'a self, _: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
        if let Some(n) = &self.0 {
            n.fetch_add(
                u64::from_le_bytes(b[0..8].try_into().unwrap()) as u32,
                Ordering::SeqCst,
            );
        }
        Box::pin(async { Ok(8) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }
    fn anon_name(&self) -> Option<&'static str> {
        self.0.as_ref().map(|_| "[eventfd]")
    }
}

fn handle_req(handle: u32, flags: u32, fd: i32, point: u64) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..4].copy_from_slice(&handle.to_le_bytes());
    b[4..8].copy_from_slice(&flags.to_le_bytes());
    b[8..12].copy_from_slice(&fd.to_le_bytes());
    b[16..24].copy_from_slice(&point.to_le_bytes());
    b
}

/// HANDLE_TO_FD / FD_TO_HANDLE: an opaque syncobj fd names the same object
/// in another open; EXPORT_SYNC_FILE / IMPORT_SYNC_FILE move fences
/// (with timeline points) through sync_files; the errnos of
/// `drm_syncobj_{handle_to_fd,fd_to_handle}_ioctl`.
fn sync_syncobj_and_sync_file_fds() -> TestResult {
    use crate::drm::syncobj_ioctl::{SYNCOBJ_FD_SYNC_FILE as SF, SYNCOBJ_FD_TIMELINE as TL};
    let files = Files::default();
    let (ta, tb) = (
        IrqSafeSpinLock::new(SyncObjTable::new()),
        IrqSafeSpinLock::new(SyncObjTable::new()),
    );
    let a = ta.lock().create(0).unwrap();
    // No descriptor table (a kernel caller): -EOPNOTSUPP.
    if ioctl(0xc1, &mut handle_req(a, 0, 0, 0), &ta, true) != Ok(EOPNOTSUPP) {
        return TestResult::Fail("fd ioctls need a descriptor table");
    }
    let mut padded = handle_req(a, 0, 0, 0);
    padded[12] = 1;
    if ioctl_files(0xc1, &mut padded, &ta, &files) != Err(FsError::InvalidData)
        || ioctl_files(0xc1, &mut handle_req(a, 4, 0, 0), &ta, &files) != Err(FsError::InvalidData)
        || ioctl_files(0xc1, &mut handle_req(a, 0, 0, 1), &ta, &files) != Err(FsError::InvalidData)
        || ioctl_files(0xc1, &mut handle_req(0xdead, 0, 0, 0), &ta, &files)
            != Err(FsError::InvalidData)
    {
        return TestResult::Fail("HANDLE_TO_FD errnos");
    }
    // Opaque export → import into another table: one object.
    let mut out = handle_req(a, 0, -1, 0);
    if ioctl_files(0xc1, &mut out, &ta, &files) != Ok(0) {
        return TestResult::Fail("HANDLE_TO_FD");
    }
    let fd = i32::from_le_bytes(out[8..12].try_into().unwrap());
    let mut imp = handle_req(0, 0, fd, 0);
    if ioctl_files(0xc2, &mut imp, &tb, &files) != Ok(0) {
        return TestResult::Fail("FD_TO_HANDLE");
    }
    let b = u32::from_le_bytes(imp[0..4].try_into().unwrap());
    tb.lock().get(b).unwrap().replace_fence(so::stub());
    if !ta.lock().get(a).unwrap().is_signalled() {
        return TestResult::Fail("an imported syncobj fd names the same object");
    }
    if ioctl_files(0xc2, &mut handle_req(0, 0, 999, 0), &tb, &files) != Err(FsError::InvalidData)
        || ioctl_files(0xc2, &mut handle_req(0, 0, 250, 0), &tb, &files)
            != Err(FsError::InvalidData)
        || ioctl_files(0xc2, &mut handle_req(0, 0, fd, 2), &tb, &files) != Err(FsError::InvalidData)
    {
        return TestResult::Fail("FD_TO_HANDLE errnos");
    }
    // EXPORT_SYNC_FILE: unknown ENOENT, no fence EINVAL, a timeline point
    // exports that point's fences.
    let t = ta.lock().create(0).unwrap();
    let (p1, p2) = (fence(), fence());
    {
        let table = ta.lock();
        let core = table.get(t).unwrap().core();
        core.add_point(p1.clone(), 1);
        core.add_point(p2.clone(), 2);
    }
    let empty = ta.lock().create(0).unwrap();
    if ioctl_files(0xc1, &mut handle_req(0xdead, SF, 0, 0), &ta, &files) != Err(FsError::NotFound)
        || ioctl_files(0xc1, &mut handle_req(empty, SF, 0, 0), &ta, &files)
            != Err(FsError::InvalidData)
        || ioctl_files(0xc1, &mut handle_req(t, SF | TL, 0, 3), &ta, &files)
            != Err(FsError::InvalidData)
    {
        return TestResult::Fail("EXPORT_SYNC_FILE errnos");
    }
    let mut ex = handle_req(t, SF | TL, -1, 1);
    if ioctl_files(0xc1, &mut ex, &ta, &files) != Ok(0) {
        return TestResult::Fail("EXPORT_SYNC_FILE point 1");
    }
    let sync_fd = i32::from_le_bytes(ex[8..12].try_into().unwrap());
    let leaves = files.sync_file_fences(sync_fd).unwrap();
    if leaves.len() != 1 || leaves[0].is_signalled() {
        return TestResult::Fail("point 1 exports its one pending fence");
    }
    p1.signal();
    if !leaves.iter().all(|l| l.is_signalled()) {
        return TestResult::Fail("the sync_file follows the point's fence");
    }
    // Full descriptor table: EMFILE.
    files.full.store(true, Ordering::SeqCst);
    let full = ioctl_files(0xc1, &mut handle_req(t, SF, -1, 0), &ta, &files);
    files.full.store(false, Ordering::SeqCst);
    if full != Ok((-24i64) as u64) {
        return TestResult::Fail("EXPORT_SYNC_FILE: EMFILE");
    }
    // IMPORT_SYNC_FILE: a bad fd / non-sync_file EINVAL before an unknown
    // handle's ENOENT; with TIMELINE the fence becomes a point.
    let dst = tb.lock().create(0).unwrap();
    if ioctl_files(0xc2, &mut handle_req(0xdead, SF, 150, 0), &tb, &files)
        != Err(FsError::InvalidData)
        || ioctl_files(0xc2, &mut handle_req(0xdead, SF, sync_fd, 0), &tb, &files)
            != Err(FsError::NotFound)
        || ioctl_files(0xc2, &mut handle_req(dst, SF | TL, sync_fd, 4), &tb, &files) != Ok(0)
        || query(&tb, dst, so::SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED) != Some(4)
        || query(&tb, dst, 0) != Some(4)
    {
        return TestResult::Fail("IMPORT_SYNC_FILE");
    }
    let pending = handle_req(t, SF, -1, 0);
    let mut pending = pending;
    if ioctl_files(0xc1, &mut pending, &ta, &files) != Ok(0) {
        return TestResult::Fail("EXPORT_SYNC_FILE whole timeline");
    }
    let whole = i32::from_le_bytes(pending[8..12].try_into().unwrap());
    if ioctl_files(0xc2, &mut handle_req(dst, SF, whole, 0), &tb, &files) != Ok(0)
        || tb.lock().get(dst).unwrap().is_signalled()
    {
        return TestResult::Fail("IMPORT_SYNC_FILE of a pending point");
    }
    p2.signal();
    if !tb.lock().get(dst).unwrap().is_signalled() {
        return TestResult::Fail("an imported sync_file signals with its fence");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_syncobj_and_sync_file_fds);

/// SYNCOBJ_EVENTFD errnos (`drm_syncobj_eventfd_ioctl`) and its watcher:
/// WAIT_AVAILABLE signals once the point is attached, otherwise once it
/// signals; a freed syncobj never signals.
fn sync_eventfd() -> TestResult {
    let files = Files::default();
    let table = IrqSafeSpinLock::new(SyncObjTable::new());
    let h = table.lock().create(0).unwrap();
    let not_eventfd = files.install_file(Arc::new(Plain(None)), true).unwrap();
    let req = |handle: u32, flags: u32, fd: i32, pad: u32| {
        let mut b = [0u8; 24];
        b[0..4].copy_from_slice(&handle.to_le_bytes());
        b[4..8].copy_from_slice(&flags.to_le_bytes());
        b[16..20].copy_from_slice(&fd.to_le_bytes());
        b[20..24].copy_from_slice(&pad.to_le_bytes());
        b
    };
    if ioctl_files(0xcf, &mut req(h, 2, not_eventfd, 0), &table, &files)
        != Err(FsError::InvalidData)
        || ioctl_files(0xcf, &mut req(h, 0, not_eventfd, 1), &table, &files)
            != Err(FsError::InvalidData)
        || ioctl_files(0xcf, &mut req(0xdead, 0, not_eventfd, 0), &table, &files)
            != Err(FsError::NotFound)
        || ioctl_files(0xcf, &mut req(h, 0, 999, 0), &table, &files) != Ok(EBADF)
        || ioctl_files(0xcf, &mut req(h, 0, not_eventfd, 0), &table, &files)
            != Err(FsError::InvalidData)
    {
        return TestResult::Fail("EVENTFD errnos");
    }
    let core = table.lock().get(h).unwrap().core().clone();
    let gate = fence();
    core.add_point(gate.clone(), 2);
    let watch = |available: bool| {
        let ev = Arc::new(Plain(Some(AtomicU32::new(0))));
        let file: Arc<dyn FileOps> = ev.clone();
        let fut = crate::drm::syncobj_ioctl::eventfd_watch(core.clone(), 2, available, file);
        (ev, fut)
    };
    let (ev, fut) = watch(true);
    narf_scheduler::block_on_spin(fut);
    if ev.0.as_ref().unwrap().load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("WAIT_AVAILABLE signals an attached point");
    }
    let (ev, fut) = watch(false);
    let mut fut = core::pin::pin!(fut);
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    if fut.as_mut().poll(&mut cx).is_ready() || ev.0.as_ref().unwrap().load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("an unsignalled point does not signal the eventfd");
    }
    gate.signal();
    narf_scheduler::block_on_spin(fut);
    if ev.0.as_ref().unwrap().load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("the point signalled");
    }
    // A point that never comes, on a syncobj that is freed: no signal.
    let lone = SyncObjCore::new(None);
    let ev = Arc::new(Plain(Some(AtomicU32::new(0))));
    let fut = crate::drm::syncobj_ioctl::eventfd_watch(lone, 1, true, ev.clone());
    narf_scheduler::block_on_spin(fut);
    if ev.0.as_ref().unwrap().load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("a freed syncobj never signals");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_eventfd);

/// DRM_CAP_SYNCOBJ_TIMELINE: 1 on amdgpu, 0 in the generic table.
fn sync_timeline_cap() -> TestResult {
    let cap = crate::drm::ioctl::drm_cap::SYNCOBJ_TIMELINE;
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&cap.to_le_bytes());
    let get_cap = 0xc010_640c;
    if crate::drm_ioctl_bridge::amdgpu_get_cap(get_cap, b.as_mut_ptr() as usize) != Some(Ok(0))
        || u64::from_le_bytes(b[8..16].try_into().unwrap()) != 1
        || crate::drm::ioctl::cap_value(cap) != 0
        || crate::drm_ioctl_bridge::amdgpu_cap_value(crate::drm::ioctl::drm_cap::SYNCOBJ) != 1
    {
        return TestResult::Fail("SYNCOBJ_TIMELINE cap");
    }
    let mut other = [0u8; 16];
    other[0..8].copy_from_slice(&crate::drm::ioctl::drm_cap::PRIME.to_le_bytes());
    if crate::drm_ioctl_bridge::amdgpu_get_cap(get_cap, other.as_mut_ptr() as usize).is_some() {
        return TestResult::Fail("other caps fall through to the card table");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_timeline_cap);

// ── amdgpu: CS, WAIT_FENCES, FENCE_TO_HANDLE, BO_LIST ─────────────────

const fn amd(nr: u32) -> u32 {
    0xc000_0000 | (0x64 << 8) | (0x40 + nr)
}

/// A submitter double shaped like one card's queues: Navi 22 (gfx, the
/// compute queue for rings 0–3, SDMA0/1; `amdgpu_navi22_cs` ticket rings)
/// or Navi 48 (gfx, compute, SDMA0). Jobs complete when the test says.
struct Engine {
    navi22: bool,
    issued: [AtomicU32; 4],
    completed: [AtomicU32; 4],
}
impl Engine {
    fn new(navi22: bool) -> Arc<Self> {
        Arc::new(Engine {
            navi22,
            issued: Default::default(),
            completed: Default::default(),
        })
    }
    fn complete_all(&self) {
        for i in 0..4 {
            self.completed[i].store(self.issued[i].load(Ordering::SeqCst), Ordering::SeqCst);
        }
    }
    fn index(&self, ring: u32) -> usize {
        (ring & 3) as usize
    }
}
impl crate::amdgpu_cs::Submitter for Engine {
    fn submit<'a>(
        &'a self,
        _vm: &'a crate::amdgpu_vm::VmState,
        s: &'a crate::amdgpu_cs::Submission,
        _health: &'a alloc::sync::Arc<crate::amdgpu_ctx::Health>,
    ) -> Pin<Box<dyn Future<Output = Result<u64, FsError>> + Send + 'a>> {
        Box::pin(async move {
            let ib = s.ibs[0];
            let ring = self
                .ring_for(ib.ip_type, ib.ip_instance, ib.ring)
                .ok_or(FsError::Unsupported)?;
            let seq = self.issued[self.index(ring)].fetch_add(1, Ordering::SeqCst) + 1;
            Ok(u64::from(ring) << 32 | u64::from(seq))
        })
    }
    fn signalled(&self, ticket: u64) -> bool {
        let ring = (ticket >> 32) as u32;
        self.completed[self.index(ring)].load(Ordering::SeqCst) >= ticket as u32
    }
    fn ring_for(&self, ip: u32, inst: u32, ring: u32) -> Option<u32> {
        if self.navi22 {
            crate::amdgpu_navi22_cs::ring_id(ip, inst, ring)
                .map(|id| crate::amdgpu_navi22_cs::ring_index(0, id))
        } else {
            match (ip, inst, ring) {
                (u::AMDGPU_HW_IP_GFX, 0, 0) => Some(0),
                (u::AMDGPU_HW_IP_COMPUTE, 0, 0) => Some(1),
                (u::AMDGPU_HW_IP_DMA, 0, 0) => Some(2),
                _ => None,
            }
        }
    }
    fn wait(
        &self,
        seq: u64,
        _deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, FsError>> + Send + '_>> {
        Box::pin(async move { Ok(self.signalled(seq)) })
    }
}

/// One open with a mapped IB buffer and a context.
struct Rig {
    gem: crate::amdgpu_gem::GemState,
    vm: crate::amdgpu_vm::VmState,
    ctx: crate::amdgpu_ctx::CtxState,
    syncobjs: IrqSafeSpinLock<SyncObjTable>,
    bo_lists: crate::amdgpu_bo_list::BoListTable,
    ctx_id: u32,
    card: u32,
}
const IB_VA: u64 = 0xffff_8001_0000_0000;
impl Rig {
    fn new(card: u32) -> Self {
        let rig = Rig {
            gem: crate::amdgpu_gem::GemState::for_card(card),
            vm: crate::amdgpu_vm::VmState::new(),
            ctx: crate::amdgpu_ctx::CtxState::new(),
            syncobjs: IrqSafeSpinLock::new(SyncObjTable::new()),
            bo_lists: crate::amdgpu_bo_list::BoListTable::new(),
            ctx_id: 0,
            card,
        };
        let bo = rig.bo(4096);
        let mut va = [0u8; 40];
        va[0..4].copy_from_slice(&bo.to_le_bytes());
        va[8..12].copy_from_slice(&u::AMDGPU_VA_OP_MAP.to_le_bytes());
        va[12..16].copy_from_slice(&0x0eu32.to_le_bytes());
        va[16..24].copy_from_slice(&IB_VA.to_le_bytes());
        va[32..40].copy_from_slice(&4096u64.to_le_bytes());
        crate::amdgpu_vm::dispatch(
            amd(u::DRM_AMDGPU_GEM_VA),
            va.as_mut_ptr() as usize,
            &rig.vm,
            &rig.gem,
        )
        .unwrap();
        let mut c = [0u8; 16];
        c[0..4].copy_from_slice(&u::AMDGPU_CTX_OP_ALLOC_CTX.to_le_bytes());
        crate::amdgpu_ctx::dispatch(
            amd(u::DRM_AMDGPU_CTX),
            c.as_mut_ptr() as usize,
            &rig.ctx,
            false,
        )
        .unwrap();
        Rig {
            ctx_id: u32::from_le_bytes(c[0..4].try_into().unwrap()),
            ..rig
        }
    }
    fn bo(&self, size: u64) -> u32 {
        self.bo_flags(size, 0)
    }
    fn bo_flags(&self, size: u64, flags: u64) -> u32 {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&size.to_le_bytes());
        b[16..24].copy_from_slice(&(u::AMDGPU_GEM_DOMAIN_GTT as u64).to_le_bytes());
        b[24..32].copy_from_slice(&flags.to_le_bytes());
        crate::amdgpu_gem::dispatch(
            amd(u::DRM_AMDGPU_GEM_CREATE),
            b.as_mut_ptr() as usize,
            &self.gem,
        )
        .unwrap();
        u32::from_le_bytes(b[0..4].try_into().unwrap())
    }
    fn open<'a>(&'a self, files: Option<&'a dyn IoctlContext>) -> crate::amdgpu_cs::CsOpen<'a> {
        crate::amdgpu_cs::CsOpen {
            vm: &self.vm,
            gem: &self.gem,
            ctx: &self.ctx,
            syncobjs: &self.syncobjs,
            bo_lists: &self.bo_lists,
            files,
        }
    }
    /// An async amdgpu ioctl, run to completion (it must not block).
    fn run(
        &self,
        cmd: u32,
        arg: &mut [u8],
        files: Option<&dyn IoctlContext>,
    ) -> Result<u64, FsError> {
        narf_scheduler::block_on_spin(crate::amdgpu_cs::dispatch_async(
            self.card,
            cmd,
            arg.as_mut_ptr() as usize,
            &self.open(files),
        ))
    }
    /// An AMDGPU_CS request of one IB on `ip` plus `extra` chunks.
    fn cs_req(&self, ip: u32, extra: &[(u32, Vec<u32>)], bo_list: u32) -> CsReq {
        let mut ib = [0u32; 8];
        ib[2] = (IB_VA + 0x100) as u32;
        ib[3] = ((IB_VA + 0x100) >> 32) as u32;
        ib[4] = 64;
        ib[5] = ip;
        let mut bodies: Vec<Vec<u32>> = alloc::vec![ib.to_vec()];
        let mut ids = alloc::vec![u::AMDGPU_CHUNK_ID_IB];
        for (id, body) in extra {
            bodies.push(body.clone());
            ids.push(*id);
        }
        let headers: Vec<[u32; 4]> = bodies
            .iter()
            .zip(&ids)
            .map(|(b, id)| {
                let at = b.as_ptr() as u64;
                [*id, b.len() as u32, at as u32, (at >> 32) as u32]
            })
            .collect();
        let pointers: Vec<u64> = headers.iter().map(|h| h.as_ptr() as u64).collect();
        let mut req = [0u8; 24];
        req[0..4].copy_from_slice(&self.ctx_id.to_le_bytes());
        req[4..8].copy_from_slice(&bo_list.to_le_bytes());
        req[8..12].copy_from_slice(&(pointers.len() as u32).to_le_bytes());
        req[16..24].copy_from_slice(&(pointers.as_ptr() as u64).to_le_bytes());
        CsReq {
            _bodies: bodies,
            _headers: headers,
            _pointers: pointers,
            req,
        }
    }
    /// AMDGPU_CS of one IB on `ip` plus `extra` chunks; the ticket.
    fn cs(&self, ip: u32, extra: &[(u32, Vec<u32>)], bo_list: u32) -> Result<u64, FsError> {
        let mut r = self.cs_req(ip, extra, bo_list);
        self.run(amd(u::DRM_AMDGPU_CS), &mut r.req, None)?;
        Ok(u64::from_le_bytes(r.req[0..8].try_into().unwrap()))
    }
}

/// A CS request and the storage its pointers name.
struct CsReq {
    _bodies: Vec<Vec<u32>>,
    _headers: Vec<[u32; 4]>,
    _pointers: Vec<u64>,
    req: [u8; 24],
}

fn syncobj_entry(handle: u32, flags: u32, point: u64) -> Vec<u32> {
    alloc::vec![handle, flags, point as u32, (point >> 32) as u32]
}

fn bo_handles_chunk(handles: &[u32]) -> (Vec<[u32; 2]>, Vec<u32>) {
    let entries: Vec<[u32; 2]> = handles.iter().map(|&h| [h, 0]).collect();
    let at = entries.as_ptr() as u64;
    let body = alloc::vec![0, 0, handles.len() as u32, 8, at as u32, (at >> 32) as u32];
    (entries, body)
}

/// The CS synchronisation chunks on both engine shapes: TIMELINE_SIGNAL
/// attaches the job as a point (and point 0 as the payload), TIMELINE_WAIT
/// and SYNCOBJ_IN resolve with Linux's errnos, out-syncobjs must exist
/// (EINVAL), and a dependency on a job its ring never emitted is EINVAL.
fn sync_cs_timeline_chunks_and_dependencies() -> TestResult {
    for (card, navi22) in [(0x7ffe_0501u32, true), (0x7ffe_0502, false)] {
        let engine = Engine::new(navi22);
        crate::amdgpu_cs::register_submitter(card, engine.clone());
        let result = (|| -> Option<&'static str> {
            let rig = Rig::new(card);
            let tl = rig.syncobjs.lock().create(0).unwrap();
            let bin = rig.syncobjs.lock().create(0).unwrap();
            // Point 3 on `tl`, the payload of `bin`, in one chunk.
            let mut signal = syncobj_entry(tl, 0, 3);
            signal.extend(syncobj_entry(bin, 0, 0));
            let Ok(t1) = rig.cs(
                u::AMDGPU_HW_IP_GFX,
                &[(u::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL, signal)],
                0,
            ) else {
                return Some("CS with TIMELINE_SIGNAL");
            };
            if query(&rig.syncobjs, tl, so::SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED) != Some(3)
                || query(&rig.syncobjs, tl, 0) != Some(0)
                || rig.syncobjs.lock().get(bin).unwrap().is_signalled()
            {
                return Some("the job is point 3 and the binary payload, pending");
            }
            // SYNCOBJ_TIMELINE_WAIT on point 3 (pending) must not run yet;
            // on point 4 (not submitted) is EINVAL; unknown syncobj ENOENT;
            // an unknown out-syncobj EINVAL; an unknown flag EINVAL.
            if rig.cs(
                u::AMDGPU_HW_IP_GFX,
                &[(
                    u::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT,
                    syncobj_entry(tl, 0, 4),
                )],
                0,
            ) != Err(FsError::InvalidData)
                || rig.cs(
                    u::AMDGPU_HW_IP_GFX,
                    &[(
                        u::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT,
                        syncobj_entry(0xdead, 0, 1),
                    )],
                    0,
                ) != Err(FsError::NotFound)
                || rig.cs(
                    u::AMDGPU_HW_IP_GFX,
                    &[(
                        u::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT,
                        syncobj_entry(tl, 4, 1),
                    )],
                    0,
                ) != Err(FsError::InvalidData)
                || rig.cs(
                    u::AMDGPU_HW_IP_GFX,
                    &[(u::AMDGPU_CHUNK_ID_SYNCOBJ_OUT, alloc::vec![0xdead])],
                    0,
                ) != Err(FsError::InvalidData)
                || rig.cs(
                    u::AMDGPU_HW_IP_GFX,
                    &[(u::AMDGPU_CHUNK_ID_SYNCOBJ_IN, alloc::vec![0xdead])],
                    0,
                ) != Err(FsError::NotFound)
            {
                return Some("CS syncobj errnos");
            }
            engine.complete_all();
            if query(&rig.syncobjs, tl, 0) != Some(3)
                || !rig.syncobjs.lock().get(bin).unwrap().is_signalled()
            {
                return Some("point 3 signalled with the job");
            }
            if ioctl(
                0xca,
                &mut timeline_wait_req(&[tl], &[3], 0, 0),
                &rig.syncobjs,
                true,
            ) != Ok(0)
            {
                return Some("TIMELINE_WAIT on the job's point");
            }
            let Ok(_) = rig.cs(
                u::AMDGPU_HW_IP_GFX,
                &[(
                    u::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT,
                    syncobj_entry(tl, 0, 3),
                )],
                0,
            ) else {
                return Some("CS waiting on a signalled point");
            };
            // Dependencies: { ip, inst, ring, ctx, handle(lo, hi) }.
            let dep = |ip: u32, ring: u32, ctx: u32, handle: u64| {
                alloc::vec![ip, 0, ring, ctx, handle as u32, (handle >> 32) as u32]
            };
            let future = t1 + 100;
            let gfx = u::AMDGPU_HW_IP_GFX;
            if rig.cs(
                gfx,
                &[(
                    u::AMDGPU_CHUNK_ID_DEPENDENCIES,
                    dep(gfx, 0, rig.ctx_id, future),
                )],
                0,
            ) != Err(FsError::InvalidData)
                || rig.cs(
                    gfx,
                    &[(
                        u::AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES,
                        dep(gfx, 0, rig.ctx_id, future),
                    )],
                    0,
                ) != Err(FsError::InvalidData)
                || rig.cs(
                    gfx,
                    &[(
                        u::AMDGPU_CHUNK_ID_DEPENDENCIES,
                        dep(u::AMDGPU_HW_IP_DMA, 0, rig.ctx_id, t1),
                    )],
                    0,
                ) != Err(FsError::InvalidData)
                || rig.cs(
                    gfx,
                    &[(u::AMDGPU_CHUNK_ID_DEPENDENCIES, dep(gfx, 9, rig.ctx_id, 0))],
                    0,
                ) != Err(FsError::InvalidData)
                || rig.cs(
                    gfx,
                    &[(
                        u::AMDGPU_CHUNK_ID_DEPENDENCIES,
                        dep(gfx, 0, rig.ctx_id + 9, 0),
                    )],
                    0,
                ) != Err(FsError::InvalidData)
                || rig
                    .cs(
                        gfx,
                        &[(u::AMDGPU_CHUNK_ID_DEPENDENCIES, dep(gfx, 0, rig.ctx_id, t1))],
                        0,
                    )
                    .is_err()
                || rig
                    .cs(
                        gfx,
                        &[(u::AMDGPU_CHUNK_ID_DEPENDENCIES, dep(gfx, 0, rig.ctx_id, 0))],
                        0,
                    )
                    .is_err()
            {
                return Some("dependency resolution");
            }
            None
        })();
        crate::amdgpu_cs::unregister_submitter(card);
        if let Some(why) = result {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm-sync",
    sync_cs_timeline_chunks_and_dependencies
);

fn fence_req(ctx: u32, ip: u32, ring: u32, seq: u64) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0..4].copy_from_slice(&ctx.to_le_bytes());
    b[4..8].copy_from_slice(&ip.to_le_bytes());
    b[12..16].copy_from_slice(&ring.to_le_bytes());
    b[16..24].copy_from_slice(&seq.to_le_bytes());
    b
}

/// AMDGPU_WAIT_FENCES (`amdgpu_cs_wait_fences_ioctl`) and
/// AMDGPU_FENCE_TO_HANDLE (`amdgpu_cs_fence_to_handle_ioctl`) on both
/// engine shapes, and without an engine.
fn sync_wait_fences_and_fence_to_handle() -> TestResult {
    for (card, navi22) in [(0x7ffe_0511u32, true), (0x7ffe_0512, false)] {
        let engine = Engine::new(navi22);
        let rig = Rig::new(card);
        let wait = |fences: &[[u8; 24]], all: bool, timeout: u64| {
            let flat: Vec<u8> = fences.iter().flatten().copied().collect();
            let mut b = [0u8; 24];
            b[0..8].copy_from_slice(&(flat.as_ptr() as u64).to_le_bytes());
            b[8..12].copy_from_slice(&(fences.len() as u32).to_le_bytes());
            b[12..16].copy_from_slice(&u32::from(all).to_le_bytes());
            b[16..24].copy_from_slice(&timeout.to_le_bytes());
            rig.run(amd(u::DRM_AMDGPU_WAIT_FENCES), &mut b, None)
                .map(|_| {
                    (
                        u32::from_le_bytes(b[0..4].try_into().unwrap()),
                        u32::from_le_bytes(b[4..8].try_into().unwrap()),
                    )
                })
        };
        let gfx = u::AMDGPU_HW_IP_GFX;
        // No engine: handle 0 is signalled, anything else EINVAL.
        if wait(&[fence_req(rig.ctx_id, gfx, 0, 0)], true, 0) != Ok((1, 0))
            || wait(&[fence_req(rig.ctx_id, gfx, 0, 5)], true, 0) != Err(FsError::InvalidData)
        {
            return TestResult::Fail("WAIT_FENCES without an engine");
        }
        crate::amdgpu_cs::register_submitter(card, engine.clone());
        let result = (|| -> Option<&'static str> {
            let t1 = rig.cs(gfx, &[], 0).ok()?;
            let t2 = rig.cs(u::AMDGPU_HW_IP_DMA, &[], 0).ok()?;
            let f1 = fence_req(rig.ctx_id, gfx, 0, t1);
            let f2 = fence_req(rig.ctx_id, u::AMDGPU_HW_IP_DMA, 0, t2);
            if wait(&[], true, 0) != Err(FsError::InvalidData)
                || wait(&[fence_req(rig.ctx_id + 7, gfx, 0, t1)], true, 0)
                    != Err(FsError::InvalidData)
                || wait(&[fence_req(rig.ctx_id, gfx, 0, t1 + 1)], true, 0)
                    != Err(FsError::InvalidData)
                || wait(&[fence_req(rig.ctx_id, gfx, 0, t2)], true, 0) != Err(FsError::InvalidData)
                || wait(&[f1, f2], true, 0) != Ok((0, 0))
                || wait(&[f1, f2], false, 0) != Ok((0, !0))
                || wait(&[f1, fence_req(rig.ctx_id, gfx, 0, 0)], false, 0) != Ok((1, 1))
            {
                return Some("WAIT_FENCES pending");
            }
            // DMA completes first: ANY names it, ALL still waits.
            let dma = engine.index((t2 >> 32) as u32);
            engine.completed[dma].store(t2 as u32, Ordering::SeqCst);
            if wait(&[f1, f2], false, 0) != Ok((1, 1)) || wait(&[f1, f2], true, 0) != Ok((0, 0)) {
                return Some("WAIT_FENCES partial");
            }
            // ALL stops at the first timeout: an invalid entry after it is
            // not reached.
            if wait(&[f1, fence_req(rig.ctx_id, gfx, 0, t1 + 9)], true, 0) != Ok((0, 0)) {
                return Some("WAIT_FENCES all stops at the first timeout");
            }
            engine.complete_all();
            if wait(&[f1, f2], true, 0) != Ok((1, 0)) || wait(&[f1, f2], false, 0) != Ok((1, 0)) {
                return Some("WAIT_FENCES complete");
            }
            // FENCE_TO_HANDLE.
            let t3 = rig.cs(gfx, &[], 0).ok()?;
            let files = Files::default();
            let to_handle = |seq: u64, what: u32, files: Option<&dyn IoctlContext>| {
                let mut b = [0u8; 32];
                b[0..24].copy_from_slice(&fence_req(rig.ctx_id, gfx, 0, seq));
                b[24..28].copy_from_slice(&what.to_le_bytes());
                rig.run(amd(u::DRM_AMDGPU_FENCE_TO_HANDLE), &mut b, files)
                    .map(|r| (r, u32::from_le_bytes(b[0..4].try_into().unwrap())))
            };
            let Ok((0, h)) = to_handle(t3, u::AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ, None) else {
                return Some("FENCE_TO_HANDLE syncobj");
            };
            if rig.syncobjs.lock().get(h).unwrap().is_signalled() {
                return Some("the syncobj holds the pending job");
            }
            let Ok((0, sync_fd)) =
                to_handle(t3, u::AMDGPU_FENCE_TO_HANDLE_GET_SYNC_FILE_FD, Some(&files))
            else {
                return Some("FENCE_TO_HANDLE sync_file");
            };
            let leaves = files.sync_file_fences(sync_fd as i32)?;
            if leaves.len() != 1
                || leaves[0].seqno() != t3
                || leaves[0].driver_name() != "amdgpu"
                || leaves[0].is_signalled()
            {
                return Some("the sync_file holds the job itself");
            }
            let Ok((0, obj_fd)) =
                to_handle(t3, u::AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ_FD, Some(&files))
            else {
                return Some("FENCE_TO_HANDLE syncobj fd");
            };
            let mut imp = handle_req(0, 0, obj_fd as i32, 0);
            if ioctl_files(0xc2, &mut imp, &rig.syncobjs, &files) != Ok(0) {
                return Some("the syncobj fd imports");
            }
            if to_handle(t3, u::AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ_FD, None).map(|r| r.0)
                != Ok(EOPNOTSUPP)
                || to_handle(t3, 3, None) != Err(FsError::InvalidData)
                || to_handle(t3 + 5, 3, None) != Err(FsError::InvalidData)
            {
                return Some("FENCE_TO_HANDLE errnos");
            }
            let Ok((0, stub)) = to_handle(0, u::AMDGPU_FENCE_TO_HANDLE_GET_SYNCOBJ, None) else {
                return Some("FENCE_TO_HANDLE of handle 0");
            };
            if !rig.syncobjs.lock().get(stub).unwrap().is_signalled() {
                return Some("handle 0 is the signalled stub");
            }
            engine.complete_all();
            if !leaves[0].is_signalled() || !rig.syncobjs.lock().get(h).unwrap().is_signalled() {
                return Some("both follow the job");
            }
            None
        })();
        crate::amdgpu_cs::unregister_submitter(card);
        if let Some(why) = result {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_wait_fences_and_fence_to_handle);

/// AMDGPU_BO_LIST create/update/destroy (`amdgpu_bo_list_ioctl`) and a CS
/// naming a list (`amdgpu_cs_parser_bos`).
fn sync_bo_list_ioctl() -> TestResult {
    let card = 0x7ffe_0521;
    let engine = Engine::new(true);
    let rig = Rig::new(card);
    let (a, b) = (rig.bo(4096), rig.bo(4096));
    let entries = [[a, 3u32], [b, 1u32]];
    let req = |op: u32, handle: u32, count: u32, size: u32, ptr: u64| {
        let mut r = [0u8; 24];
        r[0..4].copy_from_slice(&op.to_le_bytes());
        r[4..8].copy_from_slice(&handle.to_le_bytes());
        r[8..12].copy_from_slice(&count.to_le_bytes());
        r[12..16].copy_from_slice(&size.to_le_bytes());
        r[16..24].copy_from_slice(&ptr.to_le_bytes());
        r
    };
    let list_ioctl = |r: &mut [u8; 24]| {
        crate::amdgpu_bo_list::dispatch(
            amd(u::DRM_AMDGPU_BO_LIST),
            r.as_mut_ptr() as usize,
            &rig.bo_lists,
            &rig.gem,
        )
        .map(|_| u32::from_le_bytes(r[0..4].try_into().unwrap()))
    };
    let ptr = entries.as_ptr() as u64;
    let bad = [[0xdeadu32, 0]];
    let Ok(l1) = list_ioctl(&mut req(u::AMDGPU_BO_LIST_OP_CREATE, 0, 2, 8, ptr)) else {
        return TestResult::Fail("BO_LIST create");
    };
    if l1 != 1
        || list_ioctl(&mut req(
            u::AMDGPU_BO_LIST_OP_CREATE,
            0,
            1,
            8,
            bad.as_ptr() as u64,
        )) != Err(FsError::NotFound)
        || list_ioctl(&mut req(
            u::AMDGPU_BO_LIST_OP_CREATE,
            0,
            crate::amdgpu_bo_list::MAX_ENTRIES + 1,
            8,
            ptr,
        )) != Err(FsError::InvalidData)
        || list_ioctl(&mut req(
            u::AMDGPU_BO_LIST_OP_DESTROY,
            0,
            crate::amdgpu_bo_list::MAX_ENTRIES + 1,
            8,
            ptr,
        )) != Err(FsError::InvalidData)
        || list_ioctl(&mut req(9, 0, 0, 8, 0)) != Err(FsError::InvalidData)
        || list_ioctl(&mut req(u::AMDGPU_BO_LIST_OP_UPDATE, 77, 1, 8, ptr))
            != Err(FsError::NotFound)
        || list_ioctl(&mut req(u::AMDGPU_BO_LIST_OP_UPDATE, l1, 1, 8, ptr)) != Ok(l1)
        || list_ioctl(&mut req(u::AMDGPU_BO_LIST_OP_DESTROY, 77, 0, 8, 0)) != Ok(0)
    {
        return TestResult::Fail("BO_LIST errnos");
    }
    // A 4-byte entry size: handles only, priorities zero; a 16-byte one
    // reads the leading 8 bytes of each.
    let wide = [[a, 0, 0xffff, 0xffff], [b, 2, 0, 0]];
    if list_ioctl(&mut req(
        u::AMDGPU_BO_LIST_OP_CREATE,
        0,
        2,
        16,
        wide.as_ptr() as u64,
    )) != Ok(2)
        || list_ioctl(&mut req(
            u::AMDGPU_BO_LIST_OP_CREATE,
            0,
            1,
            4,
            [a].as_ptr() as u64,
        )) != Ok(3)
        || rig.bo_lists.get(2).map(|l| l.len()) != Ok(2)
        || rig.bo_lists.get(l1).map(|l| l.len()) != Ok(1)
    {
        return TestResult::Fail("BO_LIST entry sizes");
    }
    crate::amdgpu_cs::register_submitter(card, engine.clone());
    let result = (|| -> Option<&'static str> {
        let (_keep, body) = bo_handles_chunk(&[a]);
        let gfx = u::AMDGPU_HW_IP_GFX;
        if rig.cs(gfx, &[], 2).is_err()
            || rig.cs(gfx, &[], 99) != Err(FsError::NotFound)
            || rig.cs(gfx, &[(u::AMDGPU_CHUNK_ID_BO_HANDLES, body)], 2) != Err(FsError::InvalidData)
        {
            return Some("CS with a BO list handle");
        }
        // The list's buffers got the job as writer.
        let object = rig.gem.object(b)?;
        if object
            .dma_buf()
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Read)
            .is_empty()
        {
            return Some("a listed buffer gets the job's fence");
        }
        let mut destroy = req(u::AMDGPU_BO_LIST_OP_DESTROY, 2, 0, 8, 0);
        if list_ioctl(&mut destroy) != Ok(0) || rig.cs(gfx, &[], 2) != Err(FsError::NotFound) {
            return Some("a destroyed list");
        }
        None
    })();
    crate::amdgpu_cs::unregister_submitter(card);
    match result {
        Some(why) => TestResult::Fail(why),
        None => TestResult::Pass,
    }
}
kernel_test_in!("drivers/gpu/drm-sync", sync_bo_list_ioctl);

/// Implicit sync as `amdgpu_cs_sync_rings` / `amdgpu_cs_submit`: the job
/// becomes the writer of every listed buffer and of the user fence buffer,
/// never of an unlisted one; a fence of the open's own address space does
/// not hold the job (AMDGPU_SYNC_NE_OWNER), a foreign one does; GEM_WAIT_IDLE
/// on an unlisted buffer is idle, on a VM_ALWAYS_VALID one waits for the
/// space's jobs.
fn sync_implicit_sync_follows_linux() -> TestResult {
    for (card, navi22) in [(0x7ffe_0531u32, true), (0x7ffe_0532, false)] {
        let engine = Engine::new(navi22);
        crate::amdgpu_cs::register_submitter(card, engine.clone());
        let result = (|| -> Option<&'static str> {
            let rig = Rig::new(card);
            let (listed, unlisted, uf) = (rig.bo(4096), rig.bo(4096), rig.bo(4096));
            let always = rig.bo_flags(4096, u64::from(u::AMDGPU_GEM_CREATE_VM_ALWAYS_VALID));
            let (_keep, body) = bo_handles_chunk(&[listed]);
            let gfx = u::AMDGPU_HW_IP_GFX;
            let fence_chunk = alloc::vec![uf, 0];
            rig.cs(
                gfx,
                &[
                    (u::AMDGPU_CHUNK_ID_BO_HANDLES, body.clone()),
                    (u::AMDGPU_CHUNK_ID_FENCE, fence_chunk),
                ],
                0,
            )
            .ok()?;
            let fences = |h: u32| {
                rig.gem
                    .object(h)
                    .unwrap()
                    .dma_buf()
                    .resv
                    .fences(narf_filesystem::dma_buf::DmaResvUsage::Read)
                    .len()
            };
            if fences(listed) != 1 || fences(uf) != 1 || fences(unlisted) != 0 {
                return Some("the job fences the listed and user-fence buffers only");
            }
            // The pending own job on `listed` does not hold a second job on
            // another ring of the same space.
            if rig
                .cs(
                    u::AMDGPU_HW_IP_DMA,
                    &[(u::AMDGPU_CHUNK_ID_BO_HANDLES, body.clone())],
                    0,
                )
                .is_err()
            {
                return Some("an own-space fence does not hold the job");
            }
            let idle = |h: u32| {
                let mut w = [0u8; 16];
                w[0..4].copy_from_slice(&h.to_le_bytes());
                rig.run(amd(u::DRM_AMDGPU_GEM_WAIT_IDLE), &mut w, None)
                    .map(|_| u32::from_le_bytes(w[0..4].try_into().unwrap()))
            };
            if idle(unlisted) != Ok(0)
                || idle(listed) != Ok(1)
                || idle(always) != Ok(1)
                || idle(0xdead) != Err(FsError::NotFound)
            {
                return Some("GEM_WAIT_IDLE");
            }
            // Another open (a foreign owner) sharing the buffer: its job
            // waits for this open's pending writer.
            let other = Rig::new(card);
            let shared = other.gem.import(&rig.gem.object(listed)?).ok()?;
            let (_k2, b2) = bo_handles_chunk(&[shared]);
            let mut r = other.cs_req(gfx, &[(u::AMDGPU_CHUNK_ID_BO_HANDLES, b2)], 0);
            let open = other.open(None);
            let issued = engine.issued[0].load(Ordering::SeqCst);
            {
                let mut job = core::pin::pin!(crate::amdgpu_cs::dispatch_async(
                    card,
                    amd(u::DRM_AMDGPU_CS),
                    r.req.as_mut_ptr() as usize,
                    &open,
                ));
                let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
                if job.as_mut().poll(&mut cx).is_ready()
                    || engine.issued[0].load(Ordering::SeqCst) != issued
                {
                    return Some("a foreign job waits for the shared buffer's writer");
                }
                engine.complete_all();
                if narf_scheduler::block_on_spin(job).is_err() {
                    return Some("the foreign job after the writer completed");
                }
            }
            engine.complete_all();
            if idle(listed) != Ok(0) || idle(always) != Ok(0) {
                return Some("idle after completion");
            }
            None
        })();
        crate::amdgpu_cs::unregister_submitter(card);
        if let Some(why) = result {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/drm-sync", sync_implicit_sync_follows_linux);
