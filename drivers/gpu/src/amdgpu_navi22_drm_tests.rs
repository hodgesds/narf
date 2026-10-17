//! The Navi 22 render ABI against an in-memory device: the ioctl sequence
//! Mesa 26.2.4 radeonsi issues on GFX10.3 (docs/MESA_AMD.md, Linux
//! reference order) and the Linux validation answers.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
pub(crate) struct FakeBo {
    size: u64,
    vram: bool,
    words: IrqSafeSpinLock<BTreeMap<u64, u64>>,
}
pub(crate) struct Fake {
    epoch: AtomicU64,
    emitted: [AtomicU64; 4],
    done: [AtomicU64; 4],
    busy_once: AtomicBool,
    vms: AtomicU64,
    log: IrqSafeSpinLock<Vec<(Ring, u8, Vec<Ib>)>>,
    maps: IrqSafeSpinLock<Vec<(u8, VaMap)>>,
    unmaps: IrqSafeSpinLock<Vec<u64>>,
}
fn fake() -> Fake {
    Fake {
        epoch: AtomicU64::new(0),
        emitted: Default::default(),
        done: Default::default(),
        busy_once: AtomicBool::new(false),
        vms: AtomicU64::new(0),
        log: IrqSafeSpinLock::new(Vec::new()),
        maps: IrqSafeSpinLock::new(Vec::new()),
        unmaps: IrqSafeSpinLock::new(Vec::new()),
    }
}
fn slot(r: Ring) -> usize {
    super::track_index(r)
}
impl Device for Fake {
    type Vm = u8;
    type Bo = FakeBo;
    fn active(&self) -> bool {
        true
    }
    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }
    fn create_vm(&self) -> BoxFut<'_, Result<(u8, VmRef), DevError>> {
        Box::pin(async move {
            let n = self.vms.fetch_add(1, Ordering::SeqCst) as u8 + 1;
            Ok((
                n,
                VmRef {
                    vmid: n,
                    generation: u64::from(n),
                    page_table_base: 0x1000,
                },
            ))
        })
    }
    fn destroy_vm(&self, _vm: u8) -> BoxFut<'_, ()> {
        Box::pin(async {})
    }
    fn alloc(
        &self,
        size: u64,
        vram: bool,
        _uncached: bool,
    ) -> BoxFut<'_, Result<FakeBo, DevError>> {
        Box::pin(async move {
            Ok(FakeBo {
                size,
                vram,
                words: IrqSafeSpinLock::new(BTreeMap::new()),
            })
        })
    }
    fn frames(&self, bo: &FakeBo, offset: u64, len: u64) -> Result<Vec<u64>, DevError> {
        if offset + len > bo.size {
            return Err(DevError::Invalid);
        }
        Ok((0..len.div_ceil(4096))
            .map(|p| 0x10_0000 + p * 4096)
            .collect())
    }
    fn write_u64(&self, bo: &FakeBo, offset: u64, value: u64) {
        bo.words.lock().insert(offset, value);
    }
    fn is_vram(&self, bo: &FakeBo) -> bool {
        bo.vram
    }
    fn size(&self, bo: &FakeBo) -> u64 {
        bo.size
    }
    fn map<'a>(
        &'a self,
        vm: &'a u8,
        map: VaMap,
        _bo: Arc<FakeBo>,
    ) -> BoxFut<'a, Result<(), DevError>> {
        Box::pin(async move {
            self.maps.lock().push((*vm, map));
            Ok(())
        })
    }
    fn unmap<'a>(&'a self, _vm: &'a u8, va: u64) -> BoxFut<'a, Result<(), DevError>> {
        Box::pin(async move {
            self.unmaps.lock().push(va);
            Ok(())
        })
    }
    fn submit<'a>(
        &'a self,
        ring: Ring,
        vm: VmRef,
        _c: u64,
        ibs: &'a [Ib],
    ) -> BoxFut<'a, Result<u64, DevError>> {
        Box::pin(async move {
            if self.busy_once.swap(false, Ordering::SeqCst) {
                return Err(DevError::Busy(
                    self.emitted[slot(ring)].load(Ordering::SeqCst),
                ));
            }
            self.log.lock().push((ring, vm.vmid, ibs.to_vec()));
            Ok(self.emitted[slot(ring)].fetch_add(1, Ordering::SeqCst) + 1)
        })
    }
    fn completed(&self, ring: Ring) -> BoxFut<'_, Result<u64, DevError>> {
        Box::pin(async move { Ok(self.done[slot(ring)].load(Ordering::SeqCst)) })
    }
}
impl Fake {
    fn complete_all(&self) {
        for i in 0..4 {
            self.done[i].store(self.emitted[i].load(Ordering::SeqCst), Ordering::SeqCst);
        }
    }
}

/// Kernel-pointer ioctl context.
struct K;
impl IoctlContext for K {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        // SAFETY: tests pass pointers to live kernel buffers of this length.
        unsafe {
            core::ptr::copy_nonoverlapping(
                address as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            )
        };
        Ok(())
    }
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        // SAFETY: as above.
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), address as *mut u8, source.len())
        };
        Ok(())
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn process_id(&self) -> u32 {
        77
    }
}

const fn cmd(nr: u32) -> u32 {
    0xc000_0000 | (0x64 << 8) | nr
}
const fn amd(nr: u32) -> u32 {
    cmd(0x40 + nr)
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
type Ctxs = crate::amdgpu_ctx::CtxState;
fn call(s: &FileState<Fake>, c: &Ctxs, nr: u32, buf: &mut [u8]) -> Result<u64, FsError> {
    run(ioctl(s, c, nr, buf.as_mut_ptr() as u64, &K)).expect("not routed")
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn get64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn new_ctx(c: &Ctxs) -> u32 {
    let mut b = [0u8; 16];
    put32(&mut b, 0, uapi::AMDGPU_CTX_OP_ALLOC_CTX);
    crate::amdgpu_ctx::dispatch(amd(uapi::DRM_AMDGPU_CTX), b.as_mut_ptr() as usize, c, false)
        .unwrap();
    get32(&b, 0)
}
fn gem_create(
    s: &FileState<Fake>,
    c: &Ctxs,
    size: u64,
    domains: u64,
    flags: u64,
) -> Result<u32, FsError> {
    let mut b = [0u8; 32];
    put64(&mut b, 0, size);
    put64(&mut b, 8, 4096);
    put64(&mut b, 16, domains);
    put64(&mut b, 24, flags);
    call(s, c, amd(uapi::DRM_AMDGPU_GEM_CREATE), &mut b).map(|_| get32(&b, 0))
}
fn gem_va(
    s: &FileState<Fake>,
    c: &Ctxs,
    handle: u32,
    op: u32,
    va: u64,
    size: u64,
) -> Result<u64, FsError> {
    let mut b = [0u8; 40];
    put32(&mut b, 0, handle);
    put32(&mut b, 8, op);
    put32(&mut b, 12, 0x8e);
    put64(&mut b, 16, va);
    put64(&mut b, 32, size);
    call(s, c, amd(uapi::DRM_AMDGPU_GEM_VA), &mut b)
}
fn syncobj_create(s: &FileState<Fake>, c: &Ctxs) -> u32 {
    let mut b = [0u8; 8];
    call(s, c, cmd(0xbf), &mut b).unwrap();
    get32(&b, 0)
}
const HIGH_VA: u64 = 0xffff_8001_0000_0000;

struct Cs {
    ctx_id: u32,
    bo: u32,
    fence_bo: u32,
    syncobj: u32,
    point: u64,
    ib_va: u64,
}
/// One radeonsi-shaped CS: BO_HANDLES, SYNCOBJ_TIMELINE_SIGNAL, FENCE, IB.
fn submit(s: &FileState<Fake>, c: &Ctxs, cs: &Cs) -> Result<u64, FsError> {
    let mut list = [0u8; 8];
    put32(&mut list, 0, cs.bo);
    let mut bo_in = [0u8; 24];
    put32(&mut bo_in, 8, 1);
    put32(&mut bo_in, 12, 8);
    put64(&mut bo_in, 16, list.as_ptr() as u64);
    let mut sig = [0u8; 16];
    put32(&mut sig, 0, cs.syncobj);
    put64(&mut sig, 8, cs.point);
    let mut fence = [0u8; 8];
    put32(&mut fence, 0, cs.fence_bo);
    let mut ib = [0u8; 32];
    put64(&mut ib, 8, cs.ib_va);
    put32(&mut ib, 16, 64);
    put32(&mut ib, 20, uapi::AMDGPU_HW_IP_GFX);
    let mut chunks = [[0u8; 16]; 4];
    for (k, (id, data, len)) in [
        (uapi::AMDGPU_CHUNK_ID_BO_HANDLES, bo_in.as_ptr() as u64, 6),
        (
            uapi::AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL,
            sig.as_ptr() as u64,
            4,
        ),
        (uapi::AMDGPU_CHUNK_ID_FENCE, fence.as_ptr() as u64, 2),
        (uapi::AMDGPU_CHUNK_ID_IB, ib.as_ptr() as u64, 8),
    ]
    .into_iter()
    .enumerate()
    {
        put32(&mut chunks[k], 0, id);
        put32(&mut chunks[k], 4, len);
        put64(&mut chunks[k], 8, data);
    }
    let ptrs: Vec<u64> = chunks.iter().map(|c| c.as_ptr() as u64).collect();
    let mut b = [0u8; 24];
    put32(&mut b, 0, cs.ctx_id);
    put32(&mut b, 8, 4);
    put64(&mut b, 16, ptrs.as_ptr() as u64);
    call(s, c, amd(uapi::DRM_AMDGPU_CS), &mut b).map(|r| if r == 0 { get64(&b, 0) } else { r })
}
fn timeline_wait(
    s: &FileState<Fake>,
    c: &Ctxs,
    syncobj: u32,
    point: u64,
    timeout: u64,
) -> Result<u64, FsError> {
    let handles = [syncobj];
    let points = [point];
    let mut b = [0u8; 48];
    put64(&mut b, 0, handles.as_ptr() as u64);
    put64(&mut b, 8, points.as_ptr() as u64);
    put64(&mut b, 16, timeout);
    put32(&mut b, 24, 1);
    put32(&mut b, 28, 1 | 2); // WAIT_ALL | WAIT_FOR_SUBMIT
    call(s, c, cmd(0xca), &mut b)
}

fn navi22_drm_radeonsi_first_submission() -> TestResult {
    let s = FileState::new(fake());
    let c = Ctxs::new();
    let ctx_id = new_ctx(&c);
    let so = syncobj_create(&s, &c);
    // GTT (flags USWC) and VRAM|GTT (NO_CPU_ACCESS|USWC) as radeonsi asks.
    let (Ok(gtt), Ok(vram)) = (
        gem_create(&s, &c, 4096, 2, 4),
        gem_create(&s, &c, 2 << 20, 6, 6),
    ) else {
        return TestResult::Fail("GEM_CREATE refused Mesa's domains/flags");
    };
    let mut m = [0u8; 8];
    put32(&mut m, 0, vram);
    if call(&s, &c, amd(uapi::DRM_AMDGPU_GEM_MMAP), &mut m).is_err()
        || s.mmap_frames(get64(&m, 0), 2 << 20).map(|f| f.len()) != Ok(512)
    {
        return TestResult::Fail("GEM_MMAP offset or frames");
    }
    if gem_va(&s, &c, vram, uapi::AMDGPU_VA_OP_MAP, HIGH_VA, 2 << 20).is_err()
        || gem_va(
            &s,
            &c,
            gtt,
            uapi::AMDGPU_VA_OP_MAP,
            HIGH_VA + (2 << 20),
            4096,
        )
        .is_err()
        || s.device.maps.lock()[0].1.va != 0x8001_0000_0000
    {
        return TestResult::Fail("GEM_VA at the high VA (hole-stripped)");
    }
    let cs = Cs {
        ctx_id,
        bo: vram,
        fence_bo: gtt,
        syncobj: so,
        point: 1,
        ib_va: HIGH_VA + 0x100,
    };
    let seq = match submit(&s, &c, &cs) {
        Ok(seq) => seq,
        Err(_) => return TestResult::Fail("radeonsi CS refused"),
    };
    let log = s.device.log.lock().clone();
    if log.len() != 1
        || log[0].0 != Ring::Gfx
        || log[0].1 != 1
        || log[0].2
            != [Ib {
                va: 0x8001_0000_0100,
                dwords: 16,
            }]
    {
        return TestResult::Fail("IB not queued on gfx under the client's VMID");
    }
    // Not complete: a zero-timeout wait times out with ETIME.
    if timeline_wait(&s, &c, so, 1, 0) != Ok(errno(ETIME)) {
        return TestResult::Fail("unsignalled timeline point did not report ETIME");
    }
    s.device.complete_all();
    if timeline_wait(&s, &c, so, 1, u64::MAX) != Ok(0) {
        return TestResult::Fail("signalled timeline point did not complete the wait");
    }
    // The user fence BO holds the CS sequence; WAIT_CS reports idle.
    let gtt_obj = s.mmap_owner(u64::from(gtt) << 12).unwrap();
    let mut w = [0u8; 32];
    put64(&mut w, 0, seq);
    put32(&mut w, 28, ctx_id);
    if gtt_obj.words.lock().get(&0) != Some(&seq)
        || call(&s, &c, amd(uapi::DRM_AMDGPU_WAIT_CS), &mut w).is_err()
        || get64(&w, 0) != 0
    {
        return TestResult::Fail("user fence or WAIT_CS status");
    }
    // Teardown: UNMAP + GEM_CLOSE.
    let mut close = [0u8; 8];
    put32(&mut close, 0, vram);
    if gem_va(&s, &c, vram, uapi::AMDGPU_VA_OP_UNMAP, HIGH_VA, 2 << 20).is_err()
        || call(&s, &c, cmd(0x09), &mut close).is_err()
        || s.mmap_frames(u64::from(vram) << 12, 4096).is_ok()
    {
        return TestResult::Fail("UNMAP/GEM_CLOSE teardown");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_drm_radeonsi_first_submission
);

fn navi22_drm_rejects_like_linux() -> TestResult {
    let s = FileState::new(fake());
    let c = Ctxs::new();
    let ctx_id = new_ctx(&c);
    let so = syncobj_create(&s, &c);
    let bo = gem_create(&s, &c, 8192, 4, 0).unwrap();
    gem_va(&s, &c, bo, uapi::AMDGPU_VA_OP_MAP, 0x10_0000, 8192).unwrap();
    let einval = Err(FsError::InvalidData);
    let cs = |ctx_id, ib_va| Cs {
        ctx_id,
        bo,
        fence_bo: bo,
        syncobj: so,
        point: 0,
        ib_va,
    };
    let checks = [
        // GDS and encrypted BOs, zero size.
        gem_create(&s, &c, 4096, 8, 0).map(|_| 0) == einval,
        gem_create(&s, &c, 4096, 4, 1 << 10).map(|_| 0) == einval,
        gem_create(&s, &c, 0, 4, 0).map(|_| 0) == einval,
        // Overlapping map, unaligned VA, VA in the hole, wrong-handle unmap.
        gem_va(&s, &c, bo, uapi::AMDGPU_VA_OP_MAP, 0x10_1000, 4096) == einval,
        gem_va(&s, &c, bo, uapi::AMDGPU_VA_OP_MAP, 0x20_0800, 4096) == einval,
        gem_va(&s, &c, bo, uapi::AMDGPU_VA_OP_MAP, 0x9000_0000_0000, 4096) == einval,
        gem_va(&s, &c, 0x1234, uapi::AMDGPU_VA_OP_UNMAP, 0x10_0000, 8192) == Err(FsError::NotFound),
        // IB outside every mapping, unknown context.
        submit(&s, &c, &cs(ctx_id, 0x40_0000)) == einval,
        submit(&s, &c, &cs(999, 0x10_0000)) == einval,
        // Binary wait on a never-submitted syncobj without WAIT_FOR_SUBMIT.
        {
            let h = [so];
            let mut b = [0u8; 40];
            put64(&mut b, 0, h.as_ptr() as u64);
            put32(&mut b, 16, 1);
            call(&s, &c, cmd(0xc3), &mut b) == einval
        },
    ];
    if checks.iter().any(|ok| !ok) {
        return TestResult::Fail("a Linux EINVAL/ENOENT case was accepted");
    }
    // Throttled once: the CS waits for the ring and still succeeds.
    s.device.busy_once.store(true, Ordering::SeqCst);
    if submit(&s, &c, &cs(ctx_id, 0x10_0000)).is_err() || s.device.log.lock().len() != 1 {
        return TestResult::Fail("throttled CS not retried");
    }
    // After a recovery, the old context's CS is ECANCELED.
    s.device.epoch.store(1, Ordering::SeqCst);
    if submit(&s, &c, &cs(ctx_id, 0x10_0000)) != Ok(errno(ECANCELED)) {
        return TestResult::Fail("pre-recovery context not cancelled");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/navi22", navi22_drm_rejects_like_linux);

fn navi22_drm_version_caps_and_syncobj_timeline() -> TestResult {
    let s = FileState::new(fake());
    let c = Ctxs::new();
    let mut name = [0u8; 16];
    let mut v = [0u8; 64];
    put64(&mut v, 16, 16);
    put64(&mut v, 24, name.as_mut_ptr() as u64);
    if call(&s, &c, cmd(0x00), &mut v).is_err() || &name[..6] != b"amdgpu" || get64(&v, 16) != 6 {
        return TestResult::Fail("DRM_IOCTL_VERSION name");
    }
    let (major, minor, _) = drm_version();
    if (get32(&v, 0), get32(&v, 4)) != (major, minor) {
        return TestResult::Fail("DRM_IOCTL_VERSION numbers");
    }
    let mut cap = [0u8; 16];
    put64(&mut cap, 0, 0x14);
    if call(&s, &c, cmd(0x0c), &mut cap).is_err() || get64(&cap, 8) != 1 {
        return TestResult::Fail("SYNCOBJ_TIMELINE cap");
    }
    put64(&mut cap, 0, 0x10); // ADDFB2_MODIFIERS belongs to KMS.
    if run(ioctl(&s, &c, cmd(0x0c), cap.as_mut_ptr() as u64, &K)).is_some() {
        return TestResult::Fail("KMS cap intercepted");
    }
    // Timeline: signal 3 from the CPU, query, transfer to a binary syncobj.
    let (a, b) = (syncobj_create(&s, &c), syncobj_create(&s, &c));
    let handles = [a];
    let mut points = [3u64];
    let mut arr = [0u8; 24];
    put64(&mut arr, 0, handles.as_ptr() as u64);
    put64(&mut arr, 8, points.as_mut_ptr() as u64);
    put32(&mut arr, 16, 1);
    if call(&s, &c, cmd(0xcd), &mut arr).is_err() {
        return TestResult::Fail("TIMELINE_SIGNAL");
    }
    points[0] = 0;
    if call(&s, &c, cmd(0xcb), &mut arr).is_err()
        || points[0] != 3
        || timeline_wait(&s, &c, a, 2, 0) != Ok(0)
    {
        return TestResult::Fail("QUERY / point 2 satisfied by point 3");
    }
    let mut t = [0u8; 32];
    put32(&mut t, 0, a);
    put32(&mut t, 4, b);
    put64(&mut t, 8, 3);
    if call(&s, &c, cmd(0xcc), &mut t).is_err() {
        return TestResult::Fail("TRANSFER");
    }
    let hb = [b];
    let mut w = [0u8; 40];
    put64(&mut w, 0, hb.as_ptr() as u64);
    put32(&mut w, 16, 1);
    if call(&s, &c, cmd(0xc3), &mut w) != Ok(0) {
        return TestResult::Fail("binary wait after transfer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_drm_version_caps_and_syncobj_timeline
);

fn navi22_drm_get_client_matches_drm_getclient() -> TestResult {
    let mut b = [0u8; 40];
    let ok = crate::drm_ioctl_bridge::get_client(b.as_mut_ptr() as u64, &K, true);
    let mut other = [0u8; 40];
    put32(&mut other, 0, 1);
    if ok != Ok(0)
        || get32(&b, 4) != 1
        || get64(&b, 8) != 77
        || get64(&b, 16) != 65534
        || crate::drm_ioctl_bridge::get_client(other.as_mut_ptr() as u64, &K, false)
            != Err(FsError::InvalidData)
        || crate::drm_ioctl_bridge::DRM_IOCTL_GET_CLIENT != 0xc028_6405
    {
        return TestResult::Fail("GET_CLIENT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_drm_get_client_matches_drm_getclient
);

fn navi22_drm_prime_round_trip_names_the_same_object() -> TestResult {
    let (a, b) = (FileState::new(fake()), FileState::new(fake()));
    let c = Ctxs::new();
    let h = gem_create(&a, &c, 3 * 4096, 4, 0).unwrap();
    let Some((bo, frames, size)) = a.export(h) else {
        return TestResult::Fail("export of a live handle");
    };
    let imported = b.import(Arc::clone(&bo));
    if frames.len() != 3
        || size != 3 * 4096
        || a.import(Arc::clone(&bo)) != Ok(h)
        || imported.is_err()
        || b.mmap_owner(u64::from(imported.unwrap()) << 12)
            .is_none_or(|o| !Arc::ptr_eq(&o, &bo))
        || a.export(h + 99).is_some()
    {
        return TestResult::Fail("PRIME export/import identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_drm_prime_round_trip_names_the_same_object
);
