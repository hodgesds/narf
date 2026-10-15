//! Linux sync_file and dma-buf implicit-sync ioctl ABI.
//!
//! Chromium's GPU process reads every fence back through
//! `SYNC_IOC_FILE_INFO` (`ui/gfx/gpu_fence.cc`) and moves fences between
//! dma-bufs and sync_files with `DMA_BUF_IOCTL_EXPORT_SYNC_FILE` /
//! `DMA_BUF_IOCTL_IMPORT_SYNC_FILE` (`wayland_buffer_manager_host.cc`).
//! While both fd types answered every ioctl with ENOTTY, its GPU path logged
//! "sync_file_info returned null" and "Failed DMA_BUF_IOCTL_IMPORT_SYNC_FILE"
//! and YouTube never played.
//!
//! Every case drives real `ioctl(2)` (and `ppoll(2)`) through the syscall
//! table. sync_file fds are minted by the real producer path, a fenced
//! `VIRTGPU_EXECBUFFER` with `FENCE_FD_OUT`, on a render-node double that
//! hands out a controllable device fence. The dma-buf double is a thin
//! FileOps shell around the real generic core
//! (`narf_filesystem::dma_buf::dma_buf_ioctl`), the same function the DRM
//! PRIME files forward to.
//!
//! Linux refs: `drivers/dma-buf/sync_file.c`, `drivers/dma-buf/dma-buf.c`,
//! `drivers/dma-buf/dma-fence-unwrap.c`, `include/uapi/linux/sync_file.h`,
//! `include/uapi/linux/dma-buf.h`.
use crate::abi_test_support::*;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use narf_filesystem::dma_buf::DmaBufObject;
use narf_filesystem::{FileOps, FsFuture, Mode, Stat};

const DRM_IOCTL_VIRTGPU_EXECBUFFER: u64 = 0xC040_6442;
const VIRTGPU_EXECBUF_FENCE_FD_OUT: u32 = 0x02;

/// `_IOWR('>', 3, struct sync_merge_data)` (48 bytes).
const SYNC_IOC_MERGE: u64 = 0xC030_3E03;
/// `_IOWR('>', 4, struct sync_file_info)` (56 bytes).
const SYNC_IOC_FILE_INFO: u64 = 0xC038_3E04;
/// `_IOW('>', 5, struct sync_set_deadline)` (16 bytes).
const SYNC_IOC_SET_DEADLINE: u64 = 0x4010_3E05;
/// `_IOWR('>', 6, struct sync_file_info)`: an unassigned sync_file number.
const SYNC_IOC_UNKNOWN: u64 = 0xC038_3E06;

const DMA_BUF_IOCTL_SYNC: u64 = 0x4008_6200;
const DMA_BUF_SET_NAME_B: u64 = 0x4008_6201;
const DMA_BUF_IOCTL_EXPORT_SYNC_FILE: u64 = 0xC008_6202;
const DMA_BUF_IOCTL_IMPORT_SYNC_FILE: u64 = 0x4008_6203;
/// `_IOW('b', 4, __u64)`: an unassigned dma-buf number.
const DMA_BUF_IOCTL_UNKNOWN: u64 = 0x4008_6204;
const DMA_BUF_SYNC_READ: u64 = 1;
const DMA_BUF_SYNC_WRITE: u64 = 2;
const DMA_BUF_SYNC_RW: u64 = 3;
const DMA_BUF_SYNC_END: u64 = 4;

/// A controllable device fence with its own driver/timeline names.
struct TestFence {
    signalled: AtomicBool,
    /// Signal on the first `wait` (a fence whose completion a waiter reaps).
    signal_on_wait: bool,
    waits: AtomicU32,
    context: u64,
    seqno: u64,
}

impl TestFence {
    fn new(context: u64, seqno: u64) -> Arc<Self> {
        Arc::new(Self {
            signalled: AtomicBool::new(false),
            signal_on_wait: false,
            waits: AtomicU32::new(0),
            context,
            seqno,
        })
    }

    fn completing_on_wait(context: u64) -> Arc<Self> {
        Arc::new(Self {
            signalled: AtomicBool::new(false),
            signal_on_wait: true,
            waits: AtomicU32::new(0),
            context,
            seqno: 1,
        })
    }

    fn signal(&self) {
        self.signalled.store(true, Ordering::Release);
    }
}

impl narf_filesystem::DrmFence for TestFence {
    fn is_signalled(&self) -> bool {
        self.signalled.load(Ordering::Acquire)
    }

    fn wait(&self, _timeout_ms: u64) -> bool {
        self.waits.fetch_add(1, Ordering::Relaxed);
        if self.signal_on_wait {
            self.signal();
        }
        self.is_signalled()
    }

    fn context(&self) -> Option<u64> {
        Some(self.context)
    }

    fn seqno(&self) -> u64 {
        self.seqno
    }

    fn driver_name(&self) -> &str {
        "test_gpu"
    }

    fn timeline_name(&self) -> &str {
        "ring0"
    }
}

fn plain_stat() -> Stat {
    Stat {
        size: 0,
        blocks: 0,
        mode: Mode::FILE_RO,
        mtime_cycles: 0,
    }
}

/// Render-node double: EXECBUFFER succeeds and FENCE_FD_OUT receives
/// `fence` (or the signalled stub when `None`).
struct FenceSource {
    fence: Option<Arc<TestFence>>,
}

impl FileOps for FenceSource {
    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
        let n = b.len();
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        plain_stat()
    }
    fn as_drm_render_index(&self) -> Option<u32> {
        Some(0)
    }
    fn ioctl(&self, cmd: u32, _arg: usize) -> Result<u64, narf_filesystem::FsError> {
        if cmd as u64 == DRM_IOCTL_VIRTGPU_EXECBUFFER {
            Ok(0)
        } else {
            Err(narf_filesystem::FsError::Unsupported)
        }
    }
    fn drm_execbuf_fence(&self) -> Option<Arc<dyn narf_filesystem::DrmFence>> {
        self.fence
            .clone()
            .map(|fence| fence as Arc<dyn narf_filesystem::DrmFence>)
    }
    fn drm_execbuf_context(&self, _ring_idx: u32) -> Option<u64> {
        // A context no test fence uses, so no wait is elided.
        Some(u64::MAX)
    }
}

/// dma-buf double: a FileOps shell over the real generic dma-buf core.
struct TestDmaBuf {
    object: Arc<DmaBufObject>,
}

impl FileOps for TestDmaBuf {
    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _o: u64, _b: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(narf_filesystem::FsError::InvalidData) })
    }
    fn stat(&self) -> Stat {
        plain_stat()
    }
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        context: &'a dyn narf_filesystem::IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(
            async move { narf_filesystem::dma_buf::dma_buf_ioctl(&self.object, cmd, arg, context) },
        )
    }
}

/// A plain fd with no sync_file or dma-buf identity.
struct Plain;
impl FileOps for Plain {
    fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
        let n = b.len();
        Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> Stat {
        plain_stat()
    }
}

fn install_ops(ops: Arc<dyn FileOps>) -> Result<u32, &'static str> {
    crate::fd::install(
        FAKE_TASK,
        crate::fd::FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: crate::fd::O_RDWR,
        },
    )
    .ok_or("install fixture fd")
}

fn ioctl(fd: i32, cmd: u64, arg: u64) -> Option<i64> {
    call(Syscall::Ioctl.raw(), a3(fd as u64, cmd, arg, 0))
}

/// Mint a real sync_file through EXECBUFFER(FENCE_FD_OUT).
fn sync_file_for(fence: Option<Arc<TestFence>>) -> Result<i32, &'static str> {
    let render = install_ops(Arc::new(FenceSource { fence }))?;
    let mut execbuf = [0u8; 64];
    execbuf[0..4].copy_from_slice(&VIRTGPU_EXECBUF_FENCE_FD_OUT.to_ne_bytes());
    execbuf[28..32].copy_from_slice(&(-1i32).to_ne_bytes());
    if ioctl(
        render as i32,
        DRM_IOCTL_VIRTGPU_EXECBUFFER,
        execbuf.as_mut_ptr() as u64,
    ) != Some(0)
    {
        return Err("EXECBUFFER(FENCE_FD_OUT) fixture failed");
    }
    let fd = i32::from_ne_bytes(execbuf[28..32].try_into().unwrap());
    if fd < 0 {
        return Err("EXECBUFFER returned no sync_file");
    }
    Ok(fd)
}

fn readable(fd: i32) -> Result<bool, &'static str> {
    // struct pollfd { int fd; short events; short revents; }, POLLIN = 1;
    // a zero timespec makes ppoll a non-blocking readiness probe.
    let mut pollfd = [0u8; 8];
    pollfd[0..4].copy_from_slice(&fd.to_ne_bytes());
    pollfd[4..6].copy_from_slice(&1i16.to_ne_bytes());
    let ts: [u64; 2] = [0, 0];
    match call(
        Syscall::Ppoll.raw(),
        a4(pollfd.as_mut_ptr() as u64, 1, ts.as_ptr() as u64, 0, 8),
    ) {
        Some(0) => Ok(false),
        Some(1) => Ok(i16::from_ne_bytes([pollfd[6], pollfd[7]]) & 1 != 0),
        _ => Err("ppoll on a sync_file failed"),
    }
}

fn fd_flags(fd: i32) -> Option<u32> {
    fd::with_table(FAKE_TASK, |table| {
        table.get(fd as u32).map(|entry| entry.flags)
    })
    .flatten()
}

/// `struct sync_file_info` with `num_fences` and the array pointer set.
fn file_info(num_fences: u32, array: u64) -> [u8; 56] {
    let mut info = [0u8; 56];
    info[40..44].copy_from_slice(&num_fences.to_ne_bytes());
    info[48..56].copy_from_slice(&array.to_ne_bytes());
    info
}

fn info_status(info: &[u8; 56]) -> i32 {
    i32::from_ne_bytes(info[32..36].try_into().unwrap())
}

fn info_count(info: &[u8; 56]) -> u32 {
    u32::from_ne_bytes(info[40..44].try_into().unwrap())
}

/// The NUL-terminated prefix of a fixed char array.
fn cstr(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// Both FILE_INFO calls; returns (status, count, name, per-fence entries).
/// `(status, num_fences, name, sync_fence_info entries)`.
type FileInfo = (i32, u32, Vec<u8>, Vec<[u8; 80]>);

fn query(fd: i32) -> Result<FileInfo, &'static str> {
    let mut first = file_info(0, 0);
    if ioctl(fd, SYNC_IOC_FILE_INFO, first.as_mut_ptr() as u64) != Some(0) {
        return Err("FILE_INFO(num_fences = 0) failed");
    }
    let count = info_count(&first);
    let mut entries = alloc::vec![[0u8; 80]; count as usize];
    let mut second = file_info(count, entries.as_mut_ptr() as u64);
    if ioctl(fd, SYNC_IOC_FILE_INFO, second.as_mut_ptr() as u64) != Some(0) {
        return Err("FILE_INFO(num_fences = count) failed");
    }
    if info_count(&second) != count || info_status(&second) != info_status(&first) {
        return Err("the two FILE_INFO calls disagree");
    }
    Ok((
        info_status(&first),
        count,
        cstr(&first[..32]).to_vec(),
        entries,
    ))
}

fn entry_status(entry: &[u8; 80]) -> i32 {
    i32::from_ne_bytes(entry[64..68].try_into().unwrap())
}

fn entry_timestamp(entry: &[u8; 80]) -> u64 {
    u64::from_ne_bytes(entry[72..80].try_into().unwrap())
}

fn merge_data(fd2: i32, name: &[u8]) -> [u8; 48] {
    let mut data = [0u8; 48];
    data[..name.len()].copy_from_slice(name);
    data[32..36].copy_from_slice(&fd2.to_ne_bytes());
    data[36..40].copy_from_slice(&(-1i32).to_ne_bytes());
    data
}

fn expect_name(name: &[u8], expected: &str) -> Result<(), &'static str> {
    if name == expected.as_bytes() {
        Ok(())
    } else {
        Err("sync_file_get_name mismatch")
    }
}

// sync_file_ioctl_fence_info: num_fences == 0 returns only the status and
// the count; num_fences >= count fills sync_fence_info. An unsignalled leaf
// reports its driver/timeline names, status 0 and timestamp 0; once it
// signals, status 1, a timestamp, and dma_fence_driver_name's
// "detached-driver" / "signaled-timeline".
fn smoke_abi_sync_file_info_pending_then_signalled() -> TestResult {
    with_setup(|| {
        let fence = TestFence::new(0x5157, 42);
        let fd = sync_file_for(Some(fence.clone()))?;
        let (status, count, name, entries) = query(fd)?;
        if status != 0 || count != 1 {
            return Err("pending sync_file must report status 0 and one fence");
        }
        expect_name(&name, "test_gpu-ring020823-42")?;
        let entry = &entries[0];
        if cstr(&entry[0..32]) != b"ring0"
            || cstr(&entry[32..64]) != b"test_gpu"
            || entry_status(entry) != 0
            || entry_timestamp(entry) != 0
        {
            return Err("pending sync_fence_info fields are wrong");
        }

        fence.signal();
        let (status, count, name, entries) = query(fd)?;
        if status != 1 || count != 1 {
            return Err("signalled sync_file must report status 1");
        }
        // sync_file_get_name's snprintf(buf, 32, "%s-%s%llu-%lld") truncates
        // "detached-driver-signaled-timeline20823-42" to 31 bytes + NUL.
        expect_name(&name, "detached-driver-signaled-timeli")?;
        let entry = &entries[0];
        if cstr(&entry[0..32]) != b"signaled-timeline"
            || cstr(&entry[32..64]) != b"detached-driver"
            || entry_status(entry) != 1
            || entry_timestamp(entry) == 0
        {
            return Err("signalled sync_fence_info fields are wrong");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_sync_file_info_pending_then_signalled
);

// FILE_INFO rejects flags/pad (EINVAL), an array smaller than the fence
// count (EINVAL), and faulting struct or array pointers (EFAULT).
fn smoke_abi_sync_file_info_rejects_bad_requests() -> TestResult {
    with_setup(|| {
        const BAD_USER_PTR: u64 = 1 << 47;
        let a = sync_file_for(Some(TestFence::new(0x100, 1)))?;
        let b = sync_file_for(Some(TestFence::new(0x200, 1)))?;
        let mut data = merge_data(b, b"");
        if ioctl(a, SYNC_IOC_MERGE, data.as_mut_ptr() as u64) != Some(0) {
            return Err("merge fixture failed");
        }
        let merged = i32::from_ne_bytes(data[36..40].try_into().unwrap());

        let mut flags = file_info(0, 0);
        flags[36] = 1;
        if ioctl(merged, SYNC_IOC_FILE_INFO, flags.as_mut_ptr() as u64) != Some(EINVAL) {
            return Err("FILE_INFO flags != 0 must be -EINVAL");
        }
        let mut pad = file_info(0, 0);
        pad[44] = 1;
        if ioctl(merged, SYNC_IOC_FILE_INFO, pad.as_mut_ptr() as u64) != Some(EINVAL) {
            return Err("FILE_INFO pad != 0 must be -EINVAL");
        }
        let mut one = [[0u8; 80]; 1];
        let mut short = file_info(1, one.as_mut_ptr() as u64);
        if ioctl(merged, SYNC_IOC_FILE_INFO, short.as_mut_ptr() as u64) != Some(EINVAL) {
            return Err("FILE_INFO with num_fences < count must be -EINVAL");
        }
        let mut bad_array = file_info(2, BAD_USER_PTR);
        if ioctl(merged, SYNC_IOC_FILE_INFO, bad_array.as_mut_ptr() as u64) != Some(EFAULT) {
            return Err("FILE_INFO with a faulting array must be -EFAULT");
        }
        if ioctl(merged, SYNC_IOC_FILE_INFO, BAD_USER_PTR) != Some(EFAULT) {
            return Err("FILE_INFO with a faulting struct must be -EFAULT");
        }
        // Positive control: a larger-than-needed array is accepted and the
        // count comes back exact.
        let mut three = [[0u8; 80]; 3];
        let mut big = file_info(3, three.as_mut_ptr() as u64);
        if ioctl(merged, SYNC_IOC_FILE_INFO, big.as_mut_ptr() as u64) != Some(0)
            || info_count(&big) != 2
        {
            return Err("FILE_INFO with num_fences > count must succeed with the real count");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sync_file_info_rejects_bad_requests);

// SYNC_IOC_MERGE of two pending fences on different contexts is a
// dma_fence_array: both leaves listed, the merge name reported, readable
// only once BOTH signal. The new fd is O_CLOEXEC and the inputs stay valid.
fn smoke_abi_sync_file_merge_waits_for_both() -> TestResult {
    with_setup(|| {
        let first = TestFence::new(0x300, 5);
        let second = TestFence::new(0x400, 6);
        let a = sync_file_for(Some(first.clone()))?;
        let b = sync_file_for(Some(second.clone()))?;
        let mut data = merge_data(b, b"chromium-merge");
        if ioctl(a, SYNC_IOC_MERGE, data.as_mut_ptr() as u64) != Some(0) {
            return Err("SYNC_IOC_MERGE of two sync_files failed");
        }
        let merged = i32::from_ne_bytes(data[36..40].try_into().unwrap());
        if merged < 0 || merged == a || merged == b {
            return Err("MERGE did not return a new fd");
        }
        if fd_flags(merged).is_none_or(|flags| flags & crate::fd::FD_CLOEXEC == 0) {
            return Err("merged sync_file must be O_CLOEXEC");
        }
        let (status, count, name, entries) = query(merged)?;
        if status != 0 || count != 2 || entries.iter().any(|e| entry_status(e) != 0) {
            return Err("merged file must list both pending fences");
        }
        expect_name(&name, "chromium-merge")?;
        if readable(merged)? {
            return Err("merged file readable before either fence signalled");
        }
        first.signal();
        if readable(merged)? {
            return Err("merged file readable with one fence still pending");
        }
        let (status, _, _, entries) = query(merged)?;
        if status != 0 || entry_status(&entries[0]) != 1 || entry_status(&entries[1]) != 0 {
            return Err("half-signalled merge must report status 0 with one leaf done");
        }
        second.signal();
        if !readable(merged)? {
            return Err("merged file not readable after both fences signalled");
        }
        if query(merged)?.0 != 1 {
            return Err("fully signalled merge must report status 1");
        }
        if !readable(a)? || !readable(b)? {
            return Err("merge must leave its inputs intact");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sync_file_merge_waits_for_both);

// dma_fence_unwrap_merge drops signalled leaves: merging a pending fence
// with a signalled one yields that single fence, not an array.
fn smoke_abi_sync_file_merge_drops_signalled() -> TestResult {
    with_setup(|| {
        let pending = TestFence::new(0x500, 1);
        let a = sync_file_for(Some(pending.clone()))?;
        let done = sync_file_for(None)?;
        let mut data = merge_data(done, b"");
        if ioctl(a, SYNC_IOC_MERGE, data.as_mut_ptr() as u64) != Some(0) {
            return Err("MERGE with a signalled file failed");
        }
        let merged = i32::from_ne_bytes(data[36..40].try_into().unwrap());
        let (status, count, name, _) = query(merged)?;
        if status != 0 || count != 1 {
            return Err("signalled leaves must be dropped by MERGE");
        }
        // No user name: the name of the surviving fence (0x500 = 1280).
        expect_name(&name, "test_gpu-ring01280-1")
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sync_file_merge_drops_signalled);

// sync_file_ioctl_merge: flags or pad → EINVAL; an fd2 that is not an open
// sync_file → ENOENT; no descriptor is consumed by a failure; and because
// get_unused_fd_flags runs first, a full table is EMFILE before any of them.
fn smoke_abi_sync_file_merge_errors() -> TestResult {
    with_setup(|| {
        let a = sync_file_for(Some(TestFence::new(0x600, 1)))?;
        let b = sync_file_for(Some(TestFence::new(0x700, 1)))?;
        let plain = install_ops(Arc::new(Plain))? as i32;
        let probe_next = || {
            install_ops(Arc::new(Plain)).inspect(|&fd| {
                let _ = fd::with_table(FAKE_TASK, |table| table.close(fd));
            })
        };
        let next_before = probe_next()?;

        for bad in [-1, plain, 999] {
            let mut data = merge_data(bad, b"x");
            if ioctl(a, SYNC_IOC_MERGE, data.as_mut_ptr() as u64) != Some(ENOENT) {
                return Err("MERGE with fd2 not a sync_file must be -ENOENT");
            }
        }
        let mut flags = merge_data(b, b"x");
        flags[40] = 1;
        if ioctl(a, SYNC_IOC_MERGE, flags.as_mut_ptr() as u64) != Some(EINVAL) {
            return Err("MERGE flags != 0 must be -EINVAL");
        }
        let mut pad = merge_data(b, b"x");
        pad[44] = 1;
        if ioctl(a, SYNC_IOC_MERGE, pad.as_mut_ptr() as u64) != Some(EINVAL) {
            return Err("MERGE pad != 0 must be -EINVAL");
        }
        if ioctl(a, SYNC_IOC_MERGE, 1 << 47) != Some(EFAULT) {
            return Err("MERGE with a faulting struct must be -EFAULT");
        }
        if probe_next()? != next_before {
            return Err("a failed MERGE leaked its reserved descriptor");
        }

        let limit = next_before as u64;
        if !crate::handlers::__test_set_rlimit(FAKE_TASK, 7, limit, 4096) {
            return Err("lower RLIMIT_NOFILE");
        }
        let mut invalid = merge_data(-1, b"x");
        invalid[40] = 1;
        if ioctl(a, SYNC_IOC_MERGE, invalid.as_mut_ptr() as u64) != Some(EMFILE) {
            return Err("MERGE at RLIMIT_NOFILE must be -EMFILE before validating");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sync_file_merge_errors);

// SYNC_IOC_SET_DEADLINE: a hint, accepted with pad == 0; pad != 0 is
// EINVAL. Unknown sync_file ioctls are ENOTTY without touching the pointer.
fn smoke_abi_sync_file_set_deadline_and_unknown() -> TestResult {
    with_setup(|| {
        let fd = sync_file_for(Some(TestFence::new(0x800, 1)))?;
        let mut deadline = [0u64; 2];
        deadline[0] = narf_time::wall::monotonic_ns() + 16_000_000;
        if ioctl(fd, SYNC_IOC_SET_DEADLINE, deadline.as_mut_ptr() as u64) != Some(0) {
            return Err("SET_DEADLINE with pad 0 must succeed");
        }
        deadline[1] = 1;
        if ioctl(fd, SYNC_IOC_SET_DEADLINE, deadline.as_mut_ptr() as u64) != Some(EINVAL) {
            return Err("SET_DEADLINE with pad != 0 must be -EINVAL");
        }
        if ioctl(fd, SYNC_IOC_UNKNOWN, 1 << 47) != Some(ENOTTY) {
            return Err("an unknown sync_file ioctl must be -ENOTTY");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_sync_file_set_deadline_and_unknown);

fn new_dma_buf() -> Result<(i32, Arc<DmaBufObject>), &'static str> {
    let object = Arc::new(DmaBufObject::new());
    let fd = install_ops(Arc::new(TestDmaBuf {
        object: object.clone(),
    }))?;
    Ok((fd as i32, object))
}

fn dma_buf_sync(fd: i32, flags: u64) -> Option<i64> {
    let mut sync = flags.to_ne_bytes();
    ioctl(fd, DMA_BUF_IOCTL_SYNC, sync.as_mut_ptr() as u64)
}

fn export_sync_file(fd: i32, flags: u32) -> Result<i32, Option<i64>> {
    let mut arg = [0u8; 8];
    arg[0..4].copy_from_slice(&flags.to_ne_bytes());
    arg[4..8].copy_from_slice(&(-1i32).to_ne_bytes());
    match ioctl(fd, DMA_BUF_IOCTL_EXPORT_SYNC_FILE, arg.as_mut_ptr() as u64) {
        Some(0) => Ok(i32::from_ne_bytes(arg[4..8].try_into().unwrap())),
        other => Err(other),
    }
}

fn import_sync_file(fd: i32, flags: u32, sync_fd: i32) -> Option<i64> {
    let mut arg = [0u8; 8];
    arg[0..4].copy_from_slice(&flags.to_ne_bytes());
    arg[4..8].copy_from_slice(&sync_fd.to_ne_bytes());
    ioctl(fd, DMA_BUF_IOCTL_IMPORT_SYNC_FILE, arg.as_mut_ptr() as u64)
}

// DMA_BUF_IOCTL_SYNC: flags outside DMA_BUF_SYNC_VALID_FLAGS_MASK and
// requests with neither READ nor WRITE are EINVAL; START/END with a
// direction succeed on an idle buffer.
fn smoke_abi_dma_buf_sync_flag_validation() -> TestResult {
    with_setup(|| {
        let (buf, _) = new_dma_buf()?;
        for flags in [
            DMA_BUF_SYNC_READ,
            DMA_BUF_SYNC_WRITE,
            DMA_BUF_SYNC_RW,
            DMA_BUF_SYNC_READ | DMA_BUF_SYNC_END,
            DMA_BUF_SYNC_RW | DMA_BUF_SYNC_END,
        ] {
            if dma_buf_sync(buf, flags) != Some(0) {
                return Err("valid DMA_BUF_IOCTL_SYNC flags were rejected");
            }
        }
        for flags in [0, DMA_BUF_SYNC_END, 8, DMA_BUF_SYNC_RW | 8, 1 << 32] {
            if dma_buf_sync(buf, flags) != Some(EINVAL) {
                return Err("invalid DMA_BUF_IOCTL_SYNC flags must be -EINVAL");
            }
        }
        if ioctl(buf, DMA_BUF_IOCTL_SYNC, 1 << 47) != Some(EFAULT) {
            return Err("DMA_BUF_IOCTL_SYNC with a faulting pointer must be -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_dma_buf_sync_flag_validation);

// __dma_buf_begin_cpu_access waits on dma_resv_usage_rw(write): a CPU read
// waits for writers only, a CPU write for readers and writers; END never
// waits.
fn smoke_abi_dma_buf_sync_start_waits_implicit_fences() -> TestResult {
    with_setup(|| {
        let (buf, object) = new_dma_buf()?;
        let reader = TestFence::completing_on_wait(0x900);
        object
            .resv
            .add_fence(reader.clone(), narf_filesystem::dma_buf::DmaResvUsage::Read);
        if dma_buf_sync(buf, DMA_BUF_SYNC_READ) != Some(0)
            || reader.waits.load(Ordering::Relaxed) != 0
        {
            return Err("CPU-read START must not wait on a read fence");
        }
        if dma_buf_sync(buf, DMA_BUF_SYNC_WRITE | DMA_BUF_SYNC_END) != Some(0)
            || reader.waits.load(Ordering::Relaxed) != 0
        {
            return Err("END must not wait");
        }
        if dma_buf_sync(buf, DMA_BUF_SYNC_WRITE) != Some(0)
            || reader.waits.load(Ordering::Relaxed) == 0
        {
            return Err("CPU-write START must wait on a pending read fence");
        }
        let writer = TestFence::completing_on_wait(0xA00);
        object.resv.add_fence(
            writer.clone(),
            narf_filesystem::dma_buf::DmaResvUsage::Write,
        );
        if dma_buf_sync(buf, DMA_BUF_SYNC_READ) != Some(0)
            || writer.waits.load(Ordering::Relaxed) == 0
        {
            return Err("CPU-read START must wait on a pending write fence");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_dma_buf_sync_start_waits_implicit_fences
);

// IMPORT a pending sync_file as a WRITE fence, then EXPORT for READ: the
// exported sync_file is that fence (pending, then signalled with it). A
// READ import is only visible to a WRITE export.
fn smoke_abi_dma_buf_import_export_round_trip() -> TestResult {
    with_setup(|| {
        let (buf, _) = new_dma_buf()?;
        let write_fence = TestFence::new(0xB00, 3);
        let write_sync = sync_file_for(Some(write_fence.clone()))?;
        if import_sync_file(buf, DMA_BUF_SYNC_WRITE as u32, write_sync) != Some(0) {
            return Err("IMPORT_SYNC_FILE(WRITE) failed");
        }
        let exported = export_sync_file(buf, DMA_BUF_SYNC_READ as u32)
            .map_err(|_| "EXPORT_SYNC_FILE(READ) failed")?;
        if fd_flags(exported).is_none_or(|flags| flags & crate::fd::FD_CLOEXEC == 0) {
            return Err("exported sync_file must be O_CLOEXEC");
        }
        let (status, count, name, _) = query(exported)?;
        if status != 0 || count != 1 || readable(exported)? {
            return Err("export must carry the pending imported write fence");
        }
        expect_name(&name, "test_gpu-ring02816-3")?;
        write_fence.signal();
        if !readable(exported)? || query(exported)?.0 != 1 {
            return Err("exported sync_file must signal with the imported fence");
        }

        let (buf, _) = new_dma_buf()?;
        let read_fence = TestFence::new(0xC00, 1);
        let read_sync = sync_file_for(Some(read_fence.clone()))?;
        if import_sync_file(buf, DMA_BUF_SYNC_READ as u32, read_sync) != Some(0) {
            return Err("IMPORT_SYNC_FILE(READ) failed");
        }
        let for_read = export_sync_file(buf, DMA_BUF_SYNC_READ as u32)
            .map_err(|_| "EXPORT_SYNC_FILE(READ) failed")?;
        if !readable(for_read)? {
            return Err("a READ export must not wait on read fences");
        }
        let for_write = export_sync_file(buf, DMA_BUF_SYNC_WRITE as u32)
            .map_err(|_| "EXPORT_SYNC_FILE(WRITE) failed")?;
        if readable(for_write)? {
            return Err("a WRITE export must wait on read fences");
        }
        read_fence.signal();
        if !readable(for_write)? {
            return Err("WRITE export did not signal with the read fence");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_dma_buf_import_export_round_trip);

// Importing a merged sync_file adds every leaf; an EXPORT of several
// pending fences is one dma_fence_array sync_file listing them all.
fn smoke_abi_dma_buf_import_merged_exports_array() -> TestResult {
    with_setup(|| {
        let (buf, _) = new_dma_buf()?;
        let first = TestFence::new(0xD00, 1);
        let second = TestFence::new(0xE00, 1);
        let a = sync_file_for(Some(first.clone()))?;
        let b = sync_file_for(Some(second.clone()))?;
        let mut data = merge_data(b, b"");
        if ioctl(a, SYNC_IOC_MERGE, data.as_mut_ptr() as u64) != Some(0) {
            return Err("merge fixture failed");
        }
        let merged = i32::from_ne_bytes(data[36..40].try_into().unwrap());
        if import_sync_file(buf, DMA_BUF_SYNC_RW as u32, merged) != Some(0) {
            return Err("IMPORT_SYNC_FILE(RW) of a merged file failed");
        }
        let exported = export_sync_file(buf, DMA_BUF_SYNC_READ as u32)
            .map_err(|_| "EXPORT_SYNC_FILE failed")?;
        let (status, count, name, _) = query(exported)?;
        if status != 0 || count != 2 || !name.starts_with(b"dma_fence_array-unbound") {
            return Err("export of two fences must be a dma_fence_array of both");
        }
        first.signal();
        second.signal();
        if !readable(exported)? {
            return Err("array export did not signal with its leaves");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_dma_buf_import_merged_exports_array);

// dma_buf_export_sync_file on a buffer without fences returns
// dma_fence_get_stub(): one signalled fence (context 0, seqno 0).
fn smoke_abi_dma_buf_export_without_fences_is_signalled() -> TestResult {
    with_setup(|| {
        let (buf, _) = new_dma_buf()?;
        for flags in [DMA_BUF_SYNC_READ, DMA_BUF_SYNC_WRITE, DMA_BUF_SYNC_RW] {
            let fd = export_sync_file(buf, flags as u32)
                .map_err(|_| "EXPORT_SYNC_FILE on an idle buffer failed")?;
            if !readable(fd)? {
                return Err("idle-buffer export must be readable at once");
            }
            let (status, count, name, entries) = query(fd)?;
            if status != 1 || count != 1 || entry_status(&entries[0]) != 1 {
                return Err("idle-buffer export must be one signalled fence");
            }
            expect_name(&name, "detached-driver-signaled-timeli")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_dma_buf_export_without_fences_is_signalled
);

// EXPORT/IMPORT flags must be READ, WRITE or both (EINVAL otherwise, before
// the fd is looked at); IMPORT of a bad fd or a non-sync_file is EINVAL
// (sync_file_get_fence's NULL); EXPORT at RLIMIT_NOFILE is EMFILE; an
// unknown dma-buf ioctl is ENOTTY.
fn smoke_abi_dma_buf_sync_file_ioctl_errors() -> TestResult {
    with_setup(|| {
        let (buf, _) = new_dma_buf()?;
        let sync = sync_file_for(Some(TestFence::new(0xF00, 1)))?;
        let plain = install_ops(Arc::new(Plain))? as i32;
        for flags in [0u32, 4, 8, 3 | 4] {
            if export_sync_file(buf, flags) != Err(Some(EINVAL)) {
                return Err("EXPORT_SYNC_FILE with bad flags must be -EINVAL");
            }
            if import_sync_file(buf, flags, sync) != Some(EINVAL) {
                return Err("IMPORT_SYNC_FILE with bad flags must be -EINVAL");
            }
        }
        for bad in [-1, plain, 999] {
            if import_sync_file(buf, DMA_BUF_SYNC_WRITE as u32, bad) != Some(EINVAL) {
                return Err("IMPORT_SYNC_FILE of a non-sync_file must be -EINVAL");
            }
        }
        if ioctl(buf, DMA_BUF_IOCTL_EXPORT_SYNC_FILE, 1 << 47) != Some(EFAULT) {
            return Err("EXPORT_SYNC_FILE with a faulting pointer must be -EFAULT");
        }
        if ioctl(buf, DMA_BUF_IOCTL_UNKNOWN, 1 << 47) != Some(ENOTTY) {
            return Err("an unknown dma-buf ioctl must be -ENOTTY");
        }
        let next = install_ops(Arc::new(Plain))?;
        let _ = fd::with_table(FAKE_TASK, |table| table.close(next));
        if !crate::handlers::__test_set_rlimit(FAKE_TASK, 7, next as u64, 4096) {
            return Err("lower RLIMIT_NOFILE");
        }
        if export_sync_file(buf, DMA_BUF_SYNC_READ as u32) != Err(Some(EMFILE)) {
            return Err("EXPORT_SYNC_FILE at RLIMIT_NOFILE must be -EMFILE");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_dma_buf_sync_file_ioctl_errors);

// DMA_BUF_SET_NAME: strndup_user(buf, DMA_BUF_NAME_LEN) — up to 31 bytes
// plus NUL is stored; 32 bytes without a NUL is EINVAL; a fault is EFAULT.
fn smoke_abi_dma_buf_set_name() -> TestResult {
    with_setup(|| {
        let (buf, object) = new_dma_buf()?;
        let name = b"chromium-video-frame\0";
        if ioctl(buf, DMA_BUF_SET_NAME_B, name.as_ptr() as u64) != Some(0) {
            return Err("DMA_BUF_SET_NAME of a short name failed");
        }
        if object.name().as_deref() != Some(&b"chromium-video-frame"[..]) {
            return Err("DMA_BUF_SET_NAME did not store the name");
        }
        let longest = [b'a'; 32];
        let mut fits = longest;
        fits[31] = 0;
        if ioctl(buf, DMA_BUF_SET_NAME_B, fits.as_ptr() as u64) != Some(0) {
            return Err("a 31-byte name must be accepted");
        }
        if ioctl(buf, DMA_BUF_SET_NAME_B, longest.as_ptr() as u64) != Some(EINVAL) {
            return Err("a name without NUL in 32 bytes must be -EINVAL");
        }
        if ioctl(buf, DMA_BUF_SET_NAME_B, 1 << 47) != Some(EFAULT) {
            return Err("DMA_BUF_SET_NAME with a faulting pointer must be -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_dma_buf_set_name);
