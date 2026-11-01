//! Native conversations with the production capture, permit pool and file.
//! Literal 36-byte header/extent vectors come from MIT Linux b90c984d
//! xe_guc_log.{c,h}, abi/guc_log_abi.h. No extraction or decoder assumptions.

use super::*;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
struct Memory {
    words: Vec<AtomicU32>,
    pages: u32,
    coherent: bool,
    reads: AtomicUsize,
    change_header: AtomicBool,
}
impl Memory {
    fn new() -> Self {
        let words = (0..LOG_BYTES / 4)
            .map(|word| AtomicU32::new(0x5a000000 ^ (word as u32 * 4)))
            .collect();
        let memory = Self {
            words,
            pages: 0x115,
            coherent: true,
            reads: AtomicUsize::new(0),
            change_header: AtomicBool::new(false),
        };
        for (offset, values) in [
            (
                0,
                [0xcabba9e6, 0xdeadfeed, 0, 16, 0x10000, 16, 0x10000, 3, 2],
            ),
            (36, [0xcabba9e6, 0x8086dead, 0, 0, 0x4000, 0, 0x4000, 0, 2]),
            (
                72,
                [
                    0xcabba9f7, 0xbeeffeed, 0, 32, 0x100000, 32, 0x100000, 0x1f, 2,
                ],
            ),
        ] {
            for (word, value) in values.into_iter().enumerate() {
                memory.put(offset + word * 4, value);
            }
        }
        memory
    }
    fn put(&self, offset: usize, value: u32) {
        self.words[offset / 4].store(value, Ordering::Release);
    }
}
impl GpuBacking for Memory {
    fn coherent_for_device(&self) -> bool {
        self.coherent
    }
    fn ggtt_offset(&self) -> u32 {
        panic!("capture must not inspect/export a GGTT address")
    }
    fn size_pages(&self) -> u32 {
        self.pages
    }
    fn read32(&self, offset: u64) -> u32 {
        assert!(offset & 3 == 0 && offset < LOG_BYTES as u64);
        self.reads.fetch_add(1, Ordering::Relaxed);
        let value = self.words[offset as usize / 4].load(Ordering::Acquire);
        if offset == (LOG_BYTES - 4) as u64 && self.change_header.swap(false, Ordering::AcqRel) {
            self.put(12, 64);
        }
        value
    }
    fn write32(&self, _: u64, _: u32) {
        panic!("passive capture must not consume or alter logs")
    }
}
fn identity(platform: GtPlatform) -> Identity {
    Identity {
        epoch: 42,
        incarnation: 99,
        now_ns: 123456,
        platform,
        firmware_version: (70, 54, 1),
        firmware_digest: [0xa5; 32],
    }
}
fn slot() -> u32 {
    (0..MAX_CARDS as u32)
        .rev()
        .find(|index| RETAINED[*index as usize].load(Ordering::Acquire) == 0)
        .expect("free log fixture slot")
}
fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn qword(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture expected a ready operation"),
    }
}

fn smoke_guc_log_exact_copy_header_and_profiles() -> TestResult {
    for (platform, tag) in [
        (GtPlatform::Alchemist, 1),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            2,
        ),
        (GtPlatform::Battlemage, 3),
    ] {
        let memory = Memory::new();
        let index = slot();
        let snapshot = CaptureBuffer::reserve_for_test(index)
            .unwrap()
            .capture(&memory, identity(platform), || true)
            .unwrap();
        assert_eq!(memory.reads.load(Ordering::Relaxed), 0x115000 / 4 + 54);
        let mut header = [0; 112];
        assert_eq!(snapshot.read_for_test(0, &mut header), 112);
        assert_eq!(&header[..8], b"NARFGLOG");
        assert_eq!(dword(&header, 8), 1);
        assert_eq!(dword(&header, 12), 112);
        assert_eq!(dword(&header, 16), 0x115000);
        assert_eq!(dword(&header, 20), index);
        assert_eq!(dword(&header, 24), tag);
        assert_eq!(dword(&header, 28), 3);
        assert_eq!(qword(&header, 32), 42);
        assert_eq!(qword(&header, 40), 99);
        assert_eq!(qword(&header, 48), 123456);
        assert_eq!(
            (dword(&header, 56), dword(&header, 60), dword(&header, 64)),
            (70, 54, 1)
        );
        assert_eq!(dword(&header, 68), 7);
        assert_eq!(dword(&header, 72), 0);
        assert_eq!(dword(&header, 76), 0x40);
        assert_eq!(&header[80..], &[0xa5; 32]);
        let mut body = [0; 4];
        assert_eq!(snapshot.read(112, &mut body), 4);
        assert_eq!(body, 0xcabba9e6u32.to_le_bytes());
        snapshot.read((112 + LOG_BYTES - 4) as u64, &mut body);
        assert_eq!(body, (0x5a000000u32 ^ 0x114ffcu32).to_le_bytes());
        // Read the entire image in deliberately unaligned pieces, including
        // the header/payload seam. Expected body comes from independent data.
        let mut offset = 0;
        let mut piece = [0; 4093];
        while offset < SNAPSHOT_BYTES {
            let n = snapshot.read(offset as u64, &mut piece);
            assert!(n > 0 && n <= piece.len());
            for (within, byte) in piece[..n].iter().enumerate() {
                let position = offset + within;
                let expected = if position < 112 {
                    header[position]
                } else {
                    let body = position - 112;
                    memory.words[body / 4].load(Ordering::Relaxed).to_le_bytes()[body % 4]
                };
                assert_eq!(*byte, expected);
            }
            offset += n;
        }
        assert_eq!(snapshot.read(SNAPSHOT_BYTES as u64, &mut body), 0);
        assert_eq!(snapshot.read(u64::MAX, &mut body), 0);
        assert_eq!(snapshot.read(0, &mut []), 0);
        drop(snapshot);
        assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_log_exact_copy_header_and_profiles
);

fn smoke_guc_log_untrusted_headers_never_control_copy() -> TestResult {
    let memory = Memory::new();
    // Malformed marker/size/pointers cannot drive reads outside the allocation.
    memory.put(0, 0);
    memory.put(36 + 16, u32::MAX);
    memory.put(72 + 8, 0x100001);
    memory.change_header.store(true, Ordering::Release);
    let snapshot = CaptureBuffer::reserve(slot())
        .unwrap()
        .capture(&memory, identity(GtPlatform::Battlemage), || true)
        .unwrap();
    assert_eq!(dword(&snapshot.header, 68), 0);
    assert_eq!(dword(&snapshot.header, 72), 1);
    assert_eq!(memory.reads.load(Ordering::Relaxed), 0x115000 / 4 + 54);
    assert_eq!(snapshot.buffer.bytes.len(), 0x115000);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_log_untrusted_headers_never_control_copy
);

fn smoke_guc_log_coherency_extent_and_access_loss() -> TestResult {
    let index = slot();
    for (coherent, pages, expected) in [
        (false, 0x115, FsError::Unsupported),
        (true, 0x114, FsError::InvalidData),
        (true, 0x116, FsError::InvalidData),
        (true, u32::MAX, FsError::InvalidData),
    ] {
        let mut memory = Memory::new();
        memory.coherent = coherent;
        memory.pages = pages;
        let result = CaptureBuffer::reserve(index).unwrap().capture(
            &memory,
            identity(GtPlatform::Alchemist),
            || panic!("invalid backing must be refused before access"),
        );
        assert_eq!(result.unwrap_err(), expected);
        assert_eq!(memory.reads.load(Ordering::Relaxed), 0);
    }
    for allowed in [0, 1, 2, 17, 278] {
        let memory = Memory::new();
        let mut checks = 0;
        let result = CaptureBuffer::reserve(index).unwrap().capture(
            &memory,
            identity(GtPlatform::Alchemist),
            || {
                checks += 1;
                checks <= allowed
            },
        );
        assert_eq!(result.unwrap_err(), FsError::NoDevice);
        assert_eq!(checks, allowed + 1);
        assert_eq!(
            memory.reads.load(Ordering::Relaxed),
            if allowed == 0 {
                0
            } else {
                27 + (allowed - 1).min(277) * 1024
            }
        );
        assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    }
    for mut identity in [identity(GtPlatform::Alchemist); 3]
        .into_iter()
        .enumerate()
        .map(|(index, mut value)| {
            match index {
                0 => value.epoch = 0,
                1 => value.incarnation = 0,
                _ => value.firmware_version = (70, 1, 0),
            };
            value
        })
    {
        let memory = Memory::new();
        assert_eq!(
            CaptureBuffer::reserve(index)
                .unwrap()
                .capture(&memory, identity, || true)
                .unwrap_err(),
            FsError::NoDevice
        );
        identity.platform = GtPlatform::Integrated(crate::intel_gpu::Generation::TigerLake);
        assert_eq!(
            CaptureBuffer::reserve(index)
                .unwrap()
                .capture(&memory, identity, || true)
                .unwrap_err(),
            FsError::Unsupported
        );
        assert_eq!(memory.reads.load(Ordering::Relaxed), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_log_coherency_extent_and_access_loss
);

static ENABLED: AtomicBool = AtomicBool::new(true);
static AUTHORIZED: AtomicBool = AtomicBool::new(true);
fn test_enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}
fn log_capability(cap: u32) -> bool {
    assert_eq!(cap, 34);
    AUTHORIZED.load(Ordering::Acquire)
}
struct Hook(Option<fn(u32) -> bool>);
impl Hook {
    fn install() -> Self {
        ENABLED.store(true, Ordering::Release);
        AUTHORIZED.store(true, Ordering::Release);
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            log_capability,
        )))
    }
}
impl Drop for Hook {
    fn drop(&mut self) {
        narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}
#[derive(Debug)]
struct Backend {
    memory: Memory,
    calls: AtomicUsize,
    pending: AtomicBool,
    available: AtomicBool,
    revoke_on_capture: AtomicBool,
    epoch: AtomicU64,
    incarnation: AtomicU64,
}
impl Backend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            memory: Memory::new(),
            calls: AtomicUsize::new(0),
            pending: AtomicBool::new(false),
            available: AtomicBool::new(true),
            revoke_on_capture: AtomicBool::new(false),
            epoch: AtomicU64::new(42),
            incarnation: AtomicU64::new(99),
        })
    }
    fn node(self: &Arc<Self>, index: u32) -> Node {
        Node {
            index,
            backend: self.clone(),
            gate: Gate {
                enabled: test_enabled,
                capable,
            },
        }
    }
}
impl UserBackend for Backend {
    fn status(&self) -> Option<crate::intel_gpu_user::UserStatus> {
        None
    }
    fn submit<'a>(
        &'a self,
        _: Arc<crate::intel_gpu_user::UserContext>,
        _: crate::intel_gpu_user::UserBatch,
    ) -> FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        Box::pin(async { Err(FsError::Unsupported) })
    }
    fn guc_log_snapshot(&self, buffer: CaptureBuffer) -> FsFuture<'_, Snapshot> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            core::future::poll_fn(|_| {
                if self.pending.load(Ordering::Acquire) {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            let mut identity = identity(GtPlatform::Battlemage);
            identity.epoch = self.epoch.load(Ordering::Acquire);
            identity.incarnation = self.incarnation.load(Ordering::Acquire);
            let snapshot = buffer.capture(&self.memory, identity, || {
                self.available.load(Ordering::Acquire)
            })?;
            if self.revoke_on_capture.load(Ordering::Acquire) {
                AUTHORIZED.store(false, Ordering::Release);
            }
            Ok(snapshot)
        })
    }
}
fn open(node: &Node) -> Arc<dyn FileOps> {
    node.open_instance_checked(false).unwrap().unwrap()
}

fn smoke_guc_log_default_off_and_capability_revocation() -> TestResult {
    use narf_boot::args::KernelCmdline;
    for line in [
        "",
        "narf.intel.guc_log",
        "narf.intel.guc_log=0",
        "narf.intel.guc_log=01",
        "narf.intel.guc_log=1 narf.intel.guc_log=0",
        "narf.intel.guc_log=1 narf.intel.guc_log=1",
        "narf.intel.guc_log=1 narf.intel.guc_log",
    ] {
        assert!(!opted_in(KernelCmdline::new(line)));
    }
    assert!(opted_in(KernelCmdline::new(
        "quiet narf.intel.guc_log=1 other=1"
    )));
    let _hook = Hook::install();
    let backend = Backend::new();
    let node = backend.node(slot());
    ENABLED.store(false, Ordering::Release);
    assert_eq!(
        node.open_instance_checked(false).err().unwrap(),
        FsError::OperationNotPermitted
    );
    ENABLED.store(true, Ordering::Release);
    let saved = narf_filesystem::__test_swap_caller_capable_hook(None);
    assert_eq!(
        node.open_instance_checked(false).err().unwrap(),
        FsError::OperationNotPermitted
    );
    narf_filesystem::__test_swap_caller_capable_hook(saved);
    AUTHORIZED.store(false, Ordering::Release);
    assert_eq!(
        node.open_instance_checked(false).err().unwrap(),
        FsError::OperationNotPermitted
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    AUTHORIZED.store(true, Ordering::Release);
    assert_eq!(
        node.open_instance_checked(true).err().unwrap(),
        FsError::ReadOnly
    );
    let file = open(&node);
    let mut output = [0x55; 16];
    AUTHORIZED.store(false, Ordering::Release);
    assert_eq!(
        ready(file.read(0, &mut output)),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    assert_eq!(output, [0x55; 16]);
    AUTHORIZED.store(true, Ordering::Release);
    assert_eq!(ready(file.read(0, &mut output)), Ok(16));
    let reads = backend.memory.reads.load(Ordering::Relaxed);
    AUTHORIZED.store(false, Ordering::Release);
    assert_eq!(
        ready(file.read(112, &mut output)),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(
        ready(file.read(u64::MAX, &mut [])),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(backend.memory.reads.load(Ordering::Relaxed), reads);
    AUTHORIZED.store(true, Ordering::Release);
    let other = open(&node);
    backend.revoke_on_capture.store(true, Ordering::Release);
    output.fill(0x55);
    assert_eq!(
        ready(other.read(0, &mut output)),
        Err(FsError::OperationNotPermitted)
    );
    assert_eq!(output, [0x55; 16]);
    assert_eq!(RETAINED[node.index as usize].load(Ordering::Acquire), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_log_default_off_and_capability_revocation
);

fn smoke_guc_log_pool_partial_reads_and_reset_lifetime() -> TestResult {
    let _hook = Hook::install();
    let backend = Backend::new();
    let index = slot();
    let node = backend.node(index);
    let first = open(&node);
    let second = open(&node);
    let third = open(&node);
    let mut first_header = [0; 112];
    assert_eq!(ready(first.read(0, &mut first_header)), Ok(112));
    backend.epoch.store(43, Ordering::Release);
    backend.incarnation.store(100, Ordering::Release);
    backend.memory.put(4096, 0xfedcba98);
    let mut second_header = [0; 112];
    assert_eq!(ready(second.read(0, &mut second_header)), Ok(112));
    assert_eq!(qword(&first_header, 32), 42);
    assert_eq!(qword(&second_header, 32), 43);
    assert_eq!(qword(&first_header, 40), 99);
    assert_eq!(qword(&second_header, 40), 100);
    let mut output = [0; 4];
    assert_eq!(ready(third.read(0, &mut output)), Err(FsError::Busy));
    assert_eq!(backend.calls.load(Ordering::Relaxed), 2);
    backend.available.store(false, Ordering::Release);
    assert_eq!(ready(first.read(112 + 4096, &mut output)), Ok(4));
    assert_eq!(output, 0x5a001000u32.to_le_bytes());
    assert_eq!(ready(second.read(112 + 4096, &mut output)), Ok(4));
    assert_eq!(output, 0xfedcba98u32.to_le_bytes());
    assert_eq!(
        ready(second.read(SNAPSHOT_BYTES as u64, &mut output)),
        Ok(0)
    );
    assert_eq!(ready(second.read(u64::MAX, &mut output)), Ok(0));
    assert_eq!(ready(second.write(0, b"clear")), Err(FsError::ReadOnly));
    // Duplicated descriptors retain the same copy and permit.
    let duplicate = first.clone();
    drop(first);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 2);
    drop(duplicate);
    assert_eq!(ready(third.read(0, &mut output)), Err(FsError::NoDevice));
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 1);
    backend.available.store(true, Ordering::Release);
    assert_eq!(ready(third.read(0, &mut output)), Ok(4));
    drop(second);
    drop(third);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    assert_eq!(CaptureBuffer::reserve(64).unwrap_err(), FsError::NoDevice);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_log_pool_partial_reads_and_reset_lifetime
);

fn smoke_guc_log_cancelled_waiters_release_only_their_copy() -> TestResult {
    let _hook = Hook::install();
    let backend = Backend::new();
    backend.pending.store(true, Ordering::Release);
    let index = slot();
    let node = backend.node(index);
    let first = open(&node);
    let second = open(&node);
    let mut a = [0; 8];
    let mut b = [0; 8];
    let mut c = [0; 8];
    let mut wait_a = first.read(0, &mut a);
    let mut wait_b = second.read(0, &mut b);
    let mut context = Context::from_waker(Waker::noop());
    assert!(wait_a.as_mut().poll(&mut context).is_pending());
    assert!(wait_b.as_mut().poll(&mut context).is_pending());
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 2);
    let mut same_file = first.read(0, &mut c);
    assert!(same_file.as_mut().poll(&mut context).is_pending());
    assert_eq!(backend.calls.load(Ordering::Acquire), 2);
    // No asynchronous firmware request exists: cancellation discards only a
    // private preallocated destination, leaving the owner/BO untouched.
    drop(wait_a);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 1);
    assert_eq!(backend.memory.reads.load(Ordering::Relaxed), 0);
    assert!(same_file.as_mut().poll(&mut context).is_pending());
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 2);
    drop(same_file);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 1);
    backend.incarnation.store(101, Ordering::Release);
    backend.pending.store(false, Ordering::Release);
    assert_eq!(wait_b.as_mut().poll(&mut context), Poll::Ready(Ok(8)));
    drop(wait_b);
    assert_eq!(b, *b"NARFGLOG");
    assert_eq!(ready(first.read(0, &mut a)), Ok(8));
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 2);
    drop(first);
    drop(second);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_guc_log",
    smoke_guc_log_cancelled_waiters_release_only_their_copy
);
