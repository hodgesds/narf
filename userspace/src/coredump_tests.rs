//! Preserve crash identity even when a large dump cannot be completed.
use super::*;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_filesystem::{FsFuture, Mode, Stat};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

struct Capture {
    bytes: IrqSafeSpinLock<Vec<u8>>,
    calls: AtomicUsize,
    capacity: usize,
    chunk: usize,
}

impl Capture {
    fn new(capacity: usize, chunk: usize) -> Self {
        Self {
            bytes: IrqSafeSpinLock::new(Vec::new()),
            calls: AtomicUsize::new(0),
            capacity,
            chunk,
        }
    }
}

impl FileOps for Capture {
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Ok(0) })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let offset = offset as usize;
            if offset >= self.capacity {
                return Err(FsError::NoSpace);
            }
            let count = buf.len().min(self.chunk).min(self.capacity - offset);
            let mut bytes = self.bytes.lock();
            let size = bytes.len().max(offset + count);
            bytes.resize(size, 0);
            bytes[offset..offset + count].copy_from_slice(&buf[..count]);
            Ok(count)
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.bytes.lock().len() as u64,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

fn fixture(headers: usize) -> (Elf64_Ehdr, Vec<Elf64_Phdr>, Vec<u8>) {
    let notes = build_note_segment(
        &user_regs_struct::default(),
        &__test_prpsinfo(4242, b"greeter-crash"),
        &[],
    );
    let (phoff, note_offset, _) = metadata_offsets(headers, notes.len());
    let ehdr = Elf64_Ehdr {
        e_ident: [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        e_type: 4,
        e_phoff: phoff,
        e_ehsize: 64,
        e_phentsize: 56,
        e_phnum: headers as u16,
        ..Default::default()
    };
    let mut phdrs = alloc::vec![Elf64_Phdr::default(); headers];
    phdrs[0] = Elf64_Phdr {
        p_type: 4,
        p_offset: note_offset,
        p_filesz: notes.len() as u64,
        ..Default::default()
    };
    (ehdr, phdrs, notes)
}

fn smoke_coredump_interrupted_metadata_preserves_notes() -> TestResult {
    // The physical greeter's dump stopped after 822 of 853 headers, before
    // any registers or identity were saved. Simulate an even earlier stop.
    let (ehdr, phdrs, notes) = fixture(853);
    let file = Arc::new(Capture::new(4096, usize::MAX));
    if write_metadata(0, file.clone(), u64::MAX, &ehdr, &phdrs, &notes).is_ok() {
        return TestResult::Fail("injected metadata write interruption was hidden");
    }
    let bytes = file.bytes.lock();
    let start = phdrs[0].p_offset as usize;
    if bytes.get(start..start + notes.len()) != Some(notes.as_slice()) {
        return TestResult::Fail("partial metadata lost crash registers and identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_interrupted_metadata_preserves_notes
);

fn smoke_coredump_metadata_batches_writes_and_retries_short_writes() -> TestResult {
    let (ehdr, phdrs, notes) = fixture(853);
    let full = Arc::new(Capture::new(usize::MAX, usize::MAX));
    if write_metadata(0, full.clone(), u64::MAX, &ehdr, &phdrs, &notes).is_err()
        || full.calls.load(Ordering::Relaxed) != 1
    {
        return TestResult::Fail("core metadata still needs a write per mapping");
    }
    let short = Arc::new(Capture::new(usize::MAX, 317));
    if write_metadata(0, short.clone(), u64::MAX, &ehdr, &phdrs, &notes).is_err()
        || *full.bytes.lock() != *short.bytes.lock()
    {
        return TestResult::Fail("short metadata writes did not preserve every byte");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_metadata_batches_writes_and_retries_short_writes
);

fn smoke_coredump_zero_write_is_an_error() -> TestResult {
    let file = Arc::new(Capture::new(4096, 0));
    if write_at(0, file.clone(), u64::MAX, 0, b"core").is_ok() {
        return TestResult::Fail("a zero-length write reported a completed core");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/coredump", smoke_coredump_zero_write_is_an_error);

/// Linux `vma_dump_size` dumps nothing for VM_IO/VM_PFNMAP mappings. A DRM
/// VRAM BAR mapping (WriteCombining device frames, here at 992 GiB, far above
/// the direct map) keeps its PT_LOAD size but no file bytes; reading it
/// through `kernel_ptr` faulted the kernel and froze the machine.
fn smoke_coredump_skips_device_mappings() -> TestResult {
    use narf_memory::address_space::{Region, RegionPerms};
    let bar = PhysAddr::new(0xf8_0000_0000);
    let Ok(backing) = narf_memory::region_backing::RegionBacking::try_from_slice(&[bar]) else {
        return TestResult::Fail("backing allocation");
    };
    let shared = RegionPerms(
        RegionPerms::READ.0
            | RegionPerms::WRITE.0
            | RegionPerms::SHARED.0
            | RegionPerms::LOCK_EXEMPT.0,
    );
    let device = Region {
        base: narf_memory::VirtAddr::new(0x7000_0000),
        len: 4096,
        perms: shared.with_memory_type(narf_memory::MemoryType::WriteCombining),
        phys: backing.clone(),
    };
    let write_back = Region {
        perms: shared,
        ..device.clone()
    };
    let anon = Region {
        perms: RegionPerms(RegionPerms::READ.0 | RegionPerms::WRITE.0),
        ..device.clone()
    };
    if dump_len(&device) != 0 {
        return TestResult::Fail("device (VRAM BAR) mapping would be read into the core");
    }
    if dump_len(&write_back) != 4096 || dump_len(&anon) != 4096 {
        return TestResult::Fail("write-back mappings must still be dumped");
    }
    // The per-page guard: a non-RAM frame is never dereferenced.
    if narf_memory::frame::is_system_ram(bar) {
        return TestResult::Fail("a 992 GiB BAR frame classified as System RAM");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/coredump", smoke_coredump_skips_device_mappings);

fn smoke_coredump_sparse_anonymous_trimmed() -> TestResult {
    use narf_memory::address_space::{Region, RegionPerms};
    let anon_perms = RegionPerms(RegionPerms::READ.0 | RegionPerms::WRITE.0);
    let empty_region = Region {
        base: narf_memory::VirtAddr::new(0x1000_0000),
        len: 64 * 1024 * 1024,
        perms: anon_perms,
        phys: narf_memory::region_backing::RegionBacking::new(),
    };
    if dump_len(&empty_region) != 0 {
        return TestResult::Fail("unbacked sparse region must dump 0 bytes");
    }

    let mut sparse_backing = narf_memory::region_backing::RegionBacking::new();
    if sparse_backing.reserve_slot(2).is_err() {
        return TestResult::Fail("backing reservation failed");
    }
    if let Some(slot) = sparse_backing.get_mut(2) {
        *slot = PhysAddr::new(0x2000);
    } else {
        return TestResult::Fail("backing slot 2 absent");
    }
    let sparse_region = Region {
        base: narf_memory::VirtAddr::new(0x1000_0000),
        len: 64 * 1024 * 1024,
        perms: anon_perms,
        phys: sparse_backing,
    };
    if dump_len(&sparse_region) != 3 * 4096 {
        return TestResult::Fail("sparse region must only dump up to highest resident page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_sparse_anonymous_trimmed
);

static DUMP_WAKES: AtomicUsize = AtomicUsize::new(0);
static RETAINED_WRITE: IrqSafeSpinLock<Option<OwnedDumpWrite>> = IrqSafeSpinLock::new(None);

fn retain_fixture_write(write: OwnedDumpWrite) {
    *RETAINED_WRITE.lock() = Some(write);
}

struct SignalFixture(u64);
impl SignalFixture {
    fn new(task: u64) -> Self {
        crate::handlers::__test_signal_reset();
        crate::handlers::signal_waker_init();
        Self(task)
    }
}
impl Drop for SignalFixture {
    fn drop(&mut self) {
        crate::handlers::clear_signal_pending(self.0, 9);
        crate::handlers::drop_signal_waker(self.0);
        RETAINED_WRITE.lock().take();
    }
}

struct WaitingWrite {
    ready: Arc<core::sync::atomic::AtomicBool>,
    drops: Arc<AtomicUsize>,
}
impl Future for WaitingWrite {
    type Output = Result<usize, FsError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        if self.ready.load(Ordering::Acquire) {
            Poll::Ready(Ok(4))
        } else {
            Poll::Pending
        }
    }
}
impl Drop for WaitingWrite {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
fn fixture_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {
        DUMP_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    unsafe fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop);
    // SAFETY: the vtable touches only a static atomic and ignores the pointer.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

fn smoke_coredump_sigkill_wakes_pending_owned_write() -> TestResult {
    const TASK: u64 = 0x0c0d_e519;
    let _signals = SignalFixture::new(TASK);
    DUMP_WAKES.store(0, Ordering::Relaxed);
    let ready = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let waker = fixture_waker();
    let mut cx = Context::from_waker(&waker);
    let mut write = DumpWrite {
        task: TASK,
        write: Some(Box::pin(WaitingWrite {
            ready: ready.clone(),
            drops: drops.clone(),
        })),
        started: false,
        drain: retain_fixture_write,
    };
    if Pin::new(&mut write).poll(&mut cx) != Poll::Pending
        || !crate::handlers::dbg_has_signal_waker(TASK)
    {
        return TestResult::Fail("pending core write did not arm a signal wake");
    }
    // The I/O future never wakes itself. Only the fatal signal wakes this
    // same executor waker, so poll_blocking can resume and observe the kill.
    crate::handlers::raise_signal_pending(TASK, 9);
    if DUMP_WAKES.load(Ordering::Relaxed) != 1
        || Pin::new(&mut write).poll(&mut cx) != Poll::Ready(Err(DumpWriteError::Killed))
    {
        return TestResult::Fail("SIGKILL did not interrupt a never-waking core write");
    }
    drop(write);
    if drops.load(Ordering::Relaxed) != 0 || crate::handlers::dbg_has_signal_waker(TASK) {
        return TestResult::Fail("cancel dropped in-flight ownership or left a stale signal waker");
    }
    let Some(mut retained) = RETAINED_WRITE.lock().take() else {
        return TestResult::Fail("pending write was not retained for terminal completion");
    };
    if retained.as_mut().poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("retained write invented completion");
    }
    ready.store(true, Ordering::Release);
    if retained.as_mut().poll(&mut cx) != Poll::Ready(Ok(4)) {
        return TestResult::Fail("retained write could not finish");
    }
    drop(retained);
    if drops.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail(
            "core I/O ownership not released exactly once at terminal completion",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_sigkill_wakes_pending_owned_write
);

fn smoke_coredump_cancel_before_first_poll_posts_no_io() -> TestResult {
    const TASK: u64 = 0x0c0d_e520;
    let _signals = SignalFixture::new(TASK);
    crate::handlers::raise_signal_pending(TASK, 9);
    let ready = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let waker = fixture_waker();
    let mut cx = Context::from_waker(&waker);
    let mut write = DumpWrite {
        task: TASK,
        write: Some(Box::pin(WaitingWrite {
            ready,
            drops: drops.clone(),
        })),
        started: false,
        drain: retain_fixture_write,
    };
    let result = Pin::new(&mut write).poll(&mut cx);
    drop(write);
    if result != Poll::Ready(Err(DumpWriteError::Killed))
        || drops.load(Ordering::Relaxed) != 1
        || RETAINED_WRITE.lock().is_some()
    {
        return TestResult::Fail("preexisting kill posted I/O or falsely completed the dump");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_cancel_before_first_poll_posts_no_io
);

fn smoke_coredump_large_metadata_uses_bounded_writes() -> TestResult {
    let (ehdr, phdrs, notes) = fixture(3000);
    let file = Arc::new(Capture::new(usize::MAX, usize::MAX));
    if write_metadata(0, file.clone(), u64::MAX, &ehdr, &phdrs, &notes).is_err()
        || file.calls.load(Ordering::Relaxed) != 3
    {
        return TestResult::Fail("large core metadata was not split into bounded writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/coredump",
    smoke_coredump_large_metadata_uses_bounded_writes
);
