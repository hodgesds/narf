//! Kernel tests for mapped-file writeback.
//!
//! The cache is driven directly: a test publishes pages for an in-memory
//! file exactly as a fault does, stores into the frames as a mapping would,
//! and unmaps them through the same release hook memory calls. The engine
//! is polled by hand where a test needs to stop it half way.

use super::super::{
    drop_address_space, note_file_written, publish_shared_file_pages, release_shared_file_page,
    retain_shared_file_page, retain_shared_file_page_writable,
};
use super::*;
use alloc::vec;
use core::sync::atomic::AtomicU8;
use narf_filesystem::{FsFuture, InodeAttrs, Mode, Stat};
use narf_kernel_test::{kernel_test_in, TestResult};

const WRITES: u8 = 0;
/// The write never completes: anything that waits for it waits for ever.
const NEVER: u8 = 1;
const NO_SPACE: u8 = 2;
/// The write waits for `Store::gate_open`.
const GATED: u8 = 3;
/// Every write fails with EIO.
const IO_ERROR: u8 = 4;

/// What a test keeps of its file after dropping every reference to it.
struct Store {
    bytes: IrqSafeSpinLock<Vec<u8>>,
    /// `(offset, len)` of every write that reached the file.
    log: IrqSafeSpinLock<Vec<(u64, usize)>>,
    attempts: AtomicUsize,
    mode: AtomicU8,
    gate_open: AtomicBool,
    /// A `fn()` run at the start of every write.
    on_write: AtomicUsize,
    dropped: AtomicUsize,
}

struct MemFile {
    store: Arc<Store>,
    generation: AtomicU64,
    device: u64,
}

impl Drop for MemFile {
    fn drop(&mut self) {
        self.store.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

struct Gate<'a>(&'a AtomicBool);

impl Future for Gate<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.0.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl FileOps for MemFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let bytes = self.store.bytes.lock();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let count = (bytes.len() - start).min(buf.len());
            buf[..count].copy_from_slice(&bytes[start..start + count]);
            Ok(count)
        })
    }

    fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.store.attempts.fetch_add(1, Ordering::Relaxed);
            let hook = self.store.on_write.load(Ordering::Acquire);
            if hook != 0 {
                // SAFETY: the only non-zero values stored are `fn()`
                // pointers, by the tests below.
                let hook: fn() = unsafe { core::mem::transmute(hook) };
                hook();
            }
            match self.store.mode.load(Ordering::Acquire) {
                NEVER => core::future::pending::<()>().await,
                NO_SPACE => return Err(FsError::NoSpace),
                IO_ERROR => return Err(FsError::Io(narf_block::BlockError::IOError)),
                GATED => Gate(&self.store.gate_open).await,
                _ => {}
            }
            {
                let mut bytes = self.store.bytes.lock();
                let start = offset as usize;
                let end = start + buf.len();
                if bytes.len() < end {
                    bytes.resize(end, 0);
                }
                bytes[start..end].copy_from_slice(buf);
            }
            self.generation.fetch_add(1, Ordering::AcqRel);
            self.store.log.lock().push((offset, buf.len()));
            Ok(buf.len())
        })
    }

    fn truncate<'a>(&'a self, len: u64) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.store.bytes.lock().resize(len as usize, 0);
            self.generation.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.store.bytes.lock().len() as u64,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn mmap_cache_generation(&self) -> Option<u64> {
        Some(self.generation.load(Ordering::Acquire))
    }

    fn inode_attrs(&self) -> InodeAttrs {
        InodeAttrs {
            dev: self.device,
            ..InodeAttrs::default()
        }
    }
}

/// One test's file. Dropping it removes everything the test left in the
/// cache, so no later pass — in this test or another — meets a page of a
/// file whose writes can no longer complete.
struct Fixture {
    store: Arc<Store>,
    ops: Option<Arc<dyn FileOps>>,
    identity: SharedFileIdentity,
    /// Pages this fixture still holds a mapping of.
    held: Vec<PhysAddr>,
    /// Map as a mapping that cannot store to the file does.
    read_only: bool,
}

static NEXT_DEVICE: AtomicU64 = AtomicU64::new(0x5742_0000);

impl Fixture {
    fn new(pages: usize) -> Self {
        let store = Arc::new(Store {
            bytes: IrqSafeSpinLock::new(vec![0u8; pages * 4096]),
            log: IrqSafeSpinLock::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            mode: AtomicU8::new(WRITES),
            gate_open: AtomicBool::new(false),
            on_write: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        });
        let ops: Arc<dyn FileOps> = Arc::new(MemFile {
            store: Arc::clone(&store),
            generation: AtomicU64::new(1),
            device: NEXT_DEVICE.fetch_add(1, Ordering::Relaxed),
        });
        let identity = shared_file_identity(ops.as_ref());
        Self {
            store,
            ops: Some(ops),
            identity,
            held: Vec::new(),
            read_only: false,
        }
    }

    fn ops(&self) -> &Arc<dyn FileOps> {
        self.ops.as_ref().expect("the test still holds its file")
    }

    /// Fault `count` pages in from `first`, as a `MAP_SHARED` mapping does:
    /// read each into a fresh frame, publish, take the mapping reference.
    fn map(&mut self, first: usize, count: usize) -> Option<Vec<PhysAddr>> {
        let ops = Arc::clone(self.ops());
        let mut candidates = Vec::new();
        for index in first..first + count {
            let frame = narf_memory::alloc_frame().ok()?.start_address();
            // SAFETY: a fresh, exclusively owned, identity-mapped frame.
            let page =
                unsafe { core::slice::from_raw_parts_mut(frame.kernel_mut_ptr::<u8>(), 4096) };
            page.fill(0);
            let bytes = self.store.bytes.lock();
            let start = index * 4096;
            if start < bytes.len() {
                let len = (bytes.len() - start).min(4096);
                page[..len].copy_from_slice(&bytes[start..start + len]);
            }
            candidates.push(frame);
        }
        let generation = ops.mmap_cache_generation();
        let (canonical, publication) =
            publish_shared_file_pages(&ops, first as u64 * 4096, candidates, generation);
        for phys in &canonical {
            let retained = if self.read_only {
                retain_shared_file_page(phys.raw())
            } else {
                retain_shared_file_page_writable(phys.raw())
            };
            if !retained {
                return None;
            }
            self.held.push(*phys);
        }
        publication.commit();
        Some(canonical)
    }

    /// The last unmap of `pages`: what `munmap`, `exit_mmap` and the old
    /// image of an `execve` all come down to for the file cache.
    fn unmap(&mut self, pages: &[PhysAddr]) {
        for phys in pages {
            if let Some(at) = self.held.iter().position(|held| held == phys) {
                self.held.swap_remove(at);
                release_shared_file_page(phys.raw());
            }
        }
    }

    fn entry(&self) -> Option<(Arc<CachedFile>, Arc<dyn FileOps>)> {
        lookup(self.identity)
    }

    fn file_bytes(&self, at: usize, len: usize) -> Vec<u8> {
        self.store.bytes.lock()[at..at + len].to_vec()
    }

    fn log(&self) -> Vec<(u64, usize)> {
        self.store.log.lock().clone()
    }

    /// This file's unmapped pages that still owe it bytes.
    fn idle_dirty(&self) -> usize {
        let pages = SHARED_FILE_PAGES.lock();
        pages
            .idle_dirty
            .range(key(self.identity, 0)..)
            .take_while(|listed| listed.file == self.identity)
            .count()
    }

    /// `(mapped, listed as idle-dirty)` of the cached page at `page`.
    fn cached(&self, page: usize) -> Option<(bool, bool)> {
        let pages = SHARED_FILE_PAGES.lock();
        let phys = pages.by_file.get(&key(self.identity, page as u64 * 4096))?;
        let cached = pages.by_phys.get(phys)?;
        Some((cached.mappings != 0, cached.idle_dirty))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Nothing may be left that a later pass would wait on.
        self.store.mode.store(WRITES, Ordering::Release);
        self.store.gate_open.store(true, Ordering::Release);
        self.store.on_write.store(0, Ordering::Release);
        let held = core::mem::take(&mut self.held);
        for phys in held {
            release_shared_file_page(phys.raw());
        }
        drop_idle_dirty(self.identity);
        let mut cursor = 0;
        while let Some(next) = invalidate_step(self.identity, cursor, u64::MAX) {
            cursor = next;
        }
        release_if_unused(self.identity);
    }
}

fn store_bytes(phys: PhysAddr, at: usize, bytes: &[u8]) {
    // SAFETY: the test maps this cache page; frames are identity-mapped.
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            phys.kernel_mut_ptr::<u8>().add(at),
            bytes.len(),
        );
    }
}

fn page_bytes(phys: PhysAddr, at: usize, len: usize) -> Vec<u8> {
    // SAFETY: as in `store_bytes`.
    unsafe { core::slice::from_raw_parts(phys.kernel_ptr::<u8>().add(at), len).to_vec() }
}

/// Poll `future` to completion in place. Only for futures that make
/// progress by being polled (a yield, an open gate).
fn run<F: Future>(future: F) -> Option<F::Output> {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return Some(value);
        }
    }
    None
}

/// An address space that maps nothing, for the teardown hook.
const TEST_SPACE: u64 = u64::MAX - 0x5742;

/// The headline: tearing down an address space with dirty shared pages —
/// what `exit` and a SIGKILL both come to — writes nothing, waits for
/// nothing, and loses nothing. The file here can never complete a write, so
/// a teardown that tried one would not return.
fn smoke_teardown_writes_nothing_and_strands_nothing() -> TestResult {
    const PAGES: usize = 8;
    let mut fixture = Fixture::new(PAGES);
    fixture.store.mode.store(NEVER, Ordering::Release);
    let Some(pages) = fixture.map(0, PAGES) else {
        return TestResult::Fail("could not map the test file");
    };
    for (index, phys) in pages.iter().enumerate() {
        store_bytes(*phys, 0, &[0xD0 + index as u8; 64]);
    }
    let waits_before = crate::handlers::fallback_waits();

    fixture.unmap(&pages);
    drop_address_space(TEST_SPACE);

    if fixture.store.attempts.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("address-space teardown wrote a dirty MAP_SHARED page");
    }
    if crate::handlers::fallback_waits() != waits_before {
        return TestResult::Fail("address-space teardown waited on the filesystem with no task");
    }
    if fixture.idle_dirty() != PAGES {
        return TestResult::Fail("teardown did not hand its dirty pages to the file cache");
    }
    if (0..PAGES).any(|page| fixture.cached(page) != Some((false, true))) {
        return TestResult::Fail("a dirty page was dropped or left mapped by teardown");
    }

    // The page belongs to the file, and the cache keeps the file: every
    // other reference can go — the process is dead, its descriptors closed.
    fixture.ops = None;
    if fixture.store.dropped.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("the cache did not keep a file with unwritten pages open");
    }

    // The writeback task does what teardown did not.
    fixture.store.mode.store(WRITES, Ordering::Release);
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    if fixture.idle_dirty() != 0 {
        return TestResult::Fail("the background pass left unmapped dirty pages behind");
    }
    for index in 0..PAGES {
        if fixture.file_bytes(index * 4096, 64) != [0xD0 + index as u8; 64] {
            return TestResult::Fail("a store made before teardown never reached the file");
        }
    }
    if fixture.store.dropped.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("the cache kept the file open after its last page was written");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_teardown_writes_nothing_and_strands_nothing
);

/// Neighbouring dirty pages go to the filesystem as one operation per
/// batch, each page once, and a second pass finds nothing to do.
fn smoke_contiguous_pages_are_one_write_per_batch() -> TestResult {
    const PAGES: usize = 2 * BATCH_PAGES + 2;
    let mut fixture = Fixture::new(PAGES);
    let Some(pages) = fixture.map(0, PAGES) else {
        return TestResult::Fail("could not map the test file");
    };
    for (index, phys) in pages.iter().enumerate() {
        store_bytes(*phys, 8, &(index as u64 + 1).to_le_bytes());
    }
    fixture.unmap(&pages);
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    let batch = BATCH_PAGES * 4096;
    let expected = [
        (0u64, batch),
        (batch as u64, batch),
        (2 * batch as u64, 2 * 4096),
    ];
    if fixture.log() != expected {
        return TestResult::Fail("contiguous dirty pages were not written one batch at a time");
    }
    for index in 0..PAGES {
        if fixture.file_bytes(index * 4096 + 8, 8) != (index as u64 + 1).to_le_bytes() {
            return TestResult::Fail("a batched page reached the file with the wrong bytes");
        }
    }
    if run(background_pass()).is_none() || fixture.log().len() != expected.len() {
        return TestResult::Fail("a page already written was written again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_contiguous_pages_are_one_write_per_batch
);

/// Two mappers of one file dirty different pages. One goes away: its page
/// is written, the other's — still mapped, not yet due — is not, and is
/// neither lost nor written twice when its turn comes.
fn smoke_two_mappers_nothing_lost_nothing_twice() -> TestResult {
    let mut fixture = Fixture::new(4);
    let (Some(first), Some(second)) = (fixture.map(0, 1), fixture.map(2, 1)) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(first[0], 0, b"first mapper");
    store_bytes(second[0], 0, b"second mapper");

    fixture.unmap(&first);
    if run(background_pass()).is_none() || fixture.log() != [(0, 4096)] {
        return TestResult::Fail("the departed mapper's page was not the one page written");
    }
    if fixture.cached(2) != Some((true, false)) {
        return TestResult::Fail("the live mapper's page did not stay mapped and unlisted");
    }

    fixture.unmap(&second);
    if run(background_pass()).is_none() || fixture.log() != [(0, 4096), (8192, 4096)] {
        return TestResult::Fail("the second mapper's page was lost or a page was written twice");
    }
    if fixture.file_bytes(0, 12) != *b"first mapper"
        || fixture.file_bytes(8192, 13) != *b"second mapper"
    {
        return TestResult::Fail("a mapper's store did not reach the file");
    }
    if run(background_pass()).is_none() || fixture.log().len() != 2 {
        return TestResult::Fail("a clean page was written again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_two_mappers_nothing_lost_nothing_twice
);

/// A page that is still mapped is written once it has been dirty for the
/// expiry interval, and not before.
fn smoke_mapped_page_is_written_when_it_expires() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(pages[0], 100, b"still mapped");

    // First sight of the dirty page starts its clock.
    if run(background_pass()).is_none() || !fixture.log().is_empty() {
        return TestResult::Fail("a mapped page was written before it had expired");
    }
    // Restart the clock with nothing left on it, then let a pass find the
    // page due.
    DIRTY_EXPIRE_OVERRIDE_MS.store(0, Ordering::Relaxed);
    {
        let mut cache = SHARED_FILE_PAGES.lock();
        if let Some(page) = cache.by_phys.get_mut(&pages[0].raw()) {
            page.write_due = None;
        }
    }
    let first = run(background_pass()).is_some();
    let second = run(background_pass()).is_some();
    DIRTY_EXPIRE_OVERRIDE_MS.store(u64::MAX, Ordering::Relaxed);
    if !first || !second {
        return TestResult::Fail("the background pass did not complete");
    }
    if fixture.log() != [(0, 4096)] || fixture.file_bytes(100, 12) != *b"still mapped" {
        return TestResult::Fail("an expired mapped page was not written exactly once");
    }
    if fixture.cached(0) != Some((true, false)) {
        return TestResult::Fail("writeback disturbed the live mapping");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_mapped_page_is_written_when_it_expires
);

static RACING_PAGE: AtomicU64 = AtomicU64::new(0);

/// A mapper's store that lands while the page is being written: the page's
/// counter moves on between writeback's copy and its completion.
fn racing_store() {
    let phys = PhysAddr::new(RACING_PAGE.load(Ordering::Acquire));
    let mut counter = [0u8; 8];
    counter.copy_from_slice(&page_bytes(phys, 0, 8));
    store_bytes(phys, 0, &(u64::from_le_bytes(counter) + 1).to_le_bytes());
}

/// A writer keeps incrementing a counter in a mapped page while writeback
/// runs again and again. Every pass marks the page clean from the bytes it
/// WROTE, never from the page as it is when the write completes, so the
/// increment that landed in between is still owed: when the writer stops,
/// one more pass leaves the file equal to the page.
fn smoke_store_during_writeback_is_not_lost() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    let page = pages[0];
    RACING_PAGE.store(page.raw(), Ordering::Release);
    store_bytes(page, 0, &1u64.to_le_bytes());
    fixture
        .store
        .on_write
        .store(racing_store as usize, Ordering::Release);
    for round in 0..16u64 {
        if super::super::flush_current_file(fixture.ops()).is_err() {
            return TestResult::Fail("fsync of the mapped file failed");
        }
        // The file has the value the pass copied; the page is one ahead.
        if fixture.file_bytes(0, 8) != (round + 1).to_le_bytes()
            || page_bytes(page, 0, 8) != (round + 2).to_le_bytes()
        {
            return TestResult::Fail("writeback did not write the image it copied");
        }
    }
    // The writer stops. Its last increment has never been written.
    fixture.store.on_write.store(0, Ordering::Release);
    let writes = fixture.log().len();
    if super::super::flush_current_file(fixture.ops()).is_err() {
        return TestResult::Fail("fsync of the mapped file failed");
    }
    if fixture.log().len() != writes + 1 {
        return TestResult::Fail(
            "a store that landed during writeback was marked clean without being written",
        );
    }
    if fixture.file_bytes(0, 4096) != page_bytes(page, 0, 4096) {
        return TestResult::Fail("the file does not equal the page after the writer stopped");
    }
    if super::super::flush_current_file(fixture.ops()).is_err() || fixture.log().len() != writes + 1
    {
        return TestResult::Fail("a page equal to the file was written again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_store_during_writeback_is_not_lost
);

/// `write(2)` through the handler path: the bytes reach the file, then the
/// cache is told.
fn write2(fixture: &Fixture, offset: u64, bytes: &[u8]) -> bool {
    let stamp = write_stamp();
    let ops = fixture.ops();
    if run(ops.write(offset, bytes)) != Some(Ok(bytes.len())) {
        return false;
    }
    note_file_written(ops, offset, bytes, stamp);
    true
}

/// `write(2)` against a page a mapping has dirtied, in both orders, gives
/// what Linux gives — there both are stores into one folio and the later
/// one wins byte for byte — and leaves the file, the page and the page's
/// clean image agreeing, so nothing is rewritten for ever.
fn smoke_write2_and_mapped_store_agree_on_the_last_writer() -> TestResult {
    let mut fixture = Fixture::new(2);
    let Some(pages) = fixture.map(0, 2) else {
        return TestResult::Fail("could not map the test file");
    };

    // Mapped store first, then a write(2) over part of it.
    store_bytes(pages[0], 0, b"MAPSTORE");
    if !write2(&fixture, 4, b"WRITE2!!") {
        return TestResult::Fail("write(2) to the mapped file failed");
    }
    if page_bytes(pages[0], 0, 12) != *b"MAPSWRITE2!!" {
        return TestResult::Fail("write(2) did not reach the live page");
    }
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.file_bytes(0, 12) != *b"MAPSWRITE2!!"
    {
        return TestResult::Fail("map-store then write(2): the file is not MAPSWRITE2!!");
    }

    // write(2) first, then a mapped store over part of it.
    if !write2(&fixture, 4096, b"WRITE2!!") {
        return TestResult::Fail("write(2) to the mapped file failed");
    }
    store_bytes(pages[1], 2, b"MAP");
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.file_bytes(4096, 8) != *b"WRMAP2!!"
    {
        return TestResult::Fail("write(2) then map-store: the file is not WRMAP2!!");
    }

    // A page that differs from its old image only by a write(2) that is
    // already on the file is clean: writeback has nothing to do.
    let writes = fixture.log().len();
    if !write2(&fixture, 64, b"already on the file") {
        return TestResult::Fail("write(2) to the mapped file failed");
    }
    let after_write2 = fixture.log().len();
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.log().len() != after_write2
        || after_write2 != writes + 1
    {
        return TestResult::Fail("a page changed only by write(2) was written back again");
    }
    if page_bytes(pages[0], 0, 4096) != fixture.file_bytes(0, 4096)
        || page_bytes(pages[1], 0, 4096) != fixture.file_bytes(4096, 4096)
    {
        return TestResult::Fail("file and page disagree after write(2) and mapped stores");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_write2_and_mapped_store_agree_on_the_last_writer
);

/// A `write(2)` that lands while a batch holds the page: the batch's older
/// image reaches the file after it. The page must come out dirty, so the
/// next pass puts the `write(2)` bytes back — whichever of the two orders
/// the cache hears about them in.
fn smoke_write2_racing_a_batch_is_written_again() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    let page = pages[0];
    let Some((entry, ops)) = fixture.entry() else {
        return TestResult::Fail("a mapped file has no cache entry");
    };

    // The cache is told while the batch still holds the page.
    store_bytes(page, 0, b"mapped store");
    fixture.store.mode.store(GATED, Ordering::Release);
    {
        let mut budget = usize::MAX;
        let mut batch = core::pin::pin!(write_range(
            &entry,
            &ops,
            (0, u64::MAX),
            Plan::background(Select::All),
            &mut budget,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if batch.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("the gated batch did not stop in its write");
        }
        // write(2) lands on the file and is reported, batch still in flight.
        let stamp = write_stamp();
        fixture.store.bytes.lock()[512..520].copy_from_slice(b"WRITE(2)");
        note_file_written(fixture.ops(), 512, b"WRITE(2)", stamp);
        fixture.store.gate_open.store(true, Ordering::Release);
        if !matches!(batch.as_mut().poll(&mut cx), Poll::Ready(Ok(_))) {
            return TestResult::Fail("the released batch did not complete");
        }
    }
    if fixture.file_bytes(512, 8) == *b"WRITE(2)" {
        return TestResult::Fail("the test did not produce the race it is about");
    }
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.file_bytes(512, 8) != *b"WRITE(2)"
    {
        return TestResult::Fail("a write(2) overwritten by an older batch was never rewritten");
    }

    // The cache is told only after the batch has finished and unpinned.
    fixture.store.mode.store(WRITES, Ordering::Release);
    let stamp = write_stamp();
    fixture.store.bytes.lock()[1024..1032].copy_from_slice(b"LATENOTE");
    store_bytes(page, 2048, b"another mapped store");
    if super::super::flush_current_file(fixture.ops()).is_err() {
        return TestResult::Fail("fsync of the mapped file failed");
    }
    // The batch wrote the whole page, without the write(2) bytes.
    note_file_written(fixture.ops(), 1024, b"LATENOTE", stamp);
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.file_bytes(1024, 8) != *b"LATENOTE"
        || fixture.file_bytes(0, 4096) != page_bytes(page, 0, 4096)
    {
        return TestResult::Fail(
            "a write(2) reported after a batch completed was taken as already on the file",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_write2_racing_a_batch_is_written_again
);

/// A batch stopped half way through its write, and a truncate to zero and
/// back: the size change has to wait for the batch, and afterwards nothing
/// the truncate removed comes back. And the other way round: a batch that
/// has to wait for a size change starts from the cache the size change
/// left.
fn smoke_truncate_excludes_a_batch_in_flight() -> TestResult {
    const PAGES: usize = 4;
    let mut fixture = Fixture::new(PAGES);
    let Some(pages) = fixture.map(0, PAGES) else {
        return TestResult::Fail("could not map the test file");
    };
    for phys in &pages {
        store_bytes(*phys, 0, &[0xEE; 4096]);
    }
    fixture.unmap(&pages);
    let Some((entry, ops)) = fixture.entry() else {
        return TestResult::Fail("a file with dirty pages has no cache entry");
    };
    let mut cx = Context::from_waker(Waker::noop());

    // A batch in flight, stopped inside its filesystem write.
    fixture.store.mode.store(GATED, Ordering::Release);
    {
        let mut budget = usize::MAX;
        let mut batch = core::pin::pin!(write_range(
            &entry,
            &ops,
            (0, u64::MAX),
            Plan::background(Select::Idle),
            &mut budget,
        ));
        if batch.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("the gated batch did not stop in its write");
        }
        // The truncate wants the lock `size_change_serialized` takes.
        let mut resize = core::pin::pin!(entry.lock.lock());
        if resize.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("a size change did not have to wait for the batch");
        }
        fixture.store.gate_open.store(true, Ordering::Release);
        if !matches!(batch.as_mut().poll(&mut cx), Poll::Ready(Ok(_))) {
            return TestResult::Fail("the released batch did not complete");
        }
        let Poll::Ready(guard) = resize.as_mut().poll(&mut cx) else {
            return TestResult::Fail("the size change was not admitted after the batch");
        };
        drop(guard);
    }
    fixture.store.mode.store(WRITES, Ordering::Release);
    let shrink = size_change_serialized(fixture.ops(), || run(fixture.ops().truncate(0)));
    let grow = size_change_serialized(fixture.ops(), || {
        run(fixture.ops().truncate(PAGES as u64 * 4096))
    });
    if shrink != Some(Ok(())) || grow != Some(Ok(())) {
        return TestResult::Fail("the truncate failed");
    }
    if (0..PAGES).any(|page| fixture.cached(page).is_some()) {
        return TestResult::Fail("a cached page survived a truncate to zero");
    }
    if run(background_pass()).is_none()
        || super::super::flush_current_file(fixture.ops()).is_err()
        || fixture
            .file_bytes(0, PAGES * 4096)
            .iter()
            .any(|byte| *byte != 0)
    {
        return TestResult::Fail("data removed by a truncate came back from the cache");
    }

    // The other order: the size change holds the lock, the batch waits.
    let Some(pages) = fixture.map(0, PAGES) else {
        return TestResult::Fail("could not map the test file again");
    };
    for phys in &pages {
        store_bytes(*phys, 0, &[0xDD; 4096]);
    }
    fixture.unmap(&pages);
    let writes = fixture.log().len();
    let attempts = fixture.store.attempts.load(Ordering::Relaxed);
    let Some((entry, ops)) = fixture.entry() else {
        return TestResult::Fail("a file with dirty pages has no cache entry");
    };
    {
        let Some(guard) = entry.lock.try_lock() else {
            return TestResult::Fail("the file's writeback lock was not free");
        };
        let mut budget = usize::MAX;
        let mut batch = core::pin::pin!(write_range(
            &entry,
            &ops,
            (0, u64::MAX),
            Plan::background(Select::Idle),
            &mut budget,
        ));
        if batch.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("a batch started during a size change");
        }
        if fixture.store.attempts.load(Ordering::Relaxed) != attempts {
            return TestResult::Fail("a batch wrote during a size change");
        }
        // What the size change does while it holds the lock.
        if run(fixture.ops().truncate(0)) != Some(Ok(())) {
            return TestResult::Fail("the truncate failed");
        }
        invalidate_past(fixture.identity, 0);
        if run(fixture.ops().truncate(PAGES as u64 * 4096)) != Some(Ok(())) {
            return TestResult::Fail("the truncate failed");
        }
        drop(guard);
        if !matches!(batch.as_mut().poll(&mut cx), Poll::Ready(Ok(_))) {
            return TestResult::Fail("the batch did not complete after the size change");
        }
    }
    if fixture.log().len() != writes
        || fixture.store.bytes.lock().len() != PAGES * 4096
        || fixture
            .file_bytes(0, PAGES * 4096)
            .iter()
            .any(|byte| *byte != 0)
    {
        return TestResult::Fail("a batch that waited for a truncate wrote what it removed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_truncate_excludes_a_batch_in_flight
);

/// A hole punched under a dirty cached page: the hole stays a hole when the
/// page is written back, and the page's bytes outside it still arrive.
fn smoke_hole_punch_reaches_cached_pages() -> TestResult {
    let mut fixture = Fixture::new(2);
    let Some(pages) = fixture.map(0, 2) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(pages[0], 0, &[0xAB; 4096]);
    store_bytes(pages[1], 0, &[0xCD; 4096]);
    fixture.unmap(&pages);

    // Punch [2048, 6144): the second half of page 0, the first of page 1.
    fallocate_serialized(
        fixture.ops(),
        FALLOC_FL_PUNCH_HOLE | 0x01,
        2048,
        4096,
        || fixture.store.bytes.lock()[2048..6144].fill(0),
        |_| true,
    );
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    let bytes = fixture.file_bytes(0, 8192);
    if bytes[2048..6144].iter().any(|byte| *byte != 0) {
        return TestResult::Fail("a dirty cached page wrote old bytes back into a punched hole");
    }
    if bytes[..2048].iter().any(|byte| *byte != 0xAB)
        || bytes[6144..].iter().any(|byte| *byte != 0xCD)
    {
        return TestResult::Fail("a hole punch lost dirty bytes outside the hole");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/writeback", smoke_hole_punch_reaches_cached_pages);

/// Write errors, as Linux btrfs treats them. A transient one (ENOSPC) keeps
/// the page dirty for as many passes as it takes — it is never dropped on a
/// timer — and the next `fsync` reports it once, after writing the page
/// when space is back. A hard one (EIO) is recorded and reported once, and
/// the page stops being dirty with the bytes that were attempted, as
/// `extent_writepage` leaves a folio after `-EIO`.
fn smoke_write_errors_keep_transient_pages_and_report_once() -> TestResult {
    let mut fixture = Fixture::new(2);
    let Some(pages) = fixture.map(0, 2) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(pages[0], 0, b"no room for this");
    fixture.unmap(&pages[..1]);

    fixture.store.mode.store(NO_SPACE, Ordering::Release);
    for _ in 0..8 {
        if run(background_pass()).is_none() {
            return TestResult::Fail("the background pass did not complete");
        }
    }
    if fixture.idle_dirty() != 1 || fixture.cached(0) != Some((false, true)) {
        return TestResult::Fail("a page that failed with ENOSPC was dropped or marked clean");
    }
    // Space comes back; fsync writes the page and still says that a write
    // was lost track of in the meantime — once.
    fixture.store.mode.store(WRITES, Ordering::Release);
    if super::super::flush_current_file(fixture.ops()) != Err(FsError::NoSpace) {
        return TestResult::Fail("fsync did not report the background ENOSPC");
    }
    if fixture.file_bytes(0, 16) != *b"no room for this" {
        return TestResult::Fail("fsync did not write the page that had failed");
    }
    if super::super::flush_current_file(fixture.ops()) != Ok(()) {
        return TestResult::Fail("the same writeback error was reported twice");
    }

    // A hard error.
    store_bytes(pages[1], 0, b"lost to EIO");
    fixture.unmap(&pages[1..]);
    fixture.store.mode.store(IO_ERROR, Ordering::Release);
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    if fixture.idle_dirty() != 0 {
        return TestResult::Fail("a page that failed with EIO stayed dirty");
    }
    fixture.store.mode.store(WRITES, Ordering::Release);
    if !matches!(
        super::super::flush_current_file(fixture.ops()),
        Err(FsError::Io(_))
    ) {
        return TestResult::Fail("fsync did not report the background EIO");
    }
    if super::super::flush_current_file(fixture.ops()) != Ok(()) {
        return TestResult::Fail("the EIO was reported twice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_write_errors_keep_transient_pages_and_report_once
);

static THROTTLE_HOOK: AtomicUsize = AtomicUsize::new(0);
static THROTTLE_ROUNDS_SEEN: AtomicUsize = AtomicUsize::new(0);

/// Called from each round of `throttle_dirtier`'s wait.
pub(super) fn throttle_round() {
    let hook = THROTTLE_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `fn()` pointers are stored, by the test below.
        let hook: fn() = unsafe { core::mem::transmute(hook) };
        hook();
    }
}

/// The flusher catching up on the second round a dirtier waits.
fn flusher_catches_up() {
    if THROTTLE_ROUNDS_SEEN.fetch_add(1, Ordering::AcqRel) == 1 {
        let _ = run(background_pass());
    }
}

/// A dirtier that has left more unwritten pages behind than allowed waits —
/// and stops waiting as soon as writeback has brought the count down.
fn smoke_dirtier_waits_for_writeback() -> TestResult {
    const PAGES: usize = 6;
    let mut fixture = Fixture::new(PAGES);
    let Some(pages) = fixture.map(0, PAGES) else {
        return TestResult::Fail("could not map the test file");
    };
    for phys in &pages {
        store_bytes(*phys, 0, b"dirty");
    }
    // The limit is on every file's unwritten pages together: write whatever
    // earlier tests left behind first, so what remains cannot move.
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    let baseline = IDLE_DIRTY_PAGES.load(Ordering::Relaxed);

    // Under the limit: no wait at all.
    DIRTY_LIMIT.store(baseline + PAGES, Ordering::Relaxed);
    let waits = THROTTLE_WAITS.load(Ordering::Relaxed);
    fixture.unmap(&pages);
    throttle_dirtier();
    let waited_under_limit = THROTTLE_WAITS.load(Ordering::Relaxed) != waits;

    // Over it: wait until the flusher has caught up, then return.
    DIRTY_LIMIT.store(baseline + 1, Ordering::Relaxed);
    THROTTLE_ROUNDS_SEEN.store(0, Ordering::Release);
    THROTTLE_HOOK.store(flusher_catches_up as usize, Ordering::Release);
    throttle_dirtier();
    THROTTLE_HOOK.store(0, Ordering::Release);
    DIRTY_LIMIT.store(0, Ordering::Relaxed);
    let rounds = THROTTLE_ROUNDS_SEEN.load(Ordering::Acquire);

    if waited_under_limit {
        return TestResult::Fail("a dirtier under the limit was made to wait");
    }
    if rounds < 2 {
        return TestResult::Fail("a dirtier over the limit was not made to wait");
    }
    if rounds > 3 || IDLE_DIRTY_PAGES.load(Ordering::Relaxed) > baseline + 1 {
        return TestResult::Fail("the dirtier kept waiting after writeback caught up");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/writeback", smoke_dirtier_waits_for_writeback);

/// A future that is pending for its first two polls.
struct ThirdTime(u8);

impl Future for ThirdTime {
    type Output = u8;

    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u8> {
        self.0 += 1;
        if self.0 == 3 {
            Poll::Ready(7)
        } else {
            Poll::Pending
        }
    }
}

/// A filesystem wait with no task to park still finishes its operation —
/// it is never abandoned half way — and is counted, so the tests above can
/// tell that teardown no longer gets there.
fn smoke_fallback_wait_completes_and_is_counted() -> TestResult {
    let before = crate::handlers::fallback_waits();
    if crate::handlers::poll_io_to_completion(ThirdTime(0)) != Some(7) {
        return TestResult::Fail("a pending wait with no task was abandoned");
    }
    if crate::handlers::fallback_waits() != before + 1 {
        return TestResult::Fail("a wait with no task to park was not counted once");
    }
    if crate::handlers::poll_io_to_completion(core::future::ready(1u8)) != Some(1)
        || crate::handlers::fallback_waits() != before + 1
    {
        return TestResult::Fail("a wait that completed at once was counted as a fallback");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_fallback_wait_completes_and_is_counted
);

static SIBLING_TICKS: AtomicUsize = AtomicUsize::new(0);
static FLUSH_DONE: AtomicBool = AtomicBool::new(false);
static TICKS_AT_WRITE: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static WRITES_SEEN: AtomicUsize = AtomicUsize::new(0);

fn record_sibling_ticks() {
    let write = WRITES_SEEN.fetch_add(1, Ordering::AcqRel);
    if write < TICKS_AT_WRITE.len() {
        TICKS_AT_WRITE[write].store(SIBLING_TICKS.load(Ordering::Acquire), Ordering::Release);
    }
}

/// A task that only counts how often it gets to run.
async fn sibling() {
    while !FLUSH_DONE.load(Ordering::Acquire) {
        SIBLING_TICKS.fetch_add(1, Ordering::AcqRel);
        narf_scheduler::yield_now().await;
    }
}

/// Dirty `batches` batches of unmapped pages and arm the per-write probe.
fn long_flush(fixture: &mut Fixture, batches: usize) -> bool {
    let count = batches * BATCH_PAGES;
    let Some(pages) = fixture.map(0, count) else {
        return false;
    };
    for phys in &pages {
        store_bytes(*phys, 0, b"dirty");
    }
    fixture.unmap(&pages);
    SIBLING_TICKS.store(0, Ordering::Release);
    WRITES_SEEN.store(0, Ordering::Release);
    FLUSH_DONE.store(false, Ordering::Release);
    fixture
        .store
        .on_write
        .store(record_sibling_ticks as usize, Ordering::Release);
    true
}

fn sibling_ran_between_every_batch(batches: usize) -> bool {
    WRITES_SEEN.load(Ordering::Acquire) == batches
        && (1..batches).all(|write| {
            TICKS_AT_WRITE[write].load(Ordering::Acquire)
                > TICKS_AT_WRITE[write - 1].load(Ordering::Acquire)
        })
}

/// The writeback task between two batches of a long flush: a task queued on
/// the same CPU runs. Each batch is one filesystem operation that completes
/// inside one poll, so without the scheduling point the whole flush would
/// be a single uninterrupted run.
fn smoke_flusher_yields_between_batches() -> TestResult {
    const BATCHES: usize = 3;
    let mut fixture = Fixture::new(BATCHES * BATCH_PAGES);
    if !long_flush(&mut fixture, BATCHES) {
        return TestResult::Fail("could not map the test file");
    }
    // An executor with nothing else on it, as every test that drains one
    // starts: the harness boot leaves long-lived tasks queued.
    narf_scheduler::__reset_queues_for_test();
    // Both spawned the default way: pinned to the boot CPU.
    narf_scheduler::spawn(sibling());
    narf_scheduler::spawn(async {
        background_pass().await;
        FLUSH_DONE.store(true, Ordering::Release);
    });
    narf_scheduler::run_until_empty();
    if !FLUSH_DONE.load(Ordering::Acquire) {
        return TestResult::Fail("the background pass did not complete");
    }
    if !sibling_ran_between_every_batch(BATCHES) {
        return TestResult::Fail("a task on the flusher's CPU did not run between two batches");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/writeback", smoke_flusher_yields_between_batches);

/// The same for a flush running in its caller — `fsync`, `sync`, `msync` —
/// on that task's own kernel stack. Nothing there returns `Pending`, so the
/// task has to give the CPU up itself; a sibling on its CPU runs between
/// every two batches.
fn smoke_fsync_yields_between_batches() -> TestResult {
    const BATCHES: usize = 3;
    let mut fixture = Fixture::new(BATCHES * BATCH_PAGES);
    if !long_flush(&mut fixture, BATCHES) {
        return TestResult::Fail("could not map the test file");
    }
    static FSYNC_OK: AtomicBool = AtomicBool::new(false);
    FSYNC_OK.store(false, Ordering::Release);
    let ops = Arc::clone(fixture.ops());
    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(sibling());
    narf_scheduler::spawn_stackful(async move {
        FSYNC_OK.store(
            super::super::flush_current_file(&ops).is_ok(),
            Ordering::Release,
        );
        FLUSH_DONE.store(true, Ordering::Release);
    });
    narf_scheduler::run_until_empty();
    if !FLUSH_DONE.load(Ordering::Acquire) || !FSYNC_OK.load(Ordering::Acquire) {
        return TestResult::Fail("the in-caller flush did not complete");
    }
    if !sibling_ran_between_every_batch(BATCHES) {
        return TestResult::Fail("fsync ran its whole flush without letting a sibling task run");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/writeback", smoke_fsync_yields_between_batches);

/// A kernel read of the file sees a store a mapping has made and writeback
/// has not written — and only that: where the page agrees with what it last
/// saw of the file, the filesystem's bytes stand.
fn smoke_reads_see_unwritten_mapped_stores() -> TestResult {
    let mut fixture = Fixture::new(2);
    let Some(pages) = fixture.map(0, 2) else {
        return TestResult::Fail("could not map the test file");
    };
    // "across the page": six bytes at the end of page 0, nine in page 1.
    store_bytes(pages[0], 4090, b"across");
    store_bytes(pages[1], 0, b" the page");
    // The file changes behind the cache's back at a byte no mapping stored
    // to: the filesystem knows better there.
    fixture.store.bytes.lock()[100] = 0x5A;

    let mut read = vec![0u8; 8192];
    if run(fixture.ops().read(0, &mut read)) != Some(Ok(8192)) {
        return TestResult::Fail("read of the test file failed");
    }
    overlay_dirty(fixture.ops(), 0, &mut read, read_epoch());
    if read[4090..4105] != *b"across the page" {
        return TestResult::Fail("a read did not see a mapped store that is not written back");
    }
    if read[100] != 0x5A {
        return TestResult::Fail("the overlay replaced bytes no mapping had changed");
    }
    // An unaligned window inside the second page.
    let mut tail = vec![0u8; 5];
    overlay_dirty(fixture.ops(), 4100, &mut tail, read_epoch());
    if tail != *b" page" {
        return TestResult::Fail("the overlay misplaced bytes in an unaligned read");
    }

    // Still true after the last unmap, and once written the file says so
    // itself.
    fixture.unmap(&pages);
    let mut again = vec![0u8; 15];
    overlay_dirty(fixture.ops(), 4090, &mut again, read_epoch());
    if again != *b"across the page" {
        return TestResult::Fail("a read after munmap lost the unwritten store");
    }
    if run(background_pass()).is_none() || fixture.file_bytes(4090, 15) != *b"across the page" {
        return TestResult::Fail("the store did not reach the file");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_reads_see_unwritten_mapped_stores
);

/// A second `MAP_SHARED` mapping made while the first one's store is still
/// unwritten gets that page — not a fresh read of the stale file — and the
/// page stops being an unmapped one.
fn smoke_second_mapping_adopts_the_unwritten_page() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(first) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(first[0], 0, b"not on the file yet");
    fixture.unmap(&first);
    if fixture.idle_dirty() != 1 {
        return TestResult::Fail("an unmapped dirty page was not listed");
    }
    let Some(second) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file again");
    };
    if second[0] != first[0] || page_bytes(second[0], 0, 19) != *b"not on the file yet" {
        return TestResult::Fail("a second mapping did not get the unwritten page");
    }
    if fixture.idle_dirty() != 0 || fixture.cached(0) != Some((true, false)) {
        return TestResult::Fail("a page mapped again stayed listed as unmapped");
    }
    if !fixture.log().is_empty() {
        return TestResult::Fail("mapping the file again wrote to it");
    }
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.file_bytes(0, 19) != *b"not on the file yet"
    {
        return TestResult::Fail("the adopted page's store did not reach the file");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_second_mapping_adopts_the_unwritten_page
);

/// Two address spaces that map the same dirty pages are torn down at the
/// same time, before anything has been written. On the old code each
/// teardown captured a CPU: the first writing page by page, the second
/// busy-polling for the filesystem lock the first held. Neither writes or
/// waits now, the pages are handed to the file once, and they are written
/// once.
fn smoke_two_teardowns_at_once_write_nothing() -> TestResult {
    const PAGES: usize = 6;
    let mut fixture = Fixture::new(PAGES);
    fixture.store.mode.store(NEVER, Ordering::Release);
    let (Some(first), Some(second)) = (fixture.map(0, PAGES), fixture.map(0, PAGES)) else {
        return TestResult::Fail("could not map the test file twice");
    };
    if first != second {
        return TestResult::Fail("two mappings of one file did not share its pages");
    }
    for (index, phys) in first.iter().enumerate() {
        store_bytes(*phys, 32, &[0xA0 + index as u8; 32]);
    }
    let waits_before = crate::handlers::fallback_waits();

    // The two teardowns interleaved page by page, as two CPUs would.
    for index in 0..PAGES {
        fixture.unmap(&first[index..index + 1]);
        fixture.unmap(&second[index..index + 1]);
    }
    drop_address_space(TEST_SPACE);
    drop_address_space(TEST_SPACE - 1);

    if fixture.store.attempts.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("one of two concurrent teardowns wrote a dirty page");
    }
    if crate::handlers::fallback_waits() != waits_before {
        return TestResult::Fail("one of two concurrent teardowns waited on the filesystem");
    }
    if fixture.idle_dirty() != PAGES {
        return TestResult::Fail("two teardowns did not leave each dirty page listed once");
    }
    fixture.store.mode.store(WRITES, Ordering::Release);
    if run(background_pass()).is_none() || fixture.log() != [(0, PAGES * 4096)] {
        return TestResult::Fail("pages left by two teardowns were not written exactly once");
    }
    for index in 0..PAGES {
        if fixture.file_bytes(index * 4096 + 32, 32) != [0xA0 + index as u8; 32] {
            return TestResult::Fail("a store made before the teardowns never reached the file");
        }
    }
    if run(background_pass()).is_none() || fixture.log().len() != 1 {
        return TestResult::Fail("a page already written was written again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_two_teardowns_at_once_write_nothing
);

/// `(page comparisons, evictions)` made while `PROBE` pages are faulted in
/// and unmapped through a read-only mapping and as many through a writable
/// one, with `resident` other pages already in the cache.
fn fault_and_unmap_work(resident: usize) -> Option<(u64, u64)> {
    const PROBE: usize = 32;
    let mut cache = Fixture::new(resident);
    cache.map(0, resident)?;
    let mut read_only = Fixture::new(PROBE);
    read_only.read_only = true;
    let mut writable = Fixture::new(PROBE);
    let compares = PAGE_COMPARES.load(Ordering::Relaxed);
    let evictions = EVICTIONS.load(Ordering::Relaxed);

    let pages = read_only.map(0, PROBE)?;
    read_only.unmap(&pages);
    let pages = writable.map(0, PROBE)?;
    for phys in &pages {
        store_bytes(*phys, 0, b"dirty");
    }
    writable.unmap(&pages);

    Some((
        PAGE_COMPARES.load(Ordering::Relaxed) - compares,
        EVICTIONS.load(Ordering::Relaxed) - evictions,
    ))
}

/// A fault's publication and an unmap cost the same however full the cache
/// is. With the cache past its retention cap, every publication used to
/// walk the whole cache under the cache lock, comparing each unmapped page
/// with its clean copy, and every unmap compared the page it released:
/// 65,536 first touches of a clean 256 MiB mapping took 70 s. Now neither
/// path compares anything — whether a page may be dirty is recorded — and
/// eviction takes at most one page off a list per page released.
fn smoke_fault_and_unmap_cost_does_not_grow_with_the_cache() -> TestResult {
    const PROBE: u64 = 32;
    let cap = super::super::MAX_RETAINED_SHARED_FILE_PAGES;
    let (Some(small), Some(large)) = (
        fault_and_unmap_work(cap + 64),
        fault_and_unmap_work(3 * cap),
    ) else {
        return TestResult::Skip("frame allocator drained");
    };
    if small.0 != 0 || large.0 != 0 {
        return TestResult::Fail("a fault or an unmap compared page contents");
    }
    if small.1 > PROBE || large.1 > PROBE {
        return TestResult::Fail("faulting and unmapping evicted more pages than it released");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_fault_and_unmap_cost_does_not_grow_with_the_cache
);

/// A page only read-only mappings have held is clean by record: its last
/// unmap lists it for reuse without comparing it, and writeback never
/// looks at it. A page a writable mapping has held is writeback's to
/// check, and is found clean there — outside every lock — if nothing was
/// stored.
fn smoke_dirtiness_is_recorded_not_compared_at_unmap() -> TestResult {
    let mut read_only = Fixture::new(2);
    read_only.read_only = true;
    let Some(pages) = read_only.map(0, 2) else {
        return TestResult::Fail("could not map the test file");
    };
    let compares = PAGE_COMPARES.load(Ordering::Relaxed);
    read_only.unmap(&pages);
    if read_only.idle_dirty() != 0 || read_only.cached(0) != Some((false, false)) {
        return TestResult::Fail("a page only mapped read-only was listed for writeback");
    }

    let mut writable = Fixture::new(2);
    let Some(pages) = writable.map(0, 2) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(pages[1], 0, b"stored");
    writable.unmap(&pages);
    if PAGE_COMPARES.load(Ordering::Relaxed) != compares {
        return TestResult::Fail("an unmap compared page contents");
    }
    if writable.idle_dirty() != 2 {
        return TestResult::Fail("pages of a writable mapping were not left for writeback");
    }
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    if writable.log() != [(4096, 4096)] || writable.idle_dirty() != 0 {
        return TestResult::Fail("writeback did not write exactly the page that was stored to");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_dirtiness_is_recorded_not_compared_at_unmap
);

/// A file `len` bytes long, mapped in full (`len < 4096`).
fn short_file(len: usize) -> Option<(Fixture, PhysAddr)> {
    let mut fixture = Fixture::new(1);
    fixture.store.bytes.lock().truncate(len);
    let page = fixture.map(0, 1)?[0];
    Some((fixture, page))
}

/// Read the file through the filesystem node and then through the read
/// overlay, as `read(2)` does: the bytes a reader gets.
fn read2(fixture: &Fixture, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let n = run(fixture.ops().read(0, &mut buf))?.ok()?;
    buf.truncate(n);
    overlay_dirty(fixture.ops(), 0, &mut buf, read_epoch());
    Some(buf)
}

/// Writing back the file's last page writes it only up to EOF, and what a
/// mapping stored past EOF is cleared from the page (`folio_zero_segment`).
fn smoke_writeback_clears_stores_past_eof() -> TestResult {
    let Some((fixture, page)) = short_file(100) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(page, 10, b"in");
    store_bytes(page, 200, b"GARBAGE");
    if super::super::flush_current_file(fixture.ops()).is_err() {
        return TestResult::Fail("fsync of the mapped file failed");
    }
    if fixture.store.bytes.lock().len() != 100 {
        return TestResult::Fail("writeback of the last page extended the file");
    }
    if fixture.file_bytes(10, 2) != *b"in" {
        return TestResult::Fail("the store inside EOF did not reach the file");
    }
    if page_bytes(page, 200, 7) != [0; 7] {
        return TestResult::Fail("a store past EOF survived writeback in the mapped page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_writeback_clears_stores_past_eof
);

/// The checks both extension tests share: past the old EOF the file reads
/// zeros through `read(2)`, through the mapping and from the file node,
/// before and after writeback.
fn zeros_past_old_eof(fixture: &Fixture, page: PhysAddr) -> Result<(), &'static str> {
    if page_bytes(page, 200, 7) != [0; 7] {
        return Err("the mapping still shows a store made past the old EOF");
    }
    match read2(fixture, 4096) {
        Some(bytes) if bytes.len() > 207 && bytes[200..207] == [0; 7] => {}
        _ => return Err("read(2) returned a store made past the old EOF"),
    }
    if super::super::flush_current_file(fixture.ops()).is_err() {
        return Err("fsync of the mapped file failed");
    }
    if fixture.file_bytes(200, 7) != [0; 7] {
        return Err("a store made past the old EOF reached the file");
    }
    if fixture.file_bytes(10, 2) != *b"in" {
        return Err("the store inside the old EOF was lost");
    }
    Ok(())
}

/// `ftruncate` up over bytes a mapping stored past EOF: they read as zeros
/// everywhere (`pagecache_isize_extended` / `truncate_setsize`).
fn smoke_ftruncate_up_zeroes_stores_past_eof() -> TestResult {
    let Some((fixture, page)) = short_file(100) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(page, 10, b"in");
    store_bytes(page, 200, b"GARBAGE");
    let grown = size_change_serialized(fixture.ops(), || run(fixture.ops().truncate(4096)));
    if grown != Some(Ok(())) {
        return TestResult::Fail("the extending truncate failed");
    }
    match zeros_past_old_eof(&fixture, page) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "userspace/writeback",
    smoke_ftruncate_up_zeroes_stores_past_eof
);

/// A `write(2)` that starts past EOF, over bytes a mapping stored there:
/// the gap reads as zeros everywhere, the written bytes as written.
fn smoke_write_past_eof_zeroes_stores_in_the_gap() -> TestResult {
    let Some((fixture, page)) = short_file(100) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(page, 10, b"in");
    store_bytes(page, 200, b"GARBAGE");
    // The handler path: killable write, then the cache is told.
    let stamp = write_stamp();
    let mut payload = b"W".to_vec();
    let wrote = crate::killable_wait::write(fixture.ops(), 300, &mut payload);
    if !matches!(wrote, Ok(Some(Ok(1)))) {
        return TestResult::Fail("the extending write failed");
    }
    note_file_written(fixture.ops(), 300, b"W", stamp);
    if let Err(why) = zeros_past_old_eof(&fixture, page) {
        return TestResult::Fail(why);
    }
    if fixture.file_bytes(300, 1) != *b"W" || page_bytes(page, 300, 1) != *b"W" {
        return TestResult::Fail("the extending write's own bytes were lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_write_past_eof_zeroes_stores_in_the_gap
);

/// One writer's life as a real user task: it holds pages of a writable
/// shared mapping, stores through them, unmaps them and exits — no msync,
/// no fsync, no kick. Only the flusher's own scheduling (its first pass and
/// its timer) is left to write the pages.
async fn writer_task(pages: Vec<PhysAddr>, text: &'static [u8]) {
    // What the first writable shared mapping does.
    ensure_flusher();
    narf_scheduler::yield_now().await;
    for phys in &pages {
        store_bytes(*phys, 0, text);
        release_shared_file_page(phys.raw());
    }
}

/// Run one writer as a real user task and the executor until everything —
/// writer, flusher — has finished. Returns whether its stores reached the
/// file (read from the file node, not through the overlay), and how many
/// times a flusher was started.
fn one_writer(pid: u64, text: &'static [u8]) -> Result<(bool, u64), &'static str> {
    const PAGES: usize = 2;
    let mut fixture = Fixture::new(PAGES);
    let pages = fixture.map(0, PAGES).ok_or("could not map the test file")?;
    // The task owns these mapping references now.
    fixture.held.clear();
    // SAFETY: kernel tests run with paging enabled; a fresh inactive root.
    let mm = unsafe { narf_memory::AddressSpace::new_for_user() }
        .map_err(|_| "AddressSpace::new_for_user failed")?;
    let starts = FLUSHER_STARTS.load(Ordering::Relaxed);
    narf_scheduler::spawn_user(
        narf_scheduler::TaskId(pid),
        writer_task(pages, text),
        narf_scheduler::TaskSpec::unthrottled(),
        Arc::new(mm),
    );
    narf_scheduler::run_until_empty();
    crate::task::release_task(pid);
    let written = (0..PAGES).all(|page| fixture.file_bytes(page * 4096, text.len()) == text)
        && fixture.idle_dirty() == 0;
    Ok((written, FLUSHER_STARTS.load(Ordering::Relaxed) - starts))
}

/// The flusher under real user tasks, with nothing calling it by hand: the
/// first writer starts it, it writes what that writer left when it exited,
/// it goes when no user task is left, and the next writer starts another.
///
/// SIGKILL of the writer is not run here: delivering a fatal signal needs a
/// real user program in this harness. A killed task ends through the same
/// slot drop and address-space teardown as this one's exit, which is what
/// hands its pages to the flusher.
fn smoke_flusher_writes_for_real_user_tasks() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    if FLUSHER_STARTED.load(Ordering::Acquire) {
        return TestResult::Fail("a dropped flusher left its running flag set");
    }
    // The timer path within a test's patience; the logic is unchanged.
    WRITEBACK_INTERVAL_OVERRIDE_MS.store(20, Ordering::Relaxed);
    let passes = PASSES.load(Ordering::Relaxed);
    let first = one_writer(0x5742_1000, b"first writer");
    let flag_after_first = FLUSHER_STARTED.load(Ordering::Acquire);
    let second = one_writer(0x5742_1001, b"second writer");
    WRITEBACK_INTERVAL_OVERRIDE_MS.store(u64::MAX, Ordering::Relaxed);
    let (first, second) = match (first, second) {
        (Ok(first), Ok(second)) => (first, second),
        (Err(why), _) | (_, Err(why)) => return TestResult::Fail(why),
    };
    if PASSES.load(Ordering::Relaxed) == passes {
        return TestResult::Fail("no flusher pass ran");
    }
    if !first.0 {
        return TestResult::Fail("an exited writer's stores never reached the file");
    }
    if first.1 != 1 {
        return TestResult::Fail("the first writer did not start exactly one flusher");
    }
    if flag_after_first {
        return TestResult::Fail("the flusher did not go when no user task was left");
    }
    if !second.0 || second.1 != 1 {
        return TestResult::Fail("the next writer did not get a new flusher of its own");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_flusher_writes_for_real_user_tasks
);

/// Review item 1, the out-of-lock case: an unmapped dirty page; a write
/// that does not take the file lock (AIO, a splice sink) samples its stamp;
/// a batch that copied the page before that write puts the older bytes on
/// the file after it. Completing, the batch must not settle the page — on a
/// filesystem without a cache generation that freed it, on one with a
/// generation it listed it for eviction — or the write's report finds no
/// page to tell, and the older bytes stay on the file for good.
fn smoke_out_of_lock_write_racing_a_batch_keeps_its_page() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    let page = pages[0];
    store_bytes(page, 0, b"mapped store");
    fixture.unmap(&pages);
    let Some((entry, ops)) = fixture.entry() else {
        return TestResult::Fail("a file with an unwritten page has no cache entry");
    };
    fixture.store.mode.store(GATED, Ordering::Release);
    let mut cx = Context::from_waker(Waker::noop());
    let stamp;
    {
        let mut budget = usize::MAX;
        let mut batch = core::pin::pin!(write_range(
            &entry,
            &ops,
            (0, u64::MAX),
            Plan::background(Select::Idle),
            &mut budget,
        ));
        if batch.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("the gated batch did not stop in its write");
        }
        // The out-of-lock write begins, and reaches the file.
        stamp = write_stamp();
        fixture.store.bytes.lock()[100..108].copy_from_slice(b"WRITE(2)");
        // The batch's older image of the whole page lands after it.
        fixture.store.gate_open.store(true, Ordering::Release);
        if !matches!(batch.as_mut().poll(&mut cx), Poll::Ready(Ok(_))) {
            return TestResult::Fail("the released batch did not complete");
        }
    }
    fixture.store.mode.store(WRITES, Ordering::Release);
    if fixture.cached(0) != Some((false, true)) {
        return TestResult::Fail(
            "a batch settled a page an out-of-lock write still had to report to",
        );
    }
    note_file_written(fixture.ops(), 100, b"WRITE(2)", stamp);
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.file_bytes(100, 8) != *b"WRITE(2)"
        || fixture.file_bytes(0, 12) != *b"mapped store"
    {
        return TestResult::Fail("the out-of-lock write was lost to the older batch image");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_out_of_lock_write_racing_a_batch_keeps_its_page
);

/// The guard of item 1 does not hold pages for ever under a writer that
/// never pauses: a write that began after a page's last batch does not
/// keep that page from settling.
fn smoke_newer_writers_do_not_hold_pages() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(pages[0], 0, b"settle me");
    fixture.unmap(&pages);
    let older = write_stamp();
    if super::super::flush_current_file(fixture.ops()).is_err() {
        return TestResult::Fail("fsync of the mapped file failed");
    }
    if fixture.cached(0) != Some((false, true)) {
        return TestResult::Fail("a page was settled while an older writer was in flight");
    }
    // A stream of writers: each new one starts before the last ends.
    let newer = write_stamp();
    drop(older);
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    let settled = fixture.cached(0) == Some((false, false));
    drop(newer);
    if !settled {
        return TestResult::Fail("a writer newer than the page's last batch kept it unsettled");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/writeback", smoke_newer_writers_do_not_hold_pages);

/// Review item 1, the `write(2)` path: while a batch of the file is in
/// progress, a write waits for the file lock — nothing of it reaches the
/// file or the cache — and then writes and reports in one step.
fn smoke_write2_waits_for_a_batch_in_flight() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    let Some((entry, _)) = fixture.entry() else {
        return TestResult::Fail("a mapped file has no cache entry");
    };
    let Some(batch_holds) = entry.lock.try_lock() else {
        return TestResult::Fail("the file's writeback lock was not free");
    };
    let mut cx = Context::from_waker(Waker::noop());
    let mut write = core::pin::pin!(write_and_note(
        Arc::clone(fixture.ops()),
        64,
        b"locked write".to_vec()
    ));
    if write.as_mut().poll(&mut cx).is_ready()
        || fixture.store.attempts.load(Ordering::Relaxed) != 0
    {
        return TestResult::Fail("a write(2) ran while a batch held the file");
    }
    drop(batch_holds);
    let done = match write.as_mut().poll(&mut cx) {
        Poll::Ready((result, _)) => result,
        Poll::Pending => return TestResult::Fail("the write did not run once the batch let go"),
    };
    if done != Ok(12)
        || fixture.file_bytes(64, 12) != *b"locked write"
        || page_bytes(pages[0], 64, 12) != *b"locked write"
    {
        return TestResult::Fail("the locked write did not reach both the file and the page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_write2_waits_for_a_batch_in_flight
);

/// Review item 2: with no memory to do a batch, `fsync` says so — it does
/// not return success with the pages unwritten — and the pages stay dirty
/// for the next attempt.
fn smoke_fsync_reports_no_memory_and_keeps_pages() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(pages[0], 0, b"not yet");
    fixture.unmap(&pages);
    FAIL_RESERVE.store(true, Ordering::Release);
    let starved = super::super::flush_current_file(fixture.ops());
    FAIL_RESERVE.store(false, Ordering::Release);
    if starved != Err(FsError::OutOfMemory) {
        return TestResult::Fail("fsync with no memory for a batch did not report ENOMEM");
    }
    if fixture.cached(0) != Some((false, true)) || !fixture.log().is_empty() {
        return TestResult::Fail("a batch with no memory touched the page or the file");
    }
    if super::super::flush_current_file(fixture.ops()).is_err()
        || fixture.file_bytes(0, 7) != *b"not yet"
    {
        return TestResult::Fail("the page was not written once memory was back");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_fsync_reports_no_memory_and_keeps_pages
);

/// Review item 3: the release hook memory calls under its locks never
/// drops a file. A read-only page whose open has gone is released; the
/// entry that held the file open is parked, and dropped at the next point
/// that holds no lock.
fn smoke_release_hook_never_drops_a_file() -> TestResult {
    let mut fixture = Fixture::new(1);
    fixture.read_only = true;
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    fixture.ops = None;
    fixture.unmap(&pages);
    if fixture.store.dropped.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("the release hook dropped the file's last reference");
    }
    super::super::release_deferred_slots();
    if fixture.store.dropped.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("a parked entry was never dropped");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/writeback", smoke_release_hook_never_drops_a_file);

/// Review item 5: a read that a batch overtakes. The page is stored to,
/// the read fetches the file's older bytes, a batch writes the page and
/// calls it clean, and only then is the read overlaid: it must still
/// return the store.
fn smoke_read_overtaken_by_a_batch_sees_the_store() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    store_bytes(pages[0], 0, b"stored before the read");
    let epoch = read_epoch();
    let mut read = vec![0u8; 22];
    if run(fixture.ops().read(0, &mut read)) != Some(Ok(22)) {
        return TestResult::Fail("read of the test file failed");
    }
    if super::super::flush_current_file(fixture.ops()).is_err() {
        return TestResult::Fail("fsync of the mapped file failed");
    }
    overlay_dirty(fixture.ops(), 0, &mut read, epoch);
    if read != *b"stored before the read" {
        return TestResult::Fail("a read overtaken by a batch missed a store made before it");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_read_overtaken_by_a_batch_sees_the_store
);

/// Review item 7: `syncfs` (`sync_all_files` for one device) reports a
/// mapped page it could not write, and an unmount of that filesystem
/// leaves nothing of it in the cache: no entry holding a file open, no
/// page for a later writeback to send to the unmounted volume. While a page
/// is still mapped, the unmount would be EBUSY.
fn smoke_syncfs_reports_and_unmount_forgets_the_device() -> TestResult {
    let mut fixture = Fixture::new(1);
    let Some(pages) = fixture.map(0, 1) else {
        return TestResult::Fail("could not map the test file");
    };
    let device = fixture.identity.device;
    store_bytes(pages[0], 0, b"cannot be written");
    if !device_mapped(device) {
        return TestResult::Fail("a mapped file's filesystem did not count as busy");
    }
    fixture.unmap(&pages);
    if device_mapped(device) {
        return TestResult::Fail("an unmapped file's filesystem still counted as busy");
    }
    fixture.store.mode.store(IO_ERROR, Ordering::Release);
    if !matches!(sync_all_files(Some(device)), Err(FsError::Io(_))) {
        return TestResult::Fail("syncfs did not report a mapped page it could not write");
    }
    fixture.ops = None;
    forget_device(device);
    super::super::release_deferred_slots();
    if fixture.cached(0).is_some() {
        return TestResult::Fail("a page of an unmounted filesystem stayed cached");
    }
    if fixture.store.dropped.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("the cache kept a file of an unmounted filesystem open");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_syncfs_reports_and_unmount_forgets_the_device
);

/// What `read(2)` of a file with no cached page costs the cache: nothing
/// past one lock-free check per call. A 64 MiB file is read in 1 MiB calls
/// through the same helper `read`/`pread64`/`readv` use, while another file
/// does have a cache entry (so the "no entries at all" shortcut does not
/// apply). No call may take the cache lock or compute the file's full
/// identity (`inode_attrs()`, an inode lock and copy on btrfs).
/// A 64 MiB file that is the byte 0x5A throughout, held nowhere: the kernel
/// heap has no room for 64 MiB in one piece.
struct PatternFile;

impl FileOps for PatternFile {
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let left = (64u64 << 20).saturating_sub(offset) as usize;
            let n = left.min(buf.len());
            buf[..n].fill(0x5A);
            Ok(n)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 64 << 20,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

fn smoke_read_of_an_unmapped_file_costs_the_cache_nothing() -> TestResult {
    const LEN: usize = 64 << 20;
    const CALL: usize = 1 << 20;
    // Another file with a cache entry.
    let mut mapped = Fixture::new(1);
    if mapped.map(0, 1).is_none() {
        return TestResult::Fail("could not map the other test file");
    }
    let file: Arc<dyn FileOps> = Arc::new(PatternFile);
    if anchor_bucket(file.mmap_backing_identity()).load(Ordering::Acquire) != 0 {
        // The lock-free filter is shared by hash; this file landed in a
        // bucket another entry uses, which a later run will not repeat.
        return TestResult::Skip("the unmapped file's filter bucket is in use");
    }
    let locks = OVERLAY_LOCKS.load(Ordering::Relaxed);
    let lookups = IDENTITY_LOOKUPS.load(Ordering::Relaxed);
    let mut staging = vec![0u8; CALL];
    let mut offset = 0usize;
    while offset < LEN {
        match crate::killable_wait::read(
            &file,
            offset as u64,
            &mut staging,
            CALL,
            narf_filesystem::ReadOptions::default(),
        ) {
            Ok(Some(Ok(n))) if n == CALL => offset += n,
            _ => return TestResult::Fail("a 1 MiB read of the unmapped file failed"),
        }
    }
    let locks = OVERLAY_LOCKS.load(Ordering::Relaxed) - locks;
    let lookups = IDENTITY_LOOKUPS.load(Ordering::Relaxed) - lookups;
    if staging.iter().any(|byte| *byte != 0x5A) {
        return TestResult::Fail("the reads returned the wrong bytes");
    }
    if locks != 0 {
        return TestResult::Fail("reading an unmapped file took the cache lock");
    }
    if lookups != 0 {
        return TestResult::Fail("reading an unmapped file computed its full identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_read_of_an_unmapped_file_costs_the_cache_nothing
);

static STORM_PAGES: IrqSafeSpinLock<Vec<PhysAddr>> = IrqSafeSpinLock::new(Vec::new());
static STORM_STORES: AtomicU64 = AtomicU64::new(0);

/// Other threads dirtying the mapping as fast as they can: every page gets a
/// new store each time the filesystem is entered.
fn storm() {
    let round = STORM_STORES.fetch_add(1, Ordering::AcqRel) + 1;
    for phys in STORM_PAGES.lock().iter() {
        store_bytes(*phys, 1024, &round.to_le_bytes());
    }
}

/// `msync(MS_SYNC)` while other threads keep dirtying every page of the
/// mapping: it returns, having written each page at most once — never
/// chasing pages redirtied behind it — and every byte stored before it
/// started is on the file.
fn smoke_msync_under_a_store_storm_returns() -> TestResult {
    const PAGES: usize = 3 * BATCH_PAGES / 2;
    let mut fixture = Fixture::new(PAGES);
    let Some(pages) = fixture.map(0, PAGES) else {
        return TestResult::Fail("could not map the test file");
    };
    for (index, phys) in pages.iter().enumerate() {
        store_bytes(*phys, 0, &(index as u64 + 1).to_le_bytes());
    }
    *STORM_PAGES.lock() = pages.clone();
    fixture
        .store
        .on_write
        .store(storm as usize, Ordering::Release);
    let synced = super::super::flush_current_file(fixture.ops());
    fixture.store.on_write.store(0, Ordering::Release);
    STORM_PAGES.lock().clear();
    if synced.is_err() {
        return TestResult::Fail("msync under a store storm failed");
    }
    let written: usize = fixture.log().iter().map(|(_, len)| len / 4096).sum();
    if written > PAGES {
        return TestResult::Fail("msync wrote a page more than once, chasing redirtied pages");
    }
    for index in 0..PAGES {
        if fixture.file_bytes(index * 4096, 8) != (index as u64 + 1).to_le_bytes() {
            return TestResult::Fail("a store made before msync did not reach the file");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_msync_under_a_store_storm_returns
);

/// The per-file lock is handed over in arrival order: a waiter that queued
/// first gets it when it is released, even if another caller polls first.
/// With the old mutex the later caller won and the woken waiter went to the
/// back of the queue, which starved `msync` and `ftruncate` behind a stream
/// of writers.
fn smoke_file_lock_serves_waiters_in_order() -> TestResult {
    let lock = FairLock::new();
    let mut cx = Context::from_waker(Waker::noop());
    let Some(holder) = lock.try_lock() else {
        return TestResult::Fail("a free lock could not be taken");
    };
    let mut first = core::pin::pin!(lock.lock());
    if first.as_mut().poll(&mut cx).is_ready() {
        return TestResult::Fail("a held lock was taken");
    }
    drop(holder);
    // A newcomer polls before the queued waiter gets to run.
    let mut newcomer = core::pin::pin!(lock.lock());
    if newcomer.as_mut().poll(&mut cx).is_ready() || lock.try_lock().is_some() {
        return TestResult::Fail("a newcomer jumped the queue");
    }
    let Poll::Ready(guard) = first.as_mut().poll(&mut cx) else {
        return TestResult::Fail("the first waiter was not handed the lock");
    };
    drop(guard);
    if newcomer.as_mut().poll(&mut cx).is_pending() {
        return TestResult::Fail("the second waiter was not served next");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_file_lock_serves_waiters_in_order
);

/// Everything the cache holds for `identity`: (pages, file entry, pages
/// listed idle-dirty).
fn held_for(identity: SharedFileIdentity) -> (usize, bool, usize) {
    let pages = SHARED_FILE_PAGES.lock();
    let cached = pages
        .by_file
        .range(key(identity, 0)..)
        .take_while(|(cached, _)| cached.file == identity)
        .count();
    let dirty = pages
        .idle_dirty
        .range(key(identity, 0)..)
        .take_while(|listed| listed.file == identity)
        .count();
    (cached, pages.files.contains_key(&identity), dirty)
}

/// Many files mapped, stored to, unmapped and their processes gone: once
/// the flusher has run, the cache holds nothing for them but clean pages
/// kept for reuse — no entry, no file kept open, no frame or record left
/// behind — and when reclaim asks, those go too. Each cached page costs its
/// frame and one 4 KiB clean image on the kernel heap; reclaim gives both
/// back.
fn smoke_cache_returns_to_baseline_and_shrinks_on_reclaim() -> TestResult {
    const FILES: usize = 8;
    const PAGES: usize = 4;
    let doomed = SHARED_FILE_PAGES.lock().doomed.len();
    let mut fixtures = Vec::new();
    for _ in 0..FILES {
        let mut fixture = Fixture::new(PAGES);
        let Some(pages) = fixture.map(0, PAGES) else {
            return TestResult::Fail("could not map a test file");
        };
        for phys in &pages {
            store_bytes(*phys, 0, b"cycle");
        }
        fixture.unmap(&pages);
        // The process is gone: nothing but the cache holds the file.
        fixture.ops = None;
        fixtures.push(fixture);
    }
    drop_address_space(TEST_SPACE);
    if run(background_pass()).is_none() {
        return TestResult::Fail("the background pass did not complete");
    }
    super::super::release_deferred_slots();
    for fixture in &fixtures {
        let (_, entry, dirty) = held_for(fixture.identity);
        if entry || dirty != 0 {
            return TestResult::Fail("written-back files left an entry or a listed page behind");
        }
        if fixture.store.dropped.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("the cache kept a written-back file open");
        }
        if fixture.file_bytes(0, 5) != *b"cycle" {
            return TestResult::Fail("a store never reached its file");
        }
    }
    if SHARED_FILE_PAGES.lock().doomed.len() != doomed {
        return TestResult::Fail("frames were left waiting on a batch that had ended");
    }
    // Reclaim asks for everything it can get.
    let counted = shrink_count();
    let freed = shrink_scan(usize::MAX);
    if freed < counted.min(FILES * PAGES * PAGES_PER_CACHED_PAGE) {
        return TestResult::Fail("reclaim freed less than the cache said it could");
    }
    for fixture in &fixtures {
        if held_for(fixture.identity).0 != 0 {
            return TestResult::Fail("reclaim left a clean unmapped page cached");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/writeback",
    smoke_cache_returns_to_baseline_and_shrinks_on_reclaim
);
