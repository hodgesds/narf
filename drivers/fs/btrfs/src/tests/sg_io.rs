//! The member I/O path ([`crate::bio`]): requests go to the device over the
//! caller's pages, concurrently, nothing held across the round trip.

use super::*;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use narf_block::{
    BlockCompletion, BlockDevice, BlockFeature, BlockRequest, CancelResult, LbaRange, SgRequest,
};
use narf_filesystem::FsInstance;

/// A device that answers every scatter-gather request `latency_ms` later
/// and counts how many it has in flight: a slow disk whose queue depth is
/// what the submitter makes of it.
#[derive(Debug)]
struct LatencyDevice {
    inner: Arc<narf_block::SyncBlock>,
    latency_ms: AtomicU64,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    requests: AtomicUsize,
}

impl LatencyDevice {
    fn new(inner: Arc<narf_block::SyncBlock>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            latency_ms: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
        })
    }
}

impl BlockDevice for LatencyDevice {
    fn logical_block_size(&self) -> u32 {
        self.inner.logical_block_size()
    }
    fn physical_block_size(&self) -> u32 {
        self.inner.physical_block_size()
    }
    fn capacity_blocks(&self) -> u64 {
        self.inner.capacity_blocks()
    }
    fn supports(&self, feature: BlockFeature) -> bool {
        self.inner.supports(feature)
    }
    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send {
        // Boxed so this device's futures are no larger than `SyncBlock`'s:
        // the volume's futures are instantiated for it too, and the frame
        // budget counts them.
        Box::pin(self.track(self.inner.submit(req)))
            as Pin<Box<dyn Future<Output = BlockCompletion> + Send + '_>>
    }
    fn flush(&self) -> impl Future<Output = ()> + Send {
        self.inner.flush()
    }
    fn flush_result(&self) -> impl Future<Output = Result<(), narf_block::BlockError>> + Send {
        self.inner.flush_result()
    }
    fn discard(&self, range: LbaRange) -> impl Future<Output = ()> + Send {
        self.inner.discard(range)
    }
    fn cancel(&self, tag: u64) -> impl Future<Output = CancelResult> + Send {
        self.inner.cancel(tag)
    }
    fn submit_sg(&self, req: SgRequest) -> impl Future<Output = BlockCompletion> + Send {
        Box::pin(self.track(self.inner.submit_sg(req)))
            as Pin<Box<dyn Future<Output = BlockCompletion> + Send + '_>>
    }
}

impl LatencyDevice {
    /// Count `io` in flight and delay it by the configured latency.
    async fn track(&self, io: impl Future<Output = BlockCompletion> + Send) -> BlockCompletion {
        self.requests.fetch_add(1, Ordering::AcqRel);
        let now = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        self.max_in_flight.fetch_max(now, Ordering::AcqRel);
        let latency = self.latency_ms.load(Ordering::Acquire);
        if latency > 0 {
            narf_time::sleep_ms(latency).await;
        }
        let completion = io.await;
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        completion
    }
}

type Vol = Arc<BtrfsVolume<LatencyDevice>>;
type Job = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

/// Run `jobs` on CPUs 1..=4 round-robin and wait for all of them.
fn run_parallel(jobs: Vec<Job>) -> Result<(), &'static str> {
    use core::fmt::Write as _;
    let done = Arc::new(AtomicU32::new(0));
    let failed = Arc::new(AtomicU32::new(0));
    let count = jobs.len() as u32;
    for (i, job) in jobs.into_iter().enumerate() {
        let (done, failed) = (done.clone(), failed.clone());
        narf_scheduler::spawn_stackful_pinned(
            async move {
                if let Err(error) = job.await {
                    let _ = writeln!(narf_console::Writer, "btrfs sg reader {i}: {error}");
                    failed.fetch_add(1, Ordering::AcqRel);
                }
                done.fetch_add(1, Ordering::AcqRel);
            },
            1 + (i as u32 % 4),
        );
    }
    let mut spins = 0u64;
    while done.load(Ordering::Acquire) < count && spins < 40_000_000_000 {
        core::hint::spin_loop();
        spins += 1;
    }
    if done.load(Ordering::Acquire) < count {
        return Err("the concurrent readers did not finish (deadlock?)");
    }
    if failed.load(Ordering::Acquire) != 0 {
        return Err("a concurrent reader failed");
    }
    Ok(())
}

fn mount_latency(dev: &Arc<LatencyDevice>) -> Result<Vol, &'static str> {
    poll_once(BtrfsVolume::mount(dev.clone(), DomainId::DRIVER_0))
        .and_then(|r| r.ok())
        .ok_or("fixture did not mount")
}

fn body(i: usize) -> Vec<u8> {
    format!("sg-reader-{i}:").into_bytes().repeat(8192)[..64 * 1024].to_vec()
}

fn read_whole(vol: &Vol, name: &str, want: &[u8]) -> Result<(), String> {
    let file = poll_once(vol.root().lookup_async(name))
        .and_then(|r| r.ok())
        .ok_or_else(|| format!("lookup {name}"))?;
    let mut buf = vec![0u8; want.len()];
    let n = poll_once(file.read(0, &mut buf))
        .and_then(|r| r.ok())
        .ok_or_else(|| format!("read {name}"))?;
    if n != want.len() || buf != want {
        return Err(format!("{name} read back wrong"));
    }
    Ok(())
}

async fn read_whole_async(vol: Vol, name: String, want: Vec<u8>) -> Result<(), String> {
    let file = vol
        .root()
        .lookup_async(&name)
        .await
        .map_err(|e| format!("lookup {name}: {e:?}"))?;
    let mut buf = vec![0u8; want.len()];
    let n = file
        .read(0, &mut buf)
        .await
        .map_err(|e| format!("read {name}: {e:?}"))?;
    if n != want.len() || buf != want {
        return Err(format!("{name} read back wrong"));
    }
    Ok(())
}

/// N readers of N different files on a slow device finish in about the time
/// of one of them, with more than one request at the device: a volume no
/// longer serialises its members' I/O behind one scratch buffer.
fn concurrent_readers_overlap() -> Result<(), &'static str> {
    const READERS: usize = 8;
    const LATENCY_MS: u64 = 5;
    if narf_lib::smp::cpu_count() < 5 {
        return Err("skip");
    }
    let sparse = writable_sparse(FIXTURE_BGT_SPARSE);
    let dev = LatencyDevice::new(narf_block::SyncBlock::new(
        sparse as Arc<dyn narf_block::BlockDeviceSync>,
    ));
    {
        let vol = mount_latency(&dev)?;
        for i in 0..=READERS {
            let file = poll_once(vol.root().create(&format!("f{i}")))
                .and_then(|r| r.ok())
                .ok_or("create failed")?;
            let want = body(i);
            if poll_once(file.write(0, &want)) != Some(Ok(want.len())) {
                return Err("write failed");
            }
        }
        if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return Err("sync failed");
        }
    }
    // A fresh mount: every node and extent below comes from the device.
    let vol = mount_latency(&dev)?;
    dev.latency_ms.store(LATENCY_MS, Ordering::Release);

    // One reader alone: the yardstick.
    let t0 = narf_time::monotonic_ns();
    read_whole(&vol, "f0", &body(0)).map_err(|_| "solo read failed")?;
    let solo_ns = narf_time::monotonic_ns() - t0;
    let solo_requests = dev.requests.swap(0, Ordering::AcqRel);
    dev.max_in_flight.store(0, Ordering::Release);

    // N readers together.
    let jobs: Vec<Job> = (1..=READERS)
        .map(|i| -> Job { Box::pin(read_whole_async(vol.clone(), format!("f{i}"), body(i))) })
        .collect();
    let t0 = narf_time::monotonic_ns();
    run_parallel(jobs)?;
    let together_ns = narf_time::monotonic_ns() - t0;
    let max_in_flight = dev.max_in_flight.load(Ordering::Acquire);
    let requests = dev.requests.load(Ordering::Acquire);
    dev.latency_ms.store(0, Ordering::Release);
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "btrfs-sg: solo {} ms ({} requests); {} readers {} ms ({} requests, max {} in flight)",
            solo_ns / 1_000_000,
            solo_requests,
            READERS,
            together_ns / 1_000_000,
            requests,
            max_in_flight
        );
    }
    if max_in_flight < 2 {
        return Err("the readers never had more than one request at the device");
    }
    // Serialised, the readers take READERS × solo; together they take about
    // one solo plus scheduling. Half the serialised time is a wide margin.
    if together_ns >= solo_ns * READERS as u64 / 2 {
        return Err("concurrent readers took as long as reading one after another");
    }
    Ok(())
}

fn smoke_btrfs_sg_concurrent_readers_overlap() -> TestResult {
    match concurrent_readers_overlap() {
        Ok(()) => TestResult::Pass,
        Err("skip") => TestResult::Skip("needs five CPUs"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/sg",
    smoke_btrfs_sg_concurrent_readers_overlap
);

/// Every request is one scatter-gather submission over the caller's range —
/// a 16 KiB node and a 4 KiB superblock are one request each on 512-byte
/// blocks — and the bounce path reads back exactly what was written at an
/// unaligned offset (read-modify-write of the enclosing blocks).
fn smoke_btrfs_sg_bounce_round_trip() -> TestResult {
    use narf_block::BlockDeviceSync;
    let total = 64u64 << 20;
    let sparse = blank_writable(total);
    let dev = LatencyDevice::new(narf_block::SyncBlock::new(
        sparse.clone() as Arc<dyn narf_block::BlockDeviceSync>
    ));
    let rmw = narf_lib::mutex::Mutex::new(());
    // An unaligned write: starts 100 bytes into LBA 2000, spills into 2001.
    let offset = 2000 * 512 + 100;
    let data: Vec<u8> = (0..600u32).map(|i| (i % 251) as u8).collect();
    let written = poll_once(crate::bio::write_exact_to(
        &*dev,
        512,
        DomainId::DRIVER_0,
        &rmw,
        total,
        offset,
        &data,
        false,
    ));
    if written != Some(Ok(())) {
        return TestResult::Fail("unaligned write failed");
    }
    if dev.requests.load(Ordering::Acquire) != 2 {
        return TestResult::Fail("an unaligned write is one read plus one write");
    }
    let mut back = vec![0u8; 600];
    let read = poll_once(crate::bio::read_exact_from(
        &*dev,
        512,
        DomainId::DRIVER_0,
        total,
        offset,
        &mut back,
        true,
    ));
    if read != Some(Ok(())) || back != data {
        return TestResult::Fail("unaligned read did not return the written bytes");
    }
    // The neighbouring bytes of both blocks are untouched (still zero).
    let mut block = vec![0u8; 1024];
    if sparse.read(2000, 2, &mut block).is_err()
        || block[..100].iter().any(|&b| b != 0)
        || block[700..].iter().any(|&b| b != 0)
    {
        return TestResult::Fail("read-modify-write disturbed the neighbouring bytes");
    }
    // An aligned 16 KiB write is ONE request.
    dev.requests.store(0, Ordering::Release);
    let node = vec![0xA5u8; 16384];
    let written = poll_once(crate::bio::write_exact_to(
        &*dev,
        512,
        DomainId::DRIVER_0,
        &rmw,
        total,
        1 << 20,
        &node,
        true,
    ));
    if written != Some(Ok(())) || dev.requests.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("an aligned node write is not one request");
    }
    let mut back = vec![0u8; 16384];
    dev.requests.store(0, Ordering::Release);
    let read = poll_once(crate::bio::read_exact_from(
        &*dev,
        512,
        DomainId::DRIVER_0,
        total,
        1 << 20,
        &mut back,
        false,
    ));
    if read != Some(Ok(())) || back != node || dev.requests.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("an aligned node read is not one request");
    }
    // Many requests, no growth: a payload's cap comes from a pool, not a new
    // object-table index per I/O (indices are never reused, and a cap per
    // request grew the table and the io registry by one slot each).
    let before = narf_capabilities::object_table::len();
    for i in 0..64u64 {
        let mut back = vec![0u8; 4096];
        let read = poll_once(crate::bio::read_exact_from(
            &*dev,
            512,
            DomainId::DRIVER_0,
            total,
            (1 << 20) + i * 4096,
            &mut back,
            i % 2 == 0,
        ));
        if read != Some(Ok(())) {
            return TestResult::Fail("a repeated read failed");
        }
    }
    if narf_capabilities::object_table::len() > before + 2 {
        return TestResult::Fail("every read minted a new capability index");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs/sg", smoke_btrfs_sg_bounce_round_trip);

/// A failing stripe fails the join only after every stripe finished, and the
/// window keeps the device busy: `join_all` is the commit's write-out.
fn smoke_btrfs_sg_join_waits_for_all() -> TestResult {
    let finished = Arc::new(AtomicUsize::new(0));
    let mut futs: Vec<crate::bio::IoFut<'static>> = Vec::new();
    for i in 0..6usize {
        let finished = finished.clone();
        futs.push(Box::pin(async move {
            // Later futures take longer, so the early error (i == 1) is
            // reported only once the slow ones are done too.
            narf_time::sleep_ms(1 + 2 * i as u64).await;
            finished.fetch_add(1, Ordering::AcqRel);
            if i == 1 {
                Err(FsError::Io(narf_block::BlockError::IOError))
            } else {
                Ok(())
            }
        }));
    }
    let result = poll_once(crate::bio::join_all(futs, 4));
    if result != Some(Err(FsError::Io(narf_block::BlockError::IOError))) {
        return TestResult::Fail("the first error was not the join's result");
    }
    if finished.load(Ordering::Acquire) != 6 {
        return TestResult::Fail("the join returned before every future finished");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs/sg", smoke_btrfs_sg_join_waits_for_all);
