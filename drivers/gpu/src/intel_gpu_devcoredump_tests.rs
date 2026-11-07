//! Native fixed-layout/capability/retention conversations. Opaque corrupt
//! firmware words never influence the bounded copies. Source contract: MIT
//! Linux b90c984d xe_devcoredump.c and xe_guc_{log,ct}.c snapshots.
use super::*;
mod vm_dump {
    include!("intel_gpu_vm_dump_tests.rs");
}
use crate::{
    intel_gpu_engine::{Engine, EngineSet},
    intel_gpu_gt::GtPlatform,
};
use core::{
    cell::Cell,
    future::Future,
    sync::atomic::AtomicBool,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Backing {
    pages: u32,
    coherent: bool,
    reads: Cell<usize>,
    seed: Cell<u32>,
}
impl Backing {
    fn new(bytes: usize) -> Self {
        Self {
            pages: (bytes / 4096) as u32,
            coherent: true,
            reads: Cell::new(0),
            seed: Cell::new(0xffff_ffff),
        }
    }
}
impl GpuBacking for Backing {
    fn coherent_for_device(&self) -> bool {
        self.coherent
    }
    fn ggtt_offset(&self) -> u32 {
        panic!("crash copy must not query a GPU address")
    }
    fn size_pages(&self) -> u32 {
        self.pages
    }
    fn read32(&self, offset: u64) -> u32 {
        assert_eq!(offset % 4, 0);
        assert!(offset + 4 <= u64::from(self.pages) * 4096);
        self.reads.set(self.reads.get() + 1);
        self.seed.get() ^ offset as u32
    }
    fn write32(&self, _: u64, _: u32) {
        panic!("crash capture is passive")
    }
}
fn report() -> Report {
    Report::capture(
        super::super::Capture {
            platform: GtPlatform::Battlemage,
            reason: super::super::Reason::Timeout,
            epoch: 42,
            now_ns: 90,
            state: crate::intel_gpu_guc_gt::GtState::SchedulingReady,
            engines: EngineSet::of(&[Engine::Rcs0, Engine::Bcs8]),
            process_name: None,
            pid: None,
            snapshot_time: None,
        },
        super::super::Contexts::new(0),
        |_| Some(0x1234),
    )
}
fn identity() -> Identity {
    Identity {
        epoch: 42,
        incarnation: 7,
        now_ns: 91,
        platform: GtPlatform::Battlemage,
        firmware_version: (70, 54, 0),
        firmware_digest: [0xa5; 32],
    }
}
fn free_slot() -> u32 {
    (0..MAX_CARDS as u32)
        .rev()
        .find(|index| {
            snapshot(*index).is_none() && RETAINED[*index as usize].load(Ordering::Acquire) == 0
        })
        .unwrap()
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("immutable crash descriptor waited for hardware"),
    }
}
fn yes() -> bool {
    true
}
fn no() -> bool {
    false
}
const OPEN: Gate = Gate {
    enabled: yes,
    capable: yes,
    admin: yes,
};

fn smoke_coredump_wire_fixed_extents_and_immutable_reads() -> TestResult {
    let index = free_slot();
    let log = Backing::new(LOG_BYTES);
    let ct = Backing::new(CT_BYTES);
    Armed::reserve(index).unwrap().capture(
        report(),
        Some(identity()),
        Some(&log),
        Some(&ct),
        || true,
    );
    let dump = snapshot(index).unwrap();
    assert_eq!(dump.bytes.len(), DUMP_BYTES);
    assert_eq!(&dump.bytes[..8], b"NARFCDMP");
    assert_eq!(
        (
            word(&dump.bytes, 8),
            word(&dump.bytes, 12),
            word(&dump.bytes, 16)
        ),
        (4, 256, DUMP_BYTES as u32)
    );
    assert_eq!(word(&dump.bytes, 20), index);
    assert_eq!(word(&dump.bytes, 72), 7);
    assert_eq!(&dump.bytes[80..112], &[0xa5; 32]);
    assert_eq!(
        (
            word(&dump.bytes, 112),
            word(&dump.bytes, 120),
            word(&dump.bytes, 124),
            word(&dump.bytes, 128),
            word(&dump.bytes, 132)
        ),
        (256, 4352, 0x115000, 0x116100, 0x6000)
    );
    assert_eq!(log.reads.get(), LOG_BYTES / 4);
    assert_eq!(ct.reads.get(), CT_BYTES / 4);
    assert_eq!(word(&dump.bytes, LOG_OFFSET), u32::MAX);
    assert_eq!(
        word(&dump.bytes, EXEC_OFFSET - 4),
        u32::MAX ^ (CT_BYTES - 4) as u32
    );
    let mut captured_report = report();
    captured_report.generation = dump.generation;
    let text = Snapshot {
        report: captured_report,
        suppressed: 0,
    }
    .text();
    assert_eq!(word(&dump.bytes, 116) as usize, text.len());
    assert_eq!(
        &dump.bytes[REPORT_OFFSET..REPORT_OFFSET + text.len()],
        text.as_bytes()
    );
    assert!(dump.bytes[REPORT_OFFSET + text.len()..LOG_OFFSET]
        .iter()
        .all(|byte| *byte == 0));
    let file = File {
        dump: dump.clone(),
        gate: OPEN,
        writable: false,
    };
    log.seed.set(0);
    ct.seed.set(0);
    // Read across every section boundary plus EOF; never revisit live backing.
    for offset in [0, 251, 4347, 0x1160fb, DUMP_BYTES - 3, DUMP_BYTES] {
        let mut output = [0xa5; 17];
        let count = ready(file.read(offset as u64, &mut output)).unwrap();
        let expected = (DUMP_BYTES - offset).min(17);
        assert_eq!(count, expected);
        assert_eq!(&output[..count], &dump.bytes[offset..offset + count]);
        assert!(output[count..].iter().all(|byte| *byte == 0xa5));
    }
    assert_eq!(ready(file.read(u64::MAX, &mut [0; 1])), Ok(0));
    assert_eq!(log.reads.get(), LOG_BYTES / 4);
    assert!(clear(index, dump.generation));
    drop(file);
    drop(dump);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_wire_fixed_extents_and_immutable_reads
);

fn smoke_coredump_loss_discards_partial_bytes_and_latches() -> TestResult {
    for deny_after in [0, 2, LOG_BYTES / 4096 + 1, LOG_BYTES / 4096 + 4] {
        let index = free_slot();
        let log = Backing::new(LOG_BYTES);
        let ct = Backing::new(CT_BYTES);
        let mut calls = 0;
        Armed::reserve(index).unwrap().capture(
            report(),
            Some(identity()),
            Some(&log),
            Some(&ct),
            || {
                calls += 1;
                calls != deny_after + 1 // would become true again without capture's loss latch
            },
        );
        let dump = snapshot(index).unwrap();
        assert_eq!(calls, deny_after + 1);
        let sections = word(&dump.bytes, 72);
        if deny_after <= LOG_BYTES / 4096 + 1 {
            assert_eq!(sections, 1);
            assert!(dump.bytes[LOG_OFFSET..].iter().all(|byte| *byte == 0));
            assert_eq!(ct.reads.get(), 0);
        } else {
            assert_eq!(sections, 3);
            assert!(dump.bytes[CT_OFFSET..].iter().all(|byte| *byte == 0));
        }
        assert!(clear(index, dump.generation));
    }
    // One-shot cache cleaning is not a substitute for live coherence. Wrong
    // host extents and missing firmware identity also do not touch backing.
    for kind in 0..3 {
        let index = free_slot();
        let mut log = Backing::new(LOG_BYTES);
        let mut ct = Backing::new(CT_BYTES);
        if kind == 0 {
            log.coherent = false;
            ct.coherent = false;
        }
        if kind == 1 {
            log.pages += 1;
            ct.pages -= 1;
        }
        Armed::reserve(index).unwrap().capture(
            report(),
            (kind != 2).then(identity),
            Some(&log),
            Some(&ct),
            || true,
        );
        let dump = snapshot(index).unwrap();
        assert_eq!(word(&dump.bytes, 72), 1);
        assert_eq!((log.reads.get(), ct.reads.get()), (0, 0));
        assert!(clear(index, dump.generation));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_loss_discards_partial_bytes_and_latches
);

fn smoke_coredump_first_failure_generation_and_two_buffer_bound() -> TestResult {
    let index = free_slot();
    drop(Armed::reserve(index).unwrap()); // cancelled preparation returns permit
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    let log = Backing::new(LOG_BYTES);
    let ct = Backing::new(CT_BYTES);
    Armed::reserve(index).unwrap().capture(
        report(),
        Some(identity()),
        Some(&log),
        Some(&ct),
        || true,
    );
    let first = snapshot(index).unwrap();
    let generation = first.generation;
    Armed::reserve(index).unwrap().capture(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        || false,
    );
    assert!(Arc::ptr_eq(&first, &snapshot(index).unwrap()));
    let old = File {
        dump: first.clone(),
        gate: OPEN,
        writable: true,
    };
    assert_eq!(ready(old.write(0, b"clear\n")), Ok(6));
    assert!(snapshot(index).is_none());
    // The previous descriptor still owns the complete old immutable bytes.
    Armed::reserve(index).unwrap().capture(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        || false,
    );
    let second = snapshot(index).unwrap();
    assert!(second.generation > generation);
    assert_eq!(word(&second.bytes, 72), 1);
    assert!(matches!(Armed::reserve(index), Err(FsError::Busy)));
    assert_eq!(ready(old.write(0, b"clear\n")), Err(FsError::Busy));
    let mut output = [0; 4];
    assert_eq!(ready(old.read(LOG_OFFSET as u64, &mut output)), Ok(4));
    assert_eq!(u32::from_le_bytes(output), u32::MAX);
    assert!(clear(index, second.generation));
    drop(second);
    drop(old);
    drop(first);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    // An older prepared buffer cannot resurrect a failure after a newer
    // generation has already been published and acknowledged.
    let stale = Armed::reserve(index).unwrap();
    Armed::reserve(index).unwrap().capture(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        || false,
    );
    let newer = snapshot(index).unwrap();
    assert!(clear(index, newer.generation));
    stale.capture(report(), None, None::<&Backing>, None::<&Backing>, || false);
    assert!(snapshot(index).is_none());
    drop(newer);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_first_failure_generation_and_two_buffer_bound
);

static CAPABLE: AtomicBool = AtomicBool::new(true);
static ADMIN: AtomicBool = AtomicBool::new(true);
fn current_capable() -> bool {
    CAPABLE.load(Ordering::Acquire)
}
fn current_admin() -> bool {
    ADMIN.load(Ordering::Acquire)
}
fn smoke_coredump_opt_in_live_capability_and_clear_authority() -> TestResult {
    use narf_boot::args::KernelCmdline;
    for args in [
        "",
        "narf.intel.devcoredump",
        "narf.intel.devcoredump=0",
        "narf.intel.devcoredump=01",
        "narf.intel.devcoredump=1 narf.intel.devcoredump=1",
        "narf.intel.devcoredump=1 narf.intel.devcoredump",
    ] {
        assert!(!opted_in(KernelCmdline::new(args)));
    }
    assert!(opted_in(KernelCmdline::new(
        "quiet narf.intel.devcoredump=1"
    )));
    let index = free_slot();
    let disabled = Node {
        index,
        gate: Gate {
            enabled: no,
            ..OPEN
        },
    };
    assert!(matches!(
        disabled.open_instance_checked(false),
        Err(FsError::OperationNotPermitted)
    ));
    let node = Node {
        index,
        gate: Gate {
            enabled: yes,
            capable: current_capable,
            admin: current_admin,
        },
    };
    CAPABLE.store(true, Ordering::Release);
    ADMIN.store(true, Ordering::Release);
    assert!(matches!(
        node.open_instance_checked(false),
        Err(FsError::WouldBlock)
    ));
    Armed::reserve(index).unwrap().capture(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        || panic!("no live backing"),
    );
    let file = node.open_instance_checked(true).unwrap().unwrap();
    let readonly = node.open_instance_checked(false).unwrap().unwrap();
    assert_eq!(file.stat().size, DUMP_BYTES as u64);
    CAPABLE.store(false, Ordering::Release);
    for offset in [0, DUMP_BYTES as u64, u64::MAX] {
        assert_eq!(
            ready(file.read(offset, &mut [])),
            Err(FsError::OperationNotPermitted)
        );
    }
    assert_eq!(file.stat().size, 0);
    assert!(matches!(
        node.open_instance_checked(false),
        Err(FsError::OperationNotPermitted)
    ));
    assert_eq!(
        ready(file.write(0, b"clear\n")),
        Err(FsError::OperationNotPermitted)
    );
    CAPABLE.store(true, Ordering::Release);
    ADMIN.store(false, Ordering::Release);
    assert_eq!(
        ready(file.write(0, b"clear\n")),
        Err(FsError::OperationNotPermitted)
    );
    assert!(matches!(
        node.open_instance_checked(true),
        Err(FsError::OperationNotPermitted)
    ));
    ADMIN.store(true, Ordering::Release);
    assert_eq!(ready(readonly.write(0, b"clear\n")), Err(FsError::ReadOnly));
    for (offset, input) in [
        (1, b"clear\n".as_slice()),
        (0, b"clear".as_slice()),
        (0, b"anything\n".as_slice()),
    ] {
        assert_eq!(ready(file.write(offset, input)), Err(FsError::InvalidData));
    }
    assert_eq!(ready(file.write(0, b"clear\n")), Ok(6));
    assert_eq!(ready(file.read(0, &mut [0; 8])), Ok(8));
    drop(file);
    drop(readonly);
    assert_eq!(RETAINED[index as usize].load(Ordering::Acquire), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_opt_in_live_capability_and_clear_authority
);

fn smoke_coredump_fixed_report_limits_and_truncation() -> TestResult {
    use super::super::{ContextInfo, ContextPhase, Contexts};
    let mut report = report();
    report.generation = u64::MAX;
    report.capture.engines = EngineSet::of(&Engine::GRAPHICS);
    report.contexts = Contexts::new(64);
    for _ in 0..super::super::MAX_CONTEXTS {
        report.contexts.push(ContextInfo {
            engine: None,
            placements: report.capture.engines,
            id: u16::MAX,
            request_stamp: u32::MAX,
            phase: ContextPhase::RetireInvalidating,
            timed_out: true,
            reset: true,
            observed_runtime_ticks: Some(u32::MAX),
        });
    }
    let snapshot = Snapshot {
        report,
        suppressed: u64::MAX,
    };
    let mut output = [0xa5; MAX_REPORT_BYTES + 32];
    let len = snapshot.text_into(&mut output[16..16 + MAX_REPORT_BYTES]);
    assert!(len <= MAX_REPORT_BYTES);
    assert_eq!(&output[16..16 + len], snapshot.text().as_bytes());
    assert!(output[..16]
        .iter()
        .chain(output[16 + MAX_REPORT_BYTES..].iter())
        .all(|byte| *byte == 0xa5));
    let len = snapshot.text_into(&mut output[16..144]);
    assert!(len <= 128);
    assert!(output[16..16 + len].ends_with(b"\noutput_truncated=1\n"));
    for size in 0..40 {
        let mut guarded = [0xa5; 72];
        let len = snapshot.text_into(&mut guarded[16..16 + size]);
        assert!(len <= size);
        assert!(guarded[..16]
            .iter()
            .chain(guarded[16 + size..].iter())
            .all(|byte| *byte == 0xa5));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_fixed_report_limits_and_truncation
);

fn execution_info(id: u16) -> ContextInfo {
    ContextInfo {
        engine: None,
        placements: EngineSet::of(&[Engine::Ccs0, Engine::Ccs1]),
        id,
        request_stamp: 0x534e4150,
        phase: ContextPhase::Running,
        timed_out: true,
        reset: false,
        observed_runtime_ticks: Some(u32::MAX),
    }
}

fn smoke_coredump_execution_wire_lrc_ring_scratch_and_immutable_reads() -> TestResult {
    let index = free_slot();
    let image = Backing::new(3 * 4096);
    let ring = Backing::new(8192);
    let scratch = Backing::new(4096);
    image.seed.set(0x12345678);
    ring.seed.set(0x89abcdef);
    scratch.seed.set(0xfaceabcd);
    Armed::reserve(index).unwrap().capture_with_execution(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        |output, access| {
            output.push(
                execution_info(37),
                37,
                0,
                &image,
                &ring,
                Some(&scratch),
                access,
            );
            output.push(execution_info(38), 37, 1, &image, &ring, None, access);
            Some(2)
        },
        || true,
    );
    let dump = snapshot(index).unwrap();
    // Version4 preserves the earlier report/log/CT/execution offsets.
    assert_eq!(word(&dump.bytes, 8), 4);
    assert_eq!(dump.bytes.len(), 0x27d3c0);
    assert_eq!(word(&dump.bytes, 72), 9);
    assert_eq!(word(&dump.bytes, 144), 0x11c100);
    assert_eq!(word(&dump.bytes, 148), 64 + 8 * 0x13080);
    assert_eq!(word(&dump.bytes, 152), 0);
    let execution = &dump.bytes[0x11c100..];
    assert_eq!(&execution[..8], b"NARFEXEC");
    assert_eq!(
        (word(execution, 8), word(execution, 12), word(execution, 16)),
        (1, 64, 0x13080)
    );
    assert_eq!(
        (
            word(execution, 20),
            word(execution, 24),
            word(execution, 28),
            word(execution, 32)
        ),
        (8, 2, 2, 2)
    );
    let first = &execution[64..];
    assert_eq!(
        (
            word(first, 0),
            word(first, 4),
            word(first, 8),
            word(first, 12)
        ),
        (37, 37, 0, 6)
    );
    assert_eq!(word(first, 16), 0x534e4150);
    assert_eq!(word(first, 20), 5);
    assert_eq!(word(first, 24), 0x18);
    assert_eq!(word(first, 28), u32::MAX);
    assert_eq!((word(first, 32), word(first, 36)), (u32::MAX, u32::MAX));
    assert_eq!(word(first, 40), 7);
    assert_eq!((word(first, 44), word(first, 48)), (0x11c1c0, 0x3000));
    assert_eq!((word(first, 52), word(first, 56)), (0x12c1c0, 0x2000));
    assert_eq!((word(first, 60), word(first, 64)), (0x12e1c0, 0x1000));
    assert_eq!(word(&dump.bytes, 0x11c1c0), 0x12345678);
    assert_eq!(word(&dump.bytes, 0x12c1c0), 0x89abcdef);
    assert_eq!(word(&dump.bytes, 0x12e1c0), 0xfaceabcd);
    assert!(dump.bytes[0x11f1c0..0x12c1c0].iter().all(|v| *v == 0));
    let second = &execution[64 + 0x13080..];
    assert_eq!(
        (
            word(second, 0),
            word(second, 4),
            word(second, 8),
            word(second, 40)
        ),
        (38, 37, 1, 3)
    );
    assert_eq!((word(second, 60), word(second, 64)), (0, 0));
    assert!(execution[64 + 2 * 0x13080..].iter().all(|v| *v == 0));
    let file = File {
        dump: dump.clone(),
        gate: OPEN,
        writable: false,
    };
    image.seed.set(0);
    ring.seed.set(0);
    scratch.seed.set(0);
    let reads = (image.reads.get(), ring.reads.get(), scratch.reads.get());
    for offset in [
        EXEC_OFFSET + 60,
        0x11c1be,
        0x12c1be,
        0x12e1be,
        DUMP_BYTES - 5,
    ] {
        let mut output = [0xa5; 17];
        let count = ready(file.read(offset as u64, &mut output)).unwrap();
        assert_eq!(&output[..count], &dump.bytes[offset..offset + count]);
    }
    assert_eq!(
        (image.reads.get(), ring.reads.get(), scratch.reads.get()),
        reads
    );
    assert!(clear(index, dump.generation));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_execution_wire_lrc_ring_scratch_and_immutable_reads
);

fn smoke_coredump_execution_capacity_and_invalid_backing_never_extend_bounds() -> TestResult {
    let index = free_slot();
    let image = Backing::new(3 * 4096);
    let ring = Backing::new(8192);
    Armed::reserve(index).unwrap().capture_with_execution(
        report(),
        None,
        None::<&Backing>,
        None::<&Backing>,
        |output, access| {
            for id in 1..=10 {
                output.push(execution_info(id), id, 0, &image, &ring, None, access);
            }
            Some(10)
        },
        || true,
    );
    let dump = snapshot(index).unwrap();
    let exec = &dump.bytes[EXEC_OFFSET..];
    assert_eq!(
        (
            word(exec, 24),
            word(exec, 28),
            word(exec, 32),
            word(exec, 36)
        ),
        (10, 8, 8, 1)
    );
    assert_eq!(image.reads.get(), 8 * 3 * 4096 / 4);
    assert_eq!(ring.reads.get(), 8 * 8192 / 4);
    assert!(clear(index, dump.generation));
    drop(dump);
    for kind in 0..4 {
        let mut image = Backing::new(3 * 4096);
        let mut ring = Backing::new(8192);
        let mut info = execution_info(10);
        match kind {
            0 => image.pages = 17,
            1 => ring.pages = 3,
            2 => image.coherent = false,
            _ => info.placements = EngineSet::of(&[Engine::Rcs0, Engine::Ccs0]),
        }
        Armed::reserve(index).unwrap().capture_with_execution(
            report(),
            None,
            None::<&Backing>,
            None::<&Backing>,
            |output, access| {
                output.push(info, 10, 0, &image, &ring, None, access);
                Some(1)
            },
            || true,
        );
        let dump = snapshot(index).unwrap();
        let exec = &dump.bytes[EXEC_OFFSET..];
        let entry = &exec[64..];
        assert_eq!(word(exec, 32), 0);
        assert_ne!(word(exec, 36) & 12, 0);
        if kind != 1 {
            assert_eq!(image.reads.get(), 0);
            assert_eq!(word(entry, 44), 0);
            assert_eq!(word(entry, 48), 0);
        }
        if kind == 1 || kind == 3 {
            assert_eq!(ring.reads.get(), 0);
            assert_eq!(word(entry, 52), 0);
            assert_eq!(word(entry, 56), 0);
        }
        assert!(clear(index, dump.generation));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_execution_capacity_and_invalid_backing_never_extend_bounds
);

fn smoke_coredump_execution_current_access_loss_zeros_partial_and_stops_later_reads() -> TestResult
{
    for deny_after in [0, 1, 3, 4, 5, 7] {
        let index = free_slot();
        let image = Backing::new(3 * 4096);
        let ring = Backing::new(8192);
        let scratch = Backing::new(4096);
        let mut calls = 0;
        Armed::reserve(index).unwrap().capture_with_execution(
            report(),
            None,
            None::<&Backing>,
            None::<&Backing>,
            |output, access| {
                output.push(
                    execution_info(1),
                    1,
                    0,
                    &image,
                    &ring,
                    Some(&scratch),
                    access,
                );
                Some(1)
            },
            || {
                calls += 1;
                calls != deny_after + 1
            },
        );
        assert_eq!(calls, deny_after + 1);
        let dump = snapshot(index).unwrap();
        let exec = &dump.bytes[EXEC_OFFSET..];
        let entry = &exec[64..];
        assert_eq!(word(exec, 36) & 2, 2);
        assert_eq!(word(exec, 32), 0);
        let available = word(entry, 40);
        if available & 1 == 0 {
            assert!(entry[128..128 + IMAGE_BYTES].iter().all(|v| *v == 0));
        }
        if available & 2 == 0 {
            assert!(entry[128 + IMAGE_BYTES..128 + IMAGE_BYTES + RING_BYTES]
                .iter()
                .all(|v| *v == 0));
        }
        assert!(entry[128 + IMAGE_BYTES + RING_BYTES..EXEC_STRIDE]
            .iter()
            .all(|v| *v == 0));
        assert_eq!(scratch.reads.get(), 0);
        if deny_after <= 4 {
            assert_eq!(ring.reads.get(), 0);
        }
        assert!(clear(index, dump.generation));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_execution_current_access_loss_zeros_partial_and_stops_later_reads
);

fn xe_capture(
    index: u32,
    text: impl FnOnce(&mut XeText<'_>, &Report, &mut dyn FnMut() -> bool) -> bool,
    access: impl FnMut() -> bool,
) -> Arc<Dump> {
    let log = Backing::new(LOG_BYTES);
    let ct = Backing::new(CT_BYTES);
    Armed::reserve(index).unwrap().capture_with_text(
        report(),
        Some(identity()),
        Some(&log),
        Some(&ct),
        |_, _| None,
        |_, _| None,
        text,
        access,
    );
    snapshot(index).unwrap()
}

fn smoke_coredump_xe_text_section_queue_job_engine_and_bounds() -> TestResult {
    use crate::intel_gpu_error::capture;
    let lists = capture::Lists::new(capture::Family::XeHpg, true, 1, 1, 4).unwrap();
    let mut node = capture::Node::new(lists.max_regs()).unwrap();
    node.capture_manual(capture::Family::XeHpg, Engine::Rcs0, |offset| {
        Some(offset as u32)
    });
    let device = capture::Device {
        device_id: 0xe20b,
        revision: 3,
        gmd_id: 20 << 22 | 1 << 14 | 4,
        reference_clock: Some(100_000_000),
    };
    let mut batches = [0; capture::QUEUE_LANES];
    batches[0] = 0x1_0000;
    let queue = capture::Queue {
        id: 5,
        lrca: 0x12_3000,
        engine: Engine::Rcs0,
        placements: EngineSet::of(&[Engine::Rcs0]),
        logical_mask: 1,
        width: 1,
        stamp: 77,
        kernel: false,
        priority: 2,
        timeslice_us: 1000,
        low_latency: true,
        phase: super::super::ContextPhase::Running,
        timed_out: true,
        reset: false,
        batches,
        batch_count: 1,
        wq: None,
        comm: None,
        pid: None,
        snapshot_time: None,
    };
    let index = free_slot();
    let dump = xe_capture(
        index,
        |out, report, access| {
            assert!(access());
            out.flags |= XE_QUEUE | XE_MANUAL;
            let facts = capture::Facts {
                engine: Engine::Rcs0,
                logical: 0,
                wake_ref: 1,
            };
            capture::print_dump(
                out,
                &device,
                report,
                Some(&queue),
                Some((facts, &node)),
                &lists,
                0,
                0,
            )
            .is_ok()
        },
        || true,
    );
    assert_eq!(dump.bytes.len(), DUMP_BYTES);
    assert_eq!(word(&dump.bytes, 8), 4);
    assert_eq!(word(&dump.bytes, 72), 7 | 32);
    assert_eq!(
        (
            word(&dump.bytes, 172),
            word(&dump.bytes, 176),
            word(&dump.bytes, 180)
        ),
        (XE_OFFSET as u32, XE_BYTES as u32, XE_QUEUE | XE_MANUAL)
    );
    // Earlier sections keep their version-3 offsets.
    assert_eq!(word(&dump.bytes, 160) as usize, VM_OFFSET);
    let xe = &dump.bytes[XE_OFFSET..];
    assert_eq!(&xe[..8], b"NARFXETX");
    assert_eq!(
        (word(xe, 8), word(xe, 12), word(xe, 16), word(xe, 24)),
        (1, 64, 32768, XE_QUEUE | XE_MANUAL)
    );
    let len = word(xe, 20) as usize;
    assert!(xe[64 + len..].iter().all(|byte| *byte == 0));
    let text = core::str::from_utf8(&xe[64..64 + len]).unwrap();
    assert!(text.starts_with(
        "**** Xe Device Coredump ****\nReason: Timedout job - seqno=77, lrc_seqno=77, guc_id=5, flags=0x20\nkernel: narf\nmodule: narf-drivers-gpu\nSnapshot time: unavailable\nUptime: 0.000000090\nProcess: unavailable\nPCI ID: 0xe20b\nPCI revision: 0x03\nGT id: 0\n\tTile: 0\n\tType: main\n\tIP ver: 20.1.4\n\tCS reference clock: 100000000\n"
    ));
    assert!(text.contains(
        "GuC ID: 5\n\tName: rcs5\n\tClass: 0\n\tLogical mask: 0x1\n\tWidth: 1\n\tRef: unavailable\n\tTimeout: 5000 (ms)\n\tTimeslice: 1000 (us)\n\tPreempt timeout: 500000 (us)\n"
    ));
    // ENABLED|REGISTERED plus BANNED for the timed-out queue.
    assert!(text.contains("\tSchedule State: 0x203\n\tFlags: 0x20\n"));
    assert!(text.contains("\n**** Job ****\nbatch_addr[0]: 0x0000000000010000\n"));
    assert!(text.contains(
        "\n**** HW Engines ****\nrcs0 (physical), logical instance=0\n\tCapture_source: Manual\n"
    ));
    assert!(text.contains("\tRING_HEAD: 0x00002034\n"));
    assert!(text.ends_with("\n**** VM state ****\nNARF: binary section at header 160/164\n"));
    // Disclosure stays in the CAP_SYSLOG bundle: the public report has no
    // engine snapshot registers.
    let public = Snapshot {
        report: report(),
        suppressed: 0,
    }
    .text();
    assert!(!public.contains("RING_START") && !public.contains("ACTHD"));
    assert!(!public.contains("Capture_source"));
    assert!(clear(index, dump.generation));

    // Text past the fixed region truncates with a marker, never beyond it.
    let index = free_slot();
    let dump = xe_capture(
        index,
        |out, _, _| {
            use core::fmt::Write as _;
            for line in 0..4096 {
                if writeln!(out, "line {line:08}").is_err() {
                    break;
                }
            }
            true
        },
        || true,
    );
    let xe = &dump.bytes[XE_OFFSET..];
    let len = word(xe, 20) as usize;
    assert!(len <= XE_TEXT_BYTES);
    assert_eq!(word(xe, 24) & XE_TRUNCATED, XE_TRUNCATED);
    assert!(xe[64..64 + len].ends_with(b"\noutput_truncated=1\n"));
    assert_eq!(word(&dump.bytes, 180) & XE_TRUNCATED, XE_TRUNCATED);
    assert!(clear(index, dump.generation));

    // Lost authority latches into the section; no text leaves no section.
    let index = free_slot();
    let dump = xe_capture(
        index,
        |out, _, access| {
            assert!(!access());
            core::fmt::Write::write_str(out, "x\n").is_ok()
        },
        || false,
    );
    assert_eq!(word(&dump.bytes, 180) & XE_LOST, XE_LOST);
    assert!(clear(index, dump.generation));
    let index = free_slot();
    let dump = xe_capture(index, |_, _, _| false, || true);
    assert_eq!(word(&dump.bytes, 72) & 32, 0);
    assert_eq!(word(&dump.bytes, 180), 0);
    assert!(dump.bytes[XE_OFFSET..].iter().all(|byte| *byte == 0));
    assert!(clear(index, dump.generation));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_xe_text_section_queue_job_engine_and_bounds
);

fn smoke_coredump_process_and_snapshot_time_formatting() -> TestResult {
    use crate::intel_gpu_error::capture;
    use alloc::string::String;

    let device = capture::Device {
        device_id: 0xe20b,
        revision: 3,
        gmd_id: (20 << 22) | (1 << 14) | 4,
        reference_clock: Some(100_000_000),
    };
    let lists = capture::Lists::new(capture::Family::XeHpg, true, 0x1, 0, 4).unwrap();
    let rep = report();

    // 1. Process and snapshot time from Queue:
    let queue = capture::Queue {
        id: 5,
        lrca: 0x12_3000,
        engine: Engine::Rcs0,
        placements: EngineSet::of(&[Engine::Rcs0]),
        logical_mask: 1,
        width: 1,
        stamp: 77,
        kernel: false,
        priority: 2,
        timeslice_us: 1000,
        low_latency: true,
        phase: super::super::ContextPhase::Running,
        timed_out: true,
        reset: false,
        batches: [0; capture::QUEUE_LANES],
        batch_count: 0,
        wq: None,
        comm: None,
        pid: None,
        snapshot_time: None,
    }
    .with_process("render_app", 4321)
    .with_snapshot_time(1700000000, 500000000);

    let mut text = String::new();
    capture::print_dump(&mut text, &device, &rep, Some(&queue), None, &lists, 0, 0).unwrap();
    assert!(text.contains("Snapshot time: 1700000000.500000000\n"));
    assert!(text.contains("Process: render_app [4321]\n"));

    // 2. Fallback to Report when Queue has no process or snapshot time:
    let mut report_with_facts = rep;
    report_with_facts.capture = report_with_facts
        .capture
        .with_process("compute_app", 8765)
        .with_snapshot_time(1700000001, 250000000);

    let queue_empty = capture::Queue {
        id: 6,
        lrca: 0x12_4000,
        engine: Engine::Ccs0,
        placements: EngineSet::of(&[Engine::Ccs0]),
        logical_mask: 1,
        width: 1,
        stamp: 78,
        kernel: false,
        priority: 2,
        timeslice_us: 1000,
        low_latency: false,
        phase: super::super::ContextPhase::Running,
        timed_out: false,
        reset: false,
        batches: [0; capture::QUEUE_LANES],
        batch_count: 0,
        wq: None,
        comm: None,
        pid: None,
        snapshot_time: None,
    };

    let mut text2 = String::new();
    capture::print_dump(
        &mut text2,
        &device,
        &report_with_facts,
        Some(&queue_empty),
        None,
        &lists,
        0,
        0,
    )
    .unwrap();
    assert!(text2.contains("Snapshot time: 1700000001.250000000\n"));
    assert!(text2.contains("Process: compute_app [8765]\n"));

    // 3. Fallback to Report with no queue:
    let mut text3 = String::new();
    capture::print_dump(
        &mut text3,
        &device,
        &report_with_facts,
        None,
        None,
        &lists,
        0,
        0,
    )
    .unwrap();
    assert!(text3.contains("Snapshot time: 1700000001.250000000\n"));
    assert!(text3.contains("Process: compute_app [8765]\n"));

    // 4. Default fallback when neither has them:
    let mut text4 = String::new();
    capture::print_dump(&mut text4, &device, &rep, None, None, &lists, 0, 0).unwrap();
    assert!(text4.contains("Snapshot time: unavailable\n"));
    assert!(text4.contains("Process: unavailable\n"));

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_coredump_process_and_snapshot_time_formatting
);
