//! Native fixed-layout/capability/retention conversations. Opaque corrupt
//! firmware words never influence the bounded copies. Source contract: MIT
//! Linux b90c984d xe_devcoredump.c and xe_guc_{log,ct}.c snapshots.
use super::*;
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
    assert_eq!(dump.bytes.len(), 0x11c100);
    assert_eq!(&dump.bytes[..8], b"NARFCDMP");
    assert_eq!(
        (
            word(&dump.bytes, 8),
            word(&dump.bytes, 12),
            word(&dump.bytes, 16)
        ),
        (1, 256, 0x11c100)
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
        word(&dump.bytes, DUMP_BYTES - 4),
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
    report.capture.engines = EngineSet::of(&Engine::ALL);
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
