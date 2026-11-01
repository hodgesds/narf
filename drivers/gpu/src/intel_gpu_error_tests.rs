//! Native production capture/store/sysfs conversations. Fixed status offsets
//! and field masks are independent MIT Linux b90c984d xe_guc_capture.c /
//! xe_engine_regs.h vectors. No C extraction or hardware-address dumps.

use super::*;
use alloc::vec::Vec;
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_filesystem::{DirOps, FsError};
use narf_kernel_test::{kernel_test_in, TestResult};

const EXPECTED: [u64; 22] = [
    0xc000, 0xc314, 0x941c, 0x190018, 0x2034, 0x2030, 0x209c, 0x20b8, 0x206c, 0x23a8, 0x22034,
    0x22030, 0x2209c, 0x220b8, 0x2206c, 0x223a8, 0x1a034, 0x1a030, 0x1a09c, 0x1a0b8, 0x1a06c,
    0x1a3a8,
];
fn capture(platform: GtPlatform, reason: Reason) -> Capture {
    Capture {
        platform,
        reason,
        epoch: 42,
        now_ns: 9000,
        state: GtState::Lost,
        engines: EngineSet::of(&[Engine::Rcs0, Engine::Bcs0, Engine::Ccs0]),
    }
}
fn contexts(total: usize) -> Contexts {
    let mut contexts = Contexts::new(total);
    for n in 0..total {
        contexts.push(ContextInfo {
            engine: Engine::Rcs0,
            id: (n + 1) as u16,
            request_stamp: n as u32 + 100,
            phase: ContextPhase::Running,
            timed_out: n == 0,
            reset: false,
            observed_runtime_ticks: Some(15_000_000),
        });
    }
    contexts
}
fn report(reason: Reason) -> Report {
    Report::capture(capture(GtPlatform::Alchemist, reason), contexts(1), |_| {
        Some(0x12345678)
    })
}
fn free_slot() -> Option<u32> {
    (0..MAX_CARDS as u32)
        .rev()
        .find(|index| snapshot(*index).is_none())
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("diagnostic read unexpectedly waited for hardware"),
    }
}

fn smoke_intel_error_whitelist_profiles_and_redaction() -> TestResult {
    for platform in [
        GtPlatform::Alchemist,
        GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        GtPlatform::Battlemage,
    ] {
        let mut reads = Vec::new();
        let report = Report::capture(capture(platform, Reason::Protocol), contexts(1), |offset| {
            reads.push(offset);
            assert!(
                EXPECTED.contains(&offset),
                "capture read a non-whitelisted register"
            );
            Some(if matches!(offset & 0xfff, 0x30 | 0x34) {
                0xfedcba98
            } else {
                0x12345678
            })
        });
        assert_eq!(reads, EXPECTED);
        assert_eq!(report.access, RegisterAccess::Complete);
        let text = Snapshot {
            report,
            suppressed: 0,
        }
        .text();
        assert!(text.contains("rcs0.head_offset=0x001cba98"));
        assert!(text.contains("bcs0.tail_offset=0x001cba98"));
        for forbidden in [
            "fedcba98",
            "lrca",
            "acthd",
            "bbaddr",
            "ring_start",
            "hws_pga",
            "kernel_ptr",
            "physical",
        ] {
            assert!(
                !text.contains(forbidden),
                "report leaked an address-bearing field"
            );
        }
        assert!(text.contains("context rcs0 id=1 request=100 phase=Running timed_out=1"));
    }
    let report = Report::capture(
        capture(
            GtPlatform::Integrated(crate::intel_gpu::Generation::TigerLake),
            Reason::Boot,
        ),
        contexts(0),
        |_| {
            panic!("unsupported graphics profile performed MMIO");
        },
    );
    assert_eq!(report.access, RegisterAccess::Unavailable);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_intel_error_whitelist_profiles_and_redaction
);

fn smoke_intel_error_lost_access_preserves_software_and_stops_mmio() -> TestResult {
    for lose_at in [0, 1, 7, 21] {
        let mut reads = 0;
        let report = Report::capture(
            capture(GtPlatform::Battlemage, Reason::WakeLost),
            contexts(2),
            |offset| {
                assert_eq!(offset, EXPECTED[reads]);
                let result = (reads != lose_at).then_some(0x12345678);
                reads += 1;
                result
            },
        );
        assert_eq!(
            reads,
            lose_at + 1,
            "capture continued after current ownership was lost"
        );
        let text = Snapshot {
            report,
            suppressed: 0,
        }
        .text();
        assert!(text.contains("epoch=42\n") && text.contains("reason=WakeLost\n"));
        assert!(text.contains("contexts=2\n") && text.contains("unavailable"));
        assert_eq!(
            report.access,
            if lose_at == 0 {
                RegisterAccess::Unavailable
            } else {
                RegisterAccess::Partial
            }
        );
    }
    let mut reads = 0;
    let report = Report::capture(
        capture(GtPlatform::Alchemist, Reason::Unavailable),
        contexts(0),
        |_| {
            reads += 1;
            Some(u32::MAX)
        },
    );
    assert_eq!(reads, 1);
    assert!(report.registers.iter().all(Option::is_none));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_intel_error_lost_access_preserves_software_and_stops_mmio
);

fn smoke_intel_error_first_capture_clear_and_immutable_readers() -> TestResult {
    let Some(index) = free_slot() else {
        return TestResult::Skip("all diagnostic slots belong to live devices");
    };
    let RecordResult::Stored(first) = record(index, report(Reason::Timeout)) else {
        panic!("free slot refused report");
    };
    let reader = snapshot(index).unwrap();
    let original = reader.text();
    assert_eq!(
        record(index, report(Reason::Recovery)),
        RecordResult::Retained(first)
    );
    let later = snapshot(index).unwrap();
    assert_eq!(later.suppressed, 1);
    assert_eq!(later.report.capture.reason, Reason::Timeout);
    assert_eq!(
        reader.suppressed, 0,
        "already pinned reader mutated after another error"
    );
    assert_eq!(reader.text(), original);
    assert!(!clear(index, first + 1));
    assert!(clear(index, first));
    assert!(snapshot(index).is_none());
    let RecordResult::Stored(next) = record(index, report(Reason::Boot)) else {
        panic!("cleared slot refused new report");
    };
    assert!(next > first);
    assert!(
        !clear(index, first),
        "stale acknowledgement cleared a newer error"
    );
    assert_eq!(
        reader.text(),
        original,
        "slot reuse invalidated an owned report"
    );
    assert!(clear(index, next));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_intel_error_first_capture_clear_and_immutable_readers
);

fn smoke_intel_error_limits_partial_reads_and_slot_bounds() -> TestResult {
    let report = Report::capture(
        Capture {
            epoch: u64::MAX,
            now_ns: u64::MAX,
            ..capture(GtPlatform::Battlemage, Reason::Transport)
        },
        contexts(64),
        |_| Some(0xfffffffe),
    );
    let reader = Snapshot {
        report,
        suppressed: u64::MAX,
    };
    let text = reader.text();
    assert_eq!(reader.report.contexts.entries().count(), 8);
    assert_eq!(reader.report.contexts.total(), 64);
    assert!(text.contains("contexts=8\ncontexts_truncated=56\n"));
    assert!(text.len() <= 4096 && text.ends_with('\n'));
    let mut copied = Vec::new();
    let mut buffer = [0; 7];
    loop {
        let n = reader.read(copied.len() as u64, &mut buffer);
        if n == 0 {
            break;
        }
        copied.extend_from_slice(&buffer[..n]);
    }
    assert_eq!(copied, text.as_bytes());
    assert_eq!(reader.read(text.len() as u64, &mut buffer), 0);
    assert_eq!(reader.read(u64::MAX, &mut buffer), 0);
    assert_eq!(reader.read(0, &mut []), 0);
    assert_eq!(record(64, report), RecordResult::OutOfRange);
    assert!(snapshot(u32::MAX).is_none());
    assert!(!clear(u32::MAX, 1));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_intel_error_limits_partial_reads_and_slot_bounds
);

fn smoke_intel_error_read_only_sysfs_and_inflight_read_race() -> TestResult {
    let Some(index) = free_slot() else {
        return TestResult::Skip("all diagnostic slots belong to live devices");
    };
    let node = narf_filesystem::sysfs::Kobject::new_root("intel-error-fixture");
    populate_card(index, &node);
    let dir = narf_filesystem::sysfs::SysKobjDir { kobj: node.clone() };
    let file = dir.lookup("error").expect("production error file missing");
    assert!(!node.attr_is_writable("error"));
    assert_eq!(file.stat().mode.perms, 0o444);
    assert_eq!(ready(file.write(0, b"clear\n")), Err(FsError::ReadOnly));
    assert_eq!(
        node.attr_show("error"),
        Some(String::from("narf-intel-error-v1\nstate=none\n"))
    );
    let RecordResult::Stored(first) = record(index, report(Reason::EngineReset)) else {
        panic!("slot occupied");
    };
    let before = show(index);
    let mut output = [0; 4096];
    let read = file.read(0, &mut output);
    // Sysfs captured an owned string before returning the read future.
    // Driver clear/reuse before its poll must not mutate that in-flight read.
    assert!(clear(index, first));
    let RecordResult::Stored(next) = record(index, report(Reason::State)) else {
        panic!("slot occupied");
    };
    let n = ready(read).unwrap();
    assert_eq!(&output[..n], before.as_bytes());
    assert!(show(index).contains("reason=State\n"));
    assert!(!clear(index, first));
    assert!(clear(index, next));
    assert_eq!(ready(file.read(u64::MAX, &mut output)).unwrap(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_error",
    smoke_intel_error_read_only_sysfs_and_inflight_read_race
);
