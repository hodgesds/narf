//! Subsystem smokes for `narf-observability`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `observability` subsystem.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_obs_pmu_cycles_monotonic() -> TestResult {
    use crate::{read_cycles, ObsError, Pmu};
    use narf_capabilities::{Cap, Read};

    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    let a = match read_cycles(&cap) {
        Ok(v) => v,
        Err(ObsError::NotAvailable) => {
            return TestResult::Skip("PMU not exposed at this ring (CR4.PCE / PMUSERENR_EL0)");
        }
        Err(_) => {
            return TestResult::Fail("read_cycles failed unexpectedly");
        }
    };
    for _ in 0..10_000 {
        core::hint::spin_loop();
    }
    let b = match read_cycles(&cap) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("second read_cycles failed"),
    };
    if b > a {
        TestResult::Pass
    } else {
        TestResult::Fail("cycle counter did not advance across busy-wait")
    }
}
kernel_test_in!("observability", smoke_obs_pmu_cycles_monotonic);

fn smoke_obs_pmu_cap_gated() -> TestResult {
    use crate::{read_cycles, ObsError, Pmu};
    use narf_capabilities::{Cap, Read};

    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    cap.revoke();
    match read_cycles(&cap) {
        Err(ObsError::Revoked) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error variant from revoked PMU cap"),
        Ok(_) => TestResult::Fail("read_cycles accepted a revoked cap"),
    }
}
kernel_test_in!("observability", smoke_obs_pmu_cap_gated);

fn smoke_obs_crash_frame_captures_regs() -> TestResult {
    use crate::{capture_crash_frame, ArchRegs, CRASH_STACK_WORDS};

    #[cfg(target_arch = "x86_64")]
    let regs = ArchRegs {
        rax: 0x11,
        rbx: 0x22,
        rcx: 0x33,
        rdx: 0x44,
        rsi: 0x55,
        rdi: 0x66,
        rbp: 0x77,
        rsp: 0x88,
        r8: 0x99,
        r9: 0xAA,
        r10: 0xBB,
        r11: 0xCC,
        r12: 0xDD,
        r13: 0xEE,
        r14: 0xFF,
        r15: 0x10,
        rip: 0xDEAD_BEEF,
        rflags: 0x202,
        cs: 0x08,
        ss: 0x10,
    };
    #[cfg(target_arch = "aarch64")]
    let regs = {
        let mut r = ArchRegs::default();
        r.x[0] = 0x11;
        r.x[30] = 0x1E; // LR
        r.sp = 0x88;
        r.pc = 0xDEAD_BEEF;
        r.pstate = 0x3C5;
        r
    };

    let frame = capture_crash_frame(regs);

    if frame.registers != regs {
        return TestResult::Fail("crash_frame did not preserve ArchRegs verbatim");
    }
    if frame.instruction_ptr != 0xDEAD_BEEF {
        return TestResult::Fail("instruction_ptr not synthesised from arch regs");
    }
    if frame.stack.len() != CRASH_STACK_WORDS {
        return TestResult::Fail("stack snapshot has wrong length");
    }
    if !frame.stack.iter().any(|w| *w != 0) {
        return TestResult::Fail("stack snapshot was entirely zero");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_crash_frame_captures_regs);

fn smoke_obs_panic_snapshot_roundtrip() -> TestResult {
    use crate::{
        install_panic_snapshot, take_snapshot, ObservabilityEvent, Recorder,
        __test_clear_panic_ring, SNAPSHOT_CAPACITY,
    };
    use narf_capabilities::{Cap, Grant};
    use narf_tracing::FlightRing;

    __test_clear_panic_ring();

    static RING: FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY> = FlightRing::new();

    let cap: Cap<Recorder, Grant> = Cap::bootstrap();
    if install_panic_snapshot(&cap, &RING).is_err() {
        return TestResult::Fail("install_panic_snapshot returned Err with a live cap");
    }

    let events = [
        ObservabilityEvent::CapInvoke {
            kind: 1,
            generation: 100,
        },
        ObservabilityEvent::Pmu {
            cycles: 200,
            instructions: 0,
        },
        ObservabilityEvent::Panic {
            ip: 0xDEAD_BEEF,
            domain: 7,
        },
    ];
    for ev in &events {
        RING.record(*ev);
    }

    let snap = match take_snapshot() {
        Some(s) => s,
        None => {
            __test_clear_panic_ring();
            return TestResult::Fail("take_snapshot returned None after install");
        }
    };
    if snap.len() < events.len() {
        __test_clear_panic_ring();
        return TestResult::Fail("snapshot length below pushed event count");
    }
    let entries = snap.entries();
    let expected_newest = events[events.len() - 1];
    if entries[0] != expected_newest {
        __test_clear_panic_ring();
        return TestResult::Fail("snapshot ordering is not newest-first");
    }
    for (i, ev) in events.iter().rev().enumerate() {
        if entries[i] != *ev {
            __test_clear_panic_ring();
            return TestResult::Fail("snapshot entry did not match pushed event");
        }
    }
    __test_clear_panic_ring();
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_panic_snapshot_roundtrip);

fn smoke_obs_pmu_sample_into_ring() -> TestResult {
    use crate::{
        install_panic_snapshot, sample_pmu, take_snapshot, ObsError, ObservabilityEvent, Pmu,
        Recorder, __test_clear_panic_ring, SNAPSHOT_CAPACITY,
    };
    use narf_capabilities::{Cap, Read};
    use narf_tracing::FlightRing;

    __test_clear_panic_ring();

    static RING: FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY> = FlightRing::new();
    let rec: Cap<Recorder, narf_capabilities::Grant> = Cap::bootstrap();
    if install_panic_snapshot(&rec, &RING).is_err() {
        return TestResult::Fail("install_panic_snapshot failed");
    }

    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    if sample_pmu(&cap, &RING).is_err() {
        __test_clear_panic_ring();
        return TestResult::Fail("sample_pmu returned Err with a live cap");
    }
    if sample_pmu(&cap, &RING).is_err() {
        __test_clear_panic_ring();
        return TestResult::Fail("sample_pmu second call returned Err");
    }
    let snap = match take_snapshot() {
        Some(s) => s,
        None => {
            __test_clear_panic_ring();
            return TestResult::Fail("take_snapshot returned None after sampling");
        }
    };
    if snap.len() < 2 {
        __test_clear_panic_ring();
        return TestResult::Fail("ring received fewer than 2 samples");
    }
    for ev in snap.entries().iter().take(2) {
        match ev {
            ObservabilityEvent::Pmu { .. } => {}
            _ => {
                __test_clear_panic_ring();
                return TestResult::Fail("sampled entry was not Pmu variant");
            }
        }
    }

    cap.revoke();
    match sample_pmu(&cap, &RING) {
        Err(ObsError::Revoked) => {}
        _ => {
            __test_clear_panic_ring();
            return TestResult::Fail("sample_pmu did not fail-closed on revoked cap");
        }
    }

    __test_clear_panic_ring();
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_pmu_sample_into_ring);

fn smoke_obs_core_dump_bundles_snapshot() -> TestResult {
    use crate::{
        capture_core_dump, install_panic_snapshot, ArchRegs, ObservabilityEvent, Recorder,
        __test_clear_panic_ring, SNAPSHOT_CAPACITY,
    };
    use narf_capabilities::{Cap, Grant};
    use narf_tracing::FlightRing;

    __test_clear_panic_ring();

    let regs = ArchRegs::default();
    let dump_before = capture_core_dump(regs);
    if dump_before.snapshot.is_some() {
        return TestResult::Fail("snapshot is Some before any install");
    }

    static RING: FlightRing<ObservabilityEvent, SNAPSHOT_CAPACITY> = FlightRing::new();
    let rec: Cap<Recorder, Grant> = Cap::bootstrap();
    if install_panic_snapshot(&rec, &RING).is_err() {
        return TestResult::Fail("install_panic_snapshot failed");
    }
    RING.record(ObservabilityEvent::Panic {
        ip: 0x1234,
        domain: 2,
    });

    let dump_after = capture_core_dump(regs);
    let snap = match dump_after.snapshot {
        Some(s) => s,
        None => {
            __test_clear_panic_ring();
            return TestResult::Fail("snapshot missing after install + record");
        }
    };
    if snap.len() < 1 {
        __test_clear_panic_ring();
        return TestResult::Fail("snapshot is empty after recording an event");
    }
    match snap.entries()[0] {
        ObservabilityEvent::Panic {
            ip: 0x1234,
            domain: 2,
        } => {}
        _ => {
            __test_clear_panic_ring();
            return TestResult::Fail("snapshot head did not match recorded Panic event");
        }
    }

    __test_clear_panic_ring();
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_core_dump_bundles_snapshot);
