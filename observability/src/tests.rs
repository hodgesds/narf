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

// ── relocated from verification (subsystem 'observability') ──

fn smoke_obs_gdb_packet_checksum() -> TestResult {
    use crate::gdb::GdbPacket;
    let p = GdbPacket::new("OK");
    if !p.checksum_valid() {
        return TestResult::Fail("freshly-built packet has wrong checksum");
    }
    let wire = p.to_wire();
    if !wire.starts_with("$OK#") {
        return TestResult::Fail("wire format incorrect prefix");
    }
    let mut tampered = p.clone();
    tampered.checksum = tampered.checksum.wrapping_add(1);
    if tampered.checksum_valid() {
        return TestResult::Fail("tampered checksum accepted");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_packet_checksum);

fn smoke_obs_gdb_attach_not_implemented() -> TestResult {
    use narf_capabilities::{Cap, Invoke};
    use crate::{gdb, Debugger, GdbError};
    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    match gdb::attach(&cap) {
        Err(GdbError::NotImplemented) => {}
        _ => return TestResult::Fail("attach should return NotImplemented pending arch backend"),
    }
    cap.revoke();
    match gdb::attach(&cap) {
        Err(GdbError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked debugger cap not rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_attach_not_implemented);

fn smoke_obs_peek_provider_registration() -> TestResult {
    use alloc::vec::Vec;
    use narf_capabilities::{Cap, Read};
    use crate::{peek, Diagnostics, MetricSample, MetricValue, Provider};

    peek::__test_reset();

    struct TestProvider;
    impl Provider for TestProvider {
        fn name(&self) -> &'static str {
            "test"
        }
        fn sample(&self, out: &mut Vec<MetricSample>) {
            out.push(MetricSample {
                provider: alloc::string::String::from("test"),
                name: alloc::string::String::from("counter"),
                value: MetricValue::U64(42),
            });
        }
    }

    peek::register(TestProvider);
    if peek::provider_count() != 1 {
        peek::__test_reset();
        return TestResult::Fail("provider did not register");
    }
    let cap: Cap<Diagnostics, Read> = Cap::bootstrap();
    let mut out = Vec::new();
    if peek::sample_all(&cap, &mut out).is_err() {
        peek::__test_reset();
        return TestResult::Fail("sample_all failed on a live cap");
    }
    if out.len() != 1 || out[0].value != MetricValue::U64(42) {
        peek::__test_reset();
        return TestResult::Fail("sample_all did not return test provider data");
    }
    peek::__test_reset();
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_peek_provider_registration);

// ── deep observability coverage ───────────────────────────────────

fn smoke_obs_error_variants_distinct() -> TestResult {
    use crate::ObsError;
    let all = [
        ObsError::Revoked,
        ObsError::NotAvailable,
        ObsError::CounterDisabled,
        ObsError::EnableUnsupported,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("ObsError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_error_variants_distinct);

fn smoke_obs_panic_snapshot_ring_empty_after_reset() -> TestResult {
    // __test_clear_panic_ring drains the snapshot ring but does NOT
    // reset install_count (counts the panic-hook *installations*,
    // not ring entries). Verify the ring is drained.
    crate::__test_clear_panic_ring();
    if crate::take_snapshot().is_some() {
        return TestResult::Fail("take_snapshot returned Some after reset");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_panic_snapshot_ring_empty_after_reset);

fn smoke_obs_pmu_read_cycles_revoked_cap_rejected() -> TestResult {
    use crate::{ObsError, Pmu};
    use narf_capabilities::{Cap, Read};
    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    cap.revoke();
    match crate::read_cycles(&cap) {
        Err(ObsError::Revoked) => TestResult::Pass,
        _ => TestResult::Fail("revoked cap didn't surface Revoked"),
    }
}
kernel_test_in!("observability", smoke_obs_pmu_read_cycles_revoked_cap_rejected);

fn smoke_obs_pmu_read_instructions_revoked_cap_rejected() -> TestResult {
    use crate::{ObsError, Pmu};
    use narf_capabilities::{Cap, Read};
    let cap: Cap<Pmu, Read> = Cap::bootstrap();
    cap.revoke();
    match crate::read_instructions(&cap) {
        Err(ObsError::Revoked) => TestResult::Pass,
        _ => TestResult::Fail("revoked cap didn't surface Revoked"),
    }
}
kernel_test_in!("observability", smoke_obs_pmu_read_instructions_revoked_cap_rejected);

fn smoke_obs_pmu_enable_user_reads_revoked_cap_rejected() -> TestResult {
    use crate::{ObsError, Pmu};
    use narf_capabilities::{Cap, Write};
    let cap: Cap<Pmu, Write> = Cap::bootstrap();
    cap.revoke();
    match crate::enable_user_reads(&cap) {
        Err(ObsError::Revoked) => TestResult::Pass,
        _ => TestResult::Fail("revoked cap didn't surface Revoked"),
    }
}
kernel_test_in!("observability", smoke_obs_pmu_enable_user_reads_revoked_cap_rejected);

// ── deep observability/gdb + peek ───────────────────────────────────

fn smoke_obs_gdb_packet_to_wire_format() -> TestResult {
    use crate::gdb::GdbPacket;
    let pkt = GdbPacket::new("OK");
    // 'O' + 'K' = 0x4F + 0x4B = 0x9A.
    let s = pkt.to_wire();
    if s != "$OK#9a" {
        return TestResult::Fail("to_wire format drifted from $payload#XX");
    }
    // Empty payload checksum = 0 → "$#00".
    let empty = GdbPacket::new("");
    if empty.to_wire() != "$#00" {
        return TestResult::Fail("empty payload should serialise to $#00");
    }
    // Round-trip: checksum_valid() agrees with new().
    let p = GdbPacket::new("qSupported");
    if !p.checksum_valid() {
        return TestResult::Fail("freshly-built packet failed checksum_valid");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_packet_to_wire_format);

fn smoke_obs_gdb_command_variants_distinct() -> TestResult {
    use crate::gdb::GdbCommand;
    let a = GdbCommand::ReadRegs;
    let b = GdbCommand::WriteRegs(alloc::vec![1, 2]);
    let c = GdbCommand::ReadMem { addr: 0x1000, len: 4 };
    let d = GdbCommand::WriteMem { addr: 0x2000, bytes: alloc::vec![0xFF] };
    let e = GdbCommand::Continue { addr: None };
    let f = GdbCommand::Step { addr: Some(0x3000) };
    let g = GdbCommand::InsertBp { addr: 0x4000, kind: 1 };
    let h = GdbCommand::RemoveBp { addr: 0x4000, kind: 1 };
    let i = GdbCommand::HaltReason;
    let j = GdbCommand::QSupported(alloc::string::String::from("multiprocess+"));
    // Spot-check distinctness on a few pairs that share addr/kind
    // but differ by variant — Eq must distinguish by variant tag.
    if g == h {
        return TestResult::Fail("InsertBp == RemoveBp with same addr/kind");
    }
    if a == i {
        return TestResult::Fail("ReadRegs == HaltReason");
    }
    if e == f {
        return TestResult::Fail("Continue(None) == Step(Some)");
    }
    // Same-variant inequality: WriteRegs with different bytes.
    let b2 = GdbCommand::WriteRegs(alloc::vec![1, 3]);
    if b == b2 {
        return TestResult::Fail("WriteRegs Eq ignored inner");
    }
    let _ = (c, d, j); // touch the rest to keep them constructible
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_command_variants_distinct);

fn smoke_obs_gdb_error_variants_distinct() -> TestResult {
    use crate::gdb::GdbError;
    let all = [
        GdbError::AuthorityRevoked,
        GdbError::MalformedPacket,
        GdbError::Unsupported,
        GdbError::NotImplemented,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("GdbError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_error_variants_distinct);

fn smoke_obs_peek_metric_value_variants_distinct() -> TestResult {
    use crate::peek::MetricValue;
    // Different variants never equal.
    if MetricValue::U64(0) == MetricValue::Bool(false) {
        return TestResult::Fail("U64(0) == Bool(false)");
    }
    // Same variant, different inner.
    if MetricValue::U64(1) == MetricValue::U64(2) {
        return TestResult::Fail("U64(1) == U64(2)");
    }
    if MetricValue::Bool(true) == MetricValue::Bool(false) {
        return TestResult::Fail("Bool(true) == Bool(false)");
    }
    // Same variant, same inner.
    if MetricValue::U64(42) != MetricValue::U64(42) {
        return TestResult::Fail("U64(42) != U64(42)");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_peek_metric_value_variants_distinct);

fn smoke_obs_peek_error_variants_distinct() -> TestResult {
    use crate::peek::PeekError;
    if PeekError::AuthorityRevoked == PeekError::NotRegistered {
        return TestResult::Fail("PeekError variants collapsed");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_peek_error_variants_distinct);
