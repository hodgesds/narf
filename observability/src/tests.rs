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

fn smoke_obs_gdb_attach_legacy_no_transport() -> TestResult {
    // Legacy no-transport `attach` shim still returns NotImplemented:
    // the real entry point is now `run_session` / `attach_com1`.
    use narf_capabilities::{Cap, Invoke};
    use crate::{gdb, Debugger, GdbError};
    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    match gdb::attach(&cap) {
        Err(GdbError::NotImplemented) => {}
        _ => return TestResult::Fail("legacy attach should still surface NotImplemented"),
    }
    cap.revoke();
    match gdb::attach(&cap) {
        Err(GdbError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked debugger cap not rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_attach_legacy_no_transport);

fn smoke_obs_gdb_handshake_qsupported_then_halt() -> TestResult {
    // Host sends `qSupported:multiprocess+` then `?`. We expect:
    //   - `+` ack on the qSupported, then `$PacketSize=400#<sum>` reply
    //   - `+` ack on `?`, then `$S05#<sum>` reply (SigTrap)
    use crate::{gdb, ArchRegs, Debugger};
    use narf_capabilities::{Cap, Invoke};

    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    let mut transport = gdb::VecTransport::new();
    transport.push_packet("qSupported:multiprocess+");
    transport.push_packet("?");
    transport.push_packet("c"); // sentinel so run_session returns
    let mut session = gdb::GdbSession::new(ArchRegs::default(), gdb::HaltReason::SigTrap);
    if gdb::run_session(&cap, &mut transport, &mut session).is_err() {
        return TestResult::Fail("run_session returned Err on clean handshake");
    }
    let out = transport.outbound_str();
    if !out.contains("+$PacketSize=400#") {
        return TestResult::Fail("missing qSupported reply with PacketSize advertisement");
    }
    if !out.contains("$S05#") {
        return TestResult::Fail("halt-reason reply did not encode SigTrap");
    }
    if session.packets_handled < 3 {
        return TestResult::Fail("dispatcher did not advance packets_handled");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_handshake_qsupported_then_halt);

fn smoke_obs_gdb_read_regs_packs_archregs() -> TestResult {
    use crate::{gdb, ArchRegs, Debugger};
    use narf_capabilities::{Cap, Invoke};

    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    let mut transport = gdb::VecTransport::new();
    transport.push_packet("g");
    transport.push_packet("c");
    #[cfg(target_arch = "x86_64")]
    let regs = ArchRegs {
        rax: 0xCAFE_BABE,
        rbx: 0xDEAD_BEEF,
        rip: 0x1234_5678,
        rflags: 0x202,
        cs: 0x08,
        ss: 0x10,
        ..Default::default()
    };
    #[cfg(target_arch = "aarch64")]
    let regs = {
        let mut r = ArchRegs::default();
        r.pc = 0x1234_5678;
        r
    };

    let mut session = gdb::GdbSession::new(regs, gdb::HaltReason::SigTrap);
    if gdb::run_session(&cap, &mut transport, &mut session).is_err() {
        return TestResult::Fail("run_session returned Err");
    }
    let out = transport.outbound_str();
    // x86_64: rax is the first 8 bytes (16 hex chars) of the `g`
    // reply, encoded little-endian.
    #[cfg(target_arch = "x86_64")]
    {
        if !out.contains("$bebafeca00000000") {
            return TestResult::Fail("rax not packed little-endian at head of g reply");
        }
        if !out.contains("efbeadde00000000") {
            return TestResult::Fail("rbx not packed correctly");
        }
    }
    let _ = out;
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_read_regs_packs_archregs);

fn smoke_obs_gdb_read_mem_via_test_shim() -> TestResult {
    use crate::{gdb, ArchRegs, Debugger};
    use narf_capabilities::{Cap, Invoke};

    fn fake_peek(addr: u64, len: u32) -> Option<alloc::vec::Vec<u8>> {
        if addr == 0xCAFE_BABE && len == 4 {
            return Some(alloc::vec![0xDE, 0xAD, 0xBE, 0xEF]);
        }
        None
    }
    fn fake_poke(_addr: u64, _bytes: &[u8]) -> bool {
        true
    }
    gdb::__test_install_memory(fake_peek, fake_poke);

    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    let mut transport = gdb::VecTransport::new();
    transport.push_packet("mcafebabe,4");
    transport.push_packet("c");
    let mut session = gdb::GdbSession::new(ArchRegs::default(), gdb::HaltReason::SigTrap);
    let res = gdb::run_session(&cap, &mut transport, &mut session);
    gdb::__test_clear_memory();
    if res.is_err() {
        return TestResult::Fail("run_session returned Err");
    }
    let out = transport.outbound_str();
    if !out.contains("$deadbeef#") {
        return TestResult::Fail("m reply did not contain the synthetic memory hex");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_read_mem_via_test_shim);

fn smoke_obs_gdb_step_returns_from_session() -> TestResult {
    use crate::{gdb, ArchRegs, Debugger};
    use narf_capabilities::{Cap, Invoke};

    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    let mut transport = gdb::VecTransport::new();
    transport.push_packet("s");
    let mut session = gdb::GdbSession::new(ArchRegs::default(), gdb::HaltReason::SigTrap);
    if gdb::run_session(&cap, &mut transport, &mut session).is_err() {
        return TestResult::Fail("run_session returned Err on `s`");
    }
    let out = transport.outbound_str();
    if !out.contains("$S05#") {
        return TestResult::Fail("step reply did not encode SigTrap signal");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_step_returns_from_session);

fn smoke_obs_gdb_run_session_revoked_cap() -> TestResult {
    use crate::{gdb, ArchRegs, Debugger, GdbError};
    use narf_capabilities::{Cap, Invoke};

    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    cap.revoke();
    let mut transport = gdb::VecTransport::new();
    let mut session = gdb::GdbSession::new(ArchRegs::default(), gdb::HaltReason::SigTrap);
    match gdb::run_session(&cap, &mut transport, &mut session) {
        Err(GdbError::AuthorityRevoked) => TestResult::Pass,
        _ => TestResult::Fail("revoked Debugger cap was not rejected"),
    }
}
kernel_test_in!("observability", smoke_obs_gdb_run_session_revoked_cap);

fn smoke_obs_gdb_parse_command_dispatch() -> TestResult {
    use crate::gdb::{parse_command, GdbCommand, GdbError};
    if !matches!(parse_command("?"), Ok(GdbCommand::HaltReason)) {
        return TestResult::Fail("? did not parse as HaltReason");
    }
    if !matches!(parse_command("g"), Ok(GdbCommand::ReadRegs)) {
        return TestResult::Fail("g did not parse as ReadRegs");
    }
    if !matches!(parse_command("mABCD,4"), Ok(GdbCommand::ReadMem { addr: 0xABCD, len: 4 })) {
        return TestResult::Fail("m did not parse addr+len in hex");
    }
    if !matches!(parse_command("c1000"), Ok(GdbCommand::Continue { addr: Some(0x1000) })) {
        return TestResult::Fail("c<addr> did not parse continue with address");
    }
    if !matches!(parse_command("s"), Ok(GdbCommand::Step { addr: None })) {
        return TestResult::Fail("bare s did not parse Step{None}");
    }
    match parse_command("qSupported:multiprocess+") {
        Ok(GdbCommand::QSupported(ref s)) if s == "multiprocess+" => {}
        _ => return TestResult::Fail("qSupported did not parse feature list"),
    }
    // Unrecognised query → Unsupported.
    if !matches!(parse_command("qOther"), Err(GdbError::Unsupported)) {
        return TestResult::Fail("unknown q query was not Unsupported");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_parse_command_dispatch);

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

// ── GDB software breakpoint smokes ────────────────────────────────
//
// Tests exercise the Z0/z0 packet dispatch + BP_MAP without touching
// real kernel memory. The synthetic memory shim intercepts the
// volatile read/write so no actual pointer dereference occurs; the
// important invariants are:
//   1. After Z0, BP_MAP has an entry for the address.
//   2. After z0, BP_MAP no longer has that entry.
//   3. The original byte is preserved across install + restore.

fn smoke_obs_gdb_bp_install_restore_round_trip() -> TestResult {
    // Drive Z0 through run_session; verify BP_MAP has an entry for the
    // address afterward. Uses the BP read/write test hooks so no real
    // pointer dereference occurs.
    use crate::{gdb, ArchRegs, Debugger};
    use narf_capabilities::{Cap, Invoke};

    gdb::__test_clear_bp_map();

    // Synthetic 1-byte "memory" at address 0xF000_0000, seeded 0x90 (NOP).
    static CELL: narf_lib::sync::IrqSafeSpinLock<u8> =
        narf_lib::sync::IrqSafeSpinLock::new(0x90);
    fn fake_read(va: u64) -> Option<u8> {
        if va == 0xF000_0000 { Some(*CELL.lock()) } else { None }
    }
    fn fake_write(va: u64, byte: u8) -> bool {
        if va == 0xF000_0000 { *CELL.lock() = byte; true } else { false }
    }
    gdb::__test_install_bp_hooks(fake_read, fake_write);

    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();
    let mut transport = gdb::VecTransport::new();
    transport.push_packet("Z0,f0000000,1");
    transport.push_packet("c");
    let mut session = gdb::GdbSession::new(ArchRegs::default(), gdb::HaltReason::SigTrap);
    let res = gdb::run_session(&cap, &mut transport, &mut session);
    gdb::__test_clear_bp_hooks();
    if res.is_err() {
        gdb::__test_clear_bp_map();
        return TestResult::Fail("run_session returned Err on Z0");
    }
    let out = transport.outbound_str();
    if !out.contains("+$OK#") {
        gdb::__test_clear_bp_map();
        return TestResult::Fail("Z0 reply was not OK");
    }
    // BP_MAP must have an entry for 0xF000_0000.
    let found = gdb::BP_MAP.lock().contains_key(&0xF000_0000u64);
    gdb::__test_clear_bp_map();
    if !found {
        return TestResult::Fail("BP_MAP missing entry after Z0");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_bp_install_restore_round_trip);

fn smoke_obs_gdb_bp_map_preserves_original_byte() -> TestResult {
    // After Z0, BP_MAP entry must equal the pre-INT3 byte (0x55).
    // After z0, the entry must be gone.
    use crate::{gdb, ArchRegs, Debugger};
    use narf_capabilities::{Cap, Invoke};

    gdb::__test_clear_bp_map();

    static CELL2: narf_lib::sync::IrqSafeSpinLock<u8> =
        narf_lib::sync::IrqSafeSpinLock::new(0x55);
    fn fake_read2(va: u64) -> Option<u8> {
        if va == 0xF000_1000 { Some(*CELL2.lock()) } else { None }
    }
    fn fake_write2(va: u64, byte: u8) -> bool {
        if va == 0xF000_1000 { *CELL2.lock() = byte; true } else { false }
    }
    gdb::__test_install_bp_hooks(fake_read2, fake_write2);

    let cap: Cap<Debugger, Invoke> = Cap::bootstrap();

    // Z0 — install.
    {
        let mut transport = gdb::VecTransport::new();
        transport.push_packet("Z0,f0001000,1");
        transport.push_packet("c");
        let mut session = gdb::GdbSession::new(ArchRegs::default(), gdb::HaltReason::SigTrap);
        if gdb::run_session(&cap, &mut transport, &mut session).is_err() {
            gdb::__test_clear_bp_hooks();
            gdb::__test_clear_bp_map();
            return TestResult::Fail("run_session failed on Z0");
        }
    }

    // Verify original byte in BP_MAP is 0x55.
    let orig = gdb::BP_MAP.lock().get(&0xF000_1000u64).copied();
    if orig != Some(0x55) {
        gdb::__test_clear_bp_hooks();
        gdb::__test_clear_bp_map();
        return TestResult::Fail("BP_MAP original byte is wrong or missing");
    }

    // z0 — remove.
    {
        let mut transport = gdb::VecTransport::new();
        transport.push_packet("z0,f0001000,1");
        transport.push_packet("c");
        let mut session = gdb::GdbSession::new(ArchRegs::default(), gdb::HaltReason::SigTrap);
        if gdb::run_session(&cap, &mut transport, &mut session).is_err() {
            gdb::__test_clear_bp_hooks();
            gdb::__test_clear_bp_map();
            return TestResult::Fail("run_session failed on z0");
        }
    }

    gdb::__test_clear_bp_hooks();

    // BP_MAP must be empty.
    let still_present = gdb::BP_MAP.lock().contains_key(&0xF000_1000u64);
    gdb::__test_clear_bp_map();
    if still_present {
        return TestResult::Fail("BP_MAP still has entry after z0");
    }
    TestResult::Pass
}
kernel_test_in!("observability", smoke_obs_gdb_bp_map_preserves_original_byte);
