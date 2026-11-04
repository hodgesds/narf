//! Per-crate smoke tests for `narf-capabilities`.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_cap_slot_layout() -> TestResult {
    // The cap-slot wire format is 16 bytes, 16-byte aligned. The ipc/
    // ring-slot layout assumes this; a size/align drift here is an ABI
    // break that would silently misalign every submission.
    use crate::CapSlot;
    if core::mem::size_of::<CapSlot>() != 16 {
        return TestResult::Fail("CapSlot size != 16");
    }
    if core::mem::align_of::<CapSlot>() != 16 {
        return TestResult::Fail("CapSlot align != 16");
    }
    let s = CapSlot::new(1, 2, 3, 4);
    if s.generation != 1 || s.index != 2 || s.rights != 3 || s.type_tag != 4 {
        return TestResult::Fail("CapSlot::new field order wrong");
    }
    if !CapSlot::EMPTY.is_empty() {
        return TestResult::Fail("EMPTY not empty");
    }
    if s.is_empty() {
        return TestResult::Fail("non-zero slot reported empty");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_slot_layout);

fn smoke_cap_kind_registry() -> TestResult {
    // The CapKind integer values are permanent per spec §3.1 — adding
    // kinds is allowed, renumbering is an ABI break.
    use crate::{kind_name, parse_kind, CapKind};
    let pinned: &[(&str, CapKind, u32)] = &[
        ("BusDevice", CapKind::BusDevice, 0x0001),
        ("BlockDevice", CapKind::BlockDevice, 0x0010),
        ("NetIface", CapKind::NetIface, 0x0020),
        ("NetfilterAdmin", CapKind::NetfilterAdmin, 0x0022),
        ("FileNode", CapKind::FileNode, 0x0030),
        ("Ring", CapKind::Ring, 0x0040),
        ("Domain", CapKind::Domain, 0x0050),
        ("Probe", CapKind::Probe, 0x0060),
        ("Key", CapKind::Key, 0x0070),
        ("Task", CapKind::Task, 0x0080),
        ("SleepableReader", CapKind::SleepableReader, 0x0090),
        ("Process", CapKind::Process, 0x00A0),
    ];
    for &(name, kind, wire) in pinned {
        if kind as u32 != wire {
            return TestResult::Fail("CapKind wire value drifted — ABI break");
        }
        match parse_kind(name) {
            Ok(k) if k as u32 == wire => {}
            _ => return TestResult::Fail("parse_kind round-trip broken"),
        }
        if kind_name(kind) != name {
            return TestResult::Fail("kind_name round-trip broken");
        }
    }
    if parse_kind("DefinitelyNotAKind").is_ok() {
        return TestResult::Fail("parse_kind accepted garbage");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_kind_registry);

fn smoke_cap_derive_narrows_rights() -> TestResult {
    // Stage 3 Wave 2: derive checks if the cap is live, so the slot
    // must point to a real entry in the object table.
    use crate::{Cap, CapKind, CapType, Grant, Rights, Write};

    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Domain;
    }

    let parent: Cap<TestObj, Grant> = Cap::<TestObj, Grant>::bootstrap();
    let derived: Cap<TestObj, Write> = parent.derive::<Write>().unwrap();

    let p = parent.slot();
    let d = derived.slot();
    if p.index != d.index || p.type_tag != d.type_tag {
        return TestResult::Fail("derive dropped non-rights metadata");
    }
    if d.rights != Write::BITS {
        return TestResult::Fail("derive did not tag rights bits");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_derive_narrows_rights);

fn smoke_cap_bootstrap_and_invoke() -> TestResult {
    // A freshly-bootstrapped cap is live: check_live / is_live / invoke
    // with NoopOp all succeed. Epoch starts at 1.
    use crate::{object_table, Cap, CapKind, CapType, NoopOp, Write};

    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }

    let cap: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    if !cap.is_live() {
        return TestResult::Fail("fresh cap not live");
    }
    if cap.check_live().is_err() {
        return TestResult::Fail("check_live on fresh cap failed");
    }
    if cap.invoke(NoopOp).is_err() {
        return TestResult::Fail("NoopOp invoke failed on fresh cap");
    }
    if object_table::kind_at(cap.slot().index) != Some(CapKind::Endpoint) {
        return TestResult::Fail("object_table lost the registered kind");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_bootstrap_and_invoke);

fn smoke_cap_revoke_invalidates() -> TestResult {
    // Bootstrap cap, keep a clone, revoke the original → clone sees
    // Revoked on its next check_live / invoke. O(1) mass invalidation.
    use crate::{Cap, CapError, CapKind, CapType, NoopOp, Write};

    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }

    let parent: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    let clone = parent; // Cap is Copy
    let derived: Cap<TestObj, Write> = parent.derive::<Write>().unwrap();
    parent.revoke();

    match clone.check_live() {
        Err(CapError::Revoked) => {}
        Ok(_) => return TestResult::Fail("clone still live after revoke"),
        Err(_) => return TestResult::Fail("clone reported wrong error"),
    }
    if derived.is_live() {
        return TestResult::Fail("derived cap survived parent revoke");
    }
    if clone.invoke(NoopOp) != Err(CapError::Revoked) {
        return TestResult::Fail("invoke didn't gate on epoch");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_revoke_invalidates);

fn smoke_cap_independent_objects() -> TestResult {
    // Revoking one object does not invalidate caps to another object
    // of the same kind — epochs are per-index, not global.
    use crate::{Cap, CapKind, CapType, Write};

    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }

    let a: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    let b: Cap<TestObj, Write> = Cap::<TestObj, Write>::bootstrap();
    if a.slot().index == b.slot().index {
        return TestResult::Fail("distinct bootstraps produced the same index");
    }
    a.revoke();
    if !b.is_live() {
        return TestResult::Fail("revoking a killed unrelated b");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_independent_objects);

fn smoke_rights_lattice_derive() -> TestResult {
    // Allowed derivations under the rights lattice:
    //   Read ⊂ Write   → Cap<_, Write>.derive::<Read>()
    //   Read ⊂ Invoke  → Cap<_, Invoke>.derive::<Read>()
    //   Read ⊂ Spend   → Cap<_, Spend>.derive::<Read>()
    //
    // The original verification-side test wired this against
    // `narf_drivers::DriverHandle`. To stay inside `narf-capabilities`
    // (no upward dep on `narf-drivers`) we use a local `CapType`.
    use crate::{Cap, CapKind, CapType, Invoke, Read, Spend, Write};

    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }

    let w: Cap<TestObj, Write> = Cap::bootstrap();
    let r: Cap<TestObj, Read> = match w.derive() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Read ⊂ Write derive failed"),
    };
    if r.check_live().is_err() {
        return TestResult::Fail("derived Read cap not live");
    }

    let i: Cap<TestObj, Invoke> = Cap::bootstrap();
    let _ir: Cap<TestObj, Read> = match i.derive() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Read ⊂ Invoke derive failed"),
    };

    let s: Cap<TestObj, Spend> = Cap::bootstrap();
    let _sr: Cap<TestObj, Read> = match s.derive() {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("Read ⊂ Spend derive failed"),
    };
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_rights_lattice_derive);

// ── deep capabilities coverage ─────────────────────────────────────
//
// Closes the remaining invariants on the rights lattice + CapSlot
// atomic round-trip + CapKind registry + CapError variants.

fn smoke_cap_rights_bits_are_distinct_singletons() -> TestResult {
    // Each Rights marker carries a single distinct bit. Catches a
    // refactor that collapses two markers onto the same wire bit.
    use crate::{Grant, Invoke, Read, Rights, Spend, Write};
    let bits = [
        ("Read", Read::BITS),
        ("Write", Write::BITS),
        ("Grant", Grant::BITS),
        ("Spend", Spend::BITS),
        ("Invoke", Invoke::BITS),
    ];
    for &(_, b) in bits.iter() {
        if b == 0 {
            return TestResult::Fail("a Rights marker bit is zero");
        }
        if b.count_ones() != 1 {
            return TestResult::Fail("a Rights bit is not a singleton");
        }
    }
    for (i, &(_, a)) in bits.iter().enumerate() {
        for (j, &(_, b)) in bits.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("two Rights markers share a bit");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "capabilities",
    smoke_cap_rights_bits_are_distinct_singletons
);

fn smoke_cap_grant_derives_every_lesser_right() -> TestResult {
    // Grant is the lattice top — must derive Read, Write, Spend,
    // and Invoke without complaint.
    use crate::{Cap, CapKind, CapType, Grant, Invoke, Read, Spend, Write};
    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Domain;
    }

    let g: Cap<TestObj, Grant> = Cap::bootstrap();
    if g.derive::<Read>().is_err() {
        return TestResult::Fail("Read ⊂ Grant failed");
    }
    if g.derive::<Write>().is_err() {
        return TestResult::Fail("Write ⊂ Grant failed");
    }
    if g.derive::<Spend>().is_err() {
        return TestResult::Fail("Spend ⊂ Grant failed");
    }
    if g.derive::<Invoke>().is_err() {
        return TestResult::Fail("Invoke ⊂ Grant failed");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_grant_derives_every_lesser_right);

fn smoke_cap_slot_u128_round_trip() -> TestResult {
    // as_u128 + from_u128 must round-trip the 16-byte slot bit-for-bit.
    // The atomic CAS path depends on this.
    use crate::CapSlot;
    let cases = [
        CapSlot::EMPTY,
        CapSlot::new(1, 2, 3, 4),
        CapSlot::new(u32::MAX, u32::MAX, u32::MAX, u32::MAX),
        CapSlot::new(0xDEAD_BEEF, 0xCAFE_F00D, 0x1234_5678, 0xABCD_EF01),
    ];
    for &c in cases.iter() {
        let raw = c.as_u128();
        let back = CapSlot::from_u128(raw);
        if back != c {
            return TestResult::Fail("CapSlot u128 round-trip lost data");
        }
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_slot_u128_round_trip);

fn smoke_cap_error_variants_distinct() -> TestResult {
    use crate::CapError;
    let all = [
        CapError::Revoked,
        CapError::DomainMismatch,
        CapError::TypeMismatch,
        CapError::RightsTooWeak,
        CapError::CapTableFull,
        CapError::ObjectMismatch,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j && a == b {
                return TestResult::Fail("CapError variants collapsed");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_error_variants_distinct);

fn smoke_cap_kind_full_registry_round_trip() -> TestResult {
    // Every CapKind in KIND_NAMES must round-trip via parse_kind +
    // kind_name. Catches an entry missing from one side of the
    // table.
    use crate::{kind_name, parse_kind, CapKind};
    let all: &[CapKind] = &[
        CapKind::BusDevice,
        CapKind::BusDeviceP2pDma,
        CapKind::BusReconfigureAcs,
        CapKind::BusRegistry,
        CapKind::BlockDevice,
        CapKind::BlockDeviceBackend,
        CapKind::BlockIoQueueOwn,
        CapKind::Namespace,
        CapKind::NetIface,
        CapKind::StackInstall,
        CapKind::FileNode,
        CapKind::DirNode,
        CapKind::MountPoint,
        CapKind::FsInstance,
        CapKind::Ring,
        CapKind::RingPair,
        CapKind::Endpoint,
        CapKind::Domain,
        CapKind::DmaBuffer,
        CapKind::SharedRegion,
        CapKind::Probe,
        CapKind::TraceRing,
        CapKind::Recorder,
        CapKind::Pmu,
        CapKind::HwCrypto,
        CapKind::HwTrace,
        CapKind::Debugger,
        CapKind::Diagnostics,
        CapKind::Watchpoint,
        CapKind::Key,
        CapKind::KeyMgr,
        CapKind::Rng,
        CapKind::Tpm,
        CapKind::Spdm,
        CapKind::Task,
        CapKind::CpuAffinity,
        CapKind::CpuLifecycle,
        CapKind::CpuBudget,
        CapKind::FreqHint,
        CapKind::Power,
        CapKind::Timer,
        CapKind::DevicePm,
        CapKind::Governor,
        CapKind::PmBus,
        CapKind::SleepableReader,
        CapKind::Scmi,
        CapKind::Process,
        CapKind::Driver,
        CapKind::FbScanout,
        CapKind::AudioStream,
        CapKind::I3cBus,
        CapKind::Pwm,
        CapKind::Firmware,
        CapKind::FirmwareRegistry,
        CapKind::Bluetooth,
        CapKind::UsbPd,
        CapKind::CpuTelemetry,
    ];
    for &k in all {
        let name = kind_name(k);
        if name == "Unknown" {
            return TestResult::Fail("a CapKind has no name entry");
        }
        match parse_kind(name) {
            Ok(parsed) if parsed == k => {}
            _ => return TestResult::Fail("parse_kind didn't round-trip a registered kind"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_kind_full_registry_round_trip);

fn smoke_cap_kind_wire_values_pairwise_distinct() -> TestResult {
    // Any two CapKind values must have distinct wire u32s. A
    // refactor that accidentally aliases two kinds breaks
    // type-tag dispatch across the cap-table runtime.
    use crate::CapKind;
    let all: [CapKind; 8] = [
        CapKind::BusDevice,
        CapKind::BlockDevice,
        CapKind::NetIface,
        CapKind::FileNode,
        CapKind::Ring,
        CapKind::Domain,
        CapKind::Probe,
        CapKind::Key,
    ];
    for (i, &a) in all.iter().enumerate() {
        for (j, &b) in all.iter().enumerate() {
            if i != j && (a as u32) == (b as u32) {
                return TestResult::Fail("two CapKind values share a wire u32");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_kind_wire_values_pairwise_distinct);

fn smoke_cap_badge_default_zero() -> TestResult {
    use crate::Badge;
    if Badge::default().0 != 0 {
        return TestResult::Fail("Badge::default != 0");
    }
    if Badge(0xDEAD) == Badge(0xBEEF) {
        return TestResult::Fail("distinct Badges compared equal");
    }
    if Badge(42) != Badge(42) {
        return TestResult::Fail("identical Badges compared unequal");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_badge_default_zero);

fn smoke_cap_clone_preserves_slot() -> TestResult {
    // Cap is Copy + Clone; both produce a structurally-identical
    // sibling that shares the underlying object table slot.
    use crate::{Cap, CapKind, CapType, Write};
    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }

    let a: Cap<TestObj, Write> = Cap::bootstrap();
    let b = a; // Copy
    let c = a; // Copy again from the same source
    if a.slot() != b.slot() || a.slot() != c.slot() {
        return TestResult::Fail("clone/copy didn't preserve the slot");
    }
    // Revoking through one handle must invalidate the rest.
    a.revoke();
    if b.is_live() || c.is_live() {
        return TestResult::Fail("clone/copy survived revoke");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_clone_preserves_slot);

fn smoke_cap_empty_slot_helper() -> TestResult {
    // CapSlot::EMPTY round-trip + is_empty contract.
    use crate::CapSlot;
    if !CapSlot::EMPTY.is_empty() {
        return TestResult::Fail("EMPTY not empty");
    }
    if !CapSlot::new(0, 0, 0, 0).is_empty() {
        return TestResult::Fail("all-zero new() not empty");
    }
    let mut s = CapSlot::EMPTY;
    s.generation = 1;
    if s.is_empty() {
        return TestResult::Fail("partial-fill slot reported empty");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_empty_slot_helper);

// ── per-task cap tables (#1283) ─────────────────────────────────────

fn smoke_cap_table_new_sentinel() -> TestResult {
    // A fresh table has INITIAL_SLOTS empty slots; position 0 is the
    // null-cap sentinel and out-of-range positions are Revoked.
    use crate::{CapSlot, CapTable};
    let t = CapTable::new();
    if t.capacity() != CapTable::INITIAL_SLOTS {
        return TestResult::Fail("new table capacity != INITIAL_SLOTS");
    }
    if t.capacity() != 256 {
        return TestResult::Fail("INITIAL_SLOTS != 256 (spec §9.7)");
    }
    if CapTable::MAX_SLOTS != 131_072 {
        return TestResult::Fail("MAX_SLOTS != 131072 (spec §9.7)");
    }
    if CapTable::RESERVED_SLOTS != 16 {
        return TestResult::Fail("RESERVED_SLOTS != 16 (spec §9.7)");
    }
    // Position 0, empty sentinel: any presentation is Revoked.
    let probe = CapSlot::new(1, 0, 1, 0x0042);
    if t.lookup(probe).is_ok() {
        return TestResult::Fail("null-cap sentinel resolved");
    }
    // Out of range.
    let oob = CapSlot::new(1, 256, 1, 0x0042);
    if t.lookup(oob).is_ok() {
        return TestResult::Fail("out-of-range lookup resolved");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_table_new_sentinel);

fn smoke_cap_table_bootstrap_region() -> TestResult {
    // Bootstrap installs land in 0..16 in order; the 17th is
    // CapTableFull. Each installed slot resolves through lookup.
    use crate::{Cap, CapError, CapKind, CapSlot, CapTable, CapType, Read};
    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }
    let mut t = CapTable::new();
    for expect in 0..16u32 {
        let cap: Cap<TestObj, Read> = Cap::bootstrap();
        match t.install_bootstrap(&cap) {
            Ok(at) if at == expect => {}
            Ok(_) => return TestResult::Fail("bootstrap slot out of order"),
            Err(_) => return TestResult::Fail("bootstrap install failed early"),
        }
        let s = cap.slot();
        let presented = CapSlot::new(s.generation, expect, s.rights, s.type_tag);
        match t.lookup(presented) {
            Ok(entry) if entry.index == s.index => {}
            Ok(_) => return TestResult::Fail("lookup resolved wrong object"),
            Err(_) => return TestResult::Fail("installed bootstrap slot did not resolve"),
        }
    }
    let extra: Cap<TestObj, Read> = Cap::bootstrap();
    if t.install_bootstrap(&extra) != Err(CapError::CapTableFull) {
        return TestResult::Fail("17th bootstrap install did not report CapTableFull");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_table_bootstrap_region);

fn smoke_cap_table_transfer() -> TestResult {
    // Grant-gated transfer: receiver slot >= 16, sender retains its
    // slot (sharing), receiver lookup resolves to the same object.
    // Mismatched objects, revoked caps, and revoked grants refuse.
    use crate::{Cap, CapError, CapKind, CapSlot, CapTable, CapType, Grant, Read};
    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }
    let grant: Cap<TestObj, Grant> = Cap::bootstrap();
    let read: Cap<TestObj, Read> = grant.derive().unwrap();
    let mut target = CapTable::new();
    let at = match grant.transfer(&read, &mut target) {
        Ok(at) => at,
        Err(_) => return TestResult::Fail("Grant transfer failed"),
    };
    if at < 16 {
        return TestResult::Fail("transfer landed in the bootstrap region");
    }
    // Sender retains: sharing semantics, both still live.
    if !grant.is_live() || !read.is_live() {
        return TestResult::Fail("transfer revoked the sender");
    }
    // Receiver lookup resolves to the same object.
    let s = read.slot();
    let presented = CapSlot::new(s.generation, at, s.rights, s.type_tag);
    match target.lookup(presented) {
        Ok(entry) if entry.index == s.index && entry.generation == s.generation => {}
        Ok(_) => return TestResult::Fail("transfer lookup resolved wrong object"),
        Err(_) => return TestResult::Fail("transferred slot did not resolve"),
    }
    // Mismatched objects: a Grant for A cannot hand out B's cap.
    let other_grant: Cap<TestObj, Grant> = Cap::bootstrap();
    let other_read: Cap<TestObj, Read> = other_grant.derive().unwrap();
    let mut target2 = CapTable::new();
    if grant.transfer(&other_read, &mut target2) != Err(CapError::ObjectMismatch) {
        return TestResult::Fail("cross-object transfer did not report ObjectMismatch");
    }
    // Revoked transferred cap refuses (grant still live, cap dead).
    let grant3: Cap<TestObj, Grant> = Cap::bootstrap();
    let read3: Cap<TestObj, Read> = grant3.derive().unwrap();
    let dead = read3;
    dead.revoke();
    let mut target3 = CapTable::new();
    if grant3.transfer(&read3, &mut target3) != Err(CapError::Revoked) {
        return TestResult::Fail("revoked-cap transfer did not report Revoked");
    }
    // Revoked grant refuses.
    let grant4: Cap<TestObj, Grant> = Cap::bootstrap();
    let read4: Cap<TestObj, Read> = grant4.derive().unwrap();
    let dead_grant = grant4;
    dead_grant.revoke();
    let mut target4 = CapTable::new();
    if grant4.transfer(&read4, &mut target4) != Err(CapError::Revoked) {
        return TestResult::Fail("revoked-grant transfer did not report Revoked");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_table_transfer);

fn smoke_cap_table_cross_task_isolation() -> TestResult {
    // The #1283 core property: a slot installed in table A is not
    // usable from table B. Presenting A's bytes to B either hits an
    // empty entry (Revoked) or resolves to B's OWN entry at that
    // position — never to A's object.
    use crate::{Cap, CapKind, CapSlot, CapTable, CapType, Grant, Read};
    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }
    let grant_a: Cap<TestObj, Grant> = Cap::bootstrap();
    let read_a: Cap<TestObj, Read> = grant_a.derive().unwrap();
    let mut table_a = CapTable::new();
    let at_a = grant_a.transfer(&read_a, &mut table_a).unwrap();
    let s_a = read_a.slot();
    let presented_a = CapSlot::new(s_a.generation, at_a, s_a.rights, s_a.type_tag);
    // B empty at that position: Revoked.
    let table_b_empty = CapTable::new();
    if table_b_empty.lookup(presented_a).is_ok() {
        return TestResult::Fail("A's slot resolved in an empty B table");
    }
    // B with its own entry at the same position: resolves to B's
    // object, never A's.
    let grant_b: Cap<TestObj, Grant> = Cap::bootstrap();
    let read_b: Cap<TestObj, Read> = grant_b.derive().unwrap();
    let mut table_b = CapTable::new();
    let at_b = grant_b.transfer(&read_b, &mut table_b).unwrap();
    if at_b != at_a {
        return TestResult::Fail("transfer slot numbering diverged between tables");
    }
    match table_b.lookup(presented_a) {
        Ok(entry) if entry.index == read_b.slot().index => {}
        Ok(_) => return TestResult::Fail("A's bytes resolved to A's object in B's table"),
        Err(_) => return TestResult::Fail("B's own entry did not resolve"),
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_table_cross_task_isolation);

fn smoke_cap_table_lookup_validation() -> TestResult {
    // Dispatch validation order and errors: wrong generation →
    // Revoked, wrong type → TypeMismatch, superset rights →
    // RightsTooWeak, subset rights (downgrade) → Ok, revoked object
    // → Revoked.
    use crate::{Cap, CapError, CapKind, CapSlot, CapTable, CapType, Grant, Read, Rights, Write};
    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }
    let grant: Cap<TestObj, Grant> = Cap::bootstrap();
    let read: Cap<TestObj, Read> = grant.derive().unwrap();
    let mut t = CapTable::new();
    let at = grant.transfer(&read, &mut t).unwrap();
    let s = read.slot();
    // Wrong generation.
    let bad_gen = CapSlot::new(s.generation + 1, at, s.rights, s.type_tag);
    if t.lookup(bad_gen) != Err(CapError::Revoked) {
        return TestResult::Fail("wrong generation did not report Revoked");
    }
    // Wrong type tag.
    let bad_type = CapSlot::new(s.generation, at, s.rights, CapKind::Domain as u32);
    if t.lookup(bad_type) != Err(CapError::TypeMismatch) {
        return TestResult::Fail("wrong type tag did not report TypeMismatch");
    }
    // Superset rights (claiming Write on a Read entry).
    let wide = CapSlot::new(s.generation, at, Write::BITS, s.type_tag);
    if t.lookup(wide) != Err(CapError::RightsTooWeak) {
        return TestResult::Fail("superset rights did not report RightsTooWeak");
    }
    // Subset rights (downgrade to nothing held... rights=0 is a
    // subset of any entry) resolves.
    let narrow = CapSlot::new(s.generation, at, 0, s.type_tag);
    if t.lookup(narrow).is_err() {
        return TestResult::Fail("subset-rights presentation refused");
    }
    // Revoked object: lookup fails even with correct presentation.
    let grant2: Cap<TestObj, Grant> = Cap::bootstrap();
    let read2: Cap<TestObj, Read> = grant2.derive().unwrap();
    let mut t2 = CapTable::new();
    let at2 = grant2.transfer(&read2, &mut t2).unwrap();
    let killer = read2;
    killer.revoke();
    let s2 = read2.slot();
    let presented2 = CapSlot::new(s2.generation, at2, s2.rights, s2.type_tag);
    if t2.lookup(presented2) != Err(CapError::Revoked) {
        return TestResult::Fail("revoked object's table entry still resolved");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_table_lookup_validation);

fn smoke_cap_table_growth_and_cap() -> TestResult {
    // Growth doubles capacity (256 → 512 → …) and installing past
    // MAX_SLOTS reports CapTableFull. Transfers are O(1) via the
    // install cursor, so filling the table is a loop, not a scan.
    use crate::{Cap, CapError, CapKind, CapTable, CapType, Grant, Read};
    struct TestObj;
    impl CapType for TestObj {
        const KIND: CapKind = CapKind::Endpoint;
    }
    let grant: Cap<TestObj, Grant> = Cap::bootstrap();
    let read: Cap<TestObj, Read> = grant.derive().unwrap();
    let mut t = CapTable::new();
    // Fill the general region to the first growth boundary: 240
    // installs (16..256), then the next install grows to 512.
    for _ in 0..240 {
        if grant.transfer(&read, &mut t).is_err() {
            return TestResult::Fail("transfer failed before first growth");
        }
    }
    if t.capacity() != 256 {
        return TestResult::Fail("capacity moved before growth boundary");
    }
    if grant.transfer(&read, &mut t).is_err() {
        return TestResult::Fail("transfer at growth boundary failed");
    }
    if t.capacity() != 512 {
        return TestResult::Fail("capacity did not double at growth boundary");
    }
    // Fill to the hard cap: 131072 - 16 general slots total, 241
    // already installed.
    let remaining = (CapTable::MAX_SLOTS - 16) - 241;
    for _ in 0..remaining {
        if grant.transfer(&read, &mut t).is_err() {
            return TestResult::Fail("transfer failed before hard cap");
        }
    }
    if t.capacity() != CapTable::MAX_SLOTS {
        return TestResult::Fail("capacity did not reach MAX_SLOTS");
    }
    if grant.transfer(&read, &mut t) != Err(CapError::CapTableFull) {
        return TestResult::Fail("install past MAX_SLOTS did not report CapTableFull");
    }
    TestResult::Pass
}
kernel_test_in!("capabilities", smoke_cap_table_growth_and_cap);
