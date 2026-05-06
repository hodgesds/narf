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
    if CapSlot::EMPTY.is_empty() != true {
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
