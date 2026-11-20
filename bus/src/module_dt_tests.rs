//! End-to-end test for the loadable-module Devicetree shim: a registered
//! module match drives a real `dt_match::probe_blob` walk through the module
//! probe call gate.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::driver_match::{set_module_probe_call_gate, ModuleProbeFn};
use crate::module_dt::{__reset_for_test, register_module_dt_driver, unregister_module_dt_drivers};

// ── Minimal flattened-Devicetree builder (compatible-only nodes) ────────
struct Node<'a>(&'a str, &'a [(&'a str, &'a [u8])], &'a [Node<'a>]);

fn emit(s: &mut Vec<u8>, strings: &mut Vec<u8>, node: &Node<'_>) {
    let pad = |s: &mut Vec<u8>| {
        while s.len() % 4 != 0 {
            s.push(0);
        }
    };
    s.extend_from_slice(&1u32.to_be_bytes());
    s.extend_from_slice(node.0.as_bytes());
    s.push(0);
    pad(s);
    for (name, value) in node.1 {
        let off = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        s.extend_from_slice(&3u32.to_be_bytes());
        s.extend_from_slice(&(value.len() as u32).to_be_bytes());
        s.extend_from_slice(&off.to_be_bytes());
        s.extend_from_slice(value);
        pad(s);
    }
    for child in node.2 {
        emit(s, strings, child);
    }
    s.extend_from_slice(&2u32.to_be_bytes());
}

fn blob(children: &[Node<'_>]) -> Vec<u8> {
    let (mut s, mut strings) = (Vec::new(), Vec::new());
    emit(&mut s, &mut strings, &Node("", &[], children));
    s.extend_from_slice(&9u32.to_be_bytes());
    let off_struct = 56u32;
    let off_strings = off_struct + s.len() as u32;
    let mut out = Vec::new();
    for v in [
        0xd00d_feedu32,
        off_strings + strings.len() as u32,
        off_struct,
        off_strings,
        40,
        17,
        16,
        0,
        strings.len() as u32,
        s.len() as u32,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&s);
    out.extend_from_slice(&strings);
    out
}

// ── Call-gate + probe spy ───────────────────────────────────────────────
static PROBE_HITS: AtomicU64 = AtomicU64::new(0);

/// A direct-call probe gate (the module subsystem's real gate pins the module
/// Live and enters its domain; here the call is immediate).
fn direct_gate(_owner: u64, probe: ModuleProbeFn, dev: u64, reserved: u64) -> i32 {
    probe(dev, reserved)
}

extern "C" fn probe_bind(_dev_token: u64, _reserved: u64) -> i32 {
    PROBE_HITS.fetch_add(1, Ordering::Relaxed);
    0 // bind the node
}

const COMPAT: &str = "narf,module-dt-test";

fn smoke_module_dt_registers_matches_and_binds_a_node() -> TestResult {
    __reset_for_test();
    set_module_probe_call_gate(direct_gate);
    PROBE_HITS.store(0, Ordering::Relaxed);

    // SAFETY: `probe_bind` is a valid extern "C" fn that stays mapped.
    let rc = unsafe { register_module_dt_driver(7, "mod-dt-test", COMPAT, probe_bind as usize) };
    if rc != 0 {
        return TestResult::Fail("first DT registration should succeed");
    }
    // A foreign owner may not claim the same compatible.
    // SAFETY: `probe_bind` is a valid extern "C" fn that stays mapped.
    let busy =
        unsafe { register_module_dt_driver(8, "mod-dt-test-2", COMPAT, probe_bind as usize) };
    if busy != -16 {
        return TestResult::Fail("a foreign owner must not steal the compatible");
    }

    // A tree with one matching node and one unrelated node.
    let dt = blob(&[
        Node("other@0", &[("compatible", b"vendor,unrelated\0")], &[]),
        Node("wifi@1", &[("compatible", b"narf,module-dt-test\0")], &[]),
    ]);
    // SAFETY: the test owns this blob for the duration of the walk; leaking it
    // gives the `'static` lifetime `probe_blob` requires.
    let leaked: &'static [u8] = Vec::leak(dt);

    let bound = crate::dt_match::probe_blob(leaked);
    if bound != 1 {
        return TestResult::Fail("probe_blob should bind exactly the matching node");
    }
    if PROBE_HITS.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("the module probe was not dispatched through the gate");
    }

    // Unregister drops the match; a fresh walk binds nothing (and the already
    // bound node is not re-probed).
    unregister_module_dt_drivers(7);
    PROBE_HITS.store(0, Ordering::Relaxed);
    let dt2 = blob(&[Node(
        "wifi@2",
        &[("compatible", b"narf,module-dt-test\0")],
        &[],
    )]);
    // SAFETY: as above.
    let leaked2: &'static [u8] = Vec::leak(dt2);
    if crate::dt_match::probe_blob(leaked2) != 0 || PROBE_HITS.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("unregister did not remove the DT match");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "bus/module_dt",
    smoke_module_dt_registers_matches_and_binds_a_node
);
