#![cfg(feature = "linux-compat")]
//! End-to-end smokes for sysfs uevent hotplug broadcast.
//!
//! Walks the full path a udev/systemd-tmpfiles consumer would see:
//!   register kobject → emit ADD → reader receives properly-formatted
//!   message with all required keys → unregister → emit REMOVE →
//!   reader receives.
//!
//! Linux reference: `lib/kobject_uevent.c::kobject_uevent_env` (6.9).
//!
//! # Smokes
//!
//!  1. Manual emit ADD — reader receives event, format is correct
//!  2. Manual emit REMOVE — reader receives REMOVE event
//!  3. SEQNUM monotonic — 5 emits yield SEQNUM 1..5 in order
//!  4. Block device register fires ADD — SUBSYSTEM=block, DEVPATH contains name
//!  5. Block device unregister fires REMOVE — same DEVPATH
//!  6. Multi-reader broadcast — 3 readers all receive the same ADD
//!  7. Slow reader cursor advances independently — Reader B not drained;
//!     emit 5 more; B's next poll returns all 5
//!  8. Ring overflow drops oldest, no panic — emit 300 events into
//!     256-entry ring; ring holds ≤ 256; no panic
//!  9. Net iface register fires ADD with SUBSYSTEM=net
//! 10. Input device register fires ADD with SUBSYSTEM=input
//! 11. Format compliance — every ADD/REMOVE has ACTION, DEVPATH,
//!     SUBSYSTEM, SEQNUM in that order; terminated with double-newline
//! 12. Multiple subsystems independent — block + net + input each
//!     register; ring contains 3 ADD events with distinct SUBSYSTEMs
//!
//! GPL-2.0-or-later — NARF is GPL-2.0-or-later as of 2026-05-20.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(feature = "linux-compat")]
use crate::sysfs::{class_device_register, class_register, kobject_emit_uevent};
use crate::uevent::{self, UeventAction, UeventReader};

// ── Minimal fake block device ─────────────────────────────────────────────

struct FakeBlock {
    lba_size: u32,
    capacity: u64,
}

impl core::fmt::Debug for FakeBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeBlock").finish()
    }
}

impl FakeBlock {
    // Returns Arc<dyn BlockDeviceSync> rather than Self so callers get the trait object directly.
    #[allow(clippy::new_ret_no_self)]
    fn new(lba_size: u32, cap: u64) -> Arc<dyn narf_block::BlockDeviceSync> {
        Arc::new(Self {
            lba_size,
            capacity: cap,
        })
    }
}

impl narf_block::BlockDeviceSync for FakeBlock {
    fn lba_size(&self) -> u32 {
        self.lba_size
    }
    fn capacity(&self) -> u64 {
        self.capacity
    }
    fn read(&self, _lba: u64, n: u16, out: &mut [u8]) -> Result<(), narf_block::BlockIoError> {
        let n_bytes = n as usize * self.lba_size as usize;
        out[..n_bytes].fill(0);
        Ok(())
    }
    fn write(&self, _lba: u64, _n: u16, _data: &[u8]) -> Result<(), narf_block::BlockIoError> {
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Reset both uevent ring and sysfs state for test isolation.
#[cfg(feature = "linux-compat")]
fn reset() {
    crate::sysfs::__reset_for_test();
    uevent::__reset_for_test();
}

// ══════════════════════════════════════════════════════════════════════════
// Smoke 1 — Manual emit ADD → reader receives
//
// Linux ref: kobject_uevent.c::kobject_uevent_env — the ADD action
// is emitted when kobject_uevent(kobj, KOBJ_ADD) is called from
// device_add() (drivers/base/core.c:3549).
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_manual_add() -> TestResult {
    reset();

    let mut reader = UeventReader::new();

    uevent::emit(
        UeventAction::Add,
        "/devices/pci/0000:00:14.0".to_string(),
        "usb".to_string(),
    );

    let evs = reader.drain(10);
    if evs.len() != 1 {
        return TestResult::Fail("reader.drain() did not yield exactly 1 event after ADD emit");
    }

    let ev = &evs[0];
    if ev.action != UeventAction::Add {
        return TestResult::Fail("event action is not Add");
    }

    let text = ev.to_text();
    if !text.contains("ACTION=add") {
        return TestResult::Fail("rendered text missing ACTION=add");
    }
    if !text.contains("DEVPATH=/devices/pci/0000:00:14.0") {
        return TestResult::Fail("rendered text missing DEVPATH");
    }
    if !text.contains("SUBSYSTEM=usb") {
        return TestResult::Fail("rendered text missing SUBSYSTEM=usb");
    }
    if !text.contains("SEQNUM=1") {
        return TestResult::Fail("rendered text missing SEQNUM=1");
    }
    if !text.ends_with("\n\n") {
        return TestResult::Fail("rendered text missing double-newline terminator");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_manual_add);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 2 — Manual emit REMOVE → reader receives
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_manual_remove() -> TestResult {
    reset();

    let mut reader = UeventReader::new();

    uevent::emit(
        UeventAction::Remove,
        "/devices/pci/0000:00:14.0".to_string(),
        "usb".to_string(),
    );

    let evs = reader.drain(10);
    if evs.len() != 1 {
        return TestResult::Fail("reader.drain() did not yield 1 event after REMOVE emit");
    }

    let ev = &evs[0];
    if ev.action != UeventAction::Remove {
        return TestResult::Fail("event action is not Remove");
    }

    let text = ev.to_text();
    if !text.contains("ACTION=remove") {
        return TestResult::Fail("rendered text missing ACTION=remove");
    }
    if !text.ends_with("\n\n") {
        return TestResult::Fail("rendered text missing double-newline terminator");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_manual_remove);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 3 — SEQNUM monotonic
//
// Linux ref: uevent_seqnum (lib/kobject_uevent.c:91) is a global
// atomic counter incremented on each kobject_uevent call.
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_seqnum_monotonic() -> TestResult {
    reset();

    let mut reader = UeventReader::new();

    for i in 0..5 {
        uevent::emit(
            UeventAction::Add,
            alloc::format!("/devices/fake{}", i),
            "test".to_string(),
        );
    }

    let evs = reader.drain(10);
    if evs.len() != 5 {
        return TestResult::Fail("expected 5 events, got wrong count");
    }

    for (i, ev) in evs.iter().enumerate() {
        let expected_seqnum = (i as u64) + 1;
        if ev.seqnum != expected_seqnum {
            return TestResult::Fail("SEQNUM not monotonically increasing from 1");
        }
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_seqnum_monotonic);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 4 — Block device register fires ADD
//
// Simulates what blk_register_queue does on Linux:
//   kobject_add() then kobject_uevent(kobj, KOBJ_ADD)
// (block/blk-sysfs.c:852, lib/kobject_uevent.c:639).
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_block_register_fires_add() -> TestResult {
    reset();

    let snap = narf_block::registry::__snapshot_for_test();

    let mut reader = UeventReader::new();

    // Register block device in the kobject tree and emit ADD — mirrors
    // what the sysfs bridge does in populate_block_class + a driver
    // notifying hotplug.
    let dev = FakeBlock::new(512, 8);
    narf_block::registry::register_block_device("uevent-blk0", dev);

    let class_block = class_register("block");
    let kobj = class_device_register(class_block, "uevent-blk0");
    kobject_emit_uevent(&kobj, UeventAction::Add);

    let result = (|| -> TestResult {
        let evs = reader.drain(10);
        if evs.is_empty() {
            return TestResult::Fail("no uevent ADD after block register");
        }

        let ev = evs
            .iter()
            .find(|e| e.action == UeventAction::Add && e.devpath.contains("uevent-blk0"));
        let ev = match ev {
            Some(e) => e,
            None => return TestResult::Fail("ADD event for uevent-blk0 not found in ring"),
        };

        if !ev.subsystem.contains("block") {
            return TestResult::Fail("block register ADD event SUBSYSTEM != block");
        }
        if !ev.devpath.contains("uevent-blk0") {
            return TestResult::Fail("block register ADD event DEVPATH missing device name");
        }
        TestResult::Pass
    })();

    narf_block::registry::__restore_for_test(snap);
    result
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_block_register_fires_add);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 5 — Block device unregister fires REMOVE
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_block_unregister_fires_remove() -> TestResult {
    reset();

    let snap = narf_block::registry::__snapshot_for_test();

    // Register and capture the kobject so we can emit REMOVE later.
    let dev = FakeBlock::new(512, 8);
    narf_block::registry::register_block_device("uevent-blk1", dev);

    let class_block = class_register("block");
    let kobj = class_device_register(class_block, "uevent-blk1");
    kobject_emit_uevent(&kobj, UeventAction::Add);

    // Now set up a fresh reader that captures only post-ADD events.
    let mut reader = UeventReader::new();

    // Simulate unregister: emit REMOVE, then remove from block registry.
    kobject_emit_uevent(&kobj, UeventAction::Remove);
    narf_block::registry::unregister_block_device("uevent-blk1");

    let result = (|| -> TestResult {
        let evs = reader.drain(10);
        if evs.is_empty() {
            return TestResult::Fail("no uevent REMOVE after block unregister");
        }

        let ev = evs
            .iter()
            .find(|e| e.action == UeventAction::Remove && e.devpath.contains("uevent-blk1"));
        let ev = match ev {
            Some(e) => e,
            None => return TestResult::Fail("REMOVE event for uevent-blk1 not found in ring"),
        };

        if !ev.subsystem.contains("block") {
            return TestResult::Fail("block unregister REMOVE event SUBSYSTEM != block");
        }

        // Verify block registry no longer contains the device.
        if narf_block::registry::find_block_device("uevent-blk1").is_some() {
            return TestResult::Fail("uevent-blk1 still in block registry after unregister");
        }

        TestResult::Pass
    })();

    narf_block::registry::__restore_for_test(snap);
    result
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_block_unregister_fires_remove);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 6 — Multi-reader broadcast
//
// Linux ref: each connected netlink socket gets independent delivery
// (struct uevent_sock, kobject_uevent.c:75). Here UeventReader is the
// NARF equivalent.
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_multi_reader_broadcast() -> TestResult {
    reset();

    let mut reader_a = UeventReader::new();
    let mut reader_b = UeventReader::new();
    let mut reader_c = UeventReader::new();

    uevent::emit(
        UeventAction::Add,
        "/devices/pci/0000:01:00.0".to_string(),
        "pci".to_string(),
    );

    let evs_a = reader_a.drain(10);
    let evs_b = reader_b.drain(10);
    let evs_c = reader_c.drain(10);

    if evs_a.len() != 1 {
        return TestResult::Fail("reader_a did not receive the broadcast ADD");
    }
    if evs_b.len() != 1 {
        return TestResult::Fail("reader_b did not receive the broadcast ADD");
    }
    if evs_c.len() != 1 {
        return TestResult::Fail("reader_c did not receive the broadcast ADD");
    }

    // All three must agree on seqnum.
    let seq_a = evs_a[0].seqnum;
    let seq_b = evs_b[0].seqnum;
    let seq_c = evs_c[0].seqnum;

    if seq_a != seq_b || seq_b != seq_c {
        return TestResult::Fail("readers disagree on SEQNUM for the same broadcast event");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_multi_reader_broadcast);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 7 — Slow reader cursor advances independently
//
// Reader A drains; Reader B does not drain. Emit 5 more events. B's
// next poll returns all 5. This mirrors how a slow userspace netlink
// consumer doesn't affect delivery to a fast one.
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_slow_reader_independent_cursor() -> TestResult {
    reset();

    // Emit one event that both readers see.
    uevent::emit(
        UeventAction::Add,
        "/devices/fake-seed".to_string(),
        "test".to_string(),
    );

    let mut reader_a = UeventReader::from_start();
    let mut reader_b = UeventReader::from_start();

    // Reader A drains the seed event; Reader B does not.
    let _ = reader_a.drain(10);

    // Emit 5 more events.
    for i in 0..5 {
        uevent::emit(
            UeventAction::Change,
            alloc::format!("/devices/fake-delta{}", i),
            "test".to_string(),
        );
    }

    // Reader A should see only the 5 new events.
    let new_evs_a = reader_a.drain(20);
    if new_evs_a.len() != 5 {
        return TestResult::Fail("reader_a (fast) did not get exactly 5 new events");
    }

    // Reader B should see all 6 (seed + 5 deltas).
    let all_evs_b = reader_b.drain(20);
    if all_evs_b.len() != 6 {
        return TestResult::Fail("reader_b (slow) did not get all 6 events");
    }

    // Verify reader_b includes the seed event first.
    if all_evs_b[0].devpath != "/devices/fake-seed" {
        return TestResult::Fail("reader_b first event is not the seed event");
    }

    TestResult::Pass
}
kernel_test_in!(
    "uevent_e2e",
    smoke_uevent_e2e_slow_reader_independent_cursor
);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 8 — Ring overflow drops oldest, no panic
//
// Emit UEVENT_RING_N + 44 (= 300) events. The ring must hold exactly
// UEVENT_RING_N (256) events and must not panic. The oldest events
// are silently dropped — matching Linux's netlink-queue-full behaviour
// (kobject_uevent.c; when the netlink socket buffer is full the event
// is simply not delivered to that slow consumer).
//
// After the overflow the ring contains the last 256 events; their
// seqnums start at 45 (events 1..44 were evicted).
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_ring_overflow_no_panic() -> TestResult {
    reset();

    const TOTAL: usize = uevent::UEVENT_RING_N + 44; // 300

    for i in 0..TOTAL {
        uevent::emit(
            UeventAction::Add,
            alloc::format!("/devices/overflow-fake{}", i),
            "overflow".to_string(),
        );
    }

    // Ring must be exactly full, not larger.
    let ring_len = uevent::ring_len();
    if ring_len != uevent::UEVENT_RING_N {
        return TestResult::Fail("ring length after overflow != UEVENT_RING_N");
    }

    // The oldest event still in the ring should have seqnum 45
    // (events 1..44 were evicted when the 256-slot ring filled and
    // was overwritten from event 257 onwards).
    let mut reader = UeventReader::from_start();
    let evs = reader.drain(uevent::UEVENT_RING_N + 10);

    if evs.len() != uevent::UEVENT_RING_N {
        return TestResult::Fail("drain after overflow did not return UEVENT_RING_N events");
    }

    // Oldest remaining event: seqnum should be TOTAL - UEVENT_RING_N + 1 = 45.
    let oldest_seq = evs[0].seqnum;
    let expected_oldest = (TOTAL - uevent::UEVENT_RING_N + 1) as u64;
    if oldest_seq != expected_oldest {
        return TestResult::Fail("oldest surviving event has wrong seqnum after overflow");
    }

    // Newest event should have seqnum == TOTAL.
    let newest_seq = evs[evs.len() - 1].seqnum;
    if newest_seq != TOTAL as u64 {
        return TestResult::Fail("newest event seqnum does not match total emit count");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_ring_overflow_no_panic);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 9 — Net iface register fires ADD with SUBSYSTEM=net
//
// Simulates what netdev_register_kobject does on Linux
// (net/core/net-sysfs.c:1814): kobject_add() then kobject_uevent(
// kobj, KOBJ_ADD) with the kset name "net".
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_net_register_fires_add() -> TestResult {
    reset();

    let mut reader = UeventReader::new();

    // Simulate a net driver registering its kobject — exactly what
    // the sysfs bridge does in populate_net_class + the driver calling
    // kobject_uevent(kobj, KOBJ_ADD).
    let class_net = class_register("net");
    let kobj = class_device_register(class_net, "eth0-e2e");
    kobject_emit_uevent(&kobj, UeventAction::Add);

    let evs = reader.drain(10);
    if evs.is_empty() {
        return TestResult::Fail("no uevent ADD after net iface register");
    }

    let ev = evs
        .iter()
        .find(|e| e.action == UeventAction::Add && e.devpath.contains("eth0-e2e"));
    let ev = match ev {
        Some(e) => e,
        None => return TestResult::Fail("ADD event for eth0-e2e not found in ring"),
    };

    if ev.subsystem != "net" {
        return TestResult::Fail("net register ADD event SUBSYSTEM != 'net'");
    }
    if !ev.devpath.contains("eth0-e2e") {
        return TestResult::Fail("net register ADD event DEVPATH missing device name");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_net_register_fires_add);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 10 — Input device register fires ADD with SUBSYSTEM=input
//
// Simulates evdev_connect (drivers/input/evdev.c:1306) which calls
// kobject_uevent(kobj, KOBJ_ADD) after registering the evdev node.
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_input_register_fires_add() -> TestResult {
    reset();

    let mut reader = UeventReader::new();

    let class_input = class_register("input");
    let kobj = class_device_register(class_input, "event0-e2e");
    kobject_emit_uevent(&kobj, UeventAction::Add);

    let evs = reader.drain(10);
    if evs.is_empty() {
        return TestResult::Fail("no uevent ADD after input device register");
    }

    let ev = evs
        .iter()
        .find(|e| e.action == UeventAction::Add && e.devpath.contains("event0-e2e"));
    let ev = match ev {
        Some(e) => e,
        None => return TestResult::Fail("ADD event for event0-e2e not found in ring"),
    };

    if ev.subsystem != "input" {
        return TestResult::Fail("input register ADD event SUBSYSTEM != 'input'");
    }
    if !ev.devpath.contains("event0-e2e") {
        return TestResult::Fail("input register ADD event DEVPATH missing device name");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_input_register_fires_add);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 11 — Format compliance: required keys in Linux order
//
// Linux ref: lib/kobject_uevent.c::uevent_net_broadcast_untagged
// (lines ~560-580 in 6.9) formats ACTION=\nDEVPATH=\nSUBSYSTEM=\n…
// All four mandatory keys must be present in that order.
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_format_required_keys_order() -> TestResult {
    reset();

    let mut reader = UeventReader::new();

    // Test both ADD and REMOVE to ensure both actions comply.
    uevent::emit(
        UeventAction::Add,
        "/devices/class/net/eth1".to_string(),
        "net".to_string(),
    );
    uevent::emit(
        UeventAction::Remove,
        "/devices/class/net/eth1".to_string(),
        "net".to_string(),
    );

    let evs = reader.drain(10);
    if evs.len() != 2 {
        return TestResult::Fail("expected 2 events (ADD + REMOVE), got wrong count");
    }

    for ev in &evs {
        let text = ev.to_text();

        // All four mandatory keys must be present.
        if !text.contains("ACTION=") {
            return TestResult::Fail("event text missing ACTION=");
        }
        if !text.contains("DEVPATH=") {
            return TestResult::Fail("event text missing DEVPATH=");
        }
        if !text.contains("SUBSYSTEM=") {
            return TestResult::Fail("event text missing SUBSYSTEM=");
        }
        if !text.contains("SEQNUM=") {
            return TestResult::Fail("event text missing SEQNUM=");
        }

        // Linux ordering: ACTION before DEVPATH before SUBSYSTEM before SEQNUM.
        let pos_action = match text.find("ACTION=") {
            Some(p) => p,
            None => return TestResult::Fail("ACTION= not found"),
        };
        let pos_devpath = match text.find("DEVPATH=") {
            Some(p) => p,
            None => return TestResult::Fail("DEVPATH= not found"),
        };
        let pos_subsystem = match text.find("SUBSYSTEM=") {
            Some(p) => p,
            None => return TestResult::Fail("SUBSYSTEM= not found"),
        };
        let pos_seqnum = match text.find("SEQNUM=") {
            Some(p) => p,
            None => return TestResult::Fail("SEQNUM= not found"),
        };

        if !(pos_action < pos_devpath && pos_devpath < pos_subsystem && pos_subsystem < pos_seqnum)
        {
            return TestResult::Fail(
                "mandatory keys are not in Linux order: ACTION DEVPATH SUBSYSTEM SEQNUM",
            );
        }

        // Must end with double-newline (Linux uevent terminator).
        if !text.ends_with("\n\n") {
            return TestResult::Fail("event text missing double-newline terminator");
        }
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_format_required_keys_order);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 12 — Multiple subsystems independent
//
// Register block + net + input devices in the same test. Ring must
// contain 3 ADD events with distinct SUBSYSTEM values. This exercises
// the full fan-out of the global ring across subsystem boundaries.
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_multiple_subsystems() -> TestResult {
    reset();

    let mut reader = UeventReader::new();

    // Block ADD.
    let snap = narf_block::registry::__snapshot_for_test();
    let dev = FakeBlock::new(512, 4);
    narf_block::registry::register_block_device("multi-blk0", dev);
    let class_block = class_register("block");
    let blk_kobj = class_device_register(class_block, "multi-blk0");
    kobject_emit_uevent(&blk_kobj, UeventAction::Add);

    // Net ADD.
    let class_net = class_register("net");
    let net_kobj = class_device_register(class_net, "multi-eth0");
    kobject_emit_uevent(&net_kobj, UeventAction::Add);

    // Input ADD.
    let class_input = class_register("input");
    let input_kobj = class_device_register(class_input, "multi-event0");
    kobject_emit_uevent(&input_kobj, UeventAction::Add);

    let result = (|| -> TestResult {
        let evs = reader.drain(20);
        if evs.len() != 3 {
            return TestResult::Fail("expected 3 ADD events (block + net + input)");
        }

        // All must be ADD.
        for ev in &evs {
            if ev.action != UeventAction::Add {
                return TestResult::Fail("not all 3 events have action=Add");
            }
        }

        // Collect distinct subsystems.
        let mut subsystems: Vec<String> = evs.iter().map(|e| e.subsystem.clone()).collect();
        subsystems.dedup();

        let has_block = evs.iter().any(|e| e.subsystem == "block");
        let has_net = evs.iter().any(|e| e.subsystem == "net");
        let has_input = evs.iter().any(|e| e.subsystem == "input");

        if !has_block {
            return TestResult::Fail("no block ADD event in multi-subsystem test");
        }
        if !has_net {
            return TestResult::Fail("no net ADD event in multi-subsystem test");
        }
        if !has_input {
            return TestResult::Fail("no input ADD event in multi-subsystem test");
        }

        // All three subsystems must be distinct.
        let n_distinct = {
            let mut s = evs.iter().map(|e| e.subsystem.as_str()).collect::<Vec<_>>();
            s.sort_unstable();
            s.dedup();
            s.len()
        };
        if n_distinct != 3 {
            return TestResult::Fail(
                "block, net, input ADD events do not have 3 distinct SUBSYSTEMs",
            );
        }

        TestResult::Pass
    })();

    narf_block::registry::__restore_for_test(snap);
    result
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_multiple_subsystems);
