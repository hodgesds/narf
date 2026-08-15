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
use crate::sysfs::{
    class_device_register, class_register, kobject_add_writable_attr, kobject_emit_uevent,
    uevent_action_from_write,
};
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
// Smoke 10b — a sysfs "add" WRITE triggers a netlink ADD (udevadm-trigger path)
//
// Every other smoke calls kobject_emit_uevent() directly. This one drives the
// REAL coldplug path udev uses: `udevadm trigger --action=add` walks /sys and
// writes "add" to each device's `uevent` file; sysfs `attr_store` must invoke
// the WRITABLE attr's store closure, which broadcasts the netlink uevent.
//
// This is the regression guard for making the parent `inputN` device node's
// `uevent` writable (sysfs.rs populate_input_class): a read-only uevent attr
// returns None from attr_store, so `trigger` is a silent no-op and udevd never
// sees a parent-device ADD → never writes /run/udev/data/+input:inputN. A device
// whose uevent is write-triggerable is what lets real udevd coldplug replace the
// launcher's hand-seeded seat-tag DB. Linux ref: uevent_store (core.c:2453).
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_sysfs_write_add_triggers_emit() -> TestResult {
    reset();

    let class_input = class_register("input");
    let kobj = class_device_register(class_input, "input99-e2e");
    // Mirror the parent-inputN production wiring: a WRITABLE `uevent` attr whose
    // store closure emits a netlink uevent for this kobject (weak ref, no cycle).
    let weak = Arc::downgrade(&kobj);
    kobject_add_writable_attr(
        &kobj,
        "uevent",
        || "NAME=\"narf-input99\"\n".to_string(),
        move |data: &[u8]| {
            if let Some(k) = weak.upgrade() {
                kobject_emit_uevent(&k, uevent_action_from_write(data));
            }
            Ok(())
        },
    );

    // Start the monitor AFTER registration so only the write's ADD is in view.
    let mut reader = UeventReader::new();

    // The actual `echo add > /sys/.../uevent`.
    match kobj.attr_store("uevent", b"add") {
        Some(Ok(())) => {}
        Some(Err(_)) => return TestResult::Fail("attr_store('uevent','add') errored"),
        None => {
            return TestResult::Fail(
                "uevent attr not writable (attr_store returned None) — the ReadOnly bug",
            )
        }
    }

    let evs = reader.drain(10);
    let ev = evs
        .iter()
        .find(|e| e.action == UeventAction::Add && e.devpath.contains("input99-e2e"));
    let ev = match ev {
        Some(e) => e,
        None => return TestResult::Fail("sysfs 'add' write did not broadcast an ADD uevent"),
    };
    if ev.subsystem != "input" {
        return TestResult::Fail("write-triggered ADD SUBSYSTEM != 'input'");
    }

    // A write of "change" must map to a Change action, not Add (real mapping).
    let mut reader2 = UeventReader::new();
    if kobj.attr_store("uevent", b"change").is_none() {
        return TestResult::Fail("second write to uevent attr returned None");
    }
    let evs2 = reader2.drain(10);
    if !evs2.iter().any(|e| e.action == UeventAction::Change) {
        return TestResult::Fail("write 'change' did not broadcast a CHANGE uevent");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_sysfs_write_add_triggers_emit);

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

// ══════════════════════════════════════════════════════════════════════════
// Smoke 13 — coldplug() broadcasts ≥1 well-formed add@ uevent
//
// `narf_filesystem::uevent::coldplug()` is NARF's `udevadm trigger
// --action=add`: it walks every device kobject in /sys and broadcasts an ADD.
// A KOBJECT_UEVENT monitor (here a UeventReader, bound BEFORE coldplug so it
// sees the whole sweep) must receive at least one event carrying ACTION=add,
// a DEVPATH and a SUBSYSTEM. Linux ref: udev_enumerate_scan_devices +
// kobject_uevent(KOBJ_ADD).
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_coldplug_broadcasts_add() -> TestResult {
    reset();

    // Build a small /sys with one device kobject carrying a writable `uevent`
    // (exactly the shape populate_* produce).
    let class_rtc = class_register("rtc");
    let kobj = class_device_register(class_rtc, "coldplug-rtc0");
    kobj.add_symlink("subsystem", "../../class/rtc");
    let weak = Arc::downgrade(&kobj);
    kobject_add_writable_attr(
        &kobj,
        "uevent",
        || "MAJOR=254\nMINOR=0\nDEVNAME=coldplug-rtc0\n".to_string(),
        move |data: &[u8]| {
            if let Some(k) = weak.upgrade() {
                kobject_emit_uevent(&k, uevent_action_from_write(data));
            }
            Ok(())
        },
    );

    // Bind the monitor BEFORE coldplug so it sees the sweep.
    let mut reader = UeventReader::new();

    let n = uevent::coldplug();
    if n == 0 {
        return TestResult::Fail("coldplug() emitted zero ADD uevents");
    }

    let evs = reader.drain(256);
    // Every emitted event must be an ADD with a DEVPATH and a SUBSYSTEM.
    for ev in &evs {
        if ev.action != UeventAction::Add {
            return TestResult::Fail("coldplug emitted a non-Add uevent");
        }
        if ev.devpath.is_empty() {
            return TestResult::Fail("coldplug ADD has empty DEVPATH");
        }
        if ev.subsystem.is_empty() {
            return TestResult::Fail("coldplug ADD has empty SUBSYSTEM");
        }
    }
    // Our device must be among them, with SUBSYSTEM=rtc and MAJOR/MINOR folded
    // into the netlink extras (self-contained message udevadm info can use).
    let ours = evs
        .iter()
        .find(|e| e.devpath.contains("coldplug-rtc0"))
        .cloned();
    let ours = match ours {
        Some(e) => e,
        None => return TestResult::Fail("coldplug did not emit ADD for our device"),
    };
    if ours.subsystem != "rtc" {
        return TestResult::Fail("coldplug ADD SUBSYSTEM != rtc");
    }
    let bytes = ours.to_netlink_bytes();
    let text = String::from_utf8_lossy(&bytes);
    if !text.contains("MAJOR=254") || !text.contains("DEVNAME=coldplug-rtc0") {
        return TestResult::Fail("coldplug ADD netlink bytes missing MAJOR/DEVNAME");
    }

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_coldplug_broadcasts_add);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 14 — coldplug only fires for device kobjects (uevent-attr marker)
//
// A plain container kobject (no `uevent` attr — e.g. /sys/class itself) must
// NOT get an ADD; only real devices do. Guards against the walker spamming
// non-device nodes (which udevd would reject).
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_e2e_coldplug_skips_containers() -> TestResult {
    reset();

    // A bare class container: no `uevent` attr.
    let _class = class_register("emptyclass");

    let mut reader = UeventReader::new();
    let n = uevent::coldplug();

    // No device kobjects → zero ADDs (the container must be skipped).
    if n != 0 {
        return TestResult::Fail("coldplug emitted an ADD for a non-device container");
    }
    if !reader.drain(16).is_empty() {
        return TestResult::Fail("coldplug broadcast events with no devices present");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("uevent_e2e", smoke_uevent_e2e_coldplug_skips_containers);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 15 — later device projections preserve the first replay boundary
//
// DRM and block sysfs are completed by separate Stage::Late initcalls. The
// second begin must extend the existing window, not move its start past DRM.
// ══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
fn smoke_uevent_boot_replay_preserves_earliest_projection() -> TestResult {
    reset();

    // An incomplete early device must remain outside the bounded replay.
    uevent::emit(
        UeventAction::Add,
        "/devices/early/incomplete".to_string(),
        "early".to_string(),
    );

    let drm_start = uevent::begin_boot_udevd_replay();
    uevent::emit(
        UeventAction::Add,
        "/devices/platform/narf-drm/card0".to_string(),
        "drm".to_string(),
    );

    let block_start = uevent::begin_boot_udevd_replay();
    uevent::emit(
        UeventAction::Add,
        "/devices/virtual/block/vblk0p1".to_string(),
        "block".to_string(),
    );

    if block_start != drm_start {
        return TestResult::Fail("later projection advanced the boot replay boundary");
    }
    let events = uevent::boot_udevd_replay_reader().drain(8);
    if events.len() != 2 || events[0].subsystem != "drm" || events[1].subsystem != "block" {
        return TestResult::Fail("boot replay did not retain DRM followed by block ADD");
    }
    if events.iter().any(|event| event.subsystem == "early") {
        return TestResult::Fail("boot replay included an incomplete early device");
    }

    reset();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "uevent_e2e",
    smoke_uevent_boot_replay_preserves_earliest_projection
);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 13 — a boot-replay reader that falls behind the ring loses events
//            SILENTLY, with no way to detect the gap.
//
// This is systemd-udevd's exact shape and it is not covered by smoke 8.
// udevd's netlink socket is created by PID 1 for `systemd-udevd-kernel.socket`
// and positioned with `boot_udevd_replay_reader()` — an ABSOLUTE seqnum
// captured near the start of boot. Smoke 8 reads through `from_start()`,
// which repositions onto the oldest survivor by construction and therefore
// cannot observe this at all.
//
// If boot emits more than `UEVENT_RING_N` events after that boundary, the
// coldplug ADDs the boundary exists to preserve are evicted before udevd
// ever runs, and `read_from` just skips them: the reader's cursor is below
// every surviving seqnum, so it silently resumes at the oldest survivor.
//
// LINUX-GAP: Linux does not lose a netlink monitor's events quietly. An
// overrun socket receives -ENOBUFS, which is precisely how libudev learns it
// must re-enumerate /sys instead of trusting its event stream. NARF has no
// such signal, so a lagging udevd cannot tell "no events" from "your events
// were dropped" — the difference between idling correctly and never creating
// a single /dev node. Pinned here so closing it turns this test red.
//
// Linux ref: net/netlink/af_netlink.c::netlink_dump / netlink_overrun.

#[cfg(feature = "linux-compat")]
fn smoke_uevent_boot_replay_reader_silently_loses_overrun_window() -> TestResult {
    reset();

    // Boot marks the replay boundary once its device projection is complete.
    let boundary = uevent::begin_boot_udevd_replay();

    // The events the boundary exists to preserve — the ones udevd must see.
    for i in 0..4 {
        uevent::emit(
            UeventAction::Add,
            alloc::format!("/devices/coldplug-card{}", i),
            "drm".to_string(),
        );
    }

    // Boot then continues past the ring's capacity before udevd is started.
    for i in 0..uevent::UEVENT_RING_N {
        uevent::emit(
            UeventAction::Add,
            alloc::format!("/devices/later-noise{}", i),
            "noise".to_string(),
        );
    }

    // udevd finally starts and takes the boot-replay cursor.
    let mut reader = uevent::boot_udevd_replay_reader();
    let events = reader.drain(uevent::UEVENT_RING_N * 2);

    // The cursor is genuinely below every surviving seqnum — that is what
    // makes the loss undetectable rather than merely unlucky.
    let oldest_surviving = match events.first() {
        Some(e) => e.seqnum,
        None => {
            reset();
            return TestResult::Fail("boot replay reader drained nothing at all");
        }
    };
    if oldest_surviving <= boundary {
        reset();
        return TestResult::Fail("precondition: ring did not actually overrun the replay boundary");
    }

    // The DRM coldplug ADDs are gone, and the read reported success.
    if events.iter().any(|e| e.subsystem == "drm") {
        reset();
        return TestResult::Fail("precondition: DRM coldplug events were not evicted");
    }

    // LINUX-GAP assertion: the reader is handed a clean, gap-free-looking
    // batch. Nothing in the returned data, the cursor, or a status code says
    // events were dropped. Linux would have raised ENOBUFS by now.
    if events.len() != uevent::UEVENT_RING_N {
        reset();
        return TestResult::Fail("overrun drain did not return exactly the surviving window");
    }
    if !events.iter().all(|e| e.subsystem == "noise") {
        reset();
        return TestResult::Fail("surviving window contained something other than the tail");
    }

    reset();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "uevent_e2e",
    smoke_uevent_boot_replay_reader_silently_loses_overrun_window
);

// ══════════════════════════════════════════════════════════════════════════
// Smoke 14 — the wire format must satisfy every check libudev applies in
//            `device_monitor_receive_device()` before it will build a device.
//
// udevd on the Fedora gate receives EVERY uevent we emit (seqnums 2..35,
// including the DRM card0 ADD), drains its socket, and still queues no event
// and spawns no worker — `event_run()` calls `worker_spawn()` unconditionally
// and udevd issues zero clones. So the messages are arriving and being
// dropped inside libudev's validation, which is silent (it logs at debug and
// returns -EAGAIN, and journald is not up early enough to capture it).
//
// The rules, from systemd v258.9 `src/libsystemd/sd-device/device-monitor.c`,
// in the order they are applied. One assertion per rule, so whichever is
// violated names itself instead of leaving "libudev didn't like it".
//
// Rules 2-4 (sender nl_pid/nl_groups and the SCM_CREDENTIALS uid) live on the
// recvmsg path, not in the payload, and are covered by the socket-layer
// smokes; this pins the byte format.

#[cfg(feature = "linux-compat")]
fn smoke_uevent_netlink_bytes_satisfy_libudev_validation() -> TestResult {
    reset();
    uevent::emit(
        UeventAction::Add,
        "/devices/platform/narf-drm/card0".to_string(),
        "drm".to_string(),
    );
    let mut reader = UeventReader::from_start();
    let events = reader.drain(1);
    let Some(env) = events.into_iter().next() else {
        reset();
        return TestResult::Fail("no event to render");
    };
    let buf = env.to_netlink_bytes();
    reset();

    let n = buf.len();
    // Rule 1: `if (n < 32) return -EINVAL` — short datagrams are dropped
    // outright, before any parsing.
    if n < 32 {
        return TestResult::Fail("netlink uevent shorter than libudev's 32-byte minimum");
    }
    // Rule 5: `if (!memchr(message.buf, 0, n))` — there must be a NUL.
    let Some(nul) = buf.iter().position(|&b| b == 0) else {
        return TestResult::Fail("netlink uevent contains no NUL byte");
    };
    // Rule 6: a kernel message's header must contain "@/". libudev uses this
    // to tell a kernel message from a "libudev"-magic one.
    let header = &buf[..nul];
    if !header.windows(2).any(|w| w == b"@/") {
        return TestResult::Fail("netlink uevent header lacks the \"@/\" kernel marker");
    }
    // Rule 7: `offset = strlen(nulstr) + 1` must be strictly inside the
    // message, or there are no properties to parse.
    let offset = nul + 1;
    if offset >= n {
        return TestResult::Fail("netlink uevent has no properties after its header");
    }
    // Rule 8: device_new_from_nulstr() must find DEVPATH, SUBSYSTEM, ACTION
    // and a NON-ZERO SEQNUM, or device_verify() rejects the device. The
    // properties are NUL-separated KEY=value records.
    let mut have_action = false;
    let mut have_devpath = false;
    let mut have_subsystem = false;
    let mut seqnum_nonzero = false;
    for rec in buf[offset..].split(|&b| b == 0) {
        let Ok(kv) = core::str::from_utf8(rec) else {
            return TestResult::Fail("netlink uevent property record is not valid UTF-8");
        };
        if let Some(v) = kv.strip_prefix("ACTION=") {
            have_action = !v.is_empty();
        } else if let Some(v) = kv.strip_prefix("DEVPATH=") {
            // sd-device requires an absolute, /sys-relative devpath.
            have_devpath = v.starts_with('/');
        } else if let Some(v) = kv.strip_prefix("SUBSYSTEM=") {
            have_subsystem = !v.is_empty();
        } else if let Some(v) = kv.strip_prefix("SEQNUM=") {
            seqnum_nonzero = v.parse::<u64>().map(|s| s > 0).unwrap_or(false);
        }
    }
    if !have_action {
        return TestResult::Fail("netlink uevent lacks a non-empty ACTION property");
    }
    if !have_devpath {
        return TestResult::Fail("netlink uevent lacks an absolute DEVPATH property");
    }
    if !have_subsystem {
        return TestResult::Fail("netlink uevent lacks a non-empty SUBSYSTEM property");
    }
    if !seqnum_nonzero {
        return TestResult::Fail(
            "netlink uevent lacks a non-zero SEQNUM (device_verify rejects 0)",
        );
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "uevent_e2e",
    smoke_uevent_netlink_bytes_satisfy_libudev_validation
);
