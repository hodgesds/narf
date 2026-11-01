//! Native Monitor -> owned BAR0 PMT/remapper models. Literal vectors cite
//! Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad xe_vsec.c, xe_hwmon.c,
//! regs/{xe_pmt,xe_soc_remapper_regs}.h and platform/intel/pmt header decoder.

use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

const BAR_LEN: u64 = 0x1000000;
const GUID: u32 = 0x1e2f_8010; // Telemetry/PUNIT/E2F8, client segment
const SECOND: u64 = 1_000_000_000;
const PMT_REGS: [u64; 6] = [0x35b000, 0x35b004, 0x35b008, 0x280008, 0x360230, 0x360234];

struct Punit {
    regs: RefCell<BTreeMap<u64, u32>>,
    reads: RefCell<Vec<u64>>,
    writes: RefCell<Vec<(u64, u32)>>,
    sticks: Cell<bool>,
    change_guid: Cell<bool>,
    change_selector: Cell<bool>,
}
impl Punit {
    fn new() -> Self {
        Self {
            regs: RefCell::new(
                [
                    (0x35b000, 0x0010_0002), // access BARID2, PUNIT0,256DWORD=1024bytes
                    (0x35b004, GUID),
                    (0x35b008, 0x360200),
                    (0x280008, 0x9a65_4321), // selector index9a, unrelated fields retained
                    (0x360230, 0x4000),
                    (0x360234, 0x8000), //1J package,2J card
                ]
                .into_iter()
                .collect(),
            ),
            reads: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
            sticks: Cell::new(true),
            change_guid: Cell::new(false),
            change_selector: Cell::new(false),
        }
    }
    fn set(&self, offset: u64, value: u32) {
        self.regs.borrow_mut().insert(offset, value);
    }
    fn enable_pcode(&self) {
        self.set(0x138124, 0);
        self.set(0x138128, 0);
        self.set(0x13812c, 0);
    }
    fn pmt_reads(&self) -> Vec<u64> {
        self.reads
            .borrow()
            .iter()
            .copied()
            .filter(|r| PMT_REGS.contains(r))
            .collect()
    }
}
impl MmioWindow for Punit {
    fn read32(&self, offset: u64) -> u32 {
        self.reads.borrow_mut().push(offset);
        let value = self
            .regs
            .borrow()
            .get(&offset)
            .copied()
            .unwrap_or_else(|| match offset {
                0x138124 => u32::MAX, // optional PCODE discovery unavailable, independent of PMT
                0x138434 => 71,
                0x1382c0 => 83,
                0x138260..=0x13829c if offset % 4 == 0 => 0,
                _ => panic!("non-whitelisted PMT model read {offset:x}"),
            });
        if offset == pmt::ENERGY + 4 {
            if self.change_guid.get() {
                self.set(0x35b004, GUID ^ 1)
            }
            if self.change_selector.get() {
                self.set(0x280008, 0x0165_4321)
            }
        }
        value
    }
    fn write32(&self, offset: u64, value: u32) {
        if [0x138124, 0x138128, 0x13812c].contains(&offset) {
            assert!(
                self.regs.borrow().contains_key(&0x138124),
                "unowned PCODE port"
            );
            self.writes.borrow_mut().push((offset, value));
            self.set(offset, value);
            if offset == 0x138124 {
                let data = match value {
                    0x8000_047d => [0, 0], // no fans
                    0x8000_0025 => [0x5f69_646e, 97],
                    0x8001_087c => [0x5a2e_8640, 0x2468_89ab],
                    _ => panic!("unexpected PMT sibling power write {value:x}"),
                };
                self.set(0x138128, data[0]);
                self.set(0x13812c, data[1]);
                self.set(0x138124, 0);
            }
            return;
        }
        assert_eq!(
            offset, 0x280008,
            "energy path wrote a counter/discovery word"
        );
        self.writes.borrow_mut().push((offset, value));
        if self.sticks.get() {
            self.set(offset, value);
        }
    }
}
fn monitor(bar_len: u64) -> Monitor {
    let monitor = Monitor::new(GtPlatform::Battlemage, bar_len).unwrap();
    monitor.activate(7);
    monitor
}

fn smoke_hwmon_bmg_pmt_production_descriptor_selector_units_and_cached_reads() -> TestResult {
    let monitor = monitor(BAR_LEN);
    let io = Punit::new();
    monitor.service_mmio(7, 0, &io, || true);
    assert_eq!(
        io.pmt_reads(),
        [
            0x35b000, 0x35b004, 0x35b008, 0x280008, 0x280008, 0x360230, 0x360234, 0x280008,
            0x35b000, 0x35b004, 0x35b008
        ]
    );
    assert_eq!(*io.writes.borrow(), [(0x280008, 0x0065_4321)]);
    assert_eq!(monitor.show("energy1_input", 0), "2000000\n");
    assert_eq!(monitor.show("energy2_input", 0), "1000000\n");
    assert_eq!(monitor.show("energy1_label", 0), "card\n");
    assert_eq!(monitor.show("energy2_label", 0), "pkg\n");
    let reads = io.reads.borrow().len();
    for now in [1, 999_999_999] {
        monitor.service_mmio(7, now, &io, || true);
        assert_eq!(monitor.show("energy2_input", now), "1000000\n");
    }
    assert_eq!(
        io.reads.borrow().len(),
        reads,
        "read or subperiod service triggered MMIO"
    );
    assert_eq!(monitor.show("energy1_input", MAX_AGE_NS), "2000000\n");
    assert!(monitor.show("energy1_input", MAX_AGE_NS + 1).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_production_descriptor_selector_units_and_cached_reads
);

fn smoke_hwmon_bmg_pmt_real_bar_extent_rejects_before_any_discovery_access() -> TestResult {
    for len in [0, 0x35b01f, 0x360237] {
        let monitor = monitor(len);
        let io = Punit::new();
        monitor.service_mmio(7, 0, &io, || true);
        assert!(io.pmt_reads().is_empty());
        assert!(io.writes.borrow().is_empty());
        assert!(monitor.show("energy2_input", 0).is_empty());
        assert_eq!(monitor.show("temp2_input", 0), "71000\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_real_bar_extent_rejects_before_any_discovery_access
);

fn smoke_hwmon_bmg_pmt_malformed_discovery_never_uses_arbitrary_resource_or_guid() -> TestResult {
    for (offset, invalid) in [
        (0x35b000, u32::MAX),
        (0x35b000, 2),
        (0x35b000, 0x0000_d002), //short52B
        (0x35b000, 0x0010_000f),
        (0x35b000, 0x0010_0012), //badaccess/type
        (0x35b004, GUID ^ 0x1000),
        (0x35b004, GUID | 0x4000_0000),
        (0x35b004, GUID & !0x3000_0000), //wrongdevice, record,capability
        (0x35b008, 0x360201),
        (0x35b008, 0x00ff_ff00), //foreignBAR/outofrange
    ] {
        let monitor = monitor(BAR_LEN);
        let io = Punit::new();
        io.set(offset, invalid);
        monitor.service_mmio(7, 0, &io, || true);
        assert_eq!(io.pmt_reads(), [0x35b000, 0x35b004, 0x35b008]);
        assert!(io.writes.borrow().is_empty());
        assert!(monitor.show("energy1_input", 0).is_empty());
        assert_eq!(monitor.show("temp2_input", 0), "71000\n");
    }
    let local = monitor(BAR_LEN);
    let io = Punit::new();
    io.set(0x35b000, 0x0010_0003); // ACCESS_LOCAL: discovery end +0x51f0
    io.set(0x35b008, 0x51f0); //0x35b010 +0x51f0 =0x360200
    local.service_mmio(7, 0, &io, || true);
    assert_eq!(local.show("energy2_input", 0), "1000000\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_malformed_discovery_never_uses_arbitrary_resource_or_guid
);

fn smoke_hwmon_bmg_pmt_selector_readback_and_mid_read_identity_loss_refuse_partial_data(
) -> TestResult {
    for fault in 0..3 {
        let monitor = monitor(BAR_LEN);
        let io = Punit::new();
        match fault {
            0 => io.sticks.set(false),
            1 => io.change_guid.set(true),
            _ => io.change_selector.set(true),
        }
        monitor.service_mmio(7, 0, &io, || true);
        assert!(monitor.show("energy2_input", 0).is_empty());
        if fault == 0 {
            assert!(!io.reads.borrow().contains(&pmt::ENERGY))
        }
        io.sticks.set(true);
        io.change_guid.set(false);
        io.change_selector.set(false);
        io.set(0x35b004, GUID);
        let count = io.pmt_reads().len();
        monitor.service_mmio(7, SECOND, &io, || true);
        assert_eq!(
            io.pmt_reads().len(),
            count,
            "failed series silently reopened"
        );
        monitor.activate(8);
        monitor.service_mmio(8, 2 * SECOND, &io, || true);
        assert_eq!(monitor.show("energy2_input", 2 * SECOND), "1000000\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_selector_readback_and_mid_read_identity_loss_refuse_partial_data
);

fn smoke_hwmon_bmg_pmt_wrap_series_gap_backward_identity_and_overflow_limits() -> TestResult {
    let monitor = monitor(BAR_LEN);
    let io = Punit::new();
    io.set(0x360230, 0xffff_fff0);
    io.set(0x360234, 0xffff_ff00);
    monitor.service_mmio(7, 0, &io, || true);
    assert_eq!(monitor.show("energy2_input", 0), "262143999023\n");
    assert_eq!(monitor.show("energy1_input", 0), "262143984375\n");
    io.set(0x360230, 0x10);
    io.set(0x360234, 0x100);
    monitor.service_mmio(7, SECOND, &io, || true);
    assert_eq!(monitor.show("energy2_input", SECOND), "262144000976\n");
    assert_eq!(monitor.show("energy1_input", SECOND), "262144015625\n");
    monitor.service_mmio(7, 3 * SECOND + 1, &io, || true);
    assert!(monitor.show("energy2_input", 3 * SECOND + 1).is_empty());
    monitor.activate(8);
    monitor.service_mmio(8, 4 * SECOND, &io, || true);
    monitor.state.lock().pmt.exhaust_for_test();
    io.set(0x360230, 0x11);
    monitor.service_mmio(8, 5 * SECOND, &io, || true);
    assert!(monitor.show("energy2_input", 5 * SECOND).is_empty());
    monitor.activate(9);
    monitor.service_mmio(9, 6 * SECOND, &io, || true);
    monitor.service_mmio(9, 5 * SECOND, &io, || true);
    assert!(monitor.show("energy2_input", 5 * SECOND).is_empty());
    monitor.activate(10);
    monitor.service_mmio(10, 7 * SECOND, &io, || true);
    io.set(0x35b004, GUID ^ 1); // still a qualified layout, but a different identity
    monitor.service_mmio(10, 8 * SECOND, &io, || true);
    assert!(monitor.show("energy2_input", 8 * SECOND).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_wrap_series_gap_backward_identity_and_overflow_limits
);

fn smoke_hwmon_bmg_pmt_authority_checked_at_every_discovery_selector_and_payload_operation(
) -> TestResult {
    // One optional PCODE read +18 sensor reads precede the12 PMT operations
    // (11reads +1selector write). No denied operation or later operation runs.
    for denied in 20..=31 {
        let monitor = monitor(BAR_LEN);
        let io = Punit::new();
        let mut checks = 0;
        monitor.service_mmio(7, 0, &io, || {
            checks += 1;
            checks != denied
        });
        assert_eq!(checks, denied);
        assert_eq!(
            io.reads.borrow().len() + io.writes.borrow().len(),
            denied - 1
        );
        assert!(monitor.show("energy2_input", 0).is_empty());
        assert!(
            monitor.show("temp2_input", 0).is_empty(),
            "known loss retained sibling cache"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_authority_checked_at_every_discovery_selector_and_payload_operation
);

fn smoke_hwmon_bmg_pmt_known_sibling_loss_between_ticks_revokes_energy_immediately() -> TestResult {
    let monitor = monitor(BAR_LEN);
    let io = Punit::new();
    io.enable_pcode();
    for now in [0, 10_000, 20_000, 30_000, 40_000, 50_000] {
        monitor.service_mmio(7, now, &io, || true);
    }
    assert_eq!(monitor.show("energy2_input", 60_000), "1000000\n");
    // Passive PCODE refresh posts at its actual1Hz deadline. Energy has a
    // fresh sample from this same tick; the reply then loses authority1ns later.
    let now = SECOND + 40_000;
    monitor.service_mmio(7, now, &io, || true);
    assert_eq!(monitor.show("energy1_input", now), "2000000\n");
    let mut checks = 0;
    monitor.service_mmio(7, now + 1, &io, || {
        checks += 1;
        checks < 2
    });
    assert_eq!(
        monitor.show("power2_max_status", now + 1),
        "failed 0 Access\n"
    );
    assert!(monitor.show("energy1_input", now + 1).is_empty());
    assert!(monitor.show("energy2_input", now + 1).is_empty());
    assert!(monitor.show("temp2_input", now + 1).is_empty());
    let count = io.pmt_reads().len();
    monitor.service_mmio(7, now + SECOND, &io, || true);
    assert_eq!(
        io.pmt_reads().len(),
        count,
        "lost energy continuity silently resumed"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_known_sibling_loss_between_ticks_revokes_energy_immediately
);

fn smoke_hwmon_bmg_pmt_close_during_selection_and_fresh_same_epoch_series() -> TestResult {
    let monitor = monitor(BAR_LEN);
    let io = Punit::new();
    let mut checks = 0;
    monitor.service_mmio(7, 0, &io, || {
        checks += 1;
        if checks == 24 {
            monitor.close();
            return false;
        }
        true
    });
    assert!(io.writes.borrow().is_empty());
    assert!(monitor.show("energy2_input", 0).is_empty());
    let count = io.reads.borrow().len();
    monitor.service_mmio(7, SECOND, &io, || panic!("closed PMT worker checked PCI"));
    assert_eq!(io.reads.borrow().len(), count);
    monitor.activate(7); // clean runtime idle resume may retain user epoch
    monitor.service_mmio(7, 2 * SECOND, &io, || true);
    assert_eq!(monitor.show("energy2_input", 2 * SECOND), "1000000\n");
    io.set(0x360230, 0x8000);
    monitor.service_mmio(7, 3 * SECOND, &io, || true);
    assert_eq!(monitor.show("energy2_input", 3 * SECOND), "2000000\n");
    monitor.close();
    io.set(0x360230, 0x4000);
    monitor.activate(7);
    monitor.service_mmio(7, 4 * SECOND, &io, || true);
    assert_eq!(
        monitor.show("energy2_input", 4 * SECOND),
        "1000000\n",
        "resume extended the old series"
    );
    io.set(0x360230, u32::MAX);
    monitor.service_mmio(7, 5 * SECOND, &io, || true);
    assert!(monitor.show("energy2_input", 5 * SECOND).is_empty());
    assert_eq!(monitor.show("temp2_input", 5 * SECOND), "71000\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_close_during_selection_and_fresh_same_epoch_series
);

fn smoke_hwmon_bmg_pmt_real_sysfs_is_card_scoped_read_only_cached_and_closes() -> TestResult {
    let monitor = Monitor::register(991, GtPlatform::Battlemage, BAR_LEN).unwrap();
    let class = class_register("hwmon");
    let node = class
        .child_names()
        .iter()
        .filter_map(|name| class.get_child(name))
        .find(|n| n.get_symlink("device") == Some("/sys/class/drm/card991/device".into()))
        .unwrap();
    monitor.activate(7);
    let io = Punit::new();
    monitor.service_mmio(7, narf_time::monotonic_ns(), &io, || true);
    let reads = io.reads.borrow().len();
    assert_eq!(
        node.attr_show("energy1_input").as_deref(),
        Some("2000000\n")
    );
    assert_eq!(
        node.attr_show("energy2_input").as_deref(),
        Some("1000000\n")
    );
    assert!(!node.attr_is_writable("energy1_input"));
    assert!(node.attr_store("energy2_input", b"0").is_none());
    assert_eq!(io.reads.borrow().len(), reads);
    monitor.close();
    assert_eq!(node.attr_show("energy2_input").as_deref(), Some(""));
    assert!(class.remove_child(node.name()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pmt_real_sysfs_is_card_scoped_read_only_cached_and_closes
);
