//! Native BMG firmware model driving Monitor::service_mmio and real sysfs.
//! Literal command/unit/mask vectors: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_hwmon.c, xe_pcode_api.h, regs/xe_mchbar_regs.h.

use super::*;

const FW: [u32; 2] = [0x5a2e_8640, 0x2468_89ab]; // PL1=200W, arbitrary PL2/window bits
const READ_FW: u32 = 0x01087c;
const READ: u32 = 0x087c;
const WRITE: u32 = 0x097c;

struct Firmware {
    hw: Hardware,
    defaults: Cell<[u32; 2]>,
    current: Cell<[u32; 2]>,
    pending: Cell<Option<(u32, [u32; 2])>>,
    commands: RefCell<Vec<(u32, [u32; 2])>>,
    error: Cell<Option<(usize, u8)>>,
    clamp: Cell<bool>,
    change_pl2: Cell<bool>,
}
impl Firmware {
    fn new() -> Self {
        Self {
            hw: Hardware::new(),
            defaults: Cell::new(FW),
            current: Cell::new([0; 2]),
            pending: Cell::new(None),
            commands: RefCell::new(Vec::new()),
            error: Cell::new(None),
            clamp: Cell::new(false),
            change_pl2: Cell::new(false),
        }
    }
    fn tick(&self) {
        let Some((command, input)) = self.pending.take() else {
            return;
        };
        let index = self.commands.borrow().len() - 1;
        let status = self
            .error
            .get()
            .filter(|&(at, _)| at == index)
            .map_or(0, |(_, error)| error);
        if status != 0 {
            self.hw.set(pcode::MAILBOX, u32::from(status));
            return;
        }
        let output = match command {
            0x047d => [2, 0],
            0x25 => [0x5f69_646e, 97],
            READ_FW => self.defaults.get(),
            READ => self.current.get(),
            WRITE => {
                let mut pair = input;
                if self.clamp.get() {
                    pair[0] += 1
                }
                if self.change_pl2.get() {
                    pair[1] ^= 1
                }
                self.current.set(pair);
                [0; 2]
            }
            _ => panic!("non-whitelisted BMG command {command:x}"),
        };
        self.hw.complete(0, output[0], output[1]); // source ABI: status only, no echo
    }
    fn step(&self, monitor: &Monitor, epoch: u64, now: &mut u64) {
        let completed = self.pending.get().is_some();
        self.tick();
        let before = self.commands.borrow().len();
        monitor.service_mmio(epoch, *now, self, || true);
        assert!(
            self.commands.borrow().len() - before <= 1,
            "multiple mailbox actions in one service"
        );
        if completed {
            assert_eq!(
                self.commands.borrow().len(),
                before,
                "completion poll also posted another command"
            );
        }
        *now += 10_000;
    }
    fn defaults_ready(&self, monitor: &Monitor, epoch: u64, now: &mut u64) {
        for _ in 0..6 {
            self.step(monitor, epoch, now);
        }
        assert_eq!(monitor.show("power2_max_status", *now), "default-only\n");
    }
    fn apply(&self, monitor: &Monitor, now: &mut u64, text: &[u8]) {
        monitor.bmg_power.store(text, *now).unwrap();
        for _ in 0..6 {
            self.step(monitor, 7, now);
        }
    }
    fn writes(&self) -> Vec<[u32; 2]> {
        self.commands
            .borrow()
            .iter()
            .filter_map(|&(cmd, data)| (cmd == WRITE).then_some(data))
            .collect()
    }
}
impl MmioWindow for Firmware {
    fn read32(&self, offset: u64) -> u32 {
        self.hw.read32(offset)
    }
    fn write32(&self, offset: u64, value: u32) {
        assert!(
            [pcode::MAILBOX, pcode::DATA0, pcode::DATA1].contains(&offset),
            "BMG direct power register write"
        );
        self.hw.writes.borrow_mut().push((offset, value));
        self.hw.set(offset, value);
        if offset == pcode::MAILBOX {
            assert!(
                self.pending.get().is_none(),
                "another client overwrote the shared pending command"
            );
            let command = value & 0x00ff_ffff;
            let input = [self.hw.get(pcode::DATA0), self.hw.get(pcode::DATA1)];
            self.commands.borrow_mut().push((command, input));
            self.pending.set(Some((command, input)));
        }
    }
}

fn smoke_hwmon_bmg_passive_defaults_and_periodic_reads_never_switch_source() -> TestResult {
    let monitor = monitor(GtPlatform::Battlemage);
    let fw = Firmware::new();
    let mut now = 0;
    fw.defaults_ready(&monitor, 7, &mut now);
    assert_eq!(
        fw.commands.borrow().iter().map(|c| c.0).collect::<Vec<_>>(),
        [0x047d, 0x25, 0x01087c]
    );
    for (name, value) in [
        ("power2_max_default", "200000000\n"),
        ("power2_max_max", "200000000\n"),
        ("power2_max_min", "125000\n"),
    ] {
        assert_eq!(monitor.show(name, now), value);
    }
    assert!(monitor.show("power2_max", now).is_empty());
    assert!(monitor.show("power2_rated_max", now).is_empty());
    // Six model steps post fan at0, thermal at20us and package at40us.
    // The package's own one-second period starts at that last post.
    now = SECOND + 39_999;
    fw.step(&monitor, 7, &mut now);
    assert_eq!(
        fw.commands.borrow().len(),
        3,
        "package period fired a nanosecond early"
    );
    assert!(fw.pending.get().is_none());
    now = SECOND + 40_000;
    fw.step(&monitor, 7, &mut now);
    assert_eq!(
        fw.commands.borrow().len(),
        4,
        "eligible refresh was never posted"
    );
    assert_eq!(fw.pending.get(), Some((READ_FW, [0; 2])));
    fw.step(&monitor, 7, &mut now);
    assert!(fw.pending.get().is_none());
    assert_eq!(fw.commands.borrow().last().unwrap().0, READ_FW);
    assert!(fw.writes().is_empty());
    assert_eq!(fw.current.get(), [0; 2]);
    assert!(!fw
        .hw
        .reads
        .borrow()
        .iter()
        .any(|r| [0x145930, 0x145934, 0x145938, PL1].contains(r)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_passive_defaults_and_periodic_reads_never_switch_source
);

fn smoke_hwmon_bmg_admin_pl1_pair_preservation_and_status_then_exact_readback() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Battlemage);
    let fw = Firmware::new();
    let mut now = 0;
    fw.defaults_ready(&monitor, 7, &mut now);
    monitor.bmg_power.store(b"100062500", now).unwrap(); // nearest .5 rounds up
    assert_eq!(monitor.show("power2_max_status", now), "queued 1\n");
    assert!(fw.writes().is_empty());
    fw.step(&monitor, 7, &mut now); // fresh source1 read
    fw.step(&monitor, 7, &mut now);
    fw.step(&monitor, 7, &mut now); // paired write posted
    assert_eq!(fw.writes(), [[0x5a2e_8321, FW[1]]]);
    fw.step(&monitor, 7, &mut now); // successful status alone is not publication
    assert_eq!(monitor.show("power2_max_status", now), "applying 1\n");
    assert!(monitor.show("power2_max", now).is_empty());
    fw.step(&monitor, 7, &mut now); // source0 read posted
    fw.step(&monitor, 7, &mut now); // exact readback
    assert_eq!(monitor.show("power2_max_status", now), "applied 1\n");
    assert_eq!(monitor.show("power2_max", now), "100125000\n");
    assert_eq!(monitor.show("power2_rated_max", now), "100125000\n");
    assert_eq!(monitor.show("power2_max_default", now), "200000000\n");
    assert_eq!(
        &fw.commands.borrow()[3..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        &[READ_FW, WRITE, READ]
    );
    fw.apply(&monitor, &mut now, b"125000000");
    assert_eq!(
        &fw.commands.borrow()[6..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        &[READ, WRITE, READ]
    );
    assert_eq!(fw.current.get(), [0x5a2e_83e8, FW[1]]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_admin_pl1_pair_preservation_and_status_then_exact_readback
);

fn smoke_hwmon_bmg_store_authority_bounds_quantization_staleness_and_single_queue() -> TestResult {
    let monitor = monitor(GtPlatform::Battlemage);
    let fw = Firmware::new();
    let mut now = 0;
    fw.defaults_ready(&monitor, 7, &mut now);
    {
        let _deny = Admin::deny();
        assert_eq!(
            monitor.bmg_power.store(b"100000000", now),
            Err(FsError::OperationNotPermitted)
        );
    }
    let _admin = Admin::allow();
    for bad in [
        "0",
        "124999",
        "200000001",
        "18446744073709551615",
        "-1",
        "+100000000",
        "1 2",
        "",
    ] {
        assert_eq!(
            monitor.bmg_power.store(bad.as_bytes(), now),
            Err(FsError::InvalidData),
            "{bad}"
        );
    }
    assert_eq!(
        monitor.bmg_power.store(b"125000", now + MAX_AGE_NS + 1),
        Err(FsError::NoDevice)
    );
    monitor.bmg_power.store(b"125000", now).unwrap();
    assert_eq!(
        monitor.bmg_power.store(b"100000000", now),
        Err(FsError::Busy)
    );
    for _ in 0..6 {
        fw.step(&monitor, 7, &mut now);
    }
    assert_eq!(monitor.show("power2_max", now), "125000\n");
    assert_eq!(fw.current.get()[0], 0x5a2e_8001);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_store_authority_bounds_quantization_staleness_and_single_queue
);

fn smoke_hwmon_bmg_shared_mailbox_serializes_discovery_background_and_control() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Battlemage);
    let fw = Firmware::new();
    let mut now = 0;
    fw.step(&monitor, 7, &mut now); // fan discovery pending
    assert_eq!(
        monitor.bmg_power.store(b"100000000", now),
        Err(FsError::NoDevice)
    );
    assert_eq!(fw.commands.borrow().len(), 1);
    monitor.service_mmio(7, now, &fw, || true); // still busy before timeout
    assert_eq!(fw.commands.borrow().len(), 1);
    for _ in 0..5 {
        fw.step(&monitor, 7, &mut now);
    }
    assert_eq!(monitor.show("power2_max_status", now), "default-only\n");
    now += SECOND; // first package post followed fan/thermal discovery
    fw.step(&monitor, 7, &mut now); // passive metadata refresh owns port
    assert_eq!(fw.commands.borrow().len(), 4);
    assert_eq!(fw.pending.get(), Some((READ_FW, [0; 2])));
    assert_eq!(
        monitor.bmg_power.store(b"100000000", now),
        Err(FsError::Busy)
    );
    fw.step(&monitor, 7, &mut now);
    fw.apply(&monitor, &mut now, b"100000000");
    assert_eq!(fw.writes().len(), 1);
    assert!(fw.pending.get().is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_shared_mailbox_serializes_discovery_background_and_control
);

fn smoke_hwmon_bmg_error_statuses_and_failed_rmw_reads_never_write() -> TestResult {
    let _admin = Admin::allow();
    for status in [1, 2, 3, 4, 6, 0x10, 0x11, 0xff] {
        let monitor = monitor(GtPlatform::Battlemage);
        let fw = Firmware::new();
        let mut now = 0;
        fw.defaults_ready(&monitor, 7, &mut now);
        fw.error.set(Some((3, status))); // fresh admin RMW read, not the metadata read
        monitor.bmg_power.store(b"100000000", now).unwrap();
        fw.step(&monitor, 7, &mut now);
        fw.tick();
        fw.hw.reads.borrow_mut().clear();
        monitor.service_mmio(7, now, &fw, || true);
        assert!(!fw.hw.reads.borrow().contains(&pcode::DATA0));
        assert!(fw.writes().is_empty(), "failed RMW read still wrote");
        assert!(monitor
            .show("power2_max_status", now)
            .starts_with("failed 1 Status("));
        assert_eq!(
            monitor.bmg_power.store(b"100000000", now),
            Err(FsError::Unsupported)
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_error_statuses_and_failed_rmw_reads_never_write
);

fn smoke_hwmon_bmg_clamp_or_changed_pl2_readback_refuses_without_false_ack() -> TestResult {
    let _admin = Admin::allow();
    for alter_pl2 in [false, true] {
        let monitor = monitor(GtPlatform::Battlemage);
        let fw = Firmware::new();
        let mut now = 0;
        fw.defaults_ready(&monitor, 7, &mut now);
        fw.clamp.set(!alter_pl2);
        fw.change_pl2.set(alter_pl2);
        fw.apply(&monitor, &mut now, b"100000000");
        assert_eq!(
            monitor.show("power2_max_status", now),
            "failed 1 Readback\n"
        );
        assert!(monitor.show("power2_max", now).is_empty());
        assert_eq!(
            monitor.bmg_power.store(b"100000000", now),
            Err(FsError::Unsupported)
        );
        let count = fw.commands.borrow().len();
        now = SECOND;
        fw.step(&monitor, 7, &mut now);
        assert_eq!(
            fw.commands.borrow().len(),
            count,
            "ambiguous write retried itself"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_clamp_or_changed_pl2_readback_refuses_without_false_ack
);

fn smoke_hwmon_bmg_power_access_loss_between_ticks_invalidates_all_and_quarantines() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Battlemage);
    let fw = Firmware::new();
    let mut now = 0;
    fw.defaults_ready(&monitor, 7, &mut now);
    fw.apply(&monitor, &mut now, b"100000000");
    assert_eq!(monitor.show("power2_max", now), "100000000\n");
    assert_eq!(monitor.show("temp2_crit", now), "100000\n");
    monitor.bmg_power.store(b"125000000", now).unwrap();
    fw.step(&monitor, 7, &mut now); // source0 RMW read pending
    fw.tick();
    let mut checks = 0;
    monitor.service_mmio(7, now, &fw, || {
        checks += 1;
        checks < 2
    });
    assert_eq!(monitor.show("power2_max_status", now), "failed 2 Access\n");
    assert_eq!(monitor.show("telemetry_status", now), "failed Access\n");
    for name in [
        "power2_max",
        "power2_max_default",
        "temp2_input",
        "temp2_crit",
        "fan1_input",
    ] {
        assert!(
            monitor.show(name, now).is_empty(),
            "{name} survived authority loss"
        );
    }
    let posted = fw.commands.borrow().len();
    now = SECOND;
    fw.step(&monitor, 7, &mut now);
    assert_eq!(fw.commands.borrow().len(), posted);
    assert!(monitor.show("power2_max", now).is_empty());
    assert_eq!(fw.writes().len(), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_power_access_loss_between_ticks_invalidates_all_and_quarantines
);

fn smoke_hwmon_bmg_power_foreign_busy_timeout_identity_and_late_reply_quarantine() -> TestResult {
    let _admin = Admin::allow();
    for (case, reason) in [(0, "ForeignBusy"), (1, "Timeout"), (2, "Identity")] {
        let monitor = monitor(GtPlatform::Battlemage);
        let fw = Firmware::new();
        let mut now = 0;
        fw.defaults_ready(&monitor, 7, &mut now);
        monitor.bmg_power.store(b"100000000", now).unwrap();
        if case == 0 {
            fw.hw.set(pcode::MAILBOX, 0x8000_9911);
            monitor.service_mmio(7, now, &fw, || true);
        } else {
            fw.step(&monitor, 7, &mut now); // owned admin read posted
            if case == 1 {
                now += 1_000_000
            } else {
                fw.hw.set(pcode::MAILBOX, 0x8002_087c)
            }
            monitor.service_mmio(7, now, &fw, || true);
            fw.tick(); // old response is now idle, but must never be consumed
        }
        assert_eq!(
            monitor.show("power2_max_status", now),
            format!("failed 1 {reason}\n")
        );
        assert_eq!(
            monitor.show("telemetry_status", now),
            format!("failed {reason}\n")
        );
        assert!(fw.writes().is_empty());
        let posted = fw.commands.borrow().len();
        fw.hw.reads.borrow_mut().clear();
        monitor.service_mmio(7, now + 1, &fw, || true);
        assert_eq!(fw.commands.borrow().len(), posted);
        assert!(!fw.hw.reads.borrow().contains(&pcode::DATA0));
        assert!(monitor.show("power2_max", now + 1).is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_power_foreign_busy_timeout_identity_and_late_reply_quarantine
);

fn smoke_hwmon_bmg_reset_discards_pending_source_and_retains_firmware_boot_ceiling() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Battlemage);
    let fw = Firmware::new();
    let mut now = 0;
    fw.defaults_ready(&monitor, 7, &mut now);
    fw.apply(&monitor, &mut now, b"100000000");
    monitor.bmg_power.store(b"125000000", now).unwrap();
    fw.step(&monitor, 7, &mut now); // pending source0 read
    monitor.close();
    fw.tick(); // late old reply must not restore ownership
    assert_eq!(monitor.show("power2_max_status", now), "failed 2 Closed\n");
    let count = fw.commands.borrow().len();
    monitor.service_mmio(7, now, &fw, || panic!("closed owner touched PCI"));
    assert_eq!(fw.commands.borrow().len(), count);
    monitor.activate(8);
    fw.defaults.set([0x5a2e_8320, FW[1]]); // even lowered subsequent firmware observation is not original ceiling
    now = SECOND;
    fw.defaults_ready(&monitor, 8, &mut now);
    assert_eq!(
        fw.writes().len(),
        1,
        "activation replayed policy/source switch"
    );
    assert!(monitor.show("power2_max", now).is_empty());
    assert_eq!(monitor.show("power2_max_default", now), "200000000\n");
    assert_eq!(monitor.show("power2_max_max", now), "200000000\n");
    monitor.bmg_power.store(b"200000000", now).unwrap();
    for _ in 0..6 {
        fw.step(&monitor, 8, &mut now);
    }
    assert_eq!(fw.commands.borrow()[count + 3].0, READ_FW);
    assert_eq!(monitor.show("power2_max", now), "200000000\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_reset_discards_pending_source_and_retains_firmware_boot_ceiling
);

fn smoke_hwmon_bmg_disabled_invalid_metadata_and_write_error_are_explicit() -> TestResult {
    let _admin = Admin::allow();
    for pair in [[FW[0] & !(1 << 15), FW[1]], [0, FW[1]], [u32::MAX; 2]] {
        let monitor = monitor(GtPlatform::Battlemage);
        let fw = Firmware::new();
        fw.defaults.set(pair);
        let mut now = 0;
        for _ in 0..6 {
            fw.step(&monitor, 7, &mut now);
        }
        assert!(monitor.show("power2_max_default", now).is_empty());
        assert_eq!(monitor.show("temp2_input", now), "71000\n");
        assert!(fw.writes().is_empty());
    }
    let monitor = monitor(GtPlatform::Battlemage);
    let fw = Firmware::new();
    let mut now = 0;
    fw.defaults_ready(&monitor, 7, &mut now);
    fw.error.set(Some((4, 6))); // firmware Locked on the actual write
    fw.apply(&monitor, &mut now, b"100000000");
    assert_eq!(
        monitor.show("power2_max_status", now),
        "failed 1 Status(6)\n"
    );
    assert!(monitor.show("power2_max", now).is_empty());
    assert_eq!(
        fw.commands.borrow().len(),
        5,
        "write error incorrectly queued a verify/source switch"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_disabled_invalid_metadata_and_write_error_are_explicit
);

fn smoke_hwmon_bmg_real_sysfs_uses_cached_default_only_and_admin_queue() -> TestResult {
    let monitor = Monitor::register(990, GtPlatform::Battlemage).unwrap();
    let class = class_register("hwmon");
    let node = class
        .child_names()
        .iter()
        .filter_map(|name| class.get_child(name))
        .find(|n| n.get_symlink("device") == Some("/sys/class/drm/card990/device".into()))
        .unwrap();
    let fw = Firmware::new();
    monitor.activate(7);
    let mut now = narf_time::monotonic_ns().saturating_sub(100_000);
    fw.defaults_ready(&monitor, 7, &mut now);
    assert!(node.attr_is_writable("power2_max"));
    assert!(!node.attr_is_writable("power2_max_default"));
    assert_eq!(node.attr_show("power2_max").as_deref(), Some(""));
    assert_eq!(
        node.attr_show("power2_max_default").as_deref(),
        Some("200000000\n")
    );
    {
        let _deny = Admin::deny();
        assert_eq!(
            node.attr_store("power2_max", b"100000000"),
            Some(Err(FsError::OperationNotPermitted))
        );
    }
    let _admin = Admin::allow();
    assert_eq!(node.attr_store("power2_max", b"100000000"), Some(Ok(())));
    assert!(fw.writes().is_empty());
    assert_eq!(
        node.attr_show("power2_max_status").as_deref(),
        Some("queued 1\n")
    );
    monitor.close();
    assert_eq!(
        node.attr_store("power2_max", b"100000000"),
        Some(Err(FsError::NoDevice))
    );
    assert!(class.remove_child(node.name()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_real_sysfs_uses_cached_default_only_and_admin_queue
);
