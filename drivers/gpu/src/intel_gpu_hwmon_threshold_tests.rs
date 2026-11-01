//! Source-cited native I1/window transactions through real published sysfs
//! callbacks and Monitor::service_mmio. Literal vectors: MIT Linux
//! b90c984d615e8ce2af96f5b1411a962d83fed2ad xe_hwmon.c, xe_pcode_api.h,
//! regs/xe_mchbar_regs.h. No extracted codecs or setter-only fixtures.

use super::*;
use narf_filesystem::sysfs::Kobject;

struct Published {
    monitor: Arc<Monitor>,
    node: Arc<Kobject>,
}
impl Published {
    fn new(card: u32, platform: GtPlatform) -> Self {
        let monitor = Monitor::register(card, platform, 0).unwrap();
        let class = class_register("hwmon");
        let node = class
            .child_names()
            .iter()
            .filter_map(|name| class.get_child(name))
            .find(|node| {
                node.get_symlink("device") == Some(format!("/sys/class/drm/card{card}/device"))
            })
            .unwrap();
        monitor.activate(7);
        Self { monitor, node }
    }
    fn store(&self, name: &str, value: &[u8]) -> Result<(), FsError> {
        self.node.attr_store(name, value).unwrap()
    }
    fn show(&self, name: &str) -> String {
        self.node.attr_show(name).unwrap()
    }
}
impl Drop for Published {
    fn drop(&mut self) {
        self.monitor.close();
        assert!(class_register("hwmon").remove_child(self.node.name()));
    }
}
fn ready(card: u32, word: u32) -> (Published, Firmware, u64) {
    let published = Published::new(card, GtPlatform::Battlemage);
    let fw = Firmware::new();
    fw.i1.set(Some(word));
    let mut now = narf_time::monotonic_ns().saturating_sub(1_000_000);
    fw.defaults_ready(&published.monitor, 7, &mut now);
    assert_eq!(published.show("i1_status"), "ready\n");
    (published, fw, now)
}
fn i1_writes(fw: &Firmware) -> Vec<[u32; 2]> {
    fw.commands
        .borrow()
        .iter()
        .filter_map(|&(cmd, data)| (cmd == 0x057c).then_some(data))
        .collect()
}
fn apply(fixture: &Published, fw: &Firmware, now: &mut u64, attribute: &str, value: &[u8]) {
    fixture.store(attribute, value).unwrap();
    for _ in 0..6 {
        fw.step(&fixture.monitor, 7, now);
    }
}

fn smoke_hwmon_i1_real_sysfs_mode_units_labels_and_read_only_cache() -> TestResult {
    for (word, active, inactive, value, label) in [
        (
            0x8000_3200,
            "power1_crit",
            "curr2_crit",
            "200000000\n",
            "power1_label",
        ),
        (
            0x0000_3200,
            "curr2_crit",
            "power1_crit",
            "200000\n",
            "curr2_label",
        ),
    ] {
        let (f, fw, _) = ready(1100, word);
        let before = fw.hw.reads.borrow().len();
        assert_eq!(f.show(active), value);
        assert_eq!(f.show(inactive), "");
        assert_eq!(
            f.show(label),
            if word >> 31 != 0 { "card\n" } else { "pkg\n" }
        );
        assert_eq!(f.show(&format!("{active}_default")), value);
        assert_eq!(f.show(&format!("{active}_max")), value);
        assert_eq!(
            f.show(&format!("{active}_min")),
            if word >> 31 != 0 { "15625\n" } else { "15\n" }
        );
        assert!(f.node.attr_is_writable(active));
        assert!(!f.node.attr_is_writable(&format!("{active}_default")));
        assert_eq!(
            fw.hw.reads.borrow().len(),
            before,
            "sysfs read touched hardware"
        );
        assert!(i1_writes(&fw).is_empty(), "passive discovery changed I1");
    }
    let f = Published::new(1101, GtPlatform::Alchemist);
    assert!(f.node.attr_show("power1_crit").is_none());
    assert!(f.node.attr_show("curr2_crit").is_none());
    let hw = Hardware::new();
    f.monitor
        .service_mmio(7, narf_time::monotonic_ns(), &hw, || true);
    assert!(
        hw.writes.borrow().is_empty(),
        "DG2 queried its illegal I1 subcommand"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_real_sysfs_mode_units_labels_and_read_only_cache
);

fn smoke_hwmon_i1_sysfs_admin_parse_range_mode_quantization_and_single_queue() -> TestResult {
    let (f, fw, mut now) = ready(1102, 0x8000_3200);
    {
        let _deny = Admin::deny();
        assert_eq!(
            f.store("power1_crit", b"100000000"),
            Err(FsError::OperationNotPermitted)
        );
    }
    let _admin = Admin::allow();
    for bad in [
        &b"0"[..],
        b"15624",
        b"200000001",
        b"-1",
        b"+1",
        b"1 2",
        b"",
        b"18446744073709551615",
        &[b'1'; 33],
        &[0xff],
    ] {
        assert_eq!(f.store("power1_crit", bad), Err(FsError::InvalidData));
    }
    assert_eq!(f.store("curr2_crit", b"100000"), Err(FsError::Unsupported));
    assert_eq!(
        f.monitor
            .i1
            .store("power1_crit", b"100000000", now + MAX_AGE_NS + 1),
        Err(FsError::NoDevice)
    );
    assert_eq!(f.store("power1_crit", b"100007812"), Ok(()));
    assert_eq!(f.store("power1_crit", b"100000000"), Err(FsError::Busy));
    assert!(i1_writes(&fw).is_empty());
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    // Just below half a 15625-uW step rounds down.
    assert_eq!(i1_writes(&fw), [[0x1900, 0]]);
    assert_eq!(f.show("power1_crit"), "100000000\n");
    assert_eq!(f.show("power1_crit_default"), "200000000\n");
    let (current, amps, mut t) = ready(1103, 0x3200);
    apply(&current, &amps, &mut t, "curr2_crit", b"100008");
    assert_eq!(i1_writes(&amps), [[0x1901, 0]]);
    assert_eq!(current.show("curr2_crit"), "100015\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_sysfs_admin_parse_range_mode_quantization_and_single_queue
);

fn smoke_hwmon_i1_owned_read_write_verify_status_is_not_readback() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = ready(1104, 0x8000_3200);
    f.store("power1_crit", b"100000000").unwrap();
    assert_eq!(f.show("i1_status"), "queued 1\n");
    fw.step(&f.monitor, 7, &mut now); // fresh READ_I1
    fw.step(&f.monitor, 7, &mut now);
    fw.step(&f.monitor, 7, &mut now); // WRITE_I1, mode bit absent
    assert_eq!(i1_writes(&fw), [[0x1900, 0]]);
    fw.step(&f.monitor, 7, &mut now); // firmware accepted write, unverified
    assert_eq!(f.show("i1_status"), "applying 1\n");
    assert_eq!(f.show("power1_crit"), "");
    fw.step(&f.monitor, 7, &mut now);
    fw.step(&f.monitor, 7, &mut now);
    assert_eq!(f.show("i1_status"), "applied 1\n");
    assert_eq!(f.show("power1_crit"), "100000000\n");
    assert_eq!(
        fw.commands.borrow()[4..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        [0x047c, 0x057c, 0x047c]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_owned_read_write_verify_status_is_not_readback
);

fn smoke_hwmon_i1_clamp_and_write_mode_change_fail_closed() -> TestResult {
    let _admin = Admin::allow();
    for mode in [false, true] {
        let (f, fw, mut now) = ready(1105, 0x8000_3200);
        fw.i1_clamp.set(!mode);
        fw.i1_mode_flip.set(mode);
        apply(&f, &fw, &mut now, "power1_crit", b"100000000");
        assert_eq!(f.show("i1_status"), "failed 1 Readback\n");
        assert_eq!(f.show("power1_crit"), "");
        assert_eq!(f.show("curr2_crit"), "");
        assert_eq!(f.store("power1_crit", b"100000000"), Err(FsError::NoDevice));
        assert_eq!(fw.writes().len(), 0, "I1 touched package PL1");
        now += SECOND;
        for _ in 0..4 {
            fw.step(&f.monitor, 7, &mut now);
        }
        assert_eq!(i1_writes(&fw).len(), 1, "failed policy replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_clamp_and_write_mode_change_fail_closed
);

fn smoke_hwmon_i1_fresh_mode_and_cross_epoch_boot_identity_refuse_writes() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = ready(1106, 0x8000_3200);
    f.store("power1_crit", b"100000000").unwrap();
    fw.i1.set(Some(0x3200)); // firmware changed meaning after sysfs admission
    for _ in 0..2 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("i1_status"), "failed 1 Mode\n");
    assert!(i1_writes(&fw).is_empty());
    f.monitor.close();
    f.monitor.activate(8);
    for _ in 0..8 {
        fw.step(&f.monitor, 8, &mut now);
    }
    assert_eq!(f.show("i1_status"), "failed 0 Mode\n");
    assert_eq!(f.show("curr2_crit_default"), "");
    assert_eq!(f.store("curr2_crit", b"100000"), Err(FsError::NoDevice));
    assert!(i1_writes(&fw).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_fresh_mode_and_cross_epoch_boot_identity_refuse_writes
);

fn smoke_hwmon_i1_close_at_every_stage_discards_requests_and_retains_original_ceiling() -> TestResult
{
    let _admin = Admin::allow();
    for steps in 0..=5 {
        let (f, fw, mut now) = ready(1107, 0x8000_3200);
        apply(&f, &fw, &mut now, "power1_crit", b"100000000");
        f.store("power1_crit", b"125000000").unwrap();
        for _ in 0..steps {
            fw.step(&f.monitor, 7, &mut now);
        }
        f.monitor.close();
        fw.tick();
        assert_eq!(f.show("i1_status"), "failed 2 Closed\n");
        let writes = i1_writes(&fw).len();
        f.monitor.activate(8);
        f.monitor
            .service_mmio(7, now, &fw, || panic!("old epoch touched hardware"));
        for _ in 0..8 {
            fw.step(&f.monitor, 8, &mut now);
        }
        assert_eq!(
            i1_writes(&fw).len(),
            writes,
            "activation replayed a request"
        );
        assert_eq!(f.show("power1_crit_default"), "200000000\n");
        assert_eq!(f.show("power1_crit_max"), "200000000\n");
        f.store("power1_crit", b"200000000").unwrap();
        for _ in 0..6 {
            fw.step(&f.monitor, 8, &mut now);
        }
        assert_eq!(f.show("power1_crit"), "200000000\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_close_at_every_stage_discards_requests_and_retains_original_ceiling
);

fn smoke_hwmon_i1_every_post_and_reply_access_checks_authority_and_revokes_siblings() -> TestResult
{
    let _admin = Admin::allow();
    for reply in [false, true] {
        for denied in 1..=if reply { 3 } else { 4 } {
            let (f, fw, mut now) = ready(1108, 0x8000_3200);
            f.store("power1_crit", b"100000000").unwrap();
            if reply {
                fw.step(&f.monitor, 7, &mut now);
                fw.tick();
            }
            fw.hw.reads.borrow_mut().clear();
            fw.hw.writes.borrow_mut().clear();
            let mut checks = 0;
            f.monitor.service_mmio(7, now, &fw, || {
                checks += 1;
                checks < denied
            });
            assert_eq!(
                fw.hw.reads.borrow().len() + fw.hw.writes.borrow().len(),
                denied - 1
            );
            assert_eq!(f.show("i1_status"), "failed 1 Access\n");
            for name in [
                "power1_crit",
                "power1_crit_default",
                "power2_max_default",
                "temp2_input",
                "temp2_crit",
            ] {
                assert_eq!(f.show(name), "", "{name} survived known authority loss");
            }
            assert_eq!(f.store("power1_crit", b"100000000"), Err(FsError::NoDevice));
            let before = fw.hw.reads.borrow().len();
            f.monitor.service_mmio(7, now + 1, &fw, || true);
            assert_eq!(
                fw.hw.reads.borrow().len(),
                before,
                "denial bypassed sampling rate"
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_every_post_and_reply_access_checks_authority_and_revokes_siblings
);

struct ReplyChange<'a> {
    firmware: &'a Firmware,
    after: u64,
    mailbox: u32,
}
impl MmioWindow for ReplyChange<'_> {
    fn read32(&self, offset: u64) -> u32 {
        let value = self.firmware.read32(offset);
        if offset == self.after {
            self.firmware.hw.set(pcode::MAILBOX, self.mailbox);
        }
        value
    }
    fn write32(&self, offset: u64, value: u32) {
        self.firmware.write32(offset, value)
    }
}

fn smoke_hwmon_pcode_final_reply_read_distinguishes_access_and_readable_identity_loss() -> TestResult
{
    let _admin = Admin::allow();
    for pair in [false, true] {
        for case in 0..3 {
            let (f, fw, mut now) = ready(1117, 0x8000_3200);
            let (attribute, status) = if pair {
                ("power2_max", "power2_max_status")
            } else {
                ("power1_crit", "i1_status")
            };
            f.store(attribute, b"100000000").unwrap();
            fw.step(&f.monitor, 7, &mut now);
            fw.tick();
            let io = ReplyChange {
                firmware: &fw,
                after: if pair { pcode::DATA1 } else { pcode::DATA0 },
                mailbox: match case {
                    0 => 0,
                    1 => u32::MAX,
                    _ => 0x8000_9911,
                },
            };
            fw.hw.reads.borrow_mut().clear();
            let reads = if pair { 4 } else { 3 };
            let mut checks = 0;
            f.monitor.service_mmio(7, now, &io, || {
                checks += 1;
                case != 0 || checks < reads
            });
            assert_eq!(fw.hw.reads.borrow().len(), reads - usize::from(case == 0));
            let reason = if case == 2 { "Identity" } else { "Access" };
            assert_eq!(f.show(status), format!("failed 1 {reason}\n"));
            assert_eq!(f.show("telemetry_status"), format!("failed {reason}\n"));
            for name in ["power1_crit", "power1_crit_default", "power2_max_default"] {
                assert_eq!(f.show(name), "", "{name} survived shared-port loss");
            }
            assert_eq!(
                f.show("temp2_input"),
                if case == 0 { "" } else { "71000\n" }
            );
            assert!(i1_writes(&fw).is_empty());
            assert!(fw.writes().is_empty());
            let posted = fw.commands.borrow().len();
            fw.hw.complete(0, 0x8000_3200, FW[1]);
            f.monitor.service_mmio(7, now + 1, &fw, || true);
            assert_eq!(
                fw.commands.borrow().len(),
                posted,
                "late reply reopened port"
            );
            assert_eq!(f.show(status), format!("failed 1 {reason}\n"));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_pcode_final_reply_read_distinguishes_access_and_readable_identity_loss
);

fn smoke_hwmon_i1_shared_port_serializes_admin_clients_and_quarantines_both() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = ready(1109, 0x8000_3200);
    f.store("power1_crit", b"100000000").unwrap();
    f.store("power2_max", b"125000000").unwrap();
    for _ in 0..12 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("power1_crit"), "100000000\n");
    assert_eq!(f.show("power2_max"), "125000000\n");
    assert_eq!(
        fw.commands.borrow()[4..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        [READ_FW, WRITE, READ, 0x047c, 0x057c, 0x047c]
    );
    f.store("power1_crit", b"125000000").unwrap();
    fw.hw.set(pcode::MAILBOX, 0x8000_9911);
    f.monitor.service_mmio(7, now, &fw, || true);
    assert_eq!(f.show("i1_status"), "failed 2 ForeignBusy\n");
    assert_eq!(f.show("power2_max"), "");
    assert_eq!(
        f.store("power2_max", b"100000000"),
        Err(FsError::Unsupported)
    );
    fw.hw.complete(0, 0x8000_3200, 0); // unrelated late idle reply
    let posted = fw.commands.borrow().len();
    f.monitor.service_mmio(7, now + 1, &fw, || true);
    assert_eq!(fw.commands.borrow().len(), posted);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_shared_port_serializes_admin_clients_and_quarantines_both
);

fn smoke_hwmon_i1_queued_peer_wins_over_requeued_pl1_at_transaction_boundary() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = ready(1116, 0x8000_3200);
    f.store("power2_max", b"125000000").unwrap();
    f.store("power1_crit", b"100000000").unwrap();
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("power2_max_status"), "applied 1\n");
    assert_eq!(f.show("i1_status"), "queued 1\n");
    // A continuous PL1 client immediately has more work ready. The I1
    // transaction must finish first and retain its read/write/verify order.
    f.store("power2_max", b"100000000").unwrap();
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("i1_status"), "applied 1\n");
    assert_eq!(f.show("power1_crit"), "100000000\n");
    assert_eq!(f.show("power2_max_status"), "queued 2\n");
    assert_eq!(
        fw.commands.borrow()[4..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        [READ_FW, WRITE, READ, 0x047c, 0x057c, 0x047c]
    );
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("power2_max_status"), "applied 2\n");
    assert_eq!(f.show("power2_max"), "100000000\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_queued_peer_wins_over_requeued_pl1_at_transaction_boundary
);

fn smoke_hwmon_i1_status_zero_allones_and_passive_interval_have_no_false_measurement() -> TestResult
{
    for invalid in [None, Some(0), Some(u32::MAX)] {
        let f = Published::new(1110, GtPlatform::Battlemage);
        let fw = Firmware::new();
        fw.i1.set(invalid);
        let mut now = narf_time::monotonic_ns().saturating_sub(1_000_000);
        fw.defaults_ready(&f.monitor, 7, &mut now);
        assert_eq!(f.show("power1_crit"), "");
        assert_eq!(f.show("curr2_crit"), "");
        assert!(f.show("i1_status").starts_with("failed 0 "));
        assert_eq!(f.show("power2_max_default"), "200000000\n");
        assert!(i1_writes(&fw).is_empty());
    }
    let (f, fw, mut now) = ready(1111, 0x8000_3200);
    let posted = fw.commands.borrow()[3];
    assert_eq!(posted.0, 0x047c);
    let baseline = now - 20_000; // READ_I1 was posted two model steps ago
    now = baseline + SECOND - 20_000;
    fw.step(&f.monitor, 7, &mut now); // power refresh wins first
    fw.step(&f.monitor, 7, &mut now);
    now = baseline + SECOND - 1;
    let count = fw
        .commands
        .borrow()
        .iter()
        .filter(|c| c.0 == 0x047c)
        .count();
    fw.step(&f.monitor, 7, &mut now);
    assert_eq!(
        fw.commands
            .borrow()
            .iter()
            .filter(|c| c.0 == 0x047c)
            .count(),
        count
    );
    now = baseline + SECOND;
    fw.step(&f.monitor, 7, &mut now);
    assert_eq!(fw.pending.get(), Some((0x047c, [0, 0])));
    assert!(f
        .monitor
        .show("power1_crit", baseline + MAX_AGE_NS + 10_001)
        .is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_i1_status_zero_allones_and_passive_interval_have_no_false_measurement
);

fn dg2(card: u32) -> (Published, Hardware, u64) {
    let f = Published::new(card, GtPlatform::Alchemist);
    let hw = Hardware::new();
    hw.set(0x145938, 0x000a_0e03); // time unit 2^-10 seconds, power unit 2^-3W
    hw.set(PL1, 0x5a54_8640); // x1,y10 => 1250ms; other fields nonzero
    let now = narf_time::monotonic_ns();
    f.monitor.service_mmio(7, now, &hw, || true);
    (f, hw, now)
}
fn smoke_hwmon_dg2_interval_sysfs_source_units_rmw_and_shared_pl1_queue() -> TestResult {
    let _admin = Admin::allow();
    let (f, hw, now) = dg2(1112);
    assert_eq!(f.show("power2_max_interval"), "1250\n");
    assert_eq!(f.show("power2_max_interval_min"), "1\n");
    assert_eq!(f.show("power2_max_interval_max"), "256000\n");
    let original = hw.get(PL1);
    assert_eq!(f.store("power2_max_interval", b"1000"), Ok(()));
    assert_eq!(f.store("power2_max", b"100000000"), Err(FsError::Busy));
    assert!(hw.pl1_writes().is_empty(), "sysfs store performed MMIO");
    f.monitor.service_mmio(7, now + 1, &hw, || true);
    assert_eq!(hw.pl1_writes(), [0x5a14_8640]);
    assert_eq!(hw.get(PL1) & !0x00fe_0000, original & !0x00fe_0000);
    assert_eq!(f.show("power2_max_interval"), "1000\n");
    assert_eq!(f.show("power2_max_status"), "applied 1\n");
    f.store("power2_max", b"100000000").unwrap();
    assert_eq!(f.store("power2_max_interval", b"1250"), Err(FsError::Busy));
    f.monitor.service_mmio(7, now + 2, &hw, || true);
    assert_eq!(hw.get(PL1), 0x5a14_8320);
    assert!(!hw.writes.borrow().iter().any(|&(r, _)| r == pcode::MAILBOX));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_interval_sysfs_source_units_rmw_and_shared_pl1_queue
);

fn smoke_hwmon_dg2_interval_admin_bounds_units_changed_and_stale_refusal() -> TestResult {
    let (f, hw, now) = dg2(1113);
    {
        let _deny = Admin::deny();
        assert_eq!(
            f.store("power2_max_interval", b"1000"),
            Err(FsError::OperationNotPermitted)
        );
    }
    let _admin = Admin::allow();
    for bad in [
        &b"0"[..],
        b"256001",
        b"-1",
        b"+1",
        b"18446744073709551615",
        &[b'1'; 33],
    ] {
        assert_eq!(
            f.store("power2_max_interval", bad),
            Err(FsError::InvalidData)
        );
    }
    f.store("power2_max_interval", b"1000").unwrap();
    hw.set(0x145938, 0x0009_0e03);
    f.monitor.service_mmio(7, now + 1, &hw, || true);
    assert!(hw.pl1_writes().is_empty());
    assert_eq!(f.show("power2_max_status"), "failed 1 Bounds\n");
    assert_eq!(
        f.monitor
            .power
            .store_interval(b"1000", now + MAX_AGE_NS + 2),
        Err(FsError::NoDevice)
    );
    for (shift, max) in [(0, "262144000\n"), (10, "256000\n"), (15, "8000\n")] {
        let (other, registers, t) = dg2(1114);
        registers.set(0x145938, (shift << 16) | 0xe03);
        other
            .monitor
            .service_mmio(7, t + SECOND, &registers, || true);
        assert_eq!(
            other.monitor.show("power2_max_interval_max", t + SECOND),
            max
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_interval_admin_bounds_units_changed_and_stale_refusal
);

fn smoke_hwmon_dg2_interval_readback_loss_close_and_no_replay() -> TestResult {
    let _admin = Admin::allow();
    let (f, hw, now) = dg2(1115);
    f.store("power2_max_interval", b"1000").unwrap();
    hw.sticky_pl1.set(false);
    f.monitor.service_mmio(7, now + 1, &hw, || true);
    assert_eq!(f.show("power2_max_status"), "failed 1 Readback\n");
    assert_eq!(f.show("power2_max_interval"), "1250\n");
    f.store("power2_max_interval", b"1000").unwrap();
    f.monitor.close();
    assert_eq!(f.show("power2_max_status"), "failed 2 Closed\n");
    let writes = hw.pl1_writes().len();
    f.monitor.activate(8);
    f.monitor
        .service_mmio(7, now + 2, &hw, || panic!("stale interval epoch"));
    f.monitor.service_mmio(8, now + 2, &hw, || true);
    assert_eq!(
        hw.pl1_writes().len(),
        writes,
        "interval replayed after close"
    );
    f.store("power2_max_interval", b"1000").unwrap();
    let mut checks = 0;
    f.monitor.service_mmio(8, now + 3, &hw, || {
        checks += 1;
        checks < 6
    });
    assert_eq!(
        hw.pl1_writes().len(),
        writes,
        "denied interval write reached hardware"
    );
    assert_eq!(f.show("power2_max_status"), "failed 3 Access\n");
    assert_eq!(f.show("power2_max_interval"), "");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_interval_readback_loss_close_and_no_replay
);
