//! Native real-sysfs PSYS controls through the shared MMIO firmware actor.
//! Literal vectors: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_hwmon.c, xe_pcode_api.h and regs/xe_mchbar_regs.h.
use super::*;
use narf_filesystem::sysfs::Kobject;

const CARD_FW: [u32; 2] = [0x5a54_8960, 0x2456_8c80]; //300W/400W,1250/2500ms
const CARD_READ_FW: u32 = 0x01067c;
const CARD_READ: u32 = 0x067c;
const CARD_WRITE: u32 = 0x077c;

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
fn ready(card: u32, defaults: Option<[u32; 2]>) -> (Published, Firmware, u64) {
    let f = Published::new(card, GtPlatform::Battlemage);
    let fw = Firmware::new();
    fw.card_defaults.set(defaults);
    fw.i1.set(Some(0x8000_7d00));
    let mut now = narf_time::monotonic_ns().saturating_sub(1_000_000);
    fw.defaults_ready(&f.monitor, 7, &mut now);
    (f, fw, now)
}
fn writes(fw: &Firmware) -> Vec<[u32; 2]> {
    fw.commands
        .borrow()
        .iter()
        .filter_map(|&(cmd, pair)| (cmd == CARD_WRITE).then_some(pair))
        .collect()
}
fn advance(f: &Published, fw: &Firmware, epoch: u64, now: &mut u64, steps: usize) {
    for _ in 0..steps {
        fw.step(&f.monitor, epoch, now);
    }
}
fn apply(f: &Published, fw: &Firmware, now: &mut u64, name: &str, value: &[u8]) {
    f.store(name, value).unwrap();
    advance(f, fw, 7, now, 6);
}

fn smoke_hwmon_psys_real_sysfs_units_cached_defaults_and_optional_support() -> TestResult {
    let (f, fw, _) = ready(1140, Some(CARD_FW));
    assert_eq!(
        fw.commands.borrow().iter().map(|c| c.0).collect::<Vec<_>>(),
        [0x047d, 0x25, READ_FW, 0x047c, CARD_READ_FW]
    );
    let reads = fw.hw.reads.borrow().len();
    for (name, value) in [
        ("power1_label", "card\n"),
        ("power1_max_default", "300000000\n"),
        ("power1_max_max", "300000000\n"),
        ("power1_cap_default", "400000000\n"),
        ("power1_cap_max", "400000000\n"),
        ("power1_max_min", "125000\n"),
        ("power1_cap_min", "125000\n"),
        ("power1_max_interval_min", "1\n"),
        ("power1_cap_interval_max", "256000\n"),
        ("power1_max_status", "default-only\n"),
        ("power1_cap_status", "default-only\n"),
        ("power2_max_default", "200000000\n"),
        ("power1_crit", "500000000\n"),
    ] {
        assert_eq!(f.show(name), value, "{name}");
        assert_eq!(f.node.attr_is_writable(name), name == "power1_crit");
    }
    for name in [
        "power1_max",
        "power1_cap",
        "power1_max_interval",
        "power1_cap_interval",
    ] {
        assert_eq!(f.show(name), "");
        assert!(f.node.attr_is_writable(name));
    }
    assert_eq!(
        fw.hw.reads.borrow().len(),
        reads,
        "cached sysfs read performed MMIO"
    );
    assert!(writes(&fw).is_empty());
    assert!(fw.writes().is_empty());
    drop(f);
    let (f, fw, _) = ready(1140, None);
    assert_eq!(f.show("power1_max_default"), "");
    assert_eq!(f.show("power1_max_status"), "failed 0 Status(1)\n");
    assert_eq!(f.show("power2_max_default"), "200000000\n");
    assert_eq!(f.show("i1_status"), "ready\n");
    assert!(writes(&fw).is_empty());
    drop(f);
    let f = Published::new(1140, GtPlatform::Alchemist);
    assert!(f.node.attr_show("power1_max").is_none());
    assert!(f.node.attr_show("power1_cap_interval").is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_real_sysfs_units_cached_defaults_and_optional_support
);

fn smoke_hwmon_psys_admin_bounds_quantization_and_status_is_not_readback() -> TestResult {
    let (f, fw, mut now) = ready(1141, Some(CARD_FW));
    {
        let _deny = Admin::deny();
        for name in [
            "power1_max",
            "power1_cap",
            "power1_max_interval",
            "power1_cap_interval",
        ] {
            assert_eq!(f.store(name, b"1000"), Err(FsError::OperationNotPermitted));
        }
    }
    let _admin = Admin::allow();
    for value in [
        "0",
        "124999",
        "300000001",
        "18446744073709551615",
        "-1",
        "+1",
        "0x10",
        "1 2",
        "",
    ] {
        assert_eq!(
            f.store("power1_max", value.as_bytes()),
            Err(FsError::InvalidData),
            "{value}"
        );
    }
    f.store("power1_max", b"150062500").unwrap();
    assert_eq!(f.show("power1_max_status"), "queued 1\n");
    assert_eq!(f.store("power1_cap", b"350000000"), Err(FsError::Busy));
    advance(&f, &fw, 7, &mut now, 4);
    assert_eq!(writes(&fw), [[0x5a54_84b1, CARD_FW[1]]]);
    assert_eq!(f.show("power1_max_status"), "applying 1\n");
    assert_eq!(f.show("power1_max"), "");
    advance(&f, &fw, 7, &mut now, 2);
    assert_eq!(f.show("power1_max_status"), "applied 1\n");
    assert_eq!(f.show("power1_max"), "150125000\n");
    assert_eq!(f.show("power1_cap"), "400000000\n");
    assert_eq!(f.show("power1_max_default"), "300000000\n");
    assert_eq!(
        fw.commands.borrow()[5..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        [CARD_READ_FW, CARD_WRITE, CARD_READ]
    );
    assert_eq!(
        fw.current.get(),
        [0; 2],
        "card command modified package policy"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_admin_bounds_quantization_and_status_is_not_readback
);

fn smoke_hwmon_psys_pl2_and_interval_exact_rmw_preserves_independent_words() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = ready(1142, Some(CARD_FW));
    for name in ["power1_max_interval", "power1_cap_interval"] {
        for value in ["0", "256001", "18446744073709551615"] {
            assert_eq!(f.store(name, value.as_bytes()), Err(FsError::InvalidData));
        }
    }
    apply(&f, &fw, &mut now, "power1_cap", b"350000000");
    assert_eq!(fw.card_current.get(), [CARD_FW[0], 0x2456_8af0]);
    assert_eq!(f.show("power1_cap"), "350000000\n");
    apply(&f, &fw, &mut now, "power1_max_interval", b"625");
    assert_eq!(fw.card_current.get(), [0x5a52_8960, 0x2456_8af0]);
    assert_eq!(f.show("power1_max_interval"), "625\n");
    assert_eq!(f.show("power1_cap_interval"), "2500\n");
    apply(&f, &fw, &mut now, "power1_cap_interval", b"3000");
    assert_eq!(fw.card_current.get(), [0x5a52_8960, 0x2496_8af0]);
    assert_eq!(f.show("power1_cap_interval"), "3000\n");
    assert_eq!(f.show("power1_max"), "300000000\n");
    assert_eq!(writes(&fw).len(), 3);
    assert!(fw.writes().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_pl2_and_interval_exact_rmw_preserves_independent_words
);

fn smoke_hwmon_psys_bad_defaults_sibling_bounds_and_staleness_refuse_writes() -> TestResult {
    let _admin = Admin::allow();
    for defaults in [[0; 2], [0x8000, 0x8000], [u32::MAX; 2]] {
        let (f, fw, _) = ready(1143, Some(defaults));
        assert_eq!(f.show("power1_max"), "");
        assert_eq!(f.show("power1_max_default"), "");
        assert!(f.store("power1_max", b"100000000").is_err());
        assert!(writes(&fw).is_empty());
    }
    let (f, fw, mut now) = ready(1143, Some([CARD_FW[0], 0]));
    assert_eq!(f.show("power1_cap_default"), "");
    assert_eq!(
        f.store("power1_cap", b"100000000"),
        Err(FsError::Unsupported)
    );
    apply(&f, &fw, &mut now, "power1_max", b"150000000");
    fw.card_current.set([0x5a54_84b0, CARD_FW[1]]); // firmware enabled an unqualified sibling
    f.store("power1_max", b"125000000").unwrap();
    advance(&f, &fw, 7, &mut now, 2);
    assert_eq!(f.show("power1_max_status"), "failed 2 Bounds\n");
    assert_eq!(writes(&fw).len(), 1);
    drop(f);
    let (f, fw, now) = ready(1143, Some(CARD_FW));
    assert_eq!(
        f.monitor.show("power1_max_default", now + MAX_AGE_NS + 1),
        ""
    );
    assert_eq!(
        f.monitor
            .card_power
            .store_attribute("power1_max", b"150000000", now + MAX_AGE_NS + 1),
        Err(FsError::NoDevice)
    );
    assert!(writes(&fw).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_bad_defaults_sibling_bounds_and_staleness_refuse_writes
);

fn smoke_hwmon_psys_read_write_status_clamp_and_whole_pair_verify_fail_closed() -> TestResult {
    let _admin = Admin::allow();
    for failure in 0..4 {
        let (f, fw, mut now) = ready(1144, Some(CARD_FW));
        let start = fw.commands.borrow().len();
        match failure {
            0 => fw.error.set(Some((start, 3))),
            1 => fw.error.set(Some((start + 1, 6))),
            2 => fw.card_clamp.set(true),
            _ => {}
        }
        f.store("power1_max", b"150000000").unwrap();
        if failure == 3 {
            advance(&f, &fw, 7, &mut now, 4);
            let mut pair = fw.card_current.get();
            pair[1] ^= 1;
            fw.card_current.set(pair);
            advance(&f, &fw, 7, &mut now, 2);
        } else {
            advance(&f, &fw, 7, &mut now, if failure == 0 { 2 } else { 6 });
        }
        let expected = match failure {
            0 => "failed 1 Status(3)\n",
            1 => "failed 1 Status(6)\n",
            _ => "failed 1 Readback\n",
        };
        assert_eq!(f.show("power1_max_status"), expected);
        assert_eq!(f.show("power1_cap"), "");
        assert_eq!(writes(&fw).len(), usize::from(failure != 0));
        assert_eq!(f.show("power2_max_default"), "200000000\n");
        assert_eq!(f.show("i1_status"), "ready\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_read_write_status_clamp_and_whole_pair_verify_fail_closed
);

fn smoke_hwmon_psys_each_post_reply_access_loss_revokes_all_between_tick_caches() -> TestResult {
    let _admin = Admin::allow();
    for stage in 0..6 {
        for denied in 1..=if stage == 3 { 1 } else { 4 } {
            let (f, fw, mut now) = ready(1145, Some(CARD_FW));
            f.store("power1_max", b"150000000").unwrap();
            advance(&f, &fw, 7, &mut now, stage);
            fw.tick();
            let mut checks = 0;
            f.monitor.service_mmio(7, now, &fw, || {
                checks += 1;
                checks < denied
            });
            assert_eq!(checks, denied, "stage{stage}");
            assert_eq!(
                f.show("power1_max_status"),
                "failed 1 Access\n",
                "stage{stage} access{denied}"
            );
            assert_eq!(f.show("power2_max_default"), "");
            assert_eq!(f.show("power2_max_status"), "failed 0 Access\n");
            assert_eq!(f.show("i1_status"), "failed 0 Access\n");
            assert_eq!(f.show("temp2_input"), "");
            assert_eq!(f.show("power1_cap_default"), "");
            let writes = fw.commands.borrow().len();
            f.monitor.service_mmio(7, now + 1, &fw, || true);
            assert_eq!(
                fw.commands.borrow().len(),
                writes,
                "known loss reused shared port"
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_each_post_reply_access_loss_revokes_all_between_tick_caches
);

fn smoke_hwmon_psys_close_all_stages_retains_ceilings_and_never_replays_source() -> TestResult {
    let _admin = Admin::allow();
    for steps in 0..=5 {
        let (f, fw, mut now) = ready(1146, Some(CARD_FW));
        apply(&f, &fw, &mut now, "power1_max", b"150000000");
        f.store("power1_cap_interval", b"3000").unwrap();
        advance(&f, &fw, 7, &mut now, steps);
        f.monitor.close();
        fw.tick();
        assert_eq!(f.show("power1_cap_status"), "failed 2 Closed\n");
        let count = writes(&fw).len();
        f.monitor.activate(8);
        f.monitor
            .service_mmio(7, now, &fw, || panic!("stale epoch performed MMIO"));
        advance(&f, &fw, 8, &mut now, 10);
        assert_eq!(writes(&fw).len(), count);
        assert_eq!(f.show("power1_max"), "");
        assert_eq!(f.show("power1_max_default"), "300000000\n");
        assert_eq!(f.show("power1_cap_default"), "400000000\n");
        let start = fw.commands.borrow().len();
        f.store("power1_max", b"300000000").unwrap();
        advance(&f, &fw, 8, &mut now, 6);
        assert_eq!(fw.commands.borrow()[start].0, CARD_READ_FW);
        assert_eq!(f.show("power1_max"), "300000000\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_close_all_stages_retains_ceilings_and_never_replays_source
);

fn smoke_hwmon_psys_three_admin_clients_have_fair_whole_transaction_ownership() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = ready(1147, Some(CARD_FW));
    f.store("power2_max", b"100000000").unwrap();
    f.store("power1_crit", b"450000000").unwrap();
    f.store("power1_max", b"150000000").unwrap();
    advance(&f, &fw, 7, &mut now, 6);
    assert_eq!(f.show("power2_max_status"), "applied 1\n");
    f.store("power2_cap", b"250000000").unwrap(); // fresh package work cannot bypass peers
    advance(&f, &fw, 7, &mut now, 6);
    assert_eq!(f.show("i1_status"), "applied 1\n");
    f.store("power1_crit", b"400000000").unwrap();
    advance(&f, &fw, 7, &mut now, 6);
    assert_eq!(f.show("power1_max_status"), "applied 1\n");
    assert_eq!(f.show("power2_cap_status"), "queued 2\n");
    assert_eq!(f.show("i1_status"), "queued 2\n");
    assert_eq!(
        fw.commands.borrow()[5..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        [
            READ_FW,
            WRITE,
            READ,
            0x047c,
            0x057c,
            0x047c,
            CARD_READ_FW,
            CARD_WRITE,
            CARD_READ
        ]
    );
    advance(&f, &fw, 7, &mut now, 6);
    assert_eq!(f.show("power2_cap_status"), "applied 2\n");
    assert_eq!(fw.pending.get(), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_psys_three_admin_clients_have_fair_whole_transaction_ownership
);
