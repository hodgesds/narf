//! Linux k10temp register vectors and an ECAM transport fixture.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn pci_device(segment: u16, bus: u8, slot: u8, func: u8, id: u16, phys: u64) -> BusDevice {
    let addr = narf_bus::PcieAddr::new(segment, bus, slot, func);
    BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        id: narf_bus::DeviceId {
            vendor: AMD_VENDOR,
            device: id,
            class: 0x060000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr,
            cfg_phys: PhysAddr::new(phys),
        },
    }
}

fn smoke_k10temp_root_is_host_bridge() -> TestResult {
    let df = pci_device(0, 0, 0x18, 3, 0x14e3, 0x8000);
    let root = pci_device(0, 0, 0, 0, 0x14d8, 0x4000);
    let wrong_segment = pci_device(1, 0, 0, 0, 0x14d8, 0xc000);
    let wrong_bus = pci_device(0, 1, 0, 0, 0x14d8, 0x10000);
    let mut wrong_vendor = root;
    wrong_vendor.id.vendor = 0x8086;
    let mut wrong_class = root;
    wrong_class.id.class = 0x060400;
    let candidates = [
        df,
        wrong_segment,
        wrong_bus,
        wrong_vendor,
        wrong_class,
        root,
    ];
    if smn_root(&df, &candidates).map(|r| r.addr) != Some(root.addr) {
        return TestResult::Fail("SMN must use same-segment D0F0 AMD host bridge");
    }
    if smn_root(&df, &candidates[..5]).is_some() {
        return TestResult::Fail("SMN guessed a root from unrelated functions");
    }
    let other_node = pci_device(0, 0, 0x19, 3, 0x14e3, 0x14000);
    if smn_root(&other_node, &candidates).is_some() {
        return TestResult::Fail("unsupported Data Fabric node aliased node zero");
    }
    for id in [0x1448, 0x144a, 0x14b5, 0x14e8, 0x14f4, 0x1590] {
        if chip_info(id).is_some() {
            return TestResult::Fail("legacy non-DF3 IDs must not bind k10temp");
        }
    }
    for id in [0x144b, 0x166d, 0x167c, 0x14e3, 0x14f3, 0x16fb] {
        if chip_info(id).is_none() {
            return TestResult::Fail("supported Linux DF3 ID missing");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/k10temp", smoke_k10temp_root_is_host_bridge);

fn smoke_k10temp_linux_temperature_encodings() -> TestResult {
    // Literal register vectors: CurTemp=800 counts (100 C); bit 19 or
    // TjSel=3 applies the 49 C bias. A single TjSel bit must not apply it.
    for (raw, offset, want) in [
        (0x64000000, 0, 100_000),
        (0x64080000, 0, 51_000),
        (0x64030000, 0, 51_000),
        (0x640b0000, 0, 51_000),
        (0x64010000, 0, 100_000),
        (0x64020000, 0, 100_000),
        (0x64080000, 1000, 50_000),
    ] {
        if raw_to_mc(raw, offset) != want {
            return TestResult::Fail("package temperature range/offset decoding");
        }
    }
    for (raw, want) in [
        (0x00000ad4, Some(41_500)),
        (0x00000b20, Some(51_000)),
        (0x00000800, Some(-49_000)),
        (0xfffffad4, Some(41_500)),
        (0x000002d4, None),
        (0, None),
        (u32::MAX, None),
    ] {
        if ccd_to_mc(raw) != want {
            return TestResult::Fail("CCD validity, payload or 49 C bias decoding");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/k10temp",
    smoke_k10temp_linux_temperature_encodings
);

fn smoke_k10temp_discovers_only_valid_ccds() -> TestResult {
    let chip = chip_info(0x14e3).unwrap();
    let mut addresses = Vec::new();
    let mask = discover_ccds(chip, |addr| {
        addresses.push(addr);
        match addr {
            0x59b08 => Some(0xad4),    // valid CCD 1
            0x59b0c => Some(u32::MAX), // error must not pass valid-bit test
            0x59b10 => Some(0xb20),    // valid CCD 3
            0x59b14 => None,
            _ => Some(0),
        }
    });
    if mask != 5
        || addresses
            != [
                0x59b08, 0x59b0c, 0x59b10, 0x59b14, 0x59b18, 0x59b1c, 0x59b20, 0x59b24,
            ]
    {
        return TestResult::Fail("Raphael CCD address/discovery mismatch");
    }
    let mut sensor = K10temp::new(0, 0x18, 3, chip);
    sensor.ccd_present = mask;
    if sensor.list_labels() != ["Tctl", "Tccd1", "Tccd3"] {
        return TestResult::Fail("unavailable CCD or duplicate Tdie published");
    }
    let mut reads = 0;
    discover_ccds(chip_info(0x16fb).unwrap(), |_| {
        reads += 1;
        None
    });
    if reads != 0 {
        return TestResult::Fail("unverified Strix CCD addresses accessed");
    }
    for (id, address) in [
        (0x144b, 0x59954),
        (0x166d, 0x59954),
        (0x167c, 0x59b00),
        (0x14f3, 0x59b08),
    ] {
        let mut first = None;
        discover_ccds(chip_info(id).unwrap(), |addr| {
            first.get_or_insert(addr);
            None
        });
        if first != Some(address) {
            return TestResult::Fail("client-family CCD offset mismatch");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/k10temp",
    smoke_k10temp_discovers_only_valid_ccds
);

fn smoke_k10temp_ecam_to_hwmon_live_read() -> TestResult {
    use alloc::sync::Arc;
    let mut root_cfg = alloc::vec![0u32; 1024];
    let mut df_cfg = alloc::vec![0u32; 1024];
    root_cfg[0x64 / 4] = 0x64080000; // 51 C Tctl, no CCD valid bit
    df_cfg[0x60 / 4] = 0xdeadbeef;
    let root_phys = PhysAddr::new(0x4000);
    // SAFETY: aligned 4 KiB RAM arrays outlive the scoped ECAM override.
    let _windows = unsafe {
        narf_bus::ecam::__test_windows(&[
            (root_phys, root_cfg.as_mut_ptr().cast(), 4096),
            (PhysAddr::new(0x8000), df_cfg.as_mut_ptr().cast(), 4096),
        ])
    };
    let df = pci_device(0, 0, 0x18, 3, 0x14e3, 0x8000);
    let root = pci_device(0, 0, 0, 0, 0x14d8, 0x4000);
    let chosen = smn_root(&df, &[df, root]).unwrap();
    let BusKind::Pcie { cfg_phys, .. } = chosen.kind else {
        return TestResult::Fail("root not PCI");
    };
    let mut sensor = K10temp::new(0, 0x18, 3, chip_info(0x14e3).unwrap()).with_cfg_phys(cfg_phys);
    if sensor.read_temp("Tctl") != Some(51_000)
        || sensor.read_temp("Tdie") != Some(51_000)
        || root_cfg[0x60 / 4] != 0x59800
        || df_cfg[0x60 / 4] != 0xdeadbeef
    {
        return TestResult::Fail("temperature read used wrong config function/register");
    }
    // Inject discovery results from an indexed SMN model; the ECAM fixture
    // below supplies the data word for each individual live read.
    sensor.ccd_present = discover_ccds(sensor.chip, |addr| {
        if addr == 0x59b08 {
            Some(0xad4)
        } else {
            None
        }
    });
    root_cfg[0x64 / 4] = 0xad4;
    if sensor.read_temp("Tccd1") != Some(41_500)
        || root_cfg[0x60 / 4] != 0x59b08
        || sensor.read_temp("Tccd2").is_some()
    {
        return TestResult::Fail("live CCD register selection/read");
    }
    root_cfg[0x64 / 4] = 0x2d4;
    if sensor.read_temp("Tccd1").is_some() {
        return TestResult::Fail("CCD lost valid bit but still returned a temperature");
    }
    narf_filesystem::sysfs::__reset_for_test();
    registry::__reset_devices_for_test();
    registry::register_device(Arc::new(sensor));
    crate::sysfs_bridge::populate_hwmon_class();
    narf_filesystem::sysfs::populate_hwmon(); // refresh after device probe
    let node = narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|c| c.get_child("hwmon0"));
    let result = (|| {
        let node = node.ok_or("hwmon0 missing")?;
        root_cfg[0x64 / 4] = 0x64080000;
        if node.attr_show("name").as_deref() != Some("k10temp\n")
            || node.attr_show("temp1_input").as_deref() != Some("51000\n")
        {
            return Err("live package reading lost to sysfs placeholder");
        }
        root_cfg[0x64 / 4] = 0x65080000; // sensor changed to 52 C
        if node.attr_show("temp1_input").as_deref() != Some("52000\n") {
            return Err("sysfs cached a constant temperature");
        }
        root_cfg[0x64 / 4] = u32::MAX;
        if node.attr_show("temp1_input").as_deref() != Some("") {
            return Err("PCI error response fabricated a temperature");
        }
        Ok(())
    })();
    registry::__reset_devices_for_test();
    narf_filesystem::sysfs::__reset_for_test();
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/hwmon/k10temp",
    smoke_k10temp_ecam_to_hwmon_live_read
);
