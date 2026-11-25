//! USB sysfs smokes: root hubs, devices nested under hubs, interfaces,
//! the uevents and the /sys/bus/usb and /sys/dev/char links.

use alloc::string::String;
use alloc::sync::Arc;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::usb_sysfs::{
    self, interface_modalias, minor, publish_device_at, publish_interfaces, publish_root_hub_at,
    unpublish_device, version_text,
};
use crate::usbdev::{self, RootHub, UsbDevSpec};
use crate::xhci::PortSpeed;

const PCI: &str = "devices/pci0000:c6/0000:c6:00.4";

fn lookup(path: &str) -> Option<Arc<narf_filesystem::sysfs::Kobject>> {
    let mut k = narf_filesystem::sysfs::sysfs_root();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        k = k.get_child(part)?;
    }
    Some(k)
}

fn show(path: &str, attr: &str) -> Option<String> {
    lookup(path)?.attr_show(attr)
}

fn reset() {
    narf_filesystem::sysfs::__reset_for_test();
    usbdev::__reset_for_test();
    usb_sysfs::__reset_for_test();
}

fn yubikey() -> Arc<usbdev::UsbDev> {
    let mut descriptor = [0u8; 18];
    descriptor[0] = 18;
    descriptor[1] = 1;
    descriptor[2..4].copy_from_slice(&0x0200u16.to_le_bytes());
    descriptor[7] = 64;
    descriptor[8..10].copy_from_slice(&0x1050u16.to_le_bytes());
    descriptor[10..12].copy_from_slice(&0x0407u16.to_le_bytes());
    descriptor[12..14].copy_from_slice(&0x0571u16.to_le_bytes());
    descriptor[17] = 1;
    let mut cfg = alloc::vec![9, 2, 0, 0, 2, 1, 0, 0x80, 15];
    cfg.extend_from_slice(&[9, 4, 0, 0, 1, 3, 1, 1, 0]);
    cfg.extend_from_slice(&[9, 4, 2, 0, 3, 0x0b, 0, 0, 0]);
    let total = cfg.len() as u16;
    cfg[2..4].copy_from_slice(&total.to_le_bytes());
    usbdev::__insert_for_test(UsbDevSpec {
        controller: 3,
        slot: 2,
        busnum: 7,
        devnum: 2,
        root_port: 1,
        route: 0,
        devpath: String::from("1"),
        speed: PortSpeed::Full,
        descriptor,
        configs: alloc::vec![cfg],
        config: 1,
    })
}

fn smoke_usb_sysfs_root_hub_matches_linux() -> TestResult {
    reset();
    publish_root_hub_at(
        PCI,
        "0000:c6:00.4",
        &RootHub {
            controller: 3,
            busnum: 7,
            usb3: false,
            ports: 2,
        },
    );
    let hub = alloc::format!("{PCI}/usb7");
    let r = (|| {
        let attrs = [
            ("idVendor", "1d6b\n"),
            ("idProduct", "0002\n"),
            ("bcdDevice", "0601\n"),
            ("devnum", "1\n"),
            ("speed", "480\n"),
            ("version", " 2.00\n"),
            ("maxchild", "2\n"),
            ("serial", "0000:c6:00.4\n"),
            ("manufacturer", "Linux 6.1.0-narf xhci-hcd\n"),
            ("product", "xHCI Host Controller\n"),
        ];
        for (attr, want) in attrs {
            if show(&hub, attr).as_deref() != Some(want) {
                return Err("root hub attributes differ from Linux's");
            }
        }
        let k = lookup(&hub).ok_or("usb7 missing")?;
        let mut buf = [0u8; 64];
        let n = k.bin_attr_read("descriptors", 0, &mut buf).unwrap_or(0);
        // 18-byte device descriptor + 25-byte hub configuration.
        if n != 43 || buf[6] != 1 || buf[18 + 7] != 0xe0 || buf[18 + 22] != 4 {
            return Err("root hub descriptors: single TT, wakeup, 4-byte status endpoint");
        }
        if lookup("bus/usb/devices")
            .and_then(|d| d.get_symlink("usb7"))
            .is_none_or(|t| !t.ends_with(&hub))
        {
            return Err("/sys/bus/usb/devices/usb7 must link to the root hub");
        }
        if lookup("dev/char")
            .and_then(|d| d.get_symlink("189:768"))
            .is_none()
        {
            return Err("/sys/dev/char/189:<(bus-1)*128> must exist for the root hub");
        }
        Ok(())
    })();
    reset();
    match r {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!("drivers/usb/sysfs", smoke_usb_sysfs_root_hub_matches_linux);

fn smoke_usb_sysfs_device_and_interfaces() -> TestResult {
    reset();
    let dev = yubikey();
    publish_device_at(PCI, &dev);
    publish_interfaces(&dev);
    let path = alloc::format!("{PCI}/usb7/7-1");
    let r = (|| {
        let attrs = [
            ("busnum", "7\n"),
            ("devnum", "2\n"),
            ("devpath", "1\n"),
            ("idVendor", "1050\n"),
            ("idProduct", "0407\n"),
            ("bcdDevice", "0571\n"),
            ("speed", "12\n"),
            ("version", " 2.00\n"),
            ("bConfigurationValue", "1\n"),
            ("bNumInterfaces", " 2\n"),
            ("bMaxPower", "30mA\n"),
        ];
        for (attr, want) in attrs {
            if show(&path, attr).as_deref() != Some(want) {
                return Err("device attributes differ from drivers/usb/core/sysfs.c");
            }
        }
        let uevent = show(&path, "uevent").ok_or("no uevent")?;
        for line in [
            "MAJOR=189",
            "MINOR=769",
            "DEVNAME=bus/usb/007/002",
            "DEVTYPE=usb_device",
            "PRODUCT=1050/407/571",
            "TYPE=0/0/0",
            "BUSNUM=007",
            "DEVNUM=002",
        ] {
            if !uevent.lines().any(|l| l == line) {
                return Err("device uevent misses a usb_dev_uevent field");
            }
        }
        let iface = alloc::format!("{path}/7-1:1.0");
        if show(&iface, "bInterfaceClass").as_deref() != Some("03\n")
            || show(&iface, "modalias").as_deref()
                != Some("usb:v1050p0407d0571dc00dsc00dp00ic03isc01ip01in00\n")
        {
            return Err("interface attributes / modalias differ from Linux's");
        }
        if show(&alloc::format!("{path}/7-1:1.2"), "bInterfaceClass").as_deref() != Some("0b\n") {
            return Err("every interface of the active configuration is published");
        }
        let links = lookup("bus/usb/devices").ok_or("no bus/usb/devices")?;
        if links.get_symlink("7-1").is_none() || links.get_symlink("7-1:1.0").is_none() {
            return Err("/sys/bus/usb/devices must list the device and its interfaces");
        }
        // Unplug removes the kobjects and every link.
        unpublish_device(&dev);
        if lookup(&path).is_some()
            || links.get_symlink("7-1").is_some()
            || links.get_symlink("7-1:1.0").is_some()
            || lookup("dev/char")
                .and_then(|d| d.get_symlink("189:769"))
                .is_some()
        {
            return Err("unpublish must remove the device, its interfaces and links");
        }
        Ok(())
    })();
    reset();
    match r {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!("drivers/usb/sysfs", smoke_usb_sysfs_device_and_interfaces);

fn smoke_usb_sysfs_text_helpers() -> TestResult {
    if minor(1, 1) != 0 || minor(7, 2) != 769 || minor(2, 128) != 255 {
        return TestResult::Fail("usbfs minor is (bus-1)*128 + dev-1");
    }
    if version_text(0x0310) != " 3.10" || version_text(0x0110) != " 1.10" {
        return TestResult::Fail("version is bcdUSB as %2x.%02x");
    }
    let dev = yubikey();
    let i = dev.interfaces()[1];
    let m = interface_modalias(&dev, &i);
    usbdev::__reset_for_test();
    if m != "usb:v1050p0407d0571dc00dsc00dp00ic0Bisc00ip00in02" {
        return TestResult::Fail("modalias uses upper-case hex per usb_if_uevent");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/sysfs", smoke_usb_sysfs_text_helpers);
