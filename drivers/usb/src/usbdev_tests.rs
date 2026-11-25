//! USB device registry smokes: Linux's device numbering, devpath, the
//! configuration walk and interface claims.

use alloc::string::String;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::usbdev::{
    self, alloc_devnum, devpath, free_devnum, interfaces_of, Interface, Owner, UsbDevSpec,
};
use crate::xhci::PortSpeed;

/// A configuration descriptor: header, then `(number, alt, class,
/// subclass, protocol, endpoints)` interface descriptors, each followed
/// by a dummy HID class descriptor.
fn config(value: u8, ifaces: &[(u8, u8, u8, u8, u8, u8)]) -> Vec<u8> {
    let mut c = alloc::vec![9, 2, 0, 0, ifaces.len() as u8, value, 0, 0x80, 50];
    for &(n, alt, class, sub, proto, eps) in ifaces {
        c.extend_from_slice(&[9, 4, n, alt, eps, class, sub, proto, 0]);
        c.extend_from_slice(&[9, 0x21, 0x11, 0x01, 0, 1, 0x22, 0x20, 0]);
    }
    let total = c.len() as u16;
    c[2..4].copy_from_slice(&total.to_le_bytes());
    c
}

fn smoke_usbdev_devnum_follows_choose_devnum() -> TestResult {
    usbdev::__reset_for_test();
    // Root hub holds 1; numbering starts at 2.
    let a = alloc_devnum(7);
    let b = alloc_devnum(7);
    let other_bus = alloc_devnum(8);
    if (a, b, other_bus) != (Some(2), Some(3), Some(2)) {
        usbdev::__reset_for_test();
        return TestResult::Fail("devnums must start at 2 per bus (root hub is 1)");
    }
    // A freed number is not reused until devnum_next wraps.
    free_devnum(7, 2);
    if alloc_devnum(7) != Some(4) {
        usbdev::__reset_for_test();
        return TestResult::Fail("choose_devnum continues from devnum_next, not the lowest free");
    }
    // Exhaust 5..=127, then wrap to the freed 2.
    for _ in 5..=127 {
        if alloc_devnum(7).is_none() {
            usbdev::__reset_for_test();
            return TestResult::Fail("bus ran out of devnums early");
        }
    }
    let wrapped = alloc_devnum(7);
    let full = alloc_devnum(7);
    usbdev::__reset_for_test();
    if wrapped != Some(2) || full.is_some() {
        return TestResult::Fail("after 127 choose_devnum wraps to 1.., and a full bus has none");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/usbdev",
    smoke_usbdev_devnum_follows_choose_devnum
);

fn smoke_usbdev_devpath_from_route() -> TestResult {
    let cases = [
        (1u8, 0u32, "1"),
        (2, 0x3, "2.3"),
        (2, 0x13, "2.3.1"),
        (4, 0x0f2, "4.2.15"),
    ];
    for (rh, route, want) in cases {
        if devpath(rh, route) != want {
            return TestResult::Fail("devpath must be the root-hub port then one .port per tier");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/usbdev", smoke_usbdev_devpath_from_route);

fn smoke_usbdev_interfaces_and_claims() -> TestResult {
    // A YubiKey 5 shape: OTP keyboard, FIDO, CCID; an alt setting that
    // must not be listed twice.
    let cfg = config(
        1,
        &[
            (0, 0, 3, 1, 1, 1),
            (1, 0, 3, 0, 0, 2),
            (1, 1, 3, 0, 0, 2),
            (2, 0, 0x0b, 0, 0, 3),
        ],
    );
    let ifaces = interfaces_of(&cfg);
    let want = [
        Interface {
            number: 0,
            class: 3,
            subclass: 1,
            protocol: 1,
            num_endpoints: 1,
        },
        Interface {
            number: 1,
            class: 3,
            subclass: 0,
            protocol: 0,
            num_endpoints: 2,
        },
        Interface {
            number: 2,
            class: 0x0b,
            subclass: 0,
            protocol: 0,
            num_endpoints: 3,
        },
    ];
    if ifaces != want {
        return TestResult::Fail("interfaces_of must list each interface's alt setting 0");
    }
    usbdev::__reset_for_test();
    let mut descriptor = [0u8; 18];
    descriptor[0] = 18;
    descriptor[1] = 1;
    descriptor[8..10].copy_from_slice(&0x1050u16.to_le_bytes());
    descriptor[10..12].copy_from_slice(&0x0407u16.to_le_bytes());
    descriptor[17] = 1;
    let dev = usbdev::__insert_for_test(UsbDevSpec {
        controller: 3,
        slot: 4,
        busnum: 7,
        devnum: 2,
        root_port: 1,
        route: 0,
        devpath: String::from("1"),
        speed: PortSpeed::Full,
        descriptor,
        configs: alloc::vec![cfg],
        config: 0,
    });
    let unconfigured = dev.interfaces().is_empty();
    dev.set_config_value(1);
    let r = (|| {
        if !unconfigured || dev.interfaces().len() != 3 {
            return Err("interfaces come from the active configuration only");
        }
        if dev.name() != "7-1" || dev.vendor() != 0x1050 || dev.product_id() != 0x0407 {
            return Err("name and ids must come from bus, devpath and the device descriptor");
        }
        if dev.claim(0, Owner::Driver("usbhid")).is_err()
            || dev.claim(0, Owner::Driver("usbhid")).is_err()
        {
            return Err("a holder may re-claim its own interface");
        }
        if dev.claim(0, Owner::File(9)) != Err(Owner::Driver("usbhid")) {
            return Err("a claimed interface must report its holder (-EBUSY)");
        }
        if dev.release(0, &Owner::File(9)) || !dev.release(0, &Owner::Driver("usbhid")) {
            return Err("only the holder may release");
        }
        let _ = dev.claim(2, Owner::File(9));
        dev.set_config_value(1);
        if dev.owner(2) != Some(Owner::File(9)) {
            return Err("re-setting the same configuration keeps claims");
        }
        dev.set_config_value(0);
        if dev.owner(2).is_some() {
            return Err("changing configuration drops the old interfaces' claims");
        }
        if usbdev::find_by_number(7, 2).is_none() || usbdev::find(3, 4).is_none() {
            return Err("the record must be findable by number and by slot");
        }
        Ok(())
    })();
    usbdev::__reset_for_test();
    match r {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!("drivers/usb/usbdev", smoke_usbdev_interfaces_and_claims);
