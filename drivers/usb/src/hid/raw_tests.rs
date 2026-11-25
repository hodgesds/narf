//! Raw-HID binding smokes: descriptor walks, report sizing, usbhid's
//! identity strings, and the attach-side configuration and claim rules.

use alloc::string::String;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::hid::raw::{
    hid_interface_offsets, hid_name, hid_phys, max_input_report, parse_interface,
};
use crate::usbdev::{self, UsbDevSpec};
use crate::xhci::{EndpointKind, PortSpeed};

/// The YubiKey 5 (1050:0407) configuration: OTP keyboard, FIDO and CCID.
fn yubikey_config() -> Vec<u8> {
    let mut c = alloc::vec![9, 2, 0, 0, 3, 1, 0, 0x80, 15];
    // iface 0: HID boot keyboard, one interrupt IN (8 bytes).
    c.extend_from_slice(&[9, 4, 0, 0, 1, 3, 1, 1, 0]);
    c.extend_from_slice(&[9, 0x21, 0x11, 0x01, 0, 1, 0x22, 71, 0]);
    c.extend_from_slice(&[7, 5, 0x81, 3, 8, 0, 10]);
    // iface 1: FIDO, interrupt IN + OUT (64 bytes).
    c.extend_from_slice(&[9, 4, 1, 0, 2, 3, 0, 0, 0]);
    c.extend_from_slice(&[9, 0x21, 0x10, 0x01, 0, 1, 0x22, 34, 0]);
    c.extend_from_slice(&[7, 5, 0x04, 3, 64, 0, 2]);
    c.extend_from_slice(&[7, 5, 0x84, 3, 64, 0, 2]);
    // iface 2: CCID.
    c.extend_from_slice(&[9, 4, 2, 0, 3, 0x0b, 0, 0, 0]);
    let total = c.len() as u16;
    c[2..4].copy_from_slice(&total.to_le_bytes());
    c
}

const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08,
    0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91,
    0x02, 0xC0,
];

fn smoke_raw_interface_walk() -> TestResult {
    let cfg = yubikey_config();
    let offsets = hid_interface_offsets(&cfg);
    if offsets.len() != 2 {
        return TestResult::Fail("the CCID interface is not HID");
    }
    let (Some(kbd), Some(fido)) = (
        parse_interface(&cfg, offsets[0]),
        parse_interface(&cfg, offsets[1]),
    ) else {
        return TestResult::Fail("both HID interfaces must parse");
    };
    if kbd.number != 0 || kbd.report_len != 71 || kbd.out_ep.is_some() {
        return TestResult::Fail("keyboard: iface 0, 71-byte report descriptor, no OUT");
    }
    if kbd.in_ep.kind != EndpointKind::InterruptIn || kbd.in_ep.max_packet != 8 {
        return TestResult::Fail("keyboard interrupt IN must be ep 1, 8 bytes");
    }
    let out = fido.out_ep.map(|e| (e.ep_addr, e.kind));
    if fido.number != 1
        || fido.bcd_hid != 0x0110
        || fido.report_len != 34
        || fido.in_ep.ep_addr != 0x84
        || out != Some((0x04, EndpointKind::InterruptOut))
    {
        return TestResult::Fail("FIDO: iface 1, bcdHID 1.10, IN 0x84, OUT 0x04");
    }
    // The CCID interface descriptor is not a HID interface.
    let ccid_at = cfg.len() - 9;
    if parse_interface(&cfg, ccid_at).is_some() {
        return TestResult::Fail("a non-HID interface must not parse");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid/raw", smoke_raw_interface_walk);

fn smoke_raw_max_input_report() -> TestResult {
    if max_input_report(FIDO_REPORT_DESCRIPTOR) != 64 {
        return TestResult::Fail("FIDO input report is 64 bytes, no report ID");
    }
    // Two numbered input reports, 3 and 7 data bytes: 7 + the ID byte.
    let numbered: &[u8] = &[
        0x05, 0x0C, 0x09, 0x01, 0xA1, 0x01, // Consumer, Application
        0x85, 0x01, 0x75, 0x08, 0x95, 0x03, 0x81, 0x02, // ID 1: 3 bytes
        0x85, 0x02, 0x75, 0x08, 0x95, 0x07, 0x81, 0x02, // ID 2: 7 bytes
        0xC0,
    ];
    if max_input_report(numbered) != 8 {
        return TestResult::Fail(
            "hid_find_max_report counts the ID byte when reports are numbered",
        );
    }
    if max_input_report(&[]) != 0 {
        return TestResult::Fail("an unparsable descriptor sizes to 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid/raw", smoke_raw_max_input_report);

fn device(manufacturer: Option<&str>, product: Option<&str>) -> usbdev::UsbDev {
    let mut descriptor = [0u8; 18];
    descriptor[8..10].copy_from_slice(&0x1050u16.to_le_bytes());
    descriptor[10..12].copy_from_slice(&0x0407u16.to_le_bytes());
    let mut d = usbdev::__spec_for_test(UsbDevSpec {
        controller: 3,
        slot: 2,
        busnum: 7,
        devnum: 2,
        root_port: 1,
        route: 0,
        devpath: String::from("1"),
        speed: PortSpeed::Full,
        descriptor,
        configs: alloc::vec![yubikey_config()],
        config: 1,
    });
    d.manufacturer = manufacturer.map(String::from);
    d.product = product.map(String::from);
    d
}

fn smoke_raw_usbhid_identity() -> TestResult {
    let both = device(Some("Yubico"), Some("YubiKey OTP+FIDO+CCID"));
    if hid_name(&both) != "Yubico YubiKey OTP+FIDO+CCID" {
        return TestResult::Fail("name is manufacturer + ' ' + product");
    }
    if hid_name(&device(None, Some("Key"))) != "Key" {
        return TestResult::Fail("name is the product alone without a manufacturer");
    }
    if hid_name(&device(None, None)) != "HID 1050:0407" {
        return TestResult::Fail("name falls back to HID vvvv:pppp");
    }
    if hid_phys("0000:c6:00.4", &both, 1) != "usb-0000:c6:00.4-1/input1" {
        return TestResult::Fail("phys is usb_make_path + /input<n>");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/hid/raw", smoke_raw_usbhid_identity);

fn smoke_raw_configuration_choice_and_claims() -> TestResult {
    let yk = device(None, None);
    if crate::attach::choose_configuration(&yk) != Some(1) {
        return TestResult::Fail("a class-interface configuration is chosen");
    }
    // Two configurations: vendor-specific first, then CDC. Linux takes
    // the non-vendor one.
    let mut vendor = alloc::vec![9, 2, 18, 0, 1, 1, 0, 0x80, 50];
    vendor.extend_from_slice(&[9, 4, 0, 0, 0, 0xff, 0, 0, 0]);
    let mut cdc = alloc::vec![9, 2, 18, 0, 1, 2, 0, 0x80, 50];
    cdc.extend_from_slice(&[9, 4, 0, 0, 1, 0x02, 2, 1, 0]);
    let mut two = device(None, None);
    two.configs = alloc::vec![vendor.clone(), cdc];
    if crate::attach::choose_configuration(&two) != Some(2) {
        return TestResult::Fail("usb_choose_configuration skips a vendor-specific first config");
    }
    let mut only_vendor = device(None, None);
    only_vendor.configs = alloc::vec![vendor];
    if crate::attach::choose_configuration(&only_vendor) != Some(1) {
        return TestResult::Fail("with only vendor configs the first is chosen");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hid/raw",
    smoke_raw_configuration_choice_and_claims
);
