//! The HID group a report descriptor implies — Linux `hid_scan_report`
//! (`drivers/hid/hid-core.c:925`), which `hid_add_device` runs through
//! `hid_set_group` (`hid-core.c:2720`) before the device reaches the
//! bus.
//!
//! The group is the `g%04X` field of the device's
//! `MODALIAS=hid:b%04Xg%04Xv%08Xp%08X` (`hid_uevent`, `hid-core.c:2870`):
//! module autoloading and hwdb matching key on it, and it is what tells
//! a Windows Precision Touchpad (`MULTITOUCH_WIN_8`) from a plain mouse
//! (`GENERIC`). The scan is deliberately simpler than the full parser —
//! malformed items are skipped, never fatal — exactly as Linux's is
//! ("we should be robust against hid errors").
//!
//! LINUX-GAP: `hid_set_group` skips the scan for a device whose quirk
//! entry carries `HID_QUIRK_HAVE_SPECIAL_DRIVER` (group stays 0) and
//! honours `hid_ignore_special_drivers`; NARF has no HID quirk table, so
//! every device is scanned.

use alloc::vec::Vec;

/// `HID_GROUP_*` (`include/linux/hid.h:430`).
pub mod group {
    pub const GENERIC: u16 = 0x0001;
    pub const MULTITOUCH: u16 = 0x0002;
    pub const SENSOR_HUB: u16 = 0x0003;
    pub const MULTITOUCH_WIN_8: u16 = 0x0004;
    pub const RMI: u16 = 0x0100;
    pub const WACOM: u16 = 0x0101;
    pub const VIVALDI: u16 = 0x0105;
}

// `include/linux/hid.h`.
const HID_ITEM_TAG_LONG: u8 = 15;
const HID_ITEM_TYPE_MAIN: u8 = 0;
const HID_ITEM_TYPE_GLOBAL: u8 = 1;
const HID_ITEM_TYPE_LOCAL: u8 = 2;
const HID_MAIN_ITEM_TAG_INPUT: u8 = 8;
const HID_MAIN_ITEM_TAG_BEGIN_COLLECTION: u8 = 10;
const HID_MAIN_ITEM_TAG_FEATURE: u8 = 11;
const HID_MAIN_ITEM_CONSTANT: u32 = 0x001;
const HID_COLLECTION_PHYSICAL: u32 = 0;
const HID_COLLECTION_APPLICATION: u32 = 1;
const HID_GLOBAL_ITEM_TAG_USAGE_PAGE: u8 = 0;
const HID_GLOBAL_ITEM_TAG_REPORT_SIZE: u8 = 7;
const HID_GLOBAL_ITEM_TAG_REPORT_COUNT: u8 = 9;
const HID_GLOBAL_ITEM_TAG_PUSH: u8 = 10;
const HID_GLOBAL_ITEM_TAG_POP: u8 = 11;
const HID_LOCAL_ITEM_TAG_USAGE: u8 = 0;
const HID_LOCAL_ITEM_TAG_USAGE_MINIMUM: u8 = 1;
const HID_LOCAL_ITEM_TAG_USAGE_MAXIMUM: u8 = 2;
const HID_LOCAL_ITEM_TAG_DELIMITER: u8 = 10;
const HID_UP_GENDESK: u32 = 0x0001_0000;
const HID_UP_SENSOR: u32 = 0x0020_0000;
const HID_UP_MSVENDOR: u32 = 0xff00_0000;
const HID_UP_GOOGLEVENDOR: u32 = 0xffd1_0000;
const HID_GD_POINTER: u32 = 0x0001_0001;
const HID_DG_CONTACTID: u32 = 0x000d_0051;
const HID_MAX_USAGES: u32 = 12288;
const HID_GLOBAL_STACK_SIZE: usize = 4;

// `drivers/hid/hid-ids.h`.
const USB_VENDOR_ID_MICROSOFT: u32 = 0x045e;
const USB_DEVICE_ID_MS_POWER_COVER: u32 = 0x07da;
const USB_VENDOR_ID_SYNAPTICS: u32 = 0x06cb;
const USB_VENDOR_ID_WACOM: u32 = 0x056a;

// `HID_SCAN_FLAG_*` (`include/linux/hid.h`).
const SCAN_FLAG_MT_WIN_8: u32 = 1 << 0;
const SCAN_FLAG_VENDOR_SPECIFIC: u32 = 1 << 1;
const SCAN_FLAG_GD_POINTER: u32 = 1 << 2;

/// One short or long item (`struct hid_item`).
struct Item {
    kind: u8,
    tag: u8,
    size: u8,
    /// The short item's data; 0 for a long item, whose payload no scan
    /// step reads.
    data: u32,
}

impl Item {
    /// `item_udata` (`hid-core.c:377`).
    fn udata(&self) -> u32 {
        match self.size {
            1 | 2 | 4 => self.data,
            _ => 0,
        }
    }
}

/// `fetch_item` (`hid-core.c:778`): the item at `rdesc[pos..]` and the
/// position after it, or `None` when the descriptor ends or the item is
/// truncated.
fn fetch_item(rdesc: &[u8], pos: usize) -> Option<(Item, usize)> {
    let mut p = pos;
    let b = *rdesc.get(p)?;
    p += 1;
    let kind = (b >> 2) & 3;
    let tag = (b >> 4) & 15;
    if tag == HID_ITEM_TAG_LONG {
        if rdesc.len() - p < 2 {
            return None;
        }
        let size = rdesc[p];
        let tag = rdesc[p + 1];
        p += 2;
        if rdesc.len() - p < size as usize {
            return None;
        }
        return Some((
            Item {
                kind,
                tag,
                size,
                data: 0,
            },
            p + size as usize,
        ));
    }
    // `BIT(b & 3) >> 1`: 0, 1, 2, 3 -> 0, 1, 2, 4.
    let size = (1u8 << (b & 3)) >> 1;
    if rdesc.len() - p < size as usize {
        return None;
    }
    let data = match size {
        1 => u32::from(rdesc[p]),
        2 => u32::from(u16::from_le_bytes([rdesc[p], rdesc[p + 1]])),
        4 => u32::from_le_bytes([rdesc[p], rdesc[p + 1], rdesc[p + 2], rdesc[p + 3]]),
        _ => 0,
    };
    Some((
        Item {
            kind,
            tag,
            size,
            data,
        },
        p + size as usize,
    ))
}

/// The `struct hid_global` fields the scan reads.
#[derive(Clone, Copy, Default)]
struct Global {
    usage_page: u32,
    report_size: u32,
    report_count: u32,
}

/// The `struct hid_local` fields the scan reads.
#[derive(Default)]
struct Local {
    usage: Vec<u32>,
    usage_size: Vec<u8>,
    usage_minimum: u32,
    delimiter_depth: u32,
    delimiter_branch: u32,
}

struct Scanner {
    vendor: u32,
    product: u32,
    group: u16,
    scan_flags: u32,
    global: Global,
    global_stack: Vec<Global>,
    local: Local,
}

impl Scanner {
    /// `complete_usage` (`hid-core.c:249`).
    fn complete_usage(&mut self, index: usize) {
        self.local.usage[index] &= 0xFFFF;
        self.local.usage[index] |= (self.global.usage_page & 0xFFFF) << 16;
    }

    /// `hid_add_usage` (`hid-core.c:260`); `Err` is its `-1`.
    fn add_usage(&mut self, usage: u32, size: u8) -> Result<(), ()> {
        if self.local.usage.len() as u32 >= HID_MAX_USAGES {
            return Err(());
        }
        self.local.usage.push(usage);
        self.local.usage_size.push(size);
        if size <= 2 {
            self.complete_usage(self.local.usage.len() - 1);
        }
        Ok(())
    }

    /// The `hid_parser_global` tags the scan's state depends on
    /// (`hid-core.c:401`). Values are stored before the range checks
    /// that make Linux return `-1`, as Linux stores them, and the scan
    /// ignores that return.
    fn global(&mut self, item: &Item) {
        match item.tag {
            HID_GLOBAL_ITEM_TAG_PUSH => {
                if self.global_stack.len() < HID_GLOBAL_STACK_SIZE {
                    self.global_stack.push(self.global);
                }
            }
            HID_GLOBAL_ITEM_TAG_POP => {
                if let Some(g) = self.global_stack.pop() {
                    self.global = g;
                }
            }
            HID_GLOBAL_ITEM_TAG_USAGE_PAGE => self.global.usage_page = item.udata(),
            HID_GLOBAL_ITEM_TAG_REPORT_SIZE => self.global.report_size = item.udata(),
            HID_GLOBAL_ITEM_TAG_REPORT_COUNT => self.global.report_count = item.udata(),
            _ => {}
        }
    }

    /// `hid_parser_local` (`hid-core.c:507`).
    fn local(&mut self, item: &Item) {
        let data = item.udata();
        match item.tag {
            HID_LOCAL_ITEM_TAG_DELIMITER => {
                if data != 0 {
                    // "nested delimiters"
                    if self.local.delimiter_depth != 0 {
                        return;
                    }
                    self.local.delimiter_depth += 1;
                    self.local.delimiter_branch += 1;
                } else {
                    // "bogus close delimiter"
                    if self.local.delimiter_depth < 1 {
                        return;
                    }
                    self.local.delimiter_depth -= 1;
                }
            }
            HID_LOCAL_ITEM_TAG_USAGE => {
                // "alternative usage ignored"
                if self.local.delimiter_branch > 1 {
                    return;
                }
                let _ = self.add_usage(data, item.size);
            }
            HID_LOCAL_ITEM_TAG_USAGE_MINIMUM => {
                if self.local.delimiter_branch > 1 {
                    return;
                }
                self.local.usage_minimum = data;
            }
            HID_LOCAL_ITEM_TAG_USAGE_MAXIMUM => {
                if self.local.delimiter_branch > 1 {
                    return;
                }
                let mut max = data;
                let index = self.local.usage.len() as u32;
                let count = max.wrapping_sub(self.local.usage_minimum);
                if count.wrapping_add(index) >= HID_MAX_USAGES {
                    // "ignoring exceeding usage max"
                    max = HID_MAX_USAGES
                        .wrapping_sub(index)
                        .wrapping_add(self.local.usage_minimum)
                        .wrapping_sub(1);
                    // `if (data <= 0)` on a `__u32`.
                    if max == 0 {
                        return;
                    }
                }
                let mut n = self.local.usage_minimum;
                while n <= max {
                    if self.add_usage(n, item.size).is_err() {
                        return;
                    }
                    match n.checked_add(1) {
                        Some(next) => n = next,
                        None => break,
                    }
                }
            }
            _ => {}
        }
    }

    /// `hid_concatenate_last_usage_page` (`hid-core.c:606`).
    fn concatenate_last_usage_page(&mut self) {
        let usage_page = self.global.usage_page;
        for i in (0..self.local.usage.len()).rev() {
            if self.local.usage_size[i] > 2 {
                // Ignore extended usages.
                continue;
            }
            if self.local.usage[i] >> 16 == usage_page {
                break;
            }
            self.complete_usage(i);
        }
    }

    /// `hid_scan_collection` (`hid-core.c:853`). `usage_page << 16` is
    /// the C shift of an `unsigned`: the high half falls off.
    fn collection(&mut self, kind: u32) {
        let page = self.global.usage_page << 16;
        if page == HID_UP_SENSOR
            && (kind == HID_COLLECTION_PHYSICAL || kind == HID_COLLECTION_APPLICATION)
        {
            self.group = group::SENSOR_HUB;
        }
        if self.vendor == USB_VENDOR_ID_MICROSOFT
            && self.product == USB_DEVICE_ID_MS_POWER_COVER
            && self.group == group::MULTITOUCH
        {
            self.group = group::GENERIC;
        }
        if page == HID_UP_GENDESK && self.local.usage.contains(&HID_GD_POINTER) {
            self.scan_flags |= SCAN_FLAG_GD_POINTER;
        }
        if page >= HID_UP_MSVENDOR {
            self.scan_flags |= SCAN_FLAG_VENDOR_SPECIFIC;
        }
        if page == HID_UP_GOOGLEVENDOR && self.local.usage.contains(&(HID_UP_GOOGLEVENDOR | 0x0001))
        {
            self.group = group::VIVALDI;
        }
    }

    /// `hid_scan_feature_usage` (`hid-core.c:842`): the Windows 8
    /// certification blob (`0xff0000c5`, 256 bytes) or the
    /// certification-status byte (`0xff0000c6`).
    fn feature_usage(&mut self, usage: u32) {
        let g = self.global;
        if usage == 0xff00_00c5 && g.report_count == 256 && g.report_size == 8 {
            self.scan_flags |= SCAN_FLAG_MT_WIN_8;
        }
        if usage == 0xff00_00c6 && g.report_count == 1 && g.report_size == 8 {
            self.scan_flags |= SCAN_FLAG_MT_WIN_8;
        }
    }

    /// `hid_scan_main` (`hid-core.c:884`).
    fn main(&mut self, item: &Item) {
        self.concatenate_last_usage_page();
        let data = item.udata();
        match item.tag {
            HID_MAIN_ITEM_TAG_BEGIN_COLLECTION => self.collection(data & 0xff),
            HID_MAIN_ITEM_TAG_INPUT => {
                // "ignore constant inputs, they will be ignored by
                // hid-input"
                if data & HID_MAIN_ITEM_CONSTANT == 0
                    && self.local.usage.contains(&HID_DG_CONTACTID)
                {
                    // `hid_scan_input_usage` (`hid-core.c:834`).
                    self.group = group::MULTITOUCH;
                }
            }
            HID_MAIN_ITEM_TAG_FEATURE => {
                let usages = core::mem::take(&mut self.local.usage);
                for &usage in &usages {
                    self.feature_usage(usage);
                }
                self.local.usage = usages;
            }
            _ => {}
        }
        // "Reset the local parser environment"
        self.local = Local::default();
    }
}

/// `hid_scan_report` (`hid-core.c:925`): the `HID_GROUP_*` of a device
/// with this report descriptor and vendor/product.
pub fn scan_group(rdesc: &[u8], vendor: u32, product: u32) -> u16 {
    let mut s = Scanner {
        vendor,
        product,
        group: group::GENERIC,
        scan_flags: 0,
        global: Global::default(),
        global_stack: Vec::new(),
        local: Local::default(),
    };
    let mut pos = 0;
    while let Some((item, next)) = fetch_item(rdesc, pos) {
        match item.kind {
            HID_ITEM_TYPE_MAIN => s.main(&item),
            HID_ITEM_TYPE_GLOBAL => s.global(&item),
            HID_ITEM_TYPE_LOCAL => s.local(&item),
            // `hid_parser_reserved`.
            _ => {}
        }
        pos = next;
    }
    // "Handle special flags set during scanning."
    if s.scan_flags & SCAN_FLAG_MT_WIN_8 != 0 && s.group == group::MULTITOUCH {
        s.group = group::MULTITOUCH_WIN_8;
    }
    // "Vendor specific handlings"
    match vendor {
        USB_VENDOR_ID_WACOM => s.group = group::WACOM,
        USB_VENDOR_ID_SYNAPTICS => {
            // "hid-rmi should take care of them, not hid-generic"
            if s.group == group::GENERIC
                && s.scan_flags & SCAN_FLAG_VENDOR_SPECIFIC != 0
                && s.scan_flags & SCAN_FLAG_GD_POINTER != 0
            {
                s.group = group::RMI;
            }
        }
        _ => {}
    }
    s.group
}

mod tests {
    use super::{group, scan_group};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The FIDO U2F/CTAPHID descriptor the CTAP spec publishes (usage
    /// page 0xF1D0, 64-byte IN and OUT reports): a plain HID device.
    const FIDO: &[u8] = &[
        0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
        0x09, 0x01, // Usage (U2F Authenticator Device)
        0xa1, 0x01, // Collection (Application)
        0x09, 0x20, //   Usage (Input Report Data)
        0x15, 0x00, //   Logical Minimum (0)
        0x26, 0xff, 0x00, //   Logical Maximum (255)
        0x75, 0x08, //   Report Size (8)
        0x95, 0x40, //   Report Count (64)
        0x81, 0x02, //   Input (Data,Var,Abs)
        0x09, 0x21, //   Usage (Output Report Data)
        0x15, 0x00, //   Logical Minimum (0)
        0x26, 0xff, 0x00, //   Logical Maximum (255)
        0x75, 0x08, //   Report Size (8)
        0x95, 0x40, //   Report Count (64)
        0x91, 0x02, //   Output (Data,Var,Abs)
        0xc0, // End Collection
    ];

    /// A touchpad shaped like a Windows Precision Touchpad: a Contact
    /// Identifier input, then the 256-byte certification blob feature
    /// on the Microsoft vendor page.
    fn ptp(with_blob: bool) -> alloc::vec::Vec<u8> {
        let mut d = alloc::vec![
            0x05, 0x0d, // Usage Page (Digitizer)
            0x09, 0x05, // Usage (Touch Pad)
            0xa1, 0x01, // Collection (Application)
            0x85, 0x01, //   Report ID (1)
            0x09, 0x22, //   Usage (Finger)
            0xa1, 0x02, //   Collection (Logical)
            0x09, 0x51, //     Usage (Contact Identifier)
            0x75, 0x08, //     Report Size (8)
            0x95, 0x01, //     Report Count (1)
            0x81, 0x02, //     Input (Data,Var,Abs)
            0xc0, //   End Collection
        ];
        if with_blob {
            d.extend_from_slice(&[
                0x06, 0x00, 0xff, //   Usage Page (Vendor 0xFF00)
                0x85, 0x05, //   Report ID (5)
                0x09, 0xc5, //   Usage (0xC5)
                0x15, 0x00, //   Logical Minimum (0)
                0x26, 0xff, 0x00, //   Logical Maximum (255)
                0x75, 0x08, //   Report Size (8)
                0x96, 0x00, 0x01, //   Report Count (256)
                0xb1, 0x02, //   Feature (Data,Var,Abs)
            ]);
        }
        d.push(0xc0); // End Collection
        d
    }

    fn smoke_hid_scan_group_classifies_like_linux() -> TestResult {
        // A FIDO token is GENERIC (Yubico 1050:0407 on Linux reads
        // `MODALIAS=hid:b0003g0001v00001050p00000407`).
        if scan_group(FIDO, 0x1050, 0x0407) != group::GENERIC {
            return TestResult::Fail("FIDO descriptor not HID_GROUP_GENERIC");
        }
        // Contact ID alone: MULTITOUCH; with the Win8 blob: WIN_8 —
        // the SYNA8018 06CB:CE67 touchpad's `g0004`.
        if scan_group(&ptp(false), 0x06cb, 0xce67) != group::MULTITOUCH {
            return TestResult::Fail("Contact ID input not HID_GROUP_MULTITOUCH");
        }
        if scan_group(&ptp(true), 0x06cb, 0xce67) != group::MULTITOUCH_WIN_8 {
            return TestResult::Fail("Win8 blob did not upgrade to MULTITOUCH_WIN_8");
        }
        // A constant Contact ID input is padding hid-input ignores.
        let mut constant = ptp(false);
        let input = constant
            .windows(2)
            .position(|w| w == [0x81, 0x02])
            .unwrap_or(0);
        constant[input + 1] = 0x03;
        if scan_group(&constant, 0, 0) != group::GENERIC {
            return TestResult::Fail("constant Contact ID input counted");
        }
        // The blob without a Contact ID input stays GENERIC.
        let blob_only = [
            0x06, 0x00, 0xff, 0x09, 0x01, 0xa1, 0x01, 0x09, 0xc5, 0x75, 0x08, 0x96, 0x00, 0x01,
            0xb1, 0x02, 0xc0,
        ];
        if scan_group(&blob_only, 0, 0) != group::GENERIC {
            return TestResult::Fail("Win8 blob alone changed the group");
        }
        // Wacom is WACOM whatever the descriptor says.
        if scan_group(FIDO, 0x056a, 0x0001) != group::WACOM {
            return TestResult::Fail("Wacom vendor not HID_GROUP_WACOM");
        }
        TestResult::Pass
    }
    kernel_test_in!("input/hid_scan", smoke_hid_scan_group_classifies_like_linux);

    fn smoke_hid_scan_group_sensor_rmi_and_malformed() -> TestResult {
        // An application collection on the sensor page: SENSOR_HUB.
        let sensor = [0x05, 0x20, 0x09, 0x01, 0xa1, 0x01, 0xc0];
        if scan_group(&sensor, 0x1022, 0x0001) != group::SENSOR_HUB {
            return TestResult::Fail("sensor application collection not SENSOR_HUB");
        }
        // A logical (2) sensor collection does not count.
        let logical = [0x05, 0x20, 0x09, 0x01, 0xa1, 0x02, 0xc0];
        if scan_group(&logical, 0, 0) != group::GENERIC {
            return TestResult::Fail("logical sensor collection counted");
        }
        // Synaptics with a vendor-page collection and a GD Pointer usage
        // in a Generic Desktop collection goes to hid-rmi.
        let rmi = [
            0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, // GD, Usage (Mouse), App
            0x09, 0x01, 0xa1, 0x00, //   Usage (Pointer), Physical
            0xc0, 0x06, 0x00, 0xff, 0x09, 0x01, 0xa1, 0x01, 0xc0, 0xc0,
        ];
        if scan_group(&rmi, 0x06cb, 0x1234) != group::RMI {
            return TestResult::Fail("Synaptics vendor+pointer descriptor not HID_GROUP_RMI");
        }
        if scan_group(&rmi, 0x1234, 0x1234) != group::GENERIC {
            return TestResult::Fail("RMI rule applied to a non-Synaptics vendor");
        }
        // Push/Pop restore the usage page: the Contact ID usage is
        // completed against Digitizer after the pop.
        let pushpop = [
            0x05, 0x0d, 0xa4, 0x05, 0x01, 0xb4, 0x09, 0x51, 0x75, 0x08, 0x95, 0x01, 0x81, 0x02,
        ];
        if scan_group(&pushpop, 0, 0) != group::MULTITOUCH {
            return TestResult::Fail("Pop did not restore the Digitizer usage page");
        }
        // A 4-byte extended usage is not re-paged.
        let extended = [0x05, 0x01, 0x0b, 0x51, 0x00, 0x0d, 0x00, 0x81, 0x02];
        if scan_group(&extended, 0, 0) != group::MULTITOUCH {
            return TestResult::Fail("extended usage was concatenated with the usage page");
        }
        // Truncated items end the scan without error; empty is GENERIC.
        if scan_group(&[], 0, 0) != group::GENERIC
            || scan_group(&[0x05], 0, 0) != group::GENERIC
            || scan_group(&[0xfe, 0x10], 0, 0) != group::GENERIC
        {
            return TestResult::Fail("truncated descriptor not handled as Linux does");
        }
        // A long item is skipped whole.
        let long_then_contact = [
            0xfe, 0x02, 0x00, 0xaa, 0xbb, 0x05, 0x0d, 0x09, 0x51, 0x81, 0x02,
        ];
        if scan_group(&long_then_contact, 0, 0) != group::MULTITOUCH {
            return TestResult::Fail("long item not skipped");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "input/hid_scan",
        smoke_hid_scan_group_sensor_rmi_and_malformed
    );
}
