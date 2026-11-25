//! sysfs for USB devices: what udev and libusb read.
//!
//! The layout follows Linux. Under the xHCI's PCI kobject sit:
//!
//! - one `usbN` per root hub;
//! - each device nested under the hub it hangs from (`usb7/7-1/7-1.2`);
//! - each interface of the active configuration under its device
//!   (`7-1:1.0`).
//!
//! Each kobject carries the attributes and uevent of
//! drivers/usb/core/sysfs.c and usb_dev_uevent / usb_if_uevent:
//!
//! - `busnum`, `devnum`, `devpath` and the binary `descriptors`
//!   (device descriptor followed by every configuration's raw
//!   descriptors);
//! - the `id*` / `b*` fields, `speed`, `version`, the strings;
//! - `PRODUCT`, `TYPE`, `BUSNUM`, `DEVNUM`, `DEVTYPE` in the uevent, and
//!   for interfaces `INTERFACE` and `MODALIAS`.
//!
//! Devices and root hubs are also linked from `/sys/bus/usb/devices`
//! and `/sys/dev/char/189:M` (usbfs's `usb_device` major). Interfaces
//! appear in `/sys/bus/usb/devices` only.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::sysfs::{
    get_or_create_child, get_root, kobject_add_attr, kobject_add_bin_attr, kobject_add_uevent_attr,
    kobject_emit_uevent, Kobject,
};
use narf_filesystem::uevent::UeventAction;
use narf_lib::sync::IrqSafeSpinLock;

use crate::usbdev::{RootHub, UsbDev};
use crate::xhci::{PortSpeed, Xhci};

/// `USB_DEVICE_MAJOR`: usbfs's character major.
pub const USB_DEVICE_MAJOR: u32 = 189;

/// The kernel release root hubs name themselves after. It mirrors the
/// release `uname(2)` reports (`userspace::handlers::sys_uname::UTS_RELEASE`).
pub const KERNEL_RELEASE: &str = "6.1.0-narf";
/// `bcdDevice` of a root hub: `LINUX_VERSION_CODE`'s version and
/// patch level.
pub const ROOT_HUB_BCD_DEVICE: u16 = 0x0601;

/// usbfs minor of `busnum`/`devnum` (`usbdev_minor`).
pub fn minor(busnum: u8, devnum: u8) -> u32 {
    (u32::from(busnum) - 1) * 128 + u32::from(devnum) - 1
}

/// Linux's `speed` attribute text.
pub fn speed_text(speed: PortSpeed) -> &'static str {
    match speed {
        PortSpeed::Low => "1.5",
        PortSpeed::Full => "12",
        PortSpeed::High => "480",
        PortSpeed::Super => "5000",
        PortSpeed::SuperPlus => "10000",
    }
}

/// Linux's `version` attribute: `bcdUSB` as `"%2x.%02x"`.
pub fn version_text(bcd_usb: u16) -> String {
    format!("{:2x}.{:02x}", bcd_usb >> 8, bcd_usb & 0xff)
}

/// `usb_dev_uevent`'s `PRODUCT`/`TYPE`/`BUSNUM`/`DEVNUM`, after the
/// device core's `MAJOR`/`MINOR`/`DEVNAME`/`DEVTYPE`.
pub fn device_uevent(
    busnum: u8,
    devnum: u8,
    vendor: u16,
    product: u16,
    bcd: u16,
    class: (u8, u8, u8),
) -> String {
    format!(
        "MAJOR={}\nMINOR={}\nDEVNAME=bus/usb/{:03}/{:03}\nDEVTYPE=usb_device\nDRIVER=usb\n\
         PRODUCT={:x}/{:x}/{:x}\nTYPE={}/{}/{}\nBUSNUM={:03}\nDEVNUM={:03}\n",
        USB_DEVICE_MAJOR,
        minor(busnum, devnum),
        busnum,
        devnum,
        vendor,
        product,
        bcd,
        class.0,
        class.1,
        class.2,
        busnum,
        devnum
    )
}

/// An interface's `modalias` (`usb_if_uevent` / `modalias_show`).
pub fn interface_modalias(dev: &UsbDev, iface: &crate::usbdev::Interface) -> String {
    let (dc, dsc, dp) = dev.class_triple();
    format!(
        "usb:v{:04X}p{:04X}d{:04X}dc{:02X}dsc{:02X}dp{:02X}ic{:02X}isc{:02X}ip{:02X}in{:02X}",
        dev.vendor(),
        dev.product_id(),
        dev.bcd_device(),
        dc,
        dsc,
        dp,
        iface.class,
        iface.subclass,
        iface.protocol,
        iface.number
    )
}

/// The xHCI's PCI kobject path below `/sys`, as `filesystem::sysfs`
/// names PCI functions.
pub fn controller_path(xhci: &Xhci) -> String {
    match xhci.bus_addr() {
        narf_bus::BusAddr::Pcie(a) => format!(
            "devices/pci{:04x}:{:02x}/{:04x}:{:02x}:{:02x}.{}",
            a.segment, a.bus, a.segment, a.bus, a.device, a.function
        ),
        _ => String::from("devices/platform/narf-usb"),
    }
}

/// `(controller, slot)` → the sysfs path its device kobject was
/// published at, so removal does not depend on its hub still being
/// registered.
static PUBLISHED: IrqSafeSpinLock<Vec<(u8, u8, String)>> = IrqSafeSpinLock::new(Vec::new());

/// The kobject at `path` below `/sys`, if it exists.
fn kobj_lookup(path: &str) -> Option<Arc<Kobject>> {
    let mut k = get_root();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        k = k.get_child(part)?;
    }
    Some(k)
}

/// The kobject at `path` below `/sys`, created as needed.
fn kobj_at(path: &str) -> Arc<Kobject> {
    let mut k = get_root();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        k = get_or_create_child(&k, part);
    }
    k
}

/// `../` repeated once per component of `path`, to reach `/sys`.
fn up_to_root(path: &str) -> String {
    "../".repeat(path.split('/').filter(|p| !p.is_empty()).count())
}

fn link_into(dir: &str, name: &str, target_path: &str) {
    let d = kobj_at(dir);
    d.add_symlink(
        String::from(name),
        format!("{}{}", up_to_root(dir), target_path),
    );
}

fn static_attr(k: &Kobject, name: &'static str, value: String) {
    kobject_add_attr(k, name, move || value.clone());
}

/// The sysfs path of a device's kobject: under its hub's kobject, or
/// under its root hub.
pub fn device_path(controller_path: &str, dev: &UsbDev) -> String {
    let parent = dev
        .parent_slot
        .and_then(|p| published_path(dev.controller, p))
        .unwrap_or_else(|| format!("{controller_path}/usb{}", dev.busnum));
    format!("{parent}/{}", dev.name())
}

/// Where `(controller, slot)`'s kobject was published.
pub fn published_path(controller: u8, slot: u8) -> Option<String> {
    PUBLISHED
        .lock()
        .iter()
        .find(|(c, s, _)| *c == controller && *s == slot)
        .map(|(_, _, p)| p.clone())
}

/// Publish root hub `hub` of `xhci` as `usbN` (idempotent).
pub fn publish_root_hub(xhci: &Xhci, hub: &RootHub) {
    publish_root_hub_at(
        &controller_path(xhci),
        &crate::hid::raw::pci_slot_name(xhci),
        hub,
    );
}

/// [`publish_root_hub`] under an explicit controller path and PCI slot
/// name (the HCD's `bus_name`, the root hub's serial).
pub fn publish_root_hub_at(controller_path: &str, slot: &str, hub: &RootHub) {
    let path = format!("{controller_path}/usb{}", hub.busnum);
    let k = kobj_at(&path);
    if k.attr_show("busnum").is_some() {
        return;
    }
    let product = if hub.usb3 { 0x0003 } else { 0x0002 };
    let (speed, bcd_usb) = if hub.usb3 {
        ("5000", 0x0300)
    } else {
        ("480", 0x0200)
    };
    static_attr(&k, "busnum", format!("{}\n", hub.busnum));
    static_attr(&k, "devnum", String::from("1\n"));
    static_attr(&k, "devpath", String::from("0\n"));
    static_attr(&k, "idVendor", String::from("1d6b\n"));
    static_attr(&k, "idProduct", format!("{product:04x}\n"));
    static_attr(&k, "bcdDevice", format!("{ROOT_HUB_BCD_DEVICE:04x}\n"));
    static_attr(&k, "bDeviceClass", String::from("09\n"));
    static_attr(&k, "bDeviceSubClass", String::from("00\n"));
    static_attr(
        &k,
        "bDeviceProtocol",
        String::from(if hub.usb3 { "03\n" } else { "01\n" }),
    );
    static_attr(&k, "bNumConfigurations", String::from("1\n"));
    static_attr(&k, "bConfigurationValue", String::from("1\n"));
    static_attr(&k, "speed", format!("{speed}\n"));
    static_attr(&k, "version", format!("{}\n", version_text(bcd_usb)));
    static_attr(&k, "maxchild", format!("{}\n", hub.ports));
    static_attr(
        &k,
        "manufacturer",
        format!("Linux {KERNEL_RELEASE} xhci-hcd\n"),
    );
    static_attr(&k, "product", String::from("xHCI Host Controller\n"));
    static_attr(&k, "serial", format!("{slot}\n"));
    let descriptors = crate::usbdev::root_hub_descriptors(hub);
    kobject_add_bin_attr(
        &k,
        "descriptors",
        Arc::new(move |off: usize, buf: &mut [u8]| copy_from(&descriptors, off, buf)),
    );
    k.add_symlink(
        String::from("subsystem"),
        format!("{}bus/usb", up_to_root(&path)),
    );
    kobject_add_uevent_attr(
        &k,
        device_uevent(
            hub.busnum,
            1,
            0x1d6b,
            product,
            ROOT_HUB_BCD_DEVICE,
            (9, 0, if hub.usb3 { 3 } else { 1 }),
        ),
    );
    link_into("bus/usb/devices", &format!("usb{}", hub.busnum), &path);
    link_into(
        "dev/char",
        &format!("{}:{}", USB_DEVICE_MAJOR, minor(hub.busnum, 1)),
        &path,
    );
    kobject_emit_uevent(&k, UeventAction::Add);
}

fn copy_from(src: &[u8], off: usize, buf: &mut [u8]) -> usize {
    if off >= src.len() {
        return 0;
    }
    let n = buf.len().min(src.len() - off);
    buf[..n].copy_from_slice(&src[off..off + n]);
    n
}

/// Publish a registered device (`usb_new_device` → `device_add`).
pub fn publish_device(xhci: &Xhci, dev: &Arc<UsbDev>) {
    for hub in crate::usbdev::root_hubs()
        .iter()
        .filter(|h| h.controller == xhci.id())
    {
        publish_root_hub(xhci, hub);
    }
    publish_device_at(&controller_path(xhci), dev);
}

/// [`publish_device`] under an explicit controller path.
pub fn publish_device_at(controller_path: &str, dev: &Arc<UsbDev>) {
    let path = device_path(controller_path, dev);
    {
        let mut g = PUBLISHED.lock();
        g.retain(|(c, s, _)| !(*c == dev.controller && *s == dev.slot));
        g.push((dev.controller, dev.slot, path.clone()));
    }
    let k = kobj_at(&path);
    let d = dev.descriptor;
    static_attr(&k, "busnum", format!("{}\n", dev.busnum));
    static_attr(&k, "devnum", format!("{}\n", dev.devnum));
    static_attr(&k, "devpath", format!("{}\n", dev.devpath));
    static_attr(&k, "idVendor", format!("{:04x}\n", dev.vendor()));
    static_attr(&k, "idProduct", format!("{:04x}\n", dev.product_id()));
    static_attr(&k, "bcdDevice", format!("{:04x}\n", dev.bcd_device()));
    static_attr(&k, "bDeviceClass", format!("{:02x}\n", d[4]));
    static_attr(&k, "bDeviceSubClass", format!("{:02x}\n", d[5]));
    static_attr(&k, "bDeviceProtocol", format!("{:02x}\n", d[6]));
    static_attr(&k, "bMaxPacketSize0", format!("{}\n", d[7]));
    static_attr(&k, "bNumConfigurations", format!("{}\n", d[17]));
    static_attr(&k, "speed", format!("{}\n", speed_text(dev.speed)));
    static_attr(&k, "version", format!("{}\n", version_text(dev.bcd_usb())));
    for (name, value) in [
        ("manufacturer", &dev.manufacturer),
        ("product", &dev.product),
        ("serial", &dev.serial),
    ] {
        if let Some(v) = value {
            static_attr(&k, name, format!("{v}\n"));
        }
    }
    {
        let dev = dev.clone();
        kobject_add_attr(&k, "bConfigurationValue", move || {
            match dev.config_value() {
                0 => String::new(),
                v => format!("{v}\n"),
            }
        });
    }
    {
        let dev = dev.clone();
        kobject_add_attr(&k, "bNumInterfaces", move || {
            dev.active_config()
                .map(|c| format!("{:2}\n", c[4]))
                .unwrap_or_default()
        });
    }
    {
        let dev = dev.clone();
        kobject_add_attr(&k, "bMaxPower", move || {
            dev.active_config()
                .map(|c| {
                    // SuperSpeed counts bMaxPower in 8 mA units, others 2 mA.
                    let unit = if matches!(dev.speed, PortSpeed::Super | PortSpeed::SuperPlus) {
                        8
                    } else {
                        2
                    };
                    format!("{}mA\n", u32::from(c[8]) * unit)
                })
                .unwrap_or_default()
        });
    }
    let mut raw = Vec::from(dev.descriptor);
    for c in &dev.configs {
        raw.extend_from_slice(c);
    }
    kobject_add_bin_attr(
        &k,
        "descriptors",
        Arc::new(move |off: usize, buf: &mut [u8]| copy_from(&raw, off, buf)),
    );
    k.add_symlink(
        String::from("subsystem"),
        format!("{}bus/usb", up_to_root(&path)),
    );
    kobject_add_uevent_attr(
        &k,
        device_uevent(
            dev.busnum,
            dev.devnum,
            dev.vendor(),
            dev.product_id(),
            dev.bcd_device(),
            dev.class_triple(),
        ),
    );
    link_into("bus/usb/devices", &dev.name(), &path);
    link_into(
        "dev/char",
        &format!("{}:{}", USB_DEVICE_MAJOR, minor(dev.busnum, dev.devnum)),
        &path,
    );
    kobject_emit_uevent(&k, UeventAction::Add);
}

/// Publish the interfaces of the device's active configuration
/// (`usb_set_configuration` → `device_add` per interface).
pub fn publish_interfaces(dev: &Arc<UsbDev>) {
    let config = dev.config_value();
    if config == 0 {
        return;
    }
    let Some(dev_path) = published_path(dev.controller, dev.slot) else {
        return;
    };
    for iface in dev.interfaces() {
        let name = format!("{}:{}.{}", dev.name(), config, iface.number);
        let path = format!("{dev_path}/{name}");
        let k = kobj_at(&path);
        if k.attr_show("bInterfaceNumber").is_some() {
            continue;
        }
        static_attr(&k, "bInterfaceNumber", format!("{:02x}\n", iface.number));
        static_attr(&k, "bAlternateSetting", String::from(" 0\n"));
        static_attr(
            &k,
            "bNumEndpoints",
            format!("{:02x}\n", iface.num_endpoints),
        );
        static_attr(&k, "bInterfaceClass", format!("{:02x}\n", iface.class));
        static_attr(
            &k,
            "bInterfaceSubClass",
            format!("{:02x}\n", iface.subclass),
        );
        static_attr(
            &k,
            "bInterfaceProtocol",
            format!("{:02x}\n", iface.protocol),
        );
        let modalias = interface_modalias(dev, &iface);
        static_attr(&k, "modalias", format!("{modalias}\n"));
        k.add_symlink(
            String::from("subsystem"),
            format!("{}bus/usb", up_to_root(&path)),
        );
        kobject_add_uevent_attr(
            &k,
            format!(
                "DEVTYPE=usb_interface\nPRODUCT={:x}/{:x}/{:x}\nTYPE={}/{}/{}\n\
                 INTERFACE={}/{}/{}\nMODALIAS={}\n",
                dev.vendor(),
                dev.product_id(),
                dev.bcd_device(),
                dev.class_triple().0,
                dev.class_triple().1,
                dev.class_triple().2,
                iface.class,
                iface.subclass,
                iface.protocol,
                modalias
            ),
        );
        link_into("bus/usb/devices", &name, &path);
        kobject_emit_uevent(&k, UeventAction::Add);
    }
}

/// Remove a device's kobjects and links (`usb_disconnect` →
/// `device_del`), children first.
pub fn unpublish_device(dev: &UsbDev) {
    let path = {
        let mut g = PUBLISHED.lock();
        let Some(i) = g
            .iter()
            .position(|(c, s, _)| *c == dev.controller && *s == dev.slot)
        else {
            return;
        };
        g.remove(i).2
    };
    let Some(k) = kobj_lookup(&path) else {
        return;
    };
    for iface in dev.interfaces() {
        let name = format!("{}:{}.{}", dev.name(), dev.config_value(), iface.number);
        if let Some(ik) = k.get_child(&name) {
            kobject_emit_uevent(&ik, UeventAction::Remove);
        }
        kobj_at("bus/usb/devices").remove_symlink(&name);
    }
    kobject_emit_uevent(&k, UeventAction::Remove);
    kobj_at("bus/usb/devices").remove_symlink(&dev.name());
    kobj_at("dev/char").remove_symlink(&format!(
        "{}:{}",
        USB_DEVICE_MAJOR,
        minor(dev.busnum, dev.devnum)
    ));
    if let Some((parent, name)) = path.rsplit_once('/') {
        if let Some(p) = kobj_lookup(parent) {
            p.remove_child(name);
        }
    }
}

/// Publish every root hub of every controller (boot: before any
/// device attaches, so `lsusb` lists empty buses too).
pub fn publish_all_root_hubs() -> usize {
    let hubs = crate::usbdev::root_hubs();
    for hub in &hubs {
        if let Some(xhci) = crate::xhci::controller_by_id(hub.controller) {
            publish_root_hub(&xhci, hub);
        }
    }
    hubs.len()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    PUBLISHED.lock().clear();
}
