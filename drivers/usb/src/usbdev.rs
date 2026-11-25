//! The USB device registry: Linux's `struct usb_device` bookkeeping for
//! every addressed device.
//!
//! The registry holds what usbfs, sysfs and the raw-HID binding need
//! that the per-class bindings never kept:
//!
//! - bus and device numbers;
//! - the port path;
//! - the raw device and configuration descriptors and the strings;
//! - the active configuration;
//! - which interfaces are claimed, and by whom.
//!
//! **Bus numbers** follow Linux's HCD registration order. Each xHCI
//! registers its USB 2 root hub, then its USB 3 root hub when it has
//! USB 3 ports (`xhci_pci_probe` → `usb_add_hcd` twice). Controllers are
//! taken in probe order, so the four xHCIs of a Phoenix laptop are buses
//! 1–8.
//!
//! **Root-hub ports** are numbered per root hub: an xHCI port's number
//! is its position among the controller's ports of the same major
//! protocol (`xhci_setup_port_arrays`).
//!
//! **Device numbers** come from `choose_devnum`: each bus hands out
//! 1..=127 round-robin from `devnum_next`, and the root hub holds 1.
//!
//! **The device path** (`devpath`) is the root-hub port followed by
//! each hub port from the route string (`2.3`). The device's sysfs and
//! usbfs name is `busnum-devpath` (`1-2.3`).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::xhci::{PortSpeed, Xhci};

/// Who holds an interface: a kernel class driver, or a usbfs open file
/// (Linux `usb_driver_claim_interface` with usbfs's driver).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    Driver(&'static str),
    File(u64),
}

/// One interface of the active configuration (alternate setting 0).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub number: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub num_endpoints: u8,
}

#[derive(Debug)]
struct DevState {
    /// `bConfigurationValue` of the active configuration; 0 when
    /// unconfigured.
    config: u8,
    claims: Vec<(u8, Owner)>,
}

/// One addressed USB device.
#[derive(Debug)]
pub struct UsbDev {
    pub controller: u8,
    pub slot: u8,
    pub generation: u64,
    pub busnum: u8,
    pub devnum: u8,
    /// xHCI root port the device's branch hangs off.
    pub root_port: u8,
    /// xHCI route string (hub ports below the root port, one nibble
    /// per tier).
    pub route: u32,
    /// Linux `devpath`: root-hub port, then hub ports (`2.3`).
    pub devpath: String,
    pub speed: PortSpeed,
    /// Slot of the parent hub, `None` on a root port.
    pub parent_slot: Option<u8>,
    /// The 18-byte device descriptor.
    pub descriptor: [u8; 18],
    /// Every configuration descriptor, full length, in index order.
    pub configs: Vec<Vec<u8>>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    state: IrqSafeSpinLock<DevState>,
}

impl UsbDev {
    /// `dev_name(&udev->dev)`: `busnum-devpath`.
    pub fn name(&self) -> String {
        format!("{}-{}", self.busnum, self.devpath)
    }

    pub fn vendor(&self) -> u16 {
        u16::from_le_bytes([self.descriptor[8], self.descriptor[9]])
    }

    pub fn product_id(&self) -> u16 {
        u16::from_le_bytes([self.descriptor[10], self.descriptor[11]])
    }

    pub fn bcd_device(&self) -> u16 {
        u16::from_le_bytes([self.descriptor[12], self.descriptor[13]])
    }

    pub fn bcd_usb(&self) -> u16 {
        u16::from_le_bytes([self.descriptor[2], self.descriptor[3]])
    }

    /// `bDeviceClass` / `bDeviceSubClass` / `bDeviceProtocol`.
    pub fn class_triple(&self) -> (u8, u8, u8) {
        (self.descriptor[4], self.descriptor[5], self.descriptor[6])
    }

    /// `(parent hub slot, port on that hub)` for a device behind a hub:
    /// the route string's deepest tier is the device's own port.
    pub fn hub_port(&self) -> Option<(u8, u8)> {
        let parent = self.parent_slot?;
        let mut r = self.route & 0x000F_FFFF;
        let mut port = 0u8;
        while r & 0xf != 0 {
            port = (r & 0xf) as u8;
            r >>= 4;
        }
        (port != 0).then_some((parent, port))
    }

    /// Active `bConfigurationValue` (0 when unconfigured).
    pub fn config_value(&self) -> u8 {
        self.state.lock().config
    }

    /// Record that `SET_CONFIGURATION(value)` succeeded. Claims belong
    /// to the old configuration's interfaces and are dropped.
    pub fn set_config_value(&self, value: u8) {
        let mut st = self.state.lock();
        if st.config != value {
            st.claims.clear();
        }
        st.config = value;
    }

    /// The active configuration's descriptor blob.
    pub fn active_config(&self) -> Option<&[u8]> {
        let value = self.config_value();
        self.configs
            .iter()
            .find(|c| c.len() >= 9 && c[5] == value)
            .map(|c| c.as_slice())
    }

    /// The active configuration's interfaces (alternate setting 0).
    pub fn interfaces(&self) -> Vec<Interface> {
        self.active_config().map(interfaces_of).unwrap_or_default()
    }

    /// Claim `iface` for `owner` (`usb_driver_claim_interface`).
    /// `Err` carries the current holder when someone else has it.
    pub fn claim(&self, iface: u8, owner: Owner) -> Result<(), Owner> {
        let mut st = self.state.lock();
        if let Some((_, held)) = st.claims.iter().find(|(i, _)| *i == iface) {
            return if *held == owner {
                Ok(())
            } else {
                Err(held.clone())
            };
        }
        st.claims.push((iface, owner));
        Ok(())
    }

    /// Release `iface` if `owner` holds it. Returns whether it did.
    pub fn release(&self, iface: u8, owner: &Owner) -> bool {
        let mut st = self.state.lock();
        let before = st.claims.len();
        st.claims.retain(|(i, o)| !(*i == iface && o == owner));
        st.claims.len() != before
    }

    /// Release everything `owner` holds.
    pub fn release_all(&self, owner: &Owner) {
        self.state.lock().claims.retain(|(_, o)| o != owner);
    }

    /// Who holds `iface`, if anyone.
    pub fn owner(&self, iface: u8) -> Option<Owner> {
        self.state
            .lock()
            .claims
            .iter()
            .find(|(i, _)| *i == iface)
            .map(|(_, o)| o.clone())
    }
}

/// Walk a configuration descriptor for its interfaces at alternate
/// setting 0 (USB 2.0 §9.6.5: `bLength`, type 4, number at +2, alt at
/// +3, endpoints at +4, class triple at +5..+7).
pub fn interfaces_of(config: &[u8]) -> Vec<Interface> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 2 <= config.len() {
        let len = usize::from(config[at]);
        if len < 2 || at + len > config.len() {
            break;
        }
        if config[at + 1] == 0x04 && len >= 9 && config[at + 3] == 0 {
            out.push(Interface {
                number: config[at + 2],
                num_endpoints: config[at + 4],
                class: config[at + 5],
                subclass: config[at + 6],
                protocol: config[at + 7],
            });
        }
        at += len;
    }
    out
}

// ── Bus and port numbering ───────────────────────────────────────────

/// One root hub: the bus Linux gives it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RootHub {
    pub controller: u8,
    pub busnum: u8,
    /// USB 3 (SuperSpeed) root hub, as opposed to USB 2.
    pub usb3: bool,
    /// Ports on this root hub.
    pub ports: u8,
}

/// Root-hub major protocol for an xHCI port: 3 for SuperSpeed ports,
/// 2 otherwise (USB 2 and 1.1 ports share the USB 2 root hub).
fn usb3_port(xhci: &Xhci, port: u8) -> bool {
    xhci.port_protocol(port) == 3
}

/// Every root hub, numbered as Linux numbers its buses.
pub fn root_hubs() -> Vec<RootHub> {
    let mut controllers = crate::xhci::controllers();
    controllers.sort_by_key(|c| c.id());
    let mut out = Vec::new();
    let mut next = 1u8;
    for c in &controllers {
        let usb3_ports = (1..=c.max_ports()).filter(|&p| usb3_port(c, p)).count() as u8;
        let usb2_ports = c.max_ports() - usb3_ports;
        out.push(RootHub {
            controller: c.id(),
            busnum: next,
            usb3: false,
            ports: usb2_ports,
        });
        next = next.saturating_add(1);
        if usb3_ports != 0 {
            out.push(RootHub {
                controller: c.id(),
                busnum: next,
                usb3: true,
                ports: usb3_ports,
            });
            next = next.saturating_add(1);
        }
    }
    out
}

/// The bus a device on `root_port` of `xhci` belongs to.
pub fn busnum_for(xhci: &Xhci, root_port: u8) -> Option<u8> {
    let usb3 = usb3_port(xhci, root_port);
    root_hubs()
        .into_iter()
        .find(|h| h.controller == xhci.id() && h.usb3 == usb3)
        .map(|h| h.busnum)
}

/// The root-hub-relative number of xHCI port `port`.
pub fn rh_port(xhci: &Xhci, port: u8) -> u8 {
    let usb3 = usb3_port(xhci, port);
    1 + (1..port).filter(|&p| usb3_port(xhci, p) == usb3).count() as u8
}

/// `devpath` for a device on root-hub port `rh_port` with xHCI route
/// string `route`: the root-hub port, then one `.port` per tier.
pub fn devpath(rh_port: u8, route: u32) -> String {
    let mut s = format!("{rh_port}");
    let mut r = route & 0x000F_FFFF;
    while r != 0 {
        let nibble = r & 0xf;
        if nibble == 0 {
            break;
        }
        s.push_str(&format!(".{nibble}"));
        r >>= 4;
    }
    s
}

/// A root hub's descriptors as Linux synthesizes them (`hcd.c`): the
/// USB 2 or USB 3 root-hub device descriptor and its one configuration,
/// one hub interface with a 4-byte status-change endpoint (plus the SS
/// companion on USB 3). As `rh_call_control` patches them for xHCI, the
/// USB 2 descriptor reports an integrated single TT (protocol 1 in
/// `bDeviceProtocol`) and the configuration remote wakeup
/// (`bmAttributes` 0xe0).
/// `bcdDevice` is the kernel version.
pub fn root_hub_descriptors(hub: &RootHub) -> Vec<u8> {
    let [bcd_lo, bcd_hi] = crate::usb_sysfs::ROOT_HUB_BCD_DEVICE.to_le_bytes();
    let mut d = if hub.usb3 {
        alloc::vec![
            0x12, 0x01, 0x00, 0x03, 0x09, 0x00, 0x03, 0x09, 0x6b, 0x1d, 0x03, 0x00, bcd_lo, bcd_hi,
            0x03, 0x02, 0x01, 0x01,
        ]
    } else {
        alloc::vec![
            0x12, 0x01, 0x00, 0x02, 0x09, 0x00, 0x01, 0x40, 0x6b, 0x1d, 0x02, 0x00, bcd_lo, bcd_hi,
            0x03, 0x02, 0x01, 0x01,
        ]
    };
    // wMaxPacketSize = (USB_MAXCHILDREN + 1 + 7) / 8 = 4.
    let hub_if: [u8; 25] = [
        0x09, 0x02, 0x19, 0x00, 0x01, 0x01, 0x00, 0xe0, 0x00, // configuration
        0x09, 0x04, 0x00, 0x00, 0x01, 0x09, 0x00, 0x00, 0x00, // hub interface
        0x07, 0x05, 0x81, 0x03, 0x04, 0x00, 0x0c, // status-change endpoint
    ];
    d.extend_from_slice(&hub_if);
    if hub.usb3 {
        d.extend_from_slice(&[0x06, 0x30, 0x00, 0x00, 0x02, 0x00]);
        // wTotalLength 0x1f with the companion.
        d[18 + 2] = 0x1f;
    }
    d
}

// ── Device numbers ───────────────────────────────────────────────────

#[derive(Debug)]
struct BusMap {
    busnum: u8,
    /// Bit n set when devnum n is taken; bit 1 is the root hub.
    map: u128,
    next: u8,
}

static DEVMAPS: IrqSafeSpinLock<Vec<BusMap>> = IrqSafeSpinLock::new(Vec::new());

/// `choose_devnum`: the first free number at or after `devnum_next`,
/// wrapping to 1; `devnum_next` moves past it (back to 1 after 127).
pub fn alloc_devnum(busnum: u8) -> Option<u8> {
    let mut g = DEVMAPS.lock();
    let idx = match g.iter().position(|b| b.busnum == busnum) {
        Some(i) => i,
        None => {
            // usb_add_hcd: the root hub is devnum 1, devnum_next 2.
            g.push(BusMap {
                busnum,
                map: 1 << 1,
                next: 2,
            });
            g.len() - 1
        }
    };
    let b = &mut g[idx];
    let free = |from: u8, b: &BusMap| (from..128).find(|&n| b.map & (1u128 << n) == 0);
    let devnum = free(b.next, b).or_else(|| free(1, b))?;
    b.next = if devnum >= 127 { 1 } else { devnum + 1 };
    b.map |= 1u128 << devnum;
    Some(devnum)
}

/// Return `devnum` to `busnum`'s pool (`release_devnum`).
pub fn free_devnum(busnum: u8, devnum: u8) {
    if devnum == 1 || devnum >= 128 {
        return;
    }
    if let Some(b) = DEVMAPS.lock().iter_mut().find(|b| b.busnum == busnum) {
        b.map &= !(1u128 << devnum);
    }
}

// ── Registry ─────────────────────────────────────────────────────────

static DEVICES: IrqSafeSpinLock<Vec<Arc<UsbDev>>> = IrqSafeSpinLock::new(Vec::new());

/// Fetch configuration descriptor `index` in full.
pub async fn fetch_config(xhci: &Xhci, slot: u8, index: u8) -> Option<Vec<u8>> {
    let mut head = [0u8; 9];
    xhci.get_config_descriptor(slot, index, &mut head)
        .await
        .ok()?;
    let total = usize::from(u16::from_le_bytes([head[2], head[3]]));
    if !(9..=0xffff).contains(&total) {
        return None;
    }
    let mut full = alloc::vec![0u8; total];
    let n = xhci
        .get_config_descriptor(slot, index, &mut full)
        .await
        .ok()?;
    full.truncate(n);
    Some(full)
}

/// What [`register`] needs to know about where the device sits.
#[derive(Copy, Clone, Debug)]
pub struct Placement {
    pub root_port: u8,
    pub route: u32,
    pub speed: PortSpeed,
    pub parent_slot: Option<u8>,
}

/// Record a newly addressed device (`usb_new_device`'s bookkeeping):
/// number it, read every configuration descriptor and its strings.
/// The device starts unconfigured. Returns `None` when the bus has no
/// free device number.
pub async fn register(
    xhci: &Xhci,
    slot: u8,
    descriptor: [u8; 18],
    at: Placement,
) -> Option<Arc<UsbDev>> {
    remove(xhci.id(), slot);
    let busnum = busnum_for(xhci, at.root_port)?;
    let devnum = alloc_devnum(busnum)?;
    let mut configs = Vec::new();
    for index in 0..descriptor[17] {
        match fetch_config(xhci, slot, index).await {
            Some(c) => configs.push(c),
            None => break,
        }
    }
    let string = |index: u8| crate::hid::identity::fetch_product_string(xhci, slot, index);
    let manufacturer = string(descriptor[14]).await;
    let product = string(descriptor[15]).await;
    let serial = string(descriptor[16]).await;
    let dev = Arc::new(UsbDev {
        controller: xhci.id(),
        slot,
        generation: xhci.device_generation(slot).unwrap_or(0),
        busnum,
        devnum,
        root_port: at.root_port,
        route: at.route,
        devpath: devpath(rh_port(xhci, at.root_port), at.route),
        speed: at.speed,
        parent_slot: at.parent_slot,
        descriptor,
        configs,
        manufacturer,
        product,
        serial,
        state: IrqSafeSpinLock::new(DevState {
            config: 0,
            claims: Vec::new(),
        }),
    });
    DEVICES.lock().push(dev.clone());
    crate::usb_sysfs::publish_device(xhci, &dev);
    Some(dev)
}

/// Forget `(controller, slot)` (`usb_disconnect`), freeing its device
/// number.
pub fn remove(controller: u8, slot: u8) -> Option<Arc<UsbDev>> {
    if let Some(dev) = find(controller, slot) {
        crate::usb_sysfs::unpublish_device(&dev);
    }
    let removed = {
        let mut g = DEVICES.lock();
        let i = g
            .iter()
            .position(|d| d.controller == controller && d.slot == slot)?;
        g.remove(i)
    };
    free_devnum(removed.busnum, removed.devnum);
    Some(removed)
}

/// Forget every device on `controller` (controller recovery).
pub fn remove_controller(controller: u8) -> Vec<Arc<UsbDev>> {
    // Children attach after their hubs: unpublish newest first.
    for dev in all().iter().rev().filter(|d| d.controller == controller) {
        crate::usb_sysfs::unpublish_device(dev);
    }
    let removed: Vec<Arc<UsbDev>> = {
        let mut g = DEVICES.lock();
        let (gone, keep): (Vec<_>, Vec<_>) = g.drain(..).partition(|d| d.controller == controller);
        *g = keep;
        gone
    };
    for d in &removed {
        free_devnum(d.busnum, d.devnum);
    }
    removed
}

/// The record for `(controller, slot)`.
pub fn find(controller: u8, slot: u8) -> Option<Arc<UsbDev>> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.controller == controller && d.slot == slot)
        .cloned()
}

/// The record named by bus and device number (usbfs's `BBB/DDD`).
pub fn find_by_number(busnum: u8, devnum: u8) -> Option<Arc<UsbDev>> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.busnum == busnum && d.devnum == devnum)
        .cloned()
}

/// Every registered device, in attach order.
pub fn all() -> Vec<Arc<UsbDev>> {
    DEVICES.lock().clone()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    DEVICES.lock().clear();
    DEVMAPS.lock().clear();
}

/// Build a record from `spec` without registering it.
#[doc(hidden)]
pub fn __spec_for_test(spec: UsbDevSpec) -> UsbDev {
    UsbDev {
        controller: spec.controller,
        slot: spec.slot,
        generation: 1,
        busnum: spec.busnum,
        devnum: spec.devnum,
        root_port: spec.root_port,
        route: spec.route,
        devpath: spec.devpath,
        speed: spec.speed,
        parent_slot: None,
        descriptor: spec.descriptor,
        configs: spec.configs,
        manufacturer: None,
        product: None,
        serial: None,
        state: IrqSafeSpinLock::new(DevState {
            config: spec.config,
            claims: Vec::new(),
        }),
    }
}

/// Build and register a record from `spec`.
#[doc(hidden)]
pub fn __insert_for_test(spec: UsbDevSpec) -> Arc<UsbDev> {
    let dev = Arc::new(__spec_for_test(spec));
    DEVICES.lock().push(dev.clone());
    dev
}

/// Fields for [`__spec_for_test`] / [`__insert_for_test`].
#[doc(hidden)]
#[derive(Debug)]
pub struct UsbDevSpec {
    pub controller: u8,
    pub slot: u8,
    pub busnum: u8,
    pub devnum: u8,
    pub root_port: u8,
    pub route: u32,
    pub devpath: String,
    pub speed: PortSpeed,
    pub descriptor: [u8; 18],
    pub configs: Vec<Vec<u8>>,
    pub config: u8,
}
