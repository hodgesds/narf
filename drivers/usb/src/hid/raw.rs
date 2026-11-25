//! Raw HID over USB: the usbhid half of hidraw.
//!
//! Linux binds usbhid to every HID-class interface. Each becomes a
//! `hid_device`, and every input report it receives reaches hidraw.
//! Here, an interface no in-kernel input binder claimed binds through
//! [`bind_interface`]. FIDO authenticators (page 0xF1D0) are the main
//! case: no input mapping exists for them, and raw access through
//! `/dev/hidrawN` is how browsers and libfido2 reach them.
//!
//! The binding:
//!
//! - registers a [`narf_input::hid_device`] device with usbhid's
//!   identity (name, phys, uniq, bcdHID, country) and the report
//!   descriptor;
//! - pumps its interrupt-IN endpoint into `report_in`;
//! - serves output and get/set report requests ([`UsbHidTransport`],
//!   `usbhid_output_report` / `usbhid_raw_request`).
//!
//! Interfaces bound by an input binder (boot keyboard, mouse, …)
//! publish through the same registry from their own pumps.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use async_trait::async_trait;
use narf_input::hid_device::{self, HidDevice, HidInfo, HidIoError, HidTransport, ReportType};
use narf_lib::sync::IrqSafeSpinLock;

use crate::usbdev::{Owner, UsbDev};
use crate::xhci::{EndpointConfig, EndpointKind, Xhci, XhciError, USB_REQ_GET_DESCRIPTOR};

const HID_INTERFACE_CLASS: u8 = 0x03;
const HID_DT_HID: u8 = 0x21;
const HID_DT_REPORT: u8 = 0x22;
const HID_REQ_GET_REPORT: u8 = 0x01;
const HID_REQ_SET_IDLE: u8 = 0x0a;
const HID_REQ_SET_REPORT: u8 = 0x09;
/// `USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE`.
const RT_CLASS_IFACE_IN: u8 = 0xa1;
/// `USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE`.
const RT_CLASS_IFACE_OUT: u8 = 0x21;
/// `USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_INTERFACE`.
const RT_STD_IFACE_IN: u8 = 0x81;
/// Largest single interrupt transfer the endpoint page carries.
const MAX_TRANSFER: usize = 4096;
/// `USB_CTRL_SET_TIMEOUT`: 5 s for an interrupt-OUT report.
const OUT_TIMEOUT_NS: u64 = 5_000_000_000;

/// The pieces of a HID interface's descriptors usbhid reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HidInterface {
    pub number: u8,
    /// `bcdHID` from the HID class descriptor.
    pub bcd_hid: u16,
    pub country: u8,
    /// `wDescriptorLength` of the report descriptor.
    pub report_len: u16,
    pub in_ep: EndpointConfig,
    pub out_ep: Option<EndpointConfig>,
}

/// Walk the configuration for the HID interface starting at `offset`:
/// its HID class descriptor, first interrupt-IN and first interrupt-OUT
/// endpoints (`usbhid_parse` / `usbhid_start`). `None` when it is not a
/// HID interface with a report descriptor and an interrupt-IN endpoint.
pub fn parse_interface(cfg: &[u8], offset: usize) -> Option<HidInterface> {
    let head = cfg.get(offset..offset + 9)?;
    if head[1] != 0x04 || head[5] != HID_INTERFACE_CLASS {
        return None;
    }
    let number = head[2];
    let mut hid: Option<(u16, u8, u16)> = None;
    let mut in_ep = None;
    let mut out_ep = None;
    let mut at = offset + usize::from(head[0]);
    while at + 2 <= cfg.len() {
        let len = usize::from(cfg[at]);
        if len < 2 || at + len > cfg.len() {
            break;
        }
        match cfg[at + 1] {
            0x04 => break, // next interface (or alternate setting)
            HID_DT_HID if len >= 9 && cfg[at + 6] == HID_DT_REPORT => {
                hid = Some((
                    u16::from_le_bytes([cfg[at + 2], cfg[at + 3]]),
                    cfg[at + 4],
                    u16::from_le_bytes([cfg[at + 7], cfg[at + 8]]),
                ));
            }
            0x05 if len >= 7 && cfg[at + 3] & 0x03 == 0x03 => {
                let addr = cfg[at + 2];
                let ep = EndpointConfig {
                    ep_addr: addr,
                    max_packet: u16::from_le_bytes([cfg[at + 4], cfg[at + 5]]) & 0x7ff,
                    kind: if addr & 0x80 != 0 {
                        EndpointKind::InterruptIn
                    } else {
                        EndpointKind::InterruptOut
                    },
                    interval: cfg[at + 6],
                };
                if addr & 0x80 != 0 {
                    in_ep.get_or_insert(ep);
                } else {
                    out_ep.get_or_insert(ep);
                }
            }
            _ => {}
        }
        at += len;
    }
    let (bcd_hid, country, report_len) = hid?;
    Some(HidInterface {
        number,
        bcd_hid,
        country,
        report_len,
        in_ep: in_ep?,
        out_ep,
    })
}

/// Offsets of every HID-class interface at alternate setting 0.
pub fn hid_interface_offsets(cfg: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 2 <= cfg.len() {
        let len = usize::from(cfg[at]);
        if len < 2 || at + len > cfg.len() {
            break;
        }
        if cfg[at + 1] == 0x04 && len >= 9 && cfg[at + 3] == 0 && cfg[at + 5] == HID_INTERFACE_CLASS
        {
            out.push(at);
        }
        at += len;
    }
    out
}

/// `hid_find_max_report(hid, HID_INPUT_REPORT, &insize)`: the longest
/// input report in bytes, counting the report-ID byte when the device
/// numbers its reports.
pub fn max_input_report(report_desc: &[u8]) -> usize {
    let Ok(desc) = narf_hid::parse(report_desc) else {
        return 0;
    };
    let mut per_id: Vec<(u8, u32)> = Vec::new();
    for f in &desc.fields {
        if f.kind != narf_hid::FieldKind::Input {
            continue;
        }
        let end = f.bit_offset + f.report_size * f.report_count;
        match per_id.iter_mut().find(|(id, _)| *id == f.report_id) {
            Some((_, bits)) => *bits = (*bits).max(end),
            None => per_id.push((f.report_id, end)),
        }
    }
    let numbered = usize::from(desc.has_report_ids);
    per_id
        .iter()
        .map(|&(_, bits)| (bits as usize).div_ceil(8) + numbered)
        .max()
        .unwrap_or(0)
}

/// usbhid's `hid->name`: manufacturer and product, else `HID vvvv:pppp`.
pub fn hid_name(dev: &UsbDev) -> String {
    let mut name = String::new();
    if let Some(m) = &dev.manufacturer {
        name.push_str(m);
    }
    if let Some(p) = &dev.product {
        if !name.is_empty() {
            name.push(' ');
        }
        name.push_str(p);
    }
    if name.is_empty() {
        name = format!("HID {:04x}:{:04x}", dev.vendor(), dev.product_id());
    }
    truncate_to(&mut name, 127);
    name
}

fn truncate_to(s: &mut String, max: usize) {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
}

/// `usb_make_path` + `/input<n>`: `usb-<hcd bus name>-<devpath>/input<n>`.
pub fn hid_phys(pci_slot: &str, dev: &UsbDev, iface: u8) -> String {
    let mut phys = format!("usb-{}-{}/input{}", pci_slot, dev.devpath, iface);
    truncate_to(&mut phys, 63);
    phys
}

/// The xHCI's PCI slot name (`0000:c6:00.4`), the HCD's `bus_name`.
pub fn pci_slot_name(xhci: &Xhci) -> String {
    match xhci.bus_addr() {
        narf_bus::BusAddr::Pcie(a) => format!(
            "{:04x}:{:02x}:{:02x}.{}",
            a.segment, a.bus, a.device, a.function
        ),
        _ => String::from("narf"),
    }
}

/// The sysfs path (below `/sys`) of a USB interface: the xHCI's PCI
/// kobject as `filesystem::sysfs` names it (`devices/pciSSSS:BB/` +
/// slot), then `usbN/<dev>/<dev>:<config>.<iface>` as Linux names
/// them.
pub fn interface_sysfs_path(xhci: &Xhci, dev: &UsbDev, config: u8, iface: u8) -> String {
    let pci = match xhci.bus_addr() {
        narf_bus::BusAddr::Pcie(a) => format!(
            "devices/pci{:04x}:{:02x}/{}",
            a.segment,
            a.bus,
            pci_slot_name(xhci)
        ),
        _ => String::from("devices/platform/narf-usb"),
    };
    let name = dev.name();
    format!("{pci}/usb{}/{name}/{name}:{config}.{iface}", dev.busnum)
}

fn io_error(e: XhciError) -> HidIoError {
    match e {
        XhciError::CmdFailed(6) => HidIoError::Stall,
        XhciError::CmdFailed(0xFD) | XhciError::BadPort => HidIoError::NoDevice,
        XhciError::CmdTimeout | XhciError::PortResetTimeout | XhciError::ResetTimeout => {
            HidIoError::Timeout
        }
        _ => HidIoError::Io,
    }
}

/// The HID transport of one bound USB interface.
#[derive(Debug)]
pub struct UsbHidTransport {
    controller: u8,
    slot: u8,
    generation: u64,
    iface: u8,
    out_ep: Option<EndpointConfig>,
}

impl UsbHidTransport {
    fn xhci(&self) -> Result<Arc<Xhci>, HidIoError> {
        let x = crate::xhci::controller_by_id(self.controller).ok_or(HidIoError::NoDevice)?;
        if x.device_generation(self.slot) != Some(self.generation) {
            return Err(HidIoError::NoDevice);
        }
        Ok(x)
    }
}

#[async_trait]
impl HidTransport for UsbHidTransport {
    /// `usbhid_output_report`: interrupt OUT, a leading 0 report ID not
    /// sent but counted.
    async fn output_report(&self, data: &[u8]) -> Result<usize, HidIoError> {
        let Some(ep) = self.out_ep else {
            return Err(HidIoError::Unsupported);
        };
        let xhci = self.xhci()?;
        let (payload, skipped) = match data.first() {
            Some(0) => (&data[1..], 1),
            _ => (data, 0),
        };
        if payload.is_empty() || payload.len() > MAX_TRANSFER {
            return Err(HidIoError::InvalidArgs);
        }
        let dci = ep.dci();
        xhci.arm_interrupt_out(self.slot, dci, payload)
            .map_err(io_error)?;
        let deadline = now_ns().saturating_add(OUT_TIMEOUT_NS);
        loop {
            match xhci.poll_interrupt_out(self.slot, dci, payload.len() as u32) {
                Ok(Some(n)) => return Ok(n + skipped),
                Ok(None) => {}
                Err(e) => return Err(io_error(e)),
            }
            if now_ns() >= deadline {
                return Err(HidIoError::Timeout);
            }
            narf_scheduler::yield_now().await;
        }
    }

    /// `usbhid_raw_request` → `usbhid_get_raw_report` /
    /// `usbhid_set_raw_report`. With report ID 0 the ID byte is not on
    /// the wire, but stays in `buf[0]` and is counted.
    async fn raw_request(
        &self,
        id: u8,
        buf: &mut [u8],
        kind: ReportType,
        set: bool,
    ) -> Result<usize, HidIoError> {
        let xhci = self.xhci()?;
        if buf.is_empty() {
            return Err(HidIoError::InvalidArgs);
        }
        let value = (u16::from(kind.wire()) << 8) | u16::from(id);
        let index = u16::from(self.iface);
        let n = if set {
            let (wire, skipped) = if buf[0] == 0 {
                (&buf[1..], 1)
            } else {
                (&buf[..], 0)
            };
            let n = xhci
                .control_out_generation(
                    self.slot,
                    self.generation,
                    RT_CLASS_IFACE_OUT,
                    HID_REQ_SET_REPORT,
                    value,
                    index,
                    wire,
                )
                .await
                .map_err(io_error)?;
            if n > 0 {
                n + skipped
            } else {
                n
            }
        } else {
            buf[0] = id;
            let (wire, skipped) = if id == 0 {
                (&mut buf[1..], 1)
            } else {
                (&mut buf[..], 0)
            };
            let n = xhci
                .control_in_generation(
                    self.slot,
                    self.generation,
                    RT_CLASS_IFACE_IN,
                    HID_REQ_GET_REPORT,
                    value,
                    index,
                    wire,
                )
                .await
                .map_err(io_error)?;
            if n > 0 {
                n + skipped
            } else {
                n
            }
        };
        Ok(n)
    }
}

pub(crate) fn now_ns() -> u64 {
    narf_time::cycles_to_ns(narf_time::raw_cycles())
}

/// One raw-bound interface.
#[derive(Debug)]
struct RawBinding {
    controller: u8,
    slot: u8,
    /// `(parent hub slot, port)` behind a hub, kept out of idle suspend.
    hub_port: Option<(u8, u8)>,
    iface: u8,
    in_dci: u8,
    in_len: u32,
    dev: Arc<HidDevice>,
}

static RAW: IrqSafeSpinLock<Vec<RawBinding>> = IrqSafeSpinLock::new(Vec::new());

/// Why [`bind_interface`] did not bind.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RawError {
    /// Not a usable HID interface (no report descriptor or interrupt IN).
    NotHid,
    /// Another owner holds the interface.
    Claimed,
    /// A control or endpoint operation failed.
    Transfer(XhciError),
}

/// Bind the HID interface at `offset` of `cfg` (the active
/// configuration) as raw HID: claim it, SET_IDLE(0), read its report
/// descriptor, configure its interrupt endpoints, register the device
/// and arm the first IN transfer.
pub async fn bind_interface(
    xhci: &Xhci,
    usb: &Arc<UsbDev>,
    cfg: &[u8],
    offset: usize,
) -> Result<Arc<HidDevice>, RawError> {
    let hi = parse_interface(cfg, offset).ok_or(RawError::NotHid)?;
    if hi.report_len == 0 || usize::from(hi.report_len) > hid_device::HID_MAX_DESCRIPTOR_SIZE {
        return Err(RawError::NotHid);
    }
    let owner = Owner::Driver("usbhid");
    usb.claim(hi.number, owner.clone())
        .map_err(|_| RawError::Claimed)?;
    let r = bind_claimed(xhci, usb, &hi).await;
    if r.is_err() {
        usb.release(hi.number, &owner);
    }
    r
}

async fn bind_claimed(
    xhci: &Xhci,
    usb: &Arc<UsbDev>,
    hi: &HidInterface,
) -> Result<Arc<HidDevice>, RawError> {
    let slot = usb.slot;
    let generation = usb.generation;
    // usbhid_parse: hid_set_idle(dev, ifnum, 0, 0), result ignored.
    let _ = xhci
        .control_out_generation(
            slot,
            generation,
            RT_CLASS_IFACE_OUT,
            HID_REQ_SET_IDLE,
            0,
            u16::from(hi.number),
            &[],
        )
        .await;
    let mut rdesc = alloc::vec![0u8; usize::from(hi.report_len)];
    let n = xhci
        .control_in_generation(
            slot,
            generation,
            RT_STD_IFACE_IN,
            USB_REQ_GET_DESCRIPTOR,
            u16::from(HID_DT_REPORT) << 8,
            u16::from(hi.number),
            &mut rdesc,
        )
        .await
        .map_err(RawError::Transfer)?;
    rdesc.truncate(n);

    let mut eps = alloc::vec![hi.in_ep];
    eps.extend(hi.out_ep);
    xhci.configure_endpoints(slot, &eps)
        .await
        .map_err(RawError::Transfer)?;

    let in_len = max_input_report(&rdesc)
        .max(usize::from(hi.in_ep.max_packet))
        .clamp(1, MAX_TRANSFER) as u32;
    let in_dci = hi.in_ep.dci();
    xhci.arm_interrupt_in(slot, in_dci, in_len)
        .map_err(RawError::Transfer)?;

    let info = HidInfo {
        bus: narf_input::evdev::bus::USB,
        vendor: u32::from(usb.vendor()),
        product: u32::from(usb.product_id()),
        version: u32::from(hi.bcd_hid),
        country: hi.country,
        name: hid_name(usb),
        phys: hid_phys(&pci_slot_name(xhci), usb, hi.number),
        uniq: usb.serial.clone().unwrap_or_default(),
        report_descriptor: rdesc,
        sysfs_parent: interface_sysfs_path(xhci, usb, usb.config_value(), hi.number),
    };
    let transport = Arc::new(UsbHidTransport {
        controller: xhci.id(),
        slot,
        generation,
        iface: hi.number,
        out_ep: hi.out_ep,
    });
    let dev = hid_device::register(info, transport);
    RAW.lock().push(RawBinding {
        controller: xhci.id(),
        slot,
        hub_port: usb.hub_port(),
        iface: hi.number,
        in_dci,
        in_len,
        dev: dev.clone(),
    });
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  usb-hid: raw {} iface={} on {} ({})",
            dev.sysfs_name(),
            hi.number,
            usb.name(),
            dev.info().name
        );
    }
    Ok(dev)
}

/// Bind every HID interface of the active configuration that nobody
/// claimed. Returns how many bound.
pub async fn bind_unclaimed(xhci: &Xhci, usb: &Arc<UsbDev>) -> usize {
    let Some(cfg) = usb.active_config().map(|c| c.to_vec()) else {
        return 0;
    };
    let mut bound = 0;
    for offset in hid_interface_offsets(&cfg) {
        let number = cfg[offset + 2];
        if usb.owner(number).is_some() {
            continue;
        }
        if bind_interface(xhci, usb, &cfg, offset).await.is_ok() {
            bound += 1;
        }
    }
    bound
}

/// Drain every raw-bound interface on `xhci` into its device's
/// `report_in`. Called from the supervisor's pump.
pub fn pump_all(xhci: &Xhci) -> usize {
    let targets: Vec<(u8, u8, u32, Arc<HidDevice>)> = RAW
        .lock()
        .iter()
        .filter(|b| b.controller == xhci.id())
        .map(|b| (b.slot, b.in_dci, b.in_len, b.dev.clone()))
        .collect();
    let mut reports = 0;
    let mut buf = [0u8; MAX_TRANSFER];
    for (slot, dci, len, dev) in targets {
        let window = &mut buf[..len as usize];
        while let Ok(Some(n)) = xhci.poll_interrupt_in(slot, dci, window) {
            dev.report_in(&window[..n.min(window.len())]);
            reports += 1;
        }
    }
    reports
}

/// Unbind the raw interfaces of `(controller, slot)`.
pub fn detach(controller: u8, slot: u8) {
    let gone: Vec<RawBinding> = {
        let mut g = RAW.lock();
        let (gone, keep) = core::mem::take(&mut *g)
            .into_iter()
            .partition(|b| b.controller == controller && b.slot == slot);
        *g = keep;
        gone
    };
    for b in gone {
        hid_device::unregister(&b.dev);
    }
}

/// Unbind the raw binding of interface `iface` alone (usbfs DISCONNECT,
/// `usb_driver_release_interface`), releasing its claim. Returns whether
/// one was bound. Its armed interrupt TRB stays posted until the caller
/// reprograms the endpoints.
pub fn unbind_interface(controller: u8, slot: u8, iface: u8) -> bool {
    let gone: Vec<RawBinding> = {
        let mut g = RAW.lock();
        let (gone, keep) = core::mem::take(&mut *g)
            .into_iter()
            .partition(|b| b.controller == controller && b.slot == slot && b.iface == iface);
        *g = keep;
        gone
    };
    let any = !gone.is_empty();
    for b in gone {
        hid_device::unregister(&b.dev);
    }
    if any {
        if let Some(usb) = crate::usbdev::find(controller, slot) {
            usb.release(iface, &Owner::Driver("usbhid"));
        }
    }
    any
}

/// Unbind every raw interface on `controller` (controller recovery).
pub fn detach_all(controller: u8) {
    let gone: Vec<RawBinding> = {
        let mut g = RAW.lock();
        let (gone, keep) = core::mem::take(&mut *g)
            .into_iter()
            .partition(|b| b.controller == controller);
        *g = keep;
        gone
    };
    for b in gone {
        hid_device::unregister(&b.dev);
    }
}

/// Drain the endpoint of the raw binding behind `dev`, for a caller
/// that waits on its reports synchronously (the CTAPHID pipe).
pub fn pump_device(dev: &Arc<HidDevice>) -> usize {
    let target = RAW
        .lock()
        .iter()
        .find(|b| Arc::ptr_eq(&b.dev, dev))
        .map(|b| (b.controller, b.slot, b.in_dci, b.in_len));
    let Some((controller, slot, dci, len)) = target else {
        return 0;
    };
    let Some(xhci) = crate::xhci::controller_by_id(controller) else {
        return 0;
    };
    let mut buf = [0u8; MAX_TRANSFER];
    let window = &mut buf[..len as usize];
    let mut reports = 0;
    while let Ok(Some(n)) = xhci.poll_interrupt_in(slot, dci, window) {
        dev.report_in(&window[..n.min(window.len())]);
        reports += 1;
    }
    reports
}

/// A HID device an input binder owns, unregistered when the binding
/// is dropped.
#[derive(Debug)]
pub struct RawHidHandle(Arc<HidDevice>);

impl RawHidHandle {
    /// Tee one input report into the device's raw stream.
    pub fn report_in(&self, data: &[u8]) {
        self.0.report_in(data);
    }

    pub fn device(&self) -> &Arc<HidDevice> {
        &self.0
    }
}

impl Drop for RawHidHandle {
    fn drop(&mut self) {
        hid_device::unregister(&self.0);
    }
}

/// Publish interface `iface` of `(xhci, slot)` — which an input binder
/// (boot keyboard, …) has just bound in configuration index 0 — as a HID
/// device too, as usbhid and hid-input share one `hid_device` in Linux.
/// The binder keeps the endpoint and tees its reports through the
/// returned handle. Output reports take the SET_REPORT path, because
/// the binder configures no interrupt-OUT endpoint. `None` when the
/// interface has no report descriptor to publish.
pub async fn register_binder_interface(xhci: &Xhci, slot: u8, iface: u8) -> Option<RawHidHandle> {
    let usb = crate::usbdev::find(xhci.id(), slot)?;
    let cfg = usb.configs.first()?.clone();
    let config_value = *cfg.get(5)?;
    let offset = hid_interface_offsets(&cfg)
        .into_iter()
        .find(|&o| cfg[o + 2] == iface)?;
    let hi = parse_interface(&cfg, offset)?;
    if hi.report_len == 0 || usize::from(hi.report_len) > hid_device::HID_MAX_DESCRIPTOR_SIZE {
        return None;
    }
    // The binder has just set this configuration; record it before the
    // claim so recording it again later keeps the claim.
    usb.set_config_value(config_value);
    let _ = usb.claim(iface, Owner::Driver("usbhid"));
    let mut rdesc = alloc::vec![0u8; usize::from(hi.report_len)];
    let n = xhci
        .control_in_generation(
            slot,
            usb.generation,
            RT_STD_IFACE_IN,
            USB_REQ_GET_DESCRIPTOR,
            u16::from(HID_DT_REPORT) << 8,
            u16::from(iface),
            &mut rdesc,
        )
        .await
        .ok()?;
    rdesc.truncate(n);
    let info = HidInfo {
        bus: narf_input::evdev::bus::USB,
        vendor: u32::from(usb.vendor()),
        product: u32::from(usb.product_id()),
        version: u32::from(hi.bcd_hid),
        country: hi.country,
        name: hid_name(&usb),
        phys: hid_phys(&pci_slot_name(xhci), &usb, iface),
        uniq: usb.serial.clone().unwrap_or_default(),
        report_descriptor: rdesc,
        sysfs_parent: interface_sysfs_path(xhci, &usb, config_value, iface),
    };
    let transport = Arc::new(UsbHidTransport {
        controller: xhci.id(),
        slot,
        generation: usb.generation,
        iface,
        out_ep: None,
    });
    Some(RawHidHandle(hid_device::register(info, transport)))
}

/// Hub ports with raw-bound devices on `controller`: an authenticator
/// waiting for a touch must not be idle-suspended.
pub fn hub_ports(controller: u8) -> Vec<(u8, u8)> {
    RAW.lock()
        .iter()
        .filter(|b| b.controller == controller)
        .filter_map(|b| b.hub_port)
        .collect()
}

/// Whether `(controller, slot)` has a raw-bound interface (the idle
/// suspend pass keeps such devices awake).
pub fn has_binding(controller: u8, slot: u8) -> bool {
    RAW.lock()
        .iter()
        .any(|b| b.controller == controller && b.slot == slot)
}

#[doc(hidden)]
pub fn __bound_ifaces_for_test(controller: u8, slot: u8) -> Vec<u8> {
    RAW.lock()
        .iter()
        .filter(|b| b.controller == controller && b.slot == slot)
        .map(|b| b.iface)
        .collect()
}
