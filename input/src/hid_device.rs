//! Transport-neutral HID devices — the part of Linux's HID core
//! (`struct hid_device`, `struct hid_ll_driver`) that raw HID users
//! need.
//!
//! Every HID transport (USB HID, I2C-HID) registers each device it binds
//! here, with its identity and its raw report descriptor. It hands every
//! input report it receives to [`HidDevice::report_in`] before any
//! parsing, and implements [`HidTransport`] so raw users can send output
//! reports and get or set reports. Consumers subscribe:
//!
//! - `/dev/hidrawN` (the filesystem crate) through [`set_change_hook`]
//!   and [`HidDevice::subscribe`];
//! - in-kernel raw clients through [`HidDevice::subscribe`].
//!
//! Identity follows `struct hid_device`. Vendor, product and version are
//! 32-bit, as sysfs prints them in `HID_ID=%04X:%08X:%08X`, and devices
//! are numbered in registration order (`hid->id`, the `.%04X` of the
//! sysfs name `BBBB:VVVV:PPPP.NNNN`).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use async_trait::async_trait;
use narf_lib::sync::IrqSafeSpinLock;

/// `HID_MAX_DESCRIPTOR_SIZE`: the largest report descriptor accepted.
pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
/// `HID_MAX_BUFFER_SIZE`: the largest report a raw user may send.
pub const HID_MAX_BUFFER_SIZE: usize = 16384;

/// A HID report type (`enum hid_report_type`). On the wire, USB's
/// `wValue` high byte and I2C-HID's report-type field are `self as u8
/// + 1` (Input 1, Output 2, Feature 3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReportType {
    Input = 0,
    Output = 1,
    Feature = 2,
}

impl ReportType {
    /// The 1-based transport encoding (`HID_*_REPORT + 1`).
    pub const fn wire(self) -> u8 {
        self as u8 + 1
    }
}

/// A failed transport request. Each variant is the errno Linux's
/// transports return through `hid_hw_*`, so raw users can hand it back
/// to userspace unchanged.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HidIoError {
    /// The device is gone (`-ENODEV`).
    NoDevice,
    /// The device stalled the request (`-EPIPE`).
    Stall,
    /// The request timed out (`-ETIMEDOUT`).
    Timeout,
    /// The transport has no such path, e.g. no interrupt OUT endpoint
    /// (`-ENOSYS`, what `hid_hw_output_report` returns without one).
    Unsupported,
    /// The request is malformed for this transport (`-EINVAL`).
    InvalidArgs,
    /// Any other transfer failure (`-EIO`).
    Io,
}

/// What a raw user can ask of the transport (`struct hid_ll_driver`).
#[async_trait]
pub trait HidTransport: Send + Sync + core::fmt::Debug {
    /// `hid_hw_output_report`: send `data` as an output report on the
    /// transport's interrupt-OUT path. `data[0]` is the report ID (0
    /// when the device uses none). `Err(Unsupported)` when there is no
    /// such path. hidraw then falls back to `raw_request(Output, set)`,
    /// as `hidraw_send_report` does.
    async fn output_report(&self, data: &[u8]) -> Result<usize, HidIoError>;

    /// `hid_hw_raw_request`: GET_REPORT (`set == false`, filling `buf`)
    /// or SET_REPORT (`set == true`, sending `buf`) of `kind` for
    /// report `id`. `buf[0]` holds the report ID, as in Linux. Returns
    /// the number of bytes transferred.
    async fn raw_request(
        &self,
        id: u8,
        buf: &mut [u8],
        kind: ReportType,
        set: bool,
    ) -> Result<usize, HidIoError>;
}

/// A device's identity, as the transport discovered it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HidInfo {
    /// `BUS_*` ([`crate::evdev::bus`]).
    pub bus: u16,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    /// HID descriptor `bCountryCode`.
    pub country: u8,
    pub name: String,
    pub phys: String,
    pub uniq: String,
    /// The raw report descriptor, at most [`HID_MAX_DESCRIPTOR_SIZE`].
    pub report_descriptor: Vec<u8>,
    /// sysfs path (below `/sys`) of the transport device this HID
    /// device sits under, e.g.
    /// `devices/pci0000:00/0000:00:08.3/0000:c6:00.4/usb7/7-1/7-1:1.1`.
    /// Empty means the publisher picks the platform parent.
    pub sysfs_parent: String,
}

/// A raw-input-report subscriber. Called from the transport's receive
/// path, so keep it short: copy and wake.
pub type ReportSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// One registered HID device.
pub struct HidDevice {
    id: u32,
    info: HidInfo,
    transport: Arc<dyn HidTransport>,
    alive: AtomicBool,
    sinks: IrqSafeSpinLock<Vec<(u64, ReportSink)>>,
    next_sink: AtomicU32,
}

impl core::fmt::Debug for HidDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HidDevice")
            .field("id", &self.id)
            .field("info", &self.info)
            .field("alive", &self.alive.load(Ordering::Relaxed))
            .finish()
    }
}

impl HidDevice {
    /// Registration-order number (`hid->id`).
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn info(&self) -> &HidInfo {
        &self.info
    }

    pub fn transport(&self) -> &Arc<dyn HidTransport> {
        &self.transport
    }

    /// False once [`unregister`] has run.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Linux's sysfs name for the device: `BBBB:VVVV:PPPP.NNNN`
    /// (`hid_add_device`).
    pub fn sysfs_name(&self) -> String {
        alloc::format!(
            "{:04X}:{:04X}:{:04X}.{:04X}",
            self.info.bus,
            self.info.vendor & 0xffff,
            self.info.product & 0xffff,
            self.id
        )
    }

    /// Hand one input report, exactly as received (report ID first
    /// when the device uses IDs), to every subscriber
    /// (`hid_input_report` → `hidraw_report_event`).
    pub fn report_in(&self, data: &[u8]) {
        if !self.is_alive() {
            return;
        }
        // Snapshot so a sink runs without the lock (it may wake a
        // poller, which may subscribe or unsubscribe).
        let sinks: Vec<ReportSink> = self.sinks.lock().iter().map(|(_, s)| s.clone()).collect();
        for sink in &sinks {
            sink(data);
        }
    }

    /// Subscribe to raw input reports. Returns the handle for
    /// [`HidDevice::unsubscribe`].
    pub fn subscribe(&self, sink: ReportSink) -> u64 {
        let id = u64::from(self.next_sink.fetch_add(1, Ordering::Relaxed));
        self.sinks.lock().push((id, sink));
        id
    }

    pub fn unsubscribe(&self, handle: u64) {
        self.sinks.lock().retain(|(id, _)| *id != handle);
    }
}

/// What a change hook is told.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Added,
    Removed,
}

type ChangeHook = fn(&Arc<HidDevice>, Change);

static DEVICES: IrqSafeSpinLock<Vec<Arc<HidDevice>>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
static HOOK: IrqSafeSpinLock<Option<ChangeHook>> = IrqSafeSpinLock::new(None);

/// Install the publisher's change hook (one per boot: the filesystem's
/// hidraw bridge). Devices already registered are replayed as
/// `Added`.
pub fn set_change_hook(hook: ChangeHook) {
    *HOOK.lock() = Some(hook);
    for dev in devices() {
        hook(&dev, Change::Added);
    }
}

fn notify(dev: &Arc<HidDevice>, change: Change) {
    let hook = *HOOK.lock();
    if let Some(hook) = hook {
        hook(dev, change);
    }
}

/// Register a device the transport has bound (`hid_add_device`). The
/// report descriptor is truncated to [`HID_MAX_DESCRIPTOR_SIZE`].
pub fn register(mut info: HidInfo, transport: Arc<dyn HidTransport>) -> Arc<HidDevice> {
    info.report_descriptor.truncate(HID_MAX_DESCRIPTOR_SIZE);
    let dev = Arc::new(HidDevice {
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        info,
        transport,
        alive: AtomicBool::new(true),
        sinks: IrqSafeSpinLock::new(Vec::new()),
        next_sink: AtomicU32::new(1),
    });
    DEVICES.lock().push(dev.clone());
    notify(&dev, Change::Added);
    dev
}

/// Remove a device (`hid_destroy_device`): it stops delivering reports,
/// its subscribers are dropped, and the publisher is told. Opens that
/// still hold the `Arc` see [`HidDevice::is_alive`] go false.
pub fn unregister(dev: &Arc<HidDevice>) {
    dev.alive.store(false, Ordering::Release);
    DEVICES.lock().retain(|d| !Arc::ptr_eq(d, dev));
    dev.sinks.lock().clear();
    notify(dev, Change::Removed);
}

/// Every live device, in registration order.
pub fn devices() -> Vec<Arc<HidDevice>> {
    DEVICES.lock().clone()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    let all: Vec<Arc<HidDevice>> = core::mem::take(&mut *DEVICES.lock());
    for dev in &all {
        dev.alive.store(false, Ordering::Release);
    }
    *HOOK.lock() = None;
    NEXT_ID.store(1, Ordering::Relaxed);
}
