//! The module build's USB binding: the rtw88 USB driver over the USB KABI.
//!
//! Built in, `usb_driver.rs` registers the RTL8821CU / RTL8822BU id tables
//! with the USB class registry and attaches over a `USBDevice`. In the
//! `.ko` the same ids are registered through `narf_register_usb_driver`, and
//! the probe drives the function through `narf_usb_*` requests. Everything
//! from the first register access on is the driver's own code:
//! `usb_firmware::Backend` (registers, firmware, H2C, packets),
//! `usb_driver`'s factory read and provisioning stages, the
//! `firmware_lifecycle` stage machine and the `interface::Device` station
//! shell. This file supplies only what `usb_driver.rs` gets from the kernel
//! USB stack:
//!
//! - [`Control`] — the `ControlIo` EP0 transport (Realtek vendor requests),
//!   over `narf_usb_control`;
//! - [`Bulk`] — the `Io` bulk-pipe transport over `narf_usb_submit` /
//!   `narf_usb_poll` / `narf_usb_cancel`. The KABI moves at most 4 KiB per
//!   request and one request per endpoint at a time; rtw88 posts 32 KiB
//!   receive buffers, 4.1 KiB firmware pages and several queued sends per
//!   pipe. A [`Bulk`] transfer is therefore a chain of 4 KiB requests on a
//!   per-endpoint FIFO: an OUT transfer is split on 4 KiB boundaries (a
//!   multiple of every bulk `wMaxPacketSize`, so the packets on the wire are
//!   the same as one transfer's) and an IN transfer completes on the first
//!   short chunk or when full — exactly when one large URB would;
//! - the attach sequence (`usb_driver::attach`): device identity, SET_
//!   CONFIGURATION and endpoint configuration, then the driver's own power
//!   on, factory map, B22 PHY/mode switch, shell publication and the
//!   retried provisioning through station activation;
//! - the executor heartbeat: `narf_usb_spawn_poller` (1 ms) and every USB
//!   completion run [`platform::EXEC`].

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};

use super::firmware_lifecycle::{Lifecycle, Stage};
use super::firmware_transport::Error;
use super::platform::narf_drivers_usb::bulk::ep_for;
use super::platform::narf_drivers_usb::device::UsbError;
use super::platform::narf_drivers_usb::xhci::PortSpeed;
use super::platform::narf_drivers_wireless_rtl_usb::{
    ControlIo, Io, REALTEK_USB_CMD_REQ, REALTEK_USB_READ, REALTEK_USB_WRITE,
};
use super::platform::narf_lib::sync::IrqSafeSpinLock;
use super::platform::{self, narf_console};
use super::usb::{self, Endpoints, Speed};
use super::usb_driver::{self, Backend, Factory, Station};

/// KABI exports this binding calls.
mod ffi {
    unsafe extern "C" {
        #[allow(clippy::too_many_arguments)]
        pub fn narf_register_usb_driver(
            name: *const u8,
            name_len: usize,
            match_flags: u16,
            vendor: u16,
            product: u16,
            class: u8,
            subclass: u8,
            protocol: u8,
            probe: usize,
        ) -> i32;
        pub fn narf_usb_config_descriptor(
            dev: u64,
            buf: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> i32;
        pub fn narf_usb_configure(
            dev: u64,
            endpoints: *const u8,
            count: usize,
            callback: usize,
            cookie: u64,
            out_urb: *mut u64,
        ) -> i32;
        pub fn narf_usb_control(
            dev: u64,
            setup: *const u8,
            data: *const u8,
            len: usize,
            callback: usize,
            cookie: u64,
            out_urb: *mut u64,
        ) -> i32;
        pub fn narf_usb_submit(
            dev: u64,
            endpoint: u8,
            data: *const u8,
            len: usize,
            callback: usize,
            cookie: u64,
            out_urb: *mut u64,
        ) -> i32;
        pub fn narf_usb_poll(
            dev: u64,
            urb: u64,
            buf: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> i32;
        pub fn narf_usb_cancel(dev: u64, urb: u64) -> i32;
        pub fn narf_usb_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
    }
}

/// `narf_bus::module_usb::MATCH_VENDOR_PRODUCT | MATCH_INT_{CLASS,SUBCLASS,
/// PROTOCOL}`: `USB_DEVICE_AND_INTERFACE_INFO(vid, pid, 0xff, 0xff, 0xff)`,
/// the built-in `rtw_8821cu_id_table` / `rtw_8822bu_id_table` entries.
const MATCH_ID_AND_INTERFACE: u16 = 0x0f;
/// The KABI's largest single transfer (`narf_bus::module_usb::MAX_TRANSFER`).
const CHUNK: usize = 4096;
/// USB 2.0 §9.4.3 GET_DESCRIPTOR(DEVICE).
const GET_DESCRIPTOR: u8 = 0x06;
const EAGAIN: i32 = -11;
const EBUSY: i32 = -16;
const ENODEV: i32 = -19;
const EIO: i32 = -5;
/// `pci.rs::schedule_owner`'s retry spacing.
const RETRY_MS: u64 = 500;

fn log(args: core::fmt::Arguments<'_>) {
    narf_console::klog!("  rtw88.ko: {}\n", args);
}

/// Every USB completion and the 1 ms poller: run the executor, so the task
/// waiting on that request (or on a deadline) makes progress now.
extern "C" fn kick(_cookie: u64) -> i32 {
    let _ = platform::EXEC.run();
    0
}

// ── Requests ────────────────────────────────────────────────────────────

/// Collect request `urb` into `buf` once terminal: `Pending` while the
/// kernel reports `-EAGAIN`, then the transferred length or the errno.
struct Collect<'a> {
    urb: u64,
    buf: &'a mut [u8],
}

impl Future for Collect<'_> {
    type Output = Result<usize, i32>;
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (ptr, len) = if self.buf.is_empty() {
            (core::ptr::null_mut(), 0)
        } else {
            (self.buf.as_mut_ptr(), self.buf.len())
        };
        let mut got = 0usize;
        // SAFETY: `ptr` names `len` writable bytes (null when 0); `got` is a
        // live local; `urb` is this module's own request.
        let rc = unsafe { ffi::narf_usb_poll(platform::device(), self.urb, ptr, len, &mut got) };
        match rc {
            // No waker to arm: the completion `kick` and the poller re-run
            // the executor, which re-polls every task.
            EAGAIN => Poll::Pending,
            0 => Poll::Ready(Ok(got)),
            e => Poll::Ready(Err(e)),
        }
    }
}

/// One EP0 control transfer: `setup` with `data` as the OUT data stage, or
/// `data` as the IN buffer when bit 7 of `bmRequestType` is set.
async fn control(setup: [u8; 8], data: &mut [u8]) -> Result<usize, i32> {
    let is_in = setup[0] & 0x80 != 0;
    let (ptr, len) = if is_in || data.is_empty() {
        (core::ptr::null(), 0)
    } else {
        (data.as_ptr(), data.len())
    };
    let mut urb = 0u64;
    // SAFETY: `setup` names 8 bytes, `ptr` `len` readable bytes (null when
    // 0); `kick` is a valid callback in this image; `urb` is a live local.
    let rc = unsafe {
        ffi::narf_usb_control(
            platform::device(),
            setup.as_ptr(),
            ptr,
            len,
            kick as usize,
            0,
            &mut urb,
        )
    };
    if rc != 0 {
        return Err(rc);
    }
    let buf: &mut [u8] = if is_in { data } else { &mut [] };
    let n = Collect { urb, buf }.await?;
    Ok(if is_in { n } else { len })
}

fn setup(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
    let (v, i, l) = (
        value.to_le_bytes(),
        index.to_le_bytes(),
        length.to_le_bytes(),
    );
    [request_type, request, v[0], v[1], i[0], i[1], l[0], l[1]]
}

/// The configuration descriptor the function was probed with.
fn config_descriptor(dev: u64) -> Result<Vec<u8>, i32> {
    let mut need = 0usize;
    // SAFETY: sizing call — null buffer, zero length, live `need`.
    let rc = unsafe { ffi::narf_usb_config_descriptor(dev, core::ptr::null_mut(), 0, &mut need) };
    if rc != 0 && rc != -105 {
        return Err(rc);
    }
    if !(9..=usb_driver::CONFIG_MAX).contains(&need) {
        return Err(ENODEV);
    }
    let mut config = alloc::vec![0u8; need];
    // SAFETY: `config` names `need` writable bytes.
    let rc = unsafe { ffi::narf_usb_config_descriptor(dev, config.as_mut_ptr(), need, &mut need) };
    if rc != 0 {
        return Err(rc);
    }
    config.truncate(need);
    Ok(config)
}

// ── EP0: `ControlIo` ────────────────────────────────────────────────────

/// The `UsbControl` of the module build: Realtek vendor register requests
/// on EP0 (`rtw_usb_read` / `rtw_usb_write`).
pub(super) struct Control {
    vendor: u16,
    product: u16,
    config: Arc<[u8]>,
}

#[async_trait::async_trait]
impl ControlIo for Control {
    fn identity(&self) -> Option<(u16, u16)> {
        Some((self.vendor, self.product))
    }
    async fn configuration(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        let n = self.config.len().min(out.len());
        out[..n].copy_from_slice(&self.config[..n]);
        Ok(n)
    }
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        let s = setup(
            REALTEK_USB_READ,
            REALTEK_USB_CMD_REQ,
            addr,
            0,
            out.len() as u16,
        );
        control(s, out).await.map_err(UsbError::from_errno)
    }
    async fn write(&self, addr: u16, data: &[u8]) -> Result<usize, UsbError> {
        let s = setup(
            REALTEK_USB_WRITE,
            REALTEK_USB_CMD_REQ,
            addr,
            0,
            data.len() as u16,
        );
        let mut copy = data.to_vec();
        control(s, &mut copy).await.map_err(UsbError::from_errno)
    }
    /// Register-sequence delays: short ones busy-wait (`narf_udelay`), as
    /// `udelay` does; longer ones sleep on the executor heartbeat.
    async fn delay_us(&self, us: u64) {
        if us <= 1_000 {
            platform::delay_ns(us.saturating_mul(1_000));
        } else {
            narf_module_rt::time::sleep_until(narf_module_rt::time::Deadline::after_ns(
                us.saturating_mul(1_000),
            ))
            .await;
        }
    }
}

// ── Bulk pipes: `Io` ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Pending,
    Done(usize),
    Failed(UsbError),
}

/// One driver-level bulk transfer, carried as a chain of ≤ 4 KiB requests.
struct Transfer {
    endpoint: u8,
    /// OUT: the payload; IN: what was received so far.
    data: Vec<u8>,
    /// IN: the receive capacity; OUT: `data.len()`.
    total: usize,
    /// Bytes moved by completed requests.
    done: usize,
    /// The request in flight and its length.
    urb: Option<(u64, usize)>,
    /// `stop` asked for cancellation.
    cancel: bool,
    outcome: Outcome,
}

impl Transfer {
    fn is_in(&self) -> bool {
        self.endpoint & 0x80 != 0
    }
}

/// One transfer, shared between its receipt and its endpoint's queue.
type Shared = Arc<IrqSafeSpinLock<Transfer>>;

/// A bulk receipt: the transfer, shared with its endpoint's queue.
pub(super) struct Receipt(Shared);

/// One endpoint's FIFO: only the head transfer has a request in flight
/// (the KABI carries one per endpoint), as a host controller's ring orders
/// them.
type Pipe = (u8, VecDeque<Shared>);

static PIPES: IrqSafeSpinLock<Vec<Pipe>> = IrqSafeSpinLock::new(Vec::new());

/// Submit the head transfer's next chunk.
fn submit_next(t: &mut Transfer) {
    let len = (t.total - t.done).min(CHUNK);
    let mut urb = 0u64;
    let (ptr, n) = if t.is_in() {
        (core::ptr::null(), len)
    } else {
        (t.data[t.done..].as_ptr(), len)
    };
    // SAFETY: for OUT `ptr` names `n` readable bytes of `t.data` (copied
    // before return); IN passes null; `kick` is a valid callback in this
    // image; `urb` is a live local.
    let rc = unsafe {
        ffi::narf_usb_submit(
            platform::device(),
            t.endpoint,
            ptr,
            n,
            kick as usize,
            0,
            &mut urb,
        )
    };
    if rc == 0 {
        t.urb = Some((urb, len));
    } else {
        t.outcome = Outcome::Failed(UsbError::from_errno(rc));
    }
}

/// Advance the head transfer as far as its requests have completed,
/// submitting each next chunk at once: `true` when the transfer reached its
/// outcome (and may leave the queue), `false` while a request is in flight.
fn advance(t: &mut Transfer) -> bool {
    loop {
        if t.outcome != Outcome::Pending {
            return true;
        }
        if t.urb.is_none() {
            if t.cancel {
                t.outcome = Outcome::Failed(UsbError::Timeout);
                return true;
            }
            if t.done == t.total {
                t.outcome = Outcome::Done(t.done);
                return true;
            }
            submit_next(t);
            if t.outcome != Outcome::Pending {
                return true;
            }
        }
        let Some((urb, len)) = t.urb else {
            return false;
        };
        let mut chunk = [0u8; CHUNK];
        let (ptr, cap) = if t.is_in() {
            (chunk.as_mut_ptr(), len)
        } else {
            (core::ptr::null_mut(), 0)
        };
        let mut got = 0usize;
        // SAFETY: IN: `chunk` names `len` (≤ 4096) writable bytes; OUT: null.
        let rc = unsafe { ffi::narf_usb_poll(platform::device(), urb, ptr, cap, &mut got) };
        if rc == EAGAIN {
            return false;
        }
        t.urb = None;
        if rc != 0 {
            t.outcome = Outcome::Failed(UsbError::from_errno(rc));
            return true;
        }
        let got = got.min(len);
        if t.is_in() {
            t.data.extend_from_slice(&chunk[..got]);
        }
        t.done += got;
        // A short chunk ends the transfer (IN: the device's short packet;
        // OUT: the controller moved less than asked).
        if got < len || t.done == t.total {
            t.outcome = Outcome::Done(t.done);
            return true;
        }
    }
}

/// Run `endpoint`'s queue as far as it goes without waiting.
fn pump(endpoint: u8) {
    let mut pipes = PIPES.lock();
    let Some((_, queue)) = pipes.iter_mut().find(|(ep, _)| *ep == endpoint) else {
        return;
    };
    while let Some(head) = queue.front().cloned() {
        let finished = advance(&mut head.lock());
        if !finished {
            break;
        }
        queue.pop_front();
    }
}

fn enqueue(endpoint: u8, data: Vec<u8>, total: usize) -> Receipt {
    let transfer = Arc::new(IrqSafeSpinLock::new(Transfer {
        endpoint,
        data,
        total,
        done: 0,
        urb: None,
        cancel: false,
        outcome: Outcome::Pending,
    }));
    {
        let mut pipes = PIPES.lock();
        match pipes.iter_mut().find(|(ep, _)| *ep == endpoint) {
            Some((_, queue)) => queue.push_back(transfer.clone()),
            None => pipes.push((endpoint, VecDeque::from([transfer.clone()]))),
        }
    }
    pump(endpoint);
    Receipt(transfer)
}

/// The `UsbIo` of the module build.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Bulk;

#[async_trait::async_trait]
impl Io for Bulk {
    type Receipt = Receipt;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<Receipt, UsbError> {
        if length == 0 {
            return Err(UsbError::BufferTooSmall);
        }
        Ok(enqueue(
            ep_for(dci),
            Vec::with_capacity(length.min(CHUNK)),
            length,
        ))
    }
    fn poll_receive(&self, receipt: &Receipt, bytes: &mut [u8]) -> Result<Option<usize>, UsbError> {
        let endpoint = receipt.0.lock().endpoint;
        pump(endpoint);
        let t = receipt.0.lock();
        match t.outcome {
            Outcome::Pending => Ok(None),
            Outcome::Failed(e) => Err(e),
            Outcome::Done(n) => {
                if bytes.len() < n {
                    return Err(UsbError::BufferTooSmall);
                }
                bytes[..n].copy_from_slice(&t.data[..n]);
                Ok(Some(n))
            }
        }
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<Receipt, UsbError> {
        if bytes.is_empty() {
            return Err(UsbError::BufferTooSmall);
        }
        Ok(enqueue(ep_for(dci), bytes.to_vec(), bytes.len()))
    }
    fn poll_send(&self, receipt: &Receipt) -> Result<Option<usize>, UsbError> {
        let endpoint = receipt.0.lock().endpoint;
        pump(endpoint);
        match receipt.0.lock().outcome {
            Outcome::Pending => Ok(None),
            Outcome::Failed(e) => Err(e),
            Outcome::Done(n) => Ok(Some(n)),
        }
    }
    /// Cancel the transfer and wait until no request of it is in flight.
    async fn stop(&self, receipt: &Receipt) -> Result<(), UsbError> {
        let endpoint = {
            let mut t = receipt.0.lock();
            t.cancel = true;
            if let Some((urb, _)) = t.urb {
                // SAFETY: argument-only call on our own request.
                let _ = unsafe { ffi::narf_usb_cancel(platform::device(), urb) };
            }
            t.endpoint
        };
        core::future::poll_fn(|_| {
            pump(endpoint);
            let mut t = receipt.0.lock();
            if t.urb.is_some() {
                return Poll::Pending;
            }
            if t.outcome == Outcome::Pending {
                // Queued behind another transfer: never submitted.
                t.outcome = Outcome::Failed(UsbError::Timeout);
            }
            Poll::Ready(())
        })
        .await;
        // Drop it from its queue if it never reached the head.
        let mut pipes = PIPES.lock();
        if let Some((_, queue)) = pipes.iter_mut().find(|(ep, _)| *ep == endpoint) {
            queue.retain(|t| !Arc::ptr_eq(t, &receipt.0));
        }
        Ok(())
    }
}

// ── Registration and probe ─────────────────────────────────────────────

/// One function per module instance (the platform's device token is
/// single, as `ath11k.ko`'s is).
static BOUND: AtomicBool = AtomicBool::new(false);

/// The bound function's station shell, once published.
static STATION: IrqSafeSpinLock<Option<Arc<Station>>> = IrqSafeSpinLock::new(None);

/// `module_usb_driver(rtw_8821cu_driver)` / `(rtw_8822bu_driver)`: every
/// VID/PID of both id tables, with their vendor-specific interface triple.
pub(super) fn register() {
    for (name, ids) in [
        (b"rtw8821cu".as_slice(), usb::RTL8821CU_IDS),
        (b"rtw8822bu".as_slice(), usb::RTL8822BU_IDS),
    ] {
        for &(vendor, product) in ids {
            // SAFETY: `name` is 'static; `probe_c` is a valid extern "C" fn;
            // the loader unregisters every match before unmapping this image.
            let rc = unsafe {
                ffi::narf_register_usb_driver(
                    name.as_ptr(),
                    name.len(),
                    MATCH_ID_AND_INTERFACE,
                    vendor,
                    product,
                    0xff,
                    0xff,
                    0xff,
                    probe_c as usize,
                )
            };
            if rc != 0 {
                log(format_args!(
                    "USB registration of {vendor:04x}:{product:04x} failed ({rc})"
                ));
            }
        }
    }
}

/// Probe thunk the USB dispatcher calls (task context, module domain).
extern "C" fn probe_c(dev: u64, _reserved: u64) -> i32 {
    if BOUND.swap(true, Ordering::AcqRel) {
        return EBUSY;
    }
    let rc = probe_device(dev);
    if rc != 0 {
        platform::set_device(0);
        BOUND.store(false, Ordering::Release);
    }
    rc
}

/// `rtw_usb_probe` up to the asynchronous part: the configuration
/// descriptor and `rtw_usb_parse` ([`Endpoints::parse`]), then the
/// heartbeat and the attach task. A token without a live USB context is
/// refused before any device access (the descriptor read fails first).
fn probe_device(dev: u64) -> i32 {
    let config = match config_descriptor(dev) {
        Ok(config) => config,
        Err(rc) => return if rc < 0 { rc } else { ENODEV },
    };
    let Ok(endpoints) = Endpoints::parse(&config) else {
        return ENODEV;
    };
    platform::set_device(dev);
    // SAFETY: `kick` is a valid extern "C" fn in this image; the kernel
    // stops the poller with the USB context, before this image is unmapped.
    let rc = unsafe { ffi::narf_usb_spawn_poller(dev, kick as usize, 0) };
    if rc != 0 {
        log(format_args!("no device heartbeat ({rc})"));
        return if rc < 0 { rc } else { EIO };
    }
    let config: Arc<[u8]> = Arc::from(config.into_boxed_slice());
    platform::spawn(async move {
        if let Err(error) = attach(config, endpoints).await {
            log(format_args!("attach failed: {error:?}"));
        }
    });
    let _ = platform::EXEC.run();
    0
}

/// SET_CONFIGURATION, then the xHCI endpoint contexts for the bulk pipes
/// rtw88 submits on (`usb_driver::interface_init`).
async fn interface_init(config: &[u8], endpoints: &Endpoints) -> Result<(), Error> {
    let s = setup(
        0x00,
        usb_driver::SET_CONFIGURATION,
        u16::from(config[5]),
        0,
        0,
    );
    control(s, &mut []).await.map_err(|_| Error::Access)?;
    let mut pipes = Vec::with_capacity(1 + usize::from(endpoints.out_count));
    pipes.push(endpoints.bulk_in);
    pipes.extend_from_slice(&endpoints.out[..usize::from(endpoints.out_count)]);
    let mut urb = 0u64;
    // SAFETY: `pipes` names `pipes.len()` readable bytes; `kick` is a valid
    // callback in this image; `urb` is a live local.
    let rc = unsafe {
        ffi::narf_usb_configure(
            platform::device(),
            pipes.as_ptr(),
            pipes.len(),
            kick as usize,
            0,
            &mut urb,
        )
    };
    if rc != 0 {
        return Err(Error::Access);
    }
    Collect { urb, buf: &mut [] }
        .await
        .map(|_| ())
        .map_err(|_| Error::Access)
}

/// `usb_driver::attach` over the KABI.
async fn attach(config: Arc<[u8]>, endpoints: Endpoints) -> Result<(), Error> {
    let mut descriptor = [0u8; 18];
    let n = control(
        setup(0x80, GET_DESCRIPTOR, 0x0100, 0, descriptor.len() as u16),
        &mut descriptor,
    )
    .await
    .map_err(|_| Error::Access)?;
    if n < 12 || descriptor[1] != 1 {
        return Err(Error::Unsupported);
    }
    let vendor = u16::from_le_bytes([descriptor[8], descriptor[9]]);
    let product = u16::from_le_bytes([descriptor[10], descriptor[11]]);
    let did = usb_driver::chip(vendor, product).ok_or(Error::Unsupported)?;
    let name = usb_driver::driver_name(did);
    interface_init(&config, &endpoints).await?;
    // The USB KABI carries no port speed; the bulk-IN max packet size fixes
    // it (64 / 512 / 1024: full / high / SuperSpeed).
    let speed = Speed::from_port(PortSpeed::from_bulk_packet(endpoints.bulk_in_packet));
    let mut backend = Backend::new_for(
        did,
        Control {
            vendor,
            product,
            config: config.clone(),
        },
        Bulk,
        endpoints,
        speed,
    )?;
    let factory = usb_driver::power_and_factory_for(&mut backend, did).await?;
    if let Factory::B22(f) = &factory {
        // `rtw_usb_probe` after `rtw_chip_info_setup`: `rtw_usb_phy_cfg` at
        // the chip cut, then `rtw_usb_switch_mode`.
        let registers = backend.registers();
        let cut = (registers
            .read32(0xf0)
            .await
            .map_err(super::usb_firmware::usb_error)?
            >> 12
            & 15) as u8;
        registers
            .phy_cfg(cut)
            .await
            .map_err(super::usb_firmware::usb_error)?;
        if registers
            .switch_mode(f.usb_mode_switch())
            .await
            .map_err(super::usb_firmware::usb_error)?
        {
            // The chip re-enumerates as USB 3; the new function probes fresh.
            log(format_args!(
                "{name} {vendor:04x}:{product:04x}: switching to USB 3 mode"
            ));
            return Ok(());
        }
    }
    // The kernel's installed regulatory domain, which the signed per-board
    // records are checked against (built in: `narf_wireless::reg::db`).
    if let Err(error) = platform::narf_wireless::reg::db::refresh() {
        log(format_args!(
            "no regulatory domain from the kernel ({error:?}): calibration will be refused"
        ));
    }
    let mac = factory.mac();
    let lifecycle: Arc<Lifecycle<Backend>> =
        Arc::new(Lifecycle::new(did).on(super::phy8821c::Interface::Usb { vendor, product }));
    let station = Arc::new(Station::new(
        super::iface_module::SHELL_NAME,
        mac,
        lifecycle.clone(),
        Arc::new(super::station::NativeEnvironment),
    ));
    super::interface::publish(station.clone()).map_err(|_| Error::State)?;
    *STATION.lock() = Some(station.clone());
    log(format_args!(
        "{name} {vendor:04x}:{product:04x} {speed:?} {} bulk-out, mac {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        endpoints.out_count, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ));
    let pending = IrqSafeSpinLock::new(Some(backend));
    let result = drive(&lifecycle, &station, &factory, &pending).await;
    match &result {
        Ok(()) => {
            log(format_args!("{name}: station ready"));
            super::iface_module::station_ready();
        }
        Err(error) => log(format_args!(
            "{name}: provisioning stopped at {:?}: {error:?}",
            lifecycle.status().stage
        )),
    }
    result
}

/// `usb_driver::Generation::drive`: retry provisioning while the firmware
/// image or the signed records are not registered yet (120 attempts,
/// 500 ms apart, as `pci.rs::schedule_owner`).
async fn drive(
    lifecycle: &Lifecycle<Backend>,
    station: &Station,
    factory: &Factory,
    pending: &IrqSafeSpinLock<Option<Backend>>,
) -> Result<(), Error> {
    let mut last = Error::State;
    for attempt in 0..usb_driver::ATTEMPTS {
        if attempt > 0 {
            narf_module_rt::time::sleep_ms(RETRY_MS).await;
        }
        let step: Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>> =
            Box::pin(usb_driver::provision(lifecycle, station, factory, pending));
        match step.await {
            Ok(()) => return Ok(()),
            Err(error) => {
                last = error;
                if !usb_driver::retryable(lifecycle, station) {
                    return Err(error);
                }
            }
        }
    }
    Err(last)
}

/// The bound station shell, once published (for the module's netdev).
pub(super) fn station() -> Option<Arc<Station>> {
    STATION.lock().clone()
}

/// The lifecycle stage of the bound station, for diagnostics.
pub(super) fn stage() -> Option<Stage> {
    STATION.lock().as_ref().map(|s| s.lifecycle.status().stage)
}
