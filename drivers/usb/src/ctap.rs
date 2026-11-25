//! FIDO2 authenticators: CTAP2 over raw HID (issue #999, power-suspend
//! lane P3).
//!
//! A FIDO authenticator is a HID-class interface whose report
//! descriptor declares the FIDO Alliance usage page (0xF1D0) with
//! 64-byte Input and Output reports. That descriptor check, not the
//! interface class alone, is the discrimination.
//!
//! FIDO interfaces bind like every other HID interface no input binder
//! claims: as raw HID (`hid::raw`), published in the
//! `narf_input::hid_device` registry and served to userspace as
//! `/dev/hidrawN` (browsers, libfido2). The interrupt endpoint pair has
//! that one owner.
//!
//! This module finds the authenticators in that registry
//! ([`fido_devices`]) and runs the `narf-ctap2` protocol over the same
//! device ([`HidDevicePipe`], [`open_client`]) for the suspend service.
//! The pipe takes input reports from the device's report stream and
//! sends output reports through its transport.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_input::hid_device::{self, HidDevice};
use narf_lib::sync::IrqSafeSpinLock;

use narf_ctap2::ctaphid::{HidPipe, REPORT_LEN};
use narf_ctap2::Client;

use crate::hid::report_descriptor::{parse, FieldKind};
use crate::xhci::{EndpointConfig, EndpointKind};

/// HID usage page: FIDO Alliance (CTAP2 spec, HID binding).
pub const FIDO_USAGE_PAGE: u16 = 0xF1D0;
/// FIDO application-collection usage on that page.
pub const FIDO_USAGE_AUTHENTICATOR: u16 = 0x01;
/// USB interface class: HID.
pub const HID_INTERFACE_CLASS: u8 = 0x03;
/// HID descriptor type (the class descriptor after the interface).
pub const HID_DESC_TYPE_HID: u8 = 0x21;
/// Report descriptor type (wValue high byte for GET_DESCRIPTOR).
pub const HID_DESC_TYPE_REPORT: u8 = 0x22;
/// bmRequestType for GET_DESCRIPTOR to an interface:
/// device-to-host | standard | interface.
pub const RT_DEV_TO_HOST_STD_IFACE: u8 = 0x81;

/// Upper bound on a FIDO report descriptor fetch (the canonical
/// descriptor is 34 bytes; real tokens stay well under 512).
pub const MAX_REPORT_DESCRIPTOR: usize = 512;

/// Poll bound for one interrupt transfer completion. The pipe is
/// deliberately poll-driven (the resume environment, P5, has no
/// IRQ waits either); at xHCI demux cost per poll this bound is
/// far beyond any real token's report latency, and exhaustion is
/// a clean Timeout, never a hang.
pub const MAX_POLLS_PER_REPORT: usize = 4_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtapError {
    /// Not a FIDO HID device (wrong class, no FIDO usage, or the
    /// report shape isn't 64-byte in/out) — fall through to the
    /// next binder.
    NotFido,
    /// Endpoints missing or not 64-byte interrupt in/out.
    EndpointsMissing,
    /// The report-descriptor length was implausible or absent.
    NoReportDescriptor,
    /// A control/endpoint transfer failed.
    Transfer,
    /// No xHCI controller is registered.
    NoController,
}

/// Every registered USB HID device with the FIDO report shape, in
/// registration order.
pub fn fido_devices() -> Vec<Arc<HidDevice>> {
    hid_device::devices()
        .into_iter()
        .filter(|d| {
            d.info().bus == narf_input::evdev::bus::USB
                && descriptor_is_fido(&d.info().report_descriptor)
        })
        .collect()
}

/// Number of FIDO authenticators currently bound.
pub fn attached_count() -> usize {
    fido_devices().len()
}

/// The `index`th bound authenticator (the suspend service's common case
/// is index 0).
pub fn bound_token(index: usize) -> Option<Arc<HidDevice>> {
    fido_devices().into_iter().nth(index)
}

// ── Configuration-descriptor walkers ────────────────────────────

/// Walk the configuration descriptor for the first HID-class
/// interface (class 0x03) at or after `from`. Returns
/// (bInterfaceNumber, offset). Composite tokens may carry the
/// FIDO interface behind another HID interface, so the binder
/// iterates this over the whole blob.
pub fn find_hid_interface_from(cfg: &[u8], from: usize) -> Option<(u8, usize)> {
    let mut i = from;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 0x04 && len >= 9 && cfg[i + 5] == HID_INTERFACE_CLASS {
            return Some((cfg[i + 2], i));
        }
        i += len;
    }
    None
}

/// The first HID-class interface in the blob, if any.
pub fn find_hid_interface(cfg: &[u8]) -> Option<(u8, usize)> {
    find_hid_interface_from(cfg, 0)
}

/// Extract the Report Descriptor length from the HID class
/// descriptor (type 0x21) that follows the interface descriptor.
pub fn report_descriptor_length(cfg: &[u8], iface_offset: usize) -> Option<u16> {
    let mut i = iface_offset;
    // Skip the interface descriptor itself.
    if i + 2 <= cfg.len() {
        let skip = cfg[i] as usize;
        if skip >= 2 {
            i += skip;
        }
    }
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == HID_DESC_TYPE_HID && len >= 9 {
            if cfg[i + 6] != HID_DESC_TYPE_REPORT {
                return None;
            }
            return Some(u16::from_le_bytes([cfg[i + 7], cfg[i + 8]]));
        }
        if dtype == 0x04 || dtype == 0x05 {
            return None; // reached the next interface / an endpoint first
        }
        i += len;
    }
    None
}

/// Collect the interrupt IN and OUT endpoints following the
/// interface descriptor. Both must be 64-byte max-packet — the
/// CTAPHID report size is fixed, and a smaller endpoint cannot
/// carry one report per transfer.
pub fn find_fido_endpoints(
    cfg: &[u8],
    iface_offset: usize,
) -> Result<(EndpointConfig, EndpointConfig), CtapError> {
    let mut in_ep: Option<EndpointConfig> = None;
    let mut out_ep: Option<EndpointConfig> = None;
    let mut i = iface_offset;
    if i + 2 <= cfg.len() {
        let skip = cfg[i] as usize;
        if skip >= 2 {
            i += skip;
        }
    }
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        if dtype == 0x04 {
            break; // next interface
        }
        if dtype == 0x05 && len >= 7 {
            let addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
            let interval = cfg[i + 6];
            if attrs & 0x03 == 0x03 && max_packet as usize == REPORT_LEN {
                if addr & 0x80 != 0 && in_ep.is_none() {
                    in_ep = Some(EndpointConfig {
                        ep_addr: addr,
                        max_packet,
                        kind: EndpointKind::InterruptIn,
                        interval,
                    });
                } else if addr & 0x80 == 0 && out_ep.is_none() {
                    out_ep = Some(EndpointConfig {
                        ep_addr: addr,
                        max_packet,
                        kind: EndpointKind::InterruptOut,
                        interval,
                    });
                }
            }
        }
        i += len;
    }
    match (in_ep, out_ep) {
        (Some(a), Some(b)) => Ok((a, b)),
        _ => Err(CtapError::EndpointsMissing),
    }
}

/// True when a fetched HID report descriptor is the FIDO shape:
/// the FIDO Alliance page (0xF1D0) application collection with
/// 64-byte Input and Output fields and no report IDs. This is
/// the check that keeps keyboards (and every other HID device)
/// out of this binder.
pub fn descriptor_is_fido(report_desc: &[u8]) -> bool {
    let Ok(parsed) = parse(report_desc) else {
        return false;
    };
    if parsed.has_report_ids {
        return false;
    }
    if !parsed
        .top_level_apps
        .contains(&(FIDO_USAGE_PAGE, FIDO_USAGE_AUTHENTICATOR))
    {
        return false;
    }
    let has_dir = |kind: FieldKind| {
        parsed.fields.iter().any(|f| {
            f.kind == kind
                && f.usage_page == FIDO_USAGE_PAGE
                && f.report_size as usize * f.report_count as usize == REPORT_LEN * 8
        })
    };
    has_dir(FieldKind::Input) && has_dir(FieldKind::Output)
}

// ── Transport ───────────────────────────────────────────────────

/// Production randomness for the CTAP2 client: narf-crypto's
/// HW-entropy-gated fill (P0 surface). Fails closed when no seed-
/// grade entropy source exists.
#[derive(Debug)]
pub struct CryptoRandom;

impl narf_ctap2::RandomSource for CryptoRandom {
    fn fill_random(&mut self, out: &mut [u8]) -> Result<(), narf_ctap2::Error> {
        narf_crypto::try_fill_random_bytes(out).map_err(|_| narf_ctap2::Error::Random)
    }
}

/// Reports buffered for one pipe; a CTAPHID exchange keeps a handful
/// in flight at most.
const PIPE_QUEUE: usize = 64;

/// A CTAPHID pipe over one registered authenticator. Input reports
/// arrive through a [`HidDevice::subscribe`] sink; output reports go
/// through the device's transport. Reads pump the device's endpoint
/// themselves, so the pipe works where no other task runs (the resume
/// path, P5).
pub struct HidDevicePipe {
    dev: Arc<HidDevice>,
    queue: Arc<IrqSafeSpinLock<VecDeque<[u8; REPORT_LEN]>>>,
    sink: u64,
}

impl core::fmt::Debug for HidDevicePipe {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HidDevicePipe")
            .field("dev", &self.dev.sysfs_name())
            .field("queued", &self.queue.lock().len())
            .finish()
    }
}

impl HidDevicePipe {
    pub fn new(dev: Arc<HidDevice>) -> Self {
        let queue: Arc<IrqSafeSpinLock<VecDeque<[u8; REPORT_LEN]>>> =
            Arc::new(IrqSafeSpinLock::new(VecDeque::new()));
        let q = queue.clone();
        let sink = dev.subscribe(Arc::new(move |data: &[u8]| {
            if data.len() != REPORT_LEN {
                return;
            }
            let mut report = [0u8; REPORT_LEN];
            report.copy_from_slice(data);
            let mut g = q.lock();
            if g.len() == PIPE_QUEUE {
                g.pop_front();
            }
            g.push_back(report);
        }));
        Self { dev, queue, sink }
    }
}

impl Drop for HidDevicePipe {
    fn drop(&mut self) {
        self.dev.unsubscribe(self.sink);
    }
}

impl HidPipe for HidDevicePipe {
    fn write_report(&mut self, report: &[u8; REPORT_LEN]) -> Result<(), narf_ctap2::Error> {
        // The FIDO shape has no report IDs: a leading 0, as a hidraw
        // writer sends it.
        let mut wire = [0u8; REPORT_LEN + 1];
        wire[1..].copy_from_slice(report);
        match narf_scheduler::block_on_spin(self.dev.transport().output_report(&wire)) {
            Ok(n) if n == wire.len() => Ok(()),
            Ok(_) => Err(narf_ctap2::Error::Transport),
            Err(narf_input::hid_device::HidIoError::Timeout) => Err(narf_ctap2::Error::Timeout),
            Err(_) => Err(narf_ctap2::Error::Transport),
        }
    }

    fn read_report(&mut self, out: &mut [u8; REPORT_LEN]) -> Result<(), narf_ctap2::Error> {
        for _ in 0..MAX_POLLS_PER_REPORT {
            if let Some(report) = self.queue.lock().pop_front() {
                *out = report;
                return Ok(());
            }
            if !self.dev.is_alive() {
                return Err(narf_ctap2::Error::Transport);
            }
            crate::hid::raw::pump_device(&self.dev);
            core::hint::spin_loop();
        }
        Err(narf_ctap2::Error::Timeout)
    }
}

/// Open a CTAP2 client over a bound authenticator, ready for the
/// suspend service: fresh pipe + CTAPHID INIT + getInfo (inside
/// `Client::connect`).
pub fn open_client(
    dev: &Arc<HidDevice>,
) -> Result<Client<HidDevicePipe, CryptoRandom>, narf_ctap2::Error> {
    Client::connect(HidDevicePipe::new(dev.clone()), CryptoRandom)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use narf_kernel_test::{kernel_test_in, TestResult};

    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if !($cond) {
                return TestResult::Fail($msg);
            }
        };
    }
    macro_rules! check_eq {
        ($a:expr, $b:expr, $msg:expr) => {
            if $a != $b {
                return TestResult::Fail($msg);
            }
        };
    }
    macro_rules! try_some {
        ($e:expr, $msg:expr) => {
            match $e {
                Some(v) => v,
                None => return TestResult::Fail($msg),
            }
        };
    }
    macro_rules! try_ok {
        ($e:expr, $msg:expr) => {
            match $e {
                Ok(v) => v,
                Err(_) => return TestResult::Fail($msg),
            }
        };
    }

    /// The canonical FIDO report descriptor (CTAP2 spec's HID
    /// binding example shape, as shipped by YubiKey-class tokens).
    pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
        0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
        0x09, 0x01, // Usage (authenticator)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x20, //   Usage (input data)
        0x15, 0x00, //   Logical Minimum (0)
        0x26, 0xFF, 0x00, //   Logical Maximum (255)
        0x75, 0x08, //   Report Size (8)
        0x95, 0x40, //   Report Count (64)
        0x81, 0x02, //   Input (Data, Var, Abs)
        0x09, 0x21, //   Usage (output data)
        0x15, 0x00, 0x26, 0xFF, 0x00, 0x75, 0x08, 0x95, 0x40, //
        0x91, 0x02, //   Output (Data, Var, Abs)
        0xC0, // End Collection
    ];

    /// A boot-keyboard report descriptor (must NOT match).
    const KEYBOARD_REPORT_DESCRIPTOR: &[u8] = &[
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25,
        0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05,
        0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91,
        0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
        0x81, 0x00, 0xC0,
    ];

    /// Build a config-descriptor blob for a single-interface HID
    /// device with the given endpoints: config(9) + iface(9) +
    /// HID class desc(9) + ep descs(7 each).
    fn cfg_blob(report_desc_len: u16, eps: &[(u8, u8, u16, u8)]) -> Vec<u8> {
        let total = 9 + 9 + 9 + 7 * eps.len();
        let mut cfg = alloc::vec![
            9,
            2,
            (total as u8),
            0, // wTotalLength LE
            1,
            1,
            0,
            0x80,
            50, // 1 iface, config 1
        ];
        cfg.extend_from_slice(&[9, 4, 0, 0, eps.len() as u8, 0x03, 0x00, 0x00, 0]);
        // HID class descriptor: bcdHID 1.11, country 0, 1 sub-desc
        // (Report, length).
        cfg.extend_from_slice(&[9, 0x21, 0x11, 0x01, 0, 1, 0x22]);
        cfg.extend_from_slice(&report_desc_len.to_le_bytes());
        for (addr, attrs, maxp, interval) in eps {
            cfg.extend_from_slice(&[7, 5, *addr, *attrs]);
            cfg.extend_from_slice(&maxp.to_le_bytes());
            cfg.push(*interval);
        }
        cfg
    }

    fn smoke_fido_descriptor_matches_and_keyboard_does_not() -> TestResult {
        check!(
            descriptor_is_fido(FIDO_REPORT_DESCRIPTOR),
            "FIDO descriptor matches"
        );
        check!(
            !descriptor_is_fido(KEYBOARD_REPORT_DESCRIPTOR),
            "keyboard descriptor must not match"
        );
        check!(!descriptor_is_fido(&[]), "empty descriptor must not match");
        check!(
            !descriptor_is_fido(&[0x06, 0xD0]),
            "truncated descriptor must not match"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ctap",
        smoke_fido_descriptor_matches_and_keyboard_does_not
    );

    fn smoke_fido_config_blob_binds() -> TestResult {
        let cfg = cfg_blob(
            FIDO_REPORT_DESCRIPTOR.len() as u16,
            &[(0x81, 0x03, 64, 1), (0x01, 0x03, 64, 1)],
        );
        let (iface, off) = try_some!(find_hid_interface(&cfg), "hid iface");
        check_eq!(iface, 0, "iface number");
        let (in_ep, out_ep) = try_ok!(find_fido_endpoints(&cfg, off), "endpoints");
        check_eq!(in_ep.kind, EndpointKind::InterruptIn, "in endpoint kind");
        check_eq!(out_ep.kind, EndpointKind::InterruptOut, "out endpoint kind");
        check_eq!(
            report_descriptor_length(&cfg, off),
            Some(FIDO_REPORT_DESCRIPTOR.len() as u16),
            "report descriptor length"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ctap", smoke_fido_config_blob_binds);

    fn smoke_ccid_blob_is_not_fido() -> TestResult {
        // A CCID-shaped blob: class 0x0B interface — the HID finder
        // must not match it at all.
        let mut cfg = alloc::vec![9, 2, 18, 0, 1, 1, 0, 0x80, 50];
        cfg.extend_from_slice(&[9, 4, 0, 0, 0, 0x0B, 0x00, 0x00, 0]);
        check!(
            find_hid_interface(&cfg).is_none(),
            "CCID blob has no HID interface"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ctap", smoke_ccid_blob_is_not_fido);

    fn smoke_small_endpoint_is_not_fido() -> TestResult {
        // Interrupt pair but 32-byte packets: cannot carry CTAPHID
        // reports; must fall through.
        let cfg = cfg_blob(34, &[(0x81, 0x03, 32, 1), (0x01, 0x03, 32, 1)]);
        let (_, off) = try_some!(find_hid_interface(&cfg), "hid iface");
        check!(
            matches!(
                find_fido_endpoints(&cfg, off),
                Err(CtapError::EndpointsMissing)
            ),
            "small endpoints refused"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/ctap", smoke_small_endpoint_is_not_fido);

    /// A transport that records output reports and answers nothing.
    #[derive(Debug)]
    struct Recorder {
        sent: IrqSafeSpinLock<Vec<Vec<u8>>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                sent: IrqSafeSpinLock::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl narf_input::hid_device::HidTransport for Recorder {
        async fn output_report(
            &self,
            data: &[u8],
        ) -> Result<usize, narf_input::hid_device::HidIoError> {
            self.sent.lock().push(data.to_vec());
            Ok(data.len())
        }
        async fn raw_request(
            &self,
            _id: u8,
            _buf: &mut [u8],
            _kind: narf_input::hid_device::ReportType,
            _set: bool,
        ) -> Result<usize, narf_input::hid_device::HidIoError> {
            Err(narf_input::hid_device::HidIoError::Unsupported)
        }
    }

    fn info(bus: u16, rdesc: &[u8]) -> narf_input::hid_device::HidInfo {
        narf_input::hid_device::HidInfo {
            bus,
            vendor: 0x1050,
            product: 0x0407,
            report_descriptor: rdesc.to_vec(),
            ..Default::default()
        }
    }

    fn smoke_fido_devices_come_from_the_hid_registry() -> TestResult {
        hid_device::__reset_for_test();
        let usb = narf_input::evdev::bus::USB;
        let kbd = hid_device::register(
            info(usb, KEYBOARD_REPORT_DESCRIPTOR),
            Arc::new(Recorder::new()),
        );
        let recorder = Arc::new(Recorder::new());
        let fido = hid_device::register(info(usb, FIDO_REPORT_DESCRIPTOR), recorder.clone());
        // The same descriptor on another bus is not a USB token.
        let _i2c = hid_device::register(
            info(narf_input::evdev::bus::I2C, FIDO_REPORT_DESCRIPTOR),
            Arc::new(Recorder::new()),
        );
        check_eq!(attached_count(), 1, "only the USB FIDO device counts");
        check!(
            bound_token(0).is_some_and(|d| Arc::ptr_eq(&d, &fido)),
            "lookup by index"
        );
        check!(bound_token(1).is_none(), "no second token");

        // A pipe writes 0 + report through the transport and reads the
        // device's 64-byte input reports, ignoring other sizes.
        let mut pipe = HidDevicePipe::new(fido.clone());
        let mut report = [0u8; REPORT_LEN];
        report[0] = 0xff;
        check!(
            pipe.write_report(&report).is_ok(),
            "write through transport"
        );
        check!(
            recorder
                .sent
                .lock()
                .first()
                .is_some_and(|w| w.len() == REPORT_LEN + 1 && w[0] == 0 && w[1] == 0xff),
            "output report carries a leading 0 report ID"
        );
        fido.report_in(&[1, 2, 3]);
        let mut answer = [0u8; REPORT_LEN];
        answer[0] = 0x42;
        fido.report_in(&answer);
        let mut got = [0u8; REPORT_LEN];
        check!(pipe.read_report(&mut got).is_ok(), "read the queued report");
        check_eq!(got[0], 0x42, "the 64-byte report, not the short one");
        drop(pipe);

        hid_device::unregister(&fido);
        check_eq!(attached_count(), 0, "an unregistered token is gone");
        let _ = kbd;
        hid_device::__reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/ctap",
        smoke_fido_devices_come_from_the_hid_registry
    );
}
